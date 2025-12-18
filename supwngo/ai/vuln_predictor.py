"""
Machine Learning-based Vulnerability Prediction.

Uses feature extraction and classification to predict
vulnerability likelihood in binary functions.
"""

import hashlib
import json
import os
import pickle
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from supwngo.core.binary import Binary
from supwngo.utils.logging import get_logger

logger = get_logger(__name__)

# Try to import ML libraries
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    np = None

try:
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import cross_val_score
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


class VulnClass(Enum):
    """Vulnerability classification."""
    SAFE = 0
    MEMORY_CORRUPTION = 1
    INFO_DISCLOSURE = 2
    CODE_EXECUTION = 3
    DENIAL_OF_SERVICE = 4
    PRIVILEGE_ESCALATION = 5


@dataclass
class FunctionFeatures:
    """
    Features extracted from a binary function for ML classification.

    These features capture characteristics that correlate with vulnerabilities.
    """
    function_name: str
    address: int

    # Size features
    size: int = 0
    num_basic_blocks: int = 0
    num_instructions: int = 0
    cyclomatic_complexity: int = 0

    # Call features
    num_calls: int = 0
    dangerous_call_count: int = 0
    dangerous_calls: List[str] = field(default_factory=list)

    # Memory features
    stack_frame_size: int = 0
    num_stack_variables: int = 0
    has_stack_buffer: bool = False
    max_buffer_size: int = 0

    # Control flow features
    num_loops: int = 0
    max_loop_depth: int = 0
    num_conditionals: int = 0
    has_recursive_call: bool = False

    # String features
    num_string_refs: int = 0
    has_format_string: bool = False
    has_user_input_func: bool = False

    # Input handling
    takes_external_input: bool = False
    input_validation_score: float = 0.0

    def to_vector(self) -> List[float]:
        """Convert features to numerical vector for ML."""
        return [
            float(self.size),
            float(self.num_basic_blocks),
            float(self.num_instructions),
            float(self.cyclomatic_complexity),
            float(self.num_calls),
            float(self.dangerous_call_count),
            float(self.stack_frame_size),
            float(self.num_stack_variables),
            float(self.has_stack_buffer),
            float(self.max_buffer_size),
            float(self.num_loops),
            float(self.max_loop_depth),
            float(self.num_conditionals),
            float(self.has_recursive_call),
            float(self.num_string_refs),
            float(self.has_format_string),
            float(self.has_user_input_func),
            float(self.takes_external_input),
            self.input_validation_score,
        ]

    @staticmethod
    def feature_names() -> List[str]:
        """Get names of features in vector."""
        return [
            "size",
            "num_basic_blocks",
            "num_instructions",
            "cyclomatic_complexity",
            "num_calls",
            "dangerous_call_count",
            "stack_frame_size",
            "num_stack_variables",
            "has_stack_buffer",
            "max_buffer_size",
            "num_loops",
            "max_loop_depth",
            "num_conditionals",
            "has_recursive_call",
            "num_string_refs",
            "has_format_string",
            "has_user_input_func",
            "takes_external_input",
            "input_validation_score",
        ]


@dataclass
class VulnPrediction:
    """Prediction result for a function."""
    function_name: str
    address: int
    predicted_class: VulnClass
    confidence: float
    risk_score: float  # 0.0 - 1.0
    contributing_features: List[Tuple[str, float]]
    explanation: str = ""

    def __str__(self) -> str:
        return (f"{self.function_name} @ 0x{self.address:x}: "
                f"{self.predicted_class.name} ({self.confidence:.0%}, risk={self.risk_score:.2f})")


class FeatureExtractor:
    """
    Extracts ML features from binary functions.

    Uses static analysis to compute features that correlate
    with vulnerability presence.
    """

    # Functions that indicate dangerous patterns
    DANGEROUS_FUNCTIONS = {
        'gets', 'strcpy', 'strcat', 'sprintf', 'vsprintf',
        'scanf', 'fscanf', 'sscanf', 'vscanf',
        'printf', 'fprintf', 'syslog', 'snprintf',  # format strings
        'read', 'recv', 'recvfrom', 'fread',
        'memcpy', 'memmove', 'bcopy',
        'system', 'popen', 'execve', 'execl', 'execlp',
        'malloc', 'calloc', 'realloc', 'free',
    }

    # Functions that take user input
    INPUT_FUNCTIONS = {
        'read', 'fread', 'recv', 'recvfrom', 'recvmsg',
        'scanf', 'fscanf', 'sscanf', 'gets', 'fgets',
        'getchar', 'fgetc', 'getenv',
    }

    # Format string functions
    FORMAT_FUNCTIONS = {
        'printf', 'fprintf', 'sprintf', 'snprintf',
        'vprintf', 'vfprintf', 'vsprintf', 'vsnprintf',
        'syslog', 'vsyslog',
    }

    def __init__(self, binary: Binary):
        """
        Initialize extractor.

        Args:
            binary: Binary to extract features from
        """
        self.binary = binary
        self._cfg = None
        self._call_graph = None

    def extract_all(self) -> List[FunctionFeatures]:
        """Extract features from all functions."""
        features = []

        for func_name, func_addr in self.binary.functions.items():
            feat = self.extract_function(func_name, func_addr)
            if feat:
                features.append(feat)

        return features

    def extract_function(
        self,
        func_name: str,
        func_addr: int
    ) -> Optional[FunctionFeatures]:
        """
        Extract features from a single function.

        Args:
            func_name: Function name
            func_addr: Function address

        Returns:
            FunctionFeatures or None if extraction fails
        """
        try:
            features = FunctionFeatures(
                function_name=func_name,
                address=func_addr
            )

            # Get function info from ELF
            if hasattr(self.binary, 'elf'):
                features.size = self._get_function_size(func_addr)

            # Analyze calls
            calls = self._get_function_calls(func_addr)
            features.num_calls = len(calls)
            features.dangerous_calls = [c for c in calls if c in self.DANGEROUS_FUNCTIONS]
            features.dangerous_call_count = len(features.dangerous_calls)

            # Check input handling
            features.has_user_input_func = any(c in self.INPUT_FUNCTIONS for c in calls)
            features.takes_external_input = features.has_user_input_func

            # Check format strings
            features.has_format_string = any(c in self.FORMAT_FUNCTIONS for c in calls)

            # Estimate complexity (simplified)
            features.cyclomatic_complexity = max(1, len(calls) // 3)
            features.num_conditionals = features.cyclomatic_complexity

            # Stack analysis (simplified)
            features.has_stack_buffer = any(
                c in {'strcpy', 'strcat', 'gets', 'sprintf', 'read', 'recv'}
                for c in calls
            )

            # Input validation heuristic
            validation_funcs = {'strlen', 'strnlen', 'memcmp', 'strncmp', 'strcmp'}
            has_validation = any(c in validation_funcs for c in calls)
            features.input_validation_score = 0.7 if has_validation else 0.0

            return features

        except Exception as e:
            logger.debug(f"Error extracting features for {func_name}: {e}")
            return None

    def _get_function_size(self, addr: int) -> int:
        """Estimate function size."""
        # Simplified - would use proper analysis in production
        if hasattr(self.binary, 'elf'):
            for sym in self.binary.elf.iter_symbols():
                if sym['st_value'] == addr:
                    return sym['st_size']
        return 100  # Default estimate

    def _get_function_calls(self, addr: int) -> List[str]:
        """Get functions called by this function."""
        calls = []

        # Check PLT entries (external calls)
        if hasattr(self.binary, 'elf'):
            for name in self.binary.functions:
                if name in self.DANGEROUS_FUNCTIONS:
                    calls.append(name)

        return calls


class VulnPredictor:
    """
    Machine learning vulnerability predictor.

    Uses trained models to predict vulnerability likelihood
    based on extracted function features.

    Example:
        predictor = VulnPredictor()

        # Load or train model
        predictor.load_model()

        # Predict on binary
        predictions = predictor.predict_binary(binary)

        for pred in predictions:
            if pred.risk_score > 0.7:
                print(f"High risk: {pred}")
    """

    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize predictor.

        Args:
            model_path: Path to saved model
        """
        self.model_path = model_path or str(
            Path.home() / ".supwngo" / "vuln_predictor.pkl"
        )
        self.model = None
        self.scaler = None
        self._feature_importance = None

    def load_model(self) -> bool:
        """
        Load pre-trained model.

        Returns:
            True if model loaded successfully
        """
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, 'rb') as f:
                    data = pickle.load(f)
                    self.model = data.get('model')
                    self.scaler = data.get('scaler')
                    self._feature_importance = data.get('feature_importance')
                logger.info("Loaded vulnerability prediction model")
                return True
            except Exception as e:
                logger.warning(f"Failed to load model: {e}")

        # Create default model if not available
        logger.info("Creating default rule-based predictor")
        self._create_default_model()
        return False

    def save_model(self):
        """Save model to disk."""
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)

        data = {
            'model': self.model,
            'scaler': self.scaler,
            'feature_importance': self._feature_importance,
        }

        with open(self.model_path, 'wb') as f:
            pickle.dump(data, f)

        logger.info("Saved vulnerability prediction model")

    def _create_default_model(self):
        """Create a default rule-based model."""
        # Use a simple heuristic model if ML not available
        self.model = "heuristic"
        self.scaler = None

    def train(
        self,
        features: List[FunctionFeatures],
        labels: List[VulnClass],
        validation_split: float = 0.2
    ) -> Dict[str, float]:
        """
        Train the prediction model.

        Args:
            features: List of function features
            labels: Corresponding vulnerability labels
            validation_split: Fraction for validation

        Returns:
            Training metrics
        """
        if not SKLEARN_AVAILABLE or not NUMPY_AVAILABLE:
            logger.warning("sklearn/numpy not available for training")
            return {"error": "ML libraries not available"}

        # Convert to numpy arrays
        X = np.array([f.to_vector() for f in features])
        y = np.array([l.value for l in labels])

        # Scale features
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        # Train model
        self.model = GradientBoostingClassifier(
            n_estimators=100,
            max_depth=5,
            random_state=42
        )
        self.model.fit(X_scaled, y)

        # Get feature importance
        self._feature_importance = dict(zip(
            FunctionFeatures.feature_names(),
            self.model.feature_importances_
        ))

        # Cross-validation score
        cv_scores = cross_val_score(self.model, X_scaled, y, cv=5)

        metrics = {
            "cv_mean_accuracy": float(cv_scores.mean()),
            "cv_std": float(cv_scores.std()),
            "num_samples": len(features),
            "num_features": X.shape[1],
        }

        logger.info(f"Model trained with accuracy: {metrics['cv_mean_accuracy']:.2%}")

        return metrics

    def predict_function(
        self,
        features: FunctionFeatures
    ) -> VulnPrediction:
        """
        Predict vulnerability for a single function.

        Args:
            features: Function features

        Returns:
            Vulnerability prediction
        """
        if self.model == "heuristic":
            return self._heuristic_predict(features)

        if not SKLEARN_AVAILABLE or not NUMPY_AVAILABLE:
            return self._heuristic_predict(features)

        # Convert to vector and scale
        X = np.array([features.to_vector()])
        if self.scaler:
            X = self.scaler.transform(X)

        # Get prediction and probability
        pred_class = self.model.predict(X)[0]
        proba = self.model.predict_proba(X)[0]

        # Calculate risk score
        # Higher for code execution, memory corruption
        risk_weights = {
            VulnClass.SAFE.value: 0.0,
            VulnClass.DENIAL_OF_SERVICE.value: 0.3,
            VulnClass.INFO_DISCLOSURE.value: 0.5,
            VulnClass.MEMORY_CORRUPTION.value: 0.8,
            VulnClass.CODE_EXECUTION.value: 1.0,
            VulnClass.PRIVILEGE_ESCALATION.value: 1.0,
        }

        risk_score = 0.0
        for i, p in enumerate(proba):
            risk_score += p * risk_weights.get(i, 0.5)

        # Get contributing features
        contributing = []
        if self._feature_importance:
            feat_values = features.to_vector()
            feat_names = FunctionFeatures.feature_names()
            for name, importance in sorted(
                self._feature_importance.items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]:
                idx = feat_names.index(name)
                contributing.append((name, feat_values[idx]))

        return VulnPrediction(
            function_name=features.function_name,
            address=features.address,
            predicted_class=VulnClass(pred_class),
            confidence=float(max(proba)),
            risk_score=risk_score,
            contributing_features=contributing,
            explanation=self._generate_explanation(features, VulnClass(pred_class))
        )

    def _heuristic_predict(self, features: FunctionFeatures) -> VulnPrediction:
        """
        Rule-based prediction when ML not available.

        Args:
            features: Function features

        Returns:
            Prediction based on heuristics
        """
        risk_score = 0.0
        pred_class = VulnClass.SAFE
        explanation_parts = []

        # Check dangerous functions
        if features.dangerous_call_count > 0:
            risk_score += 0.3
            explanation_parts.append(
                f"Calls {features.dangerous_call_count} dangerous functions: "
                f"{', '.join(features.dangerous_calls[:3])}"
            )

            # Specific dangerous patterns
            if 'gets' in features.dangerous_calls:
                risk_score += 0.5
                pred_class = VulnClass.MEMORY_CORRUPTION
                explanation_parts.append("Uses gets() - always vulnerable")

            if any(f in features.dangerous_calls for f in ['strcpy', 'strcat', 'sprintf']):
                risk_score += 0.3
                pred_class = VulnClass.MEMORY_CORRUPTION

            if any(f in features.dangerous_calls for f in ['system', 'popen', 'execve']):
                risk_score += 0.4
                pred_class = VulnClass.CODE_EXECUTION
                explanation_parts.append("Uses command execution functions")

        # Format string risk
        if features.has_format_string and features.has_user_input_func:
            risk_score += 0.4
            pred_class = VulnClass.MEMORY_CORRUPTION
            explanation_parts.append("Format string with user input")

        # Input handling without validation
        if features.takes_external_input and features.input_validation_score < 0.5:
            risk_score += 0.2
            explanation_parts.append("Handles input without apparent validation")

        # Stack buffer risk
        if features.has_stack_buffer:
            risk_score += 0.2
            explanation_parts.append("Uses stack buffers")

        # Normalize risk score
        risk_score = min(1.0, risk_score)

        # Determine confidence based on evidence
        confidence = min(0.9, 0.3 + 0.2 * len(explanation_parts))

        return VulnPrediction(
            function_name=features.function_name,
            address=features.address,
            predicted_class=pred_class,
            confidence=confidence,
            risk_score=risk_score,
            contributing_features=[
                ("dangerous_call_count", features.dangerous_call_count),
                ("has_format_string", float(features.has_format_string)),
                ("takes_external_input", float(features.takes_external_input)),
            ],
            explanation="; ".join(explanation_parts) if explanation_parts else "No obvious vulnerabilities detected"
        )

    def _generate_explanation(
        self,
        features: FunctionFeatures,
        pred_class: VulnClass
    ) -> str:
        """Generate human-readable explanation."""
        parts = []

        if pred_class == VulnClass.MEMORY_CORRUPTION:
            if features.dangerous_calls:
                parts.append(f"Uses dangerous functions: {', '.join(features.dangerous_calls[:3])}")
            if features.has_stack_buffer:
                parts.append("Has stack-based buffers")
            if not features.input_validation_score:
                parts.append("Limited input validation detected")

        elif pred_class == VulnClass.CODE_EXECUTION:
            exec_funcs = [f for f in features.dangerous_calls
                         if f in {'system', 'popen', 'execve', 'execl'}]
            if exec_funcs:
                parts.append(f"Uses code execution functions: {', '.join(exec_funcs)}")

        elif pred_class == VulnClass.INFO_DISCLOSURE:
            if features.has_format_string:
                parts.append("Format string vulnerability possible")

        if not parts:
            parts.append("Classification based on feature analysis")

        return "; ".join(parts)

    def predict_binary(self, binary: Binary) -> List[VulnPrediction]:
        """
        Predict vulnerabilities for all functions in a binary.

        Args:
            binary: Binary to analyze

        Returns:
            List of predictions, sorted by risk score
        """
        extractor = FeatureExtractor(binary)
        all_features = extractor.extract_all()

        predictions = []
        for features in all_features:
            pred = self.predict_function(features)
            predictions.append(pred)

        # Sort by risk score (highest first)
        return sorted(predictions, key=lambda p: p.risk_score, reverse=True)

    def get_high_risk_functions(
        self,
        binary: Binary,
        threshold: float = 0.5
    ) -> List[VulnPrediction]:
        """
        Get functions with risk score above threshold.

        Args:
            binary: Binary to analyze
            threshold: Risk score threshold (0.0-1.0)

        Returns:
            High-risk predictions
        """
        predictions = self.predict_binary(binary)
        return [p for p in predictions if p.risk_score >= threshold]

    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance from trained model."""
        return self._feature_importance or {}


class EnsemblePredictor:
    """
    Combines multiple prediction methods for higher accuracy.

    Uses voting/averaging across:
    - ML model predictions
    - Rule-based heuristics
    - Pattern matching
    """

    def __init__(self):
        self.ml_predictor = VulnPredictor()
        self._pattern_rules = self._build_pattern_rules()

    def _build_pattern_rules(self) -> List[Callable]:
        """Build rule functions for pattern matching."""
        rules = []

        # Rule: gets() is always vulnerable
        def check_gets(features):
            if 'gets' in features.dangerous_calls:
                return (VulnClass.MEMORY_CORRUPTION, 0.95, "gets() is always vulnerable")
            return None
        rules.append(check_gets)

        # Rule: printf(variable) without format
        def check_format_string(features):
            if features.has_format_string and features.takes_external_input:
                return (VulnClass.MEMORY_CORRUPTION, 0.8, "Format string with user input")
            return None
        rules.append(check_format_string)

        # Rule: system() with variable
        def check_command_injection(features):
            if 'system' in features.dangerous_calls and features.takes_external_input:
                return (VulnClass.CODE_EXECUTION, 0.85, "system() with external input")
            return None
        rules.append(check_command_injection)

        return rules

    def predict(self, features: FunctionFeatures) -> VulnPrediction:
        """
        Make ensemble prediction.

        Args:
            features: Function features

        Returns:
            Combined prediction
        """
        # Get ML prediction
        ml_pred = self.ml_predictor.predict_function(features)

        # Get rule-based predictions
        rule_results = []
        for rule in self._pattern_rules:
            result = rule(features)
            if result:
                rule_results.append(result)

        # If rules give high-confidence result, use it
        for vuln_class, confidence, explanation in rule_results:
            if confidence > ml_pred.confidence:
                return VulnPrediction(
                    function_name=features.function_name,
                    address=features.address,
                    predicted_class=vuln_class,
                    confidence=confidence,
                    risk_score=min(1.0, confidence + 0.1),
                    contributing_features=ml_pred.contributing_features,
                    explanation=explanation
                )

        # Otherwise use ML prediction
        return ml_pred

    def predict_binary(self, binary: Binary) -> List[VulnPrediction]:
        """
        Predict vulnerabilities for all functions.

        Args:
            binary: Binary to analyze

        Returns:
            Sorted predictions
        """
        extractor = FeatureExtractor(binary)
        all_features = extractor.extract_all()

        predictions = []
        for features in all_features:
            pred = self.predict(features)
            predictions.append(pred)

        return sorted(predictions, key=lambda p: p.risk_score, reverse=True)


# Convenience function
def predict_vulnerabilities(
    binary: Binary,
    use_ensemble: bool = True
) -> List[VulnPrediction]:
    """
    Predict vulnerabilities in a binary.

    Args:
        binary: Binary to analyze
        use_ensemble: Use ensemble predictor (recommended)

    Returns:
        List of predictions sorted by risk
    """
    if use_ensemble:
        predictor = EnsemblePredictor()
    else:
        predictor = VulnPredictor()
        predictor.load_model()

    return predictor.predict_binary(binary)
