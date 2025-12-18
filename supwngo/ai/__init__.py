"""
AI-powered analysis modules for supwngo.

Integrates large language models, machine learning, and pattern matching for:
- Vulnerability discovery in decompiled code
- Exploit strategy suggestion
- Pattern recognition from CVE databases
- Vulnerability prediction using ML
"""

from supwngo.ai.llm_analyzer import (
    LLMVulnAnalyzer,
    LLMFinding,
    AnalysisConfig,
    analyze_with_llm,
    VulnSeverity,
    VulnCategory,
)

from supwngo.ai.pattern_learner import (
    CVEPatternLearner,
    PatternDatabase,
    PatternMatch,
    CVEEntry,
    VulnPattern,
    BuiltinPatternMatcher,
)

from supwngo.ai.vuln_predictor import (
    VulnPredictor,
    EnsemblePredictor,
    FeatureExtractor,
    FunctionFeatures,
    VulnPrediction,
    VulnClass,
    predict_vulnerabilities,
)

from supwngo.ai.advisor import (
    ExploitAdvisor,
    ExploitStrategy,
    ExploitStep,
    ExploitTechnique,
    ExploitDifficulty,
    get_exploit_advice,
)

__all__ = [
    # LLM Analyzer
    "LLMVulnAnalyzer",
    "LLMFinding",
    "AnalysisConfig",
    "analyze_with_llm",
    "VulnSeverity",
    "VulnCategory",
    # Pattern Learning
    "CVEPatternLearner",
    "PatternDatabase",
    "PatternMatch",
    "CVEEntry",
    "VulnPattern",
    "BuiltinPatternMatcher",
    # Vulnerability Prediction
    "VulnPredictor",
    "EnsemblePredictor",
    "FeatureExtractor",
    "FunctionFeatures",
    "VulnPrediction",
    "VulnClass",
    "predict_vulnerabilities",
    # Exploit Advisor
    "ExploitAdvisor",
    "ExploitStrategy",
    "ExploitStep",
    "ExploitTechnique",
    "ExploitDifficulty",
    "get_exploit_advice",
]
