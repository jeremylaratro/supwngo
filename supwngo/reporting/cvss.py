"""
CVSS (Common Vulnerability Scoring System) calculator.

Supports CVSS v3.1 scoring for vulnerability assessment.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple
import math

from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


class AttackVector(Enum):
    """CVSS Attack Vector metric."""
    NETWORK = "N"
    ADJACENT = "A"
    LOCAL = "L"
    PHYSICAL = "P"


class AttackComplexity(Enum):
    """CVSS Attack Complexity metric."""
    LOW = "L"
    HIGH = "H"


class PrivilegesRequired(Enum):
    """CVSS Privileges Required metric."""
    NONE = "N"
    LOW = "L"
    HIGH = "H"


class UserInteraction(Enum):
    """CVSS User Interaction metric."""
    NONE = "N"
    REQUIRED = "R"


class Scope(Enum):
    """CVSS Scope metric."""
    UNCHANGED = "U"
    CHANGED = "C"


class Impact(Enum):
    """CVSS Impact metrics (C/I/A)."""
    NONE = "N"
    LOW = "L"
    HIGH = "H"


@dataclass
class CVSSVector:
    """CVSS v3.1 vector components."""
    attack_vector: AttackVector = AttackVector.LOCAL
    attack_complexity: AttackComplexity = AttackComplexity.LOW
    privileges_required: PrivilegesRequired = PrivilegesRequired.NONE
    user_interaction: UserInteraction = UserInteraction.NONE
    scope: Scope = Scope.UNCHANGED
    confidentiality: Impact = Impact.HIGH
    integrity: Impact = Impact.HIGH
    availability: Impact = Impact.HIGH

    def to_string(self) -> str:
        """Convert to CVSS vector string."""
        return (
            f"CVSS:3.1/AV:{self.attack_vector.value}/"
            f"AC:{self.attack_complexity.value}/"
            f"PR:{self.privileges_required.value}/"
            f"UI:{self.user_interaction.value}/"
            f"S:{self.scope.value}/"
            f"C:{self.confidentiality.value}/"
            f"I:{self.integrity.value}/"
            f"A:{self.availability.value}"
        )

    @classmethod
    def from_string(cls, vector_string: str) -> "CVSSVector":
        """Parse CVSS vector string."""
        parts = {}
        for part in vector_string.replace("CVSS:3.1/", "").split("/"):
            if ":" in part:
                key, value = part.split(":", 1)
                parts[key] = value

        return cls(
            attack_vector=AttackVector(parts.get("AV", "L")),
            attack_complexity=AttackComplexity(parts.get("AC", "L")),
            privileges_required=PrivilegesRequired(parts.get("PR", "N")),
            user_interaction=UserInteraction(parts.get("UI", "N")),
            scope=Scope(parts.get("S", "U")),
            confidentiality=Impact(parts.get("C", "N")),
            integrity=Impact(parts.get("I", "N")),
            availability=Impact(parts.get("A", "N")),
        )


@dataclass
class CVSSScore:
    """CVSS score result."""
    base_score: float
    severity: str
    vector: CVSSVector
    vector_string: str
    exploitability_score: float = 0.0
    impact_score: float = 0.0


class CVSSCalculator:
    """
    CVSS v3.1 calculator.

    Example:
        calc = CVSSCalculator()

        # Calculate from vector
        score = calc.calculate(CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.HIGH,
        ))

        print(f"Score: {score.base_score} ({score.severity})")
        print(f"Vector: {score.vector_string}")

        # Calculate from vulnerability type
        score = calc.score_vulnerability("stack_buffer_overflow")
    """

    # Metric weights from CVSS v3.1 specification
    AV_WEIGHTS = {
        AttackVector.NETWORK: 0.85,
        AttackVector.ADJACENT: 0.62,
        AttackVector.LOCAL: 0.55,
        AttackVector.PHYSICAL: 0.2,
    }

    AC_WEIGHTS = {
        AttackComplexity.LOW: 0.77,
        AttackComplexity.HIGH: 0.44,
    }

    # Privileges Required weights depend on Scope
    PR_WEIGHTS_UNCHANGED = {
        PrivilegesRequired.NONE: 0.85,
        PrivilegesRequired.LOW: 0.62,
        PrivilegesRequired.HIGH: 0.27,
    }

    PR_WEIGHTS_CHANGED = {
        PrivilegesRequired.NONE: 0.85,
        PrivilegesRequired.LOW: 0.68,
        PrivilegesRequired.HIGH: 0.50,
    }

    UI_WEIGHTS = {
        UserInteraction.NONE: 0.85,
        UserInteraction.REQUIRED: 0.62,
    }

    IMPACT_WEIGHTS = {
        Impact.NONE: 0.0,
        Impact.LOW: 0.22,
        Impact.HIGH: 0.56,
    }

    # Default vectors for common vulnerability types
    VULN_VECTORS = {
        "stack_buffer_overflow": CVSSVector(
            attack_vector=AttackVector.LOCAL,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.REQUIRED,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.HIGH,
        ),
        "heap_buffer_overflow": CVSSVector(
            attack_vector=AttackVector.LOCAL,
            attack_complexity=AttackComplexity.HIGH,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.REQUIRED,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.HIGH,
        ),
        "format_string": CVSSVector(
            attack_vector=AttackVector.LOCAL,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.REQUIRED,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.LOW,
        ),
        "use_after_free": CVSSVector(
            attack_vector=AttackVector.LOCAL,
            attack_complexity=AttackComplexity.HIGH,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.REQUIRED,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.HIGH,
        ),
        "double_free": CVSSVector(
            attack_vector=AttackVector.LOCAL,
            attack_complexity=AttackComplexity.HIGH,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.REQUIRED,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.HIGH,
        ),
        "integer_overflow": CVSSVector(
            attack_vector=AttackVector.LOCAL,
            attack_complexity=AttackComplexity.HIGH,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.REQUIRED,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.LOW,
            integrity=Impact.HIGH,
            availability=Impact.LOW,
        ),
        "race_condition": CVSSVector(
            attack_vector=AttackVector.LOCAL,
            attack_complexity=AttackComplexity.HIGH,
            privileges_required=PrivilegesRequired.LOW,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.LOW,
        ),
        "command_injection": CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.HIGH,
        ),
        "sql_injection": CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.NONE,
        ),
        "path_traversal": CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.NONE,
            availability=Impact.NONE,
        ),
    }

    def calculate(self, vector: CVSSVector) -> CVSSScore:
        """
        Calculate CVSS v3.1 score from vector.

        Args:
            vector: CVSS vector components

        Returns:
            CVSSScore with base score and severity
        """
        # Calculate Exploitability Sub-score
        if vector.scope == Scope.CHANGED:
            pr_weight = self.PR_WEIGHTS_CHANGED[vector.privileges_required]
        else:
            pr_weight = self.PR_WEIGHTS_UNCHANGED[vector.privileges_required]

        exploitability = (
            8.22 *
            self.AV_WEIGHTS[vector.attack_vector] *
            self.AC_WEIGHTS[vector.attack_complexity] *
            pr_weight *
            self.UI_WEIGHTS[vector.user_interaction]
        )

        # Calculate Impact Sub-score
        isc_base = 1 - (
            (1 - self.IMPACT_WEIGHTS[vector.confidentiality]) *
            (1 - self.IMPACT_WEIGHTS[vector.integrity]) *
            (1 - self.IMPACT_WEIGHTS[vector.availability])
        )

        if vector.scope == Scope.UNCHANGED:
            impact = 6.42 * isc_base
        else:
            impact = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)

        # Calculate Base Score
        if impact <= 0:
            base_score = 0.0
        elif vector.scope == Scope.UNCHANGED:
            base_score = min(exploitability + impact, 10.0)
            base_score = math.ceil(base_score * 10) / 10
        else:
            base_score = min(1.08 * (exploitability + impact), 10.0)
            base_score = math.ceil(base_score * 10) / 10

        # Determine severity
        severity = self._get_severity(base_score)

        return CVSSScore(
            base_score=base_score,
            severity=severity,
            vector=vector,
            vector_string=vector.to_string(),
            exploitability_score=round(exploitability, 1),
            impact_score=round(impact, 1),
        )

    def _get_severity(self, score: float) -> str:
        """Get severity rating from score."""
        if score == 0.0:
            return "None"
        elif score <= 3.9:
            return "Low"
        elif score <= 6.9:
            return "Medium"
        elif score <= 8.9:
            return "High"
        else:
            return "Critical"

    def score_vulnerability(
        self,
        vuln_type: str,
        remote: bool = False,
        auth_required: bool = False,
        user_interaction: bool = True,
    ) -> CVSSScore:
        """
        Calculate CVSS score for a vulnerability type.

        Args:
            vuln_type: Vulnerability type (e.g., "stack_buffer_overflow")
            remote: If True, use Network attack vector
            auth_required: If True, set privileges required
            user_interaction: If True, user interaction required

        Returns:
            CVSSScore for the vulnerability
        """
        # Get base vector for vuln type
        vuln_type_normalized = vuln_type.lower().replace("-", "_").replace(" ", "_")

        if vuln_type_normalized in self.VULN_VECTORS:
            vector = CVSSVector(
                attack_vector=self.VULN_VECTORS[vuln_type_normalized].attack_vector,
                attack_complexity=self.VULN_VECTORS[vuln_type_normalized].attack_complexity,
                privileges_required=self.VULN_VECTORS[vuln_type_normalized].privileges_required,
                user_interaction=self.VULN_VECTORS[vuln_type_normalized].user_interaction,
                scope=self.VULN_VECTORS[vuln_type_normalized].scope,
                confidentiality=self.VULN_VECTORS[vuln_type_normalized].confidentiality,
                integrity=self.VULN_VECTORS[vuln_type_normalized].integrity,
                availability=self.VULN_VECTORS[vuln_type_normalized].availability,
            )
        else:
            # Default vector for unknown types
            vector = CVSSVector()

        # Apply modifiers
        if remote:
            vector.attack_vector = AttackVector.NETWORK

        if auth_required:
            vector.privileges_required = PrivilegesRequired.LOW

        if not user_interaction:
            vector.user_interaction = UserInteraction.NONE

        return self.calculate(vector)

    def score_from_string(self, vector_string: str) -> CVSSScore:
        """
        Calculate score from CVSS vector string.

        Args:
            vector_string: CVSS v3.1 vector string

        Returns:
            CVSSScore
        """
        vector = CVSSVector.from_string(vector_string)
        return self.calculate(vector)

    def adjust_for_protections(
        self,
        score: CVSSScore,
        nx: bool = False,
        canary: bool = False,
        pie: bool = False,
        relro: str = "None",
    ) -> CVSSScore:
        """
        Adjust CVSS score based on binary protections.

        Protections increase attack complexity.

        Args:
            score: Original CVSS score
            nx: NX/DEP enabled
            canary: Stack canary enabled
            pie: PIE/ASLR enabled
            relro: RELRO level

        Returns:
            Adjusted CVSSScore
        """
        vector = CVSSVector(
            attack_vector=score.vector.attack_vector,
            attack_complexity=score.vector.attack_complexity,
            privileges_required=score.vector.privileges_required,
            user_interaction=score.vector.user_interaction,
            scope=score.vector.scope,
            confidentiality=score.vector.confidentiality,
            integrity=score.vector.integrity,
            availability=score.vector.availability,
        )

        # Count active protections
        protection_count = sum([
            nx,
            canary,
            pie,
            relro.lower() in ["partial", "full"],
        ])

        # If multiple protections, increase complexity
        if protection_count >= 2:
            vector.attack_complexity = AttackComplexity.HIGH

        return self.calculate(vector)


def calculate_cvss(vuln_type: str, **kwargs) -> CVSSScore:
    """
    Convenience function to calculate CVSS score.

    Args:
        vuln_type: Vulnerability type
        **kwargs: Additional parameters for scoring

    Returns:
        CVSSScore
    """
    calc = CVSSCalculator()
    return calc.score_vulnerability(vuln_type, **kwargs)
