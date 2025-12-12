"""
Base vulnerability detector classes and data structures.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional

from supwngo.core.binary import Binary
from supwngo.fuzzing.crash_triage import CrashCase


class VulnType(Enum):
    """Types of vulnerabilities."""
    STACK_BUFFER_OVERFLOW = auto()
    HEAP_BUFFER_OVERFLOW = auto()
    USE_AFTER_FREE = auto()
    DOUBLE_FREE = auto()
    FORMAT_STRING = auto()
    INTEGER_OVERFLOW = auto()
    INTEGER_UNDERFLOW = auto()
    NULL_POINTER_DEREF = auto()
    COMMAND_INJECTION = auto()
    PATH_TRAVERSAL = auto()
    RACE_CONDITION = auto()
    UNKNOWN = auto()


class VulnSeverity(Enum):
    """Vulnerability severity ratings."""
    CRITICAL = auto()  # Direct code execution
    HIGH = auto()      # Memory corruption, likely exploitable
    MEDIUM = auto()    # Information disclosure, partial control
    LOW = auto()       # DoS, limited impact
    INFO = auto()      # Potential issue, needs investigation


@dataclass
class ExploitPrimitive:
    """
    Represents an exploitation primitive derived from vulnerability.
    """
    primitive_type: str  # write, read, exec, leak
    target_controllable: bool = False
    value_controllable: bool = False
    size_controllable: bool = False

    # For write primitives
    write_address: Optional[int] = None
    write_size: int = 0

    # For read/leak primitives
    read_address: Optional[int] = None
    read_size: int = 0

    # Constraints
    bad_chars: List[int] = field(default_factory=list)
    alignment_required: int = 0


@dataclass
class Vulnerability:
    """
    Represents a detected vulnerability.
    """
    vuln_type: VulnType
    severity: VulnSeverity
    address: int = 0
    function: str = ""

    # Detection details
    detection_method: str = ""  # static, dynamic, symbolic
    confidence: float = 1.0

    # Exploitation info
    controllable_input: bytes = b""
    offset: int = 0  # Offset to vulnerable buffer/pointer
    size: int = 0    # Size of overflow/controllable region

    # Primitives this vuln provides
    primitives: List[ExploitPrimitive] = field(default_factory=list)

    # Associated crash
    crash: Optional[CrashCase] = None

    # Additional metadata
    description: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "type": self.vuln_type.name,
            "severity": self.severity.name,
            "address": hex(self.address),
            "function": self.function,
            "detection_method": self.detection_method,
            "confidence": self.confidence,
            "offset": self.offset,
            "size": self.size,
            "description": self.description,
        }


class VulnerabilityDetector(ABC):
    """
    Abstract base class for vulnerability detectors.

    Each detector implements specific detection logic for a
    vulnerability class.
    """

    # Detector name
    name: str = "base_detector"

    # Vulnerability type this detector finds
    vuln_type: VulnType = VulnType.UNKNOWN

    def __init__(self, binary: Binary):
        """
        Initialize detector.

        Args:
            binary: Target binary
        """
        self.binary = binary
        self._vulnerabilities: List[Vulnerability] = []

    @abstractmethod
    def detect(
        self,
        crash: Optional[CrashCase] = None,
    ) -> List[Vulnerability]:
        """
        Detect vulnerabilities in binary.

        Args:
            crash: Optional crash case to analyze

        Returns:
            List of detected vulnerabilities
        """
        pass

    @abstractmethod
    def get_exploit_primitive(
        self,
        vuln: Vulnerability,
    ) -> Optional[ExploitPrimitive]:
        """
        Get exploitation primitive for vulnerability.

        Args:
            vuln: Detected vulnerability

        Returns:
            ExploitPrimitive or None
        """
        pass

    def detect_from_crash(
        self,
        crash: CrashCase,
    ) -> Optional[Vulnerability]:
        """
        Detect vulnerability from crash case.

        Args:
            crash: Crash case to analyze

        Returns:
            Detected vulnerability or None
        """
        # Default implementation - subclasses can override
        vulns = self.detect(crash)
        return vulns[0] if vulns else None

    def get_vulnerabilities(self) -> List[Vulnerability]:
        """Get all detected vulnerabilities."""
        return self._vulnerabilities

    def clear(self) -> None:
        """Clear detected vulnerabilities."""
        self._vulnerabilities.clear()

    def summary(self) -> str:
        """Get detection summary."""
        return f"{self.name}: {len(self._vulnerabilities)} vulnerabilities found"


class CompositeDetector:
    """
    Combines multiple vulnerability detectors.
    """

    def __init__(self, binary: Binary):
        """
        Initialize composite detector.

        Args:
            binary: Target binary
        """
        self.binary = binary
        self.detectors: List[VulnerabilityDetector] = []
        self._all_vulns: List[Vulnerability] = []

    def add_detector(self, detector: VulnerabilityDetector) -> None:
        """Add a detector."""
        self.detectors.append(detector)

    def detect_all(
        self,
        crash: Optional[CrashCase] = None,
    ) -> List[Vulnerability]:
        """
        Run all detectors.

        Args:
            crash: Optional crash case

        Returns:
            All detected vulnerabilities
        """
        self._all_vulns.clear()

        for detector in self.detectors:
            vulns = detector.detect(crash)
            self._all_vulns.extend(vulns)

        # Sort by severity
        severity_order = {
            VulnSeverity.CRITICAL: 0,
            VulnSeverity.HIGH: 1,
            VulnSeverity.MEDIUM: 2,
            VulnSeverity.LOW: 3,
            VulnSeverity.INFO: 4,
        }

        self._all_vulns.sort(key=lambda v: severity_order.get(v.severity, 5))

        return self._all_vulns

    def get_best_vulnerability(self) -> Optional[Vulnerability]:
        """Get most exploitable vulnerability."""
        if self._all_vulns:
            return self._all_vulns[0]
        return None

    def summary(self) -> str:
        """Get combined summary."""
        lines = ["Vulnerability Detection Summary", "=" * 40]

        for detector in self.detectors:
            lines.append(detector.summary())

        lines.append(f"\nTotal: {len(self._all_vulns)} vulnerabilities")

        by_type = {}
        for vuln in self._all_vulns:
            type_name = vuln.vuln_type.name
            by_type[type_name] = by_type.get(type_name, 0) + 1

        for type_name, count in by_type.items():
            lines.append(f"  {type_name}: {count}")

        return "\n".join(lines)
