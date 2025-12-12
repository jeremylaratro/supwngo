"""
Heap vulnerability detection (UAF, double-free, overflow).
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from autopwn.core.binary import Binary
from autopwn.fuzzing.crash_triage import CrashCase, CrashType
from autopwn.vulns.detector import (
    ExploitPrimitive,
    Vulnerability,
    VulnerabilityDetector,
    VulnSeverity,
    VulnType,
)
from autopwn.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class HeapChunk:
    """Represents a heap chunk."""
    address: int
    size: int
    data: bytes = b""
    freed: bool = False
    allocation_site: int = 0
    free_site: int = 0


@dataclass
class HeapState:
    """Tracks heap state during analysis."""
    chunks: Dict[int, HeapChunk] = field(default_factory=dict)
    freed_chunks: Set[int] = field(default_factory=set)
    tcache_entries: Dict[int, List[int]] = field(default_factory=dict)


class HeapVulnerabilityDetector(VulnerabilityDetector):
    """
    Detect heap vulnerabilities.

    Detection methods:
    1. Static: Track malloc/free patterns
    2. Dynamic: Instrument heap operations
    3. Crash analysis: Identify heap corruption
    """

    name = "heap_detector"
    vuln_type = VulnType.HEAP_BUFFER_OVERFLOW

    # Heap-related functions
    ALLOC_FUNCS = ["malloc", "calloc", "realloc", "memalign", "aligned_alloc"]
    FREE_FUNCS = ["free", "cfree"]

    def __init__(self, binary: Binary):
        """Initialize detector."""
        super().__init__(binary)
        self._heap_state = HeapState()

    def detect(
        self,
        crash: Optional[CrashCase] = None,
    ) -> List[Vulnerability]:
        """
        Detect heap vulnerabilities.

        Args:
            crash: Optional crash case

        Returns:
            List of vulnerabilities
        """
        vulnerabilities = []

        # Static detection
        static_vulns = self._detect_static()
        vulnerabilities.extend(static_vulns)

        # Crash analysis
        if crash:
            crash_vuln = self._detect_from_crash(crash)
            if crash_vuln:
                vulnerabilities.append(crash_vuln)

        self._vulnerabilities = vulnerabilities
        return vulnerabilities

    def _detect_static(self) -> List[Vulnerability]:
        """
        Static heap vulnerability detection.

        Returns:
            Potential vulnerabilities
        """
        vulns = []

        # Check for heap-related functions
        has_alloc = any(f in self.binary.plt for f in self.ALLOC_FUNCS)
        has_free = any(f in self.binary.plt for f in self.FREE_FUNCS)

        if not (has_alloc and has_free):
            return vulns

        # Check for potential double-free patterns
        # This would require CFG analysis
        # For now, just note that heap ops exist

        vuln = Vulnerability(
            vuln_type=VulnType.HEAP_BUFFER_OVERFLOW,
            severity=VulnSeverity.MEDIUM,
            detection_method="static",
            confidence=0.3,
            description="Binary uses heap operations - potential heap vulnerabilities",
            details={
                "alloc_funcs": [f for f in self.ALLOC_FUNCS if f in self.binary.plt],
                "free_funcs": [f for f in self.FREE_FUNCS if f in self.binary.plt],
            },
        )
        vulns.append(vuln)

        return vulns

    def _detect_from_crash(
        self,
        crash: CrashCase,
    ) -> Optional[Vulnerability]:
        """
        Detect heap vuln from crash.

        Args:
            crash: Crash case

        Returns:
            Vulnerability or None
        """
        # Check crash type
        heap_types = [
            CrashType.HEAP_BUFFER_OVERFLOW,
            CrashType.USE_AFTER_FREE,
            CrashType.DOUBLE_FREE,
        ]

        vuln_type = VulnType.HEAP_BUFFER_OVERFLOW

        if crash.crash_type == CrashType.USE_AFTER_FREE:
            vuln_type = VulnType.USE_AFTER_FREE
        elif crash.crash_type == CrashType.DOUBLE_FREE:
            vuln_type = VulnType.DOUBLE_FREE
        elif crash.crash_type not in heap_types:
            # Check backtrace for heap indicators
            bt_funcs = " ".join(f.get("function", "") for f in crash.backtrace)

            if "malloc" in bt_funcs or "free" in bt_funcs:
                # Likely heap corruption
                pass
            elif crash.signal == "SIGABRT":
                # SIGABRT often from glibc heap checks
                pass
            else:
                return None

        vuln = Vulnerability(
            vuln_type=vuln_type,
            severity=VulnSeverity.CRITICAL,
            address=crash.crash_address,
            detection_method="dynamic",
            confidence=0.8,
            controllable_input=crash.input_data,
            crash=crash,
            description=f"Heap vulnerability detected: {vuln_type.name}",
            details={
                "signal": crash.signal,
                "backtrace": crash.backtrace[:5],
            },
        )

        # Add primitives based on type
        if vuln_type == VulnType.USE_AFTER_FREE:
            primitive = ExploitPrimitive(
                primitive_type="write",
                target_controllable=True,
                value_controllable=True,
            )
            vuln.primitives.append(primitive)
        elif vuln_type == VulnType.DOUBLE_FREE:
            primitive = ExploitPrimitive(
                primitive_type="write",
                target_controllable=True,
            )
            vuln.primitives.append(primitive)

        return vuln

    def get_exploit_primitive(
        self,
        vuln: Vulnerability,
    ) -> Optional[ExploitPrimitive]:
        """Get exploitation primitive."""
        if vuln.primitives:
            return vuln.primitives[0]

        # Create based on vuln type
        if vuln.vuln_type == VulnType.USE_AFTER_FREE:
            return ExploitPrimitive(
                primitive_type="write",
                target_controllable=True,
                value_controllable=True,
            )
        elif vuln.vuln_type == VulnType.DOUBLE_FREE:
            return ExploitPrimitive(
                primitive_type="write",
                target_controllable=True,
            )
        elif vuln.vuln_type == VulnType.HEAP_BUFFER_OVERFLOW:
            return ExploitPrimitive(
                primitive_type="write",
                size_controllable=True,
            )

        return None

    def analyze_heap_state(
        self,
        crash: CrashCase,
    ) -> HeapState:
        """
        Analyze heap state from crash.

        Args:
            crash: Crash case

        Returns:
            HeapState
        """
        # This would require heap forensics
        # For now, return empty state
        return self._heap_state

    def suggest_technique(
        self,
        vuln: Vulnerability,
        libc_version: str = "",
    ) -> List[str]:
        """
        Suggest exploitation techniques.

        Args:
            vuln: Heap vulnerability
            libc_version: Target libc version

        Returns:
            List of suggested techniques
        """
        techniques = []

        # Parse libc version
        major, minor = 2, 31  # Default
        if libc_version:
            try:
                parts = libc_version.split(".")
                major = int(parts[0])
                minor = int(parts[1]) if len(parts) > 1 else 0
            except ValueError:
                pass

        # UAF techniques
        if vuln.vuln_type == VulnType.USE_AFTER_FREE:
            if major == 2 and minor >= 26:
                techniques.append("tcache_poisoning")
            techniques.append("fastbin_dup")
            techniques.append("unsorted_bin_attack")

        # Double-free techniques
        elif vuln.vuln_type == VulnType.DOUBLE_FREE:
            if major == 2 and minor >= 26:
                techniques.append("tcache_dup")
                if minor >= 32:
                    techniques.append("safe_linking_bypass")
            else:
                techniques.append("fastbin_dup")

        # Overflow techniques
        elif vuln.vuln_type == VulnType.HEAP_BUFFER_OVERFLOW:
            techniques.append("house_of_force")
            techniques.append("house_of_einherjar")
            techniques.append("unsorted_bin_attack")

        return techniques

    def summary(self) -> str:
        """Get detection summary."""
        return f"""
Heap Vulnerability Detection
============================
Binary: {self.binary.path.name}

Heap functions:
  Allocators: {[f for f in self.ALLOC_FUNCS if f in self.binary.plt]}
  Free funcs: {[f for f in self.FREE_FUNCS if f in self.binary.plt]}

Vulnerabilities: {len(self._vulnerabilities)}
"""
