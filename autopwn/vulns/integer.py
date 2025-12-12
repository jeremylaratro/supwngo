"""
Integer overflow/underflow vulnerability detection.
"""

from typing import Any, Dict, List, Optional

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


class IntegerOverflowDetector(VulnerabilityDetector):
    """
    Detect integer overflow/underflow vulnerabilities.

    These can lead to:
    - Buffer overflows (when used as size)
    - Heap corruption (when used in allocation)
    - Logic bugs
    """

    name = "integer_overflow_detector"
    vuln_type = VulnType.INTEGER_OVERFLOW

    # Functions where integer overflow is dangerous
    DANGEROUS_SIZE_FUNCS = [
        "malloc", "calloc", "realloc",
        "memcpy", "memmove", "memset",
        "read", "write", "recv", "send",
        "strncpy", "strncat", "snprintf",
    ]

    # Arithmetic operations to look for
    ARITHMETIC_OPS = [
        "add", "sub", "mul", "imul",
        "shl", "sal",  # Left shifts can overflow
    ]

    def detect(
        self,
        crash: Optional[CrashCase] = None,
    ) -> List[Vulnerability]:
        """
        Detect integer overflow vulnerabilities.

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
        Static integer overflow detection.

        Returns:
            Potential vulnerabilities
        """
        vulns = []

        # Check for functions that use sizes
        for func_name in self.DANGEROUS_SIZE_FUNCS:
            if func_name in self.binary.plt:
                vuln = Vulnerability(
                    vuln_type=VulnType.INTEGER_OVERFLOW,
                    severity=VulnSeverity.MEDIUM,
                    address=self.binary.plt[func_name],
                    function=func_name,
                    detection_method="static",
                    confidence=0.3,
                    description=f"Function {func_name} uses size parameter - potential integer overflow",
                )
                vulns.append(vuln)

        return vulns

    def _detect_from_crash(
        self,
        crash: CrashCase,
    ) -> Optional[Vulnerability]:
        """
        Detect integer overflow from crash.

        Args:
            crash: Crash case

        Returns:
            Vulnerability or None
        """
        # SIGFPE indicates arithmetic error
        if crash.crash_type == CrashType.INTEGER_OVERFLOW:
            vuln = Vulnerability(
                vuln_type=VulnType.INTEGER_OVERFLOW,
                severity=VulnSeverity.MEDIUM,
                address=crash.crash_address,
                detection_method="crash",
                confidence=0.9,
                controllable_input=crash.input_data,
                crash=crash,
                description="Integer overflow detected from SIGFPE",
            )
            return vuln

        # Check for signs of integer overflow leading to heap issues
        if crash.signal == "SIGFPE":
            vuln = Vulnerability(
                vuln_type=VulnType.INTEGER_OVERFLOW,
                severity=VulnSeverity.MEDIUM,
                address=crash.crash_address,
                detection_method="crash",
                confidence=0.85,
                controllable_input=crash.input_data,
                crash=crash,
                description="Arithmetic exception - possible integer overflow",
            )
            return vuln

        # Check backtrace for allocation with unusual sizes
        bt_funcs = " ".join(f.get("function", "") for f in crash.backtrace)
        if "malloc" in bt_funcs or "calloc" in bt_funcs:
            # Could be integer overflow in size calculation
            vuln = Vulnerability(
                vuln_type=VulnType.INTEGER_OVERFLOW,
                severity=VulnSeverity.HIGH,
                address=crash.crash_address,
                detection_method="crash",
                confidence=0.6,
                controllable_input=crash.input_data,
                crash=crash,
                description="Possible integer overflow in allocation size",
            )
            return vuln

        return None

    def get_exploit_primitive(
        self,
        vuln: Vulnerability,
    ) -> Optional[ExploitPrimitive]:
        """Get exploitation primitive."""
        # Integer overflow typically leads to other primitives
        if vuln.primitives:
            return vuln.primitives[0]

        # Most commonly leads to buffer overflow
        return ExploitPrimitive(
            primitive_type="write",
            size_controllable=True,
        )

    def find_overflow_patterns(self) -> List[Dict[str, Any]]:
        """
        Find potential integer overflow patterns.

        Returns:
            List of pattern matches
        """
        patterns = []

        try:
            # Use angr to find arithmetic near allocation calls
            engine = self.binary.get_angr_project()
            cfg = engine.analyses.CFGFast()

            for func_name in ["malloc", "calloc"]:
                if func_name in self.binary.plt:
                    plt_addr = self.binary.plt[func_name]

                    # Find callers
                    for func_addr, func in cfg.kb.functions.items():
                        if plt_addr in [b.addr for b in func.blocks]:
                            patterns.append({
                                "function": func.name,
                                "address": func_addr,
                                "calls": func_name,
                                "risk": "medium",
                            })

        except Exception as e:
            logger.debug(f"Pattern analysis failed: {e}")

        return patterns

    def generate_test_cases(self) -> List[bytes]:
        """
        Generate test cases for integer overflow.

        Returns:
            List of test inputs
        """
        test_cases = []

        # Maximum values for different sizes
        max_values = [
            0x7F,           # signed char max
            0xFF,           # unsigned char max
            0x7FFF,         # signed short max
            0xFFFF,         # unsigned short max
            0x7FFFFFFF,     # signed int max
            0xFFFFFFFF,     # unsigned int max
            0x7FFFFFFFFFFFFFFF,  # signed long max
        ]

        # Values that might overflow when multiplied or added
        overflow_vals = [
            0x40000000,  # Large value * 2 = overflow
            0x20000001,  # Causes overflow when * 8 (common element size)
            0xFFFFFFFF - 0x10,  # Near max, might wrap with addition
        ]

        for val in max_values + overflow_vals:
            # Convert to different formats
            test_cases.append(str(val).encode() + b"\n")
            test_cases.append(hex(val).encode() + b"\n")

            # Try negative values
            test_cases.append(str(-1).encode() + b"\n")
            test_cases.append(str(-(val + 1)).encode() + b"\n")

        return test_cases

    def summary(self) -> str:
        """Get detection summary."""
        size_funcs = [f for f in self.DANGEROUS_SIZE_FUNCS if f in self.binary.plt]

        return f"""
Integer Overflow Detection
==========================
Binary: {self.binary.path.name}

Size-dependent functions: {size_funcs}
Vulnerabilities: {len(self._vulnerabilities)}
"""
