"""
Stack buffer overflow detection.
"""

import re
import subprocess
import tempfile
from typing import Any, Dict, List, Optional

from supwngo.core.binary import Binary
from supwngo.fuzzing.crash_triage import CrashCase, CrashType
from supwngo.vulns.detector import (
    ExploitPrimitive,
    Vulnerability,
    VulnerabilityDetector,
    VulnSeverity,
    VulnType,
)
from supwngo.utils.helpers import cyclic, cyclic_find
from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


class StackBufferOverflowDetector(VulnerabilityDetector):
    """
    Detect stack buffer overflow vulnerabilities.

    Detection methods:
    1. Static: Identify dangerous function calls
    2. Dynamic: Analyze crashes for stack smashing
    3. Pattern: Use cyclic patterns to find offsets
    """

    name = "stack_bof_detector"
    vuln_type = VulnType.STACK_BUFFER_OVERFLOW

    # Functions that commonly cause stack overflows
    DANGEROUS_FUNCS = {
        "gets": {"severity": VulnSeverity.CRITICAL, "reason": "No bounds checking"},
        "strcpy": {"severity": VulnSeverity.HIGH, "reason": "No bounds checking"},
        "strcat": {"severity": VulnSeverity.HIGH, "reason": "No bounds checking"},
        "sprintf": {"severity": VulnSeverity.HIGH, "reason": "No length limit"},
        "vsprintf": {"severity": VulnSeverity.HIGH, "reason": "No length limit"},
        "scanf": {"severity": VulnSeverity.HIGH, "reason": "No width specifier"},
        "read": {"severity": VulnSeverity.MEDIUM, "reason": "Size may be unchecked"},
        "recv": {"severity": VulnSeverity.MEDIUM, "reason": "Size may be unchecked"},
    }

    def detect(
        self,
        crash: Optional[CrashCase] = None,
    ) -> List[Vulnerability]:
        """
        Detect stack buffer overflows.

        Args:
            crash: Optional crash case to analyze

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []

        # Static detection
        static_vulns = self._detect_static()
        vulnerabilities.extend(static_vulns)

        # If we have a crash, analyze it
        if crash:
            crash_vuln = self._detect_from_crash(crash)
            if crash_vuln:
                vulnerabilities.append(crash_vuln)

        self._vulnerabilities = vulnerabilities
        return vulnerabilities

    def _detect_static(self) -> List[Vulnerability]:
        """
        Detect potential overflows statically.

        Returns:
            List of potential vulnerabilities
        """
        vulns = []

        for func_name, info in self.DANGEROUS_FUNCS.items():
            if func_name in self.binary.plt:
                vuln = Vulnerability(
                    vuln_type=VulnType.STACK_BUFFER_OVERFLOW,
                    severity=info["severity"],
                    address=self.binary.plt[func_name],
                    function=func_name,
                    detection_method="static",
                    confidence=0.6,  # Lower confidence for static detection
                    description=f"Call to {func_name}(): {info['reason']}",
                )
                vulns.append(vuln)

        return vulns

    def _detect_from_crash(
        self,
        crash: CrashCase,
    ) -> Optional[Vulnerability]:
        """
        Detect overflow from crash.

        Args:
            crash: Crash case

        Returns:
            Vulnerability if detected
        """
        # Check if crash indicates stack overflow
        if crash.crash_type not in [
            CrashType.STACK_BUFFER_OVERFLOW,
            CrashType.UNKNOWN,
        ]:
            # Check for PC control patterns
            if not crash.pc_control:
                return None

        # Try to find offset using pattern
        offset = self._find_overflow_offset(crash)

        if offset is None:
            # Try with cyclic pattern
            offset = self._find_offset_with_cyclic()

        vuln = Vulnerability(
            vuln_type=VulnType.STACK_BUFFER_OVERFLOW,
            severity=VulnSeverity.CRITICAL if crash.pc_control else VulnSeverity.HIGH,
            address=crash.crash_address,
            detection_method="dynamic",
            confidence=0.9,
            controllable_input=crash.input_data,
            offset=offset or 0,
            crash=crash,
            description="Stack buffer overflow detected from crash",
            details={
                "pc_control": crash.pc_control,
                "signal": crash.signal,
                "registers": crash.registers,
            },
        )

        # Add exploit primitive
        if crash.pc_control:
            primitive = ExploitPrimitive(
                primitive_type="exec",
                target_controllable=True,
                value_controllable=True,
            )
            vuln.primitives.append(primitive)

        return vuln

    def _find_overflow_offset(
        self,
        crash: CrashCase,
    ) -> Optional[int]:
        """
        Find offset to return address.

        Args:
            crash: Crash case

        Returns:
            Offset or None
        """
        if not crash.input_data:
            return None

        # Check if crash address is in input
        crash_addr = crash.crash_address
        if crash_addr == 0:
            return None

        # Convert address to bytes (both endiannesses)
        addr_bytes_le = crash_addr.to_bytes(
            8 if self.binary.bits == 64 else 4,
            'little',
        )
        addr_bytes_be = crash_addr.to_bytes(
            8 if self.binary.bits == 64 else 4,
            'big',
        )

        # Search in input
        offset = crash.input_data.find(addr_bytes_le)
        if offset >= 0:
            return offset

        offset = crash.input_data.find(addr_bytes_be)
        if offset >= 0:
            return offset

        # Try cyclic pattern detection
        return cyclic_find(crash_addr)

    def _find_offset_with_cyclic(
        self,
        max_length: int = 1000,
    ) -> Optional[int]:
        """
        Find offset using cyclic pattern.

        Args:
            max_length: Maximum pattern length

        Returns:
            Offset or None
        """
        pattern = cyclic(max_length)

        # Run binary with pattern
        try:
            with tempfile.NamedTemporaryFile(delete=False) as f:
                f.write(pattern)
                input_file = f.name

            # Use GDB to get crash info
            gdb_script = f"""
set pagination off
run < {input_file}
printf "RIP:0x%lx\\n", $rip
printf "RSP:0x%lx\\n", $rsp
quit
"""
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.gdb') as f:
                f.write(gdb_script)
                gdb_file = f.name

            result = subprocess.run(
                ["gdb", "-batch", "-x", gdb_file, str(self.binary.path)],
                capture_output=True,
                timeout=30,
                text=True,
            )

            # Parse RIP value
            output = result.stdout + result.stderr
            rip_match = re.search(r"RIP:(0x[0-9a-f]+)", output)
            if rip_match:
                rip = int(rip_match.group(1), 16)
                offset = cyclic_find(rip)
                if offset >= 0:
                    return offset

        except Exception as e:
            logger.debug(f"Cyclic offset detection failed: {e}")

        return None

    def get_exploit_primitive(
        self,
        vuln: Vulnerability,
    ) -> Optional[ExploitPrimitive]:
        """
        Get exploitation primitive.

        Args:
            vuln: Vulnerability

        Returns:
            ExploitPrimitive
        """
        if vuln.primitives:
            return vuln.primitives[0]

        # Create primitive based on vulnerability
        primitive = ExploitPrimitive(
            primitive_type="exec",
            target_controllable=True,
        )

        # Check for constraints
        if vuln.crash and vuln.crash.input_data:
            # Detect bad characters
            primitive.bad_chars = self._find_bad_chars(vuln.crash.input_data)

        return primitive

    def _find_bad_chars(
        self,
        input_data: bytes,
    ) -> List[int]:
        """
        Identify bad characters that get filtered.

        Args:
            input_data: Input that caused crash

        Returns:
            List of bad byte values
        """
        bad_chars = [0x00]  # Null is almost always bad

        # Common bad characters to check
        test_chars = [0x0a, 0x0d, 0x20, 0x09]

        for char in test_chars:
            if char not in input_data:
                continue

            # Test if character gets through
            # This is a simplified check
            if char in [0x0a, 0x0d]:  # Newlines often terminate input
                bad_chars.append(char)

        return bad_chars

    def find_canary_offset(
        self,
        vuln: Vulnerability,
    ) -> Optional[int]:
        """
        Find offset to stack canary.

        Args:
            vuln: Stack overflow vulnerability

        Returns:
            Canary offset or None
        """
        if not self.binary.protections.canary:
            return None

        # Canary is typically at [rbp-8] or similar
        # This would require more sophisticated analysis
        # For now, return heuristic based on offset

        if vuln.offset:
            # Canary is usually before saved RBP
            # 64-bit: offset - 16 (8 for canary + 8 for RBP)
            # 32-bit: offset - 8 (4 for canary + 4 for EBP)
            if self.binary.bits == 64:
                return vuln.offset - 16
            else:
                return vuln.offset - 8

        return None

    def summary(self) -> str:
        """Get detection summary."""
        return f"""
Stack Buffer Overflow Detection
===============================
Binary: {self.binary.path.name}
Canary: {'Yes' if self.binary.protections.canary else 'No'}
NX: {'Yes' if self.binary.protections.nx else 'No'}

Dangerous functions found: {sum(1 for f in self.DANGEROUS_FUNCS if f in self.binary.plt)}
Vulnerabilities detected: {len(self._vulnerabilities)}
"""
