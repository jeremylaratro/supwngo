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

    # Functions that ALWAYS indicate vulnerability (no false positives)
    CRITICAL_FUNCS = {
        "gets": {"severity": VulnSeverity.CRITICAL, "reason": "Always vulnerable - no bounds checking"},
    }

    # Functions that MAY indicate vulnerability (needs additional evidence)
    # These are NOT reported unless combined with other indicators
    SUSPECT_FUNCS = {
        "strcpy": {"severity": VulnSeverity.HIGH, "reason": "No bounds checking"},
        "strcat": {"severity": VulnSeverity.HIGH, "reason": "No bounds checking"},
        "sprintf": {"severity": VulnSeverity.HIGH, "reason": "No length limit"},
        "vsprintf": {"severity": VulnSeverity.HIGH, "reason": "No length limit"},
        "scanf": {"severity": VulnSeverity.HIGH, "reason": "No width specifier"},
    }

    # Functions that are only dangerous in specific contexts (low confidence)
    CONTEXT_FUNCS = {
        "read": {"severity": VulnSeverity.LOW, "reason": "Size may be unchecked"},
        "recv": {"severity": VulnSeverity.LOW, "reason": "Size may be unchecked"},
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
        Detect potential stack buffer overflows statically.

        Detection approach:
        1. CRITICAL functions (gets) - always vulnerable, high confidence
        2. SUSPECT functions (strcpy, etc.) - report with medium confidence
        3. CONTEXT functions (read, recv) - report with low confidence

        Protections affect severity/confidence, NOT whether we report.
        A vulnerability exists regardless of mitigations - they just affect exploitation.

        Returns:
            List of potential vulnerabilities
        """
        vulns = []

        # Calculate confidence modifier based on protections
        # More protections = harder to exploit = lower confidence in practical impact
        protection_penalty = 0.0
        mitigations = []
        if self.binary.protections.canary:
            protection_penalty += 0.15
            mitigations.append("canary")
        if self.binary.protections.pie:
            protection_penalty += 0.1
            mitigations.append("PIE")
        if self.binary.protections.nx:
            protection_penalty += 0.05
            mitigations.append("NX")

        # Check for CRITICAL functions (always report - definitively vulnerable)
        for func_name, info in self.CRITICAL_FUNCS.items():
            if func_name in self.binary.plt:
                confidence = max(0.5, 0.95 - protection_penalty)
                vuln = Vulnerability(
                    vuln_type=VulnType.STACK_BUFFER_OVERFLOW,
                    severity=info["severity"],
                    address=self.binary.plt[func_name],
                    function=func_name,
                    detection_method="static",
                    confidence=confidence,
                    description=f"Call to {func_name}(): {info['reason']}",
                    details={"mitigations": mitigations} if mitigations else {},
                )
                vulns.append(vuln)

        # Check for SUSPECT functions (likely vulnerable if used with user input)
        for func_name, info in self.SUSPECT_FUNCS.items():
            if func_name in self.binary.plt:
                confidence = max(0.3, 0.6 - protection_penalty)
                vuln = Vulnerability(
                    vuln_type=VulnType.STACK_BUFFER_OVERFLOW,
                    severity=info["severity"] if not mitigations else VulnSeverity.MEDIUM,
                    address=self.binary.plt[func_name],
                    function=func_name,
                    detection_method="static",
                    confidence=confidence,
                    description=f"Potential overflow: {func_name}() - {info['reason']}",
                    details={"mitigations": mitigations} if mitigations else {},
                )
                vulns.append(vuln)
                break  # Only report once to reduce noise

        # Check for CONTEXT functions (possible overflow, needs dynamic confirmation)
        # Unlike gets/strcpy, read/recv aren't inherently dangerous - depends on size parameter
        # Only flag if binary lacks major protections (likely CTF/test binary)
        # With full protections + no other evidence = too many false positives
        has_major_protection = self.binary.protections.canary and self.binary.protections.pie

        if not has_major_protection:
            for func_name, info in self.CONTEXT_FUNCS.items():
                if func_name in self.binary.plt:
                    confidence = max(0.2, 0.4 - protection_penalty)
                    vuln = Vulnerability(
                        vuln_type=VulnType.STACK_BUFFER_OVERFLOW,
                        severity=VulnSeverity.LOW,
                        address=self.binary.plt[func_name],
                        function=func_name,
                        detection_method="static",
                        confidence=confidence,
                        description=f"Potential overflow via {func_name}() - {info['reason']}",
                        details={
                            "mitigations": mitigations,
                            "note": "Needs dynamic testing to confirm",
                        } if mitigations else {"note": "Needs dynamic testing to confirm"},
                    )
                    vulns.append(vuln)
                    break  # Only report once

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
        all_dangerous = {**self.CRITICAL_FUNCS, **self.SUSPECT_FUNCS, **self.CONTEXT_FUNCS}
        return f"""
Stack Buffer Overflow Detection
===============================
Binary: {self.binary.path.name}
Canary: {'Yes' if self.binary.protections.canary else 'No'}
NX: {'Yes' if self.binary.protections.nx else 'No'}

Dangerous functions found: {sum(1 for f in all_dangerous if f in self.binary.plt)}
Vulnerabilities detected: {len(self._vulnerabilities)}
"""
