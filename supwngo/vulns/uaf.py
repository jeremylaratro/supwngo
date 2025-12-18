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
from supwngo.vulns.detector import Vulnerability, VulnerabilityDetector
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

    def detect(self) -> List[UAFVuln]:
        """
        Detect UAF vulnerabilities.

        Returns:
            List of detected vulnerabilities
        """
        self.vulnerabilities = []

        # Check for heap functions
        self._check_heap_patterns()

        # Check for C++ patterns
        self._check_cpp_patterns()

        # Check for function pointers
        self._check_function_pointers()

        return self.vulnerabilities

    def _check_heap_patterns(self):
        """Check for dangerous heap usage patterns."""
        try:
            elf = self.binary._elf if hasattr(self.binary, '_elf') else self.binary
            plt = elf.plt if hasattr(elf, 'plt') else {}

            has_malloc = 'malloc' in plt
            has_free = 'free' in plt
            has_calloc = 'calloc' in plt
            has_realloc = 'realloc' in plt

            if has_malloc and has_free:
                # Basic heap exploitation potential
                vuln = UAFVuln(
                    name="heap-uaf-potential",
                    description="Binary uses malloc/free - potential UAF if pointers not cleared",
                    severity="medium",
                    uaf_type=UAFType.HEAP_UAF,
                )
                vuln.exploitation_notes = """
UAF Exploitation:
1. Allocate object A with function pointer/vtable
2. Free object A (pointer not nulled)
3. Allocate object B of same size (reuses A's memory)
4. Use stale pointer to A -> operates on B's data
5. Control function pointer -> code execution

Key requirements:
- Pointer to freed object must remain accessible
- Must be able to allocate same-size chunk after free
- Object must contain controllable function pointer or data
"""
                self.vulnerabilities.append(vuln)

            if has_realloc:
                vuln = UAFVuln(
                    name="realloc-uaf",
                    description="realloc() can free and return new pointer - old pointer becomes dangling",
                    severity="medium",
                    uaf_type=UAFType.HEAP_UAF,
                )
                self.vulnerabilities.append(vuln)

        except Exception as e:
            logger.debug(f"Heap pattern check failed: {e}")

    def _check_cpp_patterns(self):
        """Check for C++ virtual function patterns."""
        try:
            elf = self.binary._elf if hasattr(self.binary, '_elf') else self.binary

            # Check for C++ indicators
            cpp_indicators = [
                '__cxa_pure_virtual',
                '__cxa_throw',
                '__gxx_personality_v0',
                '_ZTV',  # vtable prefix
                '_ZTI',  # typeinfo prefix
            ]

            is_cpp = False
            symbols = elf.symbols if hasattr(elf, 'symbols') else {}

            for indicator in cpp_indicators:
                if any(indicator in str(sym) for sym in symbols):
                    is_cpp = True
                    break

            if is_cpp:
                vuln = UAFVuln(
                    name="cpp-vtable-uaf",
                    description="C++ binary with vtables - UAF can hijack virtual calls",
                    severity="high",
                    uaf_type=UAFType.VTABLE_UAF,
                )
                vuln.exploitation_notes = """
C++ Vtable UAF:
1. Object layout: [vtable_ptr][member1][member2]...
2. Free object (pointer not nulled)
3. Allocate same-size chunk with controlled data
4. First 8 bytes become fake vtable pointer
5. Virtual call dereferences: *(*(obj))[vtable_idx]()
6. Control vtable_ptr + create fake vtable = arbitrary call

Exploitation:
- Need heap leak for ASLR
- Need code/libc address for target
- Fake vtable must be at known address
- Trigger virtual method call on freed object
"""
                self.vulnerabilities.append(vuln)

            # Find vtables
            vtables = self._find_vtables()
            if vtables:
                logger.info(f"Found {len(vtables)} vtables")

        except Exception as e:
            logger.debug(f"C++ pattern check failed: {e}")

    def _find_vtables(self) -> List[VtableInfo]:
        """Find C++ vtables in binary."""
        vtables = []

        try:
            elf = self.binary._elf if hasattr(self.binary, '_elf') else self.binary

            # Look for _ZTV symbols (vtable symbols)
            symbols = elf.symbols if hasattr(elf, 'symbols') else {}

            for name, addr in symbols.items():
                name_str = str(name)
                if name_str.startswith('_ZTV'):
                    # Demangle name
                    class_name = self._demangle_vtable(name_str)

                    vtable = VtableInfo(
                        address=addr if isinstance(addr, int) else addr.address,
                        class_name=class_name,
                        num_entries=0,
                    )

                    # Try to count entries
                    try:
                        vtable_data = elf.read(vtable.address, 0x80)
                        ptr_size = 8 if self.binary.bits == 64 else 4

                        entries = []
                        for i in range(0, len(vtable_data), ptr_size):
                            ptr = int.from_bytes(
                                vtable_data[i:i + ptr_size], 'little'
                            )
                            if ptr == 0:
                                break
                            entries.append(ptr)

                        vtable.entry_addrs = entries
                        vtable.num_entries = len(entries)

                    except Exception:
                        pass

                    vtables.append(vtable)

        except Exception as e:
            logger.debug(f"Vtable finding failed: {e}")

        return vtables

    def _demangle_vtable(self, mangled: str) -> str:
        """Demangle C++ vtable name."""
        # _ZTV followed by length + name
        # e.g., _ZTV4Test -> vtable for Test

        try:
            import subprocess
            result = subprocess.run(
                ['c++filt', mangled],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass

        # Manual basic demangling
        if mangled.startswith('_ZTV'):
            rest = mangled[4:]
            # Extract length prefix
            length = 0
            i = 0
            while i < len(rest) and rest[i].isdigit():
                length = length * 10 + int(rest[i])
                i += 1
            if length > 0 and i + length <= len(rest):
                return f"vtable for {rest[i:i + length]}"

        return mangled

    def _check_function_pointers(self):
        """Check for function pointer arrays that could be hijacked."""
        try:
            elf = self.binary._elf if hasattr(self.binary, '_elf') else self.binary

            # Look for function pointer patterns in .data/.rodata
            # This is heuristic-based

            # Check for known function pointer array patterns
            if hasattr(elf, 'read'):
                # Check .data section for pointer arrays
                data_section = elf.get_section_by_name('.data')
                if data_section:
                    vuln = UAFVuln(
                        name="function-pointer-array",
                        description="Binary has .data section - may contain function pointer arrays",
                        severity="low",
                        uaf_type=UAFType.FUNCTION_PTR,
                    )
                    self.vulnerabilities.append(vuln)

        except Exception as e:
            logger.debug(f"Function pointer check failed: {e}")


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
