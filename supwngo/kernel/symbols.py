"""
Kernel symbol resolution and KASLR handling.

Provides tools for:
- Parsing /proc/kallsyms
- Computing KASLR offsets from leaks
- Resolving kernel function addresses
"""

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


# Common kernel symbol offsets (from base)
# These are defaults and should be overridden with actual kernel data
DEFAULT_SYMBOL_OFFSETS = {
    "commit_creds": 0xc8000,
    "prepare_kernel_cred": 0xc8300,
    "find_task_by_vpid": 0xc5230,
    "swapgs_restore_regs_and_return_to_usermode": 0xe00a30,
    "msleep": 0x151d40,
    "init_task": 0x1a12580,
    "init_cred": 0x1a4a4e0,
}

# Common leaked function offsets for KASLR calculation
KASLR_LEAK_FUNCTIONS = {
    "timerfd_tmrproc": 0x3370e0,
    "single_open": 0x472c90,
    "seq_read": 0x4710b0,
    "ksys_read": 0x4831d0,
}


@dataclass
class KernelSymbol:
    """Represents a kernel symbol."""
    name: str
    address: int
    type: str = "T"  # T=text, D=data, B=bss, etc.


@dataclass
class KernelSymbols:
    """
    Kernel symbol management and KASLR handling.

    Works with both:
    - Live system (/proc/kallsyms)
    - Extracted symbol files
    - vmlinux binaries
    """

    # Symbol tables
    symbols: Dict[str, KernelSymbol] = field(default_factory=dict)
    symbols_by_addr: Dict[int, KernelSymbol] = field(default_factory=dict)

    # KASLR state
    kaslr_enabled: bool = True
    kaslr_offset: int = 0
    kernel_base: int = 0
    kernel_text_base: int = 0xffffffff81000000  # Default x86_64

    @classmethod
    def from_kallsyms(cls, path: str = "/proc/kallsyms") -> "KernelSymbols":
        """
        Load symbols from kallsyms file.

        Args:
            path: Path to kallsyms (default: /proc/kallsyms)

        Returns:
            KernelSymbols instance

        Note:
            Reading /proc/kallsyms as non-root returns 0 addresses
            unless /proc/sys/kernel/kptr_restrict is 0
        """
        ksyms = cls()
        ksyms._parse_kallsyms(path)
        return ksyms

    @classmethod
    def from_vmlinux(cls, path: str) -> "KernelSymbols":
        """
        Extract symbols from vmlinux binary.

        Args:
            path: Path to vmlinux

        Returns:
            KernelSymbols instance
        """
        ksyms = cls()
        ksyms._parse_vmlinux(path)
        return ksyms

    @classmethod
    def from_leak(
        cls,
        leaked_func: str,
        leaked_addr: int,
        offset: Optional[int] = None,
    ) -> "KernelSymbols":
        """
        Create symbols table from a kernel address leak.

        Args:
            leaked_func: Name of leaked function
            leaked_addr: Leaked address value
            offset: Known offset of function (or use default)

        Returns:
            KernelSymbols instance with computed base
        """
        ksyms = cls()

        # Get offset for leaked function
        if offset is None:
            offset = KASLR_LEAK_FUNCTIONS.get(leaked_func)
            if offset is None:
                offset = DEFAULT_SYMBOL_OFFSETS.get(leaked_func)

        if offset is None:
            logger.error(f"Unknown symbol offset for {leaked_func}")
            return ksyms

        # Calculate kernel base
        ksyms.kernel_base = leaked_addr - offset
        ksyms.kaslr_offset = ksyms.kernel_base - ksyms.kernel_text_base
        ksyms.kaslr_enabled = ksyms.kaslr_offset != 0

        logger.info(f"Computed kernel base: 0x{ksyms.kernel_base:x}")
        logger.info(f"KASLR offset: 0x{ksyms.kaslr_offset:x}")

        # Populate default symbols with computed base
        for name, off in DEFAULT_SYMBOL_OFFSETS.items():
            addr = ksyms.kernel_base + off
            sym = KernelSymbol(name=name, address=addr)
            ksyms.symbols[name] = sym
            ksyms.symbols_by_addr[addr] = sym

        return ksyms

    def _parse_kallsyms(self, path: str) -> None:
        """Parse kallsyms format."""
        try:
            with open(path, 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        addr = int(parts[0], 16)
                        sym_type = parts[1]
                        name = parts[2]

                        sym = KernelSymbol(name=name, address=addr, type=sym_type)
                        self.symbols[name] = sym
                        if addr != 0:
                            self.symbols_by_addr[addr] = sym

            # Detect kernel base
            if "startup_64" in self.symbols:
                self.kernel_base = self.symbols["startup_64"].address
            elif "_text" in self.symbols:
                self.kernel_base = self.symbols["_text"].address

            if self.kernel_base:
                self.kaslr_offset = self.kernel_base - self.kernel_text_base

            logger.info(f"Loaded {len(self.symbols)} symbols from {path}")

        except PermissionError:
            logger.warning(f"Cannot read {path} - try as root or adjust kptr_restrict")
        except Exception as e:
            logger.error(f"Failed to parse kallsyms: {e}")

    def _parse_vmlinux(self, path: str) -> None:
        """Extract symbols from vmlinux using nm."""
        try:
            result = subprocess.run(
                ["nm", "-n", path],
                capture_output=True,
                text=True,
                timeout=120,
            )

            for line in result.stdout.split('\n'):
                parts = line.strip().split()
                if len(parts) >= 3:
                    try:
                        addr = int(parts[0], 16)
                        sym_type = parts[1]
                        name = parts[2]

                        sym = KernelSymbol(name=name, address=addr, type=sym_type)
                        self.symbols[name] = sym
                        self.symbols_by_addr[addr] = sym
                    except ValueError:
                        continue

            logger.info(f"Loaded {len(self.symbols)} symbols from vmlinux")

        except Exception as e:
            logger.error(f"Failed to parse vmlinux: {e}")

    def resolve(self, name: str) -> int:
        """
        Resolve symbol to address.

        Args:
            name: Symbol name

        Returns:
            Address (with KASLR applied)
        """
        if name in self.symbols:
            return self.symbols[name].address

        # Try with default offset
        if name in DEFAULT_SYMBOL_OFFSETS:
            return self.kernel_base + DEFAULT_SYMBOL_OFFSETS[name]

        raise KeyError(f"Unknown symbol: {name}")

    def resolve_many(self, names: List[str]) -> Dict[str, int]:
        """Resolve multiple symbols."""
        return {name: self.resolve(name) for name in names}

    def lookup_addr(self, addr: int) -> Optional[str]:
        """
        Look up symbol name for address.

        Args:
            addr: Address to look up

        Returns:
            Symbol name or None
        """
        if addr in self.symbols_by_addr:
            return self.symbols_by_addr[addr].name
        return None

    def get_address_info(self, addr: int) -> str:
        """Get human-readable info for address."""
        sym = self.lookup_addr(addr)
        if sym:
            return f"0x{addr:x} <{sym}>"

        # Check if in kernel range
        if self.kernel_base and addr >= self.kernel_base:
            offset = addr - self.kernel_base
            return f"0x{addr:x} (kernel_base+0x{offset:x})"

        return f"0x{addr:x}"

    def find_symbols_by_pattern(self, pattern: str) -> List[KernelSymbol]:
        """Find symbols matching regex pattern."""
        regex = re.compile(pattern, re.IGNORECASE)
        return [sym for sym in self.symbols.values() if regex.search(sym.name)]

    def get_privilege_escalation_targets(self) -> Dict[str, int]:
        """
        Get common privilege escalation target addresses.

        Returns:
            Dict of function name to address
        """
        targets = {}
        pe_funcs = [
            "commit_creds",
            "prepare_kernel_cred",
            "find_task_by_vpid",
            "init_task",
            "init_cred",
            "__x64_sys_setuid",
        ]

        for func in pe_funcs:
            try:
                targets[func] = self.resolve(func)
            except KeyError:
                pass

        return targets

    def get_kpti_trampoline(self) -> Optional[int]:
        """Get KPTI return trampoline address."""
        for name in [
            "swapgs_restore_regs_and_return_to_usermode",
            "entry_SYSCALL_64_after_hwframe",
        ]:
            try:
                return self.resolve(name)
            except KeyError:
                pass
        return None

    def summary(self) -> str:
        """Get symbols summary."""
        lines = [
            "Kernel Symbols",
            "=" * 40,
            f"Total symbols: {len(self.symbols)}",
            f"Kernel base: 0x{self.kernel_base:x}" if self.kernel_base else "Kernel base: unknown",
            f"KASLR offset: 0x{self.kaslr_offset:x}" if self.kaslr_offset else "KASLR offset: 0",
        ]

        targets = self.get_privilege_escalation_targets()
        if targets:
            lines.append("\nPrivilege Escalation Targets:")
            for name, addr in targets.items():
                lines.append(f"  {name}: 0x{addr:x}")

        return "\n".join(lines)
