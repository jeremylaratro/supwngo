"""
Useful Address Finder for Binary Exploitation.

Finds addresses useful for exploitation including:
- /bin/sh and other shell strings
- Writable memory regions (BSS, data)
- GOT/PLT entries
- mprotect targets
- stdin/stdout/stderr
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple, Any

if TYPE_CHECKING:
    from supwngo.core.binary import Binary

from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class UsefulAddress:
    """A useful address with metadata."""
    name: str
    address: int
    section: str = ""
    permissions: str = ""  # "rwx"
    size: int = 0
    notes: str = ""

    def __str__(self) -> str:
        perm = f" [{self.permissions}]" if self.permissions else ""
        return f"{self.name}: 0x{self.address:x}{perm}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "address": hex(self.address),
            "section": self.section,
            "permissions": self.permissions,
            "size": self.size,
            "notes": self.notes,
        }


@dataclass
class WritableRegion:
    """A writable memory region."""
    name: str
    start: int
    end: int
    permissions: str = "rw-"

    @property
    def size(self) -> int:
        return self.end - self.start

    def contains(self, addr: int) -> bool:
        return self.start <= addr < self.end

    def __str__(self) -> str:
        return f"{self.name}: 0x{self.start:x}-0x{self.end:x} ({self.size} bytes)"


@dataclass
class AddressReport:
    """Report of useful addresses found."""
    binary_path: str
    arch: str
    bits: int

    # Useful strings
    binsh_addr: Optional[int] = None
    binbash_addr: Optional[int] = None
    sh_addr: Optional[int] = None
    flag_strings: List[UsefulAddress] = field(default_factory=list)

    # Writable regions
    bss_addr: Optional[int] = None
    bss_size: int = 0
    data_addr: Optional[int] = None
    data_size: int = 0
    writable_regions: List[WritableRegion] = field(default_factory=list)

    # GOT/PLT
    got_entries: Dict[str, int] = field(default_factory=dict)
    plt_entries: Dict[str, int] = field(default_factory=dict)

    # Special addresses
    mprotect_target: Optional[int] = None
    shellcode_target: Optional[int] = None
    stdin_addr: Optional[int] = None
    stdout_addr: Optional[int] = None
    stderr_addr: Optional[int] = None

    # All useful addresses
    all_addresses: List[UsefulAddress] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "binary_path": self.binary_path,
            "arch": self.arch,
            "bits": self.bits,
            "binsh_addr": hex(self.binsh_addr) if self.binsh_addr else None,
            "bss_addr": hex(self.bss_addr) if self.bss_addr else None,
            "bss_size": self.bss_size,
            "mprotect_target": hex(self.mprotect_target) if self.mprotect_target else None,
            "got_entries": {k: hex(v) for k, v in self.got_entries.items()},
            "plt_entries": {k: hex(v) for k, v in self.plt_entries.items()},
            "writable_regions": [str(r) for r in self.writable_regions],
            "all_addresses": [a.to_dict() for a in self.all_addresses],
        }

    def summary(self) -> str:
        """Generate human-readable summary."""
        lines = [
            f"Address Report for {self.binary_path}",
            f"Architecture: {self.arch} ({self.bits}-bit)",
            "",
            "=== Useful Strings ===",
        ]

        if self.binsh_addr:
            lines.append(f"  /bin/sh: 0x{self.binsh_addr:x}")
        if self.binbash_addr:
            lines.append(f"  /bin/bash: 0x{self.binbash_addr:x}")
        if self.sh_addr:
            lines.append(f"  sh: 0x{self.sh_addr:x}")

        lines.append("")
        lines.append("=== Writable Regions ===")
        if self.bss_addr:
            lines.append(f"  BSS: 0x{self.bss_addr:x} ({self.bss_size} bytes)")
        if self.data_addr:
            lines.append(f"  Data: 0x{self.data_addr:x} ({self.data_size} bytes)")
        for region in self.writable_regions[:5]:
            lines.append(f"  {region}")

        lines.append("")
        lines.append("=== Exploitation Targets ===")
        if self.mprotect_target:
            lines.append(f"  mprotect target: 0x{self.mprotect_target:x}")
        if self.shellcode_target:
            lines.append(f"  shellcode target: 0x{self.shellcode_target:x}")

        if self.got_entries:
            lines.append("")
            lines.append("=== GOT Entries ===")
            for name, addr in list(self.got_entries.items())[:10]:
                lines.append(f"  {name}: 0x{addr:x}")

        return "\n".join(lines)


class AddressFinder:
    """Find useful addresses in a binary for exploitation."""

    # Common shell strings to search for
    SHELL_STRINGS = [
        "/bin/sh",
        "/bin/bash",
        "/bin/dash",
        "sh",
        "/bin//sh",
        "//bin/sh",
    ]

    # Common flag patterns
    FLAG_PATTERNS = [
        "flag",
        "FLAG",
        "/flag",
        "flag.txt",
        "/home/",
        "/root/",
    ]

    # Useful libc symbols
    USEFUL_LIBC_SYMBOLS = [
        "system",
        "execve",
        "execl",
        "execv",
        "popen",
        "mprotect",
        "mmap",
        "read",
        "write",
        "open",
        "close",
        "puts",
        "printf",
        "gets",
        "fgets",
        "scanf",
        "__libc_start_main",
        "_IO_2_1_stdin_",
        "_IO_2_1_stdout_",
        "_IO_2_1_stderr_",
    ]

    def __init__(self, binary: "Binary"):
        """
        Initialize address finder.

        Args:
            binary: Target binary
        """
        self.binary = binary
        self._report: Optional[AddressReport] = None

    def find_all(self) -> AddressReport:
        """
        Find all useful addresses.

        Returns:
            AddressReport with all findings
        """
        report = AddressReport(
            binary_path=str(self.binary.path),
            arch=self.binary.arch,
            bits=self.binary.bits,
        )

        # Find shell strings
        self._find_shell_strings(report)

        # Find writable regions
        self._find_writable_regions(report)

        # Find GOT/PLT entries
        self._find_got_plt(report)

        # Calculate exploitation targets
        self._calculate_targets(report)

        # Find special addresses
        self._find_special_addresses(report)

        self._report = report
        return report

    def _find_shell_strings(self, report: AddressReport):
        """Find shell strings in binary."""
        for s in self.SHELL_STRINGS:
            addr = self._search_string(s)
            if addr:
                ua = UsefulAddress(
                    name=s,
                    address=addr,
                    notes="Shell string for execve",
                )
                report.all_addresses.append(ua)

                if s == "/bin/sh":
                    report.binsh_addr = addr
                elif s == "/bin/bash":
                    report.binbash_addr = addr
                elif s == "sh":
                    report.sh_addr = addr

                logger.info(f"Found '{s}' @ 0x{addr:x}")

    def _find_writable_regions(self, report: AddressReport):
        """Find writable memory regions."""
        # From sections
        for name, section in self.binary.sections.items():
            if section.is_writable and section.size > 0:
                region = WritableRegion(
                    name=name,
                    start=section.address,
                    end=section.address + section.size,
                    permissions="rw-",
                )
                report.writable_regions.append(region)

                if name == ".bss":
                    report.bss_addr = section.address
                    report.bss_size = section.size
                elif name == ".data":
                    report.data_addr = section.address
                    report.data_size = section.size

    def _find_got_plt(self, report: AddressReport):
        """Find GOT and PLT entries."""
        report.got_entries = dict(self.binary.got)
        report.plt_entries = dict(self.binary.plt)

        # Add as useful addresses
        for name, addr in self.binary.got.items():
            report.all_addresses.append(UsefulAddress(
                name=f"GOT:{name}",
                address=addr,
                section=".got",
                notes="GOT entry - can be overwritten for control flow hijack",
            ))

        for name, addr in self.binary.plt.items():
            report.all_addresses.append(UsefulAddress(
                name=f"PLT:{name}",
                address=addr,
                section=".plt",
                notes="PLT entry - call to invoke function",
            ))

    def _calculate_targets(self, report: AddressReport):
        """Calculate exploitation targets."""
        # mprotect target - page-aligned writable address
        if report.bss_addr:
            # Page-align BSS address
            page_size = 0x1000
            report.mprotect_target = report.bss_addr & ~(page_size - 1)

            # Shellcode target - some offset into BSS
            report.shellcode_target = report.bss_addr + 0x100

        # If no BSS, try .data
        elif report.data_addr:
            page_size = 0x1000
            report.mprotect_target = report.data_addr & ~(page_size - 1)
            report.shellcode_target = report.data_addr + 0x100

    def _find_special_addresses(self, report: AddressReport):
        """Find special addresses like stdin/stdout."""
        special_syms = ["stdin", "stdout", "stderr",
                        "_IO_2_1_stdin_", "_IO_2_1_stdout_", "_IO_2_1_stderr_"]

        for sym in special_syms:
            if sym in self.binary.symbols:
                addr = self.binary.symbols[sym]
                if hasattr(addr, 'address'):
                    addr = addr.address

                if "stdin" in sym:
                    report.stdin_addr = addr
                elif "stdout" in sym:
                    report.stdout_addr = addr
                elif "stderr" in sym:
                    report.stderr_addr = addr

    def _search_string(self, s: str) -> Optional[int]:
        """Search for a string in the binary."""
        try:
            # Use pwntools search if available
            if hasattr(self.binary, '_elf') and self.binary._elf:
                results = list(self.binary._elf.search(s.encode()))
                if results:
                    return results[0]
        except Exception:
            pass

        # Fallback: search in raw binary data
        try:
            data = self.binary.path.read_bytes()
            idx = data.find(s.encode())
            if idx >= 0:
                # Convert file offset to virtual address
                for section in self.binary.sections.values():
                    if section.offset <= idx < section.offset + section.size:
                        return section.address + (idx - section.offset)
        except Exception:
            pass

        return None

    # === Convenience Methods ===

    def get_binsh(self) -> Optional[int]:
        """Get /bin/sh address."""
        if self._report:
            return self._report.binsh_addr
        report = self.find_all()
        return report.binsh_addr

    def get_bss(self) -> Optional[int]:
        """Get BSS section address."""
        if self._report:
            return self._report.bss_addr
        report = self.find_all()
        return report.bss_addr

    def get_mprotect_target(self) -> Optional[int]:
        """Get page-aligned address for mprotect."""
        if self._report:
            return self._report.mprotect_target
        report = self.find_all()
        return report.mprotect_target

    def get_shellcode_target(self) -> Optional[int]:
        """Get address for shellcode placement."""
        if self._report:
            return self._report.shellcode_target
        report = self.find_all()
        return report.shellcode_target

    def get_got_entry(self, name: str) -> Optional[int]:
        """Get GOT entry address by name."""
        return self.binary.got.get(name)

    def get_plt_entry(self, name: str) -> Optional[int]:
        """Get PLT entry address by name."""
        return self.binary.plt.get(name)

    def get_writable_regions(self) -> List[WritableRegion]:
        """Get all writable regions."""
        if self._report:
            return self._report.writable_regions
        report = self.find_all()
        return report.writable_regions


# Convenience functions
def find_binsh(binary: "Binary") -> Optional[int]:
    """Find /bin/sh in binary."""
    finder = AddressFinder(binary)
    return finder.get_binsh()


def find_bss(binary: "Binary") -> Optional[int]:
    """Find BSS section address."""
    finder = AddressFinder(binary)
    return finder.get_bss()


def find_useful_addresses(binary: "Binary") -> AddressReport:
    """Find all useful addresses in binary."""
    finder = AddressFinder(binary)
    return finder.find_all()
