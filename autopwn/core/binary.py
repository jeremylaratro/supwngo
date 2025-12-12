"""
Binary abstraction layer for ELF/PE parsing and analysis.
"""

import os
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from autopwn.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class Symbol:
    """Represents a binary symbol."""
    name: str
    address: int
    size: int
    type: str  # FUNC, OBJECT, NOTYPE
    binding: str  # LOCAL, GLOBAL, WEAK
    section: Optional[str] = None


@dataclass
class Section:
    """Represents a binary section."""
    name: str
    address: int
    size: int
    offset: int
    flags: int
    type: str
    is_executable: bool = False
    is_writable: bool = False


@dataclass
class Segment:
    """Represents a binary segment."""
    type: str
    address: int
    size: int
    offset: int
    flags: str
    memsz: int


@dataclass
class Import:
    """Represents an imported function."""
    name: str
    plt_address: int
    got_address: int
    library: Optional[str] = None


@dataclass
class Protections:
    """Binary protection mechanisms."""
    canary: bool = False
    nx: bool = False
    pie: bool = False
    relro: str = "No RELRO"  # No RELRO, Partial RELRO, Full RELRO
    fortify: bool = False
    aslr: bool = True  # System-wide, assumed true
    rpath: Optional[str] = None
    runpath: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "canary": self.canary,
            "nx": self.nx,
            "pie": self.pie,
            "relro": self.relro,
            "fortify": self.fortify,
            "aslr": self.aslr,
        }

    def __str__(self) -> str:
        """Pretty print protections."""
        lines = [
            f"CANARY    : {'Enabled' if self.canary else 'Disabled'}",
            f"NX        : {'Enabled' if self.nx else 'Disabled'}",
            f"PIE       : {'Enabled' if self.pie else 'Disabled'}",
            f"RELRO     : {self.relro}",
            f"FORTIFY   : {'Enabled' if self.fortify else 'Disabled'}",
        ]
        return "\n".join(lines)


@dataclass
class Binary:
    """
    Comprehensive binary abstraction combining multiple analysis sources.

    Supports ELF binaries with optional PE support for Windows targets.
    """

    path: Path
    arch: str = ""
    bits: int = 64
    endian: str = "little"
    os: str = "linux"

    # Cached analysis results
    _elf: Any = field(default=None, repr=False)
    _lief_binary: Any = field(default=None, repr=False)
    _angr_project: Any = field(default=None, repr=False)

    # Binary data
    entry_point: int = 0
    base_address: int = 0
    protections: Protections = field(default_factory=Protections)

    # Symbol tables
    symbols: Dict[str, Symbol] = field(default_factory=dict)
    imports: Dict[str, Import] = field(default_factory=dict)
    plt: Dict[str, int] = field(default_factory=dict)
    got: Dict[str, int] = field(default_factory=dict)

    # Sections and segments
    sections: Dict[str, Section] = field(default_factory=dict)
    segments: List[Segment] = field(default_factory=list)

    # Executable regions
    executable_regions: List[Tuple[int, int]] = field(default_factory=list)
    writable_regions: List[Tuple[int, int]] = field(default_factory=list)

    # Metadata
    md5: str = ""
    sha256: str = ""

    def __post_init__(self):
        """Initialize binary after dataclass creation."""
        if isinstance(self.path, str):
            self.path = Path(self.path)
        if self.path.exists():
            self._compute_hashes()

    @classmethod
    def load(cls, path: str, auto_load_libs: bool = False) -> "Binary":
        """
        Load and analyze a binary file.

        Args:
            path: Path to binary file
            auto_load_libs: Whether to load shared libraries

        Returns:
            Analyzed Binary instance
        """
        binary = cls(path=Path(path))
        binary._load_with_pwntools()
        binary._load_with_pyelftools()
        binary._detect_protections()
        return binary

    def _compute_hashes(self) -> None:
        """Compute file hashes."""
        data = self.path.read_bytes()
        self.md5 = hashlib.md5(data).hexdigest()
        self.sha256 = hashlib.sha256(data).hexdigest()

    def _load_with_pwntools(self) -> None:
        """Load binary using pwntools ELF class."""
        try:
            from pwn import ELF, context

            # Suppress pwntools output during loading
            with context.local(log_level='error'):
                self._elf = ELF(str(self.path))

            # Extract basic info
            self.arch = self._elf.arch
            self.bits = self._elf.bits
            self.endian = self._elf.endian
            self.entry_point = self._elf.entry
            self.base_address = self._elf.address

            # Extract PLT/GOT
            self.plt = dict(self._elf.plt)
            self.got = dict(self._elf.got)

            # Build imports dict
            for name, plt_addr in self.plt.items():
                got_addr = self.got.get(name, 0)
                self.imports[name] = Import(
                    name=name,
                    plt_address=plt_addr,
                    got_address=got_addr,
                )

            # Extract symbols
            for name, addr in self._elf.symbols.items():
                self.symbols[name] = Symbol(
                    name=name,
                    address=addr,
                    size=0,
                    type="UNKNOWN",
                    binding="UNKNOWN",
                )

            logger.debug(f"Loaded binary with pwntools: {self.arch} {self.bits}-bit")

        except ImportError:
            logger.warning("pwntools not available, skipping pwntools analysis")
        except Exception as e:
            logger.warning(f"Failed to load with pwntools: {e}")

    def _load_with_pyelftools(self) -> None:
        """Load binary using pyelftools for detailed ELF analysis."""
        try:
            from elftools.elf.elffile import ELFFile
            from elftools.elf.sections import SymbolTableSection

            with open(self.path, "rb") as f:
                elf = ELFFile(f)

                # Architecture detection
                machine = elf.header.e_machine
                if machine == "EM_X86_64":
                    self.arch = "amd64"
                    self.bits = 64
                elif machine == "EM_386":
                    self.arch = "i386"
                    self.bits = 32
                elif machine == "EM_ARM":
                    self.arch = "arm"
                    self.bits = 32
                elif machine == "EM_AARCH64":
                    self.arch = "aarch64"
                    self.bits = 64

                # Endianness
                self.endian = "little" if elf.little_endian else "big"

                # Entry point
                self.entry_point = elf.header.e_entry

                # Parse sections
                for section in elf.iter_sections():
                    flags = section.header.sh_flags
                    sec = Section(
                        name=section.name,
                        address=section.header.sh_addr,
                        size=section.header.sh_size,
                        offset=section.header.sh_offset,
                        flags=flags,
                        type=section.header.sh_type,
                        is_executable=bool(flags & 0x4),  # SHF_EXECINSTR
                        is_writable=bool(flags & 0x1),    # SHF_WRITE
                    )
                    self.sections[section.name] = sec

                    if sec.is_executable and sec.size > 0:
                        self.executable_regions.append(
                            (sec.address, sec.address + sec.size)
                        )
                    if sec.is_writable and sec.size > 0:
                        self.writable_regions.append(
                            (sec.address, sec.address + sec.size)
                        )

                # Parse segments
                for segment in elf.iter_segments():
                    seg = Segment(
                        type=segment.header.p_type,
                        address=segment.header.p_vaddr,
                        size=segment.header.p_filesz,
                        offset=segment.header.p_offset,
                        flags=self._segment_flags_str(segment.header.p_flags),
                        memsz=segment.header.p_memsz,
                    )
                    self.segments.append(seg)

                # Parse symbol tables
                for section in elf.iter_sections():
                    if isinstance(section, SymbolTableSection):
                        for symbol in section.iter_symbols():
                            if symbol.name:
                                sym = Symbol(
                                    name=symbol.name,
                                    address=symbol.entry.st_value,
                                    size=symbol.entry.st_size,
                                    type=symbol.entry.st_info.type,
                                    binding=symbol.entry.st_info.bind,
                                )
                                self.symbols[symbol.name] = sym

            logger.debug(f"Loaded binary with pyelftools: {len(self.sections)} sections")

        except ImportError:
            logger.warning("pyelftools not available, skipping detailed ELF analysis")
        except Exception as e:
            logger.warning(f"Failed to load with pyelftools: {e}")

    def _segment_flags_str(self, flags: int) -> str:
        """Convert segment flags to string."""
        result = ""
        result += "R" if flags & 0x4 else "-"
        result += "W" if flags & 0x2 else "-"
        result += "X" if flags & 0x1 else "-"
        return result

    def _detect_protections(self) -> None:
        """Detect binary protection mechanisms."""
        try:
            # Use pwntools checksec if available
            if self._elf:
                self.protections = Protections(
                    canary=self._elf.canary,
                    nx=self._elf.nx,
                    pie=self._elf.pie,
                    relro=self._relro_str(self._elf.relro),
                    fortify="_chk" in str(self.symbols.keys()),
                )
        except Exception as e:
            logger.warning(f"Failed to detect protections: {e}")

    def _relro_str(self, relro: bool) -> str:
        """Convert relro boolean to string."""
        if not relro:
            return "No RELRO"
        # Check for full vs partial RELRO
        if ".got.plt" not in self.sections:
            return "Full RELRO"
        got_plt = self.sections.get(".got.plt")
        if got_plt and not got_plt.is_writable:
            return "Full RELRO"
        return "Partial RELRO"

    def get_angr_project(self, auto_load_libs: bool = False) -> Any:
        """
        Get angr Project for this binary.

        Args:
            auto_load_libs: Whether to load shared libraries

        Returns:
            angr.Project instance
        """
        if self._angr_project is None:
            try:
                import angr
                self._angr_project = angr.Project(
                    str(self.path),
                    auto_load_libs=auto_load_libs,
                )
            except ImportError:
                raise RuntimeError("angr is required for symbolic execution")
        return self._angr_project

    def get_section(self, name: str) -> Optional[Section]:
        """Get section by name."""
        return self.sections.get(name)

    def get_section_data(self, name: str) -> Optional[bytes]:
        """Get raw section data."""
        section = self.sections.get(name)
        if section:
            data = self.path.read_bytes()
            return data[section.offset:section.offset + section.size]
        return None

    def read(self, address: int, size: int) -> bytes:
        """
        Read bytes from binary at virtual address.

        Args:
            address: Virtual address to read from
            size: Number of bytes to read

        Returns:
            Bytes at address
        """
        if self._elf:
            return self._elf.read(address, size)
        raise RuntimeError("Binary not loaded")

    def address(self, symbol: str) -> int:
        """
        Get address of symbol.

        Args:
            symbol: Symbol name

        Returns:
            Symbol address

        Raises:
            KeyError: If symbol not found
        """
        if symbol in self.symbols:
            return self.symbols[symbol].address
        if symbol in self.plt:
            return self.plt[symbol]
        raise KeyError(f"Symbol not found: {symbol}")

    def search(self, pattern: bytes) -> List[int]:
        """
        Search for byte pattern in binary.

        Args:
            pattern: Bytes to search for

        Returns:
            List of addresses where pattern was found
        """
        if self._elf:
            return list(self._elf.search(pattern))

        # Fallback: manual search
        data = self.path.read_bytes()
        results = []
        start = 0
        while True:
            idx = data.find(pattern, start)
            if idx == -1:
                break
            results.append(idx)
            start = idx + 1
        return results

    def strings(self, min_length: int = 4) -> List[Tuple[int, str]]:
        """
        Extract strings from binary.

        Args:
            min_length: Minimum string length

        Returns:
            List of (address, string) tuples
        """
        results = []
        data = self.path.read_bytes()

        current_string = bytearray()
        start_offset = 0

        for i, byte in enumerate(data):
            if 32 <= byte < 127:  # Printable ASCII
                if not current_string:
                    start_offset = i
                current_string.append(byte)
            else:
                if len(current_string) >= min_length:
                    results.append((start_offset, current_string.decode("ascii")))
                current_string.clear()

        return results

    def find_gadgets_region(self) -> List[Tuple[int, int]]:
        """Get executable regions for gadget searching."""
        return self.executable_regions

    def checksec(self) -> Dict[str, Any]:
        """
        Return security features as dict (checksec-style).

        Returns:
            Dictionary of security features
        """
        return self.protections.to_dict()

    def __str__(self) -> str:
        """String representation."""
        return (
            f"Binary({self.path.name}, {self.arch}, {self.bits}-bit, "
            f"entry=0x{self.entry_point:x})"
        )

    def info(self) -> str:
        """Detailed binary information."""
        lines = [
            f"Path: {self.path}",
            f"Arch: {self.arch} ({self.bits}-bit, {self.endian})",
            f"Entry: 0x{self.entry_point:x}",
            f"Base: 0x{self.base_address:x}",
            f"MD5: {self.md5}",
            f"SHA256: {self.sha256}",
            "",
            "Protections:",
            str(self.protections),
            "",
            f"Sections: {len(self.sections)}",
            f"Symbols: {len(self.symbols)}",
            f"Imports: {len(self.imports)}",
        ]
        return "\n".join(lines)
