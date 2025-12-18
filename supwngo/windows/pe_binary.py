"""
Windows PE binary parsing and analysis.

Provides PE-specific binary handling using LIEF or pefile.
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from supwngo.utils.logging import get_logger

logger = get_logger(__name__)

# Try to import PE parsing libraries
try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False


class PEMachine(Enum):
    """PE machine types."""
    UNKNOWN = 0
    I386 = 0x14c
    AMD64 = 0x8664
    ARM = 0x1c0
    ARM64 = 0xaa64


@dataclass
class PEProtections:
    """Windows PE security protections."""
    # DEP (Data Execution Prevention)
    dep_enabled: bool = False
    dep_permanent: bool = False

    # ASLR
    aslr_enabled: bool = False
    high_entropy_aslr: bool = False
    force_integrity: bool = False

    # Stack protection
    stack_cookies: bool = False  # /GS

    # SEH protection
    safe_seh: bool = False
    seh_no_handler: bool = False  # SEHOP

    # Control Flow Guard
    cfg_enabled: bool = False
    cfg_strict: bool = False

    # Authenticode
    signed: bool = False
    signature_valid: bool = False

    # Additional
    no_isolation: bool = False
    no_bind: bool = False
    app_container: bool = False
    guard_rf: bool = False  # Return Flow Guard

    def __str__(self) -> str:
        protections = []
        if self.dep_enabled:
            protections.append("DEP")
        if self.aslr_enabled:
            protections.append("ASLR")
        if self.high_entropy_aslr:
            protections.append("High-Entropy ASLR")
        if self.stack_cookies:
            protections.append("Stack Cookies (/GS)")
        if self.safe_seh:
            protections.append("SafeSEH")
        if self.seh_no_handler:
            protections.append("SEHOP")
        if self.cfg_enabled:
            protections.append("CFG")
        if self.signed:
            protections.append("Signed")
        return ", ".join(protections) if protections else "None"


@dataclass
class PESection:
    """PE section information."""
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    raw_offset: int
    characteristics: int

    # Derived properties
    readable: bool = False
    writable: bool = False
    executable: bool = False

    def contains(self, addr: int) -> bool:
        """Check if address is in this section."""
        return self.virtual_address <= addr < self.virtual_address + self.virtual_size


@dataclass
class ImportedFunction:
    """Imported function information."""
    name: str
    dll: str
    ordinal: Optional[int] = None
    iat_address: int = 0  # Import Address Table entry
    hint: int = 0


@dataclass
class ExportedFunction:
    """Exported function information."""
    name: str
    address: int
    ordinal: int
    forwarded_to: Optional[str] = None


class PEBinary:
    """
    Windows PE binary wrapper.

    Provides unified interface for PE analysis using LIEF or pefile.

    Example:
        pe = PEBinary("target.exe")

        # Check protections
        print(pe.protections)

        # Get imports
        for imp in pe.imports:
            print(f"{imp.dll}!{imp.name}")

        # Find gadgets
        gadgets = pe.find_gadgets("pop eax; ret")
    """

    # Dangerous Windows API functions
    DANGEROUS_FUNCTIONS = {
        # Memory corruption
        "strcpy", "strcat", "sprintf", "vsprintf", "gets",
        "wcscpy", "wcscat", "swprintf",
        "lstrcpy", "lstrcpyA", "lstrcpyW",
        "lstrcat", "lstrcatA", "lstrcatW",

        # Format strings
        "printf", "wprintf", "fprintf", "sprintf",

        # Memory operations
        "memcpy", "memmove", "CopyMemory", "RtlCopyMemory",

        # Execution
        "WinExec", "ShellExecute", "ShellExecuteA", "ShellExecuteW",
        "CreateProcess", "CreateProcessA", "CreateProcessW",
        "system", "_wsystem",

        # File operations
        "CreateFile", "CreateFileA", "CreateFileW",
        "WriteFile", "ReadFile",

        # Registry
        "RegSetValue", "RegSetValueEx",

        # Network
        "recv", "recvfrom", "WSARecv",
        "send", "sendto", "WSASend",
    }

    def __init__(self, path: Union[str, Path]):
        """
        Initialize PE binary.

        Args:
            path: Path to PE file
        """
        self.path = Path(path)

        if not self.path.exists():
            raise FileNotFoundError(f"PE file not found: {path}")

        self._pe = None
        self._lief_pe = None

        # Load with available library
        if LIEF_AVAILABLE:
            self._lief_pe = lief.parse(str(self.path))
            if self._lief_pe is None:
                raise ValueError(f"Failed to parse PE: {path}")
        elif PEFILE_AVAILABLE:
            self._pe = pefile.PE(str(self.path))
        else:
            raise ImportError("Neither LIEF nor pefile available. Install with: pip install lief pefile")

        # Parse binary info
        self._parse_info()

    def _parse_info(self):
        """Parse binary information."""
        if self._lief_pe:
            self._parse_lief()
        else:
            self._parse_pefile()

    def _parse_lief(self):
        """Parse using LIEF."""
        pe = self._lief_pe

        # Basic info
        self.machine = PEMachine(pe.header.machine.value)
        self.bits = 64 if self.machine == PEMachine.AMD64 else 32
        self.entry_point = pe.optional_header.addressof_entrypoint
        self.image_base = pe.optional_header.imagebase

        # Sections
        self.sections: List[PESection] = []
        for section in pe.sections:
            chars = section.characteristics
            self.sections.append(PESection(
                name=section.name,
                virtual_address=section.virtual_address,
                virtual_size=section.virtual_size,
                raw_size=section.size,
                raw_offset=section.offset,
                characteristics=chars,
                readable=bool(chars & 0x40000000),
                writable=bool(chars & 0x80000000),
                executable=bool(chars & 0x20000000),
            ))

        # Protections
        self.protections = self._parse_protections_lief()

        # Imports
        self.imports: List[ImportedFunction] = []
        if pe.has_imports:
            for imp in pe.imports:
                dll_name = imp.name
                for entry in imp.entries:
                    self.imports.append(ImportedFunction(
                        name=entry.name if entry.name else f"Ordinal_{entry.ordinal}",
                        dll=dll_name,
                        ordinal=entry.ordinal,
                        iat_address=entry.iat_address,
                        hint=entry.hint,
                    ))

        # Exports
        self.exports: List[ExportedFunction] = []
        if pe.has_exports:
            for exp in pe.exported_functions:
                self.exports.append(ExportedFunction(
                    name=exp.name,
                    address=exp.address,
                    ordinal=exp.ordinal,
                    forwarded_to=exp.forward_information.function if exp.forward_information else None,
                ))

    def _parse_pefile(self):
        """Parse using pefile."""
        pe = self._pe

        # Basic info
        self.machine = PEMachine(pe.FILE_HEADER.Machine)
        self.bits = 64 if self.machine == PEMachine.AMD64 else 32
        self.entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        self.image_base = pe.OPTIONAL_HEADER.ImageBase

        # Sections
        self.sections: List[PESection] = []
        for section in pe.sections:
            chars = section.Characteristics
            self.sections.append(PESection(
                name=section.Name.decode().rstrip('\x00'),
                virtual_address=section.VirtualAddress,
                virtual_size=section.Misc_VirtualSize,
                raw_size=section.SizeOfRawData,
                raw_offset=section.PointerToRawData,
                characteristics=chars,
                readable=bool(chars & 0x40000000),
                writable=bool(chars & 0x80000000),
                executable=bool(chars & 0x20000000),
            ))

        # Protections
        self.protections = self._parse_protections_pefile()

        # Imports
        self.imports: List[ImportedFunction] = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode()
                for imp in entry.imports:
                    self.imports.append(ImportedFunction(
                        name=imp.name.decode() if imp.name else f"Ordinal_{imp.ordinal}",
                        dll=dll_name,
                        ordinal=imp.ordinal,
                        iat_address=imp.address,
                        hint=imp.hint if imp.hint else 0,
                    ))

        # Exports
        self.exports: List[ExportedFunction] = []
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                self.exports.append(ExportedFunction(
                    name=exp.name.decode() if exp.name else "",
                    address=exp.address,
                    ordinal=exp.ordinal,
                    forwarded_to=exp.forwarder.decode() if exp.forwarder else None,
                ))

    def _parse_protections_lief(self) -> PEProtections:
        """Parse protections using LIEF."""
        pe = self._lief_pe
        prots = PEProtections()

        # DLL Characteristics
        chars = pe.optional_header.dll_characteristics

        # DEP/NX
        prots.dep_enabled = bool(chars & lief.PE.DLL_CHARACTERISTICS.NX_COMPAT)
        prots.dep_permanent = prots.dep_enabled

        # ASLR
        prots.aslr_enabled = bool(chars & lief.PE.DLL_CHARACTERISTICS.DYNAMIC_BASE)
        prots.high_entropy_aslr = bool(chars & lief.PE.DLL_CHARACTERISTICS.HIGH_ENTROPY_VA)
        prots.force_integrity = bool(chars & lief.PE.DLL_CHARACTERISTICS.FORCE_INTEGRITY)

        # SEH
        prots.seh_no_handler = bool(chars & lief.PE.DLL_CHARACTERISTICS.NO_SEH)

        # CFG
        prots.cfg_enabled = bool(chars & lief.PE.DLL_CHARACTERISTICS.GUARD_CF)

        # Check for SafeSEH in load config
        if pe.has_configuration:
            config = pe.load_configuration
            if hasattr(config, 'se_handler_table') and config.se_handler_table:
                prots.safe_seh = True

        # Stack cookies (check for __security_cookie import)
        for imp in self.imports:
            if imp.name == "__security_cookie" or imp.name == "__security_check_cookie":
                prots.stack_cookies = True
                break

        # Signature
        prots.signed = pe.has_signatures

        return prots

    def _parse_protections_pefile(self) -> PEProtections:
        """Parse protections using pefile."""
        pe = self._pe
        prots = PEProtections()

        chars = pe.OPTIONAL_HEADER.DllCharacteristics

        # DEP/NX
        prots.dep_enabled = bool(chars & 0x0100)  # IMAGE_DLLCHARACTERISTICS_NX_COMPAT
        prots.dep_permanent = prots.dep_enabled

        # ASLR
        prots.aslr_enabled = bool(chars & 0x0040)  # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        prots.high_entropy_aslr = bool(chars & 0x0020)  # IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
        prots.force_integrity = bool(chars & 0x0080)  # IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY

        # SEH
        prots.seh_no_handler = bool(chars & 0x0400)  # IMAGE_DLLCHARACTERISTICS_NO_SEH

        # CFG
        prots.cfg_enabled = bool(chars & 0x4000)  # IMAGE_DLLCHARACTERISTICS_GUARD_CF

        # SafeSEH - check load config
        if hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG'):
            config = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct
            if hasattr(config, 'SEHandlerTable') and config.SEHandlerTable:
                prots.safe_seh = True

        # Stack cookies
        for imp in self.imports:
            if imp.name in ["__security_cookie", "__security_check_cookie"]:
                prots.stack_cookies = True
                break

        # Signature
        prots.signed = hasattr(pe, 'DIRECTORY_ENTRY_SECURITY')

        return prots

    def get_section(self, name: str) -> Optional[PESection]:
        """Get section by name."""
        for section in self.sections:
            if section.name == name:
                return section
        return None

    def get_section_at(self, addr: int) -> Optional[PESection]:
        """Get section containing address."""
        for section in self.sections:
            if section.contains(addr):
                return section
        return None

    def read_bytes(self, rva: int, size: int) -> bytes:
        """Read bytes at RVA."""
        if self._lief_pe:
            return bytes(self._lief_pe.get_content_from_virtual_address(rva, size))
        else:
            offset = self._pe.get_offset_from_rva(rva)
            return self._pe.get_data(offset, size)

    def find_import(self, name: str, dll: Optional[str] = None) -> Optional[ImportedFunction]:
        """Find imported function by name."""
        for imp in self.imports:
            if imp.name == name:
                if dll is None or imp.dll.lower() == dll.lower():
                    return imp
        return None

    def find_export(self, name: str) -> Optional[ExportedFunction]:
        """Find exported function by name."""
        for exp in self.exports:
            if exp.name == name:
                return exp
        return None

    def get_dangerous_imports(self) -> List[ImportedFunction]:
        """Get list of dangerous imported functions."""
        dangerous = []
        for imp in self.imports:
            if imp.name in self.DANGEROUS_FUNCTIONS:
                dangerous.append(imp)
        return dangerous

    def find_string(self, pattern: bytes) -> List[int]:
        """Find all occurrences of a byte pattern."""
        results = []

        if self._lief_pe:
            content = bytes(self._lief_pe.content)
        else:
            content = self._pe.__data__

        pos = 0
        while True:
            pos = content.find(pattern, pos)
            if pos == -1:
                break
            results.append(pos)
            pos += 1

        return results

    def find_gadgets(
        self,
        pattern: str,
        section: Optional[str] = None
    ) -> List[Tuple[int, str]]:
        """
        Find ROP gadgets matching pattern.

        Args:
            pattern: Gadget pattern (e.g., "pop eax; ret")
            section: Limit search to specific section

        Returns:
            List of (address, disassembly) tuples
        """
        gadgets = []

        try:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

            mode = CS_MODE_64 if self.bits == 64 else CS_MODE_32
            md = Cs(CS_ARCH_X86, mode)

            # Search executable sections
            for sec in self.sections:
                if section and sec.name != section:
                    continue
                if not sec.executable:
                    continue

                data = self.read_bytes(sec.virtual_address, sec.virtual_size)

                # Find ret instructions and work backwards
                for i, b in enumerate(data):
                    if b == 0xc3:  # ret
                        # Disassemble backwards
                        for start in range(max(0, i - 20), i):
                            chunk = data[start:i + 1]
                            insns = list(md.disasm(chunk, self.image_base + sec.virtual_address + start))

                            if insns and insns[-1].mnemonic == 'ret':
                                disasm = "; ".join(f"{ins.mnemonic} {ins.op_str}".strip() for ins in insns)
                                if pattern.lower() in disasm.lower():
                                    addr = self.image_base + sec.virtual_address + start
                                    gadgets.append((addr, disasm))

        except ImportError:
            logger.warning("Capstone not available for gadget search")
        except Exception as e:
            logger.debug(f"Error finding gadgets: {e}")

        return gadgets

    def summary(self) -> str:
        """Get binary summary."""
        lines = [
            f"PE Binary: {self.path.name}",
            f"Machine: {self.machine.name} ({self.bits}-bit)",
            f"Image Base: {hex(self.image_base)}",
            f"Entry Point: {hex(self.entry_point)}",
            f"Protections: {self.protections}",
            f"Sections: {len(self.sections)}",
            f"Imports: {len(self.imports)}",
            f"Exports: {len(self.exports)}",
        ]

        dangerous = self.get_dangerous_imports()
        if dangerous:
            lines.append(f"Dangerous functions: {len(dangerous)}")
            for func in dangerous[:5]:
                lines.append(f"  - {func.dll}!{func.name}")

        return "\n".join(lines)
