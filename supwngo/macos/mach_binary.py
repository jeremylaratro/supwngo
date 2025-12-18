"""
macOS Mach-O binary parsing and analysis.

Provides Mach-O specific binary handling using LIEF or macholib.
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import plistlib

from supwngo.utils.logging import get_logger

logger = get_logger(__name__)

# Try to import Mach-O parsing libraries
try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False


class MachOType(Enum):
    """Mach-O file types."""
    EXECUTE = 0x2
    DYLIB = 0x6
    BUNDLE = 0x8
    DYLINKER = 0x7
    OBJECT = 0x1


class MachOArch(Enum):
    """Mach-O architectures."""
    X86 = "x86"
    X86_64 = "x86_64"
    ARM = "arm"
    ARM64 = "arm64"
    ARM64E = "arm64e"  # With PAC


@dataclass
class MacOSProtections:
    """macOS-specific security protections."""
    # Code signing
    signed: bool = False
    signature_valid: bool = False
    hardened_runtime: bool = False
    library_validation: bool = False

    # Entitlements
    entitlements: Dict[str, Any] = field(default_factory=dict)
    has_dangerous_entitlements: bool = False

    # Memory protections
    pie: bool = False
    nx_stack: bool = False
    nx_heap: bool = False

    # ARM64e
    arm64e_pac: bool = False
    arm64e_version: int = 0

    # Sandbox
    sandboxed: bool = False
    sandbox_profile: str = ""

    # Additional
    restrict: bool = False
    kill_on_invalid_signature: bool = False

    def __str__(self) -> str:
        protections = []
        if self.signed:
            protections.append("Signed")
        if self.hardened_runtime:
            protections.append("Hardened Runtime")
        if self.library_validation:
            protections.append("Library Validation")
        if self.pie:
            protections.append("PIE")
        if self.arm64e_pac:
            protections.append("ARM64e PAC")
        if self.sandboxed:
            protections.append("Sandboxed")
        return ", ".join(protections) if protections else "None"


@dataclass
class MachOSegment:
    """Mach-O segment information."""
    name: str
    vmaddr: int
    vmsize: int
    fileoff: int
    filesize: int
    maxprot: int
    initprot: int

    # Derived
    readable: bool = False
    writable: bool = False
    executable: bool = False


@dataclass
class MachOSection:
    """Mach-O section information."""
    name: str
    segment: str
    addr: int
    size: int
    offset: int
    align: int
    flags: int


@dataclass
class DylibInfo:
    """Dynamic library information."""
    name: str
    path: str
    current_version: str = ""
    compatibility_version: str = ""
    timestamp: int = 0


@dataclass
class EntitlementInfo:
    """Parsed entitlements."""
    raw_xml: str = ""
    entitlements: Dict[str, Any] = field(default_factory=dict)
    dangerous: List[str] = field(default_factory=list)


class MachOBinary:
    """
    macOS Mach-O binary wrapper.

    Provides unified interface for Mach-O analysis.

    Example:
        macho = MachOBinary("target")

        # Check protections
        print(macho.protections)

        # Get segments
        for seg in macho.segments:
            print(f"{seg.name}: {hex(seg.vmaddr)}")

        # Check entitlements
        if macho.entitlements.dangerous:
            print("Dangerous entitlements found!")
    """

    # Dangerous entitlements that weaken security
    DANGEROUS_ENTITLEMENTS = {
        "com.apple.security.get-task-allow",
        "com.apple.security.cs.disable-library-validation",
        "com.apple.security.cs.allow-unsigned-executable-memory",
        "com.apple.security.cs.allow-jit",
        "com.apple.security.cs.disable-executable-page-protection",
        "com.apple.security.cs.allow-dyld-environment-variables",
        "com.apple.private.skip-library-validation",
        "com.apple.private.security.no-sandbox",
        "com.apple.security.cs.debugger",
    }

    # Dangerous imported functions
    DANGEROUS_FUNCTIONS = {
        # Memory corruption
        "strcpy", "strcat", "sprintf", "vsprintf", "gets",
        "wcscpy", "wcscat",

        # Format strings
        "printf", "fprintf", "sprintf", "NSLog",

        # Memory
        "memcpy", "memmove", "bcopy",

        # Execution
        "system", "popen", "execv", "execve", "execl",
        "posix_spawn", "NSTask",

        # Objective-C runtime
        "objc_msgSend",  # Can be abused
        "dlopen", "dlsym",

        # File operations
        "open", "fopen", "chmod", "chown",
    }

    def __init__(self, path: Union[str, Path]):
        """
        Initialize Mach-O binary.

        Args:
            path: Path to Mach-O file
        """
        self.path = Path(path)

        if not self.path.exists():
            raise FileNotFoundError(f"Mach-O file not found: {path}")

        if not LIEF_AVAILABLE:
            raise ImportError("LIEF required for Mach-O parsing. Install with: pip install lief")

        self._macho = lief.parse(str(self.path))
        if self._macho is None:
            raise ValueError(f"Failed to parse Mach-O: {path}")

        # Parse binary info
        self._parse_info()

    def _parse_info(self):
        """Parse binary information."""
        macho = self._macho

        # Basic info
        self.file_type = MachOType(macho.header.file_type.value)

        # Architecture
        cpu_type = macho.header.cpu_type
        if cpu_type == lief.MachO.CPU_TYPES.x86_64:
            self.arch = MachOArch.X86_64
            self.bits = 64
        elif cpu_type == lief.MachO.CPU_TYPES.x86:
            self.arch = MachOArch.X86
            self.bits = 32
        elif cpu_type == lief.MachO.CPU_TYPES.ARM64:
            # Check for ARM64e
            if hasattr(macho.header, 'cpu_subtype'):
                subtype = macho.header.cpu_subtype
                if subtype & 0x80000000:  # CPU_SUBTYPE_ARM64E
                    self.arch = MachOArch.ARM64E
                else:
                    self.arch = MachOArch.ARM64
            else:
                self.arch = MachOArch.ARM64
            self.bits = 64
        elif cpu_type == lief.MachO.CPU_TYPES.ARM:
            self.arch = MachOArch.ARM
            self.bits = 32
        else:
            self.arch = MachOArch.X86_64
            self.bits = 64

        # Entry point
        if macho.has_entrypoint:
            self.entry_point = macho.entrypoint
        else:
            self.entry_point = 0

        # Segments
        self.segments: List[MachOSegment] = []
        for seg in macho.segments:
            prot = seg.init_protection
            self.segments.append(MachOSegment(
                name=seg.name,
                vmaddr=seg.virtual_address,
                vmsize=seg.virtual_size,
                fileoff=seg.file_offset,
                filesize=seg.file_size,
                maxprot=seg.max_protection,
                initprot=prot,
                readable=bool(prot & 1),
                writable=bool(prot & 2),
                executable=bool(prot & 4),
            ))

        # Sections
        self.sections: List[MachOSection] = []
        for sec in macho.sections:
            self.sections.append(MachOSection(
                name=sec.name,
                segment=sec.segment_name,
                addr=sec.virtual_address,
                size=sec.size,
                offset=sec.offset,
                align=sec.alignment,
                flags=sec.flags,
            ))

        # Dynamic libraries
        self.dylibs: List[DylibInfo] = []
        for lib in macho.libraries:
            self.dylibs.append(DylibInfo(
                name=lib.name.split("/")[-1],
                path=lib.name,
                current_version=str(lib.current_version),
                compatibility_version=str(lib.compatibility_version),
                timestamp=lib.timestamp,
            ))

        # Symbols
        self.symbols: Dict[str, int] = {}
        if macho.has_symbol_command:
            for sym in macho.symbols:
                if sym.value:
                    self.symbols[sym.name] = sym.value

        # Imported functions
        self.imports: List[str] = []
        for func in macho.imported_functions:
            self.imports.append(func.name)

        # Exported functions
        self.exports: Dict[str, int] = {}
        for func in macho.exported_functions:
            self.exports[func.name] = func.address

        # Protections
        self.protections = self._parse_protections()

        # Entitlements
        self.entitlements = self._parse_entitlements()

    def _parse_protections(self) -> MacOSProtections:
        """Parse macOS protections."""
        macho = self._macho
        prots = MacOSProtections()

        # Code signature
        if macho.has_code_signature:
            prots.signed = True
            sig = macho.code_signature
            # Check signature flags if available

        # PIE
        flags = macho.header.flags
        prots.pie = bool(flags & 0x200000)  # MH_PIE

        # Check for hardened runtime in code signature
        if macho.has_code_signature:
            prots.hardened_runtime = True  # Simplified - would need to parse CS blob

        # ARM64e
        if self.arch == MachOArch.ARM64E:
            prots.arm64e_pac = True

        # NX Stack (usually default on modern macOS)
        prots.nx_stack = True
        prots.nx_heap = True

        return prots

    def _parse_entitlements(self) -> EntitlementInfo:
        """Parse entitlements from code signature."""
        info = EntitlementInfo()

        if not self._macho.has_code_signature:
            return info

        try:
            # Try to extract entitlements
            sig = self._macho.code_signature
            if hasattr(sig, 'entitlements'):
                ent_data = sig.entitlements
                if ent_data:
                    info.raw_xml = ent_data.decode() if isinstance(ent_data, bytes) else ent_data

                    # Parse plist
                    try:
                        info.entitlements = plistlib.loads(ent_data if isinstance(ent_data, bytes)
                                                          else ent_data.encode())
                    except Exception:
                        pass

                    # Check for dangerous entitlements
                    for key in info.entitlements.keys():
                        if key in self.DANGEROUS_ENTITLEMENTS:
                            info.dangerous.append(key)

                    if info.dangerous:
                        self.protections.has_dangerous_entitlements = True

        except Exception as e:
            logger.debug(f"Error parsing entitlements: {e}")

        return info

    def get_segment(self, name: str) -> Optional[MachOSegment]:
        """Get segment by name."""
        for seg in self.segments:
            if seg.name == name:
                return seg
        return None

    def get_section(self, segment: str, section: str) -> Optional[MachOSection]:
        """Get section by segment and section name."""
        for sec in self.sections:
            if sec.segment == segment and sec.name == section:
                return sec
        return None

    def read_bytes(self, addr: int, size: int) -> bytes:
        """Read bytes at virtual address."""
        return bytes(self._macho.get_content_from_virtual_address(addr, size))

    def get_dangerous_imports(self) -> List[str]:
        """Get list of dangerous imported functions."""
        dangerous = []
        for imp in self.imports:
            # Strip leading underscore (common in Mach-O)
            name = imp.lstrip("_")
            if name in self.DANGEROUS_FUNCTIONS:
                dangerous.append(imp)
        return dangerous

    def find_string(self, pattern: bytes) -> List[int]:
        """Find all occurrences of a byte pattern."""
        results = []

        for seg in self.segments:
            if seg.filesize == 0:
                continue

            try:
                data = self.read_bytes(seg.vmaddr, seg.vmsize)
                pos = 0
                while True:
                    pos = data.find(pattern, pos)
                    if pos == -1:
                        break
                    results.append(seg.vmaddr + pos)
                    pos += 1
            except Exception:
                continue

        return results

    def find_gadgets(self, pattern: str) -> List[Tuple[int, str]]:
        """
        Find ROP gadgets matching pattern.

        Args:
            pattern: Gadget pattern (e.g., "pop rdi; ret")

        Returns:
            List of (address, disassembly) tuples
        """
        gadgets = []

        try:
            from capstone import Cs, CS_ARCH_X86, CS_ARCH_ARM64, CS_MODE_64, CS_MODE_32, CS_MODE_ARM

            if self.arch in [MachOArch.X86_64, MachOArch.X86]:
                arch = CS_ARCH_X86
                mode = CS_MODE_64 if self.bits == 64 else CS_MODE_32
            else:
                arch = CS_ARCH_ARM64
                mode = CS_MODE_ARM

            md = Cs(arch, mode)

            # Search executable segments
            for seg in self.segments:
                if not seg.executable:
                    continue

                try:
                    data = self.read_bytes(seg.vmaddr, seg.vmsize)
                except Exception:
                    continue

                # Find ret instructions and work backwards
                ret_byte = 0xc3 if self.arch in [MachOArch.X86_64, MachOArch.X86] else 0xd65f03c0

                for i in range(len(data)):
                    if self.arch in [MachOArch.X86_64, MachOArch.X86]:
                        if data[i] != 0xc3:
                            continue

                        for start in range(max(0, i - 20), i):
                            chunk = data[start:i + 1]
                            insns = list(md.disasm(chunk, seg.vmaddr + start))

                            if insns and insns[-1].mnemonic == 'ret':
                                disasm = "; ".join(f"{ins.mnemonic} {ins.op_str}".strip() for ins in insns)
                                if pattern.lower() in disasm.lower():
                                    gadgets.append((seg.vmaddr + start, disasm))
                    else:
                        # ARM64 ret is 4 bytes
                        if i + 4 > len(data):
                            continue
                        if data[i:i+4] == b'\xc0\x03\x5f\xd6':  # ret
                            for start in range(max(0, i - 40), i, 4):
                                chunk = data[start:i + 4]
                                insns = list(md.disasm(chunk, seg.vmaddr + start))

                                if insns and insns[-1].mnemonic == 'ret':
                                    disasm = "; ".join(f"{ins.mnemonic} {ins.op_str}".strip() for ins in insns)
                                    if pattern.lower() in disasm.lower():
                                        gadgets.append((seg.vmaddr + start, disasm))

        except ImportError:
            logger.warning("Capstone not available for gadget search")
        except Exception as e:
            logger.debug(f"Error finding gadgets: {e}")

        return gadgets

    def summary(self) -> str:
        """Get binary summary."""
        lines = [
            f"Mach-O Binary: {self.path.name}",
            f"Type: {self.file_type.name}",
            f"Architecture: {self.arch.name} ({self.bits}-bit)",
            f"Entry Point: {hex(self.entry_point)}",
            f"Protections: {self.protections}",
            f"Segments: {len(self.segments)}",
            f"Sections: {len(self.sections)}",
            f"Dynamic Libraries: {len(self.dylibs)}",
            f"Symbols: {len(self.symbols)}",
        ]

        if self.entitlements.dangerous:
            lines.append(f"Dangerous Entitlements: {len(self.entitlements.dangerous)}")
            for ent in self.entitlements.dangerous:
                lines.append(f"  - {ent}")

        dangerous = self.get_dangerous_imports()
        if dangerous:
            lines.append(f"Dangerous Imports: {len(dangerous)}")
            for func in dangerous[:5]:
                lines.append(f"  - {func}")

        return "\n".join(lines)
