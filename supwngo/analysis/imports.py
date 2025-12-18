"""
Import/Export analysis module.

Provides comprehensive analysis of binary imports and exports:
- Dependency mapping
- Weak symbol detection
- Lazy binding analysis
- Version requirements detection
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from enum import Enum, auto
import re
import struct

from supwngo.core.binary import Binary
from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


class SymbolBinding(Enum):
    """ELF symbol binding types."""
    LOCAL = 0
    GLOBAL = 1
    WEAK = 2


class SymbolType(Enum):
    """ELF symbol types."""
    NOTYPE = 0
    OBJECT = 1
    FUNC = 2
    SECTION = 3
    FILE = 4
    COMMON = 5
    TLS = 6


@dataclass
class ImportedSymbol:
    """Detailed imported symbol information."""
    name: str
    library: str
    address: int  # PLT/GOT address
    binding: SymbolBinding
    sym_type: SymbolType
    version: Optional[str] = None
    is_lazy: bool = True
    is_weak: bool = False
    required_version: Optional[str] = None


@dataclass
class ExportedSymbol:
    """Detailed exported symbol information."""
    name: str
    address: int
    size: int
    binding: SymbolBinding
    sym_type: SymbolType
    version: Optional[str] = None


@dataclass
class LibraryDependency:
    """Library dependency information."""
    name: str
    path: Optional[str] = None
    symbols_used: List[str] = field(default_factory=list)
    version_requirements: List[str] = field(default_factory=list)
    is_optional: bool = False  # NEEDED vs WEAK


# Dangerous functions by category
DANGEROUS_IMPORTS = {
    "memory_unsafe": {
        "gets", "strcpy", "strcat", "sprintf", "vsprintf",
        "scanf", "fscanf", "sscanf",
    },
    "format_string": {
        "printf", "fprintf", "sprintf", "snprintf",
        "vprintf", "vfprintf", "vsprintf", "vsnprintf",
        "syslog",
    },
    "command_exec": {
        "system", "popen", "execve", "execl", "execv",
        "execlp", "execvp", "execle", "execvpe",
    },
    "memory_mgmt": {
        "malloc", "calloc", "realloc", "free",
        "memalign", "posix_memalign",
    },
    "file_ops": {
        "open", "fopen", "creat", "access",
        "unlink", "remove", "rename",
    },
}

# Libc version indicators
GLIBC_VERSION_SYMBOLS = {
    "__libc_start_main": "2.0",
    "__stack_chk_fail": "2.4",
    "__printf_chk": "2.3.4",
    "__fortify_fail": "2.3",
    "__cxa_finalize": "2.1.3",
    "secure_getenv": "2.17",
    "explicit_bzero": "2.25",
    "reallocarray": "2.26",
    "getrandom": "2.25",
}


class ImportAnalyzer:
    """
    Import/Export analyzer for binary exploitation.

    Analyzes binary dependencies and imports to identify:
    - Exploitable function imports
    - Weak symbols that can be overridden
    - Lazy binding opportunities
    - Library version requirements
    """

    def __init__(self, binary: Binary):
        """
        Initialize import analyzer.

        Args:
            binary: Binary instance to analyze
        """
        self.binary = binary
        self.imports: Dict[str, ImportedSymbol] = {}
        self.exports: Dict[str, ExportedSymbol] = {}
        self.dependencies: Dict[str, LibraryDependency] = {}
        self.weak_symbols: List[ImportedSymbol] = []
        self.lazy_bindings: List[ImportedSymbol] = []

    def analyze(self) -> Dict[str, Any]:
        """
        Perform comprehensive import/export analysis.

        Returns:
            Analysis results dictionary
        """
        logger.info("Analyzing imports and exports...")

        # Analyze imports
        self._analyze_imports()

        # Analyze exports
        self._analyze_exports()

        # Build dependency tree
        self._analyze_dependencies()

        # Detect weak symbols
        self._detect_weak_symbols()

        # Analyze lazy binding
        self._analyze_lazy_binding()

        results = {
            "imports": {
                name: {
                    "library": imp.library,
                    "address": hex(imp.address),
                    "binding": imp.binding.name,
                    "type": imp.sym_type.name,
                    "version": imp.version,
                    "is_lazy": imp.is_lazy,
                    "is_weak": imp.is_weak,
                }
                for name, imp in self.imports.items()
            },
            "exports": {
                name: {
                    "address": hex(exp.address),
                    "size": exp.size,
                    "binding": exp.binding.name,
                    "type": exp.sym_type.name,
                }
                for name, exp in self.exports.items()
            },
            "dependencies": {
                name: {
                    "path": dep.path,
                    "symbols_used": dep.symbols_used[:20],
                    "versions": dep.version_requirements,
                }
                for name, dep in self.dependencies.items()
            },
            "weak_symbols": [s.name for s in self.weak_symbols],
            "lazy_bindings": [s.name for s in self.lazy_bindings],
            "dangerous_imports": self.get_dangerous_imports(),
            "glibc_version": self.detect_glibc_version(),
        }

        logger.info(f"Found {len(self.imports)} imports, {len(self.exports)} exports")
        return results

    def _analyze_imports(self) -> None:
        """Analyze imported symbols."""
        try:
            from elftools.elf.elffile import ELFFile

            with open(self.binary.path, 'rb') as f:
                elf = ELFFile(f)

                # Get dynamic symbol table
                dynsym = elf.get_section_by_name('.dynsym')
                if not dynsym:
                    return

                # Get version information
                versym = elf.get_section_by_name('.gnu.version')
                verneed = elf.get_section_by_name('.gnu.version_r')

                version_map = {}
                if verneed:
                    for entry in verneed.iter_versions():
                        for aux in entry[1]:
                            version_map[aux.entry['vna_other']] = aux.name

                # Process symbols
                for idx, sym in enumerate(dynsym.iter_symbols()):
                    if sym.entry['st_shndx'] == 'SHN_UNDEF':  # Imported
                        name = sym.name
                        if not name:
                            continue

                        # Get binding - handle string enum values from elftools
                        bind_val = sym.entry['st_info']['bind']
                        if isinstance(bind_val, str):
                            bind_map = {'STB_LOCAL': 0, 'STB_GLOBAL': 1, 'STB_WEAK': 2}
                            bind_val = bind_map.get(bind_val, 1)
                        binding = SymbolBinding(bind_val)

                        type_val = sym.entry['st_info']['type']
                        if isinstance(type_val, str):
                            type_map = {'STT_NOTYPE': 0, 'STT_OBJECT': 1, 'STT_FUNC': 2,
                                       'STT_SECTION': 3, 'STT_FILE': 4, 'STT_COMMON': 5, 'STT_TLS': 6}
                            type_val = type_map.get(type_val, 0)
                        sym_type = SymbolType(type_val)

                        # Get version
                        version = None
                        if versym and idx < versym.num_symbols():
                            try:
                                ver_idx = versym.get_symbol(idx).entry['ndx']
                                if isinstance(ver_idx, int):
                                    version = version_map.get(ver_idx & 0x7fff)
                            except (TypeError, KeyError):
                                pass

                        # Get PLT address
                        plt_addr = self.binary.plt.get(name, 0)

                        imp = ImportedSymbol(
                            name=name,
                            library="",  # Will be set during dependency analysis
                            address=plt_addr,
                            binding=binding,
                            sym_type=sym_type,
                            version=version,
                            is_weak=binding == SymbolBinding.WEAK,
                        )
                        self.imports[name] = imp

        except Exception as e:
            logger.warning(f"Failed to analyze imports: {e}")
            # Fallback to PLT
            for name, addr in self.binary.plt.items():
                self.imports[name] = ImportedSymbol(
                    name=name,
                    library="unknown",
                    address=addr,
                    binding=SymbolBinding.GLOBAL,
                    sym_type=SymbolType.FUNC,
                )

    def _analyze_exports(self) -> None:
        """Analyze exported symbols."""
        try:
            from elftools.elf.elffile import ELFFile

            with open(self.binary.path, 'rb') as f:
                elf = ELFFile(f)

                # Helper to convert binding/type values
                def get_binding(bind_val):
                    if isinstance(bind_val, str):
                        bind_map = {'STB_LOCAL': 0, 'STB_GLOBAL': 1, 'STB_WEAK': 2}
                        bind_val = bind_map.get(bind_val, 1)
                    return SymbolBinding(bind_val)

                def get_type(type_val):
                    if isinstance(type_val, str):
                        type_map = {'STT_NOTYPE': 0, 'STT_OBJECT': 1, 'STT_FUNC': 2,
                                   'STT_SECTION': 3, 'STT_FILE': 4, 'STT_COMMON': 5, 'STT_TLS': 6}
                        type_val = type_map.get(type_val, 0)
                    return SymbolType(type_val)

                # Check dynamic symbols
                dynsym = elf.get_section_by_name('.dynsym')
                if dynsym:
                    for sym in dynsym.iter_symbols():
                        if sym.entry['st_shndx'] != 'SHN_UNDEF' and sym.entry['st_size'] > 0:
                            name = sym.name
                            if not name:
                                continue

                            self.exports[name] = ExportedSymbol(
                                name=name,
                                address=sym.entry['st_value'],
                                size=sym.entry['st_size'],
                                binding=get_binding(sym.entry['st_info']['bind']),
                                sym_type=get_type(sym.entry['st_info']['type']),
                            )

                # Also check regular symbol table
                symtab = elf.get_section_by_name('.symtab')
                if symtab:
                    for sym in symtab.iter_symbols():
                        if sym.entry['st_shndx'] != 'SHN_UNDEF' and sym.name:
                            if sym.name not in self.exports:
                                self.exports[sym.name] = ExportedSymbol(
                                    name=sym.name,
                                    address=sym.entry['st_value'],
                                    size=sym.entry['st_size'],
                                    binding=get_binding(sym.entry['st_info']['bind']),
                                    sym_type=get_type(sym.entry['st_info']['type']),
                                )

        except Exception as e:
            logger.warning(f"Failed to analyze exports: {e}")

    def _analyze_dependencies(self) -> None:
        """Analyze library dependencies."""
        try:
            from elftools.elf.elffile import ELFFile

            with open(self.binary.path, 'rb') as f:
                elf = ELFFile(f)

                dynamic = elf.get_section_by_name('.dynamic')
                if not dynamic:
                    return

                for tag in dynamic.iter_tags():
                    if tag.entry.d_tag == 'DT_NEEDED':
                        lib_name = tag.needed
                        self.dependencies[lib_name] = LibraryDependency(name=lib_name)

                # Get version requirements
                verneed = elf.get_section_by_name('.gnu.version_r')
                if verneed:
                    for entry, auxes in verneed.iter_versions():
                        lib_name = entry.name
                        if lib_name in self.dependencies:
                            for aux in auxes:
                                self.dependencies[lib_name].version_requirements.append(aux.name)

        except Exception as e:
            logger.warning(f"Failed to analyze dependencies: {e}")

        # Map imports to libraries
        for name, imp in self.imports.items():
            # Heuristic: assign to libc for common functions
            if name in DANGEROUS_IMPORTS.get("memory_unsafe", set()) | \
               DANGEROUS_IMPORTS.get("format_string", set()) | \
               DANGEROUS_IMPORTS.get("memory_mgmt", set()):
                imp.library = "libc.so.6"
                if "libc.so.6" in self.dependencies:
                    self.dependencies["libc.so.6"].symbols_used.append(name)

    def _detect_weak_symbols(self) -> None:
        """Detect weak symbols that can be overridden."""
        self.weak_symbols = [
            imp for imp in self.imports.values()
            if imp.is_weak
        ]

        # Also check for common overridable symbols
        overridable = {'malloc', 'free', 'realloc', 'calloc', 'memalign',
                      '__malloc_hook', '__free_hook', '__realloc_hook'}

        for name in overridable:
            if name in self.imports and self.imports[name] not in self.weak_symbols:
                self.weak_symbols.append(self.imports[name])

    def _analyze_lazy_binding(self) -> None:
        """Analyze lazy binding status."""
        self.lazy_bindings = []

        # Check RELRO status
        relro = self.binary.protections.relro

        if relro == "Full":
            # Full RELRO - GOT is read-only, no lazy binding
            return

        # Partial or no RELRO - lazy binding is possible
        for name, imp in self.imports.items():
            # Check if function is in PLT (lazy binding)
            if name in self.binary.plt:
                imp.is_lazy = True
                self.lazy_bindings.append(imp)

    def get_dangerous_imports(self) -> Dict[str, List[str]]:
        """
        Get categorized dangerous imports.

        Returns:
            Dictionary mapping categories to imported function names
        """
        dangerous = {}

        for category, funcs in DANGEROUS_IMPORTS.items():
            imported = [name for name in funcs if name in self.imports]
            if imported:
                dangerous[category] = imported

        return dangerous

    def detect_glibc_version(self) -> Optional[str]:
        """
        Detect minimum glibc version required.

        Returns:
            Detected glibc version or None
        """
        max_version = None

        # Check version symbols
        for name, version in GLIBC_VERSION_SYMBOLS.items():
            if name in self.imports:
                if max_version is None or self._compare_versions(version, max_version) > 0:
                    max_version = version

        # Check version requirements
        for dep in self.dependencies.values():
            if 'libc' in dep.name.lower():
                for ver_req in dep.version_requirements:
                    # Parse GLIBC_X.Y format
                    match = re.match(r'GLIBC_(\d+\.\d+(?:\.\d+)?)', ver_req)
                    if match:
                        version = match.group(1)
                        if max_version is None or self._compare_versions(version, max_version) > 0:
                            max_version = version

        return max_version

    def _compare_versions(self, v1: str, v2: str) -> int:
        """Compare version strings."""
        parts1 = [int(x) for x in v1.split('.')]
        parts2 = [int(x) for x in v2.split('.')]

        for i in range(max(len(parts1), len(parts2))):
            p1 = parts1[i] if i < len(parts1) else 0
            p2 = parts2[i] if i < len(parts2) else 0
            if p1 != p2:
                return p1 - p2

        return 0

    def find_hook_targets(self) -> List[Dict[str, Any]]:
        """
        Find potential hooking targets.

        Returns:
            List of hookable functions with details
        """
        targets = []

        # Check for malloc hooks
        hooks = ['__malloc_hook', '__free_hook', '__realloc_hook', '__memalign_hook']
        for hook in hooks:
            if hook in self.imports or hook in self.exports:
                targets.append({
                    "name": hook,
                    "type": "malloc_hook",
                    "exploitable": True,
                    "note": "Deprecated but may still work on older glibc",
                })

        # Weak symbols can be overridden
        for sym in self.weak_symbols:
            targets.append({
                "name": sym.name,
                "type": "weak_symbol",
                "address": hex(sym.address),
                "exploitable": True,
                "note": "Can be overridden via LD_PRELOAD",
            })

        # Lazy-bound functions can have GOT overwritten
        if self.binary.protections.relro != "Full":
            for sym in self.lazy_bindings:
                if sym.name in DANGEROUS_IMPORTS.get("command_exec", set()):
                    targets.append({
                        "name": sym.name,
                        "type": "got_overwrite",
                        "got_address": hex(self.binary.got.get(sym.name, 0)),
                        "exploitable": True,
                        "note": "GOT entry can be overwritten",
                    })

        return targets

    def get_exploitation_info(self) -> Dict[str, Any]:
        """
        Get exploitation-relevant import information.

        Returns:
            Dictionary with exploitation details
        """
        return {
            "dangerous_functions": self.get_dangerous_imports(),
            "hookable_targets": self.find_hook_targets(),
            "weak_symbols": [s.name for s in self.weak_symbols],
            "lazy_bound_count": len(self.lazy_bindings),
            "relro_status": self.binary.protections.relro,
            "glibc_version": self.detect_glibc_version(),
            "has_system": "system" in self.imports,
            "has_execve": "execve" in self.imports,
            "has_mprotect": "mprotect" in self.imports,
            "has_malloc": "malloc" in self.imports,
            "has_free": "free" in self.imports,
        }

    def summary(self) -> str:
        """Get import analysis summary."""
        lines = [
            "Import/Export Analysis Summary",
            "=" * 40,
            f"Imports: {len(self.imports)}",
            f"Exports: {len(self.exports)}",
            f"Dependencies: {len(self.dependencies)}",
            f"Weak Symbols: {len(self.weak_symbols)}",
            f"Lazy Bindings: {len(self.lazy_bindings)}",
            "",
        ]

        # Dangerous imports
        dangerous = self.get_dangerous_imports()
        if dangerous:
            lines.append("Dangerous Imports:")
            for category, funcs in dangerous.items():
                lines.append(f"  {category}: {', '.join(funcs)}")

        # Dependencies
        if self.dependencies:
            lines.append("")
            lines.append("Dependencies:")
            for name, dep in list(self.dependencies.items())[:5]:
                versions = ", ".join(dep.version_requirements[:3]) if dep.version_requirements else "any"
                lines.append(f"  {name} ({versions})")

        # Glibc version
        glibc_ver = self.detect_glibc_version()
        if glibc_ver:
            lines.append("")
            lines.append(f"Minimum glibc version: {glibc_ver}")

        return "\n".join(lines)
