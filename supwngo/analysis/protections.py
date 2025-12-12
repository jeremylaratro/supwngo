"""
Binary protection detection and analysis.
"""

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from supwngo.core.binary import Binary, Protections
from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class DetailedProtections(Protections):
    """Extended protection information."""
    # Additional details
    full_relro: bool = False
    partial_relro: bool = False

    # Stack protections
    stack_clash_protection: bool = False
    safe_stack: bool = False

    # CFI/Shadow stack
    cfi: bool = False
    shadow_stack: bool = False

    # Compiler hardening
    stack_protector: str = ""  # none, canary, strong, all
    fortify_level: int = 0

    # Position independence
    pie_type: str = ""  # none, pie, static-pie

    # Other
    stripped: bool = False
    static: bool = False
    has_debug_info: bool = False

    # libc details
    libc_version: str = ""
    uses_tcache: bool = False


class ProtectionAnalyzer:
    """
    Comprehensive protection detection for binaries.

    Detects:
    - Stack canary
    - NX (Non-executable stack)
    - PIE (Position Independent Executable)
    - RELRO (Relocation Read-Only)
    - FORTIFY_SOURCE
    - ASLR (system-wide)
    - Additional hardening features
    """

    def __init__(self, binary: Binary):
        """
        Initialize protection analyzer.

        Args:
            binary: Binary to analyze
        """
        self.binary = binary

    def analyze(self) -> DetailedProtections:
        """
        Perform comprehensive protection analysis.

        Returns:
            DetailedProtections instance
        """
        prots = DetailedProtections()

        # Use pwntools checksec as base
        if self.binary._elf:
            prots.canary = self.binary._elf.canary
            prots.nx = self.binary._elf.nx
            prots.pie = self.binary._elf.pie
            prots.relro = self._get_relro_type()

        # Additional analysis
        prots.fortify = self._check_fortify()
        prots.fortify_level = self._get_fortify_level()
        prots.stripped = self._check_stripped()
        prots.static = self._check_static()
        prots.has_debug_info = self._check_debug_info()
        prots.stack_protector = self._get_stack_protector_type()

        # RELRO details
        if prots.relro == "Full RELRO":
            prots.full_relro = True
        elif prots.relro == "Partial RELRO":
            prots.partial_relro = True

        # PIE details
        prots.pie_type = self._get_pie_type()

        # libc analysis
        prots.libc_version = self._detect_libc_version()
        prots.uses_tcache = self._check_tcache()

        # System ASLR check
        prots.aslr = self._check_system_aslr()

        return prots

    def _get_relro_type(self) -> str:
        """Determine RELRO type."""
        if not self.binary._elf:
            return "No RELRO"

        # Check for GNU_RELRO segment
        has_relro = False
        for segment in self.binary.segments:
            if segment.type == "PT_GNU_RELRO":
                has_relro = True
                break

        if not has_relro:
            return "No RELRO"

        # Check if GOT is read-only (Full RELRO)
        got_plt = self.binary.sections.get(".got.plt")
        if got_plt is None:
            return "Full RELRO"

        # Check BIND_NOW flag
        try:
            from elftools.elf.elffile import ELFFile
            with open(self.binary.path, "rb") as f:
                elf = ELFFile(f)
                for segment in elf.iter_segments():
                    if segment.header.p_type == "PT_DYNAMIC":
                        for tag in segment.iter_tags():
                            if tag.entry.d_tag == "DT_FLAGS":
                                if tag.entry.d_val & 0x8:  # DF_BIND_NOW
                                    return "Full RELRO"
                            if tag.entry.d_tag == "DT_BIND_NOW":
                                return "Full RELRO"
        except Exception:
            pass

        return "Partial RELRO"

    def _check_fortify(self) -> bool:
        """Check for FORTIFY_SOURCE."""
        # Look for _chk functions in imports
        fortified_funcs = [
            "__printf_chk",
            "__sprintf_chk",
            "__fprintf_chk",
            "__strcpy_chk",
            "__strncpy_chk",
            "__strcat_chk",
            "__strncat_chk",
            "__memcpy_chk",
            "__memmove_chk",
            "__memset_chk",
            "__read_chk",
            "__gets_chk",
        ]

        for func in fortified_funcs:
            if func in self.binary.plt or func in self.binary.symbols:
                return True

        return False

    def _get_fortify_level(self) -> int:
        """Determine FORTIFY_SOURCE level."""
        # Check for specific _chk variants
        has_basic_chk = any(
            func in self.binary.plt
            for func in ["__printf_chk", "__sprintf_chk"]
        )

        has_advanced_chk = any(
            func in self.binary.plt
            for func in ["__longjmp_chk", "__fortify_fail"]
        )

        if has_advanced_chk:
            return 2
        elif has_basic_chk:
            return 1
        return 0

    def _check_stripped(self) -> bool:
        """Check if binary is stripped."""
        return len(self.binary.symbols) < 10

    def _check_static(self) -> bool:
        """Check if binary is statically linked."""
        # Static binaries have no PT_INTERP segment
        for segment in self.binary.segments:
            if segment.type == "PT_INTERP":
                return False
        return True

    def _check_debug_info(self) -> bool:
        """Check for debug information."""
        debug_sections = [".debug_info", ".debug_line", ".debug_str"]
        return any(sec in self.binary.sections for sec in debug_sections)

    def _get_stack_protector_type(self) -> str:
        """Determine stack protector variant."""
        if not self.binary.protections.canary:
            return "none"

        # Check for __stack_chk_fail
        if "__stack_chk_fail" in self.binary.plt:
            # Check for stack_chk_guard vs __stack_chk_guard
            if "__stack_chk_guard" in self.binary.got:
                return "strong"
            return "canary"

        return "none"

    def _get_pie_type(self) -> str:
        """Determine PIE type."""
        if not self.binary.protections.pie:
            return "none"

        # Check if it's static-pie
        if self._check_static():
            return "static-pie"

        return "pie"

    def _detect_libc_version(self) -> str:
        """Detect linked libc version."""
        # Try to find version string in binary
        for addr, string in self.binary.strings():
            if "GLIBC_" in string:
                # Extract version
                match = re.search(r"GLIBC_(\d+\.\d+)", string)
                if match:
                    return match.group(1)

        # Try ldd
        try:
            result = subprocess.run(
                ["ldd", str(self.binary.path)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            for line in result.stdout.split("\n"):
                if "libc.so" in line:
                    match = re.search(r"libc\.so\.(\d+)", line)
                    if match:
                        return match.group(1)
        except Exception:
            pass

        return ""

    def _check_tcache(self) -> bool:
        """Check if libc uses tcache (glibc >= 2.26)."""
        version = self._detect_libc_version()
        if version:
            try:
                major, minor = map(int, version.split("."))
                return major > 2 or (major == 2 and minor >= 26)
            except ValueError:
                pass
        return True  # Assume tcache by default

    def _check_system_aslr(self) -> bool:
        """Check system ASLR status."""
        try:
            with open("/proc/sys/kernel/randomize_va_space", "r") as f:
                value = int(f.read().strip())
                return value > 0
        except Exception:
            return True  # Assume enabled

    def get_bypass_strategies(self) -> List[Dict[str, Any]]:
        """
        Suggest bypass strategies for detected protections.

        Returns:
            List of bypass strategy suggestions
        """
        strategies = []
        prots = self.analyze()

        if prots.canary:
            strategies.append({
                "protection": "Stack Canary",
                "bypasses": [
                    "Leak canary via format string",
                    "Leak canary via information disclosure",
                    "Brute force (fork-based servers)",
                    "Overwrite canary with itself",
                    "Thread local storage overwrite",
                ],
            })

        if prots.nx:
            strategies.append({
                "protection": "NX (DEP)",
                "bypasses": [
                    "ROP chain",
                    "ret2libc",
                    "ret2syscall",
                    "mprotect() to disable NX",
                    "JIT spray (if applicable)",
                ],
            })

        if prots.pie:
            strategies.append({
                "protection": "PIE",
                "bypasses": [
                    "Information leak to defeat ASLR",
                    "Partial overwrite (12-bit entropy)",
                    "Brute force (32-bit)",
                    "ret2plt (known addresses)",
                ],
            })

        if prots.full_relro:
            strategies.append({
                "protection": "Full RELRO",
                "bypasses": [
                    "Target __malloc_hook / __free_hook",
                    "Target __exit_funcs",
                    "Target TLS dtors",
                    "Return address overwrite",
                ],
            })
        elif prots.partial_relro:
            strategies.append({
                "protection": "Partial RELRO",
                "bypasses": [
                    "GOT overwrite",
                    "PLT hijacking",
                ],
            })

        if prots.aslr:
            strategies.append({
                "protection": "ASLR",
                "bypasses": [
                    "Information leak",
                    "Brute force (32-bit: 8-12 bits entropy)",
                    "ret2plt / ret2dlresolve",
                    "Partial overwrite",
                    "Heap spray",
                ],
            })

        if prots.uses_tcache:
            strategies.append({
                "protection": "tcache",
                "bypasses": [
                    "tcache poisoning",
                    "tcache dup",
                    "tcache house of spirit",
                    "Safe-linking bypass (glibc >= 2.32)",
                ],
            })

        return strategies

    def checksec_report(self) -> str:
        """
        Generate checksec-style report.

        Returns:
            Formatted checksec output
        """
        prots = self.analyze()

        # Color codes for terminal
        GREEN = "\033[92m"
        RED = "\033[91m"
        YELLOW = "\033[93m"
        RESET = "\033[0m"

        def status(enabled: bool, good_if_enabled: bool = True) -> str:
            if enabled:
                color = GREEN if good_if_enabled else RED
                return f"{color}Enabled{RESET}"
            else:
                color = RED if good_if_enabled else GREEN
                return f"{color}Disabled{RESET}"

        lines = [
            f"Binary: {self.binary.path.name}",
            f"Arch:   {self.binary.arch}",
            "",
            f"RELRO:           {prots.relro}",
            f"Stack Canary:    {status(prots.canary)}",
            f"NX:              {status(prots.nx)}",
            f"PIE:             {status(prots.pie)}",
            f"FORTIFY:         {status(prots.fortify)} (level {prots.fortify_level})",
            "",
            f"Stripped:        {status(prots.stripped, good_if_enabled=False)}",
            f"Static:          {status(prots.static, good_if_enabled=False)}",
            f"Debug info:      {status(prots.has_debug_info, good_if_enabled=False)}",
        ]

        if prots.libc_version:
            lines.append(f"libc version:    {prots.libc_version}")
            lines.append(f"Uses tcache:     {'Yes' if prots.uses_tcache else 'No'}")

        return "\n".join(lines)

    def summary(self) -> str:
        """Get protection summary."""
        return self.checksec_report()
