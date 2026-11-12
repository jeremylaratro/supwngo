"""
Static binary analysis using multiple tools.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from supwngo.core.binary import Binary
from supwngo.utils.logging import get_logger

logger = get_logger(__name__)

# Dangerous functions that may lead to vulnerabilities
DANGEROUS_FUNCTIONS = {
    # Memory operations without bounds checking
    "gets": "Stack buffer overflow - no bounds checking",
    "strcpy": "Stack buffer overflow - no bounds checking",
    "strcat": "Stack buffer overflow - no bounds checking",
    "sprintf": "Stack buffer overflow - no format length limit",
    "vsprintf": "Stack buffer overflow - no format length limit",

    # Format string vulnerabilities
    "printf": "Format string vulnerability if user-controlled",
    "fprintf": "Format string vulnerability if user-controlled",
    "sprintf": "Format string vulnerability if user-controlled",
    "snprintf": "Format string vulnerability if user-controlled",
    "vprintf": "Format string vulnerability if user-controlled",
    "vfprintf": "Format string vulnerability if user-controlled",
    "vsprintf": "Format string vulnerability if user-controlled",
    "vsnprintf": "Format string vulnerability if user-controlled",
    "syslog": "Format string vulnerability if user-controlled",

    # Bounded but still risky
    "strncpy": "May not null-terminate if src >= n",
    "strncat": "Size parameter often misused",
    "scanf": "Buffer overflow without width specifier",
    "fscanf": "Buffer overflow without width specifier",
    "sscanf": "Buffer overflow without width specifier",
    "read": "Buffer overflow if size not validated",
    "recv": "Buffer overflow if size not validated",
    "recvfrom": "Buffer overflow if size not validated",

    # Memory allocation issues
    "malloc": "Integer overflow in size calculation",
    "calloc": "Integer overflow in size calculation",
    "realloc": "Integer overflow, use-after-realloc",
    "free": "Double-free, use-after-free",

    # Command execution
    "system": "Command injection if user input",
    "popen": "Command injection if user input",
    "execve": "Command injection if user input",
    "execl": "Command injection if user input",
    "execv": "Command injection if user input",

    # File operations
    "fopen": "Path traversal if user input",
    "open": "Path traversal if user input",
    "access": "TOCTOU race condition",
}

# Input sources for taint tracking
INPUT_SOURCES = {
    "read": "stdin/file",
    "fread": "file",
    "fgets": "stdin/file",
    "gets": "stdin",
    "scanf": "stdin",
    "fscanf": "file",
    "recv": "network",
    "recvfrom": "network",
    "recvmsg": "network",
    "getenv": "environment",
}


@dataclass
class DangerousCall:
    """Represents a call to a dangerous function."""
    function: str
    address: int
    caller: str
    caller_address: int
    risk: str
    context: str = ""


@dataclass
class StringReference:
    """A string found in the binary."""
    address: int
    value: str
    section: str
    references: List[int] = field(default_factory=list)


@dataclass
class FunctionInfo:
    """Detailed function information."""
    name: str
    address: int
    size: int
    calls: List[str] = field(default_factory=list)
    called_by: List[str] = field(default_factory=list)
    local_vars_size: int = 0
    has_canary: bool = False
    is_leaf: bool = True


class StaticAnalyzer:
    """
    Comprehensive static binary analysis.

    Combines multiple analysis techniques:
    - Symbol and string extraction
    - Control flow analysis
    - Dangerous function detection
    - Input source identification
    """

    def __init__(self, binary: Binary, angr_timeout: Optional[float] = None):
        """
        Initialize analyzer with binary.

        Args:
            binary: Binary instance to analyze
            angr_timeout: Wall-clock budget (seconds) for the angr function
                analysis before falling back to symbols. ``None`` uses the module
                default (``SUPWNGO_ANGR_TIMEOUT`` or 30 s).
        """
        from supwngo.analysis._angr_subprocess import DEFAULT_ANGR_TIMEOUT

        self.binary = binary
        self._angr_cfg = None
        self._functions: Dict[str, FunctionInfo] = {}
        self._dangerous_calls: List[DangerousCall] = []
        self._strings: List[StringReference] = []
        self._angr_timeout = DEFAULT_ANGR_TIMEOUT if angr_timeout is None else angr_timeout
        #: Provenance of the function analysis.
        self.analysis_backend: str = "angr"
        self.angr_budget_exceeded: bool = False

    def analyze(self) -> Dict[str, Any]:
        """
        Perform full static analysis.

        Returns:
            Dictionary containing analysis results
        """
        logger.info(f"Starting static analysis of {self.binary.path}")

        results = {
            "binary": str(self.binary.path),
            "protections": self.binary.checksec(),
            "dangerous_calls": [],
            "input_sources": [],
            "interesting_strings": [],
            "functions": {},
        }

        # Find dangerous function calls
        self._dangerous_calls = self.find_dangerous_functions()
        results["dangerous_calls"] = [
            {
                "function": dc.function,
                "address": hex(dc.address),
                "caller": dc.caller,
                "risk": dc.risk,
            }
            for dc in self._dangerous_calls
        ]

        # Identify input sources
        results["input_sources"] = self.detect_input_sources()

        # Extract interesting strings
        self._strings = self.get_interesting_strings()
        results["interesting_strings"] = [
            {"address": hex(s.address), "value": s.value}
            for s in self._strings[:100]  # Limit output
        ]

        # Build function information
        self._analyze_functions()
        results["functions"] = {
            name: {
                "address": hex(f.address),
                "size": f.size,
                "calls": f.calls,
            }
            for name, f in list(self._functions.items())[:50]
        }
        results["analysis_backend"] = self.analysis_backend
        results["angr_budget_exceeded"] = self.angr_budget_exceeded

        logger.info(f"Found {len(self._dangerous_calls)} dangerous calls")
        return results

    def find_dangerous_functions(self) -> List[DangerousCall]:
        """
        Find calls to dangerous functions.

        Returns:
            List of DangerousCall instances
        """
        dangerous_calls = []

        # Check PLT entries for dangerous functions
        for func_name, plt_addr in self.binary.plt.items():
            if func_name in DANGEROUS_FUNCTIONS:
                risk = DANGEROUS_FUNCTIONS[func_name]

                # Find callers using cross-references
                callers = self._find_callers(plt_addr)

                for caller_name, caller_addr, call_addr in callers:
                    dangerous_calls.append(DangerousCall(
                        function=func_name,
                        address=call_addr,
                        caller=caller_name,
                        caller_address=caller_addr,
                        risk=risk,
                    ))

        # If no xrefs available, just record the imported dangerous functions
        if not dangerous_calls:
            for func_name, plt_addr in self.binary.plt.items():
                if func_name in DANGEROUS_FUNCTIONS:
                    dangerous_calls.append(DangerousCall(
                        function=func_name,
                        address=plt_addr,
                        caller="unknown",
                        caller_address=0,
                        risk=DANGEROUS_FUNCTIONS[func_name],
                    ))

        return dangerous_calls

    def _find_callers(self, target_addr: int) -> List[Tuple[str, int, int]]:
        """
        Find functions that call a target address.

        Returns an empty list. The former angr implementation here never
        returned any caller: its first loop body was ``pass``, and its second
        iterated ``self.binary.symbols.items()`` (which binds a ``Symbol``, not
        an address) into ``cfg.kb.functions.get(Symbol)`` -- a ``Symbol`` is
        unhashable, so every lookup raised and was swallowed. It only ever paid
        for a full ``CFGFast`` build (once per dangerous PLT entry) and returned
        ``[]``. S4b-i removes that dead build -- the dominant hang on a large
        static binary's ``analyze`` -- while preserving the ``[]`` result. The
        latent "callers are never computed" defect is tracked separately in the
        work queue (it is a correctness gap, not part of the RT-05 timeout fix).
        """
        return []

    def _functions_from_symbols(self) -> None:
        """Populate function info from the symbol table (non-angr fallback)."""
        for name, symbol in self.binary.symbols.items():
            self._functions[name] = FunctionInfo(
                name=name,
                address=symbol.address,
                size=symbol.size,
                calls=[],
                called_by=[],
            )

    def detect_input_sources(self) -> List[Dict[str, Any]]:
        """
        Detect input sources in the binary.

        Returns:
            List of input source descriptions
        """
        sources = []

        for func_name, source_type in INPUT_SOURCES.items():
            if func_name in self.binary.plt:
                sources.append({
                    "function": func_name,
                    "type": source_type,
                    "plt_address": hex(self.binary.plt[func_name]),
                })

        # Check for socket-related functions
        socket_funcs = ["socket", "bind", "listen", "accept", "connect"]
        has_networking = any(f in self.binary.plt for f in socket_funcs)
        if has_networking:
            sources.append({
                "function": "networking",
                "type": "network socket",
                "plt_address": "multiple",
            })

        # Check for file operations
        # NOTE: this is NOT a vector oracle (B-2,
        # docs/plans/2026-09-26-legacy-to-canonical-gap-analysis.md item B-2).
        # `read` is the stdin primitive, so every stdin-only target also has
        # `read` in its PLT and gets labeled "file input" here regardless of
        # where its bytes actually come from. Use
        # `supwngo/analysis/vector_probe.py`'s `classify_input_vector()` for
        # actual (advisory) vector classification.
        file_funcs = ["fopen", "open", "fread", "read"]
        has_file_io = any(f in self.binary.plt for f in file_funcs)
        if has_file_io:
            sources.append({
                "function": "file_io",
                "type": "file input",
                "plt_address": "multiple",
            })

        return sources

    def get_interesting_strings(self) -> List[StringReference]:
        """
        Extract interesting strings from binary.

        Returns:
            List of StringReference instances
        """
        interesting = []
        all_strings = self.binary.strings(min_length=4)

        # Patterns for interesting strings
        patterns = [
            (r"/bin/sh", "shell"),
            (r"/bin/bash", "shell"),
            (r"flag", "flag"),
            (r"password", "credential"),
            (r"secret", "credential"),
            (r"admin", "credential"),
            (r"%[0-9]*\$", "format_specifier"),
            (r"%s", "format_specifier"),
            (r"%n", "format_write"),
            (r"%p", "format_leak"),
            (r"http://", "url"),
            (r"https://", "url"),
            (r"/etc/passwd", "sensitive_file"),
            (r"/etc/shadow", "sensitive_file"),
            (r"\.so", "library"),
            (r"GLIBC", "version"),
        ]

        for addr, string in all_strings:
            # Check if string matches any interesting pattern
            for pattern, category in patterns:
                if re.search(pattern, string, re.IGNORECASE):
                    interesting.append(StringReference(
                        address=addr,
                        value=string[:100],  # Truncate long strings
                        section=self._get_section_for_addr(addr),
                    ))
                    break

        # Also include strings with format specifiers
        for addr, string in all_strings:
            if "%" in string and string not in [s.value for s in interesting]:
                if any(c in string for c in "sdxpn"):
                    interesting.append(StringReference(
                        address=addr,
                        value=string[:100],
                        section=self._get_section_for_addr(addr),
                    ))

        return interesting

    def _get_section_for_addr(self, addr: int) -> str:
        """Get section name for an address."""
        for name, section in self.binary.sections.items():
            if section.address <= addr < section.address + section.size:
                return name
        return "unknown"

    def _analyze_functions(self) -> None:
        """Analyze all functions in binary (angr summary, budgeted; symbols on fail)."""
        from supwngo.analysis._angr_subprocess import (
            AnalysisBudgetExceeded,
            run_angr_op,
        )

        try:
            data = run_angr_op(str(self.binary.path), "static_functions", self._angr_timeout)
            for name, fn in data.items():
                info = FunctionInfo(
                    name=name,
                    address=fn["address"],
                    size=fn["size"],
                    calls=list(fn["calls"]),
                    called_by=[],
                )
                info.is_leaf = len(info.calls) == 0
                self._functions[name] = info
            self.analysis_backend = "angr"
        except AnalysisBudgetExceeded as e:
            logger.warning(
                f"angr function analysis exceeded its {self._angr_timeout:g}s budget "
                f"({e}); using the symbol table"
            )
            self.angr_budget_exceeded = True
            self.analysis_backend = "symbols"
            self._functions_from_symbols()
        except Exception as e:
            logger.debug(f"Could not analyze functions with angr: {e}; using the symbol table")
            self.analysis_backend = "symbols"
            self._functions_from_symbols()

    def build_cfg(self) -> Any:
        """
        Build control flow graph using angr.

        Returns:
            angr CFG object
        """
        try:
            proj = self.binary.get_angr_project()
            self._angr_cfg = proj.analyses.CFGFast()
            logger.debug(f"Built CFG with {len(self._angr_cfg.graph.nodes())} nodes")
            return self._angr_cfg
        except Exception as e:
            logger.error(f"Failed to build CFG: {e}")
            return None

    def get_function_cfg(self, func_name: str) -> Any:
        """
        Get CFG for a specific function.

        Args:
            func_name: Function name

        Returns:
            Function CFG or None
        """
        if not self._angr_cfg:
            self.build_cfg()

        if self._angr_cfg and func_name in self._angr_cfg.kb.functions:
            return self._angr_cfg.kb.functions[func_name]

        return None

    def find_vulnerability_sinks(self) -> List[DangerousCall]:
        """
        Find potential vulnerability sinks (dangerous function calls
        that could be exploitable).

        Returns:
            Sorted list of dangerous calls by exploitability
        """
        sinks = []

        # High-priority sinks
        high_priority = {"gets", "strcpy", "sprintf", "system", "execve"}
        medium_priority = {"strncpy", "scanf", "read", "recv", "printf"}

        for dc in self._dangerous_calls:
            if dc.function in high_priority:
                dc.context = "HIGH"
                sinks.insert(0, dc)
            elif dc.function in medium_priority:
                dc.context = "MEDIUM"
                sinks.append(dc)
            else:
                dc.context = "LOW"
                sinks.append(dc)

        return sinks

    def summary(self) -> str:
        """Get analysis summary."""
        lines = [
            f"Static Analysis Summary for {self.binary.path.name}",
            "=" * 50,
            "",
            "Protections:",
            str(self.binary.protections),
            "",
            f"Dangerous Functions: {len(self._dangerous_calls)}",
        ]

        for dc in self._dangerous_calls[:10]:
            lines.append(f"  - {dc.function}() at 0x{dc.address:x}")

        if len(self._dangerous_calls) > 10:
            lines.append(f"  ... and {len(self._dangerous_calls) - 10} more")

        lines.append("")
        lines.append(f"Interesting Strings: {len(self._strings)}")

        for s in self._strings[:5]:
            lines.append(f"  - 0x{s.address:x}: {s.value[:50]}")

        return "\n".join(lines)
