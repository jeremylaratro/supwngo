"""
Static binary analysis using multiple tools.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from supwngo.core.binary import Binary, Symbol
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
    "argv": "command line",
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

    def __init__(self, binary: Binary):
        """
        Initialize analyzer with binary.

        Args:
            binary: Binary instance to analyze
        """
        self.binary = binary
        self._angr_cfg = None
        self._functions: Dict[str, FunctionInfo] = {}
        self._dangerous_calls: List[DangerousCall] = []
        self._strings: List[StringReference] = []

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

        Args:
            target_addr: Address to find callers for

        Returns:
            List of (caller_name, caller_addr, call_site_addr) tuples
        """
        callers = []

        try:
            # Use angr CFG if available
            proj = self.binary.get_angr_project()
            cfg = proj.analyses.CFGFast()

            # Find function containing target
            for func_addr, func in cfg.kb.functions.items():
                for block in func.blocks:
                    # Check if block calls our target
                    if hasattr(block, 'instruction_addrs'):
                        for inst_addr in block.instruction_addrs:
                            # Simplified: check if any call instruction targets our address
                            pass

            # Alternative: search for call instructions
            for func_name, func_addr in self.binary.symbols.items():
                try:
                    func = cfg.kb.functions.get(func_addr)
                    if func:
                        for block in func.blocks:
                            for succ in block.successors():
                                if succ.addr == target_addr:
                                    callers.append((func_name, func_addr, block.addr))
                except Exception:
                    continue

        except Exception as e:
            logger.debug(f"Could not find callers with angr: {e}")

        return callers

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
        """Analyze all functions in binary."""
        try:
            proj = self.binary.get_angr_project()
            cfg = proj.analyses.CFGFast()

            for func_addr, func in cfg.kb.functions.items():
                if func.name and not func.name.startswith("sub_"):
                    info = FunctionInfo(
                        name=func.name,
                        address=func_addr,
                        size=func.size,
                        calls=[],
                        called_by=[],
                    )

                    # Get callees
                    for callee in func.functions_called():
                        if callee.name:
                            info.calls.append(callee.name)

                    # Check if leaf function (no calls)
                    info.is_leaf = len(info.calls) == 0

                    self._functions[func.name] = info

        except Exception as e:
            logger.debug(f"Could not analyze functions with angr: {e}")

            # Fallback: use symbols
            for name, symbol in self.binary.symbols.items():
                self._functions[name] = FunctionInfo(
                    name=name,
                    address=symbol.address,
                    size=symbol.size,
                    calls=[],
                    called_by=[],
                )

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
