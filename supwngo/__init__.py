"""
SupwnGo - Automated Binary Exploitation Framework

A comprehensive, modular automated binary exploitation framework that integrates
fuzzing, symbolic execution, vulnerability detection, and automatic exploit
generation into a unified pipeline.

Key Features:
- Binary analysis with protection detection
- Vulnerability detection (stack BOF, heap, format string, integer overflow)
- Exploit strategy suggestion based on protections and gadgets
- ROP chain building (ret2libc, SROP, ret2csu, ret2dlresolve)
- Automatic offset discovery for buffer overflows
- One-gadget detection in libc
- Fuzzing integration (AFL++, Honggfuzz, LibFuzzer)
- Symbolic execution with angr
- Libc identification from leaked addresses
"""

__version__ = "1.0.0"
__author__ = "SupwnGo Team"

from supwngo.core.binary import Binary
from supwngo.core.context import ExploitContext
from supwngo.core.database import Database

# Analysis modules
from supwngo.analysis.protections import ProtectionAnalyzer
from supwngo.analysis.static import StaticAnalyzer
from supwngo.analysis.one_gadget import OneGadgetFinder, find_one_gadgets
from supwngo.analysis.addresses import AddressFinder, AddressReport, find_useful_addresses
from supwngo.analysis.source import SourceAnalyzer, SourceAnalysisReport, analyze_source

# Exploit modules
from supwngo.exploit.strategy import (
    StrategySuggester,
    ExploitStrategy,
    ExploitApproach,
    suggest_strategies,
)
from supwngo.exploit.offset_finder import (
    OffsetFinder,
    PatternGenerator,
    cyclic,
    cyclic_find,
    find_offset,
)
from supwngo.exploit.rop.gadgets import GadgetFinder, Gadget
from supwngo.exploit.rop.chain import ROPChainBuilder
from supwngo.exploit.format_string import FormatStringExploiter, fmt_write, fmt_leak
from supwngo.exploit.templates import TemplateGenerator, TemplateType, ExploitTemplate
from supwngo.exploit.auto import AutoExploiter, auto_exploit, generate_exploit_script

# Vulnerability detection
from supwngo.vulns.detector import Vulnerability, VulnType, VulnSeverity
from supwngo.vulns.stack_bof import StackBufferOverflowDetector
from supwngo.vulns.format_string import FormatStringDetector
from supwngo.vulns.heap import HeapVulnerabilityDetector

# Remote exploitation
from supwngo.remote.libc_db import LibcDatabase

__all__ = [
    # Core
    "Binary",
    "ExploitContext",
    "Database",
    # Analysis
    "ProtectionAnalyzer",
    "StaticAnalyzer",
    "OneGadgetFinder",
    "find_one_gadgets",
    "AddressFinder",
    "AddressReport",
    "find_useful_addresses",
    # Source analysis
    "SourceAnalyzer",
    "SourceAnalysisReport",
    "analyze_source",
    # Exploit strategy
    "StrategySuggester",
    "ExploitStrategy",
    "ExploitApproach",
    "suggest_strategies",
    # Offset discovery
    "OffsetFinder",
    "PatternGenerator",
    "cyclic",
    "cyclic_find",
    "find_offset",
    # ROP
    "GadgetFinder",
    "Gadget",
    "ROPChainBuilder",
    # Format string exploitation
    "FormatStringExploiter",
    "fmt_write",
    "fmt_leak",
    # Exploit templates
    "TemplateGenerator",
    "TemplateType",
    "ExploitTemplate",
    # Auto-exploitation
    "AutoExploiter",
    "auto_exploit",
    "generate_exploit_script",
    # Vulnerability detection
    "Vulnerability",
    "VulnType",
    "VulnSeverity",
    "StackBufferOverflowDetector",
    "FormatStringDetector",
    "HeapVulnerabilityDetector",
    # Remote
    "LibcDatabase",
    # Version
    "__version__",
]
