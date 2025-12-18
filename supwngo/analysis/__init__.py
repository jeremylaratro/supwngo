"""Binary analysis modules for static and dynamic analysis."""

from supwngo.analysis.static import StaticAnalyzer
from supwngo.analysis.dynamic import DynamicAnalyzer
from supwngo.analysis.protections import ProtectionAnalyzer

# Phase 1 additions: Reverse Engineering & Analysis Enhancements
from supwngo.analysis.cfg import CFGAnalyzer, BasicBlock, Function, Loop
from supwngo.analysis.dataflow import DataFlowAnalyzer, TaintSource, TaintState
from supwngo.analysis.strings import StringAnalyzer, StringCategory, AnalyzedString
from supwngo.analysis.diff import BinaryDiffer, FunctionMatch, PatchInfo
from supwngo.analysis.decompile import Decompiler, DecompiledFunction
from supwngo.analysis.imports import ImportAnalyzer, ImportedSymbol, ExportedSymbol

__all__ = [
    # Original
    "StaticAnalyzer",
    "DynamicAnalyzer",
    "ProtectionAnalyzer",
    # CFG Analysis
    "CFGAnalyzer",
    "BasicBlock",
    "Function",
    "Loop",
    # Data Flow Analysis
    "DataFlowAnalyzer",
    "TaintSource",
    "TaintState",
    # String Analysis
    "StringAnalyzer",
    "StringCategory",
    "AnalyzedString",
    # Binary Diffing
    "BinaryDiffer",
    "FunctionMatch",
    "PatchInfo",
    # Decompilation
    "Decompiler",
    "DecompiledFunction",
    # Import Analysis
    "ImportAnalyzer",
    "ImportedSymbol",
    "ExportedSymbol",
]
