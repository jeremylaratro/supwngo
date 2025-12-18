"""Fuzzing integration modules for AFL++, Honggfuzz, and crash triage."""

from supwngo.fuzzing.afl import AFLFuzzer
from supwngo.fuzzing.honggfuzz import HonggfuzzFuzzer
from supwngo.fuzzing.libfuzzer import LibFuzzer
from supwngo.fuzzing.crash_triage import CrashTriager, CrashCase

# Advanced fuzzing techniques
from supwngo.fuzzing.snapshot import (
    SnapshotFuzzer,
    ForkBasedSnapshot,
    MemorySnapshot,
    SnapshotConfig,
    SnapshotMethod,
    ProcessSnapshot,
    FuzzingStats,
    generate_snapshot_fuzzer_template,
)
from supwngo.fuzzing.grammar import (
    GrammarFuzzer,
    GrammarParser,
    GrammarGenerator,
    GrammarMutator,
    Grammar,
    GrammarRule,
    RuleType,
    HTTP_GRAMMAR,
    JSON_GRAMMAR,
)
from supwngo.fuzzing.cmplog import (
    CMPLOGFuzzer,
    CMPLOGInstrumenter,
    ComparisonExtractor,
    DictionaryGenerator,
    InputToState,
    CMPLOGConfig,
    ComparisonType,
    ComparisonOperand,
    generate_cmplog_harness,
)

__all__ = [
    # Core fuzzers
    "AFLFuzzer",
    "HonggfuzzFuzzer",
    "LibFuzzer",
    "CrashTriager",
    "CrashCase",
    # Snapshot fuzzing
    "SnapshotFuzzer",
    "ForkBasedSnapshot",
    "MemorySnapshot",
    "SnapshotConfig",
    "SnapshotMethod",
    "ProcessSnapshot",
    "FuzzingStats",
    "generate_snapshot_fuzzer_template",
    # Grammar-aware fuzzing
    "GrammarFuzzer",
    "GrammarParser",
    "GrammarGenerator",
    "GrammarMutator",
    "Grammar",
    "GrammarRule",
    "RuleType",
    "HTTP_GRAMMAR",
    "JSON_GRAMMAR",
    # CMPLOG integration
    "CMPLOGFuzzer",
    "CMPLOGInstrumenter",
    "ComparisonExtractor",
    "DictionaryGenerator",
    "InputToState",
    "CMPLOGConfig",
    "ComparisonType",
    "ComparisonOperand",
    "generate_cmplog_harness",
]
