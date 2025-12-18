"""Vulnerability detection modules."""

from supwngo.vulns.detector import VulnerabilityDetector, Vulnerability
from supwngo.vulns.stack_bof import StackBufferOverflowDetector
from supwngo.vulns.heap import HeapVulnerabilityDetector
from supwngo.vulns.format_string import FormatStringDetector, BlindOffsetFinder, OffsetFinderResult
from supwngo.vulns.integer import IntegerOverflowDetector
from supwngo.vulns.off_by_one import OffByOneDetector, NullByteExploiter
from supwngo.vulns.uaf import UAFDetector, VtableHijacker, TypeConfusionDetector
from supwngo.vulns.canary_bypass import (
    CanaryBypassDetector,
    CanaryBypassType,
    ScanfBypassInfo,
    detect_canary_bypass,
    get_scanf_skip_payload,
)
from supwngo.vulns.race import (
    RaceConditionDetector,
    RaceType,
    RaceWindow,
    TOCTOUExploiter,
    SymlinkRacer,
    detect_toctou,
    generate_toctou_exploit,
)
# Phase 2: Advanced detection modules
from supwngo.vulns.leak_finder import (
    LeakFinder,
    LeakType,
    LeakPrimitive,
    LeakOpportunity,
    LeakChain,
)
from supwngo.vulns.heap_advanced import (
    AdvancedHeapAnalyzer,
    HeapVulnType,
    AllocationSite,
    HeapVulnerability,
)
from supwngo.vulns.integer_advanced import (
    AdvancedIntegerAnalyzer,
    IntVulnType,
    IntContext,
    IntegerOperation,
    IntegerVulnerability,
)
from supwngo.vulns.race_advanced import (
    AdvancedRaceAnalyzer,
    AdvancedRaceType,
    RaceWindow,
    SignalHandlerInfo,
    ThreadUnsafeCall,
    AdvancedRaceVuln,
)

__all__ = [
    "VulnerabilityDetector",
    "Vulnerability",
    "StackBufferOverflowDetector",
    "HeapVulnerabilityDetector",
    "FormatStringDetector",
    "BlindOffsetFinder",
    "OffsetFinderResult",
    "IntegerOverflowDetector",
    # Off-by-one
    "OffByOneDetector",
    "NullByteExploiter",
    # UAF
    "UAFDetector",
    "VtableHijacker",
    "TypeConfusionDetector",
    # Canary bypass
    "CanaryBypassDetector",
    "CanaryBypassType",
    "ScanfBypassInfo",
    "detect_canary_bypass",
    "get_scanf_skip_payload",
    # Race conditions
    "RaceConditionDetector",
    "RaceType",
    "RaceWindow",
    "TOCTOUExploiter",
    "SymlinkRacer",
    "detect_toctou",
    "generate_toctou_exploit",
    # Phase 2: Advanced detection
    "LeakFinder",
    "LeakType",
    "LeakPrimitive",
    "LeakOpportunity",
    "LeakChain",
    "AdvancedHeapAnalyzer",
    "HeapVulnType",
    "AllocationSite",
    "HeapVulnerability",
    "AdvancedIntegerAnalyzer",
    "IntVulnType",
    "IntContext",
    "IntegerOperation",
    "IntegerVulnerability",
    # Advanced race detection
    "AdvancedRaceAnalyzer",
    "AdvancedRaceType",
    "RaceWindow",
    "SignalHandlerInfo",
    "ThreadUnsafeCall",
    "AdvancedRaceVuln",
]
