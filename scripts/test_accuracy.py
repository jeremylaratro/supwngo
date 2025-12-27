#!/usr/bin/env python3
"""
Comprehensive accuracy testing for supwngo framework.

Tests:
1. Vulnerability detection (true/false positives/negatives)
2. Protection detection accuracy
3. Exploit technique selection
4. Auto-exploit success rate
"""

import os
import sys
import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict

# Add supwngo to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from supwngo.core.binary import Binary
from supwngo.vulns import (
    StackBufferOverflowDetector,
    HeapVulnerabilityDetector,
    FormatStringDetector,
    IntegerOverflowDetector,
    OffByOneDetector,
    UAFDetector,
    RaceConditionDetector,
)
from supwngo.exploit.auto import AutoExploiter, auto_exploit, smart_auto_exploit
from supwngo.exploit.chainer import ExploitChainer, suggest_techniques


@dataclass
class TestResult:
    """Result of a single test."""
    binary_name: str
    category: str
    expected_vulns: List[str]
    detected_vulns: List[str]
    expected_exploitable: bool
    detected_exploitable: bool
    exploit_attempted: bool = False
    exploit_succeeded: bool = False
    technique_used: str = ""
    notes: List[str] = field(default_factory=list)


@dataclass
class CategoryStats:
    """Statistics for a category."""
    total: int = 0
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    exploit_attempts: int = 0
    exploit_successes: int = 0

    @property
    def precision(self) -> float:
        if self.true_positives + self.false_positives == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_positives)

    @property
    def recall(self) -> float:
        if self.true_positives + self.false_negatives == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_negatives)

    @property
    def f1_score(self) -> float:
        if self.precision + self.recall == 0:
            return 0.0
        return 2 * (self.precision * self.recall) / (self.precision + self.recall)

    @property
    def accuracy(self) -> float:
        total = self.true_positives + self.true_negatives + self.false_positives + self.false_negatives
        if total == 0:
            return 0.0
        return (self.true_positives + self.true_negatives) / total


# Define expected vulnerabilities for each test binary
VULNERABLE_BINARIES = {
    # test_vulns - all vulnerable
    "01_stack_bof_basic": ["stack_bof"],
    "02_format_string": ["format_string"],
    "03_ret2libc": ["stack_bof"],
    "04_heap_uaf": ["uaf", "heap"],
    "05_integer_overflow": ["integer_overflow"],
    "06_off_by_one": ["off_by_one"],
    "07_double_free": ["double_free", "heap"],
    "08_rop_chain": ["stack_bof"],
    "09_got_overwrite": ["format_string"],
    "10_shellcode": ["stack_bof"],
    # test_binaries - phase 1 tests
    "test_pivot": ["stack_bof"],
    "test_ret2reg": ["stack_bof"],
    "test_fmtstr": ["format_string"],
    "test_partial": ["stack_bof"],
    # heap challenges
    "house_of_force_vuln": ["heap"],
    "house_of_spirit_vuln": ["heap"],
    "unsorted_bin_vuln": ["heap"],
    "large_bin_vuln": ["heap"],
}

# Secure binaries - should NOT detect vulnerabilities
SECURE_BINARIES = [
    "01_safe_input",
    "02_safe_printf",
    "03_safe_heap",
    "04_safe_read",
    "05_safe_strcpy",
    "06_safe_integer",
    "07_calculator",
    "08_file_reader",
    "09_linked_list",
    "10_echo_server",
]

# No-protection but safe binaries
NOPROTECT_SAFE = [
    "01_no_canary_safe",
    "02_no_nx_safe",
    "03_no_pie_safe",
    "04_no_relro_safe",
    "05_all_disabled_safe",
    "06_heap_safe_noprotect",
    "07_win_func_safe",
    "08_system_in_plt_safe",
    "09_gadgets_present_safe",
    "10_misleading_names_safe",
]


def detect_vulnerabilities(binary: Binary) -> List[str]:
    """Run all vulnerability detectors on a binary."""
    detected = []

    try:
        # Stack buffer overflow
        detector = StackBufferOverflowDetector(binary)
        vulns = detector.detect()
        if vulns:
            detected.append("stack_bof")
    except Exception as e:
        pass

    try:
        # Format string
        detector = FormatStringDetector(binary)
        vulns = detector.detect()
        if vulns:
            detected.append("format_string")
    except Exception as e:
        pass

    try:
        # Heap vulnerabilities
        detector = HeapVulnerabilityDetector(binary)
        vulns = detector.detect()
        if vulns:
            detected.append("heap")
    except Exception as e:
        pass

    try:
        # Integer overflow
        detector = IntegerOverflowDetector(binary)
        vulns = detector.detect()
        if vulns:
            detected.append("integer_overflow")
    except Exception as e:
        pass

    try:
        # Off-by-one
        detector = OffByOneDetector(binary)
        vulns = detector.detect()
        if vulns:
            detected.append("off_by_one")
    except Exception as e:
        pass

    try:
        # UAF
        detector = UAFDetector(binary)
        vulns = detector.detect()
        if vulns:
            detected.append("uaf")
    except Exception as e:
        pass

    try:
        # Double free (check via heap detector)
        detector = HeapVulnerabilityDetector(binary)
        vulns = detector.detect()
        for v in vulns:
            if "double" in str(v.description).lower() or "free" in str(v.description).lower():
                detected.append("double_free")
                break
    except Exception as e:
        pass

    try:
        # Race conditions
        detector = RaceConditionDetector(binary)
        vulns = detector.detect()
        if vulns:
            detected.append("race_condition")
    except Exception as e:
        pass

    return list(set(detected))


def test_binary(binary_path: Path, expected_vulns: List[str], category: str) -> TestResult:
    """Test a single binary."""
    result = TestResult(
        binary_name=binary_path.name,
        category=category,
        expected_vulns=expected_vulns,
        detected_vulns=[],
        expected_exploitable=len(expected_vulns) > 0,
        detected_exploitable=False,
    )

    try:
        binary = Binary.load(str(binary_path))
        result.detected_vulns = detect_vulnerabilities(binary)
        result.detected_exploitable = len(result.detected_vulns) > 0

        # Try auto-exploit if expected to be vulnerable
        if result.expected_exploitable:
            result.exploit_attempted = True
            try:
                report = auto_exploit(binary, timeout=3.0)
                if report.successful:
                    result.exploit_succeeded = True
                    result.technique_used = report.technique_used
            except Exception as e:
                result.notes.append(f"Exploit error: {str(e)[:50]}")

    except Exception as e:
        result.notes.append(f"Load error: {str(e)[:50]}")

    return result


def test_protection_detection(binary_path: Path) -> Dict[str, Any]:
    """Test protection detection accuracy."""
    try:
        binary = Binary.load(str(binary_path))
        protections = binary.protections

        return {
            "binary": binary_path.name,
            "canary": protections.canary,
            "nx": protections.nx,
            "pie": protections.pie,
            "relro": protections.relro,
        }
    except Exception as e:
        return {"binary": binary_path.name, "error": str(e)}


def test_chainer_suggestions(binary_path: Path) -> Dict[str, Any]:
    """Test exploit chainer suggestions."""
    try:
        binary = Binary.load(str(binary_path))
        suggestions = suggest_techniques(binary, goal="shell")

        chainer = ExploitChainer(binary)
        chainer.analyze()
        chains = chainer.build_chains()

        return {
            "binary": binary_path.name,
            "suggestions": suggestions,
            "chains_found": len(chains),
            "best_probability": chains[0].success_probability if chains else 0.0,
        }
    except Exception as e:
        return {"binary": binary_path.name, "error": str(e)}


def find_binaries(base_path: Path) -> Dict[str, List[Path]]:
    """Find all test binaries organized by category."""
    binaries = {
        "vulnerable": [],
        "secure": [],
        "noprotect_safe": [],
        "heap": [],
    }

    # test_vulns directory
    vulns_dir = base_path / "test_vulns"
    if vulns_dir.exists():
        for f in vulns_dir.iterdir():
            if f.is_file() and not f.suffix and f.name in VULNERABLE_BINARIES:
                binaries["vulnerable"].append(f)

    # test_secure directory
    secure_dir = base_path / "test_secure"
    if secure_dir.exists():
        for f in secure_dir.iterdir():
            if f.is_file() and not f.suffix and f.name in SECURE_BINARIES:
                binaries["secure"].append(f)

    # test_noprotect directory
    noprotect_dir = base_path / "test_noprotect"
    if noprotect_dir.exists():
        for f in noprotect_dir.iterdir():
            if f.is_file() and not f.suffix and f.name in NOPROTECT_SAFE:
                binaries["noprotect_safe"].append(f)

    # test_binaries directory (phase 1 + heap)
    binaries_dir = base_path / "test_binaries"
    if binaries_dir.exists():
        for f in binaries_dir.iterdir():
            if f.is_file() and not f.suffix and f.name in VULNERABLE_BINARIES:
                binaries["vulnerable"].append(f)

        heap_dir = binaries_dir / "heap"
        if heap_dir.exists():
            for f in heap_dir.iterdir():
                if f.is_file() and not f.suffix:
                    binaries["heap"].append(f)

    return binaries


def run_tests(base_path: Path) -> Tuple[List[TestResult], Dict[str, CategoryStats]]:
    """Run all tests and return results."""
    binaries = find_binaries(base_path)
    results = []
    stats = defaultdict(CategoryStats)

    print("\n" + "=" * 70)
    print("VULNERABILITY DETECTION TESTING")
    print("=" * 70)

    # Test vulnerable binaries
    print("\n[+] Testing VULNERABLE binaries...")
    for binary_path in binaries["vulnerable"]:
        expected = VULNERABLE_BINARIES.get(binary_path.name, [])
        result = test_binary(binary_path, expected, "vulnerable")
        results.append(result)

        stats["vulnerable"].total += 1
        if result.detected_exploitable and result.expected_exploitable:
            stats["vulnerable"].true_positives += 1
            status = "TP"
        elif result.detected_exploitable and not result.expected_exploitable:
            stats["vulnerable"].false_positives += 1
            status = "FP"
        elif not result.detected_exploitable and result.expected_exploitable:
            stats["vulnerable"].false_negatives += 1
            status = "FN"
        else:
            stats["vulnerable"].true_negatives += 1
            status = "TN"

        if result.exploit_attempted:
            stats["vulnerable"].exploit_attempts += 1
            if result.exploit_succeeded:
                stats["vulnerable"].exploit_successes += 1

        exploit_status = ""
        if result.exploit_succeeded:
            exploit_status = f" [EXPLOIT: {result.technique_used}]"
        elif result.exploit_attempted:
            exploit_status = " [EXPLOIT: FAILED]"

        print(f"  {binary_path.name}: {status} - detected={result.detected_vulns}{exploit_status}")

    # Test secure binaries (should NOT detect vulnerabilities)
    print("\n[+] Testing SECURE binaries (expecting no vulnerabilities)...")
    for binary_path in binaries["secure"]:
        result = test_binary(binary_path, [], "secure")
        results.append(result)

        stats["secure"].total += 1
        if result.detected_exploitable:
            stats["secure"].false_positives += 1
            status = "FP"
        else:
            stats["secure"].true_negatives += 1
            status = "TN"

        print(f"  {binary_path.name}: {status} - detected={result.detected_vulns}")

    # Test no-protection but safe binaries
    print("\n[+] Testing NO-PROTECTION SAFE binaries...")
    for binary_path in binaries["noprotect_safe"]:
        result = test_binary(binary_path, [], "noprotect_safe")
        results.append(result)

        stats["noprotect_safe"].total += 1
        if result.detected_exploitable:
            stats["noprotect_safe"].false_positives += 1
            status = "FP"
        else:
            stats["noprotect_safe"].true_negatives += 1
            status = "TN"

        print(f"  {binary_path.name}: {status} - detected={result.detected_vulns}")

    # Test heap binaries
    print("\n[+] Testing HEAP binaries...")
    for binary_path in binaries["heap"]:
        expected = VULNERABLE_BINARIES.get(binary_path.name, ["heap"])
        result = test_binary(binary_path, expected, "heap")
        results.append(result)

        stats["heap"].total += 1
        if result.detected_exploitable and result.expected_exploitable:
            stats["heap"].true_positives += 1
            status = "TP"
        elif result.detected_exploitable and not result.expected_exploitable:
            stats["heap"].false_positives += 1
            status = "FP"
        elif not result.detected_exploitable and result.expected_exploitable:
            stats["heap"].false_negatives += 1
            status = "FN"
        else:
            stats["heap"].true_negatives += 1
            status = "TN"

        print(f"  {binary_path.name}: {status} - detected={result.detected_vulns}")

    return results, dict(stats)


def print_statistics(stats: Dict[str, CategoryStats]):
    """Print detailed statistics."""
    print("\n" + "=" * 70)
    print("ACCURACY STATISTICS")
    print("=" * 70)

    overall = CategoryStats()

    for category, cat_stats in stats.items():
        print(f"\n[{category.upper()}]")
        print(f"  Total binaries: {cat_stats.total}")
        print(f"  True Positives:  {cat_stats.true_positives}")
        print(f"  False Positives: {cat_stats.false_positives}")
        print(f"  True Negatives:  {cat_stats.true_negatives}")
        print(f"  False Negatives: {cat_stats.false_negatives}")
        print(f"  Precision: {cat_stats.precision:.2%}")
        print(f"  Recall:    {cat_stats.recall:.2%}")
        print(f"  F1 Score:  {cat_stats.f1_score:.2%}")
        print(f"  Accuracy:  {cat_stats.accuracy:.2%}")

        if cat_stats.exploit_attempts > 0:
            success_rate = cat_stats.exploit_successes / cat_stats.exploit_attempts
            print(f"  Exploit Success Rate: {success_rate:.2%} ({cat_stats.exploit_successes}/{cat_stats.exploit_attempts})")

        # Aggregate
        overall.total += cat_stats.total
        overall.true_positives += cat_stats.true_positives
        overall.false_positives += cat_stats.false_positives
        overall.true_negatives += cat_stats.true_negatives
        overall.false_negatives += cat_stats.false_negatives
        overall.exploit_attempts += cat_stats.exploit_attempts
        overall.exploit_successes += cat_stats.exploit_successes

    print("\n" + "-" * 70)
    print("OVERALL")
    print("-" * 70)
    print(f"  Total binaries: {overall.total}")
    print(f"  True Positives:  {overall.true_positives}")
    print(f"  False Positives: {overall.false_positives}")
    print(f"  True Negatives:  {overall.true_negatives}")
    print(f"  False Negatives: {overall.false_negatives}")
    print(f"  Precision: {overall.precision:.2%}")
    print(f"  Recall:    {overall.recall:.2%}")
    print(f"  F1 Score:  {overall.f1_score:.2%}")
    print(f"  Accuracy:  {overall.accuracy:.2%}")

    if overall.exploit_attempts > 0:
        success_rate = overall.exploit_successes / overall.exploit_attempts
        print(f"  Exploit Success Rate: {success_rate:.2%} ({overall.exploit_successes}/{overall.exploit_attempts})")


def test_protection_accuracy(base_path: Path):
    """Test protection detection accuracy."""
    print("\n" + "=" * 70)
    print("PROTECTION DETECTION")
    print("=" * 70)

    binaries = find_binaries(base_path)
    all_binaries = []
    for cat_binaries in binaries.values():
        all_binaries.extend(cat_binaries)

    for binary_path in all_binaries[:10]:  # Sample first 10
        result = test_protection_detection(binary_path)
        if "error" not in result:
            print(f"  {result['binary']}: canary={result['canary']}, "
                  f"nx={result['nx']}, pie={result['pie']}, relro={result['relro']}")


def test_chainer_accuracy(base_path: Path):
    """Test exploit chainer suggestions."""
    print("\n" + "=" * 70)
    print("EXPLOIT CHAINER SUGGESTIONS")
    print("=" * 70)

    binaries = find_binaries(base_path)

    print("\n[+] Suggestions for vulnerable binaries:")
    for binary_path in binaries["vulnerable"][:5]:
        result = test_chainer_suggestions(binary_path)
        if "error" not in result:
            print(f"  {result['binary']}:")
            print(f"    Suggestions: {result['suggestions']}")
            print(f"    Chains found: {result['chains_found']}")
            print(f"    Best probability: {result['best_probability']:.1%}")


def main():
    base_path = Path(__file__).parent.parent

    print("=" * 70)
    print("SUPWNGO FRAMEWORK ACCURACY TESTING")
    print("=" * 70)
    print(f"Base path: {base_path}")

    # Run main vulnerability detection tests
    results, stats = run_tests(base_path)

    # Print statistics
    print_statistics(stats)

    # Test protection detection
    test_protection_accuracy(base_path)

    # Test chainer
    test_chainer_accuracy(base_path)

    print("\n" + "=" * 70)
    print("TESTING COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
