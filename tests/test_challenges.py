"""
Test exploit type detection against HackTheBox challenge binaries.

Expected exploit types based on writeups:
- crossbow: OOB write + stack pivot + mprotect + shellcode (MPROTECT_SHELLCODE/STACK_PIVOT)
- laconic: SROP (minimal static binary)
- abyss: Stack BOF + ret2win/ret2libc (ROP_SYSTEM)
- void: ret2dlresolve (RET2DLRESOLVE)
- oxidized_rop: Rust BOF (ROP_EXECVE)
- fleet_management: Shellcode with syscalls (SHELLCODE)
- htb_console: Stack BOF + ROP (ROP_SYSTEM)
- pixel_audio: Format string (FORMAT_STRING)
- assemblers_avenge: Shellcode (SHELLCODE)
- el_mundo: ret2win (RET2WIN)
- ancient_interface: Buffer underflow + alarm (ROP_SYSTEM)
"""

import pytest
from pathlib import Path
import sys

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from supwngo.core.binary import Binary
from supwngo.exploit.strategy import StrategySuggester, ExploitApproach


# Challenge directory
CHALLENGES_DIR = Path(__file__).parent.parent / "challenges"


# Expected exploit types based on writeups
# Maps binary name to list of acceptable exploit approaches
EXPECTED_STRATEGIES = {
    "laconic": [ExploitApproach.SROP, ExploitApproach.SHELLCODE],
    "crossbow": [ExploitApproach.SROP, ExploitApproach.MPROTECT_SHELLCODE, ExploitApproach.STACK_PIVOT],
    "abyss": [ExploitApproach.ROP_SYSTEM, ExploitApproach.ROP_EXECVE, ExploitApproach.RET2PLT],
    "void": [ExploitApproach.RET2DLRESOLVE, ExploitApproach.ROP_SYSTEM],
    "htb-console": [ExploitApproach.ROP_SYSTEM, ExploitApproach.ROP_EXECVE],
    "assemblers_avenge": [ExploitApproach.SHELLCODE],
    "fleet_management": [ExploitApproach.ROP_EXECVE, ExploitApproach.SHELLCODE],
    "oxidized-rop": [ExploitApproach.ROP_EXECVE, ExploitApproach.ROP_SYSTEM],
    "power_greed": [ExploitApproach.SROP, ExploitApproach.ROP_EXECVE],
    "ancient_interface": [ExploitApproach.ROP_SYSTEM, ExploitApproach.ROP_EXECVE],
    "server": [ExploitApproach.ROP_SYSTEM, ExploitApproach.ROP_EXECVE],
    "main": [ExploitApproach.FORMAT_STRING, ExploitApproach.ROP_EXECVE],  # Pixel Audio
    "portaloo": [ExploitApproach.ROP_EXECVE, ExploitApproach.ROP_SYSTEM],
    "null": [ExploitApproach.SHELLCODE, ExploitApproach.ROP_EXECVE],  # Null assembler
}


def find_binary(name: str) -> Path | None:
    """Find binary by name in challenges directory."""
    # Direct match
    direct = CHALLENGES_DIR / name
    if direct.exists() and direct.is_file():
        return direct

    # Search recursively
    for path in CHALLENGES_DIR.rglob(name):
        if path.is_file():
            return path

    # Try with common suffixes
    for suffix in ["", ".elf", ".bin"]:
        for path in CHALLENGES_DIR.rglob(f"{name}{suffix}"):
            if path.is_file():
                return path

    return None


class TestExploitTypeDetection:
    """Test that supwngo correctly identifies exploit types for each challenge."""

    @pytest.fixture
    def binary_path(self, request):
        """Get binary path from test parameter."""
        name = request.param
        path = find_binary(name)
        if path is None:
            pytest.skip(f"Binary {name} not found")
        return path

    @pytest.mark.parametrize("binary_path,expected", [
        ("laconic", EXPECTED_STRATEGIES["laconic"]),
        ("crossbow", EXPECTED_STRATEGIES["crossbow"]),
    ], indirect=["binary_path"])
    def test_static_binaries(self, binary_path, expected):
        """Test static binary strategy detection."""
        binary = Binary.load(str(binary_path))
        suggester = StrategySuggester(binary)
        report = suggester.analyze()

        assert report.recommended is not None, "Should have a recommended strategy"

        # Check if any of the expected strategies are in the recommendations
        all_approaches = [s.approach for s in report.strategies]
        matching = [a for a in expected if a in all_approaches]

        assert len(matching) > 0, \
            f"Expected one of {expected} in strategies, got {all_approaches}"

    @pytest.mark.parametrize("binary_path,expected", [
        ("abyss", EXPECTED_STRATEGIES["abyss"]),
        ("void", EXPECTED_STRATEGIES["void"]),
        ("htb-console", EXPECTED_STRATEGIES["htb-console"]),
    ], indirect=["binary_path"])
    def test_dynamic_binaries(self, binary_path, expected):
        """Test dynamically linked binary strategy detection."""
        binary = Binary.load(str(binary_path))
        suggester = StrategySuggester(binary)
        report = suggester.analyze()

        assert report.recommended is not None

        all_approaches = [s.approach for s in report.strategies]
        matching = [a for a in expected if a in all_approaches]

        assert len(matching) > 0, \
            f"Expected one of {expected} in strategies, got {all_approaches}"


class TestProtectionDetection:
    """Test protection detection accuracy."""

    def test_laconic_protections(self):
        """Laconic should have no protections (static, no canary, no PIE)."""
        path = find_binary("laconic")
        if path is None:
            pytest.skip("laconic not found")

        binary = Binary.load(str(path))

        assert not binary.protections.canary, "laconic should have no canary"
        assert not binary.protections.pie, "laconic should have no PIE"

    def test_crossbow_protections(self):
        """Crossbow is static with canary."""
        path = find_binary("crossbow")
        if path is None:
            pytest.skip("crossbow not found")

        binary = Binary.load(str(path))

        assert binary.protections.canary, "crossbow should have canary"
        assert binary.protections.nx, "crossbow should have NX"
        assert not binary.protections.pie, "crossbow should have no PIE"

    def test_abyss_protections(self):
        """Abyss should be dynamically linked with partial RELRO."""
        path = find_binary("abyss")
        if path is None:
            pytest.skip("abyss not found")

        binary = Binary.load(str(path))

        assert not binary.protections.canary, "abyss should have no canary"
        assert binary.protections.nx, "abyss should have NX"
        assert "Partial" in binary.protections.relro or "No" not in binary.protections.relro


class TestBinShDetection:
    """Test /bin/sh string detection."""

    def test_laconic_binsh(self):
        """Laconic should have /bin/sh in binary (at 0x43238 per writeup)."""
        path = find_binary("laconic")
        if path is None:
            pytest.skip("laconic not found")

        binary = Binary.load(str(path))
        suggester = StrategySuggester(binary)
        report = suggester.analyze()

        assert report.has_binsh, "laconic should have /bin/sh string"


class TestCyclicPattern:
    """Test cyclic pattern generation and finding."""

    def test_cyclic_generation(self):
        """Test pattern generation."""
        from supwngo.exploit.offset_finder import cyclic, cyclic_find

        pattern = cyclic(100)
        assert len(pattern) == 100

        # Every 4-byte sequence should be unique
        seen = set()
        for i in range(len(pattern) - 3):
            seq = pattern[i:i+4]
            assert seq not in seen, f"Duplicate sequence at {i}"
            seen.add(seq)

    def test_cyclic_find(self):
        """Test offset finding in pattern."""
        from supwngo.exploit.offset_finder import cyclic, cyclic_find

        pattern = cyclic(200)

        # Find a known subsequence
        subseq = pattern[50:54]
        offset = cyclic_find(subseq)

        assert offset == 50, f"Expected offset 50, got {offset}"

    def test_cyclic_find_int(self):
        """Test finding integer value in pattern."""
        from supwngo.exploit.offset_finder import cyclic, cyclic_find
        import struct

        pattern = cyclic(200)

        # Get value at offset 72
        val = struct.unpack("<I", pattern[72:76])[0]
        offset = cyclic_find(val)

        assert offset == 72, f"Expected offset 72, got {offset}"


class TestStrategyReport:
    """Test strategy report generation."""

    def test_report_has_all_fields(self):
        """Test that report contains all expected fields."""
        path = find_binary("laconic")
        if path is None:
            pytest.skip("laconic not found")

        binary = Binary.load(str(path))
        suggester = StrategySuggester(binary)
        report = suggester.analyze()

        # Check report fields
        assert report.binary_path
        assert report.arch
        assert report.bits
        assert report.protections_summary
        assert len(report.strategies) > 0

        # Check strategy fields
        strat = report.strategies[0]
        assert strat.approach
        assert strat.priority
        assert strat.description
        assert 0 <= strat.confidence <= 1

    def test_report_to_dict(self):
        """Test report serialization."""
        path = find_binary("abyss")
        if path is None:
            pytest.skip("abyss not found")

        binary = Binary.load(str(path))
        suggester = StrategySuggester(binary)
        report = suggester.analyze()

        d = report.to_dict()

        assert "binary_path" in d
        assert "arch" in d
        assert "strategies" in d
        assert isinstance(d["strategies"], list)


# Run basic smoke test if executed directly
if __name__ == "__main__":
    print("Running basic smoke tests...")

    # Test each binary we can find
    for name, expected in EXPECTED_STRATEGIES.items():
        path = find_binary(name)
        if path is None:
            print(f"  [SKIP] {name}: not found")
            continue

        try:
            binary = Binary.load(str(path))
            suggester = StrategySuggester(binary)
            report = suggester.analyze()

            recommended = report.recommended.approach if report.recommended else None
            all_approaches = [s.approach for s in report.strategies]

            # Check if any expected strategy is found
            matching = [a for a in expected if a in all_approaches]

            if matching:
                print(f"  [PASS] {name}: {recommended.name} (expected one of {[e.name for e in expected]})")
            else:
                print(f"  [FAIL] {name}: got {recommended.name if recommended else 'None'}, "
                      f"expected one of {[e.name for e in expected]}")
                print(f"         Available: {[a.name for a in all_approaches]}")
        except Exception as e:
            print(f"  [ERROR] {name}: {e}")

    print("\nDone!")
