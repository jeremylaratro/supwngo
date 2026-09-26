"""
Fixture-validation gate for the input-vector fixtures.

**Why this file exists.** Every fixture in `tests/fixtures/input_vector/` is a
*custom assessment*: a test elsewhere asks "did the pipeline solve this?" or "did
the probe classify this correctly?" and trusts the fixture to be a fair judge. A
fixture that cannot fail makes the test that depends on it vacuous, and that is not
hypothetical here — two such defects were caught during this sprint:

  1. `file_vector_gate.c` was originally written with two adjacent locals, which
     gcc -O0 placed 76 bytes apart. 76 is NOT in
     `VariableOverwriteExecutor`'s buffer sweep, so the fixture was **unsolvable**
     and metric M-4's gate would have measured nothing.
  2. The ad-hoc script first used to measure that was itself always-green:
     `open(p, "wb").write(data) or check(...)` short-circuits on `write()`'s
     truthy byte count, so the check never ran and all 41 offsets "passed".

So the controls live here, as a committed gate that runs in the same suite as the
tests that rely on them, rather than as a one-off shell command. Each fixture must
prove it can say **both** yes and no, and must prove it uses the transport it
claims. Ordered first by filename so a fixture regression surfaces before the
downstream tests it would silently void.

Plan: docs/plans/2026-09-26-sprint2prime-input-vector-plan.md (REVISIONS 3 and 4)
"""
from __future__ import annotations

import struct
import subprocess
from pathlib import Path

import pytest

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "input_vector"

#: The gate every solve-fixture checks. Absent from FALLBACK_MAGIC_VALUES, so a
#: win requires Sprint 1's recovered-immediate path rather than the folklore list.
GOOD = struct.pack("<I", 0x5AFEF11E)
#: Wrong-but-present: same length, same position, different value. A fixture that
#: "wins" on this is not testing the value at all.
BAD = struct.pack("<I", 0xDEADBEEF)
#: Struct-pinned distance from buffer start to the gate in every solve fixture.
GATE_OFFSET = 64

_CFLAGS = ["-m64", "-O0", "-fno-stack-protector", "-D_FORTIFY_SOURCE=0", "-w"]

SOLVE_FIXTURES = [
    "file_vector_gate",
    "mech_open_read_argv",
    "mech_line_text",
    "mech_flag_style",
    "mech_argv_payload",
    "mech_fixed_path",
]
ADVERSARIAL_FIXTURES = [
    "neg_nondeterministic",
    "neg_argc_banner",
    "neg_argv_config_stdin_payload",
    "neg_slow_config_stdin_payload",
]


@pytest.fixture(scope="module")
def built(tmp_path_factory) -> dict:
    """Compile every fixture once. Sources are committed; ELFs are not."""
    out_dir = tmp_path_factory.mktemp("input_vector_fixtures")
    built = {}
    for src in sorted(FIXTURE_DIR.glob("*.c")):
        dst = out_dir / src.stem
        subprocess.run(
            ["gcc", *_CFLAGS, "-o", str(dst), str(src)],
            check=True, capture_output=True, text=True,
        )
        built[src.stem] = dst
    missing = set(SOLVE_FIXTURES + ADVERSARIAL_FIXTURES) - set(built)
    assert not missing, f"fixture sources missing from {FIXTURE_DIR}: {sorted(missing)}"
    return built


def _run(cmd, cwd=None, stdin=None, timeout=8.0):
    try:
        r = subprocess.run(
            cmd, input=stdin, capture_output=True, timeout=timeout, cwd=cwd,
            stdin=None if stdin is not None else subprocess.DEVNULL,
        )
        return r.stdout + r.stderr, r.returncode
    except subprocess.TimeoutExpired as e:
        return (e.stdout or b"") + (e.stderr or b""), None


def _payload(value: bytes) -> bytes:
    return b"A" * GATE_OFFSET + value


def _invoke(name: str, exe: Path, value: bytes, tmp_path: Path):
    """Build the invocation that delivers `value` via this fixture's OWN transport."""
    if name == "mech_argv_payload":                      # payload IS an argv token
        return [str(exe).encode(), _payload(value)], None
    blob = tmp_path / "payload.bin"
    blob.write_bytes(_payload(value))
    if name == "mech_flag_style":                        # file behind a flag
        return [str(exe), "-f", str(blob)], None
    if name == "mech_fixed_path":                        # fixed path in cwd, no argv
        (tmp_path / "input.dat").write_bytes(_payload(value))
        return [str(exe)], str(tmp_path)
    return [str(exe), str(blob)], None                   # bare path in argv


class TestSolveFixturesCanSayBothYesAndNo:
    """The load-bearing property: a solve-fixture must discriminate on the VALUE,
    not merely on being reached. Without the negative control, a fixture that
    printed its flag unconditionally would satisfy every downstream test."""

    @pytest.mark.parametrize("name", SOLVE_FIXTURES)
    def test_correct_value_wins(self, name, built, tmp_path):
        cmd, cwd = _invoke(name, built[name], GOOD, tmp_path)
        out, _ = _run(cmd, cwd=cwd)
        assert b"FLAG" in out, (
            f"{name}: the correct gate value at offset {GATE_OFFSET} did NOT win "
            f"-- the fixture is unsolvable and any test depending on it is "
            f"vacuous. Got: {out[:120]!r}"
        )

    @pytest.mark.parametrize("name", SOLVE_FIXTURES)
    def test_wrong_but_present_value_loses(self, name, built, tmp_path):
        cmd, cwd = _invoke(name, built[name], BAD, tmp_path)
        out, _ = _run(cmd, cwd=cwd)
        assert b"FLAG" not in out, (
            f"{name}: a WRONG value at the same offset still won -- the fixture "
            f"does not test the value, so it cannot judge a technique. "
            f"Got: {out[:120]!r}"
        )


class TestEachFixtureUsesTheTransportItClaims:
    """A fixture named for a mechanism must actually exercise that mechanism,
    otherwise the mechanism matrix in the plan is fiction."""

    def test_fixed_path_ignores_argv_entirely(self, built, tmp_path):
        (tmp_path / "input.dat").write_bytes(_payload(GOOD))
        bare, _ = _run([str(built["mech_fixed_path"])], cwd=str(tmp_path))
        with_argv, _ = _run(
            [str(built["mech_fixed_path"]), "/dev/null"], cwd=str(tmp_path))
        assert b"FLAG" in bare
        assert bare == with_argv, "fixed-path fixture must not consume argv"

    def test_fixed_path_actually_reads_its_fixed_file(self, built, tmp_path):
        """Paired with the above: proves the subject of the 'ignores argv' claim
        exists, i.e. that the file is genuinely the input channel."""
        out, _ = _run([str(built["mech_fixed_path"])], cwd=str(tmp_path))
        assert b"not found" in out, (
            "with no input.dat present the fixture must report it -- otherwise "
            "it is not reading that file at all")

    def test_argv_payload_needs_no_file_at_all(self, built, tmp_path):
        cmd = [str(built["mech_argv_payload"]).encode(), _payload(GOOD)]
        out, _ = _run(cmd, cwd=str(tmp_path))
        assert b"FLAG" in out

    def test_argv_payload_must_be_passed_as_bytes_not_str(self, built, tmp_path):
        """MEASURED implementation constraint, not a style note: the same payload
        passed as a latin-1 `str` is silently corrupted, because the high bytes
        are re-encoded as multi-byte UTF-8 on exec. An argv transport built on
        `str` would produce SUCCESSes that do not reproduce."""
        exe = str(built["mech_argv_payload"])
        as_bytes, _ = _run([exe.encode(), _payload(GOOD)])
        as_str, _ = _run([exe, _payload(GOOD).decode("latin-1")])
        assert b"FLAG" in as_bytes, "bytes argv must win"
        assert b"FLAG" not in as_str, (
            "str argv unexpectedly won -- if this ever passes, the encoding "
            "hazard this gate documents has changed and the argv transport's "
            "bytes-only requirement must be re-derived rather than assumed")

    def test_flag_style_requires_its_flag(self, built, tmp_path):
        blob = tmp_path / "p.bin"
        blob.write_bytes(_payload(GOOD))
        bare, _ = _run([str(built["mech_flag_style"]), str(blob)])
        flagged, _ = _run([str(built["mech_flag_style"]), "-f", str(blob)])
        assert b"FLAG" not in bare, "a bare path must NOT satisfy a -f fixture"
        assert b"FLAG" in flagged, "the -f form must win"

    def test_line_text_stops_at_a_newline(self, built, tmp_path):
        """Proves it is genuinely a line/text reader: a payload placed after a
        newline must not reach the gate."""
        blob = tmp_path / "nl.bin"
        blob.write_bytes(b"A" * 10 + b"\n" + b"A" * 54 + GOOD)
        out, _ = _run([str(built["mech_line_text"]), str(blob)])
        assert b"FLAG" not in out


class TestAdversarialFixturesExhibitThePropertyTheyClaim:
    """These three exist to try to FOOL the vector probe. If a fixture does not
    actually have the adversarial property, the probe's negative gates prove
    nothing about the false-positive class they are named for."""

    def test_nondeterministic_fixture_really_is_nondeterministic(self, built):
        a, _ = _run([str(built["neg_nondeterministic"])])
        b, _ = _run([str(built["neg_nondeterministic"])])
        assert a != b, (
            "this fixture must vary between identical runs, otherwise the "
            "probe's determinism stage is not being tested")

    def test_argc_banner_varies_with_argc_but_never_opens_the_path(self, built, tmp_path):
        exe = str(built["neg_argc_banner"])
        none, _ = _run([exe])
        some, _ = _run([exe, str(tmp_path / "whatever")])
        assert none != some, "output must depend on argc (stage-1 bait)"
        missing, _ = _run([exe, str(tmp_path / "missing.bin")])
        present_p = tmp_path / "present.bin"
        present_p.write_bytes(b"Z" * 32)
        present, _ = _run([exe, str(present_p)])
        assert missing == present, (
            "this fixture must NOT open the path -- that is what makes it a "
            "stage-2 negative rather than a stage-2 positive")

    def test_argv_config_opens_its_config_yet_reads_payload_from_stdin(
            self, built, tmp_path):
        exe = str(built["neg_argv_config_stdin_payload"])
        cfg = tmp_path / "cfg.bin"
        cfg.write_bytes(b"Z" * 32)
        missing, _ = _run([exe, str(tmp_path / "nope.bin")])
        present, _ = _run([exe, str(cfg)])
        assert missing != present, (
            "must genuinely open the argv path -- this is the fixture that "
            "defeated the 3-stage probe, and it only does so by opening it")
        piped, _ = _run([exe, str(cfg)], stdin=_payload(GOOD))
        assert b"cfg loaded" in piped, "config must load while stdin carries the payload"

    def test_argv_config_is_content_volume_insensitive(self, built, tmp_path):
        """This is exactly the discriminator stage 3 relies on: the config's SIZE
        must not change behaviour, which is what separates a config file from a
        payload sink. If this ever fails, stage 3 has lost its basis."""
        exe = str(built["neg_argv_config_stdin_payload"])
        small = tmp_path / "s.bin"
        small.write_bytes(b"Z" * 32)
        big = tmp_path / "b.bin"
        big.write_bytes(b"Z" * 4096)
        out_s, rc_s = _run([exe, str(small)])
        out_b, rc_b = _run([exe, str(big)])
        assert (out_s, rc_s) == (out_b, rc_b), (
            "a 32-byte and a 4096-byte config must behave identically")


class TestStage3BasisIsRecordedSoWeakEvidenceIsDiscountable:
    """The probe's stage 3 fires on any (rc, output) difference between a
    32-byte and a 4096-byte file. One of the three possible bases -- a
    *timeout* on the large run -- is also produced by a target that merely does
    work proportional to its input size, so it is much weaker evidence than a
    genuine output or returncode change.

    That false-positive class is harmless by construction: the probe is
    advisory and can never commit a DeliverySpec (Sprint 2' REVISION 3). These
    tests exist so the limitation stays MEASURED and diagnosable rather than
    latent, and so nobody later mistakes a timeout-based verdict for strong
    evidence.
    """

    def test_slow_config_target_is_a_timeout_based_false_positive(self, built):
        """The known false-positive: payload channel is stdin, yet the verdict
        is file-candidate purely because the large config run timed out."""
        from supwngo.analysis.vector_probe import classify_input_vector

        r = classify_input_vector(str(built["neg_slow_config_stdin_payload"]), timeout=5.0)
        assert r.verdict == "file-candidate", (
            "if this fixture stops being classified file-candidate the "
            "limitation may have been fixed -- re-measure rather than "
            "silently dropping this gate")
        assert r.evidence.get("stage3_basis") == "timeout", (
            "a timeout-driven verdict MUST be labelled as such, so nobody "
            "mistakes it for strong evidence")

    def test_genuine_file_sink_can_show_a_strong_basis(self, built):
        """Paired positive control: without this, the assertion above could
        pass because *every* verdict is labelled 'timeout'.

        Note what this does NOT claim. `stage3_basis` is not a discriminator
        in EITHER direction -- CORRECTED from an earlier, refuted claim that
        only the "timeout" direction was ambiguous and a strong
        (output/returncode) basis was reliable. That stronger claim is
        MEASURED FALSE: tests/test_input_vector_foundation.py's
        `neg_fast_cfg_stdin_payload` fixture is not a file sink at all (its
        payload channel is stdin) yet also reports stage3_basis == 'output'.
        Symmetrically, `mech_line_text` is a genuine file sink that reports
        'timeout' (measured; it blocks on the newline-free 4096-byte probe
        file). So NEITHER basis value may be read as evidence for or against
        a genuine sink -- it is diagnostic metadata only. See
        `test_stage3_basis_is_diagnostic_only_never_a_discriminator` in
        tests/test_input_vector_foundation.py, which replaces the earlier
        (wrong) `test_stage3_basis_is_trustworthy_only_in_the_strong_direction`."""
        from supwngo.analysis.vector_probe import classify_input_vector

        r = classify_input_vector(str(built["file_vector_gate"]), timeout=5.0)
        assert r.verdict == "file-candidate"
        assert r.evidence.get("stage3_basis") == "output", (
            "this sink's difference is a real output change, so the basis must "
            "record the strong evidence rather than collapsing to 'timeout'")

    def test_slow_config_fixture_really_is_slow_only_on_the_large_file(self, built, tmp_path):
        """Validates the fixture's own claim: the 32-byte case must complete
        well inside the budget while the 4096-byte case must not. Otherwise
        this fixture is not testing the timeout basis at all."""
        exe = str(built["neg_slow_config_stdin_payload"])
        small = tmp_path / "s.bin"
        small.write_bytes(b"Z" * 32)
        big = tmp_path / "b.bin"
        big.write_bytes(b"Z" * 4096)

        out_s, rc_s = _run([exe, str(small)], timeout=5.0)
        assert rc_s == 0 and b"cfg scanned" in out_s, (
            f"32-byte config should complete quickly, got rc={rc_s} {out_s[:80]!r}")
        out_b, rc_b = _run([exe, str(big)], timeout=5.0)
        assert rc_b is None, (
            "4096-byte config must exceed the 5s budget for this fixture to "
            f"exercise the timeout basis, got rc={rc_b}")
