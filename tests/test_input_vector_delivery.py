"""
Delivery gates for Sprint 2' Wave 2 REVISION 1
(docs/plans/2026-09-26-wave2-design-review-daybreak.md).

Wave 1 (tests/test_input_vector_wiring.py) proved an operator-declared
`DeliverySpec` is stored on `ExploitContext` and resolved at call time, but
NEVER PROVED IT REACHES A SPAWN -- a declared vector produced a
byte-identical failure to the stdin default (the measured defect this wave
closes). Every test class below either drives a REAL compiled fixture
through the REAL `CanonicalAutopwnEngine` (so a green result means the
payload actually arrived over the declared channel), or exercises a
mechanism (spawn-path parity, cleanup, refusals) that a hand-rolled double
cannot fake past.

Fixture provenance: tests/fixtures/input_vector/*.c, all six mechanism
fixtures put the overwrite gate at exactly offset 64 (a struct, not two
locals -- see file_vector_gate.c's docstring for why) with winning value
0x5AFEF11E, so `VariableOverwriteExecutor`'s existing buffer-size/candidate
sweep (unmodified by this wave) can reach every one of them; the only
variable under test here is whether the payload gets DELIVERED to that
sweep's target the way the operator declared.
"""
from __future__ import annotations

import struct
import subprocess
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from supwngo.core.binary import Binary, Protections
from supwngo.core.context import ExploitContext
from supwngo.exploit.pipeline.contracts import (
    SINK_ARGV,
    SINK_FILE_ARGV,
    SINK_FILE_FIXED,
    SINK_STDIN,
    AttemptOutcome,
    AttemptRecord,
    DeliverySpec,
    Stage,
)
from supwngo.exploit.pipeline.orchestrator import (
    FILE_DELIVERY_ALLOWLIST,
    CanonicalAutopwnEngine,
)
from supwngo.exploit.pipeline.templates import generate_success_script
from supwngo.exploit.pipeline.verifier import PipelineVerifier
from supwngo.exploit.verification import ExploitVerifier, VerificationResult


def _derive_non_allowlisted_registered() -> tuple:
    """Every registered technique that is NOT on `FILE_DELIVERY_ALLOWLIST`.

    Wave 3 T1: derived rather than enumerated, so the refusal gates below
    cover the whole property ("a technique outside the allowlist must not
    reach its executor under a non-stdin vector") instead of four hand-picked
    instances a narrow gate could satisfy.
    """
    from supwngo.exploit.pipeline.executors import build_default_registry

    return tuple(
        sorted(set(build_default_registry().names()) - set(FILE_DELIVERY_ALLOWLIST))
    )


#: Computed once at import: the parametrizations below need it at collection.
_NON_ALLOWLISTED_REGISTERED = _derive_non_allowlisted_registered()

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "input_vector"
_CFLAGS = ["-m64", "-O0", "-fno-stack-protector", "-D_FORTIFY_SOURCE=0", "-w"]

MECH_NAMES = [
    "file_vector_gate",
    "mech_open_read_argv",
    "mech_line_text",
    "mech_flag_style",
    "mech_fixed_path",
    "mech_argv_payload",
]


def _fake_binary() -> SimpleNamespace:
    """`Binary`-shaped stub for tests whose subject is construction-time
    validation (raises before any real ELF parsing happens) -- same shape as
    tests/test_input_vector_wiring.py's `_fake_binary()`."""
    return SimpleNamespace(
        path=Path("/tmp/supwngo_delivery_test_vuln"),
        arch="amd64",
        bits=64,
        endian="little",
        protections=Protections(),
        detect_shipped_libc=lambda: None,
        libc_env=lambda: None,
    )


@pytest.fixture(scope="module")
def built(tmp_path_factory) -> dict:
    """Compile all six mechanism fixtures once per test module run."""
    out_dir = tmp_path_factory.mktemp("input_vector_delivery")
    paths = {}
    for name in MECH_NAMES:
        src = FIXTURE_DIR / f"{name}.c"
        dst = out_dir / name
        subprocess.run(
            ["gcc", *_CFLAGS, "-o", str(dst), str(src)],
            check=True, capture_output=True, text=True,
        )
        assert dst.is_file()
        paths[name] = dst
    return paths


def _engine_for(exe_path: Path, **kwargs) -> CanonicalAutopwnEngine:
    """Real `CanonicalAutopwnEngine` against a real compiled fixture --
    reuses the constructor's own T5/T6 validation and `DeliverySpec`
    construction rather than a hand-rolled double, then the caller drives
    `_attempt_techniques` directly (the tests/test_variable_overwrite_budget.py
    pattern: no profiling prologue is needed to exercise a single technique)."""
    binary = Binary.load(str(exe_path))
    return CanonicalAutopwnEngine(binary, static_preflight=False, **kwargs)


def _run_generated_script(script_text: str, cwd: Path, timeout: float = 20.0) -> bytes:
    """Actually EXECUTE a `generate_success_script()` artifact as its own
    child process (not merely render it and inspect the source) and return
    its combined stdout+stderr. This is what closes Class 6 test defect #1:
    a green in-pipeline verification does not prove the standalone artifact
    the operator would actually run also works."""
    script_path = cwd / f"_generated_{uuid.uuid4().hex}.py"
    script_path.write_text(script_text)
    try:
        proc = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=str(cwd), stdin=subprocess.DEVNULL,
            capture_output=True, timeout=timeout,
        )
        return proc.stdout + proc.stderr
    finally:
        try:
            script_path.unlink()
        except FileNotFoundError:
            pass


#: The correct gate value every mechanism fixture checks for at offset 64
#: (see fixture provenance docstring above) versus a WRONG-but-present value
#: at the same offset -- proves a win is attributable to payload CONTENT,
#: not merely to the channel/filename existing.
GOOD_GATE_VALUE = struct.pack("<I", 0x5AFEF11E)
BAD_GATE_VALUE = struct.pack("<I", 0xDEADBEEF)


def _direct_wrong_value_output(cfg: dict, exe: Path, kwargs: dict) -> bytes:
    """Exercise the fixture directly (bypassing the executor's own
    candidate/offset sweep entirely) over the SAME declared vector and --
    for file mechanisms -- the SAME filename the positive run in this test
    used, but with the WRONG gate value at the correct offset. Used to prove
    the earlier win is attributable to payload content, not just to the
    channel existing."""
    payload = b"A" * 64 + BAD_GATE_VALUE
    target = None
    if cfg["sink"] == SINK_ARGV:
        cmd = [str(exe), payload]
    else:
        target = exe.parent / kwargs["input_name"]
        target.write_bytes(payload)
        if cfg["input_argv"] is not None:
            cmd = [str(exe), "-f", str(target)]
        else:
            cmd = [str(exe)] if cfg["name_mode"] == "fixed" else [str(exe), str(target)]
    try:
        proc = subprocess.run(
            cmd, cwd=str(exe.parent), capture_output=True, timeout=8.0,
        )
        return proc.stdout + proc.stderr
    finally:
        if target is not None:
            try:
                target.unlink()
            except FileNotFoundError:
                pass


# ---------------------------------------------------------------------------
# TESTS item 1 + 2: end-to-end M-4 gate, one test per mechanism, PLUS the
# negative half (same fixture, default vector, must NOT succeed).
# ---------------------------------------------------------------------------

MECHANISMS = [
    dict(fixture="file_vector_gate", sink=SINK_FILE_ARGV, name_mode="random",
         input_argv=None, flag="FLAG{file_vector_reached}"),
    dict(fixture="mech_open_read_argv", sink=SINK_FILE_ARGV, name_mode="random",
         input_argv=None, flag="FLAG{open_read_argv}"),
    dict(fixture="mech_line_text", sink=SINK_FILE_ARGV, name_mode="random",
         input_argv=None, flag="FLAG{line_text}"),
    dict(fixture="mech_flag_style", sink=SINK_FILE_ARGV, name_mode="random",
         input_argv="-f @@", flag="FLAG{flag_style}"),
    dict(fixture="mech_fixed_path", sink=SINK_FILE_FIXED, name_mode="fixed",
         input_argv=None, flag="FLAG{fixed_path}"),
    dict(fixture="mech_argv_payload", sink=SINK_ARGV, name_mode="none",
         input_argv=None, flag="FLAG{argv_payload}"),
]


class TestEndToEndMechanismSolves:
    """Drives `_attempt_techniques(["variable_overwrite"])` directly against
    each of the six mechanism fixtures. The declared-vector run is always
    followed by a default-vector run against the SAME fixture -- without
    that negative half, a mechanism that happens to "solve" for reasons
    unrelated to delivery (e.g. a bug that reaches the gate via the fixed
    struct layout no matter what) would look identical to a real pass. The
    payload filename (where the mechanism uses one) is picked ONCE per case
    and only ever handed to the POSITIVE engine -- the negative engine's
    vector is the default (stdin), which T5 forbids naming at all, so
    "constant across both runs" here means: never regenerated, never
    supplied a second time.
    """

    @pytest.mark.parametrize("cfg", MECHANISMS, ids=[m["fixture"] for m in MECHANISMS])
    def test_mechanism_solves_with_declared_vector_and_fails_with_default(self, built, cfg):
        exe = built[cfg["fixture"]]

        kwargs = {"input_vector": cfg["sink"]}
        if cfg["name_mode"] == "random":
            kwargs["input_name"] = f"{uuid.uuid4().hex}.bin"
        elif cfg["name_mode"] == "fixed":
            kwargs["input_name"] = "input.dat"
        # name_mode == "none" (SINK_ARGV): no input_name at all -- T5 would
        # reject one.
        if cfg["input_argv"] is not None:
            kwargs["input_argv"] = cfg["input_argv"]

        engine_pos = _engine_for(exe, **kwargs)
        engine_pos._attempt_techniques(["variable_overwrite"])
        assert engine_pos.successful, (
            f"{cfg['fixture']}: did not solve over the declared vector "
            f"{cfg['sink']!r} -- attempts: "
            f"{[(a.technique, a.outcome.name, a.failure_reason) for a in engine_pos.context.attempts]}"
        )
        assert engine_pos.technique_used == "variable_overwrite"
        assert engine_pos.context.captured_flag == cfg["flag"]

        # Class 6 fix (test defect #1): the pipeline's own in-process
        # verification going green does not prove the STANDALONE ARTIFACT
        # an operator would actually run also delivers over the declared
        # vector -- actually execute it as its own child process and check
        # THAT process's own stdout for the fixture's flag string.
        assert engine_pos.exploit_script, (
            f"{cfg['fixture']}: no exploit_script was generated for the "
            "successful attempt"
        )
        artifact_output = _run_generated_script(engine_pos.exploit_script, cwd=exe.parent)
        assert cfg["flag"].encode() in artifact_output, (
            f"{cfg['fixture']}: the GENERATED ARTIFACT, run standalone, did "
            f"not print its flag -- got: {artifact_output[:400]!r}"
        )
        if cfg["sink"] != SINK_ARGV:
            # The standalone artifact (unlike the pipeline's own verifier)
            # re-materializes and does not clean up its payload file by
            # design -- remove it here so it doesn't confuse the cleanup
            # check below, which is about the PIPELINE's own cleanup, not
            # this test's follow-up artifact run.
            artifact_file = exe.parent / kwargs["input_name"]
            try:
                artifact_file.unlink()
            except FileNotFoundError:
                pass

        # Cleanup check for file sinks: nothing left behind that a later
        # default-vector run against the same directory could stumble on.
        if cfg["name_mode"] == "random":
            leftover = exe.parent / kwargs["input_name"]
            assert not leftover.exists(), (
                f"{cfg['fixture']}: payload file {leftover} was not cleaned "
                "up after a successful run"
            )

        engine_neg = _engine_for(exe)  # default vector: stdin, wave 1's only behavior
        engine_neg._attempt_techniques(["variable_overwrite"])
        assert not engine_neg.successful, (
            f"{cfg['fixture']}: solved over the DEFAULT (stdin) vector too "
            "-- this fixture cannot discriminate delivery over this vector "
            "from delivery over any other, so a pass above proves nothing"
        )

        # Class 6 addition: same declared vector, same filename (where one
        # applies) as the positive run above, but the WRONG gate value at
        # the correct offset -- proves the win is attributable to payload
        # CONTENT, not merely to the channel/filename existing.
        wrong_output = _direct_wrong_value_output(cfg, exe, kwargs)
        assert cfg["flag"].encode() not in wrong_output, (
            f"{cfg['fixture']}: a WRONG gate value (0xDEADBEEF) at the "
            "correct offset, delivered over the SAME declared vector/"
            "filename, still produced the flag -- the earlier win is not "
            "attributable to payload content"
        )


# ---------------------------------------------------------------------------
# TESTS item 3: both spawn paths produce identical file bytes.
# ---------------------------------------------------------------------------

def _make_consuming_reflector(tmp_path: Path) -> Path:
    """A tiny self-executing script that actually OPENS AND READS the file
    path given as its argv[1] (unlike ``/bin/true``, which ignores argv
    entirely) and appends a hex-encoded record of what it read to a
    ``<target>.consumed`` marker file -- one line per invocation. It never
    prints anything matching `verify_output`'s SUCCESS/FLAG patterns, so
    (like ``/bin/true``) it still guarantees both of `ExploitVerifier`'s
    spawn paths run for every payload tried here."""
    script = tmp_path / "consuming_reflector"
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "data = open(sys.argv[1], 'rb').read() if len(sys.argv) > 1 else b''\n"
        "with open(sys.argv[1] + '.consumed', 'a') as f:\n"
        "    f.write(data.hex() + chr(10))\n"
    )
    script.chmod(0o755)
    return script


class TestBothSpawnPathsProduceIdenticalFileBytes:
    """The reflector ignores no argv and exits 0 immediately with output
    that never matches `verify_output`'s SUCCESS/FLAG patterns, so
    `ExploitVerifier.verify_payload` ALWAYS falls through to
    `_verify_with_pwntools` after the `subprocess.run` attempt, guaranteeing
    both spawn paths actually run for every payload tried here. `pre_spawn`
    re-materializes the target file and snapshots it immediately before each
    of the two spawns; if either path silently added/omitted bytes (e.g. the
    ``sendline`` newline this task's spec explicitly forbids "fixing" for
    the stdin case, or an analogous slip for a file/argv sink), the
    snapshots would diverge.

    Class 6 fix (test defect #2): byte-equal snapshots alone only prove the
    HARNESS's own `pre_spawn` callback wrote the same bytes twice -- they
    say nothing about whether either CHILD PROCESS actually opened and read
    the file. The reflector's `.consumed` marker file (written by the CHILD,
    not the test) closes that gap.
    """

    @pytest.mark.parametrize(
        "payload", [b"", b"X", b"X\n", b"AAA\nBBB\nCCC"],
        ids=["empty", "single-byte", "trailing-newline", "embedded-newline"],
    )
    def test_identical_bytes_across_both_spawn_paths(self, tmp_path, payload):
        target_path = tmp_path / "p.bin"
        consumed_path = Path(str(target_path) + ".consumed")
        reflector = _make_consuming_reflector(tmp_path)
        snapshots = []

        def _pre_spawn():
            target_path.write_bytes(payload)
            snapshots.append(target_path.read_bytes())

        verifier = ExploitVerifier(
            str(reflector), timeout=2.0,
            argv=[str(reflector), str(target_path)],
            stdin_payload=False, pre_spawn=_pre_spawn,
        )
        verifier.verify_payload(payload)

        assert len(snapshots) >= 2, (
            f"expected both the subprocess.run path and the pwntools "
            f"fallback to spawn (and therefore call pre_spawn) for "
            f"payload {payload!r} -- got only {len(snapshots)} spawn(s); "
            "the reflector must never satisfy verify_output so both paths run"
        )
        assert all(s == payload for s in snapshots), (
            f"the spawn paths produced different file bytes for "
            f"{payload!r}: {snapshots!r}"
        )

        assert consumed_path.exists(), (
            "the reflector never opened/read the target file -- a child "
            "that ignored argv or never opened the file would leave this "
            "marker absent and the test above would still pass"
        )
        lines = consumed_path.read_text().splitlines()
        assert len(lines) >= 2, (
            f"expected the reflector to have actually been invoked (and to "
            f"have read the file) at least twice, once per spawn path -- "
            f"got {len(lines)} record(s): {lines!r}"
        )
        assert all(bytes.fromhex(line) == payload for line in lines), (
            f"the reflector's own read of the file did not match the "
            f"payload for at least one spawn -- records: {lines!r}"
        )


# ---------------------------------------------------------------------------
# TESTS item 4: forced-fallback test exercising `_verify_with_pwntools`
# directly under a file sink.
# ---------------------------------------------------------------------------

class TestForcedFallbackRematerializes:
    def test_verify_with_pwntools_directly_sees_the_full_payload(self, tmp_path):
        target_path = tmp_path / "p.bin"
        payload = b"A" * 64 + b"\x1e\xf1\xfe\x5a"  # offset-64 gate shape
        consumed_path = Path(str(target_path) + ".consumed")
        # Reused from TestBothSpawnPathsProduceIdenticalFileBytes: a target
        # that actually OPENS AND READS argv[1] and records what it read to
        # a marker file written by the CHILD itself -- "the target's own
        # output" that `_verify_with_pwntools` (which swallows launch
        # errors internally) cannot fake past.
        reflector = _make_consuming_reflector(tmp_path)

        def _pre_spawn():
            target_path.write_bytes(payload)

        verifier = ExploitVerifier(
            str(reflector), timeout=2.0,
            argv=[str(reflector), str(target_path)],
            stdin_payload=False, pre_spawn=_pre_spawn,
        )
        verifier._verify_with_pwntools(payload)

        assert target_path.read_bytes() == payload

        # Class 6 fix (test defect #3): prove the spawn actually happened
        # WITH the file argument, via the CHILD's own record of what it
        # read -- the prior version of this test only checked that the
        # harness's OWN pre_spawn write landed on disk, which says nothing
        # about whether `process(argv)` ever launched, or launched without
        # the file argument at all.
        assert consumed_path.exists(), (
            "the reflector never opened/read the target file during "
            "_verify_with_pwntools -- the spawn may not have happened at "
            "all, or happened without the file argument"
        )
        lines = consumed_path.read_text().splitlines()
        assert len(lines) == 1, (
            f"expected exactly one spawn from a direct `_verify_with_pwntools` "
            f"call, got {len(lines)} record(s): {lines!r}"
        )
        assert bytes.fromhex(lines[0]) == payload, (
            f"the reflector's own read of the file did not match the full "
            f"payload -- got {lines[0]!r}"
        )


# ---------------------------------------------------------------------------
# TESTS item 5: cleanup -- pre-existing file restored byte-for-byte,
# nonexistent file gone afterward, including on raise.
# ---------------------------------------------------------------------------

class TestCleanupRestoresOrRemoves:
    @staticmethod
    def _binary_with_true(tmp_path) -> Path:
        """A real, executable "binary" in tmp_path so `Path(binary_path)
        .resolve().parent` (SINK_FILE_FIXED's target directory) is tmp_path
        itself -- copies /bin/true's bytes rather than symlinking so the
        file genuinely lives inside tmp_path."""
        binary_path = tmp_path / "vuln"
        binary_path.write_bytes(Path("/bin/true").read_bytes())
        binary_path.chmod(0o755)
        return binary_path

    def test_preexisting_file_is_restored_byte_for_byte(self, tmp_path, monkeypatch):
        binary_path = self._binary_with_true(tmp_path)
        target = tmp_path / "input.dat"
        target.write_bytes(b"ORIGINAL-CONTENT-DO-NOT-LOSE")

        ctx = ExploitContext()
        ctx.delivery_spec = DeliverySpec(sink=SINK_FILE_FIXED, payload_filename="input.dat")
        pv = PipelineVerifier(str(binary_path), context=ctx, static_preflight=False)

        # Class 6 fix (test defect #5): a stub verifier that captures the
        # file's content WHILE materialized (via the real `pre_spawn` hook),
        # so this test can prove the file actually CHANGED mid-attempt
        # before asserting it was restored -- without this, an untouched
        # original (materialization removed entirely) would pass the final
        # byte-for-byte check just as well as a genuine restore.
        captured = {}

        class _CapturingVerifier:
            def __init__(self, *a, **kwargs):
                self._pre_spawn = kwargs.get("pre_spawn")

            def verify_payload(self, payload):
                if self._pre_spawn is not None:
                    self._pre_spawn()
                captured["mid_attempt"] = target.read_bytes()
                return VerificationResult()

        monkeypatch.setattr(
            "supwngo.exploit.pipeline.verifier.ExploitVerifier", _CapturingVerifier,
        )

        pv.verify_payload("t", b"X" * 68)

        assert captured.get("mid_attempt") == b"X" * 68, (
            f"the target file was not materialized with the payload during "
            f"the attempt -- captured {captured.get('mid_attempt')!r}; "
            "without this, the restoration check below has no proven "
            "subject to have been restored FROM"
        )
        assert target.read_bytes() == b"ORIGINAL-CONTENT-DO-NOT-LOSE"

    def test_file_that_did_not_exist_is_removed_afterwards(self, tmp_path, monkeypatch):
        binary_path = self._binary_with_true(tmp_path)
        target = tmp_path / "input.dat"
        assert not target.exists()

        ctx = ExploitContext()
        ctx.delivery_spec = DeliverySpec(sink=SINK_FILE_FIXED, payload_filename="input.dat")
        pv = PipelineVerifier(str(binary_path), context=ctx, static_preflight=False)

        # Class 6 fix (test defect #4): prove the file WAS materialized
        # with the payload bytes DURING the attempt, not merely that it is
        # absent afterward -- an absence check alone would pass identically
        # whether materialization ever happened at all.
        captured = {}

        class _CapturingVerifier:
            def __init__(self, *a, **kwargs):
                self._pre_spawn = kwargs.get("pre_spawn")

            def verify_payload(self, payload):
                if self._pre_spawn is not None:
                    self._pre_spawn()
                captured["mid_attempt"] = target.read_bytes() if target.exists() else None
                return VerificationResult()

        monkeypatch.setattr(
            "supwngo.exploit.pipeline.verifier.ExploitVerifier", _CapturingVerifier,
        )

        pv.verify_payload("t", b"X" * 68)

        assert captured.get("mid_attempt") == b"X" * 68, (
            f"the target file was not materialized with the payload during "
            f"the attempt -- captured {captured.get('mid_attempt')!r}"
        )

        assert not target.exists(), (
            "a file that did not exist before the attempt must not exist "
            "after it either -- a left-behind file with a winning payload "
            "would make a LATER default-vector run win spuriously"
        )

    def test_restoration_holds_even_when_the_attempt_raises(self, tmp_path, monkeypatch):
        binary_path = self._binary_with_true(tmp_path)
        target = tmp_path / "input.dat"
        target.write_bytes(b"ORIGINAL")

        ctx = ExploitContext()
        ctx.delivery_spec = DeliverySpec(sink=SINK_FILE_FIXED, payload_filename="input.dat")
        pv = PipelineVerifier(str(binary_path), context=ctx, static_preflight=False)

        captured = {}

        class _BoomVerifier:
            def __init__(self, *a, **kwargs):
                # Simulate the file actually getting materialized (as the
                # real ExploitVerifier's pre_spawn hook would, right before
                # its first spawn) before the crash -- otherwise this test
                # would pass even with cleanup deleted outright, since
                # nothing would have touched the file yet to restore.
                pre_spawn = kwargs.get("pre_spawn")
                # Class 6 fix (test defect #6): record whether pre_spawn was
                # actually SUPPLIED, and capture the file's content right
                # after calling it -- BEFORE the raise below -- so this test
                # proves materialization happened prior to the crash, not
                # merely that the original survives a construction that
                # never touched the file at all.
                captured["pre_spawn_supplied"] = pre_spawn is not None
                if pre_spawn is not None:
                    pre_spawn()
                captured["mid_attempt"] = target.read_bytes()

            def verify_payload(self, payload):
                raise RuntimeError("simulated crash mid-attempt")

        monkeypatch.setattr(
            "supwngo.exploit.pipeline.verifier.ExploitVerifier", _BoomVerifier,
        )

        with pytest.raises(RuntimeError):
            pv.verify_payload("t", b"X" * 68)

        assert captured.get("pre_spawn_supplied") is True, (
            "PipelineVerifier did not supply a pre_spawn hook to the "
            "verifier -- without one, no materialization can have "
            "happened before the crash at all"
        )
        assert captured.get("mid_attempt") == b"X" * 68, (
            f"the target file was not materialized with the payload BEFORE "
            f"the raise -- captured {captured.get('mid_attempt')!r}"
        )

        assert target.read_bytes() == b"ORIGINAL", (
            "restore must hold even when the underlying verifier raises "
            "(the finally block is the only thing standing between a "
            "mid-attempt crash and a corrupted fixture file)"
        )


# ---------------------------------------------------------------------------
# TESTS item 6: loud refusals.
# ---------------------------------------------------------------------------

class TestLoudRefusals:
    def test_unknown_sink_raises_from_pipeline_verifier(self, tmp_path):
        binary_path = tmp_path / "vuln"
        binary_path.write_bytes(b"")
        ctx = ExploitContext()
        ctx.delivery_spec = DeliverySpec(sink="typo-sink")
        pv = PipelineVerifier(str(binary_path), context=ctx, static_preflight=False)

        with pytest.raises(ValueError, match="not one of the four recognized transports"):
            pv.verify_payload("t", b"X")

    def test_argv_sink_with_nul_payload_raises(self, tmp_path):
        binary_path = tmp_path / "vuln"
        binary_path.write_bytes(b"")
        ctx = ExploitContext()
        ctx.delivery_spec = DeliverySpec(sink=SINK_ARGV, argv_template=("{payload_arg}",))
        pv = PipelineVerifier(str(binary_path), context=ctx, static_preflight=False)

        with pytest.raises(ValueError, match="NUL"):
            pv.verify_payload("t", b"AA\x00BB")

    def test_input_name_without_a_file_vector_raises(self):
        with pytest.raises(ValueError, match="input_name"):
            CanonicalAutopwnEngine(_fake_binary(), static_preflight=False, input_name="x.bin")

    def test_input_argv_with_stdin_vector_raises(self):
        with pytest.raises(ValueError, match="input_argv"):
            CanonicalAutopwnEngine(
                _fake_binary(), static_preflight=False,
                input_vector=SINK_STDIN, input_argv="-f @@",
            )


# ---------------------------------------------------------------------------
# TESTS item 7: default unchanged.
# ---------------------------------------------------------------------------

#: Byte-for-byte the script `generate_success_script` produced BEFORE this
#: wave's edit (captured pre-change, /tmp/before_script.py -- see the wave's
#: docs/plans/2026-09-26-wave2-design-review-daybreak.md diff record) for a
#: ret2win SUCCESS record. If a change to templates.py ever alters the
#: stdin/default branch, this is the test that must go red.
EXPECTED_STDIN_SCRIPT = '''#!/usr/bin/env python3
"""
Verified exploit for vuln
Technique: ret2win
Offset: 40
Target address: 0x401000

Generated by supwngo's canonical autopwn pipeline. This exact payload was
CONFIRMED working during the automated run (see the run's
VerificationReceipt) - this script replays it.
# - target=win@0x401000 offset=40
"""

from pwn import *

BINARY = "/tmp/vuln"
REMOTE_HOST = ""
REMOTE_PORT = 0

context.binary = BINARY
context.arch = "amd64"
context.log_level = "info"

PAYLOAD = b\'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\\x00\\x10@\\x00\\x00\\x00\\x00\\x00\'

def exploit():
    if REMOTE_HOST:
        io = remote(REMOTE_HOST, REMOTE_PORT)
    else:
        io = process(BINARY)

    io.sendline(PAYLOAD)
    io.interactive()

if __name__ == "__main__":
    exploit()
'''


class TestDefaultUnchanged:
    def _stdin_record_and_context(self):
        binary = SimpleNamespace(path=Path("/tmp/vuln"), bits=64)
        context = SimpleNamespace(binary=binary)
        payload = b"A" * 40 + b"\x00\x10\x40\x00\x00\x00\x00\x00"
        record = AttemptRecord(
            technique="ret2win",
            outcome=AttemptOutcome.SUCCESS,
            stage_reached=Stage.VERIFICATION,
            payload=payload,
            offset=40,
            target_addr=0x401000,
            notes=["target=win@0x401000 offset=40"],
        )
        return context, record

    def test_generated_stdin_script_is_byte_identical_to_pre_change_output_with_no_spec(self):
        context, record = self._stdin_record_and_context()
        script = generate_success_script(context, record)  # spec=None, the default
        assert script == EXPECTED_STDIN_SCRIPT

    def test_generated_stdin_script_is_byte_identical_with_an_explicit_default_spec(self):
        context, record = self._stdin_record_and_context()
        script = generate_success_script(context, record, DeliverySpec())
        assert script == EXPECTED_STDIN_SCRIPT

    def test_stdin_sink_default_spec_argv_is_exactly_the_binary_path(self):
        assert DeliverySpec().build_argv("/bin/vuln") == ["/bin/vuln"]

    def test_stdin_sink_resolved_verifier_argv_is_exactly_the_binary_path(self):
        verifier = ExploitVerifier("/bin/vuln")
        assert verifier._resolve_argv() == [str(Path("/bin/vuln").resolve())]


# ---------------------------------------------------------------------------
# Wave 2 REVISION 2 Class 2: embedded-placeholder prefix/suffix survives,
# proven in BOTH the launched argv and the generated script.
# ---------------------------------------------------------------------------

def _make_argv_reflector(tmp_path: Path) -> Path:
    """A tiny self-executing script that dumps its own argv[1:] (raw bytes,
    NUL-joined) to argv_dump.bin next to itself -- proves what the
    verifier's spawn paths ACTUALLY pass as argv, independent of any C
    fixture's own argv parsing."""
    script = tmp_path / "argv_reflector"
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import sys, os\n"
        "with open('argv_dump.bin', 'wb') as f:\n"
        "    f.write(b'\\x00'.join(os.fsencode(a) for a in sys.argv[1:]))\n"
    )
    script.chmod(0o755)
    return script


def _minimal_record_and_context() -> tuple:
    binary = SimpleNamespace(path=Path("/tmp/vuln"), bits=64)
    context = SimpleNamespace(binary=binary)
    record = AttemptRecord(
        technique="variable_overwrite",
        outcome=AttemptOutcome.SUCCESS,
        stage_reached=Stage.VERIFICATION,
        payload=b"HELLO",
        delivered_bytes=b"HELLO",
    )
    return context, record


class TestEmbeddedPlaceholderPrefixSurvives:
    """Wave 2 REVISION 2 Class 2 (closes H1): a token like
    ``--data={payload_arg}`` or ``--input=@@`` must keep its literal prefix
    around the substituted payload -- both when the verifier ACTUALLY LAUNCHES
    the target with that argv, and in the SOURCE of the generated replay
    script. The previous implementation replaced the whole token whenever it
    merely contained the sentinel, silently discarding the prefix in both
    places."""

    def test_argv_sink_prefix_survives_in_the_launched_argv(self, tmp_path):
        reflector = _make_argv_reflector(tmp_path)
        ctx = ExploitContext()
        ctx.delivery_spec = DeliverySpec(sink=SINK_ARGV, argv_template=("--data={payload_arg}",))
        pv = PipelineVerifier(str(reflector), context=ctx, static_preflight=False)

        pv.verify_payload("t", b"HELLO")

        dump = (tmp_path / "argv_dump.bin").read_bytes()
        assert dump.split(b"\x00") == [b"--data=HELLO"], dump

    def test_file_sink_prefix_survives_in_the_launched_argv(self, tmp_path):
        reflector = _make_argv_reflector(tmp_path)
        ctx = ExploitContext()
        ctx.delivery_spec = DeliverySpec(
            sink=SINK_FILE_ARGV, argv_template=("--input=@@",), payload_filename="p.bin",
        )
        pv = PipelineVerifier(str(reflector), context=ctx, static_preflight=False)

        pv.verify_payload("t", b"FILEDATA")

        dump = (tmp_path / "argv_dump.bin").read_bytes()
        tokens = dump.split(b"\x00")
        assert len(tokens) == 1, tokens
        assert tokens[0].startswith(b"--input="), tokens
        file_path = Path(tokens[0][len(b"--input="):].decode())
        assert file_path.name == "p.bin"
        assert file_path.parent == tmp_path

    def test_argv_sink_prefix_survives_in_generated_script(self):
        context, record = _minimal_record_and_context()
        spec = DeliverySpec(sink=SINK_ARGV, argv_template=("--data={payload_arg}",))
        script = generate_success_script(context, record, spec)
        assert "b'--data=' + PAYLOAD" in script, script

    def test_file_sink_prefix_survives_in_generated_script(self):
        context, record = _minimal_record_and_context()
        spec = DeliverySpec(sink=SINK_FILE_ARGV, argv_template=("--input=@@",), payload_filename="p.bin")
        script = generate_success_script(context, record, spec)
        assert "'--input=' + payload_path" in script, script


# ---------------------------------------------------------------------------
# Wave 2 REVISION 2 Class 3: generated non-stdin scripts refuse remote mode
# loudly instead of connecting and sending nothing.
# ---------------------------------------------------------------------------

class TestRemoteRefusalInGeneratedScript:
    """Wave 2 REVISION 2 Class 3 (closes C2): a file/argv-sink generated
    script previously connected to REMOTE_HOST and sent zero payload bytes
    -- silently. There is no transfer channel for a local file's bytes or an
    argv token into a remote process's launch, so the generated script must
    now RAISE naming the vector instead. The stdin branch is untouched and
    must keep supporting remote mode."""

    def test_argv_sink_generated_script_refuses_remote_loudly(self):
        context, record = _minimal_record_and_context()
        spec = DeliverySpec(sink=SINK_ARGV, argv_template=("{payload_arg}",))
        script = generate_success_script(context, record, spec)
        assert "raise RuntimeError(" in script
        assert "argv" in script
        assert "io = remote(REMOTE_HOST, REMOTE_PORT)" not in script

    def test_file_argv_sink_generated_script_refuses_remote_loudly(self):
        context, record = _minimal_record_and_context()
        spec = DeliverySpec(
            sink=SINK_FILE_ARGV, argv_template=("{payload_file}",), payload_filename="p.bin",
        )
        script = generate_success_script(context, record, spec)
        assert "raise RuntimeError(" in script
        assert "io = remote(REMOTE_HOST, REMOTE_PORT)" not in script

    def test_file_fixed_sink_generated_script_refuses_remote_loudly(self):
        context, record = _minimal_record_and_context()
        spec = DeliverySpec(sink=SINK_FILE_FIXED, payload_filename="input.dat")
        script = generate_success_script(context, record, spec)
        assert "raise RuntimeError(" in script
        assert "io = remote(REMOTE_HOST, REMOTE_PORT)" not in script

    def test_stdin_sink_generated_script_still_supports_remote(self):
        context, record = _minimal_record_and_context()
        script = generate_success_script(context, record, None)
        assert "raise RuntimeError(" not in script
        assert "io = remote(REMOTE_HOST, REMOTE_PORT)" in script


# ---------------------------------------------------------------------------
# Wave 2 REVISION 2 Class 4: SINK_STDIN honors a non-empty argv_template --
# the payload still goes to stdin, but the launch argv reflects the
# template.
# ---------------------------------------------------------------------------

def _make_argv_and_stdin_reflector(tmp_path: Path) -> Path:
    script = tmp_path / "argv_and_stdin_reflector"
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import sys, os\n"
        "argv = b'\\x00'.join(os.fsencode(a) for a in sys.argv[1:])\n"
        # Wave 3 T5: argv is recorded BEFORE the blocking stdin read, and to a
        # PER-PID file as well as the shared one. `verify_payload` spawns the
        # target TWICE (subprocess.run, then the pwntools fallback), and the
        # fallback's child is killed while still blocked on stdin -- so a
        # shared, overwritten dump only ever shows the one spawn that ran to
        # completion. A mutation that broke argv or stdin on one path while
        # leaving the other correct used to stay green.
        "with open('argv_dump.bin', 'wb') as f:\n"
        "    f.write(argv)\n"
        "with open('spawn_argv_%d.bin' % os.getpid(), 'wb') as f:\n"
        "    f.write(argv)\n"
        "data = sys.stdin.buffer.read()\n"
        "with open('stdin_dump.bin', 'wb') as f:\n"
        "    f.write(data)\n"
        "with open('spawn_stdin_%d.bin' % os.getpid(), 'wb') as f:\n"
        "    f.write(data)\n"
    )
    script.chmod(0o755)
    return script


class TestStdinSinkWithArgvTemplate:
    """Wave 2 REVISION 2 Class 4 (closes H2): `DeliverySpec(sink=SINK_STDIN,
    argv_template=("--config", "profile.cfg"))` must reach argv (an
    unrelated config flag pair) while the payload keeps going to stdin --
    proven at both the verifier (real spawn) and template (generated
    script) levels."""

    def test_stdin_sink_with_argv_template_reaches_argv_and_keeps_stdin(self, tmp_path):
        reflector = _make_argv_and_stdin_reflector(tmp_path)
        ctx = ExploitContext()
        ctx.delivery_spec = DeliverySpec(sink=SINK_STDIN, argv_template=("--config", "profile.cfg"))
        pv = PipelineVerifier(str(reflector), context=ctx, static_preflight=False)

        pv.verify_payload("t", b"PAYLOADBYTES")

        # Wave 3 T5: assert what BOTH spawns saw, and pin the encoding
        # exactly rather than accepting either form.
        argv_spawns = [p.read_bytes() for p in sorted(tmp_path.glob("spawn_argv_*.bin"))]
        stdin_spawns = [p.read_bytes() for p in sorted(tmp_path.glob("spawn_stdin_*.bin"))]

        assert len(argv_spawns) >= 2, (
            "expected verify_payload to spawn the target twice (subprocess.run "
            "then the pwntools fallback, which runs because a reflector never "
            f"prints a flag); saw {len(argv_spawns)} spawn(s)"
        )
        for i, dump in enumerate(argv_spawns):
            assert dump.split(b"\x00") == [b"--config", b"profile.cfg"], (i, dump)

        # The subprocess path passes `input=payload` verbatim and the child
        # runs to completion, so exactly these bytes must appear -- no "\n",
        # no alternative accepted.
        assert b"PAYLOADBYTES" in stdin_spawns, stdin_spawns
        for dump in stdin_spawns:
            assert dump.startswith(b"PAYLOADBYTES"), dump

    def test_stdin_sink_with_empty_argv_template_is_unaffected(self, tmp_path):
        reflector = _make_argv_and_stdin_reflector(tmp_path)
        ctx = ExploitContext()
        ctx.delivery_spec = DeliverySpec(sink=SINK_STDIN, argv_template=())
        pv = PipelineVerifier(str(reflector), context=ctx, static_preflight=False)

        pv.verify_payload("t", b"PAYLOADBYTES")

        argv_dump = (tmp_path / "argv_dump.bin").read_bytes()
        assert argv_dump == b"", argv_dump

    def test_stdin_sink_with_argv_template_reaches_argv_in_generated_script(self):
        context, record = _minimal_record_and_context()
        spec = DeliverySpec(sink=SINK_STDIN, argv_template=("--config", "profile.cfg"))
        script = generate_success_script(context, record, spec)
        assert "process([BINARY, '--config', 'profile.cfg'])" in script, script
        assert "io.sendline(PAYLOAD)" in script

    def test_stdin_sink_with_empty_argv_template_generated_script_unchanged(self):
        context, record = TestDefaultUnchanged()._stdin_record_and_context()
        script = generate_success_script(context, record, DeliverySpec(sink=SINK_STDIN, argv_template=()))
        assert script == EXPECTED_STDIN_SCRIPT


# ---------------------------------------------------------------------------
# Wave 2 REVISION 2 Class 5: AttemptRecord.delivered_bytes is set at the
# real executor call sites, and generate_success_script's non-stdin
# branches PREFER it over reconstructing `payload + b"\n"` by convention.
# ---------------------------------------------------------------------------

class TestDeliveredBytesIsSetAndPreferred:
    def test_variable_overwrite_success_sets_delivered_bytes(self, built):
        """Drives the REAL `VariableOverwriteExecutor` to a verified
        SUCCESS (via `file_vector_gate`, a real compiled fixture) and
        asserts the SUCCESS `AttemptRecord` it appended has
        `delivered_bytes` set to exactly `payload + b"\\n"` -- the bytes
        `PipelineVerifier.verify_payload` actually received. Falling back
        to reconstruction in `templates.py` masks a missing assignment
        here for THIS executor (since the fallback computes the same
        bytes), so this test targets the assignment directly rather than
        only its downstream effect."""
        exe = built["file_vector_gate"]
        engine = _engine_for(exe, input_vector=SINK_FILE_ARGV, input_name=f"{uuid.uuid4().hex}.bin")
        engine._attempt_techniques(["variable_overwrite"])
        assert engine.successful

        success_records = [
            a for a in engine.context.attempts
            if a.technique == "variable_overwrite" and a.outcome == AttemptOutcome.SUCCESS
        ]
        assert len(success_records) == 1
        record = success_records[0]
        assert record.delivered_bytes is not None, (
            "variable_overwrite's SUCCESS AttemptRecord did not set "
            "delivered_bytes -- a future producer that verifies something "
            "other than `payload + b'\\n'` would get a silently wrong "
            "replay script with no way to tell"
        )
        assert record.delivered_bytes == record.payload + b"\n"

    def test_generated_script_prefers_delivered_bytes_over_reconstruction(self):
        """Constructs an `AttemptRecord` where `delivered_bytes` DELIBERATELY
        differs from `payload + b"\\n"` (a producer that verified something
        else entirely) and proves `generate_success_script`'s non-stdin
        branch emits `delivered_bytes`, not the reconstruction -- the two
        must be distinguishable for this test to mean anything, unlike the
        real executors above where they always coincide."""
        binary = SimpleNamespace(path=Path("/tmp/vuln"), bits=64)
        context = SimpleNamespace(binary=binary)
        record = AttemptRecord(
            technique="variable_overwrite",
            outcome=AttemptOutcome.SUCCESS,
            stage_reached=Stage.VERIFICATION,
            payload=b"PAYLOAD-BYTES",
            delivered_bytes=b"COMPLETELY-DIFFERENT-DELIVERED-BYTES",
        )
        spec = DeliverySpec(sink=SINK_FILE_FIXED, payload_filename="input.dat")
        script = generate_success_script(context, record, spec)
        assert "COMPLETELY-DIFFERENT-DELIVERED-BYTES" in script
        assert "PAYLOAD-BYTES" not in script

    def test_generated_script_falls_back_to_reconstruction_when_delivered_bytes_absent(self):
        binary = SimpleNamespace(path=Path("/tmp/vuln"), bits=64)
        context = SimpleNamespace(binary=binary)
        record = AttemptRecord(
            technique="variable_overwrite",
            outcome=AttemptOutcome.SUCCESS,
            stage_reached=Stage.VERIFICATION,
            payload=b"PAYLOAD-BYTES",
            delivered_bytes=None,
        )
        spec = DeliverySpec(sink=SINK_FILE_FIXED, payload_filename="input.dat")
        script = generate_success_script(context, record, spec)
        assert repr(b"PAYLOAD-BYTES\n") in script


# ---------------------------------------------------------------------------
# Wave 2 REVISION 2 Class 1, the C1 half: the refusal gate must cover EVERY
# non-stdin sink, not just the two file sinks.
#
# WHY THIS CLASS EXISTS SEPARATELY from the six mechanism solves: those all
# drive `variable_overwrite`, which is ON the allowlist, so the gate is a
# NO-OP for them. Reverting the gate to `sink in (SINK_FILE_ARGV,
# SINK_FILE_FIXED)` -- valid Python, every name in scope, C1's semantics
# removed and nothing else -- left all 37 of the other tests in this file
# GREEN (measured). The C1 fix was therefore an UNMEASURED CLAIM: present in
# the code, uncovered by anything that could fail. These gates close that.
#
# The defect C1 names is that a NON-allowlisted technique reaches its
# executor under `--input-vector argv`; script-based executors never resolve
# the delivery spec at all, so one that happens to work over stdin would
# report SUCCESS without ever using argv.
# ---------------------------------------------------------------------------
class TestNonStdinVectorRefusesNonAllowlistedTechniques:
    # Real names from `build_default_registry()`, deliberately verified
    # against it rather than guessed: an unregistered name hits the "Unknown
    # technique" branch EARLIER in the loop and never reaches the gate, so a
    # typo here would make these gates vacuous (it made the first draft of
    # this test fail against a correct gate). `fmtstr_write_gate` and
    # `stack_shellcode` are the script-based executors C1 actually names --
    # they never resolve the delivery spec, so they are the ones that could
    # have reported SUCCESS over stdin under a declared non-stdin vector.
    # Wave 3 T1 (round-3 review, "Remaining tests that can pass without the
    # named capability"): DERIVED from the registry, not hand-picked. The
    # previous version named four techniques, so a gate hard-coded to refuse
    # exactly those four while letting every other non-allowlisted technique
    # through stayed green. `registry.names() - FILE_DELIVERY_ALLOWLIST` is
    # the property that actually matters, and it grows automatically when a
    # new executor is registered.
    _NON_ALLOWLISTED = _NON_ALLOWLISTED_REGISTERED

    def test_the_derived_name_set_is_non_vacuous_and_the_allowlist_is_not_stale(self):
        """Guards the gates below from going vacuous in both directions.

        A name that does not resolve in the registry is skipped as *unknown*
        earlier in `_attempt_techniques` and never reaches the delivery gate,
        so the refusal assertions would pass for the wrong reason; and an
        allowlist entry that is no longer a registered technique would make
        the positive control below unfalsifiable."""
        from supwngo.exploit.pipeline.executors import build_default_registry
        registry = build_default_registry()
        assert len(self._NON_ALLOWLISTED) >= 2, (
            "the derived non-allowlisted set collapsed -- every registered "
            "technique is on FILE_DELIVERY_ALLOWLIST, so the refusal gates "
            f"below assert nothing: {self._NON_ALLOWLISTED}"
        )
        for name in self._NON_ALLOWLISTED:
            assert registry.get(name) is not None, (
                f"{name!r} came from registry.names() but does not resolve"
            )
        for name in sorted(FILE_DELIVERY_ALLOWLIST):
            assert registry.get(name) is not None, (
                f"FILE_DELIVERY_ALLOWLIST names {name!r}, which is not a "
                "registered technique -- the allowlist is stale and the "
                "positive control cannot fail"
            )

    def _engine(self, built, **kw):
        return CanonicalAutopwnEngine(
            Binary.load(str(built["file_vector_gate"])), timeout=5.0, **kw
        )

    @pytest.mark.parametrize("vector", [SINK_ARGV, SINK_FILE_ARGV, SINK_FILE_FIXED])
    def test_non_allowlisted_techniques_are_refused_under_every_non_stdin_sink(
        self, built, vector
    ):
        """The gate must fire for SINK_ARGV exactly as it does for the file
        sinks. Parametrizing over all three is what makes the argv case
        non-vacuous -- a file-sinks-only gate passes two of these three and
        fails the third."""
        kw = {"input_vector": vector}
        if vector != SINK_ARGV:
            kw["input_name"] = "p_%s.bin" % uuid.uuid4().hex[:8]
        engine = self._engine(built, **kw)
        engine._attempt_techniques(list(self._NON_ALLOWLISTED))

        refused = {
            a.technique: a for a in engine.context.attempts
            if a.outcome == AttemptOutcome.SKIPPED
        }
        for name in self._NON_ALLOWLISTED:
            assert name in refused, (
                f"{name} was NOT refused under vector {vector!r} -- a technique "
                "outside FILE_DELIVERY_ALLOWLIST reached its executor, which is "
                "the C1 defect: it would deliver over stdin and could report "
                f"SUCCESS without ever using {vector!r}. "
                f"attempts={[(a.technique, a.outcome) for a in engine.context.attempts]}"
            )
            assert "non-stdin delivery" in (refused[name].failure_reason or ""), (
                f"{name} was skipped under {vector!r} but not for the delivery "
                f"reason: {refused[name].failure_reason!r}"
            )

    @pytest.mark.parametrize("allowed", sorted(FILE_DELIVERY_ALLOWLIST))
    def test_the_allowlisted_pair_is_not_refused_so_the_gate_is_not_refusing_everything(
        self, built, allowed
    ):
        """Positive control, paired with the refusals above: a gate that
        refused EVERY technique would satisfy the assertions in the previous
        test while breaking the whole feature.

        Wave 3 T2: parametrized over EVERY allowlist member, not just
        `variable_overwrite`. Dropping `ret2win` from the allowlist used to
        leave this file green."""
        engine = self._engine(built, input_vector=SINK_ARGV)
        engine._attempt_techniques([allowed])
        delivery_refusals = [
            a for a in engine.context.attempts
            if a.outcome == AttemptOutcome.SKIPPED
            and "non-stdin delivery" in (a.failure_reason or "")
        ]
        assert not delivery_refusals, (
            f"{allowed} is on FILE_DELIVERY_ALLOWLIST and must NOT be "
            f"refused by the delivery gate: {delivery_refusals}"
        )

    def test_stdin_vector_refuses_nothing_so_the_default_path_is_untouched(self, built):
        """The gate keys on 'not stdin'. Under an explicitly declared stdin
        vector it must refuse nothing at all -- otherwise widening it from
        file-sinks to all-non-stdin sinks would have caught the default path
        too, which is the regression that matters most here."""
        engine = self._engine(built, input_vector=SINK_STDIN)
        engine._attempt_techniques(list(self._NON_ALLOWLISTED))
        delivery_refusals = [
            a for a in engine.context.attempts
            if a.outcome == AttemptOutcome.SKIPPED
            and "non-stdin delivery" in (a.failure_reason or "")
        ]
        assert not delivery_refusals, (
            "declared stdin vector must not trigger the non-stdin delivery "
            f"refusal: {delivery_refusals}"
        )


# ---------------------------------------------------------------------------
# Wave 3 (round-3 review, docs/plans/2026-09-26-wave2-impl-review-r3-daybreak.md)
#
# T3  delivered_bytes is asserted for BOTH stock allowlisted executors.
# T4  remote refusals are EXECUTED, not grepped for.
# T6  embedded/repeated-placeholder artifacts are EXECUTED and compared,
#     argv for argv, against what the verifier actually launched (H1).
# G-W3-1  the fd-0 discipline is characterized as ONE rule for all four
#     sinks, so a partial "fix" for the non-stdin sinks cannot land silently.
# ---------------------------------------------------------------------------

#: An argv reflector that is a REAL ELF, not a `#!` script.
#:
#: Wave 3: the parity test below compares the argv the verifier launched with
#: the argv the GENERATED ARTIFACT launches, and the artifact uses pwntools'
#: `process()`, which parses its target as an ELF -- handing it a Python
#: script raises `ELFError: Magic number does not match` before the child ever
#: starts. `_make_argv_reflector`'s script form is fine for the verifier-only
#: tests above (their first spawn is `subprocess.run`), but an artifact-side
#: comparison needs a compiled binary.
_C_ARGV_REFLECTOR = r"""
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    FILE *f = fopen("argv_dump.bin", "wb");
    if (!f) return 1;
    for (int i = 1; i < argc; i++) {
        if (i > 1) fputc(0, f);
        fwrite(argv[i], 1, strlen(argv[i]), f);
    }
    fclose(f);
    return 0;
}
"""


def _make_c_argv_reflector(tmp_path: Path) -> Path:
    src = tmp_path / "c_argv_reflector.c"
    src.write_text(_C_ARGV_REFLECTOR)
    exe = tmp_path / "c_argv_reflector"
    subprocess.run(
        ["gcc", *_CFLAGS, "-o", str(exe), str(src)],
        check=True, capture_output=True, text=True,
    )
    assert exe.is_file()
    return exe


_WIN_FUNCTION_TARGET = (
    Path(__file__).resolve().parent.parent
    / "benchmark" / "corpus" / "15_win_function" / "win_function"
)


def _record_and_context_for(binary_path: Path, payload: bytes = b"HELLO") -> tuple:
    binary = SimpleNamespace(path=binary_path, bits=64)
    context = SimpleNamespace(binary=binary)
    record = AttemptRecord(
        technique="variable_overwrite",
        outcome=AttemptOutcome.SUCCESS,
        stage_reached=Stage.VERIFICATION,
        payload=payload,
        delivered_bytes=payload,
    )
    return context, record


def _run_generated_script_rc(script: str, cwd: Path, remote: bool = False) -> tuple:
    """Write `script` to `cwd` and RUN it, returning (returncode, output).

    Stdin is closed so a script that reaches `io.interactive()` cannot block
    on the parent's terminal, and the timeout is generous because importing
    pwntools dominates the runtime.
    """
    if remote:
        patched = script.replace(
            'REMOTE_HOST = ""', 'REMOTE_HOST = "127.0.0.1"',
        ).replace("REMOTE_PORT = 0", "REMOTE_PORT = 9")
        assert patched != script, "REMOTE_HOST/REMOTE_PORT constants not found"
        script = patched
    path = cwd / "replay.py"
    path.write_text(script)
    import os as _os

    env = dict(_os.environ, TERM="xterm", PWNLIB_NOTERM="1")
    done = subprocess.run(
        [sys.executable, str(path)],
        cwd=str(cwd), capture_output=True, timeout=180,
        stdin=subprocess.DEVNULL, env=env,
    )
    return done.returncode, (done.stdout + done.stderr).decode("latin-1", "ignore")


class TestRet2winAlsoRecordsDeliveredBytes:
    """Wave 3 T3: `delivered_bytes` was only ever asserted for
    `variable_overwrite`, so deleting either of `ret2win`'s two assignments
    (stack_techniques.py, both success paths) left every delivery test green.

    Driven over the DEFAULT stdin vector against the corpus win-function
    target, because the assignment is vector-independent and no committed
    fixture makes `ret2win` win over a file/argv vector (recorded as a gap in
    the plan doc -- adding a 13th input-vector fixture ripples into the
    foundation suite's EXPECTED_VERDICTS table)."""

    def test_ret2win_success_record_carries_the_exact_verified_bytes(self):
        if not _WIN_FUNCTION_TARGET.exists():
            pytest.skip("corpus target 15_win_function not built")
        engine = CanonicalAutopwnEngine(
            Binary.load(str(_WIN_FUNCTION_TARGET)), timeout=10.0,
        )
        # Unlike `variable_overwrite`, `ret2win` needs the profiling prologue:
        # without it no win/flag function is detected and the executor skips
        # with "no win/flag function detected in binary" -- which would make
        # this gate vacuous rather than failing honestly.
        engine._run_prologue()
        engine._attempt_techniques(["ret2win"])

        successes = [
            a for a in engine.context.attempts
            if a.technique == "ret2win" and a.outcome == AttemptOutcome.SUCCESS
        ]
        assert successes, (
            "ret2win did not solve the corpus win-function target, so this "
            "gate cannot observe its delivered_bytes assignment: "
            f"{[(a.technique, a.outcome, a.failure_reason) for a in engine.context.attempts]}"
        )
        record = successes[0]
        assert record.delivered_bytes is not None, (
            "ret2win's SUCCESS AttemptRecord did not set delivered_bytes"
        )
        assert record.delivered_bytes == (record.payload or b"") + b"\n", (
            "delivered_bytes must be the EXACT bytes handed to "
            f"verify_payload: {record.delivered_bytes!r}"
        )


class TestRemoteRefusalActuallyRaisesWhenRun:
    """Wave 3 T4: the round-2 remote-refusal tests only inspected the
    generated SOURCE, so a mutation to `if REMOTE_HOST and False:` kept every
    asserted string while silently taking the local branch. These RUN the
    script with the remote constants populated and require the named error.

    Port 9 (discard) on localhost is used deliberately: if the refusal is
    absent the script tries to connect there, which cannot succeed silently
    -- so the mutation shows up as a MISSING RuntimeError rather than a hang.
    """

    @pytest.mark.parametrize(
        "spec_factory,expected_fragment",
        [
            (lambda: DeliverySpec(sink=SINK_ARGV, argv_template=("{payload_arg}",)), "SINK_ARGV"),
            (
                lambda: DeliverySpec(
                    sink=SINK_FILE_ARGV, argv_template=("{payload_file}",),
                    payload_filename="p.bin",
                ),
                "file-argv",
            ),
            (
                lambda: DeliverySpec(sink=SINK_FILE_FIXED, payload_filename="input.dat"),
                "file-fixed",
            ),
        ],
        ids=["argv", "file-argv", "file-fixed"],
    )
    def test_non_stdin_script_raises_at_runtime_in_remote_mode(
        self, tmp_path, spec_factory, expected_fragment
    ):
        # A REAL ELF: the generated script sets `context.binary = BINARY`
        # before it reaches the remote refusal, so a fake header dies in
        # pwntools' ELF parser and the refusal is never exercised. The
        # reflector is never launched here -- the refusal raises first.
        target = _make_c_argv_reflector(tmp_path)
        context, record = _record_and_context_for(target)
        script = generate_success_script(context, record, spec_factory())

        rc, output = _run_generated_script_rc(script, tmp_path, remote=True)

        assert rc != 0, f"remote mode must fail loudly, got rc=0:\n{output}"
        assert "RuntimeError" in output, output
        assert expected_fragment in output, output

    def test_the_file_sink_refusal_leaves_no_payload_file_behind(self, tmp_path):
        """F4: the refusal must come BEFORE the payload file is written. A
        winning payload left in the binary's own directory is exactly what
        makes a LATER default-vector run win spuriously."""
        bindir = tmp_path / "bin"
        bindir.mkdir()
        target = _make_c_argv_reflector(bindir)
        context, record = _record_and_context_for(target)
        spec = DeliverySpec(
            sink=SINK_FILE_ARGV, argv_template=("{payload_file}",),
            payload_filename="p.bin",
        )
        script = generate_success_script(context, record, spec)

        rc, output = _run_generated_script_rc(script, tmp_path, remote=True)

        assert rc != 0 and "RuntimeError" in output, output
        assert not (bindir / "p.bin").exists(), (
            "the remote refusal wrote the payload file before raising -- a "
            "later default-vector run against this directory would win "
            "spuriously"
        )

    def test_stdin_script_still_reaches_remote_at_runtime(self, tmp_path):
        """Positive control: the stdin branch must NOT raise. Without this,
        a generator that raised for every sink would satisfy the refusals
        above."""
        # A REAL ELF: the generated script sets `context.binary = BINARY`
        # before it reaches the remote refusal, so a fake header dies in
        # pwntools' ELF parser and the refusal is never exercised. The
        # reflector is never launched here -- the refusal raises first.
        target = _make_c_argv_reflector(tmp_path)
        context, record = _record_and_context_for(target)
        script = generate_success_script(context, record, None)

        rc, output = _run_generated_script_rc(script, tmp_path, remote=True)

        assert "RuntimeError" not in output, (
            "the stdin branch must keep supporting remote mode:\n" + output
        )
        # It fails for the RIGHT reason: nothing is listening on discard/9.
        assert rc != 0
        assert ("Could not connect" in output or "refused" in output.lower()), output


class TestGeneratedArtifactArgvMatchesTheVerifiedArgv:
    """Wave 3 T6 / H1: the artifact must launch the target with the SAME argv
    the verifier used -- proven by RUNNING both against an argv reflector and
    comparing the recorded bytes, not by grepping the generated source.

    The repeated-placeholder cases are the ones that motivated this:
    `DeliverySpec.build_argv()` substitutes with `str.replace()` (all
    occurrences) and the verifier splits on all occurrences, while the
    renderer used `split(sentinel, 1)` -- so a token containing the
    placeholder twice produced an artifact carrying a LEFTOVER RANDOM
    SENTINEL where the second payload belonged. Source inspection could not
    see it; this comparison cannot miss it.
    """

    _PAYLOAD = b"HELLO"

    @pytest.mark.parametrize(
        "spec_factory",
        [
            lambda: DeliverySpec(sink=SINK_ARGV, argv_template=("{payload_arg}",)),
            lambda: DeliverySpec(sink=SINK_ARGV, argv_template=("--data={payload_arg}",)),
            lambda: DeliverySpec(
                sink=SINK_ARGV, argv_template=("--data={payload_arg}:{payload_arg}",),
            ),
            lambda: DeliverySpec(
                sink=SINK_ARGV,
                argv_template=("--a={payload_arg}", "--b={payload_arg}"),
            ),
            lambda: DeliverySpec(
                sink=SINK_FILE_ARGV, argv_template=("--in={payload_file}",),
                payload_filename="p.bin",
            ),
            lambda: DeliverySpec(
                sink=SINK_FILE_ARGV,
                argv_template=("--in={payload_file}:{payload_file}",),
                payload_filename="p.bin",
            ),
            lambda: DeliverySpec(
                sink=SINK_FILE_ARGV,
                argv_template=("--in={payload_file}", "--also={payload_file}"),
                payload_filename="p.bin",
            ),
        ],
        ids=[
            "argv-bare", "argv-prefixed", "argv-repeated-in-token",
            "argv-repeated-across-tokens", "file-prefixed",
            "file-repeated-in-token", "file-repeated-across-tokens",
        ],
    )
    def test_artifact_launches_the_same_argv_the_verifier_did(
        self, tmp_path, spec_factory
    ):
        reflector = _make_c_argv_reflector(tmp_path)
        spec = spec_factory()

        ctx = ExploitContext()
        ctx.delivery_spec = spec
        pv = PipelineVerifier(str(reflector), context=ctx, static_preflight=False)
        pv.verify_payload("t", self._PAYLOAD)
        verified_argv = (tmp_path / "argv_dump.bin").read_bytes()
        assert verified_argv, "the verifier never launched the reflector"

        # The file-sink artifact spawns with cwd=dirname(BINARY), i.e. the
        # reflector's own directory -- so the verifier's dump must be read and
        # removed before the artifact runs, or the artifact overwrites it.
        (tmp_path / "argv_dump.bin").unlink()
        for leftover in tmp_path.glob("p.bin"):
            leftover.unlink()

        context, record = _record_and_context_for(reflector, self._PAYLOAD)
        script = generate_success_script(context, record, spec)
        run_dir = tmp_path / "replay"
        run_dir.mkdir()
        rc, output = _run_generated_script_rc(script, run_dir)

        dumps = list(tmp_path.glob("argv_dump.bin")) + list(run_dir.glob("argv_dump.bin"))
        assert dumps, f"the generated artifact never launched the reflector:\n{output}"
        replayed_argv = dumps[0].read_bytes()

        assert replayed_argv == verified_argv, (
            "the generated artifact launched a DIFFERENT argv than the one "
            f"verified.\n  verified: {verified_argv!r}\n  replayed: "
            f"{replayed_argv!r}\nscript:\n{script}"
        )


class TestFdZeroDisciplineIsOneRuleForEverySink:
    """G-W3-1 (round-3 H2), recorded as a CHARACTERIZATION, not a fix.

    The round-3 review reports that non-stdin verification (`input=b""`,
    immediate EOF) and the generated artifact (open PTY, never shut down)
    disagree about fd 0. Measured: the STDIN default has the identical
    divergence and always has -- `subprocess.run(input=payload)` gives the
    child EOF after the payload while the artifact does
    `sendline(); interactive()` and leaves stdin open. So this is a
    pre-existing, family-wide property, not something the new sinks
    introduced, and the stdin script is pinned byte-identical to HEAD.

    This test pins the property as ONE rule across all four sinks: whatever
    the discipline is, every sink shares it. A future partial fix that
    shuts down stdin for the non-stdin sinks only (which would also starve
    `PipelineVerifier.verify_script`'s SHELL_ACCESS oracle, since that feeds
    the receipt token through the artifact's own stdin) turns this RED
    instead of landing silently.
    """

    @pytest.mark.parametrize(
        "spec_factory",
        [
            lambda: None,
            lambda: DeliverySpec(),
            lambda: DeliverySpec(sink=SINK_ARGV, argv_template=("{payload_arg}",)),
            lambda: DeliverySpec(
                sink=SINK_FILE_ARGV, argv_template=("{payload_file}",),
                payload_filename="p.bin",
            ),
            lambda: DeliverySpec(sink=SINK_FILE_FIXED, payload_filename="input.dat"),
        ],
        ids=["no-spec", "stdin", "argv", "file-argv", "file-fixed"],
    )
    def test_every_sink_hands_over_with_the_childs_stdin_still_open(self, spec_factory):
        context, record = _record_and_context_for(Path("/tmp/vuln"))
        script = generate_success_script(context, record, spec_factory())

        # The subject of the absence search must exist, or a rename makes the
        # assertion below vacuously true.
        assert "io.interactive()" in script, script
        assert "shutdown(" not in script, (
            "one sink now closes the child's stdin and the others do not -- "
            "see G-W3-1 in docs/plans/2026-09-26-sprint2prime-input-vector-plan.md: "
            "the fd-0 discipline must change for ALL FOUR sinks together, and "
            "verify_script's SHELL_ACCESS oracle depends on it staying open"
        )


class TestDeliveryFailureIsLoudNotAPayloadFailure:
    """Wave 3 F3 (closes round-3 H3).

    `_verify_file_sink` handed materialization to `ExploitVerifier` as the
    `pre_spawn` hook, which runs inside `verify_payload`'s blanket
    `except Exception` -- so an unwritable binary directory came back as an
    ordinary unsuccessful verification and the run reported that payload
    candidates had failed, for a run in which no payload was ever delivered.
    """

    def _readonly_bindir(self, tmp_path: Path) -> Path:
        import os

        if os.geteuid() == 0:
            pytest.skip("running as root: directory permissions are not enforced")
        bindir = tmp_path / "ro"
        bindir.mkdir()
        (bindir / "vuln").write_bytes(b"\x7fELF-not-executed-by-this-test")
        bindir.chmod(0o555)
        return bindir

    @pytest.mark.parametrize(
        "spec_factory",
        [
            lambda: DeliverySpec(
                sink=SINK_FILE_ARGV, argv_template=("{payload_file}",),
                payload_filename="p.bin",
            ),
            lambda: DeliverySpec(sink=SINK_FILE_FIXED, payload_filename="input.dat"),
        ],
        ids=["file-argv", "file-fixed"],
    )
    def test_an_unwritable_payload_path_raises_naming_delivery(
        self, tmp_path, spec_factory
    ):
        bindir = self._readonly_bindir(tmp_path)
        try:
            ctx = ExploitContext()
            ctx.delivery_spec = spec_factory()
            pv = PipelineVerifier(
                str(bindir / "vuln"), context=ctx, static_preflight=False,
            )

            with pytest.raises(Exception) as excinfo:
                pv.verify_payload("variable_overwrite", b"PAYLOAD")

            message = str(excinfo.value)
            assert "delivery failed" in message.lower(), (
                "a failure to WRITE the payload file must name delivery, not "
                f"look like a failed exploit attempt: {message!r}"
            )
            assert "no payload was delivered" in message.lower(), message
        finally:
            bindir.chmod(0o755)

    def test_a_writable_payload_path_does_not_raise(self, tmp_path):
        """Positive control: the loud path must be reachable ONLY on a real
        delivery failure. Without this, a `raise` placed unconditionally
        would satisfy the assertions above."""
        (tmp_path / "vuln").write_bytes(b"\x7fELF-not-executed-by-this-test")
        ctx = ExploitContext()
        ctx.delivery_spec = DeliverySpec(
            sink=SINK_FILE_ARGV, argv_template=("{payload_file}",),
            payload_filename="p.bin",
        )
        pv = PipelineVerifier(str(tmp_path / "vuln"), context=ctx, static_preflight=False)

        receipt = pv.verify_payload("variable_overwrite", b"PAYLOAD")

        assert receipt is not None
        assert not receipt.success
        assert not (tmp_path / "p.bin").exists(), "cleanup did not remove the payload file"
