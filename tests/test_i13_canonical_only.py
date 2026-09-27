"""
Tests for I-13: `--no-legacy` on `autopwn`/`solve`, and the `"legacy_fallback"`
positive record in `solve`'s JSON output.

Background (see docs/plans/2026-09-27-path-to-5of7-plan-v3.md): the harness at
`scripts/htb_rescore.py` measures how many HTB targets the canonical
`CanonicalAutopwnEngine` pipeline solves by invoking `supwngo.cli solve`. But
`solve` silently fell back to the legacy `EnhancedAutoExploiter` whenever the
canonical pipeline failed, so the measurement was never canonical-only. These
tests prove, without running real HTB binaries (not available here, and slow):

1. `--no-legacy` GREEN control: the legacy engine is never constructed on a
   forced canonical failure, and the JSON reports `legacy_fallback ==
   "disabled"`.
2. The matching RED proof: WITHOUT `--no-legacy`, under the identical forced
   canonical failure, the legacy engine IS constructed and the JSON reports
   `legacy_fallback == "ran"`. This is what makes test 1 non-vacuous - if this
   test could not be made to pass, test 1 would prove nothing.
3. `legacy_fallback == "not_reached"` when the canonical engine succeeds (the
   fallback condition is never true, so the block never runs at all).
4. `legacy_fallback == "ran"` is recorded even when `legacy.run()` raises -
   i.e. the existing `except Exception: pass` around the fallback cannot hide
   that the legacy engine ran.

Approach: `Binary.load` and `CanonicalAutopwnEngine` are monkeypatched at the
modules `supwngo.cli` actually imports FROM at call time
(`supwngo.core.binary.Binary.load` and
`supwngo.exploit.pipeline.CanonicalAutopwnEngine` - both imports are local to
the `solve()` function body and re-resolved from those modules' namespaces on
every call, so patching the attribute there is sufficient without needing to
patch `supwngo.cli`'s own namespace). `EnhancedAutoExploiter` is likewise
patched at `supwngo.exploit.enhanced_auto.EnhancedAutoExploiter`, the module
`solve()` imports it from.

Driven via `click.testing.CliRunner`, not a real subprocess: the fakes below
never touch pwntools/ELF internals (the reason `test_solve_command.py`'s real
end-to-end tests avoid `CliRunner` - pwntools needs a real `fileno()` - does
not apply here, since `Binary.load` and the engine are both fully faked out).
"""

import json

import pytest
from click.testing import CliRunner

from supwngo.cli import cli


class _FakeContext:
    """Minimal stand-in for `ExploitContext` - only the attributes `solve()`
    actually reads/writes on the happy and unhappy paths exercised here."""

    def __init__(self):
        self.captured_flag = None
        self.verification_level = None
        self.attempts = []
        self.offset = None


class _FakeHandoffReport:
    def to_dict(self):
        return {}


def _make_fake_engine_class(*, successful):
    """Builds a fake `CanonicalAutopwnEngine` whose `.run()` sets
    `.successful` to the given fixed outcome - `False` to force the legacy
    fallback's guard condition true, `True` to force it false."""

    class _FakeEngine:
        def __init__(self, bin_obj, timeout=None, libc_path=None, strategy=None,
                     force_all=None, input_vector=None, input_name=None,
                     input_argv=None):
            self.context = _FakeContext()
            self.successful = False
            self.technique_used = None
            self.exploit_script = None
            self.exploit_template = "# fallback template\n"
            self.final_payload = b""
            self.handoff_report = _FakeHandoffReport()

        def run(self):
            self.successful = successful
            if successful:
                self.technique_used = "ret2win"
                self.exploit_script = "# canonical exploit\n"
                self.context.captured_flag = "HTB{canonical}"

        def summary(self):
            return "fake canonical summary"

    return _FakeEngine


def _make_forbidden_legacy_class():
    """A fake `EnhancedAutoExploiter` that raises `AssertionError` the moment
    it is instantiated, and separately records every construction attempt in
    a class-level list - so a test can assert non-instantiation directly
    (`.calls == []`), not only via the JSON `legacy_fallback` field, in case
    a regression's `AssertionError` gets swallowed by `solve()`'s existing
    `except Exception: pass` around the fallback."""

    class _ForbiddenLegacy:
        calls = []

        def __init__(self, *args, **kwargs):
            type(self).calls.append((args, kwargs))
            raise AssertionError(
                "EnhancedAutoExploiter must not be instantiated under --no-legacy"
            )

    return _ForbiddenLegacy


def _make_tracking_legacy_class(*, successful=False, raise_in_run=False):
    """A fake `EnhancedAutoExploiter` that constructs cleanly (recording each
    instantiation) so the code under test can reach the point where it marks
    `legacy_fallback = "ran"` - unlike `_ForbiddenLegacy`, which must never be
    reached at all."""

    class _TrackingLegacy:
        instances = []

        def __init__(self, bin_obj, libc_path=None):
            type(self).instances.append(self)
            self.successful = successful
            self.technique_used = "legacy_technique" if successful else None
            self.exploit_script = "# legacy exploit\n" if successful else None
            self.exploit_template = "# legacy template\n"
            self.verification_level = None
            self._captured_flag = "HTB{legacy}" if successful else None

        def run(self):
            if raise_in_run:
                raise RuntimeError("legacy engine crashed mid-run")

    return _TrackingLegacy


def _invoke_solve(tmp_path, monkeypatch, *, fake_engine_cls, fake_legacy_cls, extra_args=()):
    monkeypatch.setattr(
        "supwngo.core.binary.Binary.load",
        classmethod(lambda cls, path, auto_load_libs=False: object()),
    )
    monkeypatch.setattr(
        "supwngo.exploit.pipeline.CanonicalAutopwnEngine", fake_engine_cls
    )
    monkeypatch.setattr(
        "supwngo.exploit.enhanced_auto.EnhancedAutoExploiter", fake_legacy_cls
    )

    binary = tmp_path / "challenge"
    binary.write_bytes(b"not a real elf, Binary.load is faked out")
    output = tmp_path / "exploit.py"

    # mix_stderr=False: `_json_mode()` redirects the Rich console (the
    # "solve: <binary>" banner) to stderr precisely to keep stdout clean for
    # `_emit_json`'s `click.echo`. With the default `mix_stderr=True`,
    # CliRunner interleaves that banner into `result.output` ahead of the
    # JSON, breaking a bare `json.loads(result.output)`.
    runner = CliRunner(mix_stderr=False)
    result = runner.invoke(
        cli, ["solve", str(binary), "-o", str(output), "--json", *extra_args]
    )
    assert result.exit_code == 0, result.output + result.stderr
    data = json.loads(result.stdout)
    return data


class TestNoLegacyGreenControl:
    """Test 1: with --no-legacy and a forced canonical failure,
    EnhancedAutoExploiter is never constructed."""

    def test_legacy_engine_never_instantiated(self, tmp_path, monkeypatch):
        forbidden = _make_forbidden_legacy_class()
        fake_engine = _make_fake_engine_class(successful=False)

        data = _invoke_solve(
            tmp_path, monkeypatch,
            fake_engine_cls=fake_engine, fake_legacy_cls=forbidden,
            extra_args=["--no-legacy"],
        )

        assert forbidden.calls == [], (
            "EnhancedAutoExploiter.__init__ was called despite --no-legacy"
        )
        assert data["legacy_fallback"] == "disabled"
        assert data["success"] is False
        # No `legacy:` prefix could possibly have been laundered in.
        assert not (isinstance(data["technique"], str) and data["technique"].startswith("legacy:"))


class TestNoLegacyRedProof:
    """Test 2: the RED proof that test 1 is not vacuous. WITHOUT
    --no-legacy, under the identical forced canonical failure, the legacy
    engine IS constructed and the JSON reports "ran". If this could not be
    made to pass, test 1 would prove nothing."""

    def test_legacy_engine_is_instantiated_without_the_flag(self, tmp_path, monkeypatch):
        tracking = _make_tracking_legacy_class(successful=False)
        fake_engine = _make_fake_engine_class(successful=False)

        data = _invoke_solve(
            tmp_path, monkeypatch,
            fake_engine_cls=fake_engine, fake_legacy_cls=tracking,
            extra_args=[],  # no --no-legacy
        )

        assert len(tracking.instances) == 1, (
            "EnhancedAutoExploiter was not instantiated even though "
            "--no-legacy was NOT passed - the fallback guard is over-broad"
        )
        assert data["legacy_fallback"] == "ran"


class TestNotReachedWhenCanonicalSucceeds:
    """Test 3: legacy_fallback == "not_reached" when the canonical engine
    succeeds - the fallback's guard condition is never true."""

    def test_not_reached_on_canonical_success(self, tmp_path, monkeypatch):
        # Use the forbidding fake here too: a canonical SUCCESS must mean the
        # fallback block - and therefore the legacy import/construction - is
        # never reached, regardless of --no-legacy.
        forbidden = _make_forbidden_legacy_class()
        fake_engine = _make_fake_engine_class(successful=True)

        data = _invoke_solve(
            tmp_path, monkeypatch,
            fake_engine_cls=fake_engine, fake_legacy_cls=forbidden,
            extra_args=[],
        )

        assert forbidden.calls == []
        assert data["success"] is True
        assert data["legacy_fallback"] == "not_reached"


class TestRanRecordedEvenWhenLegacyRaises:
    """Test 4: "ran" is recorded even when legacy.run() raises - the
    existing `except Exception: pass` cannot hide that the legacy engine
    ran, because `legacy_fallback` is set to "ran" BEFORE `legacy.run()` is
    called."""

    def test_ran_recorded_despite_legacy_run_raising(self, tmp_path, monkeypatch):
        tracking = _make_tracking_legacy_class(successful=False, raise_in_run=True)
        fake_engine = _make_fake_engine_class(successful=False)

        data = _invoke_solve(
            tmp_path, monkeypatch,
            fake_engine_cls=fake_engine, fake_legacy_cls=tracking,
            extra_args=[],
        )

        assert len(tracking.instances) == 1
        assert data["legacy_fallback"] == "ran"
        # The raise must not have propagated out of `solve` as an uncaught
        # exception, and must not silently look like a canonical success.
        assert data["success"] is False
