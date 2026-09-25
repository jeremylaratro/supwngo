"""
Tests for the Phase 6 (`docs/plans/2026-09-23-effectiveness-and-usability.md`)
orchestrator-level additions:

- `templates.generate_success_script()` - the fallback that gives a verified
  ``AttemptOutcome.SUCCESS`` a real, replayable exploit script even when the
  executor that produced it never populated
  ``AttemptRecord.partial_artifacts["exploit_script"]`` (true for most of
  the native stack/shellcode executors - see the docstring on
  `generate_success_script` and `docs/architecture/2026-09-23-autopwn-pipeline.md`'s
  "solve vs autopwn" addendum for why this was needed).
- `CanonicalAutopwnEngine._apply_known_facts()` - the guided-fallback resume
  hook `supwngo solve --interactive` drives via `run(known_facts=...)`.
"""

from pathlib import Path
from types import SimpleNamespace

from supwngo.core.context import ExploitContext
from supwngo.exploit.pipeline.contracts import AttemptOutcome, AttemptRecord, Stage
from supwngo.exploit.pipeline.orchestrator import CanonicalAutopwnEngine
from supwngo.exploit.pipeline.templates import generate_success_script


def _fake_binary(bits: int = 64) -> SimpleNamespace:
    return SimpleNamespace(path=Path("/tmp/vuln"), bits=bits)


class TestGenerateSuccessScript:
    def test_includes_payload_technique_and_remote_placeholders(self):
        ctx = SimpleNamespace(binary=_fake_binary())
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

        script = generate_success_script(ctx, record)

        assert "Technique: ret2win" in script
        assert repr(payload) in script
        # Same placeholder convention as generate_universal_template()/the
        # per-technique template generators, so `solve --remote` can fill
        # either kind of generated script with one shared substitution.
        assert 'REMOTE_HOST = ""' in script
        assert "REMOTE_PORT = 0" in script
        assert "def exploit():" in script
        assert "io.sendline(PAYLOAD)" in script

    def test_empty_payload_still_produces_a_valid_script(self):
        ctx = SimpleNamespace(binary=_fake_binary())
        record = AttemptRecord(technique="direct_shellcode", outcome=AttemptOutcome.SUCCESS)

        script = generate_success_script(ctx, record)

        assert "PAYLOAD = b''" in script
        assert "Technique: direct_shellcode" in script

    def test_32bit_binary_uses_i386_context_arch(self):
        ctx = SimpleNamespace(binary=_fake_binary(bits=32))
        record = AttemptRecord(technique="stack_shellcode", outcome=AttemptOutcome.SUCCESS, payload=b"B" * 4)

        script = generate_success_script(ctx, record)

        assert 'context.arch = "i386"' in script


class TestApplyKnownFacts:
    """`_apply_known_facts` is exercised directly (not through a full
    `run()`) to avoid needing a real compiled binary / pwntools ELF load in
    a unit test - it is a small, self-contained mutation of `ExploitContext`
    fields, independent of profiling/strategy/executor machinery."""

    def _engine(self) -> CanonicalAutopwnEngine:
        engine = CanonicalAutopwnEngine.__new__(CanonicalAutopwnEngine)
        engine.context = ExploitContext()
        return engine

    def test_offset(self):
        engine = self._engine()
        engine._apply_known_facts({"offset": 72})
        assert engine.context.offset == 72

    def test_canary_value(self):
        engine = self._engine()
        engine._apply_known_facts({"canary_value": 0xDEADBEEF})
        assert engine.context.stack.canary_value == 0xDEADBEEF

    def test_libc_base(self):
        engine = self._engine()
        engine._apply_known_facts({"libc_base": 0x7FFFF7A00000})
        assert engine.context.libc.base == 0x7FFFF7A00000

    def test_pie_base(self):
        engine = self._engine()
        engine._apply_known_facts({"pie_base": 0x555555554000})
        assert engine.context.leaks["pie"] == 0x555555554000

    def test_unknown_key_is_ignored_not_raised(self):
        engine = self._engine()
        engine._apply_known_facts({"bogus_fact": 1})  # must not raise
        assert engine.context.offset is None

    def test_multiple_facts_can_be_applied_at_once(self):
        # `run(known_facts=...)` accepts a dict; the CLI's guided-fallback
        # only ever supplies one key at a time (the documented "supply one
        # missing fact" cap), but the engine-level hook itself doesn't
        # enforce that - it's a CLI-layer UX choice, not a pipeline
        # constraint.
        engine = self._engine()
        engine._apply_known_facts({"offset": 40, "canary_value": 0x1122334455667788})
        assert engine.context.offset == 40
        assert engine.context.stack.canary_value == 0x1122334455667788
