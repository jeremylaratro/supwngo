"""Tests for ret2plt's runtime-built command-string fallback."""

from pathlib import Path

from supwngo.core.binary import Binary
from supwngo.core.context import ExploitContext
from supwngo.exploit.pipeline.executors.rop_techniques import Ret2PltSystemExecutor
from supwngo.exploit.pipeline.profile_stage import run_static_analysis


TARGET = Path("benchmark/corpus_r2/02_ret2plt_strcat_system/ret2plt_strcat_system")


def test_runtime_string_fallback_ranks_named_written_buffer_first():
    binary = Binary.load(str(TARGET))
    context = ExploitContext.from_binary(binary)
    run_static_analysis(context)

    assert context.binsh_addr is None
    candidates = Ret2PltSystemExecutor._writable_string_candidates(context)
    assert candidates
    assert candidates[0][0] == binary.symbols["sh_buf"].address
    assert Ret2PltSystemExecutor().is_applicable(context)


def test_static_binsh_path_does_not_enumerate_writable_fallback(monkeypatch):
    target = Path("benchmark/corpus/02_ret2plt_system/ret2plt_system")
    binary = Binary.load(str(target))
    context = ExploitContext.from_binary(binary)
    run_static_analysis(context)

    assert context.binsh_addr is not None
    monkeypatch.setattr(
        Ret2PltSystemExecutor,
        "_writable_string_candidates",
        staticmethod(lambda _context: (_ for _ in ()).throw(
            AssertionError("fallback ran despite a static /bin/sh")
        )),
    )
    assert Ret2PltSystemExecutor().is_applicable(context)
