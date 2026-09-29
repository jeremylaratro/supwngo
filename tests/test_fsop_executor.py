"""Unit and end-to-end proofs for the FSOP stdout-read executor."""

from pathlib import Path

import pytest

from supwngo.core.binary import Binary
from supwngo.core.context import ExploitContext
from supwngo.exploit.fsop import FSOPExploiter, IOFile
from supwngo.exploit.pipeline.executors import build_default_registry
from supwngo.exploit.pipeline.executors import fsop_techniques as fsop_exec
from supwngo.exploit.pipeline.orchestrator import FIRST_TECHNIQUES, LAST_TECHNIQUES
from supwngo.exploit.pipeline.verifier import PipelineVerifier
from supwngo.exploit.verification import VerificationLevel


CORPUS = Path(__file__).resolve().parents[1] / "benchmark" / "corpus_fsop"

REGISTRY_BEFORE_FSOP = (
    "env_path_hijack", "heap_strlen_ofb1", "objptr_hijack",
    "toctou_path_race", "symlink_follow_write", "path_traversal_read",
    "uninit_disclosure", "library_path_hijack", "subprocess_injection",
    "weak_prng_replay", "scanf_scalar_overwrite", "eintr_accumulator_rop",
    "srop_symtab_pivot", "variable_overwrite", "ret2win", "ret2plt",
    "int_truncation_bypass", "negative_index_write", "canary_leak_ret2win",
    "fmtstr_write_gate", "direct_shellcode", "stack_shellcode",
    "ret2libc_leak", "ret2dlresolve", "srop", "tcache_poison_got",
    "heap_record_hijack", "scanf_canary_bypass", "uaf", "double_free",
    "container_file_rop", "alloc_size_overflow", "fini_array_write",
    "off_by_one_guard", "heap_uaf_read", "type_confusion_tag",
    "loop_counter_overflow", "heap_offbynul_overlap",
    "oob_index_read_exfil",
)


def _context(path: str = "/bin/true") -> ExploitContext:
    return ExploitContext.from_binary(Binary.load(path))


def test_stdout_read_recipe_uses_the_live_flags_and_file_offsets():
    recipe = FSOPExploiter(libc_version="2.35").stdout_arbitrary_read(
        stdout_addr=0x70000000,
        target_addr=0x404000,
        current_flags=0xFBAD2285,
    )
    assert recipe["route"] == "stdout_write_base"
    assert recipe["vtable_redirect_required"] is False
    assert recipe["writes"] == [
        {
            "field": "_flags",
            "offset": IOFile.OFFSETS["_flags"],
            "target": 0x70000000,
            "value": 0xFBAD3285,
        },
        {
            "field": "_IO_write_base",
            "offset": IOFile.OFFSETS["_IO_write_base"],
            "target": 0x70000020,
            "value": 0x404000,
        },
    ]


def test_local_235_gate_disables_removed_hooks_and_selects_read_route():
    """Regression for the old DEFAULT_LIBC_VERSION=2.31 construction."""
    assert FSOPExploiter(libc_version="2.31").has_hooks is True
    gate = fsop_exec.resolve_libc_gate(_context())
    assert gate.verdict is fsop_exec.GateVerdict.PASS
    assert gate.version == (2, 35)
    assert gate.has_hooks is False
    assert gate.has_vtable_check is True
    assert dict(gate.layout) == {
        "_flags": 0,
        "_IO_write_base": 0x20,
        "vtable": 0xD8,
    }
    assert "House of Emma" in gate.modern_techniques
    assert "redirected-vtable route forbidden" in gate.reason
    assert "using _IO_write_base arbitrary read" in gate.reason


def test_libc_gate_can_report_inconclusive(monkeypatch):
    monkeypatch.setattr(fsop_exec, "local_libc_path", lambda _context: None)
    gate = fsop_exec.resolve_libc_gate(_context())
    assert gate.verdict is fsop_exec.GateVerdict.INCONCLUSIVE
    assert gate.reason.startswith("inconclusive on this libc:")


@pytest.mark.parametrize(
    ("protocol", "first", "second"),
    [
        ("relative_offset_hex", b"offset: ", b"value: "),
        ("absolute_address_hex", b"address: ", b"data: "),
        ("qword_slot_decimal", b"slot: ", b"word: "),
    ],
)
def test_target_gate_distinguishes_all_three_write_protocols(
    tmp_path, monkeypatch, protocol, first, second
):
    image = tmp_path / "fixture"
    image.write_bytes(
        b"stdout=\0vault=\0flags=\0flag.txt\0" + first + b"\0" + second
    )
    monkeypatch.setattr(
        fsop_exec, "_symbol_sizes", lambda _path: {"stdout": 8, "setvbuf": 0}
    )
    plan, reason = fsop_exec.analyse_target(str(image))
    assert reason == ""
    assert plan == fsop_exec.TargetPlan(protocol, first, second)


def test_default_registry_adds_exactly_one_executor_without_duplicates():
    names = tuple(build_default_registry().names())
    assert names == REGISTRY_BEFORE_FSOP + ("fsop_stdout_read",)
    assert len(names) == len(set(names))
    assert set(names) - {"fsop_stdout_read"} == set(REGISTRY_BEFORE_FSOP)


def test_fsop_is_seated_at_the_front_of_the_late_block_only():
    assert "fsop_stdout_read" not in FIRST_TECHNIQUES
    assert LAST_TECHNIQUES == [
        "fsop_stdout_read", "oob_index_read_exfil", "variable_overwrite"
    ]


@pytest.mark.parametrize(
    "slug",
    [
        "fsop_10_relative_offset",
        "fsop_11_absolute_address",
        "fsop_12_qword_slot",
    ],
)
def test_executor_captures_flag_on_built_variants(slug):
    binary_path = CORPUS / slug / slug
    if not binary_path.exists():
        pytest.skip("build corpus_fsop with benchmark/build_all.sh first")
    context = _context(str(binary_path))
    executor = fsop_exec.FsopStdoutReadExecutor()
    verifier = PipelineVerifier(str(binary_path), timeout=5.0, context=context)
    record = executor.attempt(context, verifier)
    assert record.outcome.name == "SUCCESS"
    assert record.receipt is not None
    assert record.receipt.level is VerificationLevel.FLAG_CAPTURED
    expected = (binary_path.parent / "flag.txt").read_text().strip()
    assert record.receipt.flag == expected
