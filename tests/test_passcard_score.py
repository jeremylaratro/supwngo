"""Tests for benchmark/passcard_score.py (SP-01 plan sections 2.1, 3.6 and 3.7).

The first half pins every verdict branch with small tables. The second half
reproduces the scorer-side pins of the 3.7 mutant self-test as pure functions
over the seven S0 targets: each "mutant" here is a function that returns the
``Run`` a shim CLI would have produced, so no process is started. The truth is a
compact fixture (accept-sets and OFF values from plan 2.3; invented addresses),
not the committed truth files, which tests/test_passcard_truth.py validates.
"""

import json
import sys
from pathlib import Path

import pytest

BENCHMARK = Path(__file__).resolve().parent.parent / "benchmark"
sys.path.insert(0, str(BENCHMARK))

import passcard_score as ps  # noqa: E402

Run, Parsed = ps.Run, ps.Parsed
PASS, FAIL, ABSTAIN, ERROR, VOID = ps.PASS, ps.FAIL, ps.ABSTAIN, ps.ERROR, ps.VOID

TRACEBACK = 'Traceback (most recent call last):\n  File "x", line 1\nKeyError: 1\n'
BODY = "void main(void) {\n  read(0, buf, 8);\n}"


def run_of(doc, rc=0, **extra):
    return Run(rc=rc, stdout=json.dumps(doc), **extra)


def parsed_of(doc):
    return Parsed(doc)


def pwn_doc(*approaches, recommended=None):
    strategies = [
        {"approach": a, "confidence": 1.0 - 0.01 * i, "priority": i + 1}
        for i, a in enumerate(approaches)
    ]
    rec = strategies[0] if recommended is None else recommended
    return {"recommended": rec, "strategies": strategies}


# --- parsing -----------------------------------------------------------------


def test_one_document_parses():
    parsed = ps.parse_run(Run(stdout='  {"a": 1}\n'))
    assert parsed.doc == {"a": 1} and parsed.problems == ()


@pytest.mark.parametrize(
    "run, problem",
    [
        (Run(stdout=""), "no_document"),
        (Run(stdout='{"a": 1}\n{"b": 2}'), "multiple_documents"),
        (Run(stdout='{"a": 1} trailing'), "non_json_output"),
        (Run(stdout="banner\n{}"), "non_json_output"),
        (Run(stdout="[1]"), "not_an_object"),
        (Run(stdout="{}", stderr=TRACEBACK), "traceback"),
        (Run(state="TIMEOUT", rc=None, stdout="{}"), "timeout"),
        (Run(state="SIGNALED", rc=None, stdout="{}"), "signaled"),
    ],
)
def test_parse_problems(run, problem):
    assert problem in ps.parse_run(run).problems


def test_a_traceback_on_stderr_leaves_the_document_readable():
    parsed = ps.parse_run(Run(stdout='{"a": 1}', stderr=TRACEBACK))
    assert parsed.doc == {"a": 1} and "traceback" in parsed.problems


def test_a_killed_run_never_yields_a_document():
    assert ps.parse_run(Run(state="TIMEOUT", rc=None, stdout="{}")).doc is None


# --- envelopes ---------------------------------------------------------------


@pytest.mark.parametrize(
    "command, doc, kind",
    [
        ("offset", {"success": True, "error": None}, "success"),
        ("offset", {"success": True, "error": "", "error_code": ""}, "success"),
        ("offset", {"success": True, "error_code": "x"}, None),
        ("offset", {"success": False, "error_code": "no_crash"}, "failure"),
        ("offset", {"success": False, "error": "boom"}, None),
        ("decompile", {"code": "int f(){}"}, "success"),
        ("decompile", {"code": "int f(){}", "error": "boom"}, None),
        ("decompile", {"code": "  "}, None),
        ("decompile", {"error": "Decompilation failed"}, "failure"),
        ("pwn", {"recommended": None, "strategies": []}, "success"),
        ("pwn", {"strategies": []}, None),
        ("pwn", {"error": "no such file"}, "failure"),
        ("template", {"technique": "srop"}, "success"),
        ("template", {"error": "bad"}, "failure"),
    ],
)
def test_envelope_kind(command, doc, kind):
    assert ps.envelope_kind(command, doc) == kind


@pytest.mark.parametrize(
    "command, doc, decline",
    [
        ("offset", {"success": False}, True),
        ("offset", {"success": True}, False),
        ("offset", {"offset": 8}, False),
        ("decompile", {"error": "x"}, True),
        ("decompile", {"error": "x", "code": "int f(){}"}, False),
        ("pwn", {"error": "x"}, True),
        ("pwn", {"error": ""}, False),
        ("template", {"error": "x"}, True),
    ],
)
def test_is_decline_reads_content_only(command, doc, decline):
    assert ps.is_decline(command, doc) is decline


# --- METHOD-R0 and TEMPLATE --------------------------------------------------


@pytest.mark.parametrize(
    "doc, accept, verdict",
    [
        (pwn_doc("ROP_SYSTEM"), ["ret2libc"], PASS),
        (pwn_doc("ROP_EXECVE"), ["ret2libc"], FAIL),
        (pwn_doc("RET2PLT"), ["ret2libc"], PASS),
        (pwn_doc("NEGATIVE_SIZE_BYPASS"), ["ret2libc"], FAIL),
        (pwn_doc("SECCOMP_BYPASS"), ["ret2libc"], FAIL),
        (pwn_doc("FOO_BAR"), ["ret2libc"], FAIL),
        ({"recommended": None, "strategies": []}, ["ret2libc"], FAIL),
        ({"strategies": []}, ["ret2libc"], FAIL),
        ({"error": "declined"}, ["ret2libc"], ABSTAIN),
    ],
)
def test_method_r0(doc, accept, verdict):
    assert ps.score_method_r0(parsed_of(doc), accept).verdict == verdict


def test_method_r0_error_without_a_document():
    cell = ps.score_method_r0(ps.parse_run(Run(stdout="")), ["srop"])
    assert cell.verdict == ERROR and cell.reason == "no_document"


def test_method_r0_unmapped_warns_once_and_vuln_axis_is_reported():
    unmapped = ps.score_method_r0(parsed_of(pwn_doc("FOO_BAR")), ["srop"])
    assert unmapped.warnings == ("unmapped:FOO_BAR",)
    vuln = ps.score_method_r0(parsed_of(pwn_doc("NEGATIVE_SIZE_BYPASS")), ["srop"])
    assert vuln.info == {"vuln": "integer"} and vuln.warnings == ()


@pytest.mark.parametrize(
    "doc, verdict",
    [
        ({"technique": "ret2system"}, PASS),
        ({"technique": "srop"}, FAIL),
        ({"technique": "leak"}, FAIL),
        ({"technique": "zzz"}, FAIL),
        ({"output": "x"}, FAIL),
        ({"error": "declined"}, ABSTAIN),
    ],
)
def test_template(doc, verdict):
    assert ps.score_template(parsed_of(doc), ["ret2libc"]).verdict == verdict


# --- METHOD-L, precision, spam ----------------------------------------------


def listing(*entries):
    """entries are (approach, confidence, priority); list order is argument order."""
    return {
        "recommended": None,
        "strategies": [
            {"approach": a, "confidence": c, "priority": p} for a, c, p in entries
        ],
    }


def test_method_l_orders_by_confidence_then_priority_then_position():
    doc = listing(
        ("RET2WIN", 0.1, 1),
        ("ROP_EXECVE", 0.9, 5),
        ("SROP", 0.9, 2),
        ("ROP_SYSTEM", 0.5, 1),
    )
    assert ps.ranked_names(doc) == ["SROP", "ROP_EXECVE", "ROP_SYSTEM", "RET2WIN"]
    tied = listing(("SROP", 0.5, 1), ("RET2WIN", 0.5, 1))
    assert ps.ranked_names(tied) == ["SROP", "RET2WIN"]


def test_method_l_takes_the_top_three_only():
    doc = listing(
        ("RET2WIN", 0.9, 1),
        ("ROP_SYSTEM", 0.8, 2),
        ("SHELLCODE", 0.7, 3),
        ("SROP", 0.1, 4),
    )
    assert ps.score_method_l(parsed_of(doc), ["shellcode"]).verdict == PASS
    assert ps.score_method_l(parsed_of(doc), ["srop"]).verdict == FAIL


@pytest.mark.parametrize(
    "doc, verdict",
    [
        ({"recommended": None, "strategies": []}, FAIL),
        ({"recommended": None}, FAIL),
        ({"error": "declined"}, ABSTAIN),
    ],
)
def test_method_l_empty_and_decline(doc, verdict):
    assert ps.score_method_l(parsed_of(doc), ["srop"]).verdict == verdict


def test_method_l_warns_for_each_distinct_unmapped_name():
    doc = listing(("FOO", 0.9, 1), ("FOO", 0.8, 2), ("BAR", 0.7, 3), ("SROP", 0.6, 4))
    cell = ps.score_method_l(parsed_of(doc), ["srop"])
    assert cell.warnings == ("unmapped:FOO", "unmapped:BAR")
    assert cell.verdict == FAIL


def test_precision_dedupes_families_after_mapping():
    doc = listing(("ROP_SYSTEM", 0.9, 1), ("RET2PLT", 0.8, 2), ("SROP", 0.7, 3))
    parsed = parsed_of(doc)
    assert ps.method_spam(parsed) == 2
    assert ps.method_l_precision(parsed, ["ret2libc"]) == 0.5


def test_precision_and_spam_are_undefined_without_a_list():
    assert ps.method_l_precision(parsed_of({"error": "x"}), ["srop"]) is None
    assert ps.method_spam(parsed_of({"error": "x"})) is None
    assert ps.method_l_precision(parsed_of(listing()), ["srop"]) is None
    assert ps.method_spam(parsed_of(listing())) == 0


# --- OFF ---------------------------------------------------------------------


def entry(kind="buf_to_ret", state="known_value", value=40):
    return {"kind": kind, "state": state, "value": value}


def offset_doc(**fields):
    return {"success": True, "error": None, **fields}


@pytest.mark.parametrize(
    "doc, ent, verdict",
    [
        (offset_doc(offset=40), entry(), PASS),
        (offset_doc(offset=41), entry(), FAIL),
        (offset_doc(offset=40, kind="buf_to_ret"), entry(), PASS),
        (offset_doc(offset=40, kind="saved_rip_unproven"), entry(), ABSTAIN),
        (offset_doc(offset=None), entry(), ABSTAIN),
        (offset_doc(offset="40"), entry(), FAIL),
        (offset_doc(offset=True), entry(value=1), FAIL),
        ({"offset": 40}, entry(), ABSTAIN),
        ({"success": False, "offset": 40, "error": "x"}, entry(), ABSTAIN),
        (offset_doc(canary_offset=4104), entry("buf_to_canary", value=4104), PASS),
        (offset_doc(canary_offset=8), entry("buf_to_canary", value=4104), FAIL),
        (offset_doc(canary_offset=None), entry("buf_to_canary", value=4104), ABSTAIN),
        ({"canary_offset": 4104}, entry("buf_to_canary", value=4104), PASS),
        (offset_doc(offset=4), entry("buf_to_var", value=4), ABSTAIN),
    ],
)
def test_off_known_value(doc, ent, verdict):
    assert ps.score_off(parsed_of(doc), ent).verdict == verdict


def test_off_error_without_a_document():
    assert ps.score_off(ps.parse_run(Run(stdout="")), entry()).verdict == ERROR


def test_off_void_is_decided_before_the_output_is_read():
    unreadable = ps.parse_run(Run(stdout=""))
    cell = ps.score_off(unreadable, entry(state="unknown", value=None))
    assert (cell.verdict, cell.reason) == (VOID, "no-truth")
    cell = ps.score_off(
        unreadable, entry(state="unknown", value=None), "interp_missing"
    )
    assert (cell.verdict, cell.reason) == (VOID, "interp_missing")
    cell = ps.score_off(unreadable, entry(), "interp_missing")
    assert (cell.verdict, cell.reason) == (VOID, "interp_missing")


@pytest.mark.parametrize("state", ["not_applicable", "known_absent"])
def test_off_states_that_are_not_cells(state):
    assert ps.score_off(parsed_of({}), entry(state=state, value=None)) is None


def test_off_unknown_state_is_refused():
    with pytest.raises(ValueError):
        ps.score_off(parsed_of({}), entry(state="maybe"))


def test_off_unscored_number_counts_only_kinds_without_a_field():
    doc = parsed_of(offset_doc(offset=72))
    assert ps.off_unscored_number(doc, "chunk_to_next_size") == 1
    assert ps.off_unscored_number(doc, "buf_to_ret") == 0
    assert ps.off_unscored_number(parsed_of(offset_doc(offset=None)), "buf_to_var") == 0
    assert ps.off_unscored_number(parsed_of({"success": False}), "buf_to_var") == 0
    assert ps.off_unscored_number(ps.parse_run(Run(stdout="")), "buf_to_var") == 0


# --- DECOMP ------------------------------------------------------------------

DECOMP_TRUTH = {
    "default_function_any_of": [0x401000, 0x401100],
    "anchors": {"calls": ["read", "puts"], "min_calls": 2},
}


def decomp_doc(code=None, address="0x401000", **extra):
    code = "void f(void) {\n  read(0, b, 8);\n  puts(b);\n}" if code is None else code
    return {"function": "f", "address": address, "code": code, **extra}


@pytest.mark.parametrize(
    "doc, verdict, reason",
    [
        (decomp_doc(), PASS, ""),
        (decomp_doc(address="0x401100"), PASS, ""),
        (decomp_doc(address=0x401000), PASS, ""),
        (decomp_doc(address="0x401004"), FAIL, "address"),
        (decomp_doc(address=None), FAIL, "address"),
        (decomp_doc(address="main"), FAIL, "address"),
        (
            decomp_doc(code="// Decompilation failed for main"),
            FAIL,
            "empty_or_sentinel",
        ),
        (decomp_doc(code="void f(void) {\n}"), FAIL, "anchors_missing:read,puts"),
        (decomp_doc(code="// read(0,b,8); puts(b);"), FAIL, "empty_or_sentinel"),
        (decomp_doc(code="read(0, b, 8);"), FAIL, "anchors_missing:puts"),
        (decomp_doc(code="fread(a); puts(b);"), FAIL, "anchors_missing:read"),
        (
            decomp_doc(code="/* puts(b); */ read(0, b, 8);"),
            FAIL,
            "anchors_missing:puts",
        ),
        (decomp_doc(code='read (0);\nputs("a//b");'), PASS, ""),
        ({"error": "Decompilation failed"}, ABSTAIN, "decline"),
    ],
)
def test_decomp(doc, verdict, reason):
    cell = ps.score_decomp(parsed_of(doc), DECOMP_TRUTH)
    assert cell.verdict == verdict
    if reason:
        assert reason in cell.reason


def test_decomp_min_calls_guards_an_empty_anchor_list():
    truth = {"default_function_any_of": [1], "anchors": {"calls": [], "min_calls": 1}}
    cell = ps.score_decomp(parsed_of(decomp_doc(address="0x1")), truth)
    assert cell.verdict == FAIL and "min_calls" in cell.reason


def test_decomp_selected_by_is_reported_and_required_on_request():
    doc = decomp_doc(selected_by="symbol")
    assert ps.score_decomp(parsed_of(doc), DECOMP_TRUTH).info["selected_by"] == "symbol"
    assert ps.score_decomp(parsed_of(decomp_doc()), DECOMP_TRUTH).verdict == PASS
    required = ps.score_decomp(parsed_of(decomp_doc()), DECOMP_TRUTH, True)
    assert required.verdict == FAIL and "selected_by" in required.reason


def test_decomp_error_without_a_document():
    assert ps.score_decomp(ps.parse_run(Run()), DECOMP_TRUTH).verdict == ERROR


def test_strip_comments_keeps_literals():
    code = 'a(); // c\nb("//x"); /* d */ c(\'"\'); /* open'
    assert ps.strip_comments(code) == 'a();  \nb("//x");   c(\'"\');  '


# --- ROBUST and TIME ---------------------------------------------------------

GOOD = {
    "pwn": {"recommended": None, "strategies": []},
    "template": {"technique": "srop"},
    "decompile": {"code": "int f(){}"},
    "offset": {"success": True, "error": None},
}
DECLINE = {
    "pwn": {"error": "no"},
    "template": {"error": "no"},
    "decompile": {"error": "no"},
    "offset": {"success": False, "error": "no", "error_code": "declined"},
}


@pytest.mark.parametrize("command", ps.COMMANDS)
def test_robust_accepts_the_two_legal_pairs(command):
    for doc, rc in ((GOOD[command], 0), (DECLINE[command], 2)):
        run = run_of(doc, rc)
        assert ps.score_robust(command, run, ps.parse_run(run)).verdict == PASS


@pytest.mark.parametrize("command", ps.COMMANDS)
@pytest.mark.parametrize("which, rc", [("good", 2), ("decline", 0), ("good", 127)])
def test_robust_rejects_an_envelope_with_the_wrong_exit_code(command, which, rc):
    doc = (GOOD if which == "good" else DECLINE)[command]
    run = run_of(doc, rc)
    assert ps.score_robust(command, run, ps.parse_run(run)).verdict == FAIL


@pytest.mark.parametrize(
    "run",
    [
        Run(stdout="", rc=0),
        Run(stdout='{"a":1}{"b":2}', rc=0),
        Run(stdout=json.dumps(GOOD["pwn"]), stderr=TRACEBACK, rc=0),
        Run(stdout=json.dumps(GOOD["pwn"]), survivors=1),
        Run(state="TIMEOUT", rc=None),
        Run(state="SPAWN_ERROR", rc=None),
        run_of({"error_code": "x"}, 0),
    ],
)
def test_robust_fails_anything_else(run):
    cell = ps.score_robust("pwn", run, ps.parse_run(run))
    assert cell.verdict == FAIL and cell.reason and cell.command == "pwn"


def test_time_sample_validity():
    quiet = Run(wall_s=1.5, load1=2.0)
    assert ps.time_sample(quiet, 4.0) == {"wall_s": 1.5, "load1": 2.0, "valid": True}
    assert ps.time_sample(Run(load1=4.0), 4.0)["valid"] is False
    assert ps.time_sample(Run(state="TIMEOUT", load1=0.1), 4.0)["valid"] is False
    assert ps.time_sample(Run(load1=None), 4.0)["valid"] is False


def test_time_quorum_cannot_be_met_with_fewer_samples_than_the_quorum():
    one_rep = {c: [{"valid": True}] for c in ps.COMMANDS}
    assert ps.time_quorum_met(one_rep, 1) is True
    assert ps.time_quorum_met(one_rep, 2) is False
    assert ps.time_quorum_met({**one_rep, "pwn": [{"valid": False}]}, 1) is False
    assert ps.time_quorum_met({}, 1) is False


# --- aggregation -------------------------------------------------------------


def cells(*verdicts):
    return [
        ps.Cell("OFF", v, target=f"t{i}", reason="why") for i, v in enumerate(verdicts)
    ]


def test_summary_counts_every_cell():
    s = ps.summarize(cells(PASS, PASS, FAIL, ERROR, ABSTAIN, VOID))
    assert s["n"] == 6
    assert s["coverage"] == pytest.approx(3 / 6)
    assert s["exact"] == pytest.approx(2 / 6)
    assert s["selective"] == pytest.approx(2 / 3)
    assert s["net"] == pytest.approx((2 - 1 - 1) / 6)
    assert s["voids"] == [{"target": "t5", "kind": None, "reason": "why"}]


def test_summary_selective_is_none_when_nothing_was_decided():
    s = ps.summarize(cells(ABSTAIN, VOID))
    assert s["coverage"] == 0 and s["exact"] == 0 and s["selective"] is None
    assert ps.summarize([])["coverage"] is None


# --- the S0 fixture and the 3.7 mutant pins ----------------------------------

TARGETS = [
    ("sick_rop", ["srop"], [("buf_to_ret", 40)]),
    ("rocket_blaster_xxx", ["ret2win", "ret2libc"], [("buf_to_ret", 40)]),
    ("snow_scan", ["srop", "rop_syscall"], [("indexed_base_ptr", None)]),
    (
        "ancient_interface",
        ["rop_syscall", "ret2libc"],
        [("buf_to_ret", 4120), ("buf_to_canary", 4104)],
    ),
    ("auth-or-out", ["objptr_hijack"], [("record_to_fnptr", None)]),
    ("sabotage", ["env_hijack"], [("buf_to_var", None)]),
    ("bon-nie-appetit", ["heap_metadata"], [("chunk_to_next_size", None)]),
]
SLUGS = [t[0] for t in TARGETS]
FAMILIES = [
    "ret2win", "ret2libc", "rop_syscall", "srop", "ret2dlresolve", "shellcode",
    "stack_pivot", "one_gadget", "fmt_write", "got_overwrite", "objptr_hijack",
    "heap_metadata", "fsop", "data_only", "env_hijack",
]  # fmt: skip


def s0_truth(index):
    slug, accept, distance = TARGETS[index]
    return {
        "slug": slug,
        "method_accept": accept,
        "distance": [
            {"kind": k, "state": "known_value" if v else "unknown", "value": v}
            for k, v in distance
        ],
        "decompile": {
            "default_function_any_of": [0x401000 + 0x100 * index],
            "anchors": {"calls": ["read"], "min_calls": 1},
        },
    }


TRUTHS = [s0_truth(i) for i in range(len(TARGETS))]


def truth_echo(truth, command):
    first = truth["method_accept"][0]
    values = {d["kind"]: d["value"] for d in truth["distance"]}
    if command == "pwn":
        return run_of(pwn_doc(first))
    if command == "template":
        return run_of({"technique": first, "output": "x.py", "script_length": 1})
    if command == "decompile":
        address = hex(truth["decompile"]["default_function_any_of"][0])
        return run_of(decomp_doc(address=address))
    return run_of(
        offset_doc(
            offset=values.get("buf_to_ret"), canary_offset=values.get("buf_to_canary")
        )
    )


def const(truth, command):
    if command == "pwn":
        return run_of(pwn_doc("ROP_SYSTEM"))
    if command == "template":
        return run_of({"technique": "ret2system", "output": "x.py", "script_length": 1})
    if command == "offset":
        return run_of(offset_doc(offset=0, canary_offset=None))
    return run_of(decomp_doc(address="0x1"))


def list_all(truth, command):
    if command == "pwn":
        return run_of(pwn_doc(*FAMILIES))
    return const(truth, command)


def list_none(truth, command):
    if command == "pwn":
        return run_of({"recommended": None, "strategies": []})
    return const(truth, command)


def abstain_all(truth, command):
    return run_of(DECLINE[command], 2)


def with_pwn(approach):
    def mutant(truth, command):
        if command == "pwn":
            return run_of(pwn_doc(approach))
        return truth_echo(truth, command)

    return mutant


def with_decompile(code=None, address=None):
    def mutant(truth, command):
        if command != "decompile":
            return truth_echo(truth, command)
        true_address = hex(truth["decompile"]["default_function_any_of"][0])
        return run_of(decomp_doc(code=code, address=address or true_address))

    return mutant


def emit(stdout="", stderr="", rc=0, **extra):
    def mutant(truth, command):
        return Run(rc=rc, stdout=stdout, stderr=stderr, **extra)

    return mutant


def score_all(mutant, **options):
    return [
        ps.score_target(t, {c: mutant(t, c) for c in ps.COMMANDS}, **options)
        for t in TRUTHS
    ]


def verdicts(scores, metric, kind=None):
    return {
        s.target: c.verdict
        for s in scores
        for c in s.cells
        if c.metric == metric and (kind is None or c.kind == kind)
    }


def split(**by_verdict):
    """Build a {slug: verdict} dict from verdict=[slugs] arguments."""
    return {slug: v for v, slugs in by_verdict.items() for slug in slugs}


def test_s0_cell_counts():
    scores = score_all(truth_echo)
    report = ps.aggregate(scores)["metrics"]
    assert report["ROBUST"]["n"] == 28
    assert report["OFF"]["n"] == 8
    assert report["OFF"]["counts"][VOID] == 4
    for metric in ("METHOD-R0", "METHOD-L", "TEMPLATE", "DECOMP"):
        assert report[metric]["n"] == 7


def test_pin_const():
    scores = score_all(const)
    wins = ["rocket_blaster_xxx", "ancient_interface"]
    others = [s for s in SLUGS if s not in wins]
    expected = split(PASS=wins, FAIL=others)
    assert verdicts(scores, "METHOD-R0") == expected
    assert verdicts(scores, "TEMPLATE") == expected
    ret = verdicts(scores, "OFF", "buf_to_ret")
    assert [
        ret[s] for s in ("sick_rop", "rocket_blaster_xxx", "ancient_interface")
    ] == [FAIL] * 3
    assert verdicts(scores, "OFF", "buf_to_canary") == {"ancient_interface": ABSTAIN}
    off = ps.aggregate(scores)["metrics"]["OFF"]
    assert off["counts"][VOID] == 4
    assert {v["reason"] for v in off["voids"]} == {"no-truth"}


def test_pin_truth_echo():
    scores = score_all(truth_echo)
    for metric in ("METHOD-R0", "METHOD-L", "TEMPLATE", "DECOMP"):
        assert set(verdicts(scores, metric).values()) == {PASS}, metric
    off = [c for s in scores for c in s.cells if c.metric == "OFF"]
    assert sorted(c.verdict for c in off) == [PASS] * 4 + [VOID] * 4
    assert {c.reason for c in off if c.verdict == VOID} == {"no-truth"}
    robust = [c for s in scores for c in s.cells if c.metric == "ROBUST"]
    assert len(robust) == 28 and {c.verdict for c in robust} == {PASS}


def test_pin_list_all():
    scores = score_all(list_all)
    assert verdicts(scores, "METHOD-L") == split(
        PASS=["rocket_blaster_xxx", "snow_scan", "ancient_interface"],
        FAIL=["sick_rop", "auth-or-out", "sabotage", "bon-nie-appetit"],
    )
    one_in_15 = ["sick_rop", "auth-or-out", "sabotage", "bon-nie-appetit"]
    for s in scores:
        expected = 1 / 15 if s.target in one_in_15 else 2 / 15
        assert s.precision == pytest.approx(expected)
        assert s.spam == 15
    report = ps.aggregate(scores)
    assert report["method_l_precision"]["macro_mean"] == pytest.approx(2 / 21)
    assert report["method_spam"] == dict.fromkeys(SLUGS, 15)


def test_pin_list_none():
    scores = score_all(list_none)
    assert set(verdicts(scores, "METHOD-L").values()) == {FAIL}
    assert len(verdicts(scores, "METHOD-L")) == 7


def test_pin_abstain_all():
    report = ps.aggregate(score_all(abstain_all))["metrics"]
    for metric in ("METHOD-R0", "METHOD-L", "TEMPLATE", "DECOMP"):
        assert report[metric]["counts"][ABSTAIN] == 7, metric
    assert report["OFF"]["counts"][ABSTAIN] == 4 and report["OFF"]["counts"][VOID] == 4
    for metric in ("METHOD-R0", "METHOD-L", "TEMPLATE", "OFF", "DECOMP"):
        assert report[metric]["coverage"] == 0 and report[metric]["exact"] == 0
        assert report[metric]["selective"] is None
    assert report["ROBUST"]["counts"][PASS] == 28


def test_pin_unmapped():
    scores = score_all(with_pwn("FOO_BAR"))
    assert set(verdicts(scores, "METHOD-R0").values()) == {FAIL}
    for s in scores:
        r0 = [c for c in s.cells if c.metric == "METHOD-R0"][0]
        assert r0.warnings == ("unmapped:FOO_BAR",)


def test_pin_vuln_axis():
    scores = score_all(with_pwn("NEGATIVE_SIZE_BYPASS"))
    assert set(verdicts(scores, "METHOD-R0").values()) == {FAIL}
    assert ps.aggregate(scores)["vuln_column"] == dict.fromkeys(SLUGS, "integer")


@pytest.mark.parametrize(
    "mutant",
    [
        with_decompile(code="// Decompilation failed for main"),
        with_decompile(code="void main(void) {\n}"),
        with_decompile(code="void main(void) {\n  // read(0, b, 8);\n}"),
        with_decompile(address="0x1"),
    ],
    ids=["sentinel", "empty_body", "anchor_in_comment", "wrong_addr"],
)
def test_pin_decomp_mutants(mutant):
    scores = score_all(mutant)
    assert set(verdicts(scores, "DECOMP").values()) == {FAIL}
    assert len(verdicts(scores, "DECOMP")) == 7


def test_sentinel_is_thirty_two_characters():
    assert len("// Decompilation failed for main") == 32


@pytest.mark.parametrize(
    "mutant",
    [
        emit(stderr=TRACEBACK, rc=1),
        emit(stdout='{"a": 1}\n{"b": 2}'),
        emit(state="TIMEOUT", rc=None),
    ],
    ids=["traceback", "two_docs", "hang"],
)
def test_pin_unreadable_output(mutant):
    scores = score_all(mutant)
    report = ps.aggregate(scores)["metrics"]
    assert report["ROBUST"]["counts"][FAIL] == 28
    for metric in ("METHOD-R0", "METHOD-L", "TEMPLATE", "DECOMP"):
        assert report[metric]["counts"][ERROR] == 7, metric
    # VOID is decided before the output is read, so the 4 truthless cells stay VOID.
    assert report["OFF"]["counts"][ERROR] == 4
    assert report["OFF"]["counts"][VOID] == 4
    assert {v["reason"] for v in report["OFF"]["voids"]} == {"no-truth"}


def test_pin_two_docs_is_not_decided_by_the_first_document():
    scores = score_all(emit(stdout=json.dumps(GOOD["pwn"]) * 2))
    assert ps.aggregate(scores)["metrics"]["METHOD-R0"]["counts"][ERROR] == 7


def test_pin_rc0_error_is_a_robust_fail_and_a_semantic_abstain():
    def rc0_error(truth, command):
        return run_of(DECLINE[command], 0)

    report = ps.aggregate(score_all(rc0_error))["metrics"]
    assert report["ROBUST"]["counts"][FAIL] == 28
    for metric in ("METHOD-R0", "METHOD-L", "TEMPLATE", "DECOMP"):
        assert report[metric]["counts"][ABSTAIN] == 7, metric


@pytest.mark.parametrize("rc, which", [(2, GOOD), (127, DECLINE), (127, GOOD)])
def test_pin_wrong_exit_code_is_a_robust_fail(rc, which):
    def mutant(truth, command):
        return run_of(which[command], rc)

    assert ps.aggregate(score_all(mutant))["metrics"]["ROBUST"]["counts"][FAIL] == 28


def test_pin_a_survivor_is_a_robust_fail():
    scores = score_all(
        lambda t, c: ps.Run(**{**truth_echo(t, c).__dict__, "survivors": 1})
    )
    assert ps.aggregate(scores)["metrics"]["ROBUST"]["counts"][FAIL] == 28


def test_pin_preflight_failure_voids_off_and_nothing_else():
    scores = score_all(truth_echo, preflight_void="interp_missing")
    report = ps.aggregate(scores)["metrics"]
    assert report["OFF"]["counts"][VOID] == 8
    assert {v["reason"] for v in report["OFF"]["voids"]} == {"interp_missing"}
    for metric in ("METHOD-R0", "METHOD-L", "TEMPLATE", "DECOMP", "ROBUST"):
        assert report[metric]["counts"][PASS] == report[metric]["n"], metric


def test_off_unscored_numbers_are_reported_not_scored():
    scores = score_all(const)
    assert ps.aggregate(scores)["off_unscored_numbers"] == 4


def parses_as_json(run):
    """The naive scorer of D5-F1: a document that parses is a pass."""
    try:
        return isinstance(json.loads(run.stdout), dict)
    except ValueError:
        return False


def test_pin_a_parses_as_json_scorer_cannot_tell_const_from_truth_echo():
    for truth in TRUTHS:
        for command in ps.COMMANDS:
            naive_const = parses_as_json(const(truth, command))
            naive_echo = parses_as_json(truth_echo(truth, command))
            assert naive_const is naive_echo is True
    const_report = ps.aggregate(score_all(const))["metrics"]
    echo_report = ps.aggregate(score_all(truth_echo))["metrics"]
    for metric in ("METHOD-R0", "TEMPLATE", "DECOMP", "OFF"):
        assert const_report[metric]["exact"] != echo_report[metric]["exact"], metric


def test_aggregate_lists_warnings_with_their_cell():
    report = ps.aggregate(score_all(with_pwn("FOO_BAR")))
    assert "sick_rop/METHOD-R0: unmapped:FOO_BAR" in report["warnings"]
