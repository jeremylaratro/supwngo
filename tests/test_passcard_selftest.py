"""Mutant self-test for the passcard (SP-01 plan 3.7; 8.1 V-1, V-2).

Every shim in benchmark/mutants plants one behaviour. Each is run end to end
through benchmark/passcard.py, as a subprocess, on the seven S0 cells under
``bwrap``, and the verdict of every (target, metric[, kind]) is pinned below.
The point is that the scorer, the sandbox and the harness together cannot be
fooled: a constant answer scores as one, the right answer scores as one, a
leaked answer key is unreachable.

The S0 binaries are gitignored and read-only here: tests skip when absent (set
``PASSCARD_TARGETS_ROOT``), and the one test that plants files plants them in a
copy under /var/tmp, never in the real tree.
"""

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from passcard_support import (  # noqa: E402
    MUTANTS,
    S0_SLUGS,
    TARGETS_ROOT,
    build_mirror,
    cli_arg,
    gcc,
    mini_truth,
    needs_bwrap,
    needs_gcc,
    needs_targets,
    run_runner,
    truth_bundle,
)

pytestmark = [needs_targets, needs_bwrap]

PASS, FAIL, ABSTAIN, ERROR, VOID = "PASS", "FAIL", "ABSTAIN", "ERROR", "VOID"
SEMANTIC = ("METHOD-R0", "METHOD-L", "TEMPLATE", "DECOMP")
COMMANDS = ("pwn", "template", "decompile", "offset")

# The 8 OFF cells (plan 3.7): 4 known_value, 4 VOID with their pinned reasons.
OFF_KNOWN = [
    ("sick_rop", "buf_to_ret"),
    ("rocket_blaster_xxx", "buf_to_ret"),
    ("ancient_interface", "buf_to_ret"),
    ("ancient_interface", "buf_to_canary"),
]
OFF_VOID = {
    ("snow_scan", "indexed_base_ptr"): "no-truth",
    ("auth-or-out", "record_to_fnptr"): "no-truth",
    ("sabotage", "buf_to_var"): "interp_empty",
    ("bon-nie-appetit", "chunk_to_next_size"): "interp_empty",
}
RET2LIBC_ACCEPTED = {"rocket_blaster_xxx", "ancient_interface"}


# --- running a mutant ---


class Runs:
    """Runs each distinct (mutant, options) once and caches its report."""

    def __init__(self, out_dir: Path):
        self.out_dir = out_dir
        self.cache = {}

    def run(self, mutant, *, truth=False, keys=None, args=(), rc=0):
        key = (mutant, truth, tuple(keys or ()), tuple(str(a) for a in args), rc)
        if key in self.cache:
            return self.cache[key]
        argv = [sys.executable, str(MUTANTS / ("%s.py" % mutant))]
        if truth:
            argv += ["--truth-json", json.dumps(truth_bundle())]
        if keys:
            argv += ["--keys-json", json.dumps(list(keys))]
        out = self.out_dir / ("%s-%d" % (mutant, len(self.cache)))
        base = [
            "--no-control", "--skip-s0pe",
            "--targets-root", TARGETS_ROOT,
            "--cli", json.dumps(argv),
            "--timeout", "60",
        ]  # fmt: skip
        done, report = run_runner([*base, *args], out)
        assert done.returncode == rc, "%s exit %s\n%s\n%s" % (
            mutant, done.returncode, done.stdout[-2000:], done.stderr[-2000:]
        )  # fmt: skip
        self.cache[key] = report
        return report


@pytest.fixture(scope="module")
def runs(tmp_path_factory):
    return Runs(tmp_path_factory.mktemp("selftest"))


# --- reading a report ---


def cells(report, metric):
    return [
        (slug, c)
        for slug, entry in report["s0"]["detail"].items()
        for c in entry["cells"]
        if c["metric"] == metric
    ]


def single(report, metric):
    """``{slug: cell}`` for a metric with exactly one cell per target."""
    found = {slug: c for slug, c in cells(report, metric)}
    assert len(found) == len(S0_SLUGS) == len(cells(report, metric)), metric
    return found


def verdict_map(report, metric):
    return {slug: c["verdict"] for slug, c in single(report, metric).items()}


def uniform(verdict):
    return {slug: verdict for slug in S0_SLUGS}


def off_map(report):
    return {(slug, c["kind"]): c for slug, c in cells(report, "OFF")}


def robust_map(report):
    return {(slug, c["command"]): c for slug, c in cells(report, "ROBUST")}


def all_cell_verdicts(report):
    """``{(slug, metric, kind-or-command): verdict}`` for every cell of the matrix."""
    return {
        (slug, c["metric"], c["kind"] or c["command"]): c["verdict"]
        for metric in ("METHOD-R0", "METHOD-L", "TEMPLATE", "OFF", "DECOMP", "ROBUST")
        for slug, c in cells(report, metric)
    }


def assert_robust(report, verdict, reason_part=None):
    got = robust_map(report)
    assert len(got) == 28
    assert {c["verdict"] for c in got.values()} == {verdict}
    if reason_part:
        assert all(reason_part in c["reason"] for c in got.values()), {
            k: c["reason"] for k, c in got.items()
        }


def assert_off(report, known, void=None):
    """OFF: the four known cells all carry ``known`` (a verdict or a {cell: verdict} map)."""
    got = off_map(report)
    assert len(got) == 8
    for cell in OFF_KNOWN:
        want = known[cell] if isinstance(known, dict) else known
        assert got[cell]["verdict"] == want, (cell, got[cell])
    assert {k: c["reason"] for k, c in got.items() if c["verdict"] == VOID} == (void or OFF_VOID)
    assert sum(c["verdict"] == VOID for c in got.values()) == 4


def assert_semantic(report, verdict):
    """Every non-VOID semantic cell carries ``verdict``; the 4 VOID OFF cells stay VOID."""
    for metric in SEMANTIC:
        assert verdict_map(report, metric) == uniform(verdict), metric
    assert_off(report, verdict)


def assert_no_survivors(report):
    assert report["isolation_observed"] == ["bwrap"]
    assert all(rec["survivors"] == 0 for rec in report["runs"])


# --- the matrix itself ---


def test_the_s0_matrix_has_the_pinned_cell_counts(runs):
    report = runs.run("abstain_all")
    metrics = report["s0"]["summary"]["metrics"]
    assert metrics["ROBUST"]["n"] == 28
    assert metrics["OFF"]["n"] == 8
    assert [metrics[m]["n"] for m in ("METHOD-R0", "METHOD-L", "TEMPLATE", "DECOMP")] == [7] * 4
    assert report["s0"]["targets"] == S0_SLUGS and report["s0pe"]["targets"] == []
    assert len(report["runs"]) == 28 and report["isolation_observed"] == ["bwrap"]


def test_the_cell_layout_is_the_v1_layout(runs):
    report = runs.run("abstain_all")
    for rec in report["runs"]:
        slug, command, rep = rec["cell"].rsplit("-", 2)
        assert command in COMMANDS and rep == "r1" and slug in S0_SLUGS
        argv = rec["argv"]
        assert argv[argv.index(command) + 1].startswith("/tmp/cell/")
        assert not any(part.startswith(".") for part in argv[argv.index(command) + 1].split("/"))


# --- constant, echo and list answers ---


def test_const_scores_as_a_constant(runs):
    report = runs.run("const")
    split = {s: (PASS if s in RET2LIBC_ACCEPTED else FAIL) for s in S0_SLUGS}
    # Plan 3.7 pins METHOD-R0 and TEMPLATE; METHOD-L, a one-item list, follows the same split.
    for metric in ("METHOD-R0", "METHOD-L", "TEMPLATE"):
        assert verdict_map(report, metric) == split, metric
    assert_off(
        report,
        {
            ("sick_rop", "buf_to_ret"): FAIL,
            ("rocket_blaster_xxx", "buf_to_ret"): FAIL,
            ("ancient_interface", "buf_to_ret"): FAIL,
            ("ancient_interface", "buf_to_canary"): ABSTAIN,  # canary_offset null: no value given
        },
    )
    assert verdict_map(report, "DECOMP") == uniform(FAIL)
    assert_robust(report, PASS)


def test_truth_echo_passes_every_scored_cell(runs):
    report = runs.run("truth_echo", truth=True)
    for metric in SEMANTIC:
        assert verdict_map(report, metric) == uniform(PASS), metric
    assert_off(report, PASS)  # the 4 VOID cells keep their pinned reasons
    assert_robust(report, PASS)
    assert report["s0"]["summary"]["metrics"]["OFF"]["counts"][PASS] == 4


def test_list_all_ranks_the_top_three_and_reports_precision_and_spam(runs):
    report = runs.run("list_all")
    top3 = {s: (PASS if s in ("rocket_blaster_xxx", "snow_scan", "ancient_interface") else FAIL)
            for s in S0_SLUGS}  # fmt: skip
    assert verdict_map(report, "METHOD-L") == top3
    prec = report["s0"]["summary"]["method_l_precision"]
    want = {
        "sick_rop": 1, "rocket_blaster_xxx": 2, "snow_scan": 2, "ancient_interface": 2,
        "auth-or-out": 1, "sabotage": 1, "bon-nie-appetit": 1,
    }  # fmt: skip
    assert prec["per_target"] == pytest.approx({s: n / 15 for s, n in want.items()})
    assert prec["macro_mean"] == pytest.approx(10 / 105) == pytest.approx(2 / 21)
    assert (prec["n_defined"], prec["n_targets"]) == (7, 7)
    assert report["s0"]["summary"]["method_spam"] == {s: 15 for s in S0_SLUGS}


def test_list_none_is_an_empty_list_not_a_decline(runs):
    report = runs.run("list_none")
    assert verdict_map(report, "METHOD-L") == uniform(FAIL)
    assert verdict_map(report, "METHOD-R0") == uniform(FAIL)
    assert_robust(report, PASS)  # a well-formed success envelope


def test_abstain_all_never_passes_or_fails_a_semantic_metric(runs):
    report = runs.run("abstain_all")
    assert_semantic(report, ABSTAIN)
    assert_robust(report, PASS)
    for metric, entry in report["s0"]["summary"]["metrics"].items():
        if metric != "ROBUST":
            assert (entry["coverage"], entry["exact"], entry["net"]) == (0.0, 0.0, 0.0), metric
    assert_no_survivors(report)


# --- name vocabulary ---


def test_an_unmapped_name_fails_with_a_warning_not_a_skip(runs):
    report = runs.run("unmapped")
    got = single(report, "METHOD-R0")
    assert {s: c["verdict"] for s, c in got.items()} == uniform(FAIL)
    assert all("unmapped:FOO_BAR" in c["warnings"] for c in got.values())


def test_a_defect_name_fails_the_method_axis_and_shows_in_the_vuln_column(runs):
    report = runs.run("vuln_axis")
    got = single(report, "METHOD-R0")
    assert {s: c["verdict"] for s, c in got.items()} == uniform(FAIL)
    assert all(c["reason"] == "vuln_axis:integer" for c in got.values())
    assert report["s0"]["summary"]["vuln_column"] == {s: "integer" for s in S0_SLUGS}


# --- decompile ---


@pytest.mark.parametrize(
    "mutant, reason_part",
    [
        ("sentinel", None),
        ("empty_body", None),
        ("anchor_in_comment", "anchors_missing"),
        ("wrong_addr", "address"),
    ],
)
def test_a_bad_decompile_fails_decomp_and_only_decomp(runs, mutant, reason_part):
    report = runs.run(mutant, truth=True)
    got = single(report, "DECOMP")
    assert {s: c["verdict"] for s, c in got.items()} == uniform(FAIL)
    if reason_part:
        assert all(reason_part in c["reason"] for c in got.values())
    for metric in ("METHOD-R0", "METHOD-L", "TEMPLATE"):
        assert verdict_map(report, metric) == uniform(ABSTAIN), metric
    assert_off(report, ABSTAIN)
    assert_robust(report, PASS)


# --- output shape, exit codes, time ---


def test_a_traceback_is_a_robust_fail_and_a_semantic_error(runs):
    report = runs.run("traceback")
    assert_robust(report, FAIL, "traceback")
    assert_semantic(report, ERROR)  # the 4 truthless OFF cells stay VOID: decided before output


def test_two_documents_fail_robust_and_cannot_pass_anything(runs):
    report = runs.run("two_docs", truth=True)
    assert_robust(report, FAIL)
    assert_semantic(report, ERROR)


def test_a_failure_envelope_with_rc_0_is_a_robust_fail_but_a_semantic_decline(runs):
    report = runs.run("rc0_error")
    assert_robust(report, FAIL)
    assert_semantic(report, ABSTAIN)


def test_a_success_envelope_with_rc_2_is_a_robust_fail(runs):
    report = runs.run("rc2_success", truth=True)
    assert_robust(report, FAIL)
    assert not [1 for v in all_cell_verdicts(report).values() if v == ERROR]


def test_a_clean_decline_with_rc_127_is_a_robust_fail(runs):
    report = runs.run("rc127_clean")
    assert_robust(report, FAIL)
    assert_semantic(report, ABSTAIN)  # the content is a clean decline; only the pair is illegal


def test_a_hang_times_out_and_leaves_no_process(runs):
    report = runs.run("hang", args=["--timeout", "1.5"])
    assert_robust(report, FAIL, "timeout")
    assert_semantic(report, ERROR)
    assert {rec["state"] for rec in report["runs"]} == {"TIMEOUT"}
    assert_no_survivors(report)


def test_a_missed_time_quorum_exits_3_deterministically(runs):
    report = runs.run("abstain_all", args=["--reps", "1", "--require-time-quorum", "2"], rc=3)
    assert report["time_quorum_failed"] is True and report["accepted"] is False
    assert "time_quorum_failed" in report["not_accepted_reasons"]
    assert len(report["time"]["shortfalls"]) == 28
    assert all((s["valid"], s["needed"]) == (1, 2) for s in report["time"]["shortfalls"])


# --- survivors ---


def test_a_detached_grandchild_dies_with_the_pid_namespace_under_bwrap(runs):
    report = runs.run("grandchild")
    assert_robust(report, PASS)
    assert_no_survivors(report)


def test_the_subreaper_finds_kills_and_reaps_a_grandchild_without_bwrap(runs):
    report = runs.run("grandchild", args=["--only", "sick_rop", "--backend", "none"])
    assert report["isolation_observed"] == ["none"] and report["accepted"] is False
    got = robust_map(report)
    assert len(got) == 4
    assert {c["verdict"] for c in got.values()} == {FAIL}
    assert all("survivors:1" in c["reason"] for c in got.values())
    sleepers = [json.loads(rec["stdout"])["sleeper_pid"] for rec in report["runs"]]
    assert len(set(sleepers)) == 4
    for pid in sleepers:  # a 60 s sleeper: still here would mean the scan did not kill it
        assert not Path("/proc/%d" % pid).exists(), "sleeper %d survived the run" % pid
    assert all(rec["survivors"] == 1 for rec in report["runs"])
    # The report says what each survivor was: "pid:state:comm", the sleeper itself.
    for rec, pid in zip(report["runs"], sleepers):
        assert [info.split(":")[0] for info in rec["survivor_info"]] == [str(pid)], rec


# --- the answer keys ---


@pytest.fixture(scope="module")
def mirror():
    m = build_mirror()
    yield m
    shutil.rmtree(m.root, ignore_errors=True)


def mirror_args(mirror, *extra):
    return ["--targets-root", mirror.targets_root, "--extra-hide", mirror.gen_dir, *extra]


def test_every_answer_key_is_readable_outside_the_sandbox(mirror):
    # The positive control: a failure inside the sandbox below means something.
    keys = mirror.all_keys()
    assert len(keys) == 28
    for path in keys:
        assert Path(path).read_bytes(), path
    # Inside the sandbox /tmp is a tmpfs, so a key under it would be unreadable for the
    # wrong reason: the mirror must live elsewhere.
    assert not str(mirror.root).startswith("/tmp/")


def test_no_answer_key_opens_inside_the_sandbox_so_nothing_passes_from_a_leak(runs, mirror):
    keys = mirror.all_keys()
    report = runs.run("answer_key", truth=True, keys=keys, args=mirror_args(mirror))
    for rec in report["runs"]:
        opened = json.loads(rec["stdout"])["key_opens"]
        assert opened == {path: False for path in keys}, rec["cell"]
    # It scores exactly as abstain_all: no metric can PASS from a leaked key.
    assert all_cell_verdicts(report) == all_cell_verdicts(runs.run("abstain_all"))
    assert PASS not in {v for k, v in all_cell_verdicts(report).items() if k[1] != "ROBUST"}
    assert verdict_map(report, "METHOD-R0") == uniform(ABSTAIN)


def test_without_the_sandbox_the_same_mutant_reads_the_keys_and_would_pass(runs, mirror):
    # Non-vacuity: the keys are reachable on the host, and a leak would score as truth_echo.
    keys = mirror.keys["sick_rop"]
    report = runs.run(
        "answer_key", truth=True, keys=keys,
        args=mirror_args(mirror, "--only", "sick_rop", "--backend", "none"),
    )  # fmt: skip
    for rec in report["runs"]:
        assert json.loads(rec["stdout"])["key_opens"] == {path: True for path in keys}
    for metric in ("METHOD-R0", "DECOMP"):
        assert [(s, c["verdict"]) for s, c in cells(report, metric)] == [("sick_rop", PASS)]


# --- a cell that cannot run is VOID for OFF only ---


@needs_gcc
def test_a_missing_relative_interpreter_voids_only_the_execution_dependent_cells(tmp_path):
    root = Path(tempfile.mkdtemp(prefix="passcard-void-", dir="/var/tmp"))
    try:
        build, src = root / "build", root / "src" / "void_app"
        build.mkdir()
        src.mkdir(parents=True)
        (build / "app.c").write_text("int main(void) { return 0; }\n")
        gcc("-o", str(src / "void_app"), "app.c", "-Wl,--dynamic-linker=./nope/ld.so", cwd=build)
        (root / "organized").mkdir()
        (root / "organized" / "void_app").symlink_to("../src/void_app/void_app")
        (root / "truth" / "s0").mkdir(parents=True)
        (root / "truth" / "s0" / "void_app.yaml").write_text(yaml.safe_dump(mini_truth("void_app")))
        bundle = {
            "void_app": {
                "approach": "ret2win", "technique": "ret2win", "offset": 40,
                "canary_offset": None, "function": "f", "address": "0x401000", "calls": ["puts"],
            }
        }  # fmt: skip
        cli = cli_arg(MUTANTS / "truth_echo.py", "--truth-json", json.dumps(bundle))
        done, report = run_runner(
            ["--no-control", "--targets-root", root / "organized", "--truth-dir", root / "truth",
             "--cli", cli, "--timeout", "60"],
            tmp_path / "void",
        )  # fmt: skip
    finally:
        shutil.rmtree(root, ignore_errors=True)
    assert done.returncode == 0, done.stdout + done.stderr
    detail = report["s0"]["detail"]["void_app"]
    assert detail["preflight"]["code"] == "interp_missing"
    off = [c for c in detail["cells"] if c["metric"] == "OFF"]
    assert [(c["verdict"], c["reason"]) for c in off] == [(VOID, "interp_missing")]
    for metric in ("METHOD-R0", "METHOD-L", "TEMPLATE", "DECOMP"):
        assert [c["verdict"] for c in detail["cells"] if c["metric"] == metric] == [PASS], metric
    assert [c["verdict"] for c in detail["cells"] if c["metric"] == "ROBUST"] == [PASS] * 4


# --- the naive scorer (D5-F1) ---


def parses_as_json(text):
    try:
        json.loads(text)
    except ValueError:
        return False
    return True


def test_a_parses_as_json_scorer_cannot_tell_const_from_truth_echo_but_the_passcard_can(runs):
    const, echo = runs.run("const"), runs.run("truth_echo", truth=True)

    def naive(report):  # exit 0 and stdout is JSON: what the pre-SP-01 scorer checked
        return {r["cell"]: r["rc"] == 0 and parses_as_json(r["stdout"]) for r in report["runs"]}

    assert naive(const) == naive(echo) and all(naive(const).values())

    def passes(report):
        return sum(1 for v in all_cell_verdicts(report).values() if v == PASS)

    # 28 ROBUST passes each; the semantic passes are what separate them.
    assert passes(const) - 28 == 6  # METHOD-R0, METHOD-L, TEMPLATE on 2 targets each
    assert passes(echo) - 28 == 32  # 4 metrics x 7 targets + 4 OFF cells


# --- the real Ghidra control cell (opt-in) ---


def _have_ghidra():
    if not os.environ.get("SUPWNGO_GHIDRA_TESTS"):
        return False
    return bool(
        shutil.which("analyzeHeadless")
        or Path("/opt/ghidra/support/analyzeHeadless").exists()
        or Path("/usr/share/ghidra/support/analyzeHeadless").exists()
    )


@pytest.mark.skipif(
    not _have_ghidra(),
    reason="opt-in Ghidra test: set SUPWNGO_GHIDRA_TESTS=1 with analyzeHeadless installed",
)
def test_the_real_ghidra_control_cell_passes_under_bwrap(tmp_path):
    # The control runs the real product CLI (no --control-cli); the scored targets
    # use a decline shim so only the control costs a Ghidra run.
    done, report = run_runner(
        ["--only", "sick_rop", "--skip-s0pe", "--targets-root", TARGETS_ROOT,
         "--cli", cli_arg(MUTANTS / "abstain_all.py"), "--timeout", "900"],
        tmp_path / "ghidra",
        timeout=1800,
        # The question is whether Ghidra works under bwrap, not how fast: the product's
        # 180 s default budget times out on a loaded host and would fall back to angr.
        env_extra={"SUPWNGO_GHIDRA_TIMEOUT": "600"},
    )  # fmt: skip
    assert done.returncode == 0, done.stdout[-3000:] + done.stderr[-3000:]
    control = report["control"]
    assert control["ran"] and control["passed"], control
    assert control["cell"]["isolation"] == "bwrap"
    assert control["sha256"] == control["expect_sha256"]
    assert report["valid"] is True
