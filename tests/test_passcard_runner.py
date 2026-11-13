"""Tests for benchmark/passcard.py (SP-01 plan 3.3, 3.4, 3.6, 3.8; 8.1 V-1, V-2, V-15).

The pure parts (truth loading, the control check, option parsing) run anywhere.
The end-to-end tests run the runner as a subprocess against a synthetic one-target
world built under /var/tmp (a sandbox hides /tmp, so shims and fixtures cannot
live there) and need a working ``bwrap``. The mutant self-test, which scores
the real S0 cells, is tests/test_passcard_selftest.py.
"""

import hashlib
import json
import os
import shutil
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from passcard_support import (  # noqa: E402
    REPO_ROOT,
    TARGETS_ROOT,
    World,
    by_cell,
    cli_arg,
    make_world,
    mini_truth,
    needs_bwrap,
    needs_targets,
    run_runner,
    tiny_elf,
    verdicts,
)

sys.path.insert(0, str(REPO_ROOT / "benchmark"))

import passcard as pc  # noqa: E402
import passcard_score as ps  # noqa: E402
import passcard_stage as st  # noqa: E402

CONTROL_DIR = REPO_ROOT / "benchmark" / "fixtures" / "ghidra_control"
COMMANDS = ("pwn", "template", "decompile", "offset")


# --- shared fixtures -----------------------------------------------------------------


@pytest.fixture(scope="module")
def world():
    w = make_world()
    yield w
    shutil.rmtree(w.root, ignore_errors=True)


def common(w: World, *extra):
    return [
        "--targets-root",
        w.targets_root,
        "--truth-dir",
        w.truth_dir,
        "--timeout",
        "30",
        *extra,
    ]


@pytest.fixture(scope="module")
def baseline(world, tmp_path_factory):
    """One decline run with no control cell, shared by the read-only report tests."""
    out = tmp_path_factory.mktemp("runner") / "decline"
    args = common(world, "--no-control", "--cli", world.cli("decline.py"))
    done, report = run_runner(args, out)
    return done, report, out


# --- parse_cli, _out_paths ------------------------------------------------------------


def test_parse_cli_takes_a_json_list_or_a_quoted_line():
    assert pc.parse_cli('["python3", "x y.py"]') == ["python3", "x y.py"]
    assert pc.parse_cli("python3 'x y.py' --flag") == ["python3", "x y.py", "--flag"]


@pytest.mark.parametrize("bad", ["", "   ", "[]", "[1, 2]", '["a", 2]'])
def test_parse_cli_refuses_empty_and_non_string_lists(bad):
    with pytest.raises(ValueError):
        pc.parse_cli(bad)


def test_out_paths_normalise_the_suffix():
    assert pc._out_paths("/x/y") == (Path("/x/y.json"), Path("/x/y.md"))
    assert pc._out_paths("/x/y.json") == (Path("/x/y.json"), Path("/x/y.md"))
    assert pc._out_paths("/x/y.md") == (Path("/x/y.json"), Path("/x/y.md"))
    assert pc._out_paths("/x/y.v1") == (Path("/x/y.v1.json"), Path("/x/y.v1.md"))


# --- truth loading --------------------------------------------------------------------


def test_metric_tokens_select_metrics():
    assert pc._metric_set({"slug": "x"}) == pc.ALL_METRICS
    assert pc._metric_set({"slug": "x", "metrics": "all"}) == pc.ALL_METRICS
    assert pc._metric_set({"slug": "x", "metrics": ["decomp", "robust"]}) == {
        "DECOMP",
        "ROBUST",
    }
    assert pc._metric_set({"slug": "x", "metrics": ["method"]}) == {
        "METHOD-R0",
        "METHOD-L",
    }
    with pytest.raises(pc.TruthError, match="unknown metrics token"):
        pc._metric_set({"slug": "x", "metrics": ["bogus"]})


def test_check_truth_names_what_is_missing():
    with pytest.raises(pc.TruthError, match="is not a mapping"):
        pc._check_truth(["nope"], "f.yaml")
    with pytest.raises(pc.TruthError, match="lacks distance"):
        truth = mini_truth("t")
        del truth["distance"]
        pc._check_truth(truth, "f.yaml")
    with pytest.raises(pc.TruthError, match="stage.files is empty"):
        truth = mini_truth("t")
        truth["stage"]["files"] = []
        pc._check_truth(truth, "f.yaml")


def test_build_target_reads_a_pinned_binary_in_place(tmp_path):
    binary = tmp_path / "pe" / "thing"
    binary.parent.mkdir()
    binary.write_bytes(tiny_elf())
    sha = hashlib.sha256(tiny_elf()).hexdigest()
    spec = {"path": str(binary), "sha256": sha}
    target = pc.build_target(
        mini_truth("thing", binary=spec), "s0pe", tmp_path / "unused"
    )
    assert (target.slug, target.table, target.target) == ("thing", "s0pe", "thing")
    assert target.source_dir == binary.parent
    assert target.sha256 == sha and target.sha_ok
    assert target.metrics == {"DECOMP", "ROBUST"}
    wrong = pc.build_target(
        mini_truth("thing", binary={"path": str(binary), "sha256": "0" * 64}),
        "s0pe",
        tmp_path / "unused",
    )
    assert not wrong.sha_ok


def test_build_target_follows_a_targets_root_symlink(tmp_path):
    real = tmp_path / "src" / "dir"
    real.mkdir(parents=True)
    (real / "slugbin").write_bytes(tiny_elf())
    root = tmp_path / "organized"
    root.mkdir()
    (root / "slugbin").symlink_to("../src/dir/slugbin")
    target = pc.build_target(mini_truth("slugbin"), "s0", root)
    assert target.source_dir == real.resolve()
    assert target.pinned_sha256 is None and target.sha_ok


def test_build_target_refuses_a_missing_or_unlisted_binary(tmp_path):
    with pytest.raises(pc.TruthError, match="binary not found"):
        pc.build_target(mini_truth("absent"), "s0", tmp_path)
    (tmp_path / "other").write_bytes(tiny_elf())
    truth = mini_truth("other")
    truth["stage"]["files"] = ["something_else"]
    with pytest.raises(pc.TruthError, match="is not in stage.files"):
        pc.build_target(truth, "s0", tmp_path)


def test_load_truths_orders_filters_and_refuses(world):
    targets = pc.load_truths(world.truth_dir, world.targets_root)
    assert [t.slug for t in targets] == ["mini_a"]
    assert (
        pc.load_truths(world.truth_dir, world.targets_root, only=["mini_a"])[0].table
        == "s0"
    )
    with pytest.raises(pc.TruthError, match="names no truth file"):
        pc.load_truths(world.truth_dir, world.targets_root, only=["nope"])
    with pytest.raises(pc.TruthError, match="no truth directory"):
        pc.load_truths(world.root / "absent", world.targets_root)


def test_load_truths_refuses_a_slug_in_both_tables(tmp_path):
    w = make_world()
    try:
        (w.truth_dir / "s0pe").mkdir()
        shutil.copy(
            w.truth_dir / "s0" / "mini_a.yaml", w.truth_dir / "s0pe" / "mini_a.yaml"
        )
        with pytest.raises(pc.TruthError, match="duplicate slugs"):
            pc.load_truths(w.truth_dir, w.targets_root)
    finally:
        shutil.rmtree(w.root, ignore_errors=True)


def test_the_real_s0pe_truth_loads_with_its_pinned_hashes():
    targets = pc.load_truths(
        REPO_ROOT / "benchmark" / "truth", TARGETS_ROOT, only=["pe_sym", "pe_strip"]
    )
    assert [t.slug for t in targets] == ["pe_sym", "pe_strip"]
    for t in targets:
        assert t.table == "s0pe" and t.pinned_sha256 and t.sha_ok
        assert t.metrics == {"DECOMP", "ROBUST"}
        assert t.source_dir == REPO_ROOT / "benchmark" / "fixtures" / "s0pe"


@needs_targets
def test_the_real_truth_dir_loads_seven_elfs_then_two_pe_fixtures():
    truth_dir = REPO_ROOT / "benchmark" / "truth"
    targets = pc.load_truths(truth_dir, TARGETS_ROOT)
    assert [t.slug for t in targets] == [*pc.S0_ORDER, *pc.S0PE_ORDER]
    assert [t.table for t in targets] == ["s0"] * 7 + ["s0pe"] * 2
    assert all(t.metrics == pc.ALL_METRICS for t in targets[:7])
    assert [
        t.slug for t in pc.load_truths(truth_dir, TARGETS_ROOT, skip_s0pe=True)
    ] == list(pc.S0_ORDER)


def test_filter_cells_keeps_only_the_enabled_metrics(world):
    truth = yaml.safe_load((world.truth_dir / "s0" / "mini_a.yaml").read_text())
    runs = {c: ps.Run(rc=2, stdout='{"error": "declined"}') for c in COMMANDS}
    full = ps.score_target(truth, runs)
    kept = pc.filter_cells(full, frozenset({"DECOMP", "ROBUST"}))
    assert {c.metric for c in kept.cells} == {"DECOMP", "ROBUST"}
    assert kept.precision is None and kept.vuln is None
    assert pc.filter_cells(full, pc.ALL_METRICS) is full


# --- the control cell's check (V-2) ---------------------------------------------------


def control(**overrides):
    fields = dict(
        directory=CONTROL_DIR,
        binary="ghidra_control.elf",
        sha256="0" * 64,
        selector="ghidra_control",
        address=0x401136,
        analysis_backend="ghidra",
        rc=0,
        anchors=("puts",),
    )
    fields.update(overrides)
    return pc.Control(**fields)


GOOD_CODE = 'void ghidra_control(void)\n{\n  puts("hi");\n}\n'


def control_run(doc=None, rc=0, state="EXITED", stdout=None):
    base = {"analysis_backend": "ghidra", "address": "0x401136", "code": GOOD_CODE}
    base.update(doc or {})
    return ps.Run(
        state=state, rc=rc, stdout=json.dumps(base) if stdout is None else stdout
    )


def test_control_fixture_loads_its_expectation():
    loaded = pc.Control.load(CONTROL_DIR)
    assert (loaded.binary, loaded.selector, loaded.address) == (
        "ghidra_control.elf",
        "ghidra_control",
        0x401136,
    )
    assert (
        loaded.analysis_backend == "ghidra"
        and loaded.rc == 0
        and loaded.anchors == ("puts",)
    )
    assert (
        loaded.sha256
        == hashlib.sha256((CONTROL_DIR / loaded.binary).read_bytes()).hexdigest()
    )


def test_an_unusable_control_fixture_is_a_harness_error(tmp_path):
    with pytest.raises(pc.HarnessError, match="unusable"):
        pc.Control.load(tmp_path)


def test_a_correct_control_answer_passes():
    assert pc.evaluate_control(control(), control_run()) == []
    assert pc.evaluate_control(control(), control_run({"address": 0x401136})) == []


@pytest.mark.parametrize(
    "run, reason",
    [
        (control_run({"analysis_backend": "angr"}), "analysis_backend:angr"),
        (control_run({"address": "0x401000"}), "address:0x401000!=0x401136"),
        (
            control_run({"code": "// Decompilation failed for ghidra_control"}),
            "code_empty_or_sentinel",
        ),
        (
            control_run({"code": "void f(void)\n{\n  /* puts( */\n}\n"}),
            "anchor_missing:puts",
        ),
        (
            control_run({"code": "void f(void)\n{\n  fputs(x);\n}\n"}),
            "anchor_missing:puts",
        ),
        (control_run(rc=2), "rc:2!=0"),
        (control_run(state="TIMEOUT", stdout=""), "state:timeout"),
        (control_run(stdout="not json"), None),
    ],
)
def test_a_wrong_control_answer_is_named(run, reason):
    reasons = pc.evaluate_control(control(), run)
    assert reasons, "a wrong control answer must not pass"
    if reason:
        assert reason in reasons


# --- small helpers --------------------------------------------------------------------


def test_stat_state_comm_parses_around_the_last_paren():
    state, comm = pc._stat_state_comm(os.getpid())
    assert state in "RSD"
    assert comm == Path("/proc/self/comm").read_text().strip()
    assert pc._stat_state_comm(2**22 + 123) is None


# --- usage errors: refused before any cell runs ---------------------------------------


def test_a_committed_baseline_is_immutable(world, tmp_path):
    baselines = tmp_path / "baselines"
    baselines.mkdir()
    existing = baselines / "pre.json"
    existing.write_text("{}\n")
    done, report = run_runner(
        common(world, "--no-control", "--cli", world.cli("decline.py")),
        baselines / "pre",
    )
    assert done.returncode == pc.EXIT_USAGE
    assert "immutable baseline" in done.stderr
    assert existing.read_text() == "{}\n"


@pytest.mark.parametrize(
    "extra, message",
    [
        (["--only", "nope"], "names no truth file"),
        (["--extra-hide", str(REPO_ROOT)], "would hide the checkout or interpreter"),
        (["--control-dir", "/var/tmp/passcard-no-such-control"], "unusable"),
    ],
)
def test_usage_errors_exit_2_and_leave_no_scratch(world, tmp_path, extra, message):
    before = set(Path("/var/tmp").glob("passcard-*"))
    done, report = run_runner(
        common(world, "--cli", world.cli("decline.py"), *extra), tmp_path / "u"
    )
    assert done.returncode == pc.EXIT_USAGE, done.stdout + done.stderr
    assert message in done.stderr
    assert report is None
    assert set(Path("/var/tmp").glob("passcard-*")) - before == set()


@pytest.mark.parametrize(
    "flag, value", [("--reps", "0"), ("--require-time-quorum", "0")]
)
def test_non_positive_counts_are_refused(world, tmp_path, flag, value):
    done, _ = run_runner(common(world, "--no-control", flag, value), tmp_path / "u")
    assert done.returncode == pc.EXIT_USAGE


# --- an end-to-end run (bwrap) --------------------------------------------------------


@needs_bwrap
def test_a_declining_cli_scores_abstain_and_robust_pass(baseline):
    done, report, _ = baseline
    assert done.returncode == 0, done.stdout + done.stderr
    assert report["s0"]["targets"] == ["mini_a"] and report["s0pe"]["targets"] == []
    got = verdicts(report)
    for metric in ("METHOD-R0", "METHOD-L", "TEMPLATE", "OFF", "DECOMP"):
        assert got[("mini_a", metric)] == ["ABSTAIN"], metric
    assert got[("mini_a", "ROBUST")] == ["PASS"] * 4


@needs_bwrap
def test_no_control_run_is_never_accepted(baseline):
    done, report, _ = baseline
    assert report["control"]["ran"] is False
    assert report["valid"] is True and report["accepted"] is False
    assert report["not_accepted_reasons"] == ["control_skipped"]
    assert "NOT ACCEPTED (control_skipped)" in done.stdout


@needs_bwrap
def test_every_cell_runs_under_bwrap_and_leaves_no_survivor(baseline):
    # bwrap's namespace init is adopted by the subreaper as a zombie after every cell;
    # the harness reaps it and does not count it. Anything else would be a survivor.
    _, report, _ = baseline
    assert report["isolation_observed"] == ["bwrap"]
    assert report["header"]["isolation"]["backend"] == "bwrap"
    assert report["header"]["isolation"]["subreaper"] is True
    assert len(report["runs"]) == 4
    for rec in report["runs"]:
        assert (
            rec["isolation"] == "bwrap" and rec["state"] == "EXITED" and rec["rc"] == 2
        )
        assert rec["survivors"] == 0
        assert rec["sandbox_init_reaped"] <= 1


@needs_bwrap
def test_each_command_gets_its_own_cell_and_the_inside_path(baseline):
    _, report, _ = baseline
    cells = by_cell(report)
    assert sorted(cells) == ["mini_a-%s-r1" % c for c in sorted(COMMANDS)]
    for command in COMMANDS:
        argv = cells["mini_a-%s-r1" % command]["argv"]
        assert argv[2:4] == [command, "/tmp/cell/mini_a"]
        tail = (
            ["-o", "/tmp/cell/tmp/exploit.py", "--json"]
            if command == "template"
            else ["--json"]
        )
        assert argv[4:] == tail
        assert not any(part.startswith(".") for part in argv[3].split("/"))


@needs_bwrap
def test_the_header_records_provenance(baseline, world):
    _, report, _ = baseline
    head = report["header"]
    assert head["schema"] == pc.SCHEMA == "passcard-report/1"
    for name in ("proc.py", "sandbox.py"):
        path = REPO_ROOT / "supwngo" / "core" / name
        assert head["core_paths"][name] == str(path)
        assert (
            head["core_sha256"][name] == hashlib.sha256(path.read_bytes()).hexdigest()
        )
    assert head["load_max"] is None and head["reps"] == 1 and head["timeout_s"] == 30.0
    assert head["v0_limits"] and head["isolation"]["self_check"]
    assert head["env_passthrough"]["JAVA_TOOL_OPTIONS"].startswith(
        "-Duser.home=/tmp/cell/home"
    )
    assert head["cli"] == [sys.executable, str(world.shim("decline.py"))]
    for hidden in (world.truth_dir, world.targets_root, world.source_dir):
        assert str(hidden) in head["hide"]
    assert str(REPO_ROOT / "benchmark" / "truth") in head["hide"]
    assert not [
        h
        for h in head["hide"]
        if str(REPO_ROOT).startswith(h.rstrip("/") + "/") or h == str(REPO_ROOT)
    ]


@needs_bwrap
def test_the_markdown_report_sits_next_to_the_json(baseline):
    _, report, out = baseline
    text = Path(str(out) + ".md").read_text()
    assert text.startswith("# Passcard report")
    assert "| cell env passthrough |" in text
    assert "`JAVA_TOOL_OPTIONS=-Duser.home=/tmp/cell/home" in text
    assert "## Ghidra control cell (V-2)" in text and "Skipped (`--no-control`)" in text
    assert "## S0 matrix (7 ELF targets, smoke, never a gate)" in text
    assert "| ROBUST | 4 | 4 | 0 | 0 | 0 | 0 |" in text
    assert pc.render_markdown(report) == text


def _harness(backend):
    args = SimpleNamespace(cli=[], control_cli=[], backend=backend, scratch_root=None)
    return pc.Harness(args, proc=None, sandbox=None)


def test_passthrough_records_the_operator_knobs_a_cell_inherits(monkeypatch):
    for key in list(os.environ):
        if key.startswith(("SUPWNGO_", "GHIDRA_")):
            monkeypatch.delenv(key)
    for key in ("JAVA_HOME", "JAVA_TOOL_OPTIONS", "VIRTUAL_ENV", "LANG", "LC_ALL"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("SUPWNGO_GHIDRA_TIMEOUT", "600")
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", "/opt/ghidra")
    monkeypatch.setenv("JAVA_HOME", "/opt/jdk")
    monkeypatch.setenv("JAVA_TOOL_OPTIONS", "-Xmx2g")
    monkeypatch.setenv("PASSCARD_NOT_PASSED", "1")
    seen = _harness("bwrap").passthrough(pc.INSIDE)
    assert seen["SUPWNGO_GHIDRA_TIMEOUT"] == "600"
    assert seen["GHIDRA_INSTALL_DIR"] == "/opt/ghidra"
    assert seen["JAVA_HOME"] == "/opt/jdk"
    assert seen["JAVA_TOOL_OPTIONS"] == "-Duser.home=/tmp/cell/home -Xmx2g"
    assert "PASSCARD_NOT_PASSED" not in seen
    assert list(seen) == sorted(seen)  # a stable order, so two reports diff cleanly
    # The env a cell is given carries every one of them.
    env = _harness("bwrap").env(pc.INSIDE)
    assert all(env[key] == value for key, value in seen.items())


def test_passthrough_without_a_bwrap_cell_path_and_without_operator_options(
    monkeypatch,
):
    monkeypatch.delenv("JAVA_TOOL_OPTIONS", raising=False)
    monkeypatch.delenv("PATH", raising=False)
    seen = _harness("none").passthrough("/var/tmp/passcard-x/cell")
    assert seen["JAVA_TOOL_OPTIONS"] == "-Duser.home=/var/tmp/passcard-x/cell/home"
    assert seen["PATH"] == pc.DEFAULT_PATH


@needs_bwrap
def test_a_command_sees_only_its_cell_and_a_scrubbed_environment(world, tmp_path):
    cli = cli_arg(
        world.shim("env_dump.py"),
        "--probe",
        world.source_dir / "mini_a",
        "--probe",
        world.truth_dir / "s0" / "mini_a.yaml",
        "--probe",
        world.shim("decline.py"),
        "--list",
        "/tmp",
        "--list",
        "/tmp/cell",
        "--list",
        world.source_dir,
    )
    done, report = run_runner(
        common(world, "--no-control", "--cli", cli),
        tmp_path / "env",
        env_extra={
            "PASSCARD_LEAK_PROBE": "1",
            "SUPWNGO_PASSCARD_PROBE": "kept",
            "JAVA_TOOL_OPTIONS": "-Dpasscard.probe=1",
        },
    )
    assert done.returncode == 0, done.stdout + done.stderr
    seen = json.loads(by_cell(report)["mini_a-pwn-r1"]["stdout"])
    assert seen["cwd"] == "/tmp/cell"
    env = seen["env"]
    assert env["HOME"] == "/tmp/cell/home" and env["TMPDIR"] == "/tmp/cell/tmp"
    assert env["XDG_CACHE_HOME"] == "/tmp/cell/cache"
    # A JVM ignores $HOME (Ghidra would write under the read-only real home), so
    # user.home is pointed at the cell home; the operator's own options follow and
    # so still win.
    assert env["JAVA_TOOL_OPTIONS"] == "-Duser.home=/tmp/cell/home -Dpasscard.probe=1"
    assert env["PYTHONPATH"] == str(REPO_ROOT) and env["PWNLIB_NOTERM"] == "1"
    assert "PASSCARD_LEAK_PROBE" not in env  # the parent environment is not inherited
    assert env["SUPWNGO_PASSCARD_PROBE"] == "kept"  # except the declared passthrough
    # The header records the same knobs, so a run describes the environment it ran in.
    recorded = report["header"]["env_passthrough"]
    assert recorded["SUPWNGO_PASSCARD_PROBE"] == "kept"
    assert recorded["JAVA_TOOL_OPTIONS"] == env["JAVA_TOOL_OPTIONS"]
    assert "PASSCARD_LEAK_PROBE" not in recorded
    assert all(env[key] == value for key, value in recorded.items())
    # The answer keys are hidden; the shim, which lives outside every hidden path,
    # is not.
    assert seen["exists"] == {
        str(world.source_dir / "mini_a"): False,
        str(world.truth_dir / "s0" / "mini_a.yaml"): False,
        str(world.shim("decline.py")): True,
    }
    assert seen["listing"]["/tmp"] == ["cell"]
    assert seen["listing"]["/tmp/cell"] == sorted(["mini_a", *st.CELL_SUBDIRS])
    assert seen["listing"][str(world.source_dir)] == []


@needs_bwrap
def test_reps_add_time_samples_without_changing_the_matrix(world, tmp_path):
    done, report = run_runner(
        common(world, "--no-control", "--cli", world.cli("decline.py"), "--reps", "2"),
        tmp_path / "r",
    )
    assert done.returncode == 0, done.stdout + done.stderr
    assert len(report["runs"]) == 8
    assert verdicts(report)[("mini_a", "ROBUST")] == ["PASS"] * 4  # rep 1 only
    assert report["s0"]["detail"]["mini_a"]["stable"] is True
    for command, stats in report["time"]["per_command"].items():
        assert (stats["samples"], stats["valid"]) == (2, 2), command


@needs_bwrap
def test_a_missed_time_quorum_exits_3(world, tmp_path):
    done, report = run_runner(
        common(
            world,
            "--no-control",
            "--cli",
            world.cli("decline.py"),
            "--require-time-quorum",
            "2",
        ),
        tmp_path / "q",
    )
    assert done.returncode == pc.EXIT_QUORUM
    assert "time_quorum_failed" in done.stderr
    assert report["time_quorum_failed"] is True and report["accepted"] is False
    assert "time_quorum_failed" in report["not_accepted_reasons"]
    assert sorted(
        (s["command"], s["valid"], s["needed"]) for s in report["time"]["shortfalls"]
    ) == [(c, 1, 2) for c in sorted(COMMANDS)]


@needs_bwrap
def test_a_met_quorum_does_not_fail_the_run(world, tmp_path):
    done, report = run_runner(
        common(
            world,
            "--no-control",
            "--cli",
            world.cli("decline.py"),
            "--reps",
            "2",
            "--require-time-quorum",
            "2",
        ),
        tmp_path / "q",
    )
    assert done.returncode == 0, done.stdout + done.stderr
    assert (
        report["time_quorum_failed"] is False and report["time"]["quorum_met"] is True
    )


@needs_bwrap
def test_a_load_ceiling_invalidates_time_samples(world, tmp_path):
    done, report = run_runner(
        common(
            world,
            "--no-control",
            "--cli",
            world.cli("decline.py"),
            "--load-max",
            "0",
            "--require-time-quorum",
            "1",
        ),
        tmp_path / "l",
    )
    assert done.returncode == pc.EXIT_QUORUM
    assert report["header"]["load_max"] == 0
    for stats in report["time"]["per_command"].values():
        assert (stats["samples"], stats["valid"]) == (1, 0)


@needs_bwrap
def test_a_passing_control_and_all_bwrap_cells_are_accepted(world, tmp_path):
    done, report = run_runner(
        common(
            world,
            "--cli",
            world.cli("decline.py"),
            "--control-cli",
            world.cli("control_ok.py"),
        ),
        tmp_path / "ok",
    )
    assert done.returncode == 0, done.stdout + done.stderr
    ctl = report["control"]
    assert ctl["ran"] and ctl["passed"] and ctl["reasons"] == []
    assert ctl["sha256"] == ctl["expect_sha256"]
    assert ctl["cell"]["argv"][2:] == [
        "decompile",
        "/tmp/cell/ghidra_control.elf",
        "-f",
        "ghidra_control",
        "--json",
    ]
    assert (
        report["valid"] and report["accepted"] and report["not_accepted_reasons"] == []
    )
    # The control cell is recorded but is in no denominator.
    assert "control-decompile-r1" in by_cell(report)
    assert report["s0"]["summary"]["metrics"]["ROBUST"]["n"] == 4
    assert report["s0"]["targets"] == ["mini_a"]


@needs_bwrap
def test_a_failing_control_makes_the_run_invalid(world, tmp_path):
    done, report = run_runner(
        common(
            world,
            "--cli",
            world.cli("decline.py"),
            "--control-cli",
            world.cli("decline.py"),
        ),
        tmp_path / "bad",
    )
    assert done.returncode == pc.EXIT_INVALID
    assert report["valid"] is False and report["accepted"] is False
    assert report["control"]["passed"] is False
    assert report["invalid_reasons"] and report["invalid_reasons"][0].startswith(
        "control_failed:"
    )
    assert (
        "**INVALID RUN, NOT ACCEPTED.**"
        in Path(str(tmp_path / "bad") + ".md").read_text()
    )
    # The product CLI still ran: INVALID is a verdict on the run, not an abort.
    assert report["s0"]["summary"]["metrics"]["ROBUST"]["n"] == 4


@needs_bwrap
def test_a_changed_control_binary_is_invalid_without_running_it(world, tmp_path):
    fixture = world.root / "control"
    shutil.copytree(CONTROL_DIR, fixture)
    expect = yaml.safe_load((fixture / "expect.yaml").read_text())
    expect["sha256"] = "0" * 64
    (fixture / "expect.yaml").write_text(yaml.safe_dump(expect))
    done, report = run_runner(
        common(
            world,
            "--cli",
            world.cli("decline.py"),
            "--control-cli",
            world.cli("control_ok.py"),
            "--control-dir",
            fixture,
        ),
        tmp_path / "sha",
    )
    assert done.returncode == pc.EXIT_INVALID
    assert report["control"]["reasons"] == ["sha256_mismatch"]
    assert "cell" not in report["control"]
    assert "control-decompile-r1" not in by_cell(report)
    assert report["invalid_reasons"] == ["control_failed: sha256_mismatch"]


@needs_bwrap
def test_backend_none_runs_on_the_host_and_is_never_accepted(world, tmp_path):
    done, report = run_runner(
        common(
            world,
            "--cli",
            world.cli("decline.py"),
            "--control-cli",
            world.cli("control_ok.py"),
            "--backend",
            "none",
        ),
        tmp_path / "none",
    )
    assert done.returncode == 0, done.stdout + done.stderr
    assert report["control"]["passed"] is True
    assert report["isolation_observed"] == ["none"]
    assert (
        report["accepted"] is False
        and "isolation:none" in report["not_accepted_reasons"]
    )
    argv = by_cell(report)["mini_a-pwn-r1"]["argv"]
    assert argv[3].startswith("/var/tmp/passcard-") and argv[3].endswith(
        "/mini_a-pwn-r1/mini_a"
    )
    assert all(
        rec["sandbox_init_reaped"] == 0 and rec["survivors"] == 0
        for rec in report["runs"]
    )


@needs_bwrap
def test_cells_are_staged_fresh_file_by_file_without_dot_components(world, tmp_path):
    scratch = world.root / "scratch"
    done, report = run_runner(
        common(
            world,
            "--no-control",
            "--cli",
            world.cli("decline.py"),
            "--scratch-root",
            scratch,
            "--keep-scratch",
        ),
        tmp_path / "keep",
    )
    assert done.returncode == 0, done.stdout + done.stderr
    cells = sorted(scratch.glob("run-*/mini_a-*-r1"))
    assert [c.name for c in cells] == ["mini_a-%s-r1" % c for c in sorted(COMMANDS)]
    for cell in cells:
        assert sorted(p.name for p in cell.iterdir()) == sorted(
            ["mini_a", *st.CELL_SUBDIRS]
        )
        assert (cell / "mini_a").read_bytes() == tiny_elf()
        assert not any(part.startswith(".") for part in cell.parts)
    assert str(scratch) in report["header"]["hide"]


# --- the S0-PE table and the pinned fixture hash (V-15) -------------------------------


@pytest.fixture
def world_pe():
    sha = hashlib.sha256(tiny_elf()).hexdigest()
    w = make_world(pinned_sha=sha)
    w.pin = sha
    yield w
    shutil.rmtree(w.root, ignore_errors=True)


@needs_bwrap
def test_the_s0pe_table_is_separate_and_scores_decomp_and_robust_only(
    world_pe, tmp_path
):
    done, report = run_runner(
        common(world_pe, "--no-control", "--cli", world_pe.cli("decline.py")),
        tmp_path / "pe",
    )
    assert done.returncode == 0, done.stdout + done.stderr
    assert report["valid"] is True
    assert report["s0"]["targets"] == ["mini_a"] and report["s0pe"]["targets"] == [
        "mini_pe"
    ]
    scored = {
        m: v["n"] for m, v in report["s0pe"]["summary"]["metrics"].items() if v["n"]
    }
    assert scored == {"DECOMP": 1, "ROBUST": 4}
    # The PE target adds nothing to the ELF matrix.
    assert report["s0"]["summary"]["metrics"]["ROBUST"]["n"] == 4
    assert (
        "## S0-PE (separate table: DECOMP and ROBUST only)"
        in Path(str(tmp_path / "pe") + ".md").read_text()
    )


@needs_bwrap
def test_a_changed_s0pe_binary_makes_the_run_invalid(tmp_path):
    w = make_world(pinned_sha="0" * 64)
    try:
        done, report = run_runner(
            common(w, "--no-control", "--cli", w.cli("decline.py")), tmp_path / "pin"
        )
    finally:
        shutil.rmtree(w.root, ignore_errors=True)
    assert done.returncode == pc.EXIT_INVALID
    assert report["valid"] is False and report["accepted"] is False
    assert report["invalid_reasons"] == ["fixture_sha256_mismatch: mini_pe"]
