#!/usr/bin/env python3
"""
benchmark/run_bench.py -- Phase-1 measurement harness for supwngo's live
`autopwn` pipeline against the 15-target benchmark corpus.

What this does, per target:
  1. Builds the target's binary via build_all.sh if it isn't already built.
  2. Runs supwngo's real `autopwn` CLI against it (not a mock, not a stub):
       - once with `--json` to capture autopwn's own structured self-report
         (technique tried, its own success/verified claim, per-attempt log)
       - once without `--json` (with `-o <script>`) because the CLI only
         writes the generated exploit script/template to -o in non-JSON
         mode (confirmed by reading supwngo/cli.py's autopwn command: the
         `if output: open(output,'w').write(...)` block lives entirely
         inside the `else` branch of `if json_output: ... else: ...`)
  3. GENUINELY VERIFIES the result independently: actually re-executes the
     generated script/template as a fresh subprocess (never trusting
     autopwn's own "success"/"verified" self-report for the SUCCESS
     determination) and greps its captured stdout+stderr for the exact,
     target-specific flag string read from that target's build-time
     flag.txt. A small, fixed, harmless stdin script
     (`cat flag.txt` + a marker echo) is piped in so that exploits which
     land a shell (rather than a target that prints its flag directly via
     a win()-style function) get a chance to actually read the flag file
     during the run, exactly like a human would at the resulting prompt.
  4. Classifies SUCCESS / PARTIAL / FAILED (see classify() for the exact,
     honest rule -- PARTIAL is allowed to reference autopwn's own claims,
     SUCCESS is never allowed to).
  5. Writes benchmark/results/<timestamp>/report.json (full raw data, incl.
     each generated script and a tail of its verification output) plus a
     human-readable summary.txt.

Usage:
    python3 benchmark/run_bench.py                       # all 15 targets
    python3 benchmark/run_bench.py --target 15_win_function
    python3 benchmark/run_bench.py --target 02_ret2plt_system --target 15_win_function
    python3 benchmark/run_bench.py --timeout 15           # per-attempt timeout passed to autopwn

Note on invoking supwngo: the `supwngo` console-script entry point declared
in pyproject.toml is not installed in this environment (`which supwngo`
fails). The package itself is importable, so this harness invokes it as
`python3 -m supwngo.cli ...` with PYTHONPATH pointing at the repo root --
confirmed working via a manual smoke test before this harness was written.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:
    print("PyYAML is required (pip install pyyaml)", file=sys.stderr)
    sys.exit(1)

HERE = Path(__file__).resolve().parent          # benchmark/
REPO_ROOT = HERE.parent                          # worktree root (supwngo/ package lives here)
CORPUS_DIR = HERE / "corpus"
CORPUS_YAML = HERE / "corpus.yaml"
BUILD_SCRIPT = HERE / "build_all.sh"
RESULTS_ROOT = HERE / "results"

DEFAULT_TIMEOUT = 10.0

# Fed to the generated script's stdin during independent verification. Both
# lines are harmless no-ops against a target that never obtains a shell
# (the target's own vuln() has already returned/exited by the time a
# script reaches io.interactive(), so stray input is simply ignored or
# rejected); against a shell-obtaining exploit, `cat flag.txt` is exactly
# what reads the flag from the target's own working directory.
VERIFY_STDIN = b"cat flag.txt\necho __SUPWNGO_BENCH_VERIFY_DONE__\n"


def load_targets() -> list[dict]:
    data = yaml.safe_load(CORPUS_YAML.read_text())
    return data["targets"]


def slug_binary_name(slug: str) -> str:
    # corpus dirs are "<NN>_<name>"; the built binary is named "<name>"
    # (matches build_all.sh's own `slug="${slug#[0-9][0-9]_}"` stripping).
    return slug.split("_", 1)[1]


def binary_path(slug: str) -> Path:
    return CORPUS_DIR / slug / slug_binary_name(slug)


def flag_path(slug: str) -> Path:
    return CORPUS_DIR / slug / "flag.txt"


def ensure_built(slug: str) -> None:
    bp = binary_path(slug)
    if bp.is_file() and os.access(bp, os.X_OK):
        return
    print(f"[build] {slug}: binary missing, building via build_all.sh ...")
    subprocess.run(
        ["bash", str(BUILD_SCRIPT), slug],
        check=True,
        cwd=str(HERE),
    )


def run_supwngo(binary_abs: Path, timeout: float, extra_args: list[str]):
    """Invoke the real supwngo autopwn CLI as a subprocess. Returns
    (returncode_or_None, stdout, stderr, wall_timed_out)."""
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    cmd = [
        sys.executable, "-m", "supwngo.cli", "autopwn", str(binary_abs),
        "--timeout", str(timeout),
    ] + extra_args
    # The consolidated pipeline (post Phase 2/3) tries up to ~11 techniques,
    # each individually bounded by --timeout, plus static/dynamic analysis
    # overhead (angr/Z3 wiring can be slow on PIE targets); give it generous
    # wall-clock room beyond the worst-case sum before considering the CLI
    # invocation itself hung.
    wall_timeout = max(120.0, timeout * 15 + 60)
    try:
        proc = subprocess.run(
            cmd, cwd=str(REPO_ROOT), env=env,
            capture_output=True, text=True, timeout=wall_timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr, False
    except subprocess.TimeoutExpired as e:
        # Quirk: subprocess.run() re-raises the TimeoutExpired from
        # Popen.communicate() as-is, without applying `text=True`'s decoding
        # step -- e.stdout/e.stderr are bytes here even though a successful
        # (non-timing-out) run() call above would have given us str.
        out = e.stdout or b""
        err = e.stderr or b""
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        if isinstance(err, bytes):
            err = err.decode("utf-8", "replace")
        return None, out, err, True


def parse_json_result(stdout: str):
    """autopwn --json prints rich log lines first, then a single JSON
    object as the last thing on stdout. Find and parse it defensively."""
    start = stdout.find("{")
    if start == -1:
        return None
    end = stdout.rfind("}")
    if end <= start:
        return None
    try:
        return json.loads(stdout[start:end + 1])
    except json.JSONDecodeError:
        return None


def independent_verify(script_path: Path, target_dir: Path, expected_flag: str, timeout: float) -> dict:
    """The ONLY source of truth for SUCCESS: actually run the generated
    script fresh and look for the exact flag string in its own output.
    Never trust autopwn's own success/verified claims here."""
    if not script_path.is_file() or script_path.stat().st_size == 0:
        return {"ran": False, "timed_out": False, "flag_found": False, "output_tail": ""}

    wall_timeout = max(30.0, timeout * 4)
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    try:
        proc = subprocess.run(
            [sys.executable, str(script_path)],
            input=VERIFY_STDIN,
            cwd=str(target_dir),
            env=env,
            capture_output=True,
            timeout=wall_timeout,
        )
        out_bytes = proc.stdout + proc.stderr
        timed_out = False
    except subprocess.TimeoutExpired as e:
        out_bytes = (e.stdout or b"") + (e.stderr or b"")
        timed_out = True

    out = out_bytes.decode("utf-8", "replace")
    flag_found = expected_flag in out
    return {
        "ran": True,
        "timed_out": timed_out,
        "flag_found": flag_found,
        "output_tail": out[-4000:],
    }


def classify(supwngo_json: dict | None, verify: dict) -> tuple[str, str]:
    if verify["flag_found"]:
        return "SUCCESS", (
            "independent re-execution of the generated exploit script produced "
            "the target-specific flag string"
        )

    claimed_success = bool(supwngo_json and supwngo_json.get("success"))
    any_attempt_success = bool(
        supwngo_json
        and any(a.get("result") == "success" for a in supwngo_json.get("attempts", []) or [])
    )
    if claimed_success or any_attempt_success:
        return "PARTIAL", (
            "autopwn self-reported success (or a successful intermediate attempt), "
            "but independently re-running the generated script did not reproduce "
            "the flag"
        )
    return "FAILED", (
        "no successful attempt reported by autopwn, and independent re-execution "
        "did not produce the flag"
    )


def run_one(target: dict, timeout: float, results_dir: Path) -> dict:
    slug = target["slug"]
    print(f"=== {slug}  [{target['technique']}, {target['difficulty']}] ===", flush=True)

    ensure_built(slug)
    bp = binary_path(slug).resolve()
    target_dir = bp.parent
    expected_flag = flag_path(slug).read_text().strip()

    t0 = time.time()

    # (1) structured self-report
    rc1, out1, err1, to1 = run_supwngo(bp, timeout, ["--json"])
    supwngo_json = parse_json_result(out1) if out1 else None

    # (2) the actual generated script (only written in non-JSON mode -- see
    #     module docstring)
    script_path = results_dir / f"{slug}_generated.py"
    rc2, out2, err2, to2 = run_supwngo(bp, timeout, ["-o", str(script_path)])

    # (3) genuine independent verification
    verify = independent_verify(script_path, target_dir, expected_flag, timeout)

    elapsed = time.time() - t0
    status, reason = classify(supwngo_json, verify)

    print(f"    -> {status}: {reason}", flush=True)

    return {
        "slug": slug,
        "technique_intended": target["technique"],
        "difficulty": target["difficulty"],
        "protections": target.get("protections"),
        "expected_flag": expected_flag,
        "elapsed_sec": round(elapsed, 1),
        "autopwn_json_probe": {
            "returncode": rc1,
            "wall_timed_out": to1,
            "parsed": supwngo_json,
            "stderr_tail": (err1 or "")[-1500:],
        },
        "autopwn_script_generation": {
            "returncode": rc2,
            "wall_timed_out": to2,
            "stderr_tail": (err2 or "")[-1500:],
        },
        "verification": verify,
        "status": status,
        "reason": reason,
    }


def write_summary(results: list[dict], out_path: Path, timeout: float) -> str:
    total = len(results)
    counts = {"SUCCESS": 0, "PARTIAL": 0, "FAILED": 0}
    for r in results:
        counts[r["status"]] += 1

    lines = []
    lines.append("supwngo Phase-1 benchmark -- run_bench.py results")
    lines.append(f"timestamp: {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"per-attempt timeout passed to autopwn: {timeout}s")
    lines.append("")
    pct = (counts["SUCCESS"] / total * 100) if total else 0.0
    lines.append(
        f"OVERALL: {counts['SUCCESS']}/{total} SUCCESS ({pct:.1f}%), "
        f"{counts['PARTIAL']} PARTIAL, {counts['FAILED']} FAILED"
    )
    lines.append("")
    lines.append(f"{'slug':<26} {'difficulty':<10} {'status':<9} reason")
    lines.append("-" * 100)
    for r in sorted(results, key=lambda r: r["slug"]):
        lines.append(f"{r['slug']:<26} {r['difficulty']:<10} {r['status']:<9} {r['reason']}")
    lines.append("")

    by_diff: dict[str, dict[str, int]] = {}
    for r in results:
        d = by_diff.setdefault(r["difficulty"], {"SUCCESS": 0, "PARTIAL": 0, "FAILED": 0, "total": 0})
        d[r["status"]] += 1
        d["total"] += 1
    lines.append("By difficulty:")
    for diff, d in sorted(by_diff.items()):
        lines.append(f"  {diff:<8} {d['SUCCESS']}/{d['total']} SUCCESS, {d['PARTIAL']} PARTIAL, {d['FAILED']} FAILED")
    lines.append("")

    lines.append("Classification rule (see run_bench.py:classify()):")
    lines.append("  SUCCESS = the generated exploit script was independently re-run fresh")
    lines.append("            and its own captured output contained the exact,")
    lines.append("            target-specific flag string -- never a match against")
    lines.append("            autopwn's own log/success claims.")
    lines.append("  PARTIAL = autopwn self-reported success (or a successful")
    lines.append("            intermediate attempt) but the independent re-run above")
    lines.append("            did not reproduce the flag.")
    lines.append("  FAILED  = neither of the above.")
    lines.append("")

    text = "\n".join(lines)
    out_path.write_text(text)
    return text


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", action="append", default=None,
                     help="Only run this target slug (e.g. 15_win_function). Repeatable.")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                     help=f"Per-attempt timeout passed to `supwngo autopwn --timeout` (default {DEFAULT_TIMEOUT})")
    args = ap.parse_args()

    all_targets = load_targets()
    if args.target:
        wanted = set(args.target)
        targets = [t for t in all_targets if t["slug"] in wanted]
        missing = wanted - {t["slug"] for t in targets}
        if missing:
            print(f"error: unknown target slug(s): {', '.join(sorted(missing))}", file=sys.stderr)
            sys.exit(1)
    else:
        targets = all_targets

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SZ")
    results_dir = RESULTS_ROOT / ts
    results_dir.mkdir(parents=True, exist_ok=True)

    results = []
    for t in targets:
        results.append(run_one(t, args.timeout, results_dir))

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "timeout": args.timeout,
        "targets_run": [t["slug"] for t in targets],
        "results": results,
    }
    (results_dir / "report.json").write_text(json.dumps(report, indent=2))
    summary_text = write_summary(results, results_dir / "summary.txt", args.timeout)

    print()
    print(summary_text)
    print(f"Full report: {results_dir / 'report.json'}")
    print(f"Summary:     {results_dir / 'summary.txt'}")


if __name__ == "__main__":
    main()
