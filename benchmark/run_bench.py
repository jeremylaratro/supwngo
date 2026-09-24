#!/usr/bin/env python3
"""
benchmark/run_bench.py -- measurement harness for supwngo's live `autopwn`
pipeline against a benchmark corpus of deliberately-vulnerable x86-64 ELF
targets.

What this does, per target:
  1. Rebuilds the target from its committed C source with a FRESH PER-RUN
     SECRET FLAG (see "Why the flag must be a per-run secret" below).
  2. Runs supwngo's real `autopwn` CLI against it (not a mock, not a stub):
       - once with `--json` to capture autopwn's own structured self-report
         (technique tried, its own success/verified claim, per-attempt log)
       - once without `--json` (with `-o <script>`) because the CLI only
         writes the generated exploit script/template to -o in non-JSON
         mode (confirmed by reading supwngo/cli.py's autopwn command: the
         `if output: open(output,'w').write(...)` block lives entirely
         inside the `else` branch of `if json_output: ... else: ...`)
  3. Runs NEGATIVE CONTROLS that involve no exploitation whatsoever, to
     prove the flag is not reachable for free (see below).
  4. GENUINELY VERIFIES the result independently: actually re-executes the
     generated script/template as a fresh subprocess (never trusting
     autopwn's own "success"/"verified" self-report for the SUCCESS
     determination) and greps its captured stdout+stderr for that run's
     secret flag string.
  5. Classifies SUCCESS / PARTIAL / FAILED / VOID (see classify()).
  6. Writes <corpus results>/<timestamp>/report.json plus summary.txt.

Why the flag must be a per-run secret
-------------------------------------
Until 23 Sep 2026 this harness scored against a flag that `build_all.sh`
grepped out of the target's *committed* C source. That made the "secret" a
public constant: present in git, and compiled verbatim into the .rodata of
every win()-style target. A generated script that merely printed that
literal -- or ran `strings` over the binary -- was therefore scored as a
successful exploitation. 9 of the original 15 targets were affected.

The harness now mints a fresh, unguessable flag per target per run and
passes it to `build_all.sh` via `SUPWNGO_BENCH_FLAG`, which both compiles it
in (`-DFLAG=...`, which every win()-style source already honours via its
`#ifndef FLAG` guard) and writes it to `flag.txt`. A flag string that
appears in a script's output therefore cannot have been known in advance.
The harness verifies this fail-closed: if the built artifacts do not
actually carry the secret, the target is scored VOID rather than measured.

Why negative controls
---------------------
A small fixed stdin script (`cat flag.txt` plus a shell-arithmetic marker)
is piped into the re-executed exploit so that exploits which land a shell
get a chance to read the flag file, exactly like a human would at the
resulting prompt. But that injected stdin is itself attacker-controlled
input to the target, and can trigger the target's bug on its own: with the
original 48-byte stdin, `13_off_by_one` (`read(0, s.buf, 32)` followed by
`s.buf[n] = 0`) was solved by the *harness*, so a "exploit" script whose
entire body was `subprocess.run(['./off_by_one'])` scored SUCCESS.

Two guards address this. The injected stdin is kept deliberately short (see
VERIFY_STDIN), and -- the actual structural guarantee -- before scoring, the
harness runs the target with no exploit at all under the same conditions. If
the flag shows up there, nothing a script does can be attributed to
exploitation, so the target is scored VOID instead of SUCCESS. This
generalises to any future corpus rather than depending on byte counts in
this one.

See docs/reports/HARNESS-SOUNDNESS-AUDIT-23SEP2026.md for the full audit and
reproductions.

Usage:
    python3 benchmark/run_bench.py                       # all targets
    python3 benchmark/run_bench.py --target 15_win_function
    python3 benchmark/run_bench.py --target 02_ret2plt_system --target 15_win_function
    python3 benchmark/run_bench.py --timeout 15          # per-attempt timeout passed to autopwn
    # reuse the harness against a later corpus round:
    python3 benchmark/run_bench.py \
        --corpus-root benchmark/corpus_r2 --manifest benchmark/corpus_r2.yaml

Note on invoking supwngo: the `supwngo` console-script entry point declared
in pyproject.toml is not installed in this environment (`which supwngo`
fails). The package itself is importable, so this harness invokes it as
`python3 -m supwngo.cli ...` with PYTHONPATH pointing at the repo root.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import subprocess
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:
    print("PyYAML is required (pip install pyyaml)", file=sys.stderr)
    sys.exit(1)

HERE = Path(__file__).resolve().parent          # benchmark/
REPO_ROOT = HERE.parent                          # worktree root (supwngo/ package lives here)
BUILD_SCRIPT = HERE / "build_all.sh"

DEFAULT_CORPUS_DIR = HERE / "corpus"
DEFAULT_CORPUS_YAML = HERE / "corpus.yaml"

DEFAULT_TIMEOUT = 10.0

# A flag shorter than this is treated as a build/provisioning fault rather
# than a secret. Guards the degenerate `"" in output` case, which would
# otherwise score every target SUCCESS.
MIN_FLAG_LEN = 16

# Fed to the generated script's stdin during independent verification, so a
# shell-obtaining exploit can read the flag file the way a human would at the
# resulting prompt.
#
# LENGTH IS LOAD-BEARING. This is attacker-controlled input to the target and
# can trigger the target's own bug: at 48 bytes it solved 13_off_by_one
# (read(0, buf, 32) + buf[n]=0) all by itself. Keep it short, and never rely
# on the length alone -- negative_control() is what actually guarantees the
# flag was not free.
#
# `echo $((6*7))` is a shell-arithmetic marker: a real command interpreter
# prints "42", whereas a target that merely echoes its input back prints the
# literal "$((6*7))". Recorded as a diagnostic (shell_proven), not as a
# SUCCESS gate -- win()-style targets legitimately never yield a shell.
VERIFY_STDIN = b"cat flag.txt\necho $((6*7))\n"
SHELL_PROOF_RE = re.compile(r"(?m)^\s*42\s*$")

# A second, cruder negative control: a benign filler blob. If this captures
# the flag, the target hands it out for arbitrary garbage.
CONTROL_FILLER = b"A" * 512 + b"\n"


@dataclass(frozen=True)
class Corpus:
    """Where a corpus lives. Parameterised so later rounds
    (benchmark/corpus_r2 + benchmark/corpus_r2.yaml, ...) reuse this harness
    unchanged."""

    root: Path
    manifest: Path

    def targets(self) -> list[dict]:
        data = yaml.safe_load(self.manifest.read_text())
        return data["targets"]

    @staticmethod
    def binary_name(slug: str) -> str:
        # corpus dirs are "<NN>_<name>"; the built binary is named "<name>"
        # (matches build_all.sh's own `slug="${slug#[0-9][0-9]_}"` stripping).
        return slug.split("_", 1)[1]

    def target_dir(self, slug: str) -> Path:
        return self.root / slug

    def binary(self, slug: str) -> Path:
        return self.target_dir(slug) / self.binary_name(slug)

    def flag_file(self, slug: str) -> Path:
        return self.target_dir(slug) / "flag.txt"

    def source(self, slug: str) -> Path:
        return self.target_dir(slug) / f"{self.binary_name(slug)}.c"

    def results_root(self) -> Path:
        # Keep results next to the corpus they describe:
        #   benchmark/corpus    -> benchmark/results
        #   benchmark/corpus_r2 -> benchmark/results_r2
        suffix = self.root.name[len("corpus"):] if self.root.name.startswith("corpus") else f"_{self.root.name}"
        return self.root.parent / f"results{suffix}"


@contextmanager
def corpus_lock(corpus: Corpus):
    """Serialise runs against one corpus tree.

    The harness rebuilds each target with a fresh secret flag mid-run, so two
    concurrent runs over the same corpus would clobber each other's binaries
    and flag.txt files -- producing spurious FAILEDs rather than an obvious
    crash. Several agents share this repo, so fail fast and loudly instead.
    Distinct corpora (benchmark/corpus vs benchmark/corpus_r2) and distinct
    worktrees are unaffected: the lock lives in the corpus root."""
    lock = corpus.root / ".run_bench.lock"
    try:
        fd = os.open(str(lock), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        print(
            f"error: {lock} exists -- another run_bench.py is using this corpus.\n"
            f"       Because each run rebuilds the targets with a fresh secret "
            f"flag, concurrent runs corrupt each other's results.\n"
            f"       If no run is active, remove the lock file and retry.",
            file=sys.stderr,
        )
        sys.exit(1)
    try:
        os.write(fd, f"pid={os.getpid()} started={datetime.now(timezone.utc).isoformat()}\n".encode())
        os.close(fd)
        yield
    finally:
        try:
            lock.unlink()
        except FileNotFoundError:
            pass


# 38 chars: "FLAG{" + 32 hex + "}".
#
# LENGTH IS A CORPUS CONTRACT, not a free parameter. A target may copy its
# flag into a fixed-size buffer, so a longer token could overflow the corpus
# itself and change the very behaviour we are measuring. The tightest case in
# benchmark/corpus is 11_heap_uaf_leak:
#     chunks[0] = malloc(80);
#     memcpy(chunks[0] + 16, FLAG, strlen(FLAG) + 1);
# which needs 16 + len(flag) + 1 <= 80, i.e. len(flag) <= 63. Keeping it fixed
# also keeps target memory layout stable run to run. Re-check this bound
# before growing the token or adopting a corpus with tighter flag buffers.
SECRET_FLAG_LEN = 38
MAX_SAFE_FLAG_LEN = 63


def mint_secret_flag() -> str:
    """A fresh, unguessable per-run flag."""
    flag = "FLAG{" + secrets.token_hex(16) + "}"
    assert len(flag) == SECRET_FLAG_LEN <= MAX_SAFE_FLAG_LEN
    return flag


class ProvisionError(RuntimeError):
    """The target could not be built such that its flag is a real secret."""


def build_with_secret(corpus: Corpus, slug: str, secret: str) -> None:
    """Rebuild the target with a per-run secret flag, then prove the secret
    actually landed. Fail-closed: anything unverified raises, and the caller
    scores the target VOID rather than reporting a number we can't trust."""
    env = dict(os.environ)
    env["SUPWNGO_BENCH_FLAG"] = secret
    env["SUPWNGO_BENCH_CORPUS"] = str(corpus.root)
    proc = subprocess.run(
        ["bash", str(BUILD_SCRIPT), slug],
        cwd=str(HERE), env=env, capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise ProvisionError(
            f"build_all.sh failed for {slug} (rc={proc.returncode}): "
            f"{(proc.stderr or proc.stdout or '').strip()[-400:]}"
        )

    bp = corpus.binary(slug)
    if not bp.is_file() or not os.access(bp, os.X_OK):
        raise ProvisionError(f"build produced no executable at {bp}")

    flag_file = corpus.flag_file(slug)
    if not flag_file.is_file():
        raise ProvisionError(f"build wrote no flag.txt for {slug}")
    on_disk = flag_file.read_text().strip()
    if on_disk != secret:
        raise ProvisionError(
            f"flag.txt for {slug} does not hold this run's secret -- the "
            f"builder ignored SUPWNGO_BENCH_FLAG, so the flag is a "
            f"predictable constant and cannot be scored honestly"
        )

    # Targets that print their own flag guard it with `#ifndef FLAG`; for
    # those the secret must be compiled in, or a genuine win() would print a
    # stale literal and be scored FAILED.
    src = corpus.source(slug)
    if src.is_file() and "#define FLAG" in src.read_text():
        if secret.encode() not in bp.read_bytes():
            raise ProvisionError(
                f"{slug} defines its own FLAG but the built binary does not "
                f"contain this run's secret -- -DFLAG did not take effect"
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


def _excerpt(text: str, limit: int = 2000) -> str:
    """Keep both ends of a long capture.

    The old code kept only `out[-4000:]`, and because stderr was appended
    after stdout the tail was always stderr -- typically pwntools/unicorn
    deprecation warnings -- so the actual flag/shell evidence never made it
    into the report and results could not be audited by hand."""
    if len(text) <= limit * 2:
        return text
    omitted = len(text) - limit * 2
    return f"{text[:limit]}\n...[{omitted} chars omitted]...\n{text[-limit:]}"


def _run_capture(argv: list[str], cwd: Path, stdin_bytes: bytes, wall_timeout: float):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    try:
        proc = subprocess.run(
            argv, input=stdin_bytes, cwd=str(cwd), env=env,
            capture_output=True, timeout=wall_timeout,
        )
        return proc.stdout or b"", proc.stderr or b"", False
    except subprocess.TimeoutExpired as e:
        return (e.stdout or b""), (e.stderr or b""), True


def negative_control(corpus: Corpus, slug: str, expected_flag: str, timeout: float) -> dict:
    """Run the target with NO exploit at all, under the same conditions the
    verification step uses. If the flag appears here it was free, and nothing
    a generated script does can be credited to exploitation."""
    bp = corpus.binary(slug)
    tdir = corpus.target_dir(slug)
    wall_timeout = max(10.0, timeout)

    controls = {}
    for name, stdin_bytes in (
        ("bare_run_verify_stdin", VERIFY_STDIN),
        ("bare_run_filler", CONTROL_FILLER),
    ):
        out_b, err_b, timed_out = _run_capture(
            [str(bp)], tdir, stdin_bytes, wall_timeout
        )
        text = (out_b + err_b).decode("utf-8", "replace")
        controls[name] = {
            "flag_found": expected_flag in text,
            "timed_out": timed_out,
            "excerpt": _excerpt(text, 600),
        }

    leaked = sorted(n for n, c in controls.items() if c["flag_found"])
    return {
        "controls": controls,
        "flag_leaked_without_exploit": leaked,
        # Documented residual limitation, not a pass/fail gate. win()-style
        # targets print a compiled-in flag, so the secret is inside the
        # binary image and a script could scrape it with `strings` instead of
        # exploiting. Verification is not sandboxed (the script runs as the
        # same user, so flag.txt is readable too), so the harness cannot
        # prevent this -- it inspects the generated script instead (see
        # inspect_generated_script) and records the exposure here.
        "flag_statically_extractable_from_binary": expected_flag.encode() in bp.read_bytes(),
    }


# Anti-gaming static checks on the generated script. A script that already
# holds the flag, or that reads it out of an artifact on disk, did not have to
# exploit anything.
#
# Deliberately narrow so legitimate exploit shapes are never caught:
#   - Python-side reads of flag.txt only. `io.sendline(b"cat flag.txt")` --
#     sending that command *to a shell the exploit obtained* -- is the
#     intended solve path for the shell targets and must NOT match, so `cat`
#     is not part of this pattern.
#   - external binary-inspection tooling invoked at exploit runtime. A real
#     pwntools exploit resolves symbols via `ELF()`; it has no reason to shell
#     out to strings/objdump/readelf/xxd at runtime.
_READS_FLAG_FILE_RE = re.compile(
    r"""(open|Path|read_text|read_bytes|readlines|getenv)\s*\([^\n]{0,80}flag\.txt""",
    re.I)
_SCRAPES_BINARY_RE = re.compile(r"""\b(strings|objdump|readelf|xxd|hexdump)\b""")


def inspect_generated_script(script_path: Path, expected_flag: str) -> dict:
    """Look at what the generated script *is*, not just what it printed."""
    if not script_path.is_file():
        return {"present": False}
    try:
        text = script_path.read_text(errors="replace")
    except OSError:
        return {"present": False}
    return {
        "present": True,
        # Decisive: supwngo is never handed the flag, so a literal match means
        # the script read it off disk (or was hand-doctored).
        "contains_flag_literal": expected_flag in text,
        "reads_flag_file_directly": bool(_READS_FLAG_FILE_RE.search(text)),
        "scrapes_binary_with_tooling": bool(_SCRAPES_BINARY_RE.search(text)),
    }


def script_cheat_reason(script_audit: dict) -> str | None:
    """Which anti-gaming check, if any, disqualifies this script."""
    if script_audit.get("contains_flag_literal"):
        return ("the generated script contains this run's secret flag as a "
                "literal -- it got the flag off disk, not by exploiting")
    if script_audit.get("reads_flag_file_directly"):
        return ("the generated script reads flag.txt itself in Python rather "
                "than through a shell it obtained")
    if script_audit.get("scrapes_binary_with_tooling"):
        return ("the generated script shells out to binary-inspection tooling "
                "(strings/objdump/readelf/xxd) at runtime, which can scrape a "
                "compiled-in flag without exploiting anything")
    return None


def independent_verify(script_path: Path, target_dir: Path, expected_flag: str, timeout: float) -> dict:
    """The ONLY source of truth for SUCCESS: actually run the generated
    script fresh and look for the exact flag string in its own output.
    Never trust autopwn's own success/verified claims here."""
    if not script_path.is_file() or script_path.stat().st_size == 0:
        return {
            "ran": False, "timed_out": False, "flag_found": False,
            "shell_proven": False, "stdout_excerpt": "", "stderr_excerpt": "",
        }

    out_b, err_b, timed_out = _run_capture(
        [sys.executable, str(script_path)], target_dir, VERIFY_STDIN,
        max(30.0, timeout * 4),
    )
    out = out_b.decode("utf-8", "replace")
    err = err_b.decode("utf-8", "replace")
    combined = out + err
    return {
        "ran": True,
        "timed_out": timed_out,
        "flag_found": expected_flag in combined,
        # Diagnostic only: did a real command interpreter evaluate our
        # shell-arithmetic marker? Distinguishes a shell-obtained flag from a
        # win()-printed one. Not a SUCCESS gate.
        "shell_proven": bool(SHELL_PROOF_RE.search(combined)),
        "stdout_excerpt": _excerpt(out),
        "stderr_excerpt": _excerpt(err),
    }


def classify(supwngo_json: dict | None, verify: dict, control: dict,
             script_audit: dict) -> tuple[str, str]:
    # Checked first: if the flag is obtainable with no exploit at all, the
    # target simply cannot be scored, however the generated script behaved.
    leaked = control.get("flag_leaked_without_exploit") or []
    if leaked:
        return "VOID", (
            "negative control produced the flag with NO exploit at all "
            f"({', '.join(leaked)}) -- this target cannot distinguish a working "
            "exploit from a no-op script, so it is not scored"
        )

    cheat = script_cheat_reason(script_audit)
    if cheat:
        return "VOID", f"{cheat}, so this result is not scored"

    if verify["flag_found"]:
        how = "via a shell the exploit obtained" if verify.get("shell_proven") else "from the target's own output"
        return "SUCCESS", (
            "independent re-execution of the generated exploit script produced "
            f"this run's secret flag string ({how}), and the negative controls "
            "did not"
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


def run_one(corpus: Corpus, target: dict, timeout: float, results_dir: Path) -> dict:
    slug = target["slug"]
    print(f"=== {slug}  [{target['technique']}, {target['difficulty']}] ===", flush=True)

    base = {
        "slug": slug,
        "technique_intended": target["technique"],
        "difficulty": target["difficulty"],
        "protections": target.get("protections"),
    }

    t0 = time.time()
    secret = mint_secret_flag()
    try:
        build_with_secret(corpus, slug, secret)
    except ProvisionError as e:
        print(f"    -> VOID: {e}", flush=True)
        return {
            **base,
            "elapsed_sec": round(time.time() - t0, 1),
            "status": "VOID",
            "reason": f"target could not be provisioned with a secret flag: {e}",
        }

    expected_flag = corpus.flag_file(slug).read_text().strip()
    if len(expected_flag) < MIN_FLAG_LEN:
        reason = (
            f"flag for {slug} is only {len(expected_flag)} chars "
            f"(< {MIN_FLAG_LEN}); too weak to grep for honestly"
        )
        print(f"    -> VOID: {reason}", flush=True)
        return {**base, "elapsed_sec": round(time.time() - t0, 1),
                "status": "VOID", "reason": reason}

    bp = corpus.binary(slug).resolve()
    target_dir = bp.parent

    # (0) prove the flag is not free BEFORE crediting any script for it
    control = negative_control(corpus, slug, expected_flag, timeout)

    # (1) structured self-report
    rc1, out1, err1, to1 = run_supwngo(bp, timeout, ["--json"])
    supwngo_json = parse_json_result(out1) if out1 else None

    # (2) the actual generated script (only written in non-JSON mode -- see
    #     module docstring)
    script_path = results_dir / f"{slug}_generated.py"
    rc2, out2, err2, to2 = run_supwngo(bp, timeout, ["-o", str(script_path)])

    # (3) genuine independent verification
    script_audit = inspect_generated_script(script_path, expected_flag)
    verify = independent_verify(script_path, target_dir, expected_flag, timeout)

    elapsed = time.time() - t0
    status, reason = classify(supwngo_json, verify, control, script_audit)

    print(f"    -> {status}: {reason}", flush=True)

    return {
        **base,
        # Recorded for audit; it is a throwaway per-run secret, not a credential.
        "secret_flag": expected_flag,
        "elapsed_sec": round(elapsed, 1),
        "negative_control": control,
        "script_audit": script_audit,
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


STATUSES = ("SUCCESS", "PARTIAL", "FAILED", "VOID")


def write_summary(results: list[dict], out_path: Path, timeout: float, corpus: Corpus) -> str:
    total = len(results)
    counts = {s: 0 for s in STATUSES}
    for r in results:
        counts[r["status"]] += 1

    # VOID targets are not measurable, so they are excluded from the rate's
    # denominator and called out separately rather than silently counted as
    # failures or successes.
    scored = total - counts["VOID"]

    lines = []
    lines.append("supwngo benchmark -- run_bench.py results")
    lines.append(f"timestamp: {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"corpus:   {corpus.root}")
    lines.append(f"manifest: {corpus.manifest}")
    lines.append(f"per-attempt timeout passed to autopwn: {timeout}s")
    lines.append("")
    pct = (counts["SUCCESS"] / scored * 100) if scored else 0.0
    lines.append(
        f"OVERALL: {counts['SUCCESS']}/{scored} SUCCESS ({pct:.1f}%) of scorable targets, "
        f"{counts['PARTIAL']} PARTIAL, {counts['FAILED']} FAILED, "
        f"{counts['VOID']} VOID (not scorable) -- {total} targets run"
    )
    lines.append("")
    lines.append(f"{'slug':<26} {'difficulty':<10} {'status':<9} reason")
    lines.append("-" * 100)
    for r in sorted(results, key=lambda r: r["slug"]):
        lines.append(f"{r['slug']:<26} {r['difficulty']:<10} {r['status']:<9} {r['reason']}")
    lines.append("")

    by_diff: dict[str, dict[str, int]] = {}
    for r in results:
        d = by_diff.setdefault(r["difficulty"], {s: 0 for s in STATUSES} | {"total": 0})
        d[r["status"]] += 1
        d["total"] += 1
    lines.append("By difficulty:")
    for diff, d in sorted(by_diff.items()):
        denom = d["total"] - d["VOID"]
        lines.append(
            f"  {diff:<8} {d['SUCCESS']}/{denom} SUCCESS, {d['PARTIAL']} PARTIAL, "
            f"{d['FAILED']} FAILED, {d['VOID']} VOID"
        )
    lines.append("")

    shells = [r["slug"] for r in results
              if r.get("verification", {}).get("shell_proven")]
    if shells:
        lines.append(f"Targets where a real shell was proven: {', '.join(sorted(shells))}")
        lines.append("")

    lines.append("Classification rule (see run_bench.py:classify()):")
    lines.append("  Every target is rebuilt per run with a fresh, unguessable secret")
    lines.append("  flag (compiled in AND written to flag.txt), so a flag string in a")
    lines.append("  script's output cannot have been known in advance.")
    lines.append("  VOID    = a negative control -- the target run with NO exploit at")
    lines.append("            all, same stdin -- produced the flag, or the target could")
    lines.append("            not be built with a real secret. Not scorable either way.")
    lines.append("  SUCCESS = the generated exploit script was independently re-run")
    lines.append("            fresh, its own captured output contained this run's secret")
    lines.append("            flag, and the negative controls did not -- never a match")
    lines.append("            against autopwn's own log/success claims.")
    lines.append("  PARTIAL = autopwn self-reported success (or a successful")
    lines.append("            intermediate attempt) but the independent re-run above")
    lines.append("            did not reproduce the flag.")
    lines.append("  FAILED  = none of the above.")
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
    ap.add_argument("--corpus-root", type=Path, default=DEFAULT_CORPUS_DIR,
                     help=f"Corpus directory of <NN>_<slug>/ targets (default {DEFAULT_CORPUS_DIR})")
    ap.add_argument("--manifest", type=Path, default=DEFAULT_CORPUS_YAML,
                     help=f"Corpus manifest YAML (default {DEFAULT_CORPUS_YAML})")
    args = ap.parse_args()

    corpus = Corpus(root=args.corpus_root.resolve(), manifest=args.manifest.resolve())
    if not corpus.root.is_dir():
        print(f"error: corpus root not found: {corpus.root}", file=sys.stderr)
        sys.exit(1)
    if not corpus.manifest.is_file():
        print(f"error: manifest not found: {corpus.manifest}", file=sys.stderr)
        sys.exit(1)

    all_targets = corpus.targets()
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
    results_dir = corpus.results_root() / ts
    results_dir.mkdir(parents=True, exist_ok=True)

    results = []
    with corpus_lock(corpus):
        for t in targets:
            results.append(run_one(corpus, t, args.timeout, results_dir))

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "timeout": args.timeout,
        "corpus_root": str(corpus.root),
        "manifest": str(corpus.manifest),
        "targets_run": [t["slug"] for t in targets],
        "results": results,
    }
    (results_dir / "report.json").write_text(json.dumps(report, indent=2))
    summary_text = write_summary(results, results_dir / "summary.txt", args.timeout, corpus)

    print()
    print(summary_text)
    print(f"Full report: {results_dir / 'report.json'}")
    print(f"Summary:     {results_dir / 'summary.txt'}")


if __name__ == "__main__":
    main()
