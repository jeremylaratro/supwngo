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
VERIFY_STDIN), and -- the structural guarantee on the TARGET side -- before
scoring, the harness runs the target with no exploit at all under the same
conditions. If the flag shows up there, nothing a script does can be
attributed to exploitation, so the target is scored VOID instead of SUCCESS.
This generalises to any future corpus rather than depending on byte counts in
this one.

BEHAVIOURAL ATTRIBUTION -- what a SUCCESS now means
---------------------------------------------------
A flag string appearing in the output is a *proxy* for exploitation, not
evidence of it, and every false-positive channel this harness has suffered
lived in that gap. Verification is not sandboxed, so the script can read
flag.txt or scrape the binary by any means it likes, and the pattern audit in
inspect_generated_script() is a BYPASSABLE HEURISTIC -- an independent review
defeated an earlier version with several two-line scripts
(`subprocess.run(['cat','flag.txt'])`, `open('flag'+'.txt')`,
`glob.glob('*.txt')`, `Path('.').iterdir()`, `ELF(b).search(b'FLAG{')`), and
`soundness_probes/pure_python_scrape.py` still defeats it in four lines.

So the harness no longer asks *whether* the flag appeared. It asks **who
wrote it**. See benchmark/attribution.py: the script is re-executed under
`strace -f`, the process tree is reconstructed from execve/clone/write, and
a SUCCESS requires the flag to have been written by the TARGET process or a
descendant of it (e.g. `cat` under a shell the exploit obtained). A write by
the script, or by a child of the script, is not credited -- which closes
`cat flag.txt`, `open()`, `glob`, `strings` and `ELF.search` in one move,
including variants nobody has enumerated, because none of them route through
the target's address space.

Consequences for reading a result:
  - "BEHAVIOURALLY ATTRIBUTED" in the reason  => the exploitation event was
    observed. This is the strong case.
  - VOID / script_gamed_the_check             => we WATCHED the script obtain
    the flag without exploiting. Not a guess.
  - "UNWITNESSED" in the reason               => no usable witness (no strace
    or no ptrace permission), so the result falls back to string-match plus
    the bypassable pattern audit and is labelled as such. Never treat a
    missing witness as a negative one. `--strict-attribution` refuses to
    score these at all.

Residual gap, stated plainly: a script could still write the flag into the
target's own output channel deliberately. That takes real effort rather than
a shortcut, and `shell_exec_by_target` corroborates the six shell-based
targets independently, but it is not structurally prevented. Witnessing the
target's control flow directly (a breakpoint on win()) would close it.

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
import ast
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
import fcntl
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:
    print("PyYAML is required (pip install pyyaml)", file=sys.stderr)
    sys.exit(1)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from attribution import (  # noqa: E402
    attribution_verdict, strace_available, witness as attribution_witness)

HERE = Path(__file__).resolve().parent          # benchmark/
REPO_ROOT = HERE.parent                          # worktree root (supwngo/ package lives here)
BUILD_SCRIPT = HERE / "build_all.sh"

DEFAULT_CORPUS_DIR = HERE / "corpus"
DEFAULT_CORPUS_YAML = HERE / "corpus.yaml"

DEFAULT_TIMEOUT = 10.0

# Reps per target. >1 by default because exploit delivery is not deterministic:
# a synchronisation race in a generated chain makes a working exploit fail some
# fraction of the time, and that fraction rises with machine load -- exactly
# when a benchmark is most likely to be running. See run_reps() for the measured
# numbers and for why the answer is two figures rather than one.
DEFAULT_REPS = 5

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
#
# CAVEAT, so this control is not over-read: 512 bytes of 'A' is ALSO the shape
# of a blind stack-overflow payload. So a leak here does not strictly prove
# "any garbage wins" -- it proves "the canonical structure-free first payload
# wins, with no offset, address or gadget computed". Either way the target
# cannot distinguish reasoning from a blob, which is what disqualifies it; but
# the right conclusion is "this target does not discriminate", not "this target
# is readable by accident".
CONTROL_FILLER = b"A" * 512 + b"\n"

# A third benign-input control, for MENU-DRIVEN targets, which the filler blob
# cannot reach: scanf("%d") rejects 'A', so the target bails out before any menu
# option runs. Each probe is an ordinary menu selection plus index 0 -- input any
# user might type, containing no address, offset or gadget. A target that hands
# over the flag for this has no liveness or authorization gate on its read path,
# so it does not require the vulnerability it claims to teach (a use-after-free
# that never needs the free, say).
#
# EACH PROBE RUNS IN A FRESH PROCESS, deliberately. A single concatenated stream
# does not work: one of the options is invariably "exit", and once the walk
# selects it the process is gone and every later option in the stream is never
# tried. That is not hypothetical -- an earlier single-stream version of this
# control reported a clean bill of health for 11_heap_uaf_leak, whose menu
# option 3 with index 0 dumps the flag out of a LIVE chunk, purely because
# option 4 ("exit") came first in the stream.
CONTROL_MENU_PROBES = tuple(b"%d\n0\n" % i for i in range(1, 7))


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
        # A slug with no "_" is a manifest error, not a target: say so rather
        # than dying with an IndexError halfway through a run.
        head, _, tail = slug.partition("_")
        if not tail:
            raise ValueError(
                f"corpus slug {slug!r} is malformed: expected '<NN>_<name>'"
            )
        return tail

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
    # flock, not O_EXCL: the kernel releases it when the process dies for ANY
    # reason, including SIGKILL. An O_EXCL lock file survives a kill and wedges
    # every later run until a human deletes it -- the wrong failure mode for a
    # tree several agents share.
    fd = os.open(str(lock), os.O_CREAT | os.O_RDWR, 0o644)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            print(
                f"error: another run_bench.py holds {lock}.\n"
                f"       Each run rebuilds the targets with a fresh secret flag, so "
                f"concurrent runs over one corpus corrupt each other's results.\n"
                f"       Wait for it to finish, or use a separate --corpus-root.",
                file=sys.stderr,
            )
            os.close(fd)
            sys.exit(1)
        os.truncate(fd, 0)
        os.write(fd, f"pid={os.getpid()} started={datetime.now(timezone.utc).isoformat()}\n".encode())
        yield
    finally:
        # Closing the fd drops the flock. The file itself is left behind
        # deliberately: an empty lock file holds no lock, so it is harmless,
        # and unlinking it would race another waiter's open().
        try:
            os.close(fd)
        except OSError:
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
    # A real check, not an `assert`: asserts vanish under `python -O`, and this
    # bound protects the corpus from being corrupted by its own flag.
    if not MIN_FLAG_LEN <= len(flag) <= MAX_SAFE_FLAG_LEN:
        raise RuntimeError(
            f"minted flag length {len(flag)} outside the corpus contract "
            f"[{MIN_FLAG_LEN}, {MAX_SAFE_FLAG_LEN}] -- see SECRET_FLAG_LEN"
        )
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
    image = bp.read_bytes()
    if src.is_file() and re.search(r"#\s*define\s+FLAG\b", src.read_text()):
        if secret.encode() not in image:
            raise ProvisionError(
                f"{slug} defines its own FLAG but the built binary does not "
                f"contain this run's secret -- -DFLAG did not take effect"
            )

    # The mirror-image check, and the more direct proof of what this is for:
    # the OLD public constant must be gone. Catches a second flag use-site, a
    # partially-applied -DFLAG, or a stale object file that the
    # secret-is-present test alone would happily pass.
    if b"FLAG{supwngo_bench" in image:
        raise ProvisionError(
            f"{slug}'s built binary still contains the legacy public flag "
            f"constant 'FLAG{{supwngo_bench...}}' -- the predictable flag was "
            f"not fully displaced by this run's secret"
        )


def run_supwngo(binary_abs: Path, timeout: float, extra_args: list[str],
                tmpdir: Path | None = None):
    """Invoke the real supwngo autopwn CLI as a subprocess. Returns
    (returncode_or_None, stdout, stderr, wall_timed_out)."""
    env = _script_env(tmpdir)
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


def _script_env(tmpdir: Path | None = None) -> dict:
    """The environment a re-executed script sees.

    Shared with the attribution witness deliberately: if the traced run and the
    plain run did not see identical environments, a disagreement between them
    would be the harness's fault rather than a finding.
    """
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    if tmpdir is not None:
        # Private per-target temp space, so parallel workers cannot collide on
        # a temp name or read each other's leftovers.
        env["TMPDIR"] = str(tmpdir)
    return env


def _run_capture(argv: list[str], cwd: Path, stdin_bytes: bytes, wall_timeout: float,
                 tmpdir: Path | None = None):
    env = _script_env(tmpdir)
    try:
        proc = subprocess.run(
            argv, input=stdin_bytes, cwd=str(cwd), env=env,
            capture_output=True, timeout=wall_timeout,
        )
        return proc.stdout or b"", proc.stderr or b"", False
    except subprocess.TimeoutExpired as e:
        return (e.stdout or b""), (e.stderr or b""), True


def negative_control(corpus: Corpus, slug: str, expected_flag: str, timeout: float,
                     tmpdir: Path | None = None) -> dict:
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
            [str(bp)], tdir, stdin_bytes, wall_timeout, tmpdir=tmpdir
        )
        text = (out_b + err_b).decode("utf-8", "replace")
        controls[name] = {
            "flag_found": expected_flag in text,
            "timed_out": timed_out,
            "excerpt": _excerpt(text, 600),
        }

    # Menu probes: one fresh process each, so an "exit" option cannot mask the
    # options after it. Records which probe won, since that is what a corpus
    # author needs in order to find the missing gate.
    menu_hits: list[str] = []
    menu_excerpt = ""
    menu_timed_out = False
    for stdin_bytes in CONTROL_MENU_PROBES:
        out_b, err_b, timed_out = _run_capture(
            [str(bp)], tdir, stdin_bytes, wall_timeout, tmpdir=tmpdir
        )
        text = (out_b + err_b).decode("utf-8", "replace")
        menu_timed_out = menu_timed_out or timed_out
        if expected_flag in text:
            menu_hits.append(stdin_bytes.decode().replace("\n", "\\n"))
            if not menu_excerpt:
                menu_excerpt = _excerpt(text, 600)
    controls["bare_run_menu_walk"] = {
        "flag_found": bool(menu_hits),
        "winning_probes": menu_hits,
        "timed_out": menu_timed_out,
        "excerpt": menu_excerpt,
    }

    # Third control, and the one that matters most for win()-style targets:
    # actually perform the scrape a recon step would perform, rather than
    # reasoning about whether it would work. `strings <bin> | grep FLAG{` is
    # routine first-step recon for an exploitation framework, so this channel
    # can be walked into without anyone intending to cheat.
    scrape_hits: list[str] = []
    image = bp.read_bytes()
    if expected_flag.encode() in image:
        scrape_hits.append("elf_image_substring")
    strings_bin = shutil.which("strings")
    if strings_bin:
        out_b, _e, _t = _run_capture([strings_bin, str(bp)], tdir, b"", wall_timeout,
                                     tmpdir=tmpdir)
        if expected_flag.encode() in out_b:
            scrape_hits.append("strings_output")

    leaked = sorted(n for n, c in controls.items() if c["flag_found"])
    return {
        "controls": controls,
        "flag_leaked_without_exploit": leaked,
        # Measured, not assumed: which scrape channels actually yield this
        # run's secret. Reported as WEAK ATTRIBUTION (see classify) and, under
        # --strict-attribution, promoted to VOID.
        "flag_scrapeable_without_exploit": scrape_hits,
        # Documented residual limitation, not a pass/fail gate. win()-style
        # targets print a compiled-in flag, so the secret is inside the
        # binary image and a script could scrape it with `strings` instead of
        # exploiting. Verification is not sandboxed (the script runs as the
        # same user, so flag.txt is readable too), so the harness cannot
        # prevent this -- it inspects the generated script instead (see
        # inspect_generated_script) and records the exposure here.
        "flag_statically_extractable_from_binary": expected_flag.encode() in bp.read_bytes(),
    }


# What a VOID means. Four very different causes, kept distinct because they
# call for opposite responses (fix the corpus / fix supwngo / fix the build).
VOID_CAUSES = {
    "harness_stdin_solves_target": "instrument fault -- the harness's own stdin reached the flag",
    "corpus_trivially_solvable": "corpus fault -- structure-free filler reached the flag",
    "corpus_missing_liveness_gate": "corpus fault -- a benign menu walk reached the flag",
    "unwitnessed_success": "no behavioural witness -- scored only under --strict-attribution",
    "script_gamed_the_check": "supwngo finding -- the script obtained the flag without exploiting",
    "provisioning_failed": "BUILD/INFRA FAULT -- the flag could not be made a real secret",
    "harness_error": "HARNESS FAULT -- run_bench.py itself raised on this target",
}
# Causes that mean "the whole run is untrustworthy", not "skip this target".
FATAL_VOID_CAUSES = {"provisioning_failed", "harness_error"}


# Anti-gaming static checks on the generated script.
#
# IMPORTANT, AND A KNOWN WEAKNESS: this is a BYPASSABLE HEURISTIC, not a
# guarantee. Verification is not sandboxed, so the script runs as the same user
# and can read flag.txt and the target binary by any means it likes. An
# independent review defeated an earlier version of these checks with several
# two-line scripts (`subprocess.run(['cat','flag.txt'])`, `open('flag'+'.txt')`,
# `glob.glob('*.txt')`, `Path('.').iterdir()`, `ELF(bin).search(b'FLAG{')`).
# The patterns below close the ones we know about; string-built or
# directory-walked paths remain out of reach of any regex.
#
# The only robust fix is behavioural attribution -- assert that the TARGET
# process did the thing (win() entered, or execve("/bin/sh") in a target
# descendant) rather than that a flag string appeared in some output. That is
# the recommended next step; see
# docs/reports/HARNESS-SOUNDNESS-AUDIT-23SEP2026.md.
#
# Kept narrow enough not to catch legitimate exploit shapes:
#   - `io.sendline(b"cat flag.txt")` and `shellcraft.cat("flag.txt")` send that
#     command *to a shell the exploit obtained* -- the intended solve path for
#     the shell targets -- so a bare `cat flag.txt` string must NOT match. Only
#     a local *process spawn* that cats it does.
#   - `hexdump` is deliberately absent: pwntools' own `hexdump()` is
#     re-exported by supwngo.utils, and a real exploit printing a leaked
#     buffer with it is entirely legitimate.
_READS_FLAG_FILE_RE = re.compile(
    r"""(open|Path|read_text|read_bytes|readlines|getenv)\s*\([^\n]{0,80}flag\.txt""",
    re.I)
# A local subprocess that reads the flag file (as opposed to bytes SENT to a
# tube). Matches the shell-out forms, e.g. subprocess.run(['cat','flag.txt']).
#
# The spawn construct must be explicit -- no bare `run`/`cat` alternatives --
# because `io.sendline(b"cat flag.txt")` is the legitimate solve path for the
# six shell targets and must never match. Newlines are not crossed, so a
# `process()` call on an earlier line cannot combine with a later `cat`.
_SPAWNS_READER_RE = re.compile(
    r"""(subprocess\.(run|call|check_output|check_call|Popen)"""
    r"""|os\.(system|popen|exec\w+|spawn\w+)"""
    r"""|\bPopen\s*\()"""
    r"""[^\n]{0,120}\b(cat|head|tail|od|base64|grep|less|more|strings|xxd)\b""",
    re.I)
# External binary-inspection tooling at exploit runtime, or pwntools-level
# scraping of the target image for the flag. A real exploit resolves symbols
# via ELF(); it does not search the binary for FLAG{.
_SCRAPES_BINARY_RE = re.compile(
    r"""\b(strings|objdump|readelf|xxd)\b|\.(search|string)\s*\([^\n]{0,40}FLAG""")


def inspect_generated_script(script_path: Path, expected_flag: str) -> dict:
    """Look at what the generated script *is*, not just what it printed.

    Only executable code is scanned: comments and docstrings are stripped
    first, because supwngo interpolates executor notes and failure reasons into
    the generated artifact's docstring, and a note mentioning "objdump" would
    otherwise disqualify an honest result.
    """
    if not script_path.is_file():
        return {"present": False}
    try:
        text = script_path.read_text(errors="replace")
    except OSError:
        return {"present": False}

    code = _strip_comments_and_docstrings(text)
    return {
        "present": True,
        # Decisive: supwngo is never handed the flag, so a literal match means
        # the script read it off disk (or was hand-doctored).
        "contains_flag_literal": expected_flag in code,
        "reads_flag_file_directly": bool(_READS_FLAG_FILE_RE.search(code)),
        "spawns_local_flag_reader": bool(_SPAWNS_READER_RE.search(code)),
        "scrapes_binary_with_tooling": bool(_SCRAPES_BINARY_RE.search(code)),
    }


def _strip_comments_and_docstrings(text: str) -> str:
    """Best-effort reduction of a script to just its executable code."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        # Not parseable (a template with placeholders, say): fall back to
        # dropping `#` comments only, and accept the extra noise.
        return "\n".join(line.split("#")[0] for line in text.splitlines())

    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = getattr(node, "body", None) or []
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                docstrings.add(id(body[0]))
    kept = [n for n in tree.body if id(n) not in docstrings]
    try:
        return ast.unparse(ast.Module(body=kept, type_ignores=[]))
    except Exception:
        return text


def script_cheat_reason(script_audit: dict) -> str | None:
    """Which anti-gaming check, if any, disqualifies this script."""
    if script_audit.get("contains_flag_literal"):
        return ("the generated script contains this run's secret flag as a "
                "literal -- it got the flag off disk, not by exploiting")
    if script_audit.get("reads_flag_file_directly"):
        return ("the generated script reads flag.txt itself in Python rather "
                "than through a shell it obtained")
    if script_audit.get("spawns_local_flag_reader"):
        return ("the generated script spawns a local process to read the flag "
                "file instead of exploiting the target")
    if script_audit.get("scrapes_binary_with_tooling"):
        return ("the generated script shells out to binary-inspection tooling "
                "(strings/objdump/readelf/xxd) at runtime, which can scrape a "
                "compiled-in flag without exploiting anything")
    return None


def independent_verify(script_path: Path, target_dir: Path, expected_flag: str,
                       timeout: float, tmpdir: Path | None = None) -> dict:
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
        max(30.0, timeout * 4), tmpdir=tmpdir,
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


def scrape_channels(control: dict) -> list[str]:
    """Which no-exploit scrape channels actually yielded this run's secret.

    Behavioural (`strings` was really run) with the plain image substring test
    as a floor, so a missing `strings` binary cannot silently downgrade the
    check to "no exposure found".
    """
    hits = list(control.get("flag_scrapeable_without_exploit") or [])
    if not hits and control.get("flag_statically_extractable_from_binary"):
        hits = ["elf_image_substring"]
    return hits


def classify(supwngo_json: dict | None, verify: dict, control: dict,
             script_audit: dict, strict_attribution: bool = False,
             attribution: dict | None = None) -> tuple[str, str, str | None]:
    """Returns (status, reason, void_cause).

    void_cause is machine-readable and distinguishes the four very different
    things a VOID can mean; see VOID_CAUSES. Collapsing them into one bucket
    would let an infra regression (the secret stopping being injected, say)
    read as an improved score, because it shrinks the denominator.
    """
    # Checked first: the harness's own injected stdin reached the flag, so the
    # instrument is solving the target. Nothing a script does is attributable.
    leaked = control.get("flag_leaked_without_exploit") or []
    if "bare_run_verify_stdin" in leaked:
        return "VOID", (
            "the harness's own injected verification stdin produced the flag with "
            "NO exploit at all -- the instrument is solving this target, so it "
            "cannot be scored"
        ), "harness_stdin_solves_target"

    if "bare_run_filler" in leaked:
        return "VOID", (
            "512 bytes of structure-free filler produced the flag with no offset, "
            "address or gadget involved -- this target does not discriminate a "
            "reasoned exploit from a blind blob, so it is not scored"
        ), "corpus_trivially_solvable"

    if "bare_run_menu_walk" in leaked:
        return "VOID", (
            "walking the menu with small integers produced the flag -- the read "
            "path has no liveness or authorization gate, so the flag is reachable "
            "without the vulnerability this target is supposed to require, and it "
            "is not scored"
        ), "corpus_missing_liveness_gate"

    # Only cheating if it actually produced the flag. Otherwise the target just
    # FAILED and must stay in the denominator -- voiding a failure would
    # silently inflate the success rate.
    if verify["flag_found"]:
        # PRIMARY EVIDENCE: who actually wrote the flag. This is the exploitation
        # event rather than a symptom of it, so it is consulted before the
        # pattern audit and overrides it in both directions.
        verdict, why = attribution_verdict(attribution or {})

        if verdict == "credited":
            return "SUCCESS", (
                "BEHAVIOURALLY ATTRIBUTED: " + why + ", so the flag was produced "
                "by exploiting the target rather than read by the script; the "
                "negative controls produced nothing"
            ), None

        if verdict == "not_credited":
            # Not a heuristic guess -- we watched the syscalls. This is a
            # finding about the generated script, not about the corpus.
            return "VOID", (
                "the generated script produced the flag WITHOUT exploiting the "
                f"target: {why}. Not scored"
            ), "script_gamed_the_check"

        # verdict == "inconclusive" (or the witness disagreed with the plain
        # run, e.g. a flaky exploit): fall back to the weaker string-match plus
        # pattern-audit path, and label the result as unwitnessed. Never treat a
        # missing witness as a negative one.
        cheat = script_cheat_reason(script_audit)
        if cheat:
            return "VOID", f"{cheat}, so this result is not scored", "script_gamed_the_check"

        if strict_attribution:
            return "VOID", (
                f"no behavioural witness could be obtained ({why}), and "
                "--strict-attribution refuses to score a SUCCESS that rests only "
                "on a flag string appearing plus a bypassable pattern audit"
            ), "unwitnessed_success"

        how = ("via a shell the exploit obtained" if verify.get("shell_proven")
               else "from the target's own output")
        reason = (
            "independent re-execution of the generated exploit script produced "
            f"this run's secret flag string ({how}), and the negative controls "
            "did not"
        )
        # No witness, so we are back to inference. Say so, and say how weak the
        # inference is: where the secret is also sitting in the binary image
        # (unavoidable for win()-style targets, which must puts() it) a script
        # could have scraped it, and only the bypassable pattern audit stands in
        # the way. Where the image holds no flag, it can only have come from the
        # target's runtime, which is at least a structural argument.
        channels = scrape_channels(control)
        reason += (
            f" [UNWITNESSED: {why}"
            + (f"; and this run's secret is readable with no exploit via "
               f"{', '.join(channels)}, so this rests on the bypassable pattern "
               "audit rather than a structural guarantee" if channels else "")
            + "]"
        )
        return "SUCCESS", reason, None

    claimed_success = bool(supwngo_json and supwngo_json.get("success"))
    # AttemptRecord.to_dict() emits {"outcome": Outcome.name}, i.e. "SUCCESS" --
    # there is no "result" key (see supwngo/exploit/pipeline/contracts.py).
    # Reading the wrong key here made this branch dead code, so a run where a
    # technique verified but engine.successful was False scored FAILED instead
    # of PARTIAL.
    any_attempt_success = bool(
        supwngo_json
        and any(str(a.get("outcome", "")).upper() == "SUCCESS"
                for a in supwngo_json.get("attempts", []) or [])
    )
    if claimed_success or any_attempt_success:
        return "PARTIAL", (
            "autopwn self-reported success (or a successful intermediate attempt), "
            "but independently re-running the generated script did not reproduce "
            "the flag"
        ), None
    return "FAILED", (
        "no successful attempt reported by autopwn, and independent re-execution "
        "did not produce the flag"
    ), None


def run_one(corpus: Corpus, target: dict, timeout: float, results_dir: Path,
            strict_attribution: bool = False, tmpdir: Path | None = None,
            echo: bool = True) -> dict:
    slug = target["slug"]

    def say(msg: str) -> None:
        # Suppressed under parallelism: interleaved per-step lines from several
        # workers splice into misleading output. run_targets() prints one
        # authoritative line per target on completion instead.
        if echo:
            print(msg, flush=True)

    say(f"=== {slug}  [{target['technique']}, {target['difficulty']}] ===")

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
        say(f"    -> VOID: {e}")
        return {
            **base,
            "elapsed_sec": round(time.time() - t0, 1),
            "status": "VOID",
            "reason": f"target could not be provisioned with a secret flag: {e}",
            "void_cause": "provisioning_failed",
        }

    expected_flag = corpus.flag_file(slug).read_text().strip()
    if len(expected_flag) < MIN_FLAG_LEN:
        reason = (
            f"flag for {slug} is only {len(expected_flag)} chars "
            f"(< {MIN_FLAG_LEN}); too weak to grep for honestly"
        )
        say(f"    -> VOID: {reason}")
        return {**base, "elapsed_sec": round(time.time() - t0, 1),
                "status": "VOID", "reason": reason,
                "void_cause": "provisioning_failed"}

    bp = corpus.binary(slug).resolve()
    target_dir = bp.parent

    # (0) prove the flag is not free BEFORE crediting any script for it
    control = negative_control(corpus, slug, expected_flag, timeout, tmpdir=tmpdir)

    # (1) structured self-report
    t_probe0 = time.time()
    rc1, out1, err1, to1 = run_supwngo(bp, timeout, ["--json"], tmpdir=tmpdir)
    probe_duration = time.time() - t_probe0
    supwngo_json = parse_json_result(out1) if out1 else None

    # (2) the actual generated script (only written in non-JSON mode -- see
    #     module docstring)
    script_path = results_dir / f"{slug}_generated.py"
    t_scriptgen0 = time.time()
    rc2, out2, err2, to2 = run_supwngo(bp, timeout, ["-o", str(script_path)],
                                       tmpdir=tmpdir)
    script_generation_duration = time.time() - t_scriptgen0

    # (3) genuine independent verification
    script_audit = inspect_generated_script(script_path, expected_flag)
    verify = independent_verify(script_path, target_dir, expected_flag, timeout,
                                tmpdir=tmpdir)

    # (4) behavioural attribution: re-execute under strace and establish WHO
    # wrote the flag. Only run when the plain verification actually produced the
    # flag -- there is nothing to attribute otherwise, and tracing every failing
    # target would double the cost of a mostly-failing run for no information.
    attribution: dict = {"available": False,
                         "unavailable_reason": "not run (no flag to attribute)"}
    if verify["flag_found"]:
        attribution = attribution_witness(
            script_path=script_path,
            target_dir=target_dir,
            target_binary=bp,
            expected_flag=expected_flag,
            stdin_bytes=VERIFY_STDIN,
            timeout=timeout,
            env=_script_env(tmpdir),
            python=sys.executable,
            trace_dir=results_dir / f"{slug}_attribution",
        )

    elapsed = time.time() - t0
    status, reason, void_cause = classify(supwngo_json, verify, control, script_audit,
                                          strict_attribution=strict_attribution,
                                          attribution=attribution)

    say(f"    -> {status}: {reason}")

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
            "duration_sec": round(probe_duration, 3),
            "parsed": supwngo_json,
            "stderr_tail": (err1 or "")[-1500:],
        },
        "autopwn_script_generation": {
            "returncode": rc2,
            "wall_timed_out": to2,
            "duration_sec": round(script_generation_duration, 3),
            "stderr_tail": (err2 or "")[-1500:],
        },
        "verification": verify,
        "attribution": attribution,
        "status": status,
        "reason": reason,
        "void_cause": void_cause,
    }


def _default_jobs() -> int:
    """One worker per core, capped.

    Each worker spends most of its wall time waiting on `autopwn`, which is
    itself CPU-hungry (angr/Z3), so the useful parallelism is bounded by cores
    rather than by the number of targets. The cap keeps a big box from
    thrashing on memory, which angr will happily do.
    """
    return max(1, min(os.cpu_count() or 1, 8))


def effective_jobs(requested: int, n_targets: int) -> int:
    """The worker count the run will ACTUALLY use.

    `requested <= 0` means "decide for me". The result is clamped to the number
    of targets because run_targets() goes serial for a single target, and a
    report.json claiming 8 workers for a 1-target run would misdescribe its own
    provenance. Never returns less than 1, so a zero-target run still records a
    sane value rather than 0.
    """
    want = requested if requested > 0 else _default_jobs()
    return max(1, min(want, n_targets or 1))


def run_reps(corpus: Corpus, target: dict, timeout: float, results_dir: Path,
             strict_attribution: bool, reps: int, tmpdir: Path | None = None,
             echo: bool = True) -> dict:
    """Run one target `reps` times and report BOTH solved and reliability.

    WHY REPS ARE NOT OPTIONAL
    -------------------------
    Exploit delivery is not deterministic. A synchronisation race in the
    generated script -- a send landing before the target is ready, a recv that
    sometimes misses its prompt -- makes a chain that genuinely works fail some
    fraction of the time, for reasons that have nothing to do with whether the
    framework can exploit the target.

    Be careful with the size of that fraction -- it is load-dependent, not a
    constant, and the first estimate made here was wrong. One probe's genuine
    ret2plt exploit was measured at 0/40 failures unloaded and 0/20 under
    strace, but 4/96 (4.2%) under 24-way contention. Assuming per-target
    independence at that rate, 13 targets give roughly a 1-in-2 chance that at
    least one flakes on a loaded box and much less on an idle one. That does not
    justify claiming a single rep usually understates the score, and it is more
    than enough to justify not betting a corpus-wide figure on one roll -- a
    benchmark tends to be run exactly when the machine is busy.

    Two numbers are therefore reported and neither is "the score" alone:

      solved       credited in AT LEAST ONE rep -- can this be exploited at all
      reliability  k/N reps credited            -- how dependably

    Reporting best-of-N without reliability would be gaming the metric.
    Reporting a single rep understates real capability. Together they are
    honest, and the pair is genuinely more informative: 5/5 and 1/5 are
    different claims about a target, and real exploitation is probabilistic
    anyway under ASLR and heap layout.

    Reps run SEQUENTIALLY for one target even under parallelism, because each
    rep rebuilds the binary with a fresh secret in the target's own directory --
    two concurrent reps of the same target would race on that rebuild.
    """
    # With reps > 1, run_one's own per-step chatter is suppressed: five copies of
    # it per target buries the result. But the reps loop must then say WHICH
    # target it is reporting on -- otherwise a serial multi-rep run prints a
    # stream of bare "-> FAILED reliability=0/5" lines and the reader cannot tell
    # them apart. So print the header and one line per rep here instead.
    chatty = echo and reps > 1
    if chatty:
        print(f"=== {target['slug']}  [{target['technique']}, "
              f"{target['difficulty']}]  x{reps} reps ===", flush=True)

    attempts: list[dict] = []
    for i in range(1, reps + 1):
        rep_dir = results_dir if reps == 1 else results_dir / f"rep{i}"
        rep_dir.mkdir(parents=True, exist_ok=True)
        r = run_one(corpus, target, timeout, rep_dir,
                    strict_attribution=strict_attribution,
                    tmpdir=tmpdir, echo=echo and reps == 1)
        attempts.append(r)
        if chatty:
            print(f"  rep {i}/{reps}: {r['status']}: {r['reason'][:140]}",
                  flush=True)
        # A VOID is a property of the corpus or the instrument, not a dice
        # roll: the negative controls and provisioning checks are
        # deterministic. So one VOID settles the target and further reps would
        # only burn time re-proving it.
        if r["status"] == "VOID":
            break

    if reps == 1:
        only = dict(attempts[0])
        only["reps"] = 1
        only["reps_credited"] = 1 if only["status"] == "SUCCESS" else 0
        only["reliability"] = None      # not measured with a single rep
        return only

    last = attempts[-1]
    void = next((a for a in attempts if a["status"] == "VOID"), None)
    credited = sum(1 for a in attempts if a["status"] == "SUCCESS")
    ran = len(attempts)

    # secret_flag per rep is NOT optional detail. Every rep rebuilds the target
    # with a FRESH secret, and the aggregate can only carry one of them, so
    # without this the verdicts for reps 2..N cannot be re-checked against their
    # own archived strace.log -- an auditor holding rep3's trace would not know
    # which string to look for, and a wrong verdict there would be undetectable
    # after the fact. Observed for real: a cross-check of all 17 archived traces
    # reported reps 2-5 as "no_flag" purely because it was matching rep1's
    # secret against rep2-5's traces.
    trimmed = [{"rep": i + 1, "status": a["status"], "reason": a["reason"],
                "void_cause": a.get("void_cause"),
                "secret_flag": a.get("secret_flag"),
                "elapsed_sec": a.get("elapsed_sec")}
               for i, a in enumerate(attempts)]

    if void is not None:
        agg = dict(void)
    elif credited:
        agg = dict(next(a for a in attempts if a["status"] == "SUCCESS"))
        agg["reason"] = f"{agg['reason']} [reliability {credited}/{ran} reps]"
    elif any(a["status"] == "PARTIAL" for a in attempts):
        agg = dict(next(a for a in attempts if a["status"] == "PARTIAL"))
    else:
        agg = dict(last)

    agg.update({
        "reps": ran,
        "reps_requested": reps,
        "reps_credited": credited,
        # agg inherits elapsed_sec from ONE representative attempt, so summing
        # elapsed_sec across a multi-rep report understates the run's real cost
        # by roughly the rep count -- which is exactly the mistake it invites.
        # Record what the target actually cost; per-rep times stay in attempts[].
        "elapsed_sec_total": round(
            sum(a.get("elapsed_sec") or 0 for a in attempts), 1),
        # None rather than 0.0 when a VOID cut the reps short: a target we
        # stopped measuring has no reliability figure, and printing 0/1 would
        # read as "tried and failed".
        "reliability": (credited / ran) if void is None else None,
        "attempts": trimmed,
    })
    if chatty:
        # Name the target again: with 5 reps between headers the header has
        # scrolled by the time the verdict lands.
        print(f"  -> {target['slug']}: {agg['status']}  "
              f"solved={bool(credited)} reliability={credited}/{ran}",
              flush=True)
    return agg


def run_targets(corpus: Corpus, targets: list[dict], timeout: float,
                results_dir: Path, strict_attribution: bool, jobs: int,
                reps: int = 1) -> list[dict]:
    """Run targets, optionally in parallel, and return results in MANIFEST
    ORDER regardless of completion order.

    Parallelism is safe here because a target's entire footprint is confined to
    its own directory: the rebuild writes only `corpus/<slug>/{binary,flag.txt}`,
    verification runs with cwd set there and reads that flag.txt, and the
    generated script, strace log and attribution artifacts are all named per
    slug under results_dir. Each worker additionally gets a PRIVATE TMPDIR so
    two targets cannot collide on a temp name.

    `~/.supwngo/libcs` stays shared deliberately: it is a read-mostly download
    cache keyed by distinct filenames, and isolating it would make several
    targets re-fetch libc over the network, trading a real flakiness risk for a
    theoretical one. `autopwn` does not touch the SQLite database that would
    otherwise be shared state (that lives on the `libc-id` path).

    Output is buffered per target and flushed as one block, so interleaved
    workers cannot produce spliced, misleading log lines.
    """
    if jobs <= 1 or len(targets) <= 1:
        return [_run_one_isolated(corpus, t, timeout, results_dir,
                                  strict_attribution, echo=True, reps=reps)
                for t in targets]

    print(f"running {len(targets)} targets x {reps} rep(s) with {jobs} parallel "
          f"workers (per-target isolation: private cwd + TMPDIR)", flush=True)

    by_slug: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = {
            pool.submit(_run_one_isolated, corpus, t, timeout, results_dir,
                        strict_attribution, False, reps): t
            for t in targets
        }
        done = 0
        for fut in as_completed(futures):
            t = futures[fut]
            res = fut.result()          # never raises; see _run_one_isolated
            by_slug[t["slug"]] = res
            done += 1
            rel = _reliability_str(res)
            print(f"[{done}/{len(targets)}] {t['slug']:<24} {res['status']}"
                  f"{rel}: {res['reason'][:150]}", flush=True)

    return [by_slug[t["slug"]] for t in targets]


def _reliability_str(res: dict) -> str:
    """` (k/N reps)` when reliability was measured, else empty."""
    if res.get("reliability") is None:
        return ""
    return f" ({res['reps_credited']}/{res['reps']} reps)"


def _run_one_isolated(corpus: Corpus, target: dict, timeout: float,
                      results_dir: Path, strict_attribution: bool,
                      echo: bool, reps: int = 1) -> dict:
    """run_one() with a private TMPDIR and no way to take the run down.

    A crash or hang in one target must never alter another target's verdict --
    an infrastructure fault that silently removed targets would shrink the
    denominator and read as a score improvement, which is the exact failure
    mode the provisioning fix exists to prevent. So an unexpected exception
    becomes a FATAL VOID for that target: recorded, attributed to the harness
    rather than to supwngo, and sufficient to withhold the whole run's rate.
    """
    slug = target["slug"]
    # Threads share os.environ, so TMPDIR is threaded through to each spawned
    # child explicitly rather than set globally -- mutating os.environ here
    # would race between workers and hand one target another's temp dir.
    tmpdir = results_dir / f"{slug}_tmp"
    tmpdir.mkdir(parents=True, exist_ok=True)
    try:
        return run_reps(corpus, target, timeout, results_dir,
                        strict_attribution=strict_attribution, reps=reps,
                        tmpdir=tmpdir, echo=echo)
    except Exception as e:  # noqa: BLE001 -- deliberately total
        reason = (f"the HARNESS itself failed on this target "
                  f"({type(e).__name__}: {e}); this is an instrument fault, "
                  f"not a measurement of supwngo")
        print(f"    -> VOID (harness error): {reason}", flush=True)
        return {
            "slug": slug,
            "technique_intended": target.get("technique"),
            "difficulty": target.get("difficulty", "unknown"),
            "protections": target.get("protections"),
            "status": "VOID",
            "reason": reason,
            "void_cause": "harness_error",
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
    voids = [r for r in results if r["status"] == "VOID"]
    fatal = [r for r in voids if r.get("void_cause") in FATAL_VOID_CAUSES]
    pct = (counts["SUCCESS"] / scored * 100) if scored else 0.0

    if fatal:
        # A build/infra fault shrinks the denominator, which makes the RATE GO
        # UP. Refuse to publish a rate at all rather than let a regression read
        # as an improvement.
        lines.append("!! RUN NOT TRUSTWORTHY -- NO SCORE PUBLISHED !!")
        lines.append(
            f"   {len(fatal)} target(s) could not be provisioned with a real secret "
            f"flag, which is a build/infra fault, not a result:")
        for r in fatal:
            lines.append(f"     - {r['slug']}: {r['reason']}")
        lines.append("   Excluding these would shrink the denominator and inflate the")
        lines.append("   success rate, so the rate is withheld. Fix the build and re-run.")
        lines.append("")
        # Withheld means withheld: print the raw counts a reader needs to debug
        # the build, but never a rate. A printed rate gets quoted downstream no
        # matter what banner sits above it.
        lines.append(
            f"OVERALL: RATE WITHHELD -- raw counts only: {counts['SUCCESS']} SUCCESS, "
            f"{counts['PARTIAL']} PARTIAL, {counts['FAILED']} FAILED, "
            f"{counts['VOID']} VOID out of {total} run."
        )
    elif scored == 0:
        lines.append("OVERALL: no scorable targets -- no success rate can be computed.")
    else:
        lines.append(
            f"OVERALL: {counts['SUCCESS']}/{scored} SUCCESS ({pct:.1f}%), "
            f"{counts['PARTIAL']} PARTIAL, {counts['FAILED']} FAILED"
        )
        # With reps > 1 this headline is a BEST-OF-N figure, and the headline is
        # the number that gets quoted downstream -- so it has to say so itself.
        # Deferring the disclosure to the SOLVED vs RELIABILITY block below is
        # not enough: nobody who quotes "7.7%" reads that far.
        n_reps = max((r.get("reps_requested") or r.get("reps") or 1)
                     for r in results)
        if n_reps > 1:
            wins = [r for r in results if r["status"] == "SUCCESS"]
            solid = sum(1 for r in wins
                        if r.get("reliability") is not None
                        and r["reps_credited"] == r["reps"])
            flaky = sum(1 for r in wins
                        if r.get("reliability") is not None
                        and 0 < r["reps_credited"] < r["reps"])
            lines.append(
                f"         SUCCESS = credited in AT LEAST 1 of {n_reps} reps, i.e. "
                f"this rate is BEST-OF-{n_reps}, not a per-attempt rate.")
            lines.append(
                f"         Of those {len(wins)} success(es): {solid} fully "
                f"reliable ({n_reps}/{n_reps}), {flaky} INTERMITTENT. A "
                f"best-of-{n_reps} rate quoted")
            lines.append(
                "         without that split overstates what the framework does "
                "per attempt.")
        # Both denominators, always. /scored is the honest rate; /total keeps it
        # comparable across runs even as the VOID set changes.
        lines.append(
            f"         also {counts['SUCCESS']}/{total} of ALL targets run "
            f"({counts['SUCCESS'] / total * 100:.1f}%) -- the {counts['SUCCESS']}/{scored} "
            f"denominator EXCLUDES {counts['VOID']} VOID target(s)."
        )
    lines.append("")

    # Spelled out here, not just in a doc: a VOID target counts as neither a
    # success nor a failure, so the denominator shrinks. Without this block a
    # later reader could see "1/14" against a 15-target corpus and assume a
    # target silently vanished.
    if voids:
        lines.append(f"EXCLUDED FROM SCORING -- {len(voids)} VOID target(s), "
                     f"counted as NEITHER success NOR failure:")
        for r in voids:
            cause = r.get("void_cause") or "unknown"
            lines.append(f"  - {r['slug']}  [{cause}: {VOID_CAUSES.get(cause, '?')}]")
            lines.append(f"      {r['reason']}")
        lines.append("")
        lines.append("  VOID is detected per run from the negative controls, the script")
        lines.append("  audit and the provisioning checks -- there is NO hardcoded")
        lines.append("  exclusion list, so a target that becomes benign-input-solvable in")
        lines.append("  any future corpus is caught automatically. The causes mean")
        lines.append("  different things and need different responses:")
        for cause, meaning in VOID_CAUSES.items():
            lines.append(f"    {cause:<30} {meaning}")
        lines.append("    -> corpus_* causes: fix or retire the target; never 'improve' its score.")
        lines.append("    -> script_gamed_the_check: a finding about supwngo, not the corpus.")
        lines.append("    -> provisioning_failed: a build fault; the whole run is void.")
        lines.append("")
    else:
        lines.append("No VOID targets: every target run was scorable.")
        lines.append("")

    # Not all SUCCESSes are equally well evidenced and the summary must never
    # present them as if they were. WITNESSED means we observed the target's own
    # process tree write the flag; UNWITNESSED means we only saw the string.
    successes = [r for r in results if r["status"] == "SUCCESS"]
    witnessed = [r for r in successes
                 if (r.get("attribution") or {}).get("flag_disclosed_by_target")]
    unwitnessed = [r for r in successes if r not in witnessed]
    if successes:
        lines.append(f"EVIDENCE FOR THE {len(successes)} SUCCESS(es) -- "
                     f"{len(witnessed)} behaviourally witnessed, "
                     f"{len(unwitnessed)} unwitnessed:")
        for r in witnessed:
            att = r["attribution"]
            shell = " (target exec'd a shell)" if att.get("shell_proven") else ""
            chain = (att.get("credited_writers") or [{}])[0].get("chain", "?")
            lines.append(f"  WITNESSED    {r['slug']}: flag written by {chain}{shell}")
        for r in unwitnessed:
            att = r.get("attribution") or {}
            why = att.get("unavailable_reason", "no witness")
            chans = scrape_channels(r.get("negative_control") or {})
            extra = (f"; secret also scrapeable via {','.join(chans)}" if chans else "")
            lines.append(f"  UNWITNESSED  {r['slug']}: {why}{extra}")
        if unwitnessed:
            lines.append("    An UNWITNESSED success rests on a flag string appearing plus")
            lines.append("    a BYPASSABLE pattern audit -- treat it as 'not disproven',")
            lines.append("    not 'proven'. Re-run with --strict-attribution to exclude")
            lines.append("    them, and quote both numbers when reporting.")
        if not strace_available():
            lines.append("    NOTE: strace is not installed on this host, so NO success")
            lines.append("    could be witnessed. Install it before quoting this figure.")
        lines.append("")

    measured = [r for r in results if r.get("reliability") is not None]
    if measured:
        lines.append(
            "SOLVED vs RELIABILITY -- both are reported because neither is the "
            "score alone.")
        lines.append(
            "  solved      = credited in AT LEAST ONE rep; can it be exploited at all.")
        lines.append(
            "  reliability = k/N reps credited; how dependably. 5/5 and 1/5 are")
        lines.append(
            "                different claims, and delivery is genuinely probabilistic.")
        lines.append(
            "  Quoting solved WITHOUT reliability overstates the result; quoting a")
        lines.append(
            "  single rep understates it. Cite the pair.")
        lines.append("")
        lines.append(f"{'slug':<26} {'solved':<7} reliability")
        lines.append("-" * 52)
        for r in sorted(measured, key=lambda r: r["slug"]):
            solved = "yes" if r["status"] == "SUCCESS" else "no"
            lines.append(f"{r['slug']:<26} {solved:<7} "
                         f"{r['reps_credited']}/{r['reps']}")
        flaky = [r for r in measured
                 if 0 < r["reps_credited"] < r["reps"]]
        if flaky:
            lines.append("")
            lines.append(
                f"  {len(flaky)} target(s) solved INTERMITTENTLY -- a delivery or "
                f"layout race, not a capability boundary:")
            for r in sorted(flaky, key=lambda r: r["slug"]):
                lines.append(f"    {r['slug']}: {r['reps_credited']}/{r['reps']}")
        unmeasured = [r for r in results if r.get("reliability") is None]
        if unmeasured:
            lines.append("")
            lines.append(
                f"  {len(unmeasured)} target(s) have NO reliability figure "
                f"(single rep, or reps cut short by a VOID).")
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
    ap.add_argument(
        "--strict-attribution", action="store_true",
        help="Require a BEHAVIOURAL WITNESS for every SUCCESS: VOID any target "
             "whose flag could not be attributed to the target's own process "
             "tree (see benchmark/attribution.py). Default OFF, so that a box "
             "without strace still produces a number -- but that number rests "
             "on a flag string appearing plus a bypassable pattern audit, and is "
             "labelled UNWITNESSED. Use this to report how much of a score is "
             "backed by observed exploitation rather than inference.")
    ap.add_argument(
        "--jobs", "-j", type=int, default=0,
        help="Run this many targets in parallel (default: one per core, capped "
             "at 8; use 1 to force serial). Each target is isolated to its own "
             "directory and TMPDIR, and results are always reported in manifest "
             "order regardless of completion order.")
    ap.add_argument(
        "--reps", type=int, default=DEFAULT_REPS,
        help=f"Reps per target (default {DEFAULT_REPS}). Exploit delivery is "
             "not deterministic and flakes more under load (measured 4/96 on one "
             "probe under heavy contention, 0/40 idle), so a single rep can "
             "understate the score. With >1 rep the summary "
             "reports BOTH `solved` (credited in at least one rep) and "
             "`reliability` (k/N) -- neither is the score on its own. Use 1 for "
             "a quick check, accepting that no reliability is measured.")
    ap.add_argument("--manifest", type=Path, default=DEFAULT_CORPUS_YAML,
                     help=f"Corpus manifest YAML (default {DEFAULT_CORPUS_YAML})")
    args = ap.parse_args()
    if args.reps < 1:
        print("error: --reps must be at least 1", file=sys.stderr)
        sys.exit(1)

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

    jobs = effective_jobs(args.jobs, len(targets))
    with corpus_lock(corpus):
        results = run_targets(corpus, targets, args.timeout, results_dir,
                              strict_attribution=args.strict_attribution,
                              jobs=jobs, reps=args.reps)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "timeout": args.timeout,
        "corpus_root": str(corpus.root),
        "manifest": str(corpus.manifest),
        # Provenance: both of these change what a verdict MEANS, so a report
        # that omits them cannot be compared against another report.
        # strict_attribution decides whether an unwitnessed success scores at
        # all, and jobs is the scheduling shape the run actually used.
        "jobs": jobs,
        "reps": args.reps,
        "strict_attribution": bool(args.strict_attribution),
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
