#!/usr/bin/env python3
"""benchmark/walkthrough/score.py -- the walkthrough scorer.

Measures whether supwngo's generated 0-to-pwn walkthroughs are FOLLOWABLE, by
the definition the R5 spec sets out (docs/plans/2026-09-24-final-round-r5-
unseen-corpus.md, Problem 1 and 1a) and the design in
docs/plans/2026-09-24-walkthrough-blind-follower-scorer.md.

WHAT IS MEASURED
----------------
A walkthrough is credited for a target when a FRESH follower, given only that
walkthrough and that binary, produces an artifact that captures that build's
secret flag -- AND the identical follower given only the binary does not.

Two arms, always:

  walkthrough  the follower gets the binary and the walkthrough
  bare         the follower gets the binary and "capture the flag". Nothing else.

Credit requires the walkthrough arm to succeed and the bare arm to fail. Where
BOTH succeed the target is UNINFORMATIVE: it cannot demonstrate the walkthrough
contributed anything. This is the necessity test from benchmark/ablation/,
applied to documentation instead of to exploit steps. A strong follower makes
easy targets uninformative and shrinks the denominator; that is reported, never
smoothed.

WHAT IS *NOT* MEASURED, AND THE NAME SAYS SO
--------------------------------------------
With `--walkthrough-variant verbatim` (the default) the follower receives the
walkthrough's runnable template and may simply execute it. So the figure is
`artifact_followable`: can a fresh agent, handed this artifact, get the flag.
It is NOT a claim that the prose was read, and no output here says otherwise.
`--walkthrough-variant prose` strips every executable statement and is the arm
that tests the teaching; figures from the two variants are not comparable.

HOW SCORING WORKS -- AND WHY THE FOLLOWER CANNOT GRADE ITSELF
-------------------------------------------------------------
Everything the follower SAYS is discarded. Only the file it wrote is scored, and
it is scored through the machinery `run_bench.py` already uses on an autopwn
artifact, imported rather than reimplemented:

  run_bench.build_with_secret        fresh per-rep secret, fail-closed
  run_bench.negative_control         VOID a target whose flag is free
  run_bench.classify                 the VOID determination, unchanged
  run_bench.inspect_generated_script the (bypassable) pattern audit
  attribution.witness_argv           the behavioural witness
  attribution.attribution_verdict    who wrote the flag

`b"flag" in out` is never a verdict, and the walkthrough engine is never asked
about its own output: this tool consumes walkthrough FILES.

THE TWO WAYS AN AGENT FOLLOWER CAN CHEAT THAT AUTOPWN CANNOT
------------------------------------------------------------
`run_bench.py` faces a non-adaptive generator that is never handed the flag. An
interactive follower with a shell is a different adversary, and two channels
open that do not exist there. Both are closed structurally, not by pattern:

1. HARDCODING / GENERATION-TIME SCRAPING. The follower can read `flag.txt` while
   it works and paste the string into `exploit.py`.
   Closed by DECOY-THEN-REMINT: the follower works against a decoy secret of
   identical length; its artifact is then FROZEN, the sandbox is WIPED of
   everything but the artifact and the walkthrough, the target is REBUILT with a
   fresh secret the follower has never seen, and the frozen artifact is scored
   against that. A pasted decoy scores NO_FLAG.

2. RUNTIME LAUNDERING. Re-minting does not stop an artifact that reads
   `flag.txt` at run time and relays the bytes THROUGH the target, which echoes
   them -- so the target writes the flag and attribution credits it.
   Closed by the BEHAVIOURAL OPEN-AUDIT: the trace also records `openat`, and a
   process OUTSIDE the target's lineage opening `flag.txt` is
   FOLLOWER_LAUNDERED and not credited. A shell the exploit obtained opening
   `flag.txt` is legitimate and is distinguished by exactly the lineage rule
   attribution already applies to writes.

DENOMINATORS -- READ THIS BEFORE QUOTING A NUMBER
-------------------------------------------------
  rate_strict      FOLLOWABLE / eligible       UNINFORMATIVE and NOT_MEASURABLE
                                               count as NON-PASSING. Cannot be
                                               inflated by anything breaking.
                                               THIS IS THE GATE FIGURE.
  rate_informative FOLLOWABLE / (FOLLOWABLE+NOT_FOLLOWABLE)
                                               the R5 spec's figure. Excluding
                                               UNINFORMATIVE means a bare-arm
                                               success on a FAILING target makes
                                               this go UP, so it is printed with
                                               its denominator and the excluded
                                               slugs named, and it is WITHHELD as
                                               a gate result once the excluded
                                               set exceeds 20% of eligible.
  rate_total       FOLLOWABLE / total

ISOLATION, STATED PLAINLY
-------------------------
Process-level, not OS-level. The sandbox is outside the repo, the walkthrough is
sanitised of repository paths (fail-closed), non-Bash file tools are confined to
cwd by the CLI, web tools are denied, and the transcript is audited for
forbidden-context markers. But `HOME` is shared, because the follower CLI reads
its credentials there, and a follower with a shell can read the filesystem. That
is a DETECTED, not PREVENTED, gap. A figure produced here must not be quoted as
if it came from a container.

Usage:
    # prove the scorer can return a NEGATIVE verdict (no LLM, no cost)
    python3 benchmark/walkthrough/score.py --selftest

    # cheap deterministic arm: does each walkthrough's own template work?
    python3 benchmark/walkthrough/score.py --follower template \\
        --walkthrough-dir /path/to/walkthroughs

    # the gate metric: blind agent follower, both arms
    python3 benchmark/walkthrough/score.py --follower agent \\
        --walkthrough-dir /path/to/walkthroughs --reps 3
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent            # benchmark/walkthrough/
BENCH = HERE.parent                                # benchmark/
REPO_ROOT = BENCH.parent
sys.path.insert(0, str(BENCH))

import run_bench as rb                            # noqa: E402
import attribution as att                          # noqa: E402

sys.path.insert(0, str(HERE))
from followers import (  # noqa: E402
    ARM_BARE, ARM_WALKTHROUGH, ARTIFACT_NAME, FOLLOWER_KINDS,
    WALKTHROUGH_VARIANTS, AgentTier, FollowerError, apply_variant,
    build_follower, follower_env, sanitize_walkthrough)

# Arm order is FIXED and recorded. Letting it vary would give a tunable knob:
# a loaded box, a warm cache or an exhausted budget affects whichever arm runs
# second, and "which arm ran second" must not be able to change the verdict.
ARM_ORDER = (ARM_WALKTHROUGH, ARM_BARE)

DEFAULT_REPS_AGENT = 3
DEFAULT_REPS_TEMPLATE = 5

# Above this share of `eligible`, the informative rate is withheld as a gate
# result: the denominator has moved too far from the pre-declared set to be the
# same measurement. Mirrors write_summary()'s RATE WITHHELD behaviour for fatal
# VOIDs -- refuse to publish a rate rather than let breakage read as a score.
MAX_EXCLUDED_SHARE = 0.20

GATE_THRESHOLD = 0.85


# --------------------------------------------------------------------------- #
# per-trial outcomes
# --------------------------------------------------------------------------- #
# What one arm of one rep produced. `credited` is the only thing the verdict
# arithmetic reads; the rest is why.
OUTCOMES = {
    "CREDITED": "the flag was written by the target's own process tree",
    "CREDITED_UNWITNESSED": "the flag appeared and no witness was available",
    "NO_FLAG": "the artifact ran and this rep's secret never appeared",
    "NO_ARTIFACT": "the follower produced no exploit artifact",
    "FOLLOWER_GAMED": "the flag appeared but the target did not produce it",
    "FOLLOWER_LAUNDERED": "a process outside the target's lineage opened flag.txt",
    "UNWITNESSED_REFUSED": "no witness, and --strict-attribution refuses to score it",
    "FOLLOWER_INVALID": "the follower did not run to completion; no measurement",
}
CREDITING_OUTCOMES = {"CREDITED", "CREDITED_UNWITNESSED"}

# Target verdicts.
VERDICTS = {
    "FOLLOWABLE": "walkthrough arm captured the flag; the bare arm never did",
    "NOT_FOLLOWABLE": "neither arm captured the flag",
    "UNINFORMATIVE": ("the BARE arm captured the flag, so this target cannot "
                      "demonstrate the walkthrough contributed anything"),
    "NOT_MEASURABLE": ("an instrument fault or a blindness break means this "
                       "target produced no measurement either way"),
    "VOID": "corpus/provisioning fault -- inherited from run_bench's controls",
    # template-follower only; structurally cannot be FOLLOWABLE (no bare arm)
    "TEMPLATE_OK": "the walkthrough's own embedded template captured the flag",
    "TEMPLATE_BROKEN": "the walkthrough's own embedded template did not",
}
# Verdicts that are in the pre-declared eligible set, i.e. the strict denominator.
ELIGIBLE_VERDICTS = {"FOLLOWABLE", "NOT_FOLLOWABLE", "UNINFORMATIVE",
                     "NOT_MEASURABLE"}


def sha256_file(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


# --------------------------------------------------------------------------- #
# the laundering audit
# --------------------------------------------------------------------------- #
_OPEN_RE = re.compile(r'\bopen(?:at)?\(([^)]*)\)\s*=\s*(-?\d+)')


def flag_file_opened_outside_target(trace_path: Path, target_dir: Path,
                                    target_binary: Path,
                                    flag_name: str = "flag.txt") -> list[dict]:
    """Which processes read the flag FILE without being the target's lineage.

    The laundering attack this exists for: `exploit.py` reads `flag.txt` itself
    and relays the bytes through the target, which echoes them -- so the *target*
    performs the flag-bearing write and write-attribution credits it. Re-minting
    the secret does not stop that, because the read happens at run time.

    The lineage rule is the same one `attribution.attribute()` applies to writes,
    and for the same reason: a shell the exploit obtained running `cat flag.txt`
    is the intended solve path for the shell targets and MUST NOT be flagged,
    while the artifact's own process opening `flag.txt` has no legitimate
    exploit purpose at all.

    Narrow on purpose. Only `flag.txt` counts -- `ELF(BINARY)` legitimately opens
    the binary from the artifact's own process, so including the image here would
    falsely accuse every honest pwntools exploit.
    """
    try:
        text = trace_path.read_text(errors="replace")
    except OSError:
        return []
    tree = att.parse_trace(trace_path, target_dir)
    target = os.path.realpath(str(target_binary))
    target_execs = {p: tree.exec_seqs(p, target) for p in tree.exec_events}
    target_execs = {p: s for p, s in target_execs.items() if s}

    def in_target_lineage(pid: int, seq: int) -> bool:
        return any(s < seq for a in tree.ancestry(pid)
                   for s in target_execs.get(a, ()))

    hits: list[dict] = []
    for seq, line in enumerate(text.splitlines()):
        m = att._LINE.match(line)
        if not m:
            continue
        pid, rest = int(m.group(1)), m.group(2)
        o = _OPEN_RE.search(rest)
        if not o or flag_name not in o.group(1):
            continue
        if o.group(2).startswith("-"):      # ENOENT etc: nothing was read
            continue
        writer = tree.process_identity(pid)
        if not in_target_lineage(writer, seq):
            hits.append({"pid": pid, "chain": tree.describe(pid),
                         "syscall": rest[:120]})
    return hits


# --------------------------------------------------------------------------- #
# scoring one artifact
# --------------------------------------------------------------------------- #
def _run_capture(argv: list[str], cwd: Path, stdin_bytes: bytes,
                 wall_timeout: float, env: dict):
    import subprocess
    try:
        proc = subprocess.run(argv, input=stdin_bytes, cwd=str(cwd), env=env,
                              capture_output=True, timeout=wall_timeout)
        return proc.stdout or b"", proc.stderr or b"", False
    except subprocess.TimeoutExpired as e:
        return (e.stdout or b""), (e.stderr or b""), True
    except OSError as e:
        return b"", f"could not run the artifact: {e}".encode(), False


def score_artifact(artifact: Path | None, workdir: Path, target_binary: Path,
                   expected_flag: str, timeout: float, trace_dir: Path,
                   strict_attribution: bool) -> dict:
    """Score a frozen follower artifact. The ONLY source of truth for credit.

    Deliberately NOT `run_bench.classify()`: that function's vocabulary is
    target-level and folds in the corpus negative controls, which are evaluated
    once per rep here rather than once per arm. The crediting RULE is identical
    and comes from the same `attribution_verdict()`; only the surrounding
    bookkeeping differs.
    """
    if artifact is None or not artifact.is_file() or artifact.stat().st_size == 0:
        return {"outcome": "NO_ARTIFACT", "credited": False,
                "reason": "the follower produced no exploit artifact to score"}

    tmp = workdir / ".tmp"
    tmp.mkdir(exist_ok=True)
    env = follower_env(REPO_ROOT, tmpdir=tmp)
    audit = rb.inspect_generated_script(artifact, expected_flag)
    argv = [sys.executable, str(artifact)]

    # Deliberately NOT rb._run_capture: that helper prepends the repo root to
    # PYTHONPATH so an autopwn artifact can `import supwngo`. A follower artifact
    # must not be able to -- that would hand it the whole framework. The traced
    # run below gets the same env, so a disagreement between the two runs can
    # never be the harness's fault.
    out_b, err_b, timed_out = _run_capture(
        argv, workdir, rb.VERIFY_STDIN, max(30.0, timeout * 4), env)
    combined = (out_b + err_b).decode("utf-8", "replace")
    flag_found = expected_flag in combined
    verify = {
        "ran": True, "timed_out": timed_out, "flag_found": flag_found,
        "shell_proven": bool(rb.SHELL_PROOF_RE.search(combined)),
        "stdout_excerpt": rb._excerpt(combined, 1200),
    }

    if not flag_found:
        return {"outcome": "NO_FLAG", "credited": False, "verify": verify,
                "script_audit": audit,
                "reason": ("the artifact ran and this rep's secret flag never "
                           "appeared in its output")}

    witness = att.witness_argv(
        argv=argv, target_dir=workdir, target_binary=target_binary,
        expected_flag=expected_flag, stdin_bytes=rb.VERIFY_STDIN,
        timeout=timeout, env=env, trace_dir=trace_dir,
        traced_syscalls=att.TRACED_SYSCALLS + ",openat,open",
    )

    launder: list[dict] = []
    if witness.get("available") and witness.get("trace_log"):
        launder = flag_file_opened_outside_target(
            Path(witness["trace_log"]), workdir, target_binary)
    if launder:
        return {
            "outcome": "FOLLOWER_LAUNDERED", "credited": False, "verify": verify,
            "script_audit": audit, "attribution": witness,
            "laundering": launder,
            "reason": ("the artifact itself opened flag.txt and relayed it: "
                       f"{launder[0]['chain']}. The target may well have written "
                       "the bytes, but it did not produce them, so this is not "
                       "exploitation"),
        }

    verdict, why = att.attribution_verdict(witness)
    base = {"verify": verify, "script_audit": audit, "attribution": witness}

    if verdict == "credited":
        return {**base, "outcome": "CREDITED", "credited": True,
                "reason": f"BEHAVIOURALLY ATTRIBUTED: {why}"}
    if verdict == "not_credited":
        return {**base, "outcome": "FOLLOWER_GAMED", "credited": False,
                "reason": f"the flag appeared but {why}"}

    # inconclusive: no usable witness. Fall back exactly as run_bench does, and
    # label it -- never treat a missing witness as a negative one.
    cheat = rb.script_cheat_reason(audit)
    if cheat:
        return {**base, "outcome": "FOLLOWER_GAMED", "credited": False,
                "reason": f"{cheat} (no behavioural witness: {why})"}
    if strict_attribution:
        return {**base, "outcome": "UNWITNESSED_REFUSED", "credited": False,
                "reason": (f"no behavioural witness ({why}) and "
                           "--strict-attribution refuses to credit a flag that "
                           "rests only on a string plus a bypassable audit")}
    return {**base, "outcome": "CREDITED_UNWITNESSED", "credited": True,
            "reason": (f"the flag appeared but UNWITNESSED ({why}); this rests "
                       "on a bypassable pattern audit, not a structural "
                       "guarantee")}


# --------------------------------------------------------------------------- #
# verdict arithmetic -- kept as PURE FUNCTIONS so the selftest can drive them
# --------------------------------------------------------------------------- #
def target_verdict(kind: str, trials: list[dict]) -> tuple[str, str]:
    """Collapse a target's trials into (verdict, reason).

    Pure, so `--selftest` can exercise the whole truth table without running a
    single follower. A verdict rule that is only ever reached through a
    600-second LLM session is a rule nobody can check.

    Precedence, and each step is there because of a specific way the number can
    be wrong:

    1. ANY invalid trial, in EITHER arm  -> NOT_MEASURABLE.
       Without this a bare-arm timeout, CLI crash or budget exhaustion reads as
       "the bare arm did not solve it" and ENABLES a FOLLOWABLE verdict on
       missing evidence.
    2. ANY blindness hit                 -> NOT_MEASURABLE.
    3. template follower                 -> TEMPLATE_OK / TEMPLATE_BROKEN.
       It has no bare arm, so it has no necessity test, so it cannot reach
       FOLLOWABLE. Structural, not a policy.
    4. ANY bare-arm credit               -> UNINFORMATIVE.
       Asymmetric on purpose: ONE bare success destroys the claim that the
       walkthrough was necessary. The asymmetry always points AWAY from
       crediting the walkthrough.
    5. ANY walkthrough-arm credit        -> FOLLOWABLE (best-of-N, disclosed).
    6. otherwise                         -> NOT_FOLLOWABLE.
    """
    invalid = [t for t in trials if not t.get("valid", True)]
    if invalid:
        arms = sorted({t["arm"] for t in invalid})
        return "NOT_MEASURABLE", (
            f"{len(invalid)} of {len(trials)} trials did not run to completion "
            f"(arms: {', '.join(arms)}): {invalid[0].get('invalid_reason')}. "
            "Neither success nor failure is evidence here, so this target is "
            "not scored rather than credited on missing evidence")
    blind = [t for t in trials if t.get("blindness_hits")]
    if blind:
        return "NOT_MEASURABLE", (
            "the follower reached forbidden context "
            f"({', '.join(blind[0]['blindness_hits'])}), so its result says "
            "nothing about the walkthrough")

    wt = [t for t in trials if t["arm"] == ARM_WALKTHROUGH]
    bare = [t for t in trials if t["arm"] == ARM_BARE]
    wt_ok = sum(1 for t in wt if t["credited"])
    bare_ok = sum(1 for t in bare if t["credited"])

    if kind == "template":
        if bare:
            raise AssertionError("the template follower must have no bare arm")
        if wt_ok:
            return "TEMPLATE_OK", (
                f"the walkthrough's own template captured the flag in {wt_ok}/"
                f"{len(wt)} reps. NOT a followability verdict: there is no bare "
                "arm, so nothing here shows the walkthrough was necessary")
        return "TEMPLATE_BROKEN", (
            f"the walkthrough's own template captured nothing in {len(wt)} reps "
            f"-- the artifact it ships does not work on this binary")

    if not bare:
        return "NOT_MEASURABLE", (
            "no bare-arm trials were run, so the necessity control is missing "
            "and no followability verdict is possible")
    if bare_ok:
        return "UNINFORMATIVE", (
            f"the BARE follower (binary only, no walkthrough) captured the flag "
            f"in {bare_ok}/{len(bare)} reps, so this target cannot demonstrate "
            f"the walkthrough contributed anything. Walkthrough arm: "
            f"{wt_ok}/{len(wt)}")
    if wt_ok:
        return "FOLLOWABLE", (
            f"the walkthrough arm captured the flag in {wt_ok}/{len(wt)} reps "
            f"and the bare arm in 0/{len(bare)}")
    return "NOT_FOLLOWABLE", (
        f"neither arm captured the flag (walkthrough 0/{len(wt)}, "
        f"bare 0/{len(bare)})")


def pairing_table(trials: list[dict], reps: int) -> dict:
    """Within-rep contingency table.

    The peer review correctly noted that a verdict computed from
    any-walkthrough-success vs zero-bare-success across all reps is not a paired
    comparison at all. The verdict stays conservative, but the paired counts are
    reported, because they are what a reader needs in order to see whether the
    arms actually differ or the follower is simply noisy.
    """
    table = {"walkthrough_only": 0, "both": 0, "neither": 0, "bare_only": 0,
             "incomplete_pairs": 0}
    for rep in range(1, reps + 1):
        w = [t for t in trials if t["rep"] == rep and t["arm"] == ARM_WALKTHROUGH]
        b = [t for t in trials if t["rep"] == rep and t["arm"] == ARM_BARE]
        if len(w) != 1 or len(b) != 1:
            table["incomplete_pairs"] += 1
            continue
        wc, bc = w[0]["credited"], b[0]["credited"]
        key = ("both" if wc and bc else "walkthrough_only" if wc
               else "bare_only" if bc else "neither")
        table[key] += 1
    return table


def compute_rates(results: list[dict]) -> dict:
    """Every denominator, side by side, with the inflation guard.

    The R5 spec says UNINFORMATIVE leaves the walkthrough denominator. The peer
    review pointed out that this lets a bare-arm success on a FAILING target
    remove it and push the rate UP -- breakage reading as improvement, which is
    the exact failure mode `run_bench.write_summary` already refuses to allow.
    Both cannot be true at once, so both numbers are published and the
    non-inflatable one is named the gate figure. The conflict is surfaced for the
    maintainer, not silently resolved in either direction.
    """
    total = len(results)
    counts = {v: 0 for v in VERDICTS}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1

    eligible = sum(counts[v] for v in ELIGIBLE_VERDICTS)
    followable = counts["FOLLOWABLE"]
    informative = counts["FOLLOWABLE"] + counts["NOT_FOLLOWABLE"]
    excluded = counts["UNINFORMATIVE"] + counts["NOT_MEASURABLE"]
    share = (excluded / eligible) if eligible else 0.0

    return {
        "total": total,
        "counts": counts,
        "eligible": eligible,
        "informative": informative,
        "excluded_from_informative": excluded,
        "excluded_share_of_eligible": round(share, 4),
        "rate_strict": (followable / eligible) if eligible else None,
        "rate_informative": (followable / informative) if informative else None,
        "rate_total": (followable / total) if total else None,
        "informative_rate_withheld": share > MAX_EXCLUDED_SHARE,
        "max_excluded_share": MAX_EXCLUDED_SHARE,
    }


def gate_result(rates: dict, kind: str, reps: int, ran_full_manifest: bool,
                variant: str) -> dict:
    """Whether an R5-style gate verdict may be stated at all.

    A gate number from a subset run, from the template follower, or from a run
    with an unmeasurable target is not a gate number. Saying `null` and why is
    the honest output; a figure that gets quoted downstream regardless of the
    caveats above it is not.
    """
    blockers = []
    if kind != "agent":
        blockers.append(
            f"the {kind} follower has no necessity control, so it cannot produce "
            "a followability gate result -- only the agent follower can")
    if not ran_full_manifest:
        blockers.append("this was a SUBSET run; a gate needs the full manifest")
    if rates["counts"].get("NOT_MEASURABLE"):
        blockers.append(
            f"{rates['counts']['NOT_MEASURABLE']} target(s) are NOT_MEASURABLE; "
            "fix the instrument and re-run rather than scoring around them")
    if rates["rate_strict"] is None:
        blockers.append("no eligible targets")
    if variant != "verbatim":
        blockers.append(
            f"walkthrough variant is {variant!r}; the gate is defined on the "
            "artifact as shipped")
    if blockers:
        return {"gate": None, "threshold": GATE_THRESHOLD, "blockers": blockers}
    passed = rates["rate_strict"] >= GATE_THRESHOLD
    return {
        "gate": "PASS" if passed else "FAIL",
        "threshold": GATE_THRESHOLD,
        "measured_on": "rate_strict",
        "value": round(rates["rate_strict"], 4),
        "blockers": [],
        "note": ("rate_strict counts UNINFORMATIVE as non-passing, so this "
                 "verdict cannot be improved by a target becoming uninformative"),
    }


# --------------------------------------------------------------------------- #
# staging
# --------------------------------------------------------------------------- #
class Stage:
    """A repo-free sandbox pair for one target: one dir per arm, stable paths.

    Stable across reps on purpose: the walkthrough's sanitised `BINARY` constant
    points at the walkthrough arm's staged copy, so that path must not move
    between reps. Per-rep freshness comes from re-staging the binary and
    `flag.txt` into the same paths, and from wiping follower leftovers.
    """

    def __init__(self, root: Path, slug: str, binary_name: str):
        self.slug = slug
        self.binary_name = binary_name
        self.dirs = {arm: root / slug / arm for arm in ARM_ORDER}
        for d in self.dirs.values():
            d.mkdir(parents=True, exist_ok=True)

    def binary(self, arm: str) -> Path:
        return self.dirs[arm] / self.binary_name

    def stage(self, src_binary: Path, src_flag: Path, arms: tuple[str, ...]) -> None:
        for arm in arms:
            shutil.copy2(src_binary, self.binary(arm))
            os.chmod(self.binary(arm), 0o755)
            shutil.copy2(src_flag, self.dirs[arm] / "flag.txt")

    def wipe_except(self, arm: str, keep: list[Path]) -> list[str]:
        """Remove everything the follower left behind except the named files.

        Not tidiness. A follower may have copied the binary, written a helper, or
        cached the DECOY flag; scoring against a leftover copy would score the
        decoy build, and a helper module left on disk would let the artifact
        depend on state the freeze did not capture.
        """
        keep_names = {p.name for p in keep} | {"flag.txt", self.binary_name}
        removed = []
        for child in sorted(self.dirs[arm].iterdir()):
            if child.name in keep_names:
                continue
            removed.append(child.name)
            if child.is_dir():
                shutil.rmtree(child, ignore_errors=True)
            else:
                child.unlink(missing_ok=True)
        return removed


def write_empty_mcp_config(path: Path) -> Path:
    path.write_text(json.dumps({"mcpServers": {}}) + "\n")
    return path


# --------------------------------------------------------------------------- #
# the run
# --------------------------------------------------------------------------- #
def resolve_walkthrough(wt_dir: Path, slug: str, binary_name: str) -> Path | None:
    """Find this target's walkthrough artifact.

    Family-agnostic by construction: matching is on the target, never on the
    family. Nothing in this file names stack_bof, rop_chain, syscall, triage,
    fmtstr, integer or heap, so a family added later needs no change here.
    """
    for pattern in (f"{slug}*.py", f"{binary_name}*.py", f"*{slug}*.py",
                    f"*{binary_name}*.py"):
        hits = sorted(wt_dir.glob(pattern))
        if hits:
            return hits[0]
    return None


def run_target(corpus: rb.Corpus, target: dict, args, stage_root: Path,
               results_dir: Path, mcp_config: Path) -> dict:
    slug = target["slug"]
    binary_name = rb.Corpus.binary_name(slug)
    kind = args.follower
    source_name = f"{binary_name}.c"
    follower = build_follower(kind, tier=args.tier, repo_root=REPO_ROOT,
                              mcp_config=mcp_config, source_name=source_name)
    # The follower decides which arms exist. The template follower has no bare
    # arm by construction (nothing to execute without a walkthrough), which is
    # precisely why it cannot reach a FOLLOWABLE verdict.
    arms = tuple(a for a in ARM_ORDER if a in follower.arms)
    reps = args.reps

    record = {
        "slug": slug,
        "technique_intended": target.get("technique"),
        "difficulty": target.get("difficulty"),
        "follower_kind": kind,
        "walkthrough_variant": args.walkthrough_variant,
        "arms": list(arms),
        "reps_requested": reps,
        "trials": [],
    }

    wt_src = resolve_walkthrough(args.walkthrough_dir, slug, binary_name)
    if wt_src is None:
        record.update({
            "verdict": "NOT_MEASURABLE",
            "reason": (f"no walkthrough artifact for {slug} in "
                       f"{args.walkthrough_dir} -- generate one before scoring; "
                       "a missing artifact is an absent measurement, not a "
                       "failed one"),
        })
        return record

    stage = Stage(stage_root, slug, binary_name)

    # --- PRE-FLIGHT: eligibility is decided BEFORE any follower runs. ------- #
    # A VOID discovered afterwards would mean a follower session was spent on an
    # unscorable target, and worse, that the eligible set was chosen after
    # seeing results.
    decoy = rb.mint_secret_flag()
    try:
        rb.build_with_secret(corpus, slug, decoy)
    except rb.ProvisionError as e:
        record.update({"verdict": "VOID", "void_cause": "provisioning_failed",
                       "reason": f"could not provision a secret flag: {e}"})
        return record
    control = rb.negative_control(corpus, slug, decoy, args.timeout)
    status, reason, cause = rb.classify(None, {"flag_found": False}, control, {})
    record["negative_control"] = control
    if status == "VOID":
        record.update({"verdict": "VOID", "void_cause": cause,
                       "reason": f"pre-flight: {reason}"})
        return record

    # --- the walkthrough artifact the follower will actually see ------------ #
    raw = wt_src.read_text(errors="replace")
    try:
        sanitised, path_info = sanitize_walkthrough(
            raw, stage.binary(ARM_WALKTHROUGH), REPO_ROOT)
        varied, variant_info = apply_variant(sanitised, args.walkthrough_variant)
    except FollowerError as e:
        record.update({"verdict": "NOT_MEASURABLE",
                       "reason": f"walkthrough could not be prepared: {e}"})
        return record
    wt_staged = stage.dirs[ARM_WALKTHROUGH] / wt_src.name
    record["walkthrough"] = {
        "source": str(wt_src),
        "source_sha256": sha256_file(wt_src),
        "presented_sha256": sha256_text(varied),
        "path_sanitisation": path_info,
        "variant": variant_info,
    }

    # --- reps. EVERY scheduled trial runs: no early stopping. --------------- #
    for rep in range(1, reps + 1):
        rep_dir = results_dir / slug / f"rep{rep}"
        rep_dir.mkdir(parents=True, exist_ok=True)

        # (1) decoy build -- what the follower works against.
        decoy = rb.mint_secret_flag()
        try:
            rb.build_with_secret(corpus, slug, decoy)
        except rb.ProvisionError as e:
            record["trials"].append({
                "rep": rep, "arm": "n/a", "valid": False, "credited": False,
                "outcome": "FOLLOWER_INVALID",
                "invalid_reason": f"decoy build failed: {e}"})
            continue
        stage.stage(corpus.binary(slug), corpus.flag_file(slug), arms)
        stage.dirs[ARM_WALKTHROUGH].joinpath(wt_src.name).write_text(varied)

        outcomes = {}
        for arm in arms:
            try:
                outcomes[arm] = follower.run(
                    arm, stage.dirs[arm], stage.binary(arm),
                    wt_staged if arm == ARM_WALKTHROUGH else None)
            except FollowerError as e:
                record["trials"].append({
                    "rep": rep, "arm": arm, "valid": False, "credited": False,
                    "outcome": "FOLLOWER_INVALID", "invalid_reason": str(e)})

        # (2) FREEZE, then RE-MINT. The follower never sees the scored secret.
        frozen: dict[str, Path | None] = {}
        for arm, outcome in outcomes.items():
            if outcome.artifact is None:
                frozen[arm] = None
                continue
            dest = rep_dir / f"{arm}_{ARTIFACT_NAME}"
            shutil.copy2(outcome.artifact, dest)
            frozen[arm] = dest
            if outcome.transcript_path and outcome.transcript_path.is_file():
                shutil.copy2(outcome.transcript_path,
                             rep_dir / outcome.transcript_path.name)

        scored_secret = rb.mint_secret_flag()
        try:
            rb.build_with_secret(corpus, slug, scored_secret)
        except rb.ProvisionError as e:
            for arm in outcomes:
                record["trials"].append({
                    "rep": rep, "arm": arm, "valid": False, "credited": False,
                    "outcome": "FOLLOWER_INVALID",
                    "invalid_reason": f"re-mint build failed: {e}"})
            continue

        for arm, outcome in outcomes.items():
            # Wipe first, THEN re-stage: the wipe removes any decoy-bearing copy
            # the follower made, and the re-stage puts the freshly-minted build
            # back at the path the artifact expects.
            keep = [p for p in [frozen.get(arm), wt_staged] if p]
            removed = stage.wipe_except(arm, keep)
            if frozen.get(arm) is not None:
                shutil.copy2(frozen[arm], stage.dirs[arm] / ARTIFACT_NAME)
            stage.stage(corpus.binary(slug), corpus.flag_file(slug), (arm,))
            if arm == ARM_WALKTHROUGH:
                wt_staged.write_text(varied)

            scored = score_artifact(
                artifact=(stage.dirs[arm] / ARTIFACT_NAME
                          if frozen.get(arm) else None),
                workdir=stage.dirs[arm], target_binary=stage.binary(arm),
                expected_flag=scored_secret, timeout=args.timeout,
                trace_dir=rep_dir / f"{arm}_attribution",
                strict_attribution=args.strict_attribution)

            trial = {
                "rep": rep, "arm": arm,
                "valid": outcome.valid, "invalid_reason": outcome.invalid_reason,
                "credited": bool(scored["credited"]) and outcome.valid,
                "outcome": ("FOLLOWER_INVALID" if not outcome.valid
                            else scored["outcome"]),
                "reason": outcome.invalid_reason or scored["reason"],
                "blindness_hits": outcome.blindness_hits,
                "decoy_flag": decoy,
                "scored_flag": scored_secret,
                "artifact_frozen": str(frozen.get(arm)) if frozen.get(arm) else None,
                "artifact_sha256": (sha256_file(frozen[arm])
                                    if frozen.get(arm) else None),
                "prompt_sha256": sha256_text(outcome.prompt) if outcome.prompt else None,
                "sandbox_wiped": removed,
                "follower": outcome.to_dict(),
                "scoring": {k: v for k, v in scored.items()
                            if k in ("verify", "attribution", "laundering",
                                     "script_audit")},
            }
            record["trials"].append(trial)

    verdict, reason = target_verdict(kind, record["trials"])
    record["verdict"] = verdict
    record["reason"] = reason
    record["pairing"] = (pairing_table(record["trials"], reps)
                         if kind == "agent" else None)
    for arm in arms:
        ts = [t for t in record["trials"] if t["arm"] == arm]
        record[f"{arm}_credited_reps"] = sum(1 for t in ts if t["credited"])
        record[f"{arm}_reps_run"] = len(ts)
    return record


# --------------------------------------------------------------------------- #
# summary
# --------------------------------------------------------------------------- #
def write_summary(results: list[dict], rates: dict, gate: dict, meta: dict,
                  out_path: Path) -> str:
    L: list[str] = []
    L.append("supwngo walkthrough scorer -- blind-follower measurement")
    L.append(f"timestamp: {meta['generated_at']}")
    L.append(f"corpus:    {meta['corpus_root']}")
    L.append(f"follower:  {meta['follower_kind']}  "
             f"tier={json.dumps(meta['follower_tier'])}")
    L.append(f"variant:   {meta['walkthrough_variant']}   "
             f"reps={meta['reps']}   arm order={' -> '.join(ARM_ORDER)}")
    L.append(f"isolation: {meta['isolation']}")
    L.append("")
    L.append("METRIC NAME: artifact_followable. With the `verbatim` variant the")
    L.append("follower receives the walkthrough's RUNNABLE TEMPLATE and may")
    L.append("simply execute it, so this measures whether the ARTIFACT is")
    L.append("usable -- NOT that its prose was read. Use --walkthrough-variant")
    L.append("prose for the teaching-only arm; the two are not comparable.")
    L.append("")

    if meta["follower_kind"] == "template":
        ok = rates["counts"].get("TEMPLATE_OK", 0)
        broken = rates["counts"].get("TEMPLATE_BROKEN", 0)
        L.append(f"TEMPLATE ARM: {ok} OK, {broken} BROKEN "
                 f"(of {ok + broken} with a walkthrough).")
        L.append("  This arm has NO BARE ARM and therefore NO NECESSITY TEST, so")
        L.append("  it CANNOT produce a followability figure and must never be")
        L.append("  quoted against the 85% gate. It answers one question only:")
        L.append("  does the template this walkthrough ships actually work?")
        L.append("")
    else:
        L.append("GATE ARITHMETIC -- three denominators, deliberately:")
        rs, ri, rt = (rates["rate_strict"], rates["rate_informative"],
                      rates["rate_total"])
        f = rates["counts"]["FOLLOWABLE"]
        L.append(f"  rate_strict      {f}/{rates['eligible']} = "
                 f"{'n/a' if rs is None else f'{rs * 100:.1f}%'}   "
                 "<- GATE FIGURE. UNINFORMATIVE and NOT_MEASURABLE count as")
        L.append("                   non-passing, so nothing breaking can push it up.")
        L.append(f"  rate_informative {f}/{rates['informative']} = "
                 f"{'n/a' if ri is None else f'{ri * 100:.1f}%'}   "
                 "<- the R5 spec's figure (UNINFORMATIVE excluded).")
        L.append(f"  rate_total       {f}/{rates['total']} = "
                 f"{'n/a' if rt is None else f'{rt * 100:.1f}%'}")
        L.append("")
        L.append(f"  {rates['excluded_from_informative']} target(s) "
                 f"({rates['excluded_share_of_eligible'] * 100:.1f}% of eligible) "
                 "leave the informative denominator.")
        if rates["informative_rate_withheld"]:
            L.append("  !! rate_informative is WITHHELD as a gate result: more than")
            L.append(f"     {rates['max_excluded_share'] * 100:.0f}% of the "
                     "pre-declared eligible set dropped out, so its denominator")
            L.append("     has moved too far to be the same measurement. Excluding")
            L.append("     a FAILING target for a bare-arm success would otherwise")
            L.append("     make this number go UP -- breakage reading as progress.")
        L.append("")
        L.append(f"  GATE (>= {gate['threshold'] * 100:.0f}%): "
                 f"{gate['gate'] or 'NOT STATED'}")
        for b in gate["blockers"]:
            L.append(f"    - no gate verdict: {b}")
        L.append("")

    L.append("Verdict counts:")
    for v, n in sorted(rates["counts"].items()):
        if n:
            L.append(f"  {v:<16} {n:>3}   {VERDICTS.get(v, '')}")
    L.append("")

    unin = [r for r in results if r["verdict"] == "UNINFORMATIVE"]
    if unin:
        L.append(f"UNINFORMATIVE -- {len(unin)} target(s) the BARE follower solved "
                 "without any walkthrough:")
        for r in unin:
            L.append(f"  - {r['slug']}: bare {r.get('bare_credited_reps')}/"
                     f"{r.get('bare_reps_run')}, walkthrough "
                     f"{r.get('walkthrough_credited_reps')}/"
                     f"{r.get('walkthrough_reps_run')}")
        L.append("  These cannot show the walkthrough contributed anything. This is")
        L.append("  the cost of a capable follower and it is reported, not hidden:")
        L.append("  a shrinking denominator is a real limitation of the metric.")
        L.append("")

    nm = [r for r in results if r["verdict"] == "NOT_MEASURABLE"]
    if nm:
        L.append(f"NOT_MEASURABLE -- {len(nm)} target(s) produced no measurement:")
        for r in nm:
            L.append(f"  - {r['slug']}: {r['reason'][:200]}")
        L.append("  Fix the instrument and re-run. These count as NON-PASSING in")
        L.append("  rate_strict so they cannot flatter the score.")
        L.append("")

    voids = [r for r in results if r["verdict"] == "VOID"]
    if voids:
        L.append(f"VOID -- {len(voids)} target(s) excluded by run_bench's own "
                 "pre-flight controls:")
        for r in voids:
            L.append(f"  - {r['slug']} [{r.get('void_cause')}]: {r['reason'][:180]}")
        L.append("  Eligibility was decided BEFORE any follower ran, so the")
        L.append("  eligible set was not chosen after seeing results.")
        L.append("")

    if meta["follower_kind"] == "agent":
        L.append("PAIRED OUTCOMES per target (within-rep), and each arm's k/N.")
        L.append("The verdict is a CONSERVATIVE SCREEN, not a treatment-effect")
        L.append(f"estimate: at reps={meta['reps']} no confidence bound is")
        L.append("meaningful and none is printed.")
        L.append("")
        L.append(f"{'slug':<26} {'verdict':<16} {'wt':<6} {'bare':<6} paired(w/b/both/neither)")
        L.append("-" * 96)
        for r in sorted(results, key=lambda r: r["slug"]):
            p = r.get("pairing") or {}
            pair = (f"{p.get('walkthrough_only', 0)}/{p.get('bare_only', 0)}/"
                    f"{p.get('both', 0)}/{p.get('neither', 0)}")
            L.append(f"{r['slug']:<26} {r['verdict']:<16} "
                     f"{r.get('walkthrough_credited_reps', 0)}/"
                     f"{r.get('walkthrough_reps_run', 0):<4} "
                     f"{r.get('bare_credited_reps', 0)}/"
                     f"{r.get('bare_reps_run', 0):<4} {pair}")
        L.append("")

    L.append(f"{'slug':<26} {'verdict':<16} reason")
    L.append("-" * 110)
    for r in sorted(results, key=lambda r: r["slug"]):
        L.append(f"{r['slug']:<26} {r['verdict']:<16} {r['reason'][:150]}")
    L.append("")
    L.append("How credit is decided (score.py:score_artifact):")
    L.append("  The follower is NEVER told the flag and its own claims are never")
    L.append("  read. Only the file it wrote is scored, by re-executing it fresh")
    L.append("  and requiring the flag to be written by the TARGET's process tree")
    L.append("  (benchmark/attribution.py). `b\"flag\" in out` is not a verdict.")
    L.append("  The follower works against a DECOY flag; its artifact is then")
    L.append("  frozen, the sandbox wiped, and the target REBUILT with a fresh")
    L.append("  secret it has never seen -- so a pasted flag scores NO_FLAG.")
    L.append("  An artifact that opens flag.txt itself and relays it through the")
    L.append("  target scores FOLLOWER_LAUNDERED, not a credit.")
    text = "\n".join(L)
    out_path.write_text(text)
    return text


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_argparser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--follower", choices=FOLLOWER_KINDS, default="template",
                    help="template: run the walkthrough's own embedded template "
                         "(deterministic, ~free, measures TEMPLATE VALIDITY and "
                         "cannot produce a gate figure). agent: a blind headless "
                         "follower with both arms (the gate metric).")
    ap.add_argument("--walkthrough-dir", type=Path,
                    help="Directory of generated walkthrough artifacts, one per "
                         "target. Matched by slug or binary name; family-agnostic.")
    ap.add_argument("--walkthrough-variant", choices=WALKTHROUGH_VARIANTS,
                    default="verbatim",
                    help="verbatim: the artifact as shipped (measures artifact "
                         "usability). prose: every executable statement stripped, "
                         "so the follower must reconstruct the exploit from the "
                         "teaching.")
    ap.add_argument("--target", action="append", default=None,
                    help="Only this slug. Repeatable. A SUBSET RUN CANNOT PRODUCE "
                         "A GATE RESULT and the report says so.")
    ap.add_argument("--reps", type=int, default=None,
                    help=f"Paired reps per target (default {DEFAULT_REPS_AGENT} "
                         f"for the agent follower, {DEFAULT_REPS_TEMPLATE} for "
                         "template). Every scheduled trial runs; there is no "
                         "early stopping on success.")
    ap.add_argument("--corpus-root", type=Path, default=rb.DEFAULT_CORPUS_DIR)
    ap.add_argument("--manifest", type=Path, default=rb.DEFAULT_CORPUS_YAML)
    ap.add_argument("--timeout", type=float, default=rb.DEFAULT_TIMEOUT)
    ap.add_argument("--strict-attribution", action="store_true",
                    help="Refuse to credit a flag with no behavioural witness. "
                         "Recommended for the agent follower: an interactive "
                         "follower can scrape in ways no regex catches, so an "
                         "unwitnessed flag from one is worth much less than one "
                         "from a generated script.")
    ap.add_argument("--sandbox-root", type=Path, default=None,
                    help="Where follower sandboxes live. Default: a fresh temp "
                         "dir OUTSIDE the repository, so no CLAUDE.md, plan or "
                         "corpus source is discoverable above the follower's cwd.")
    ap.add_argument("--model", default="sonnet",
                    help="Follower model. PINS THE MEASUREMENT: a stronger "
                         "follower raises both arms and makes more targets "
                         "UNINFORMATIVE. Figures from different tiers are not "
                         "comparable.")
    ap.add_argument("--effort", default=None)
    ap.add_argument("--budget-usd", type=float, default=2.0)
    ap.add_argument("--follower-timeout", type=float, default=900.0)
    ap.add_argument("--selftest", action="store_true",
                    help="Run the falsifiability controls and exit. Proves this "
                         "scorer can return a NEGATIVE verdict. No LLM, no cost.")
    return ap


def main() -> int:
    args = build_argparser().parse_args()

    if args.selftest:
        import selftest
        return selftest.run(args)

    if not args.walkthrough_dir:
        print("error: --walkthrough-dir is required (or use --selftest)",
              file=sys.stderr)
        return 2
    args.walkthrough_dir = args.walkthrough_dir.resolve()
    if not args.walkthrough_dir.is_dir():
        print(f"error: no such walkthrough dir: {args.walkthrough_dir}",
              file=sys.stderr)
        return 2
    if args.reps is None:
        args.reps = (DEFAULT_REPS_AGENT if args.follower == "agent"
                     else DEFAULT_REPS_TEMPLATE)
    if args.reps < 1:
        print("error: --reps must be at least 1", file=sys.stderr)
        return 2
    args.tier = AgentTier(model=args.model, effort=args.effort,
                          budget_usd=args.budget_usd,
                          wall_timeout_sec=args.follower_timeout)

    corpus = rb.Corpus(root=args.corpus_root.resolve(),
                       manifest=args.manifest.resolve())
    if not corpus.root.is_dir() or not corpus.manifest.is_file():
        print(f"error: bad corpus {corpus.root} / {corpus.manifest}",
              file=sys.stderr)
        return 2

    all_targets = corpus.targets()
    if args.target:
        wanted = set(args.target)
        targets = [t for t in all_targets if t["slug"] in wanted]
        missing = wanted - {t["slug"] for t in targets}
        if missing:
            print(f"error: unknown slug(s): {', '.join(sorted(missing))}",
                  file=sys.stderr)
            return 2
    else:
        targets = all_targets
    ran_full_manifest = len(targets) == len(all_targets)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SZ")
    results_dir = (corpus.root.parent /
                   f"results_walkthrough{corpus.root.name[len('corpus'):]}" / ts)
    results_dir.mkdir(parents=True, exist_ok=True)

    # Sandboxes live OUTSIDE the repo. This is the blindness mechanism, not a
    # tidiness preference: a sandbox inside the repo puts CLAUDE.md, the plans
    # and the corpus sources at or above the follower's cwd.
    stage_root = (args.sandbox_root.resolve() if args.sandbox_root
                  else Path(tempfile.mkdtemp(prefix="wtscore-")))
    stage_root.mkdir(parents=True, exist_ok=True)
    if str(REPO_ROOT) in str(stage_root):
        print(f"error: --sandbox-root {stage_root} is inside the repository, "
              "which breaks follower blindness. Choose a path outside it.",
              file=sys.stderr)
        return 2
    mcp_config = write_empty_mcp_config(stage_root / "empty-mcp.json")

    print(f"walkthrough scorer: follower={args.follower} "
          f"variant={args.walkthrough_variant} reps={args.reps} "
          f"targets={len(targets)}", flush=True)
    print(f"  sandboxes: {stage_root}", flush=True)
    print(f"  results:   {results_dir}", flush=True)

    results: list[dict] = []
    with rb.corpus_lock(corpus):
        for t in targets:
            t0 = time.time()
            try:
                r = run_target(corpus, t, args, stage_root, results_dir,
                               mcp_config)
            except Exception as e:  # noqa: BLE001 -- deliberately total
                r = {"slug": t["slug"], "difficulty": t.get("difficulty"),
                     "verdict": "NOT_MEASURABLE", "trials": [],
                     "reason": (f"the SCORER itself failed on this target "
                                f"({type(e).__name__}: {e}); an instrument "
                                "fault, not a measurement of the walkthrough")}
            r["elapsed_sec"] = round(time.time() - t0, 1)
            results.append(r)
            print(f"  {r['slug']:<26} {r['verdict']:<16} {r['reason'][:110]}",
                  flush=True)

    rates = compute_rates(results)
    gate = gate_result(rates, args.follower, args.reps, ran_full_manifest,
                       args.walkthrough_variant)
    meta = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "corpus_root": str(corpus.root),
        "manifest": str(corpus.manifest),
        "walkthrough_dir": str(args.walkthrough_dir),
        "follower_kind": args.follower,
        "follower_tier": args.tier.to_dict(),
        "walkthrough_variant": args.walkthrough_variant,
        "reps": args.reps,
        "arm_order": list(ARM_ORDER),
        "early_stopping": False,
        "strict_attribution": bool(args.strict_attribution),
        "ran_full_manifest": ran_full_manifest,
        "sandbox_root": str(stage_root),
        "isolation": ("process-level, NOT OS-level: sandbox outside the repo, "
                      "walkthrough sanitised fail-closed, file tools confined to "
                      "cwd, web tools denied, PYTHONPATH/SUPWNGO_* stripped, "
                      "transcript audited -- but HOME is SHARED (the follower "
                      "CLI needs its credentials) and a shell can read the "
                      "filesystem. That gap is DETECTED, not prevented."),
        "metric_name": "artifact_followable",
        "strace_available": att.strace_available(),
    }
    report = {**meta, "rates": rates, "gate": gate, "results": results}
    (results_dir / "report.json").write_text(json.dumps(report, indent=2,
                                                        default=str))
    text = write_summary(results, rates, gate, meta, results_dir / "summary.txt")
    print()
    print(text)
    print(f"Full report: {results_dir / 'report.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
