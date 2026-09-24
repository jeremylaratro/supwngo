"""Falsifiability controls for the walkthrough scorer.

A validation step that cannot fail is worse than none, and this project has found
four of them. So "the scorer can return a NEGATIVE verdict" is a runnable,
committed test rather than a claim in a docstring.

THREE LAYERS, because any one of them alone is passable by a broken scorer
-------------------------------------------------------------------------
1. ARTIFACT layer. Score one good and five deliberately-broken artifacts against
   a real build of `02_ret2plt_system` and assert each verdict.

   The POSITIVE CONTROL RUNS FIRST. If it does not score CREDITED the harness is
   broken and the run reports NOT MEASURABLE (exit 2) instead of reporting the
   five negatives as passes -- a scorer that credits nothing "fails everything"
   and looks maximally strict while measuring nothing. That is the rule
   `benchmark/ablation/ablate.py` already follows.

   Fixtures are COPIED TO RANDOMISED FILENAMES before scoring, so a scorer that
   special-cased `good_reference.py` could not pass. (Peer review, finding 5.)

2. ARITHMETIC layer. `target_verdict()` and `compute_rates()` are driven as an
   explicit truth table -- every verdict, invalid trials in either arm, the
   denominator-inflation case, the withholding rule. These are the rules that
   decide the published number, and a rule only reachable through a 600-second
   LLM session is a rule nobody can check.

3. DIFFERENTIAL layer. `attribution.witness()` and `attribution.witness_argv()`
   must agree on the same artifact, because `witness()` was refactored to delegate
   to `witness_argv()` and `run_bench.py`'s behaviour must be unchanged.

Exit codes
----------
  0  every control behaved as required
  1  a control gave the WRONG verdict -- a defect in the scorer
  2  could not measure: unbuilt corpus, no strace, or the positive control failed
"""
from __future__ import annotations

import secrets
import shutil
import sys
import tempfile
from pathlib import Path

import attribution as att
import run_bench as rb

from followers import ARM_BARE, ARM_WALKTHROUGH, follower_env, redact_to_prose
from score import (REPO_ROOT, Stage, compute_rates, gate_result, score_artifact,
                   target_verdict)

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SELFTEST_SLUG = "02_ret2plt_system"

# (fixture, acceptable outcomes, must_be_credited)
#
# The positive control is FIRST in the list and is enforced as such below.
ARTIFACT_CASES: list[tuple[str, set[str], bool]] = [
    ("good_reference.py", {"CREDITED"}, True),
    ("broken_wrong_offset.py", {"NO_FLAG"}, False),
    ("broken_undeclared_constant.py", {"NO_FLAG"}, False),
    ("broken_impossible_route.py", {"NO_FLAG"}, False),
    ("broken_launders_flag_file.py", {"FOLLOWER_LAUNDERED"}, False),
    ("broken_stale_secret.py", {"NO_FLAG"}, False),
    ("broken_scrape_no_target.py", {"FOLLOWER_LAUNDERED", "FOLLOWER_GAMED"}, False),
]


def _trial(arm: str, rep: int, credited: bool, valid: bool = True,
           blindness: list[str] | None = None) -> dict:
    return {"arm": arm, "rep": rep, "credited": credited, "valid": valid,
            "invalid_reason": None if valid else "synthetic invalid trial",
            "blindness_hits": blindness or []}


# --------------------------------------------------------------------------- #
# layer 2: the arithmetic truth table
# --------------------------------------------------------------------------- #
def check_arithmetic() -> list[str]:
    """Every verdict rule and every denominator, asserted. Returns failures."""
    fails: list[str] = []

    def expect(label: str, got, want):
        if got != want:
            fails.append(f"{label}: expected {want!r}, got {got!r}")

    W, B = ARM_WALKTHROUGH, ARM_BARE

    # --- verdicts ---------------------------------------------------------- #
    expect("walkthrough wins, bare never does -> FOLLOWABLE",
           target_verdict("agent", [_trial(W, 1, True), _trial(B, 1, False)])[0],
           "FOLLOWABLE")
    expect("neither arm wins -> NOT_FOLLOWABLE",
           target_verdict("agent", [_trial(W, 1, False), _trial(B, 1, False)])[0],
           "NOT_FOLLOWABLE")
    expect("both arms win -> UNINFORMATIVE",
           target_verdict("agent", [_trial(W, 1, True), _trial(B, 1, True)])[0],
           "UNINFORMATIVE")
    expect("bare wins alone -> UNINFORMATIVE",
           target_verdict("agent", [_trial(W, 1, False), _trial(B, 1, True)])[0],
           "UNINFORMATIVE")
    # The asymmetry: ONE bare success out of three is enough to disqualify.
    expect("one bare success in 3 reps -> UNINFORMATIVE",
           target_verdict("agent", [
               _trial(W, 1, True), _trial(B, 1, False),
               _trial(W, 2, True), _trial(B, 2, False),
               _trial(W, 3, True), _trial(B, 3, True)])[0],
           "UNINFORMATIVE")
    # An invalid BARE trial must NOT be readable as "the bare arm failed".
    expect("invalid bare trial -> NOT_MEASURABLE, not FOLLOWABLE",
           target_verdict("agent", [_trial(W, 1, True),
                                    _trial(B, 1, False, valid=False)])[0],
           "NOT_MEASURABLE")
    expect("invalid walkthrough trial -> NOT_MEASURABLE",
           target_verdict("agent", [_trial(W, 1, False, valid=False),
                                    _trial(B, 1, False)])[0],
           "NOT_MEASURABLE")
    expect("blindness hit -> NOT_MEASURABLE",
           target_verdict("agent", [_trial(W, 1, True, blindness=["/repo"]),
                                    _trial(B, 1, False)])[0],
           "NOT_MEASURABLE")
    expect("missing bare arm -> NOT_MEASURABLE",
           target_verdict("agent", [_trial(W, 1, True)])[0], "NOT_MEASURABLE")
    # The template follower must be STRUCTURALLY unable to say FOLLOWABLE.
    expect("template + win -> TEMPLATE_OK (never FOLLOWABLE)",
           target_verdict("template", [_trial(W, 1, True)])[0], "TEMPLATE_OK")
    expect("template + loss -> TEMPLATE_BROKEN",
           target_verdict("template", [_trial(W, 1, False)])[0], "TEMPLATE_BROKEN")

    # --- denominators ------------------------------------------------------ #
    def res(*verdicts: str) -> list[dict]:
        return [{"slug": f"t{i}", "verdict": v} for i, v in enumerate(verdicts)]

    r = compute_rates(res(*(["FOLLOWABLE"] * 8 + ["NOT_FOLLOWABLE"] * 2)))
    expect("8/10 strict", round(r["rate_strict"], 4), 0.8)
    expect("8/10 informative", round(r["rate_informative"], 4), 0.8)

    # THE INFLATION CASE the peer review raised: one FAILING target becomes
    # UNINFORMATIVE. rate_informative goes UP (0.800 -> 0.889) while rate_strict
    # correctly goes DOWN. The gate must read the one that cannot be inflated.
    r2 = compute_rates(res(*(["FOLLOWABLE"] * 8 + ["NOT_FOLLOWABLE"]
                             + ["UNINFORMATIVE"])))
    expect("inflation: informative rises to 8/9",
           round(r2["rate_informative"], 4), 0.8889)
    expect("inflation: strict stays 8/10", round(r2["rate_strict"], 4), 0.8)
    if not r2["rate_informative"] > r["rate_informative"]:
        fails.append("inflation case did not actually raise rate_informative -- "
                     "the control no longer demonstrates what it exists for")

    # VOID leaves the eligible set entirely; NOT_MEASURABLE does not.
    r3 = compute_rates(res("FOLLOWABLE", "VOID"))
    expect("VOID leaves eligible", r3["eligible"], 1)
    expect("VOID -> strict 1/1", round(r3["rate_strict"], 4), 1.0)
    r4 = compute_rates(res("FOLLOWABLE", "NOT_MEASURABLE"))
    expect("NOT_MEASURABLE stays eligible", r4["eligible"], 2)
    expect("NOT_MEASURABLE -> strict 1/2", round(r4["rate_strict"], 4), 0.5)

    # The withholding rule.
    r5 = compute_rates(res(*(["FOLLOWABLE"] * 7 + ["UNINFORMATIVE"] * 3)))
    expect("30% excluded -> informative rate withheld",
           r5["informative_rate_withheld"], True)
    expect("10% excluded -> not withheld",
           compute_rates(res(*(["FOLLOWABLE"] * 9
                               + ["UNINFORMATIVE"])))["informative_rate_withheld"],
           False)

    # --- gate gating ------------------------------------------------------- #
    full = compute_rates(res(*(["FOLLOWABLE"] * 9 + ["NOT_FOLLOWABLE"])))
    expect("agent + full manifest + verbatim -> a stated gate",
           gate_result(full, "agent", 3, True, "verbatim")["gate"], "PASS")
    expect("template follower -> no gate",
           gate_result(full, "template", 3, True, "verbatim")["gate"], None)
    expect("subset run -> no gate",
           gate_result(full, "agent", 3, False, "verbatim")["gate"], None)
    expect("prose variant -> no gate",
           gate_result(full, "agent", 3, True, "prose")["gate"], None)
    expect("NOT_MEASURABLE present -> no gate",
           gate_result(compute_rates(res(*(["FOLLOWABLE"] * 9
                                           + ["NOT_MEASURABLE"]))),
                       "agent", 3, True, "verbatim")["gate"], None)
    expect("below threshold -> FAIL",
           gate_result(compute_rates(res(*(["FOLLOWABLE"] * 8
                                           + ["NOT_FOLLOWABLE"] * 2))),
                       "agent", 3, True, "verbatim")["gate"], "FAIL")

    # --- the prose redaction actually removes the answer ------------------- #
    sample = ("# teaching line\nOFFSET = 72\n"
              "p = process(BINARY)\np.send(b'A' * OFFSET)\n")
    redacted, info = redact_to_prose(sample)
    if "p.send" in redacted or "process(" in redacted:
        fails.append("prose redaction left executable statements behind")
    if "OFFSET = 72" not in redacted or "# teaching line" not in redacted:
        fails.append("prose redaction removed the teaching it is supposed to keep")
    if info["lines_dropped"] != 2:
        fails.append(f"prose redaction dropped {info['lines_dropped']} lines, "
                     "expected 2")
    return fails


# --------------------------------------------------------------------------- #
# layer 1 + 3: real artifacts against a real build
# --------------------------------------------------------------------------- #
def run(args) -> int:
    print("walkthrough scorer selftest -- proving this scorer can say NO")
    print("=" * 70)

    arith_fails = check_arithmetic()
    print(f"[arithmetic] truth table: "
          f"{'PASS' if not arith_fails else f'{len(arith_fails)} FAILURE(S)'}")
    for f in arith_fails:
        print(f"    FAIL {f}")

    if not att.strace_available():
        print("\n[artifact] NOT MEASURABLE: strace is unavailable, so no verdict "
              "here could rest on behavioural attribution. Refusing to report "
              "the broken fixtures as 'correctly refused' when they would be "
              "refused for the wrong reason.")
        return 2

    corpus = rb.Corpus(root=args.corpus_root.resolve(),
                       manifest=args.manifest.resolve())
    targets = {t["slug"] for t in corpus.targets()}
    if SELFTEST_SLUG not in targets:
        print(f"\n[artifact] NOT MEASURABLE: the fixtures are written against "
              f"{SELFTEST_SLUG}, which is not in {corpus.manifest}.")
        return 2

    stage_root = Path(tempfile.mkdtemp(prefix="wtselftest-"))
    stage = Stage(stage_root, SELFTEST_SLUG,
                  rb.Corpus.binary_name(SELFTEST_SLUG))
    workdir = stage.dirs[ARM_WALKTHROUGH]
    results: list[tuple[str, str, bool, bool]] = []

    with rb.corpus_lock(corpus):
        for index, (fixture, want_outcomes, want_credited) in enumerate(
                ARTIFACT_CASES):
            secret = rb.mint_secret_flag()
            try:
                rb.build_with_secret(corpus, SELFTEST_SLUG, secret)
            except rb.ProvisionError as e:
                print(f"\n[artifact] NOT MEASURABLE: could not build "
                      f"{SELFTEST_SLUG} with a secret flag: {e}")
                return 2
            stage.stage(corpus.binary(SELFTEST_SLUG),
                        corpus.flag_file(SELFTEST_SLUG), (ARM_WALKTHROUGH,))

            # Randomised filename: a scorer that recognised `good_reference.py`
            # by name could otherwise pass this whole suite.
            alias = workdir / f"artifact_{secrets.token_hex(6)}.py"
            shutil.copy2(FIXTURES / fixture, alias)

            scored = score_artifact(
                artifact=alias, workdir=workdir,
                target_binary=stage.binary(ARM_WALKTHROUGH),
                expected_flag=secret, timeout=args.timeout,
                trace_dir=stage_root / f"trace_{index}",
                strict_attribution=False)
            outcome = scored["outcome"]
            ok = outcome in want_outcomes and bool(scored["credited"]) == want_credited
            results.append((fixture, outcome, ok, want_credited))
            print(f"  {'OK  ' if ok else 'FAIL'} {fixture:<34} -> {outcome:<20} "
                  f"credited={scored['credited']}  "
                  f"(wanted {'/'.join(sorted(want_outcomes))})")
            if not ok:
                print(f"       reason: {scored['reason'][:200]}")

            # POSITIVE CONTROL FIRST: stop here if it failed. Reporting the
            # negatives as passes when the harness cannot credit anything would
            # be the exact defect this file exists to prevent.
            if index == 0 and not ok:
                print("\n[artifact] NOT MEASURABLE: the POSITIVE CONTROL failed.")
                print("  A scorer that cannot credit a known-good exploit would")
                print("  'correctly refuse' every broken fixture for the wrong")
                print("  reason, and would look maximally strict while measuring")
                print("  nothing. Fix the harness (build flags, pwntools, ptrace")
                print("  permission) and re-run before trusting any verdict.")
                return 2

        # layer 3: witness() must still agree with witness_argv().
        diff_ok = _check_witness_differential(corpus, stage, stage_root,
                                              args.timeout)

    bad = [r for r in results if not r[2]]
    print()
    print("=" * 70)
    print(f"artifact layer : {len(results) - len(bad)}/{len(results)} correct")
    print(f"arithmetic     : {'PASS' if not arith_fails else 'FAIL'}")
    print(f"differential   : {'PASS' if diff_ok else 'FAIL'}")
    credited = [r for r in results if r[3]]
    refused = [r for r in results if not r[3] and r[2]]
    print()
    print(f"The scorer credited the {len(credited)} known-good artifact and "
          f"REFUSED {len(refused)} of {len(results) - len(credited)} deliberately "
          f"broken ones.")
    print("A scorer that had never returned a negative verdict would not be a "
          "scorer; this one has, on the record above.")
    if bad or arith_fails or not diff_ok:
        print("\nSELFTEST FAILED -- do not trust a measurement from this scorer "
              "until the failures above are fixed.")
        return 1
    print("\nSELFTEST PASSED.")
    return 0


def _check_witness_differential(corpus: rb.Corpus, stage: Stage,
                                stage_root: Path, timeout: float) -> bool:
    """`witness()` was refactored to delegate; prove it did not change.

    `run_bench.py` calls `witness()` and nothing else, so if the delegation
    altered its result the autopwn number would shift for a reason nobody
    intended. Same artifact, same build, both entry points, same verdict.
    """
    secret = rb.mint_secret_flag()
    try:
        rb.build_with_secret(corpus, SELFTEST_SLUG, secret)
    except rb.ProvisionError:
        print("  [differential] SKIPPED: could not rebuild the target")
        return True
    workdir = stage.dirs[ARM_WALKTHROUGH]
    stage.stage(corpus.binary(SELFTEST_SLUG), corpus.flag_file(SELFTEST_SLUG),
                (ARM_WALKTHROUGH,))
    artifact = workdir / "differential.py"
    shutil.copy2(FIXTURES / "good_reference.py", artifact)
    env = follower_env(REPO_ROOT, tmpdir=workdir / ".tmp")
    (workdir / ".tmp").mkdir(exist_ok=True)

    common = dict(target_dir=workdir, target_binary=stage.binary(ARM_WALKTHROUGH),
                  expected_flag=secret, stdin_bytes=rb.VERIFY_STDIN,
                  timeout=timeout, env=env)
    a = att.witness(script_path=artifact, python=sys.executable,
                    trace_dir=stage_root / "diff_witness", **common)
    b = att.witness_argv(argv=[sys.executable, str(artifact)],
                         trace_dir=stage_root / "diff_witness_argv", **common)
    keys = ("available", "flag_disclosed_by_target", "target_observed",
            "shell_proven")
    same = all(a.get(k) == b.get(k) for k in keys)
    print(f"  {'OK  ' if same else 'FAIL'} witness() vs witness_argv(): "
           + ", ".join(f"{k}={a.get(k)}/{b.get(k)}" for k in keys))
    return same
