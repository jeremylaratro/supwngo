"""Prove behavioural attribution discriminates exploitation from scraping.

For each (target, probe) pair this rebuilds the target with a fresh secret,
re-executes the probe under the strace witness, and prints what the witness
concluded. The contract being tested:

    every [GENUINE] probe   -> credited
    every [NO-EXPLOIT] probe -> not_credited or no_flag, NEVER credited

The interesting rows are the ones that defeat the pattern audit:
`pure_python_scrape.py` scores SUCCESS under string matching on any
win()-style target, and must be `not_credited` here.

    python3 benchmark/soundness_probes/attribution_sweep.py
    python3 benchmark/soundness_probes/attribution_sweep.py 15_win_function
"""
import os
import sys
from pathlib import Path

BENCH = Path(__file__).resolve().parent.parent
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(BENCH))

import attribution as attr  # noqa: E402
import run_bench as rb  # noqa: E402

NO_EXPLOIT = ["donothing_interactive.py", "donothing_subprocess.py",
              "hardcoded_flag.py", "pure_python_scrape.py"]
GENUINE = {
    "02_ret2plt_system": ["real_exploit_02.py", "real_exploit_02_explicit.py"],
    "15_win_function": ["real_exploit_15.py"],
}


def main() -> int:
    corpus = rb.Corpus(root=rb.DEFAULT_CORPUS_DIR, manifest=rb.DEFAULT_CORPUS_YAML)
    targets = sys.argv[1:] or ["02_ret2plt_system", "15_win_function"]

    if not attr.strace_available():
        print("strace is not installed -- attribution cannot be demonstrated")
        return 2

    failures = 0
    for slug in targets:
        secret = rb.mint_secret_flag()
        try:
            rb.build_with_secret(corpus, slug, secret)
        except rb.ProvisionError as e:
            print(f"{slug}: PROVISION FAILED: {e}")
            failures += 1
            continue

        flag = corpus.flag_file(slug).read_text().strip()
        tdir = corpus.target_dir(slug)
        env = {**os.environ, "PYTHONPATH": str(rb.REPO_ROOT),
               "PWNLIB_NOTERM": "1", "PWNLIB_SILENT": "1"}
        scrapeable = flag.encode() in corpus.binary(slug).read_bytes()
        print(f"\n{slug}   secret={flag}   flag_in_binary={scrapeable}")

        for probe in NO_EXPLOIT + GENUINE.get(slug, []):
            genuine = probe in GENUINE.get(slug, [])
            kind = "GENUINE   " if genuine else "NO-EXPLOIT"
            att = attr.witness(
                HERE / probe, tdir, corpus.binary(slug), flag,
                rb.VERIFY_STDIN, 10.0, env, sys.executable,
                tdir / ".attribution" / probe)
            verdict, why = attr.attribution_verdict(att)

            note = "ok"
            if genuine and verdict != "credited":
                note = "*** FALSE NEGATIVE ***"
                failures += 1
            if not genuine and verdict == "credited":
                note = "*** FALSE POSITIVE ***"
                failures += 1

            print(f"  [{kind}] {probe:<30} string_match={str(att.get('flag_in_output')):<5} "
                  f"-> {verdict:<13} shell={str(att.get('shell_proven')):<5} {note}")
            if not genuine and att.get("flag_in_output") and verdict != "credited":
                print(f"      witness: {why}")

    print()
    print("FAILURES:", failures)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
