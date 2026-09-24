"""Negative-control sweep over every target in a corpus.

Answers the question that gates whether a target is a measurement at all
(convention rule R7 in benchmark/README.md): *does this target hand out its
flag to benign input, with no exploitation?*

Run this on a new corpus BEFORE trusting any score from it. It does not invoke
autopwn, so it is fast (seconds per target, not minutes).

    python3 benchmark/soundness_probes/negative_control_sweep.py
    python3 benchmark/soundness_probes/negative_control_sweep.py \
        --corpus-root benchmark/corpus_r2 --manifest benchmark/corpus_r2.yaml

Each target is rebuilt with a fresh secret flag, so this rewrites
<corpus>/<slug>/{<binary>,flag.txt}. Don't run it concurrently with
run_bench.py on the same corpus -- point it at a copy if you need to.

Columns:
  verify_stdin  the flag appeared when the bare target was fed run_bench.py's
                own injected stdin           -> target is unmeasurable
  filler512     the flag appeared when the bare target was fed 512 'A's
                                             -> target is unmeasurable
  in_binary     this run's secret is present in the built image; such a target
                can be scraped rather than exploited (documented limitation,
                not a failure) -- prefer targets that print flag.txt instead
"""
import argparse
import sys
from pathlib import Path

BENCH = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BENCH))
import run_bench as rb  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus-root", type=Path, default=rb.DEFAULT_CORPUS_DIR)
    ap.add_argument("--manifest", type=Path, default=rb.DEFAULT_CORPUS_YAML)
    ap.add_argument("--timeout", type=float, default=10.0)
    args = ap.parse_args()

    corpus = rb.Corpus(root=args.corpus_root.resolve(),
                       manifest=args.manifest.resolve())

    print(f"corpus: {corpus.root}\n")
    print(f"{'target':<24} {'verify_stdin':<14} {'filler512':<11} in_binary")
    print("-" * 66)

    unmeasurable, failed = [], []
    for t in corpus.targets():
        slug = t["slug"]
        try:
            rb.build_with_secret(corpus, slug, rb.mint_secret_flag())
        except rb.ProvisionError as e:
            print(f"{slug:<24} PROVISION FAILED: {str(e)[:56]}")
            failed.append(slug)
            continue
        flag = corpus.flag_file(slug).read_text().strip()
        nc = rb.negative_control(corpus, slug, flag, args.timeout)
        a = nc["controls"]["bare_run_verify_stdin"]["flag_found"]
        b = nc["controls"]["bare_run_filler"]["flag_found"]
        if a or b:
            unmeasurable.append(slug)
        print(f"{slug:<24} {str(a):<14} {str(b):<11} "
              f"{nc['flag_statically_extractable_from_binary']}")

    print()
    if failed:
        print(f"PROVISIONING FAILED (see R3/R6): {failed}")
    if unmeasurable:
        print(f"UNMEASURABLE -- leak the flag to benign input (R7): {unmeasurable}")
        print("These targets cannot distinguish a working exploit from a no-op.")
        print("run_bench.py scores them VOID. Fix the targets.")
    else:
        print("OK: no target leaks its flag to benign input.")
    return 1 if (unmeasurable or failed) else 0


if __name__ == "__main__":
    sys.exit(main())
