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
  menu_walk     the flag appeared when the bare target was fed small integers,
                i.e. an ordinary menu walk with no address/offset/gadget. Catches
                a read path with no liveness or authorization gate -- a "UAF"
                target that never needs the free, say.
                                             -> target is unmeasurable
  scrapeable    channels by which this run's secret can be read with NO exploit
                at all (`strings` output / raw image substring). Not a failure by
                default -- win()-style targets must compile the flag in -- but a
                SUCCESS on such a target rests on the bypassable script audit
                rather than a structural guarantee. Prefer targets whose win()
                prints the CONTENTS OF flag.txt at runtime; run_bench.py
                --strict-attribution VOIDs these instead of scoring them.
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
    print(f"{'target':<24} {'verify_stdin':<13} {'filler512':<10} "
          f"{'menu_walk':<10} scrapeable")
    print("-" * 78)

    unmeasurable, failed, scrapeable = [], [], []
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
        c = nc["controls"]["bare_run_menu_walk"]["flag_found"]
        if a or b or c:
            unmeasurable.append(slug)
        chans = rb.scrape_channels(nc)
        if chans:
            scrapeable.append(slug)
        print(f"{slug:<24} {str(a):<13} {str(b):<10} {str(c):<10} "
              f"{','.join(chans) or '-'}")

    print()
    if failed:
        print(f"PROVISIONING FAILED (see R3/R6): {failed}")
    if unmeasurable:
        print(f"UNMEASURABLE -- leak the flag to benign input (R7): {unmeasurable}")
        print("These targets cannot distinguish a working exploit from a no-op.")
        print("run_bench.py scores them VOID. Fix the targets.")
    else:
        print("OK: no target leaks its flag to benign input.")
    if scrapeable:
        print()
        print(f"SCRAPEABLE -- secret readable with no exploit ({len(scrapeable)}): "
              f"{scrapeable}")
        print("Not counted as unmeasurable here: a win()-style target MUST compile")
        print("the flag in. But a SUCCESS on these rests on run_bench.py's")
        print("bypassable script audit, not on a structural guarantee. The corpus")
        print("fix is to have win() print the CONTENTS OF flag.txt at runtime.")
    return 1 if (unmeasurable or failed) else 0


if __name__ == "__main__":
    sys.exit(main())
