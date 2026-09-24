#!/usr/bin/env bash
# Post-run contamination check: does the autopwn route ever open the corpus SOURCE?
#
# The benchmark's premise is that the pipeline works from the BINARY. If any code
# path on the `supwngo autopwn` route read `<target>.c`, or a reference exploit,
# the measurement would be of a source-assisted pipeline and the figure would not
# mean what the report says it means.
#
# `supwngo/analysis/source.py` does read `.c` files, but static audit says it is
# reachable only from the separate `supwngo source` CLI verb, never from `autopwn`.
# A static audit is an argument about code; this is an observation of behaviour.
#
# WHAT THIS CAN AND CANNOT ESTABLISH -- stated because the gap is the point.
# This REPLAYS the cold run's command line on the same binaries AFTER the fact. It
# does not observe the cold executions themselves, so in principle a cold
# execution's access path could have differed. That residual is disclosed in the
# report rather than argued away. The bound on it: R2's secret exists only in
# `flag.txt` at runtime and attribution credits a success only when the target
# process or a descendant writes the flag, so reading source could at most confer
# an informational advantage -- it cannot manufacture a flag.
#
# Instrumenting the cold run itself was rejected deliberately: an audit hook in
# every measured process adds per-`open` overhead inside the same 20 s per-technique
# budget that is already the tightest constraint on the primary measurement. Trading
# a real risk to the primary endpoint for a check on a bounded secondary one is a
# bad trade. The structural fix -- build the hook into the instrument from the start
# of a round, so baseline and measurement share it -- is deferred to R3+.
#
# Usage: benchmark/contamination_check.sh <corpus_root> <outdir> [timeout]
set -uo pipefail

CORPUS="${1:?usage: contamination_check.sh <corpus_root> <outdir> [timeout]}"
OUTDIR="${2:?usage: contamination_check.sh <corpus_root> <outdir> [timeout]}"
TIMEOUT="${3:-20}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

mkdir -p "$OUTDIR"

pids=()
for d in "$CORPUS"/*/; do
    slug="$(basename "$d")"
    # The target binary is the one executable file that is not the .c or cflags.
    bin=""
    for f in "$d"*; do
        case "$f" in *.c|*/cflags|*/flag.txt) continue ;; esac
        [ -x "$f" ] && bin="$f"
    done
    [ -n "$bin" ] || { echo "SKIP $slug: no binary"; continue; }
    (
        cd "$REPO_ROOT" || exit 1
        strace -f -e trace=openat,open -o "$OUTDIR/$slug.strace" \
            python3 -m supwngo.cli autopwn "$bin" --timeout "$TIMEOUT" --json \
            > "$OUTDIR/$slug.stdout" 2> "$OUTDIR/$slug.stderr"
    ) &
    pids+=($!)
done

for p in "${pids[@]}"; do wait "$p"; done
echo "traces written to $OUTDIR"
