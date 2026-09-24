#!/usr/bin/env bash
# Sample host load for the duration of a benchmark run.
#
# Why: a single pre-run load snapshot cannot detect contention that ARISES
# DURING a run, and this host cannot be reserved -- other agents run the harness
# concurrently. Exploit delivery is contention-sensitive (a genuine ret2plt
# exploit measured 4/96 failures under 24-way contention and 0/96 unloaded), so a
# reliability k/N split taken under an unrecorded load spike is not interpretable.
#
# This records loadavg and the concurrent run_bench.py count every INTERVAL
# seconds so the run's load profile can be reported alongside its numbers, and
# any rep whose window overlaps an excursion can be flagged as a contention
# suspect rather than read as a capability signal.
#
# Note: the run_bench.py count uses `ps aux | grep "[r]un_bench.py"`. It does NOT
# use `pgrep -f`, which matches the searching process's own command line and so
# reports itself -- a trap that has cost three agents in this project a ~30
# minute hang.
#
# Usage:
#   benchmark/sample_load.sh <outfile> [interval_seconds]
# Stop it by killing the PID it prints.
set -euo pipefail

OUT="${1:?usage: sample_load.sh <outfile> [interval_seconds]}"
INTERVAL="${2:-15}"

printf 'timestamp_utc\tload1\tload5\tload15\trun_bench_procs\n' > "$OUT"

while true; do
    read -r l1 l5 l15 _ < /proc/loadavg
    n=$(ps aux | grep -c "[r]un_bench.py" || true)
    printf '%s\t%s\t%s\t%s\t%s\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$l1" "$l5" "$l15" "$n" >> "$OUT"
    sleep "$INTERVAL"
done
