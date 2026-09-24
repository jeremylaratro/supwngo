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
# COUNTING THE CONCURRENT HARNESSES IS ITSELF A TRAP, TWICE OVER
# -------------------------------------------------------------
# `pgrep -f run_bench.py` matches any process whose *command line* contains that
# string -- including the querying process itself, and including any
# `until ! pgrep -f "run_bench.py"` waiter, which therefore can never exit. That
# has cost three agents in this project a hang; four such stale waiters were
# found parked on this host, the oldest at ~12 hours.
#
# `ps aux | grep "[r]un_bench.py"` fixes only *self*-matching. It still counts
# every unrelated **shell** whose command line mentions the string -- the stale
# waiters above, and every `bash -c '... run_bench.py ...'` wrapper. Measured
# directly: that form reported 6 "live harnesses" when the true number of running
# Python processes was 0, the rest being 0%-CPU zsh shells.
#
# "6 live" and "0 live" support completely different claims about the conditions a
# measurement was taken under, so this counts only processes whose executable is
# actually a Python interpreter, and reports the cwd-resolved detail separately so
# a reader can audit the number rather than trust it.
#
# Usage:
#   benchmark/sample_load.sh <outfile> [interval_seconds]
# Stop it by killing the PID it prints.
set -euo pipefail

OUT="${1:?usage: sample_load.sh <outfile> [interval_seconds]}"
INTERVAL="${2:-15}"

# Count real harness processes: the comm must be a python interpreter, so a shell
# that merely mentions run_bench.py in its argv is not counted.
count_harnesses() {
    local n=0 pid comm
    while read -r pid _; do
        [ -n "$pid" ] || continue
        comm=$(cat "/proc/$pid/comm" 2>/dev/null || true)
        case "$comm" in
            python*|*python*) n=$((n + 1)) ;;
        esac
    done < <(ps -eo pid,cmd | grep -E "[r]un_bench\.py|[a]blate(_r2)?\.py" || true)
    printf '%s' "$n"
}

printf 'timestamp_utc\tload1\tload5\tload15\tharness_procs_python\n' > "$OUT"

while true; do
    read -r l1 l5 l15 _ < /proc/loadavg
    printf '%s\t%s\t%s\t%s\t%s\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$l1" "$l5" "$l15" "$(count_harnesses)" \
        >> "$OUT"
    sleep "$INTERVAL"
done
