#!/usr/bin/env bash
# Wait until no REAL interpreter process matches a pattern. Never matches itself.
#
#   scripts/await_procs.sh <egrep-pattern> [poll_seconds] [max_seconds]
#   scripts/await_procs.sh 'pytest tests/' 20 3600
#
# Exit 0  nothing matches any more (what you were waiting for is done)
# Exit 1  bad usage
# Exit 2  max_seconds elapsed while something still matched (caller must NOT
#         treat this as "done" -- it is the inconclusive third state)
#
# WHY THIS EXISTS: THE SAME TRAP HAS NOW COST THIS PROJECT FIVE TIMES
# -------------------------------------------------------------------
# `benchmark/sample_load.sh` already documents both halves of this, and it kept
# happening anyway, because that knowledge lived in one script's comments rather
# than in something a person writing a waiter would actually reach for.
#
#   Trap 1 -- `pgrep -f "pytest tests/ -k"` matches any process whose full
#   COMMAND LINE contains the string, including the querying process and
#   including the waiter shell itself, whose argv holds the very pattern it is
#   searching for. `until ! pgrep -f ...` therefore never exits. Recorded in
#   sample_load.sh as having hung three agents, with four stale waiters parked on
#   this host, the oldest ~12 hours. A fourth agent hit it on 2026-09-28 and spun
#   ~59 minutes after its tests had already finished.
#
#   Trap 2 -- `ps -eo cmd | grep -c "[p]ytest tests/"` fixes only SELF-matching.
#   It still counts every unrelated SHELL whose command line mentions the string:
#   other sessions' waiters, `bash -c '... pytest ...'` wrappers, and so on.
#   sample_load.sh measured that form reporting 6 live harnesses when the true
#   count was 0. On 2026-09-28 it reported 4 live pytest runs to this session when
#   the true count was 0 -- every match was a 0%-CPU zsh waiter, one of them from
#   an unrelated project 12 days old -- and a status report was made on that basis.
#
# Both traps share one shape, and it is the shape worth remembering: a check that
# looks like it is measuring the world while it is actually measuring itself. It
# cannot fail in a way that looks like failure. The fix is to stop trusting argv
# and ask the kernel what the process actually IS: `/proc/<pid>/comm` is the
# executable name, so a shell that merely mentions the pattern is excluded by
# construction, and so is this script.
#
# Deliberately NOT a general process manager. It waits and it reports; it never
# kills anything.
set -uo pipefail

PATTERN="${1:-}"
POLL="${2:-15}"
MAX="${3:-3600}"

if [ -z "$PATTERN" ]; then
    sed -n '2,8p' "$0" >&2
    exit 1
fi

#: Executables that count as "a real run". A match whose comm is a shell is an
#: argv coincidence, not a process doing the work.
is_interpreter() {
    case "$1" in
        python*|*python*|pytest*|node|node[0-9]*|ruby*|perl*) return 0 ;;
        *) return 1 ;;
    esac
}

# Count matching processes whose executable is an interpreter, and print their
# pids so the number can be audited instead of trusted.
#
# Prints a single line: "<count><TAB><pid(comm) pid(comm) ...>". It has to RETURN
# the detail rather than set a global, because callers invoke it as `$(count_real)`
# and command substitution runs in a subshell -- a global assigned in here is
# discarded on the way out. The first version of this script did exactly that and
# then referenced the global, so under `set -u` it aborted with "MATCHED_PIDS:
# unbound variable" the moment it found anything at all. It passed both
# self-match tests, because those return before the variable is ever read: the
# script worked only while it had nothing to wait for. That is what the positive
# control in this file's red-proofs exists to catch.
count_real() {
    local n=0 pid comm rest detail=""
    while read -r pid rest; do
        [ -n "${pid:-}" ] || continue
        # Skip ourselves unconditionally, belt and braces alongside the comm test.
        [ "$pid" = "$$" ] && continue
        comm=$(cat "/proc/$pid/comm" 2>/dev/null || true)
        [ -n "$comm" ] || continue
        if is_interpreter "$comm"; then
            n=$((n + 1))
            detail="$detail $pid($comm)"
        fi
    done < <(ps -eo pid,cmd 2>/dev/null | grep -E "$PATTERN" | grep -v "await_procs.sh" || true)
    printf '%s\t%s' "$n" "$detail"
}

# Split count_real's one line into $N and $DETAIL in the CALLER's shell.
refresh() {
    local line
    line=$(count_real)
    N="${line%%$'\t'*}"
    DETAIL="${line#*$'\t'}"
}

elapsed=0
refresh
if [ "$N" -eq 0 ]; then
    echo "await_procs: nothing real matches '$PATTERN' -- already done (0s)"
    exit 0
fi
echo "await_procs: waiting on $N process(es) matching '$PATTERN':$DETAIL"

while [ "$elapsed" -lt "$MAX" ]; do
    sleep "$POLL"
    elapsed=$((elapsed + POLL))
    refresh
    if [ "$N" -eq 0 ]; then
        echo "await_procs: done after ${elapsed}s -- nothing real matches '$PATTERN'"
        exit 0
    fi
done

# Three states, not two. Saying "done" here would be a lie, and a caller that
# cannot tell "finished" from "gave up waiting" will read a partial result as a
# complete one.
echo "await_procs: TIMED OUT after ${elapsed}s with $N still running:$DETAIL" >&2
echo "await_procs: this is INCONCLUSIVE, not done -- do not read downstream output as final" >&2
exit 2
