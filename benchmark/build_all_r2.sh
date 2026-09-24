#!/usr/bin/env bash
# Build every target in benchmark/corpus_r2/ from its committed C source,
# with the exact, documented protection flags recorded in corpus_r2.yaml.
#
# Modeled directly on benchmark/build_all.sh (round-1's builder) but kept
# entirely separate: this script only ever touches benchmark/corpus_r2/,
# never benchmark/corpus/, and benchmark/build_all.sh itself is untouched.
#
# Idempotent / safe to re-run: each target is rebuilt unconditionally (a
# fresh `gcc` invocation), so re-running just recompiles from the same
# committed source -- nothing here depends on prior build state. Binaries
# are NOT committed to git (see benchmark/.gitignore, which already covers
# corpus_r2/ via its corpus/*/* -style pattern -- see this script's final
# echo for the exact rule); this script is how a fresh clone gets working
# round-2 targets.
#
# Usage:
#   benchmark/build_all_r2.sh                         # build all 15 targets
#   benchmark/build_all_r2.sh 07_static_ret2syscall    # build just one target dir

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORPUS="$HERE/corpus_r2"

# Flags shared by every target (identical rationale to build_all.sh):
#  -m64                 x86-64 only (this corpus's declared architecture scope)
#  -D_FORTIFY_SOURCE=0  disable glibc FORTIFY checks (would abort some of
#                        the deliberately-vulnerable calls, e.g. %n format
#                        writes, before the vulnerability could be
#                        exercised) -- these targets test supwngo's own
#                        analysis, not glibc's runtime hardening
#  -Wno-format-security -Wno-format
#                        the format-string targets pass a non-literal,
#                        user-controlled string to printf() on purpose
COMMON_FLAGS=(-m64 -D_FORTIFY_SOURCE=0 -Wno-format-security -Wno-format -g)

# SECURITY / SOUNDNESS NOTE (do not regress this): round 1's build_all.sh
# baked a deterministic, name-derived flag literal into every target's
# source/.rodata (FLAG{supwngo_bench_$(basename "$dir")}), committed in
# git. Any exploit that just printed that predictable constant scored
# SUCCESS without exploiting anything -- an audit found this invalidated
# 9/15 of round 1's results. This builder deliberately does NOT reproduce
# that pattern: every target gets a FRESH random secret flag generated
# HERE, at build time, injected via `gcc -DFLAG="\"...\""`, and NEVER
# committed to git (flag.txt is gitignored; no flag literal exists in any
# committed corpus_r2/*.c source -- each references the FLAG macro only,
# and #errors out at compile time if it isn't supplied).
random_flag() {
    printf 'FLAG{%s}' "$(openssl rand -hex 16)"
}

build_one() {
    local dir="$1"
    local slug
    slug="$(basename "$dir")"
    slug="${slug#[0-9][0-9]_}"
    local src="$dir/$slug.c"
    local out="$dir/$slug"

    if [[ ! -f "$src" ]]; then
        echo "SKIP: no source found for $dir (expected $src)" >&2
        return 1
    fi

    # Per-target protection flags are declared in a `cflags` file beside the
    # source, one gcc flag per line (blank lines and #-comments ignored) --
    # NOT a hardcoded case statement here. This is the exact convention the
    # shared benchmark/build_all.sh's own fallback branch (R9) reads for any
    # corpus directory it doesn't recognize by name, and this builder reads
    # the SAME files rather than keeping a second, independently-maintained
    # list of flags: two builders that can diverge would eventually build
    # protections the manifest doesn't claim, silently invalidating the
    # measurement. Fails closed (clear error, non-zero exit) if the file is
    # missing, since the protections ARE part of what's being measured and
    # must never be guessed.
    local -a flags=("${COMMON_FLAGS[@]}")
    local cflags_file="$dir/cflags"
    if [[ -f "$cflags_file" ]]; then
        local line
        while IFS= read -r line || [[ -n "$line" ]]; do
            line="${line%%#*}"
            line="$(echo "$line" | tr -d '[:space:]')"
            [[ -n "$line" ]] && flags+=("$line")
        done < "$cflags_file"
    else
        echo "FAIL: $(basename "$dir") has no $cflags_file declaring its" >&2
        echo "      protection flags. Protections are part of the" >&2
        echo "      measurement, so this builder will not guess them." >&2
        return 1
    fi

    # Fresh random secret per target per build -- generated BEFORE
    # compilation so it can be injected as a compile-time -D define.
    # Written to flag.txt (gitignored) for the shell-obtaining targets
    # (01, 02, 03, 07), whose intended solve path lands a shell and reads
    # this file rather than the binary printing the flag itself; harmless,
    # unused input for every other target, which prints/writes FLAG
    # directly via the compiled-in macro instead.
    local flag
    flag="$(random_flag)"
    flags+=(-DFLAG="\"$flag\"")

    echo "==> building $(basename "$dir")"
    gcc "${flags[@]}" -o "$out" "$src"
    chmod 755 "$out"

    printf '%s\n' "$flag" > "$dir/flag.txt"
}

if [[ $# -gt 0 ]]; then
    for name in "$@"; do
        build_one "$CORPUS/$name"
    done
else
    for dir in "$CORPUS"/*/; do
        build_one "${dir%/}"
    done
fi

echo "Done. Binaries are gitignored (benchmark/.gitignore's corpus_r2/*/* rule," \
     "added alongside the round-1 corpus/*/* rule) -- rebuild any time with" \
     "this script."
