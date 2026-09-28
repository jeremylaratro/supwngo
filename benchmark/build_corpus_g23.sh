#!/usr/bin/env bash
# Build every target in benchmark/corpus_g23/ from its committed C source,
# with the exact, documented protection flags recorded in each target's
# `cflags` file.
#
# Modeled directly on benchmark/build_all_r2.sh: per-target protection flags
# come from a `cflags` file beside the source (one gcc flag per line, blank
# lines and #-comments ignored), never a hardcoded case statement, and every
# target's flag is a FRESH random secret written to flag.txt at build time --
# never a literal baked into any committed .c source. This family's win()
# reads flag.txt at RUNTIME (fopen), the same as
# benchmark/corpus_r2/08_int_mul_overflow/int_mul_overflow.c, so there is no
# -DFLAG compile-time define to inject here.
#
# Idempotent / safe to re-run: each target is rebuilt unconditionally.
# Binaries are NOT committed to git (benchmark/.gitignore's corpus_*/* -style
# pattern already covers this).
#
# Usage:
#   benchmark/build_corpus_g23.sh                       # build all 6 targets
#   benchmark/build_corpus_g23.sh g23_10_adjacent_above  # build just one

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORPUS="$HERE/corpus_g23"

# Flags shared by every target (same rationale as build_all.sh/build_all_r2.sh):
#  -m64                 x86-64 only
#  -D_FORTIFY_SOURCE=0  disable glibc FORTIFY checks so the deliberately
#                        narrow reads/copies in these targets are not
#                        intercepted before the bug can be exercised
COMMON_FLAGS=(-m64 -D_FORTIFY_SOURCE=0 -g)

random_flag() {
    printf 'FLAG{%s}' "$(openssl rand -hex 16)"
}

build_one() {
    local dir="$1"
    local slug
    slug="$(basename "$dir")"
    local src="$dir/$slug.c"
    local out="$dir/$slug"

    if [[ ! -f "$src" ]]; then
        echo "SKIP: no source found for $dir (expected $src)" >&2
        return 1
    fi

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

    echo "==> building $(basename "$dir")"
    gcc "${flags[@]}" -o "$out" "$src"
    chmod 755 "$out"

    # win() reads this at runtime (fopen("flag.txt")); nothing here compiles
    # the flag into the binary's .rodata.
    random_flag > "$dir/flag.txt"
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

echo "Done. Binaries are gitignored -- rebuild any time with this script."
