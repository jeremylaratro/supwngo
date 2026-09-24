#!/usr/bin/env bash
# Build every target in benchmark/corpus/ from its committed C source, with
# the exact, documented protection flags recorded in corpus.yaml.
#
# Idempotent / safe to re-run: each target is rebuilt unconditionally (a
# fresh `gcc` invocation), so re-running just recompiles from the same
# committed source -- nothing here depends on prior build state. Binaries
# are NOT committed to git (see benchmark/.gitignore); this script is how a
# fresh clone gets working targets.
#
# Usage:
#   benchmark/build_all.sh              # build all 15 targets
#   benchmark/build_all.sh 07_ret2libc_leak   # build just one target dir

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORPUS="$HERE/corpus"

# Flags shared by every target:
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

    local -a flags=("${COMMON_FLAGS[@]}")
    case "$(basename "$dir")" in
        01_shellcode_stack)
            # canary=OFF nx=OFF pie=OFF relro=partial dynamic
            flags+=(-fno-stack-protector -no-pie -z execstack)
            ;;
        02_ret2plt_system)
            # canary=OFF nx=ON pie=OFF relro=partial dynamic
            flags+=(-fno-stack-protector -no-pie)
            ;;
        03_pie_leak_ret2libc)
            # canary=OFF nx=ON pie=ON relro=partial dynamic
            flags+=(-fno-stack-protector -pie -fPIE)
            ;;
        04_canary_leak_bypass)
            # canary=ON nx=ON pie=OFF relro=partial dynamic
            flags+=(-fstack-protector-all -no-pie)
            ;;
        05_fmtstr_arbread)
            # canary=ON nx=ON pie=OFF relro=partial dynamic
            flags+=(-fstack-protector-all -no-pie)
            ;;
        06_fmtstr_arbwrite)
            # canary=OFF nx=ON pie=OFF relro=partial (GOT writable) dynamic
            flags+=(-fno-stack-protector -no-pie)
            ;;
        07_ret2libc_leak)
            # canary=OFF nx=ON pie=OFF relro=partial dynamic
            flags+=(-fno-stack-protector -no-pie)
            ;;
        08_ret2dlresolve)
            # canary=OFF nx=ON pie=OFF relro=partial/lazy (no -z now) dynamic
            flags+=(-fno-stack-protector -no-pie)
            ;;
        09_srop)
            # canary=OFF nx=ON pie=OFF relro=partial dynamic
            flags+=(-fno-stack-protector -no-pie)
            ;;
        10_int_overflow)
            # canary=OFF nx=ON pie=OFF relro=partial dynamic
            flags+=(-fno-stack-protector -no-pie)
            ;;
        11_heap_uaf_leak)
            # canary=OFF nx=ON pie=OFF relro=partial dynamic
            flags+=(-fno-stack-protector -no-pie)
            ;;
        12_heap_tcache_poison)
            # canary=OFF nx=ON pie=OFF relro=partial (GOT writable) dynamic
            flags+=(-fno-stack-protector -no-pie)
            ;;
        13_off_by_one)
            # canary=OFF nx=ON pie=ON relro=partial dynamic
            flags+=(-fno-stack-protector -pie -fPIE)
            ;;
        14_negative_index)
            # canary=OFF nx=ON pie=OFF relro=partial STATIC
            flags+=(-fno-stack-protector -no-pie -static)
            ;;
        15_win_function)
            # canary=OFF nx=ON pie=OFF relro=FULL dynamic
            flags+=(-fno-stack-protector -no-pie -Wl,-z,relro,-z,now)
            ;;
        *)
            echo "SKIP: unknown target directory $(basename "$dir")" >&2
            return 1
            ;;
    esac

    echo "==> building $(basename "$dir")"
    gcc "${flags[@]}" -o "$out" "$src"
    chmod 755 "$out"

    # For the shell-obtaining targets (01,02,03,07,08,09) the C source
    # never prints a flag itself -- the intended solve path ends in an
    # interactive shell, from which the harness's verification step reads
    # this file. It is harmless (and unused) for the win()-style targets.
    local flag
    flag="$(grep -oE 'FLAG\{[^}]*\}' "$src" | head -1 || true)"
    if [[ -z "$flag" ]]; then
        flag="FLAG{supwngo_bench_$(basename "$dir")}"
    fi
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

echo "Done. Binaries are gitignored (benchmark/.gitignore) -- rebuild any time with this script."
