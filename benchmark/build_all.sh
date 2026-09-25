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
# SUPWNGO_BENCH_CORPUS lets a caller point this builder at an alternate corpus
# tree (e.g. benchmark/corpus_r2). Unset => today's benchmark/corpus.
#
# NOTE: per-target protection flags are a case statement below, keyed on the
# target directory name, so an alternate corpus still needs its own entries
# there (an unknown directory is refused, which run_bench.py surfaces as a
# VOID "could not be provisioned" result rather than a silent mis-build).
CORPUS="${SUPWNGO_BENCH_CORPUS:-$HERE/corpus}"

# SUPWNGO_BENCH_FLAG, when set, makes the flag a PER-RUN SECRET instead of a
# constant grepped out of the (git-committed) C source. It is both compiled
# into the binary (every win()-style target guards its flag with
# `#ifndef FLAG`, so -DFLAG overrides it) and written to flag.txt, so the
# only ways to obtain it are to reach the code that prints it or to read
# flag.txt from a shell the exploit actually got.
#
# This closes a measurement false positive: with a source-derived flag, the
# "secret" is a public constant present in git AND in the binary's .rodata,
# so a script that merely hardcodes the literal (or runs `strings`) scores
# as a successful exploitation. See
# docs/reports/HARNESS-SOUNDNESS-AUDIT-23SEP2026.md.
#
# Unset => legacy source-derived behaviour, preserved for manual/ad-hoc builds.
BENCH_FLAG="${SUPWNGO_BENCH_FLAG:-}"

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
            # A target from a corpus round this case statement has never heard
            # of. The per-target protection flags ARE the measurement, so we
            # must not guess them -- building a canary=ON target with defaults
            # would silently measure a different challenge. Instead the target
            # declares them itself, in a `cflags` file beside its source, one
            # gcc flag per line (blank lines and #-comments ignored):
            #
            #     benchmark/corpus_r2/03_your_target/cflags
            #         -fno-stack-protector
            #         -no-pie
            #
            # Absent that file we fail closed rather than build something
            # plausible, so a corpus author gets a clear error instead of a
            # quiet mis-measurement.
            if [[ -f "$dir/cflags" ]]; then
                local line
                while IFS= read -r line || [[ -n "$line" ]]; do
                    line="${line%%#*}"
                    line="$(echo "$line" | tr -d '[:space:]')"
                    [[ -n "$line" ]] && flags+=("$line")
                done < "$dir/cflags"
            else
                echo "FAIL: $(basename "$dir") is not a known target and has no" >&2
                echo "      $dir/cflags declaring its protection flags." >&2
                echo "      Protections are part of the measurement, so this" >&2
                echo "      builder will not guess them. See benchmark/README.md R9." >&2
                return 1
            fi
            ;;
    esac

    # The flag this build will use. With SUPWNGO_BENCH_FLAG set it is a
    # per-run secret (see the note at the top of this file); otherwise it
    # falls back to the legacy source-derived constant.
    local flag
    if [[ -n "$BENCH_FLAG" ]]; then
        flag="$BENCH_FLAG"
        # Override the source's `#ifndef FLAG` default so win()-style targets
        # print the per-run secret rather than the committed literal.
        flags+=(-DFLAG="\"$flag\"")
    else
        flag="$(grep -oE 'FLAG\{[^}]*\}' "$src" | head -1 || true)"
        if [[ -z "$flag" ]]; then
            flag="FLAG{supwngo_bench_$(basename "$dir")}"
        fi
    fi

    echo "==> building $(basename "$dir")"
    gcc "${flags[@]}" -o "$out" "$src"
    chmod 755 "$out"

    # For the shell-obtaining targets (01,02,03,07,08,09) the C source
    # never prints a flag itself -- the intended solve path ends in an
    # interactive shell, from which the harness's verification step reads
    # this file. It is harmless (and unused) for the win()-style targets.
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
