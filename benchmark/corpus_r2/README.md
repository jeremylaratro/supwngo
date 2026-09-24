# Round 2 — held-out generalization check

Round 2 of the supwngo benchmark corpus. 15 deliberately-vulnerable x86-64
Linux ELF targets, all lab-only, purpose-built to check whether a concurrent
framework-hardening effort (on `integration/phases-0-4-7-20260923`) genuinely
generalized, or merely got tuned to round 1's specific 15 files.

**This branch (`feat/benchmark-corpus-r2-20260923`) is never merged into the
integration branch.** It stays held out so the hardening agents cannot see
it, which is the entire point of a generalization check.

Round 2 covers the same technique families as round 1 (stack overflow +
shellcode, ret2plt/system, ret2libc with/without a leak, canary leak/bypass,
format-string read and write, integer/size-arithmetic bugs, heap bugs,
off-by-one, an indexing bug, and an advanced ROP variant), but every target
is a genuinely different code shape: different struct layouts, different
stack offsets and frame sizes, different gate mechanics, different heap
primitives, different gadget chains — not a renamed or lightly-edited copy of
a round-1 source file.

| # | slug | technique | difficulty |
|---|------|-----------|------------|
| 01 | stack_shellcode_relay | stack shellcode via a memcpy relay | easy |
| 02 | ret2plt_strcat_system | ret2plt system(), runtime-built "/bin/sh" | easy |
| 03 | pie_write_leak_ret2libc | raw write()-based self-leak, PIE + ret2libc | medium |
| 04 | canary_relay_bypass | indirect canary leak via a relay buffer | medium |
| 05 | fmtstr_pie_leak | %p PIE-base leak, then a plain overflow | medium |
| 06 | fmtstr_short_write | %hn 2-byte magic-value gate write | medium |
| 07 | static_ret2syscall | static binary, raw execve() ROP, no leak | medium |
| 08 | int_mul_overflow | truncated size check vs. untruncated copy loop | hard |
| 09 | heap_dangling_global | dangling global reused by an unrelated alloc | hard |
| 10 | ret2csu_execve | hand-embedded ret2csu, argument-gated win() | hard |
| 11 | heap_overflow_tcache_poison | overflow-driven safe-linked tcache poison | medium |
| 12 | fmtstr_got_overwrite | full 8-byte %hn GOT overwrite | hard |
| 13 | off_by_one_retaddr_lsb | fencepost off-by-one, function-pointer LSB | easy |
| 14 | oob_read_flag_array | missing upper bound, positional OOB read | easy |
| 15 | ret2win_arg_gate | minimal ROP: pop rdi + argument-gated win() | easy |

5 easy, 6 medium, 4 hard — close to the ~5/7/3 target spread (see
`corpus_r2.yaml`'s header for the one-line rationale on 11 and 12, which
could reasonably sit on either side of the medium/hard line).

## Flags are read from `flag.txt` at runtime — never compiled in

`build_all_r2.sh` generates a fresh random secret per target per build
(`FLAG{<32 hex chars>}`) and writes it **only** to that target's (gitignored)
`flag.txt`, next to its executable. Every target with a dedicated
flag-printing path reads it at runtime via a small `print_flag()` /
`read_flag_into()` helper (`fopen("flag.txt", "r")`) — **no target's `.c`
source contains a `FLAG{...}` literal, and no compile-time `#define` for it
ends up in `.rodata`.**

This matters because compile-time injection (`gcc -DFLAG=...`), even of a
fresh per-build random secret, still leaves the literal in `.rodata`, where
`strings <bin> | grep 'FLAG{'` or pwntools `ELF.search()` recovers it with
zero exploitation — and that's routine first-step recon for an automated
exploitation framework, so a tool could score a "success" without exploiting
anything. Round 1 had this defect in 8 of its 14 non-void targets.

**Verified: 0 occurrences of a `FLAG{...}`-shaped string in any of the 15
built binaries.** Reproduce with:

```bash
benchmark/build_all_r2.sh
python3 -c "
import pathlib, subprocess
root = pathlib.Path('benchmark/corpus_r2')
for d in sorted(root.iterdir()):
    if not d.is_dir(): continue
    b = d / d.name.split('_', 1)[1]
    if not b.exists(): continue
    hits = [l for l in subprocess.run(['strings', str(b)], capture_output=True, text=True).stdout.splitlines() if 'FLAG{' in l]
    print(d.name, 'clean' if not hits else f'SCRAPE-HIT {hits}')
"
```

The four shell-obtaining targets (01, 02, 03, 07) never print a flag from
inside the binary at all — their win condition is landing a shell, from
which the exploit reads `flag.txt` directly (same convention as round 1's
shell-obtaining targets).

### Rotation proof

Because the flag is generated fresh every build and never derived from the
target name, a rebuild rotates every target's secret. All 15 reference
exploits in `benchmark/corpus_r2_reference/` were re-run against freshly
rotated secrets — including a build performed by the **shared**
`benchmark/build_all.sh` (via `SUPWNGO_BENCH_CORPUS`/`SUPWNGO_BENCH_FLAG`,
the same invocation `run_bench.py` uses) rather than this round's own
`build_all_r2.sh` — and all 15 still captured their target's current flag.
This proves the corpus doesn't secretly depend on its own builder.

## `cflags` files, not a YAML field, drive the build

Per-target protection flags are declared in a `cflags` file beside each
target's source (`benchmark/corpus_r2/<NN>_<slug>/cflags`), one gcc flag per
line, `#`-comments and blank lines ignored. This is what the **shared**
`benchmark/build_all.sh`'s generalized fallback branch (rule R9 in
`benchmark/README.md`) reads for any corpus directory it doesn't recognize by
name — it fails closed with a clear error if the file is missing, since
protections are part of what's being measured and must never be guessed.
`build_all_r2.sh` (this round's own standalone convenience builder) reads the
**same** files rather than keeping an independent flag list, so the two
builders cannot silently disagree about how a target was built.
`corpus_r2.yaml`'s `cflags:` field mirrors those files for readers of the
manifest; the two are checked to match exactly (see Verify, below).

## Liveness / necessity, not just reachability

Round 1 shipped two void targets because only *reachability* was ever
checked: `11_heap_uaf_leak` printed its flag from a live, never-freed chunk
(the UAF it claimed to demonstrate was never actually required), and
`13_off_by_one` was tripped by the harness's own injected stdin with no
attacker intent at all.

For round 2, every target's win path was checked to actually **require** the
corrupted/exploited state the exploit creates — see
`benchmark/corpus_r2_reference/ablation.py`, which re-runs each target's
intended chain with exactly one essential step removed (or substituted with
a plausible-but-wrong value: a skipped `free()`, a guessed-zero canary, an
un-leaked PIE base, an honest non-overflowing count, a missing count-gate
filler chunk, a wrong magic argument, an in-bounds-only index range, a
read-only format string with no `%hn`, and so on) and asserts the flag
**never** appears. All 15 ablations pass (0/15 produced the flag).

## Verify

```bash
# 1. Build all 15 with fresh random secrets, strings-scrape clean:
benchmark/build_all_r2.sh

# 2. cflags file <-> corpus_r2.yaml mirror consistency:
python3 -c "
import yaml, pathlib
root = pathlib.Path('benchmark')
d = yaml.safe_load(open(root/'corpus_r2.yaml'))
for t in d['targets']:
    f = root/'corpus_r2'/t['slug']/'cflags'
    flags = [l.split('#',1)[0].strip() for l in f.read_text().splitlines()]
    flags = [l for l in flags if l]
    assert flags == t.get('cflags', []), (t['slug'], flags, t.get('cflags'))
print('all cflags mirrors match')
"

# 3. All 15 reference exploits pass against the current build:
for f in benchmark/corpus_r2_reference/*_reference.py; do python3 "$f"; done

# 4. Every target's chain is actually necessary (0/15 should leak):
python3 benchmark/corpus_r2_reference/ablation.py

# 5. Benign-input / do-nothing controls do not pass (reuse the shared
#    soundness probes, fresh process per probe, against this round's corpus):
python3 benchmark/soundness_probes/negative_control_sweep.py \
    --corpus-root benchmark/corpus_r2 --manifest benchmark/corpus_r2.yaml
```
