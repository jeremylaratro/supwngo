# Ablation suite — round-1 corpus

Proves that every step of each target's intended exploit chain is **necessary**,
not merely that the chain works.

## Why this exists

`benchmark/soundness_probes/negative_control_sweep.py` asks *"can benign input
get the flag?"* — i.e. is the target **trivially** solvable. That is necessary
but not sufficient. It says nothing about whether the intended chain's steps are
load-bearing.

Round 1 shipped two VOID targets because only reachability was ever tested:

* **`13_off_by_one`** — `read(0, s.buf, 32)` returns 32 for any input ≥ 32 bytes,
  so ordinary input tripped `win()`. A negative control *does* catch this one.
* **`11_heap_uaf_leak`** — `show(0)` prints the flag from the **live** chunk, so
  the use-after-free the exploit was supposed to perform was never required. **No
  negative control catches this**: benign input does not get the flag, and a
  "working" exploit does. The target simply did not measure its own technique.

Ablation catches the second class. For each meaningfully separable step, run the
whole chain with exactly that step removed and require the flag **not** to
appear.

> Assert necessity, not just reachability. "The exploit works" is not evidence a
> target is sound; **"nothing less than the exploit works"** is.

## Run

```bash
benchmark/build_all.sh
python3 benchmark/ablation/ablate.py                     # all 13 valid targets
python3 benchmark/ablation/ablate.py --case 04 --case 12  # a subset
python3 benchmark/ablation/ablate.py --list               # list cases, run nothing
python3 benchmark/ablation/ablate.py --no-rebuild         # keep current flag.txt
```

Paths resolve from the script's own location, so it runs from any working
directory, including by absolute path from `/`. `--corpus-root` / `--manifest`
point it at another round's corpus.

**Exit status 0 means every ablation FAILED to produce the flag** — that is the
passing result. `1` means a chain step turned out to be unnecessary (or a
positive control failed, so the run isn't interpretable). `2` is a setup
problem: unbuilt corpus, missing `flag.txt`, bad `--corpus-root`.

## What makes the result trustworthy

1. **Fresh random secret per target.** Each target is rebuilt via the harness's
   own `run_bench.build_with_secret()`, so no verdict can rest on a stale or
   predictable flag constant. `--no-rebuild` opts out.
2. **A positive control per target, from the same code.** Every target has ONE
   parametrised chain function; the positive control is that function with all
   steps intact and each ablation is the same function with one keyword flipped.
   So `BLOCKED` cannot be an artifact of broken harness code — broken code fails
   the positive control, and the target is reported `NOT MEASURABLE` instead of
   passing silently.
3. **Every emitted byte is checked.** The `Rec` tube wrapper accumulates
   everything the target prints, so the flag can't be missed because it scrolled
   past in an earlier read.
4. **Runs under `corpus_lock`**, so it can't race `run_bench.py` while it
   rewrites binaries and flags.

## Result (23 Sep 2026, glibc 2.35 / gcc 11.4 / pwntools 4.15.0)

**49 / 49 strict ablations blocked the flag; 13 / 13 positive controls passed;
exit 0.** No round-1 target was found to be measuring less than it claims, so
nothing joins `11` and `13` as VOID.

Three cases are deliberate `RELAXATION` probes — documented details that turn out
**not** to be required. They are not defects; they are recorded so the corpus's
difficulty notes stay honest:

| target | relaxation | what it means |
|---|---|---|
| `04` | sending 8 bytes instead of filling `buf` before the echo | the `write(buf, sizeof+8)` over-read discloses the canary regardless of how much of `buf` was filled; the *leak* is still required (`canary_not_leaked` is blocked) |
| `05` | reading `%29$p` (main's canary) instead of `%25$p` (vuln's) | the canary is per-**thread** (`%fs:0x28`), stamped identically into every frame — measured byte-identical across runs. Frame attribution is *not* a step a solver must get right; distinguishing a canary from a low-byte-`0x00` **pointer** is (`%13$p` is blocked) |
| `09` | using `gadget_syscall_ret` instead of `+4` | `endbr64` is a NOP when IBT is not enforced, so the symbol address works. The `+4` still matters for reasoning: `sym+1` is *not* a bare `ret` |

## Adding cases for another round

Copy this directory, keep the harness, and rewrite the per-target chain
functions and `CASES_*` lists — ablation cases are inherently per-target, so this
is a template, not a drop-in. Give each target a single parametrised chain
function whose default arguments are the working exploit, then express each
ablation as one flipped keyword. Aim at the steps whose necessity is *not*
obvious: a `free()` a display path might not need, a state change a dump might
not check, a corruption an index might not require. That is where the round-1
defects lived.
