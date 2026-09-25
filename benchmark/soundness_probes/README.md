# Harness soundness probes

Adversarial probes for `benchmark/run_bench.py`, kept so the
23 Sep 2026 audit (`docs/reports/HARNESS-SOUNDNESS-AUDIT-23SEP2026.md`)
stays reproducible and so future harness changes can be re-checked.

These are **not** exploits supwngo generated. They are hand-written scripts
pushed through the harness's own provisioning, negative controls,
`independent_verify()` and `classify()` to answer one question: *can the
harness be made to say SUCCESS without exploitation?*

| probe | what it is | must score |
|---|---|---|
| `donothing_subprocess.py` | runs the target with inherited stdin; no payload at all | never SUCCESS |
| `donothing_interactive.py` | pwntools `process()` + `interactive()`; no payload | never SUCCESS |
| `hardcoded_flag.py` | prints the flag scraped from the committed source and from the binary's `strings` | never SUCCESS |
| `pure_python_scrape.py` | reads the binary in pure Python and regexes out the flag — no external tooling, never touches `flag.txt` | **SUCCESS on win()-style targets — known limitation, see below** |
| `real_exploit_02.py` | genuine hand-written ret2plt for `02_ret2plt_system`, ending in `io.interactive()` | SUCCESS |
| `real_exploit_02_explicit.py` | same exploit, explicit `sendline(b'cat flag.txt')` | SUCCESS |

## The one probe that still wins

`pure_python_scrape.py` deliberately documents the residual limitation.
Verification is **not sandboxed** — the generated script runs as the same
user — and for the 9 win()-style targets the secret is necessarily compiled
into the binary, so a script can read it instead of exploiting. Measured:

```
15_win_function    SUCCESS  flag=True   audit_clean=True   <- win()-style: scrape works
02_ret2plt_system  FAILED   flag=False  audit_clean=True   <- shell target: no flag in the binary
```

The anti-gaming audit is a *heuristic backstop*, not a proof: this probe uses
no external tooling and never opens `flag.txt`, so neither regex fires.
Closing this properly needs a corpus change — have `win()` print the
*contents of* `flag.txt` rather than a compiled-in literal, so the flag never
exists inside the binary. Until then, treat `SUCCESS` on a target whose
`negative_control.flag_statically_extractable_from_binary` is `true` as
"the script produced the flag", not "the script definitely exploited".

The two `real_exploit_02*` probes guard the **false-negative** side: they are
the shapes a legitimate shell-obtaining exploit takes, and the harness must
not lose the flag to buffering, stdin chunking, or the anti-gaming checks.

## `negative_control_sweep.py` — run this on every new corpus

Checks convention rule **R7** (`benchmark/README.md`): does any target hand
out its flag to benign input? No `autopwn`, so it's seconds per target, and it
exits non-zero if any target is unmeasurable or mis-provisioned.

```bash
python3 benchmark/soundness_probes/negative_control_sweep.py \
    --corpus-root benchmark/corpus_r2 --manifest benchmark/corpus_r2.yaml
```

For R1: `13_off_by_one` is the only unmeasurable target; the other 14 are
clean under both controls.

## Run

```bash
python3 benchmark/soundness_probes/drive.py 13_off_by_one 15_win_function 02_ret2plt_system
```

Each target is rebuilt with a fresh secret first, so this rewrites
`benchmark/corpus/<slug>/{<binary>,flag.txt}`. Don't run it concurrently with
`run_bench.py` on the same corpus.

Expected (post-fix): every `[NO-EXPLOIT]` row is `VOID` or `FAILED`, every
`[GENUINE]` row is `SUCCESS`. Any `*** FALSE POSITIVE ***` or
`*** FALSE NEGATIVE ***` marker means the harness regressed.

Historic note: before the fix, `donothing_subprocess.py` scored **SUCCESS** on
`13_off_by_one` (the harness's own 48-byte stdin tripped the off-by-one) and
`hardcoded_flag.py` scored **SUCCESS** on 9 targets (the flag was a constant
committed to git).
