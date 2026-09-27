# `benchmark/controls/` — positive controls for `scripts/htb_rescore.py`

These are **not corpus targets** and are not scored by `benchmark/run_bench.py`.
They exist to prove that the HTB re-score harness can reach each of its own
success levels *before* any HTB number is trusted, per the standing rule that a
custom assessment must be shown able to go both GREEN and RED first.

`htb_rescore.py` attributes a solve in exactly two ways, and **each needs its own
control**, because a harness that can only reach one of them silently cannot
score most of the corpus:

| level | what must fire | control |
|---|---|---|
| `FLAG_CAPTURED` | the per-rep planted secret is reproduced in a winning receipt | `flagfile_win/` (here) |
| `SHELL_ACCESS` | a receipt reports `shell_confirmed` | `benchmark/corpus/02_ret2plt_system`, `01_shellcode_stack` (used via `--extra-binary`; no new artifact needed) |

The negative control is `/bin/true`, also passed via `--extra-binary`.

## Why `15_win_function` cannot serve as the `FLAG_CAPTURED` control

It was tried first and it **fails as a control, for a reason that is a property of
the corpus rather than of the harness**. Every `benchmark/corpus/` target carries
its flag as a *compiled-in string* (`#define FLAG` → `puts(FLAG)`), and
`run_bench.py` makes that secret per-run by **recompiling** with
`-DFLAG=<secret>` (`build_with_secret`, `run_bench.py:359`), asserting afterwards
that the secret is present in the image.

`htb_rescore.py` deliberately cannot do that: HTB binaries ship without source, so
it plants a secret in a **file on disk** instead. Pointing it at a corpus target
therefore produces the worst possible outcome — the engine legitimately reports
`FLAG_CAPTURED` for the flag *baked into the binary*, while the harness correctly
refuses to credit it because it is not this rep's planted secret, and the rep lands
in `CLAIMED_UNATTRIBUTED`. Both components are behaving correctly; they are simply
measuring two different things.

Measured, 2026-09-27: `strings benchmark/corpus/15_win_function/win_function` contains
`FLAG{421e…}`, and a solve run against it returns `verified=FLAG_CAPTURED` with
`flag=FLAG{421e…}` while the workspace's `flag.txt` held an `HTB{…}` secret.

## What `flagfile_win` changes, and only that

It is `15_win_function` with **one thing flipped**: `win()` reads the flag from
`./flag.txt` at runtime instead of printing a compiled-in constant. The overflow,
the buffer size, the protections, and the win-function shape are deliberately
unchanged, so if the control fails while `15_win_function` solves, the difference is
attributable to the flag source and nothing else.

There is **no flag string in this binary at all** — that is the point, and it is
checkable: `strings flagfile_win | grep -E '(FLAG|HTB)\{'` must return nothing.

## Build

```sh
cd benchmark/controls/flagfile_win && ./build.sh
```

## Use

Controls first, and only then the real targets:

```sh
python3 scripts/htb_rescore.py --only-extras --reps 2 --timeout 180 \
  --extra-binary "benchmark/controls/flagfile_win/flagfile_win=POSCTL_flag" \
  --extra-binary "benchmark/corpus/02_ret2plt_system/ret2plt_system=POSCTL_shell" \
  --extra-binary "/bin/true=NEGCTL_true"
```

Expected: `POSCTL_flag` SOLVED at `FLAG_CAPTURED`, `POSCTL_shell` SOLVED at
`SHELL_ACCESS`, `NEGCTL_true` NOT_SOLVED. **Note `--reps 2` is the minimum** — the
verdict rule requires two counted reps (`htb_rescore.py:209`), so `--reps 1` is
structurally `INCONCLUSIVE` and cannot validate anything.

Any other combination means the harness is not measuring what it claims, and no HTB
figure from that run may be reported.
