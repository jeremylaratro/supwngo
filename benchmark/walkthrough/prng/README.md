# 0-to-pwn: predictable pseudo-random secrets

Runnable walkthroughs for `benchmark/corpus_prng/`. One file per target, each
self-contained (`benchmark/walkthrough/score.py` stages exactly one `.py` into a
follower's sandbox, so a shared helper module would not resolve there).

```
benchmark/walkthrough/prng/
├── prng_10_time_seed_token.py      anchor: srand(time(NULL)), 1 draw, decimal
├── prng_11_getpid_seed_pin.py      seed = getpid(); draw % 1000000
├── prng_12_unseeded_sequence.py    no srand() at all; 5 draws in order
├── prng_13_fixed_seed_password.py  literal seed 0xC0FFEE; 8 draws -> a string
├── prng_14_leak_then_recover.py    3 draws PUBLISHED -> seed solved, not guessed
├── prng_15_rand_r_hex_guard.py     rand_r() (different generator), hex answer
└── control_resists.py              why prng_90_neg_csprng cannot be brute-forced
```

Run one:

```bash
cd benchmark/corpus_prng/prng_10_time_seed_token
python3 ../../walkthrough/prng/prng_10_time_seed_token.py
```

Run the control demonstration from anywhere in the repo:

```bash
python3 benchmark/walkthrough/prng/control_resists.py   # exits 0 only "AS EXPECTED"
```

If a binary is missing, build the family first — the flag is never compiled in,
so a per-run secret is the honest way to test:

```bash
SUPWNGO_BENCH_FLAG="FLAG{$(openssl rand -hex 16)}" \
SUPWNGO_BENCH_CORPUS=benchmark/corpus_prng benchmark/build_all.sh
```

## The defect

A secret that guards something — authentication, a token, a canary substitute, an
address choice — is produced by the C library's pseudo-random generator, seeded
from something the attacker can guess. The generator is deterministic, so
**reproducing the seed reproduces the secret exactly**. The size of the secret's
value space is irrelevant: `rand()` has a 2^31 range in every one of these
targets, including the control.

## The recipe

Five questions, each answered from the image. Nothing here needs source.

### 1. Which generator? — read `.dynsym`

```bash
readelf --dyn-syms ./target | grep -E ' UND .*(rand|random)'
```

`rand`/`random`/`rand_r` are the generators; `srand`/`srandom` are the seeders.
`rand` and `random` share **one** TYPE_3 additive-feedback state in glibc, so
`srand(s); rand()` and `srandom(s); random()` produce identical values. `rand_r`
is a different generator — a three-step LCG over a caller-held `unsigned int` —
so its output for seed `s` is **not** `rand()`'s output for seed `s`.

Parsing note that cost real time: `readelf` appends a version index, so the last
whitespace-separated field of that line is `(2)`, not the symbol name. Anchor on
the `UND` binding and take the field after it.

An **absence** can be the finding (prng_12 has no seeder at all). State what was
searched: the whole dynamic symbol table, not just `main`.

### 2. Where does the seed come from? — read the call that feeds the seeder

At `-O0`, x86-64 puts the producer immediately before the consumer:

| what you see | seed class |
| --- | --- |
| `call <time@plt>` → `mov edi,eax` → `call <srand@plt>` | wall-clock second — **bracket it** |
| `call <getpid@plt>` → `call <srand@plt>` | the pid — **exact**, if you spawned it |
| `mov edi,0xc0ffee` → `call <srand@plt>` | a literal — **exact**, constant of the build |
| a generator with no seeder anywhere | implicit `srand(1)` — **exact**, constant of libc |
| the value stored into `rand_r`'s state slot | whatever produced that value |

### 3. How many draws must be predicted?

Count `call <rand@plt>` sites between the seeding and the comparison, and read
loop bounds off the compare (`cmp DWORD PTR [rbp-0x4],0x5` → five rounds). The
secret is draw #N of one stream; getting N wrong gives a perfectly reproduced
wrong answer.

### 4. How is the answer encoded?

This is the one that silently defeats a correct replay. `strtoul`'s third
argument is the base, and at `-O0` it is a literal in the register:

```
mov edx,0xa     -> answer in DECIMAL   (prng_10, prng_14)
mov edx,0x10    -> answer in HEX       (prng_15)
```

Truncation and alphabets are equally visible. gcc does not emit `div` for a
constant divisor; it emits a reciprocal multiply plus a multiply-back, and the
multiply-back carries the divisor: `imul edx,edx,0xf4240` is `% 1000000`. A
string secret indexes a named array: `lea rdx,[rip+0xca5] # 402020 <ALPHABET>`.

### 5. How many tries?

`cmp DWORD PTR [rbp-0x8],0x3` → three. The allowance decides whether a clock
bracket fits in one connection.

## Choosing the seed bracket

For a `time(NULL)` seed we do not know which second the process started in, so
candidates are ordered centre-out around our own clock: `now`, `now-1`, `now+1`,
… **±3 seconds — 7 candidates — is what these walkthroughs use**, and the bound
is set by the try allowance, not by patience.

Be clear about what the tries buy. Against a 2^31 range, 64 blind guesses win
with probability `64/2^31 = 3.0e-8`. The allowance pays for **clock
uncertainty**; the replay produces the secret. If you find yourself widening a
bracket past the allowance, you have stopped exploiting and started gambling.

A **published draw changes the economics completely.** When the target prints
values from the same stream (prng_14), the seed is not guessed, it is solved for
and then *confirmed*: a wrong seed would have to reproduce three 31-bit values,
i.e. 2^-93 per candidate. A verified search can be as wide as you like (that
walkthrough uses ±60 s), because a false positive is effectively impossible. That
same check is the **positive control for your generator model**: if your libc
stream did not match the target's, no seed in the window would reproduce the
published draws and you would *find out*, instead of quietly sending wrong
answers.

## Modelling the generator: use libc, then prove it

These walkthroughs call **libc itself** through `ctypes`, so the model cannot
drift from the target's generator. That is not a licence to skip the proof —
every file checks the model *before* it attacks, and exits if the check fails:

1. `srand(1)` must produce `1804289383, 846930886, 1681692777`.
2. `srandom(1)` must produce the *same* three values (the shared-state claim).
3. `rand_r` must match its documented LCG **and differ from `rand()`** — if they
   agreed, one of them would not be the generator it claims to be.

A model check that cannot fail proves nothing; the `rand_r` one caught a wrong
transcription of the LCG while this walkthrough was being written.

## Why the CSPRNG control cannot be brute-forced

`prng_90_neg_csprng` is the anchor with one line changed: the token comes from
`getrandom(2)` (falling back to `/dev/urandom`), masked to the same 31 bits.
Same banner, same prompt, same comparison, same 64 tries, same value space.

Both secrets sit in 2^31, so blind guessing is `3.0e-8` against **either** of
them. The anchor falls because its secret is a *function of a guessable input*:
`seed → secret`, with the seed drawn from about seven plausible seconds. The
control has no such function. There is nothing to bracket, so widening the search
does not help — there is no relationship to search over. Kernel entropy is not a
smaller haystack, it is the absence of a map.

`control_resists.py` measures two things, and the second is the one that matters:

1. **Refusal** — 64 candidates, 64 rejections, "out of tries" reached. Weak
   evidence alone: "did not solve it" also describes a broken exploit.
2. **Determinism across processes** — one predicted token is offered to two
   *independent* anchor processes started in the same second, and **both accept
   it** (2/2), while the control accepts it 0/2. That is a property the control
   provably lacks, not merely an outcome it failed to produce.

Measured output:

```
prng_10_time_seed_token  solved=True  candidates_sent=1  rejections=0   out_of_tries=False
prng_90_neg_csprng       solved=False candidates_sent=64 rejections=64  out_of_tries=True
prng_10_time_seed_token  token=1647883496  accepted_by=2/2
prng_90_neg_csprng       token=1647883496  accepted_by=0/2
```

If the control ever solves, no positive result in this family means anything: the
technique found another way in (reading `flag.txt`, a harness fault, or a 3e-8
stroke of luck). Run `control_resists.py` before trusting a number.

## What makes these solves honest

- The flag is **never compiled in**. Each target opens `./flag.txt` at the moment
  its comparison succeeds, so `strings` on the binary yields nothing and a
  per-run `SUPWNGO_BENCH_FLAG` secret cannot be pre-read.
- No walkthrough opens `flag.txt`. There is no `open()` in any of them: the flag
  appears because **the target printed it** on its own success path. `cat
  flag.txt` run by a shell the exploit obtained is exploitation; the same read
  performed by the exploit's own process is laundering, and
  `benchmark/walkthrough/score.py` audits for exactly that.
- Every constant in every template carries the instruction it was read from.
  A constant without a derivation is a cheat-sheet entry, and it will not
  transfer to the next binary.
