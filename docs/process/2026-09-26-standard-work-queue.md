# Standard work queue — schema + live queue

**Created 2026-09-26. Living document.** The date in the filename is its creation
date (per the repo's dated-artifact convention), not a snapshot — edit this file in
place rather than cloning it per sprint.

This is the **single canonical queue** for supwngo. If an item is not here, it is not
queued; if it is here, it carries an ID that every plan, commit, review, and test can
cite. It supersedes ad-hoc "next up" lists inside individual sprint plans, which may
now reference IDs but must not invent new ones.

---

## 1. Schema — every item, every field

```
### <ID> — <one-line title>

| field | value |
|---|---|
| type        | gap \| bug \| issue \| target \| gate \| assessment |
| relevance   | 1-5 (how much it moves the stated target) |
| complexity  | 1-5 (effort x blast radius x uncertainty) |
| priority    | P0 \| P1 \| P2 \| P3 (derived, then adjusted once by hand) |
| lane        | now \| next \| later \| document-and-move-on \| out-of-scope |
| status      | open \| in-sprint \| blocked \| owes \| done \| superseded |
| evidence    | `file:line`, a command + its output, or a cited doc |
| provenance  | measured \| recorded \| inferred |
| exit        | the observable condition that makes it done |
| owes        | a named review round, sweep, or measurement still outstanding |
| blocks / blocked-by | other IDs |
```

### ID namespaces

| prefix | meaning |
|---|---|
| `G-` | **gap** — a missing capability |
| `B-` | **bug** — wrong behavior |
| `I-` | **issue** — friction, debt, docs; includes pre-existing failures |
| `T-` | **target** — a goal, becomes a Phase-8 metric, never a sprint |
| `M-` | **gate** — a measurement that must pass before work ships |
| `Q-` | **quality** — test-strength / coverage debt (a gate that cannot go red) |
| `A-` | **assessment** — a scoped investigation whose deliverable is a finding, not code |

Suffix letters (`G-2b`) denote a decomposition of a parent item. A superseded item
keeps its ID and gains a `SUPERSEDED — see <ID>` line; IDs are never reused.

### Queue rules (these are the point of the standard)

1. **Nothing enters without an ID, evidence, and a provenance label.** A gap with no
   `file:line`, no command output, and no citation is `inferred`, and is triaged as
   such. `grep` before asserting something is missing.
2. **Nothing leaves `now` until its `exit` condition is observed**, and the observation
   is recorded next to the item — not in chat.
3. **An `owes` entry is an unmeasured claim, not a managed risk.** An item with a
   non-empty `owes` may not be reported as done, however green it looks.
4. **Re-triage inline when the evidence changes.** Strike the old score, keep it
   visible, and say what measurement moved it (see `B-3`, whose complexity went
   `4 → 2` on measured research). Never silently rewrite a score.
5. **Pre-existing failures are listed by name** (the `I-` namespace) and excluded
   explicitly from a sprint's gates. They are never quietly absorbed into a sprint or
   deselected to make a number look right.
6. **Out-of-scope classes are declared once here and repeated in every delegated
   prompt.** For this repo: tool-hardening, compliance controls, and "security of the
   tool itself" are out of scope, and deliberate constants (magic-value lists,
   cheat-sheet tables, technique allowlists) are **features**, not weaknesses.

---

## 2. Live queue

### Lane: `now`

**Autonomous capability run — opened 2026-09-27, worked to completion without further
authorisation.** The operative directive is per-category generalisation, not target
count:

> go one by one on category / vuln type and make it work, then test it on variants,
> adjust until they work too, then repeat on the next category

and the run serves `T-3`: the capability to **identify, walk through, and solve as many
distinct binary/software vulnerability types — and variations of each — as possible.**

Items are worked in the order below. `M-2` is re-run after every category lands and
gates the next one: **green → advance; red → iterate on the failure before advancing.**
This block is the live queue — status is edited in place, and each item's observation is
recorded beneath it (queue rule 2). The chronological record is §6.

| order | ID | item | status |
|---|---|---|---|
| 1 | `G-5` | `eintr_accumulator_rop` generalised across its variation corpus | **done** — 0/6 → 6/6, control unsolved |
| 2 | `G-6` | `srop_symtab_pivot` generalised across its variation corpus | **done** — 1/5 → 5/5, control declined |
| 3 | `A-2` | survey for vuln types this tool cannot yet reach | **done** — classification returned; 2 of 3 categories reclassified |
| 4 | `G-7b` | `sabotage`'s class — **reclassified**: self-inflicted env/PATH hijack, not memory corruption | **in-sprint** (hand-shell proven 3/3) |
| 5 | `G-7c` + `G-8b` | **merged** — indirect-call hijack over a custom allocator (`auth-or-out`'s real class) | **in-sprint** (hand-shell proven 3/3) |
| 6 | `G-8a` | **new category** — predictable pseudo-random secrets | **done** — 6/6, control declines 64/64 ×3 reps, gate claims 6 of 68 binaries |
| 7 | `G-7a` | heap off-by-one via `strlen` on an unterminated chunk — `bon-nie-appetit` | **unblocked**, awaiting a free slot (runtime found, see below) |
| 8 | `G-9` | **new P0** — no executor can express "leak first, then finish in libc" | open — shared machinery for `G-7a`/`G-7c` |
| 9 | `G-8c` | **new category** — injection into a subprocess sink (`system`/`popen`/`exec*`) | **done** — 5/5, control fails two ways |
| 10 | `I-16` | `verify_script`'s shell oracle credits an echo as a shell | **mitigated** — receipts now carry `shell_proven`/`echo_ambiguous` |
| 11 | `G-10` | **new category** — unbounded `scanf`/`strtoull` scalar-and-bound overwrite | **done** — 6/6 by reference exploit; pipeline number pending |
| 12 | `I-19` | `verify_script` could not prove a shell that has no `PATH` | **closed** — third probe `echo SH$((6*7))OK` → `SH42OK` |
| 13 | `M-2` | full pytest + every HTB challenge + every variation corpus, re-run | open |
| — | `T-3` | the breadth target the whole run serves | open |

**Revised ordering, and why (queue rule 4 — re-triage inline when the evidence
changes).** `M-2` was ordered 3rd when two cycles were in flight; it has moved to last
because it is a *whole-tree* gate and six cycles are now editing executors concurrently —
running it mid-flight would measure a tree that no single commit corresponds to, which is
the "changed harness invalidates the comparison" failure. It still gates nothing
advancing past it: no cycle is reported closed until `M-2` is green on the merged tree.
`A-2` moved earlier because it is read-only and unblocks the `G-8*` choices.

**Parallelism note.** Six cycles run concurrently on strictly disjoint path sets; the
orchestrator holds `supwngo/exploit/pipeline/executors/__init__.py`, `CHANGELOG.md`,
`docs/`, `benchmark/.gitignore` and all git, so new executors are registered centrally
and each cycle lands as its own commit. A prior run at eight concurrent agents exhausted
the session limit and killed every agent mid-flight, so six is the deliberate ceiling
here, backfilled as slots free rather than raised.

#### G-5 — `eintr_accumulator_rop` generalised across a variation corpus

| field | value |
|---|---|
| type | gap |
| relevance | 5 — one of the three executors written this session with no variant evidence behind it |
| complexity | 3 — corpus is built and the primitive is proven; the work is derivation, not discovery |
| priority | P0 |
| lane | now |
| status | **done** 2026-09-27 |
| evidence | baseline `benchmark/results_htb/eintr-baseline-20260927.json`, final `…/eintr-final-20260927.json`; reference exploit `benchmark/reference_exploits/eintr_variants_reference.py` |
| provenance | measured |
| exit | **met.** 0/6 → 6/6 positives at `SHELL_ACCESS`; `eintr_90_neg_checked_read` gate-applicable but FAILED (no shell); `ancient_interface` still `SUCCESS`/`SHELL_ACCESS` in 13.5 s |
| owes | nothing |
| blocks | `M-2` (released) |

The corpus is engineered so each variant breaks one named assumption in the current
executor: `eintr_14` kills the help-string vocabulary heuristic and uses `setitimer`;
`eintr_15` removes the banner's trailing NUL and its `!` and brackets the prompt;
`eintr_11` moves every frame offset; `eintr_12` changes the signal count and puts the
count slot on the other side of the cursor; `eintr_13` emits the accumulate as a
memory-add. A variant failure therefore names the thing that broke.

**Outcome, and the one thing it cost.** The baseline was 0/6 *including the anchor*,
which reproduces `ancient_interface`'s frame byte-for-byte — the loop detector was
pinned to one gcc's sign-extension order, so a technique written for that target no
longer fired on a rebuild of it. That is the clearest justification for corpus-first
work this run has produced, and it is worth keeping the number: a single compiler
version, not a single binary, was the load-bearing assumption.

The cost is recorded here rather than buried: signal delivery is now
`os.kill(pid, SIGALRM)`, not the target's own timer command, so the technique is
**local-process only** and would not carry to a remote service. It was chosen because
it is the only mechanism-agnostic delivery available — arming `setitimer(ITIMER_REAL)`
16 times in-band was measured to deliver **one** signal (it is one-shot), so the
in-band path cannot reach the signal counts this primitive needs on the `eintr_14`
variant at all. Logged as a deficiency (`I-15`), not as a solved problem.

#### G-6 — `srop_symtab_pivot` generalised across a variation corpus

| field | value |
|---|---|
| type | gap |
| relevance | 5 — the third session executor, and the only one with no corpus at all |
| complexity | 4 — a no-writable-segment ELF with a mapped symbol table needs a hand-built link |
| priority | P0 |
| lane | now |
| status | in-sprint |
| evidence | `supwngo/exploit/pipeline/executors/srop_nowrite_techniques.py`; `sick_rop` SOLVED in `benchmark/results_htb/full-rescore-20260927.json` |
| provenance | recorded |
| exit | every positive variant reaches a shell via `srop_symtab_pivot`, the negative control does not, and `sick_rop` is unregressed |
| owes | corpus, reference-exploit red-proof, baseline + final measurement |
| blocks | `M-2` |

#### M-2 — full suite + every challenge + every variation corpus, re-run

| field | value |
|---|---|
| type | gate |
| relevance | 5 — the only thing that distinguishes "a category generalised" from "a category traded for another" |
| complexity | 2 |
| priority | P0 |
| lane | now |
| status | open |
| evidence | prior full-suite state at `0c79463`: `1 failed, 1320 passed, 16 skipped`, the one failure pre-existing (`I-14`) |
| provenance | measured |
| exit | pytest shows no NEW failure against the recorded baseline; all 7 HTB challenges re-scored; `corpus_variants`, `corpus_eintr`, `corpus_srop` each re-run with positives solved and controls unsolved |
| owes | the run itself |
| blocked-by | `G-5`, `G-6` |

**Iterate-on-fail is part of this gate, not an exception to it.** A red result does not
advance the queue: the failure is fixed and `M-2` re-run. Only a green `M-2` releases
`G-7`.

#### G-7 — the three unsolved HTB categories

| field | value |
|---|---|
| type | gap |
| relevance | 5 — the remaining 3/7, and three categories this tool has no technique for |
| complexity | 5 — all three are PIE + canary + Full RELRO, so every technique needs a leak first |
| priority | P1 |
| lane | now |
| status | open |
| evidence | `benchmark/results_htb/full-rescore-20260927.json`: `auth-or-out` INCONCLUSIVE, `bon-nie-appetit` NOT_SOLVED, `sabotage` NOT_SOLVED |
| provenance | measured |
| exit | each of `G-7a`/`G-7b`/`G-7c` closed by its own variation corpus, not by a single-target solve |
| blocked-by | `M-2` |

Decomposition, with protections read off the images (measured, `pwntools ELF`):

| ID | target | measured shape | imports that hint at the category |
|---|---|---|---|
| `G-7a` | `bon-nie-appetit` | PIE, canary, Full RELRO, NX | `malloc` `free` `alarm` `atoi` `strlen` — heap |
| `G-7b` | `sabotage` | PIE, canary, Full RELRO, NX | `malloc` `free` `getenv` `putenv` `setenv` `open` `close` `rand`/`srand` `strcat` |
| `G-7c` | `auth-or-out` | PIE, canary, Full RELRO, NX, **with debug_info** | `__isoc99_scanf` `strtoull` `putchar` `read` — scalar/scanf path |

Each sub-item follows the same cycle as `G-5`/`G-6`: classify the defect, build a
variation corpus holding the category constant, red-proof it both ways with a
deterministic reference exploit, baseline, generalise, re-measure, regress the real
target. A single-target solve does **not** close a sub-item — queue rule: the category
is the unit.

**2026-09-27 RE outcome — all three reversed, two already at a shell by hand.** The
classification cycle did not just classify: it produced working exploits.

| sub-item | target | RE result | provenance |
|---|---|---|---|
| `G-7b` | `sabotage` | **SHELL, 3/3** — `benchmark/reference_exploits/sabotage_env_path_reference.py` | measured |
| `G-7c` | `auth-or-out` | **SHELL, 3/3** — `benchmark/reference_exploits/auth_or_out_objptr_reference.py` | measured |
| `G-7a` | `bon-nie-appetit` | bug + chunk overlap + **libc leak** measured 3/3 — `benchmark/reference_exploits/bon_nie_appetit_leak_reference.py`; finisher not built | measured |

Revised classifications, which are **not** what the import lists suggested:

* `G-7b` `sabotage` is **not** a memory-corruption category in its payoff. It is an
  unsigned size wrap plus an unsigned loop bound giving an unbounded heap write, whose
  reachable sink is a `putenv`'d **heap environment string**, escalated through a
  relative-path `system("panel")` — i.e. a PATH hijack the target performs on *itself*.
  No leak, no ASLR dependence: every offset used is a fixed intra-heap distance (the
  target is `0x20` above the allocation). The menu **ordering** is load-bearing — option
  2 before option 1, or the chunk lands above everything and glibc aborts with
  `malloc(): corrupted top size`.
* `G-7c` `auth-or-out` is **not** the scanf/scalar path the `strtoull` import suggested.
  It is a size wrap (`NoteSize + 1` → 0) over a **bump allocator whose arena is a local
  array in `main`**, corrupting a live object's function pointer, which is then reached
  by `call rax` with `rdi` fully controlled. It carries a *second* independent defect —
  `modify_author` reads 17 bytes into `Surname[16]`, so `printf("%s")` runs off the end
  and leaks the adjacent `Note` pointer, which is the stack leak that beats PIE. That
  makes it the same category as `G-8b`, so the two are now **one cycle**.
* `G-7a` `bon-nie-appetit` is a missing NUL terminator (`read` fills a chunk exactly,
  never terminating it) so that `strlen` on it returns a length reaching into the next
  chunk's `size` field — a strict **off-by-one**, not an arbitrary-length overflow.

##### `G-7a` was reported blocked. It is not — the runtime is on this host.

The RE cycle concluded `bon-nie-appetit` was "out of reach until a real `ld-2.27.so` is
obtained", because `challenge/glibc/ld-linux-x86-64.so.2` is a **0-byte file** and the
host runs 2.35. **Measured, this session:** a genuine glibc 2.27 loader ships inside snap
`core18`, and it loads the target's own bundled libc:

```
/snap/core18/3084/lib/x86_64-linux-gnu/ld-2.27.so \
  --library-path tests/htb-targets/a12c7383-.../challenge/glibc \
  tests/htb-targets/a12c7383-.../challenge/bon-nie-appetit
```

Measured: the target starts and reaches its menu. Loader is 2.27-3ubuntu1.6+esm6 against
the target's libc 2.27-3ubuntu1.5 — same upstream release, so the ABI matches. `docker`
is also present as a fallback route to an 18.04 sysroot. **`G-7a` is therefore unblocked**
and waiting only on a free agent slot, not on an acquisition.

One precision note for whoever builds the finisher: `__free_hook` is **still an exported
symbol in 2.35** (measured, `nm -D` finds it in the host libc). What changed in 2.34 is
that the malloc path no longer *calls* it. So a capability test that greps for the symbol
will wrongly conclude the 2.35 finisher works — the version check has to be on the glibc
release, not on symbol presence. Measured in the target's own 2.27: `__free_hook` at
`0x3ed8e8`, `system` at `0x4f420`.

#### A-2 — survey VRv5 agents/skills for vuln types this tool cannot reach

| field | value |
|---|---|
| type | assessment |
| relevance | 4 — decides what `G-8` builds; without it `G-8` is guesswork |
| complexity | 2 — read-only survey of an existing local corpus of agents/skills |
| priority | P1 |
| lane | now |
| status | open |
| evidence | VRv5 ships specialist agents per class (heap, kernel, browser, crypto, firmware, mobile, .NET, IIS, concolic, SROP/AEG) — enumerated in the session's agent list |
| provenance | recorded |
| exit | a ranked coverage table: every vuln type VRv5's agents/skills name, marked covered / partially covered / absent in supwngo's executor set, with the cheapest buildable fixture named for each absent one |
| blocked-by | `G-7` |

Deliverable is a finding, not code (`A-` namespace). It is explicitly allowed to
conclude that a class is out of reach for a local fixture corpus (kernel, browser,
firmware) and say so rather than inventing a fixture that does not model it.

**Partial result, 2026-09-27 — where the survey material actually is.** `measured`:
`dgx-spark-platform/VRv5/.claude/skills/` is **empty** and `.../.claude/agents/` holds
only `finding-validator.md` and `scrutiny-critic.md`, so the survey cannot be done by
reading that tree — an earlier assumption that it could was wrong. The usable inventory
is the **VRv5 agent roster itself** (the plugin's dispatchable specialists), which names
its classes explicitly: heap (glibc ptmalloc/tcache/fastbin, PartitionAlloc, Scudo,
Windows Segment Heap), kernel (Linux/Windows), browser (V8 type confusion, JIT
miscompilation, sandbox boundary), cryptographic (padding oracle, timing side channel,
**weak PRNG**, protocol downgrade), firmware/IoT, mobile (Android/iOS), .NET, IIS,
source→sink taint (SQLi, XSS, command injection, path traversal, SSRF, deserialization,
XXE, auth bypass, IDOR, CSRF), business logic (race conditions, **TOCTOU**, state-machine
violation), supply chain, and concolic/symbolic + AEG.

Cross-referencing that roster against supwngo's executor set (`canary_leak`,
`container_file`, `fmtstr`, `heap`, `heap_and_bypass`, `input_shape`, `rop`, `shellcode`,
`signal_underflow`, `srop_nowrite`, `stack`) gives the first ranked coverage call:

| VRv5 class | supwngo coverage | buildable as a local ELF fixture? |
|---|---|---|
| stack/ROP, format string, SROP, shellcode | covered | already in `benchmark/corpus/` |
| glibc heap (tcache/fastbin) | **partial** — two single targets, no variation family | yes → `G-7a` |
| unbounded scalar/`scanf` input | **partial** — `input_shape` only | yes → `G-7c` |
| weak PRNG / predictable secret | **absent** | yes, cheaply → **`G-8a`** |
| function-pointer / indirect-call hijack | **absent** | yes, cheaply → **`G-8b`** |
| injection into a subprocess sink | **absent** (no non-memory-safety class at all) | yes, cheaply → **`G-8c`** |
| TOCTOU / race | **absent** | yes, with a widened window |
| kernel, browser, firmware, mobile, .NET, IIS | absent | **no** — out of reach for a local C fixture corpus; declared out of scope for `G-8` rather than faked |

`A-2` still owes the `sabotage` classification (`G-7b`) before it can close.

#### G-8 — new-category corpora + executors for what `A-2` surfaces

| field | value |
|---|---|
| type | gap |
| relevance | 5 — this is `T-3` |
| complexity | 5 |
| priority | P1 |
| lane | now |
| status | open |
| evidence | — (opened by `A-2`) |
| provenance | inferred |
| exit | for each class `A-2` ranks as buildable: a variation corpus red-proved both ways, an executor that solves its positives and not its control, and a walkthrough that a follower can run (`T-3` has a teaching half, not just a solving half) |
| blocked-by | `A-2` |

Decomposed into `G-8a`, `G-8b`, … as `A-2` names the classes; IDs are assigned when the
class is accepted, never in advance. Three are now accepted on `A-2`'s partial result:

#### G-8a — NEW CATEGORY: predictable pseudo-random secrets

| field | value |
|---|---|
| type | gap |
| relevance | 5 — no supwngo executor attacks a PRNG, and `sabotage` + `bon-nie-appetit` both import `srand`/`rand`/`time` |
| complexity | 2 — glibc `rand()` is exactly reproducible, and a `time(NULL)` seed is a one-second bracket |
| priority | P1 |
| lane | now |
| status | in-sprint |
| evidence | `A-2` coverage table above; the two HTB imports are `measured` via `pwntools ELF` |
| provenance | measured |
| exit | `benchmark/corpus_prng/` red-proved both ways, and `weak_prng_techniques` solves every positive and not the CSPRNG control |

The control is the anchor with the secret redrawn from `getrandom()`, so the family
isolates *seed predictability* rather than "a program that has a secret". The solve must
reproduce the secret from the seed — a `strings`-greppable flag would void the
measurement, so validation runs with `SUPWNGO_BENCH_FLAG` making the flag a per-run
secret.

#### G-8b — NEW CATEGORY: function-pointer / indirect-call hijack

| field | value |
|---|---|
| type | gap |
| relevance | 4 — a distinct control-flow primitive: no return address, no canary in the way, so every canary/ROP technique in the tool is inapplicable by construction |
| complexity | 2 |
| priority | P2 |
| lane | now |
| status | open |
| evidence | `A-2` coverage table above |
| provenance | inferred |
| exit | corpus red-proved both ways + an executor solving positives and not the control |

Deliberately *not* ROP: the overwrite lands on a stored pointer that the program then
calls, so it tests whether the pipeline can recognise an indirect-call sink at all.

#### G-8c — NEW CATEGORY: injection into a subprocess sink

| field | value |
|---|---|
| type | gap |
| relevance | 4 — the tool currently has **no** non-memory-safety category whatsoever, and the brief is "binary **and software** vulns" |
| complexity | 2 |
| priority | P2 |
| lane | now |
| status | **done** 2026-09-27 |
| evidence | corpus `benchmark/corpus_inject/` (6 targets); oracle proof `benchmark/reference_exploits/inject_variants_reference.py`; executor measurement `benchmark/results_htb/inject-final-20260927.json`; `tests/test_subprocess_injection_executor.py` (19 passed) |
| provenance | measured |
| exit | **met.** Reference exploit: 5/5 positives shell, control does not. Executor `subprocess_injection`: **5/5** positives at `SHELL_ACCESS` (4.6 s each), control rejected by the gate **and** failed when forced through all 14 rungs (20 s) |

Axes actually built: `system` vs `popen` vs a hand-rolled `execl("/bin/sh","-c",…)`
(no `system@plt` in the image at all); a complete metacharacter blocklist defeated by
the program's own percent-**decode after validate**; and an injection position mid-way
through a pipeline, where the trailing `| /bin/cat -` steals an injected command's
stdout unless the payload comments it out. Control: the anchor's exact job done safely
via `execv("/bin/echo", argv)`.

`$PATH`-relative helper invocation was **not** built here and stays with `G-7b`, where
`sabotage`'s `getenv`/`putenv`/`setenv` imports suggest it belongs.

Three things were derived off the image rather than guessed, and each one picked the
winning payload as the **first** rung tried — so the ladder's retries were not what
produced the result:

* the command template (`/bin/echo checking %s`), and whether anything follows the
  `%s` — non-empty suffix promotes the `… #` spelling, which is what solves `inject_14`;
* the target's own reject set, read out of `.rodata` as a string made only of shell
  metacharacters (`;&|$\``) — a rejected separator is demoted instead of leading;
* whether the target transforms input after reading it (`isxdigit`/`strtol`), which
  promotes the percent-encoded spellings and is what solves `inject_13`.

**Protections were deliberately maximised, not minimised.** Every target is
`-fstack-protector-strong -pie -fPIE -Wl,-z,relro,-z,now`, so all four of canary/PIE/NX/
Full RELRO are on and every positive is still a shell in under 5 s. The executor gates
on no protection field at all. This is the first category in the set where the
protection table is irrelevant, and the corpus is built to stop that being re-learned
as "hardened".

The gate's single discriminator is a real static property, not a target-shaped
heuristic: an `exec*` call only counts as a shell sink when a shell **path string**
accompanies it. That is exactly what separates the positives from a program doing the
same job with an argv vector, and it is why the control is skipped rather than
attempted. Because a skipped control measures nothing, it was **also** forced through
the gate and the full ladder, and still failed (`I-16` is why that mattered).

#### T-3 — breadth: types **and** variations, identified, walked through, and solved

| field | value |
|---|---|
| type | target |
| relevance | — (targets are metrics, never sprints) |
| complexity | — |
| priority | — |
| lane | now |
| status | open |
| evidence | today: 4/7 HTB, 3 categories with a red-proved variation corpus (`corpus_variants` closed, `corpus_eintr`/`corpus_srop` in flight) |
| provenance | measured |
| exit | never "done" — reported as a count of categories with (a) a red-proved variation corpus, (b) an executor that solves its positives and not its control, and (c) a runnable walkthrough |

Per `T-3`'s three-part exit, a category is only counted when it can be **taught**, not
merely solved — a bare pass with no runnable 0-to-pwn walkthrough counts as (a)+(b) and
is reported as such.

### Lane: `next`

#### B-3 — `snowscan` stacks three format gates behind the argv gate

| field | value |
|---|---|
| type | bug |
| relevance | 4 — what stands between a working file channel and `snowscan` actually solving, i.e. between Sprint 2′ and `T-1` |
| complexity | ~~4~~ → **2** — a fully accepted BMP is built and confirmed against the real target (20×20, 8bpp, 54-byte header → `[01]…[20] PASS`, `rc=0`); the synthesizer is ~15 lines of `struct.pack` |
| priority | ~~P2~~ → **P1** (raised twice: format validation *masks* the signal a vector probe needs, so B-3 is a prerequisite of reliable detection, not a follow-on; and measured research dropped complexity 4→2) |
| lane | next |
| status | **owes** |
| evidence | `docs/plans/2026-09-26-legacy-to-canonical-gap-analysis.md:178` + the measured BMP research addendum |
| provenance | measured |
| exit | a container-envelope registry delivers a payload inside an accepted BMP **and** an accepted WAV, each proven by a target that refuses a bare payload |
| owes | **plan is at Revision 1 and NOT-APPROVED — one review round outstanding.** Do not start implementation before it clears. |
| blocked-by | Sprint 2′ commit |

**Update, 2026-09-27 — the BMP envelope's accept rule is now measured exactly, and it is
not what the error message says.** Reversed statically from `loadBitmap:0x402235`
(`docs/research/2026-09-27-snow-scan-spike.md` §7.2):

> accepted iff **`400 <= biSizeImage <= 900`** *and* **`biWidth == biHeight`**

The dimensions are **never range-checked** — only compared to each other — and the
`[400,900]` bound sits on `biSizeImage` (file offset 34), whose endpoints are `20×20` and
`30×30`, which is where the message's "20x20 to 30x30" comes from. Two consequences for
this item:

1. **The synthesizer's constraint set is smaller than assumed.** It does not need to
   reproduce a plausible image at all; it needs `bfType="BM"`, `biWidth == biHeight`,
   `biSizeImage` in `[400,900]`, and a correct `bfOffBits`. The earlier "20×20, 8bpp,
   54-byte header" recipe works, but it over-constrains — bit depth and dimensions are
   free, which matters because **the envelope must not be pinned to the one shape that
   happens to work** (the generalization mandate).
2. **The envelope and the payload length are independent, and that is the bug.** The VLA
   is sized from `biSizeImage` while the fill loop runs to **EOF** with no bound
   (`main:0x402500-0x40252a`), so payload length is not constrained by the header at all.
   A registry that sizes the payload to fit the declared image would *destroy* the
   primitive. **The envelope's job here is to satisfy the header check and then get out of
   the way** — worth stating in the design, because the intuitive implementation
   (coherent container) is the wrong one.

Re-triage: relevance **4 → 5**. B-3 is no longer only "what stands between a working file
channel and `snowscan` solving" — the exploitation route behind it is now established
(unbounded controlled stack write, no canary in `main`, static non-PIE), so the envelope
is the remaining blocker on a *candidate seat*, not on a detection signal. Complexity
stays **2**. `owes` is unchanged: the plan is still NOT-APPROVED at Revision 1.

#### A-1 — modularity assessment of the canonical pipeline *(NEW — user directive, future sprint)*

| field | value |
|---|---|
| type | assessment |
| relevance | 4 — the entire legacy→canonical port rests on the premise that capabilities are modular. That premise has never been measured, and this session produced evidence against it. |
| complexity | 2 — read-only analysis over existing code plus retrospective data already on disk; the deliverable is a written finding plus a proposed seam, not a refactor |
| priority | **P1** |
| lane | next *(explicitly NOT today — scheduled for a future sprint)* |
| status | open |
| provenance | the seed observations below are `measured`; the conclusion is unmeasured by construction |
| exit | a written assessment in `docs/research/` that (a) reports the coupling metric per capability, (b) names each seam that a new capability must cut through, (c) for every seam says *right seam* or *modularity defect*, and (d) proposes at most three changes, each with the capability it would newly make additive |
| owes | nothing yet |
| blocked-by | Sprint 2′ commit (its diff is part of the evidence) |

**Why this item exists, with the evidence already in hand:**

- **Coupling metric, measured.** Adding *one* payload-transport capability (Sprint 2′
  Wave 1+2) touched **8 production files** — `cli.py`, `core/context.py`,
  `pipeline/contracts.py`, `pipeline/orchestrator.py`, `pipeline/verifier.py`,
  `pipeline/templates.py`, `pipeline/executors/stack_techniques.py`,
  `exploit/verification.py`. A modular pipeline would have absorbed a new transport in
  one or two. The assessment should compute "files touched per capability added" across
  Sprint 1, Sprint 2′, and B-3 — that retrospective data already exists in git.
- **The central-allowlist seam.** `FILE_DELIVERY_ALLOWLIST` is a module-level constant
  in `orchestrator.py`: a new executor that wants non-stdin delivery must be added to a
  set in a file it otherwise has nothing to do with. Deliberate constants are features
  here, so this is *not* automatically a defect — but whether the capability should be
  declared **by the executor** rather than **about** the executor is exactly the
  question to answer.
- **The closed-sink enum.** The four sinks live in `contracts.py` with a `container`
  field already reserved; adding a transport currently means editing `contracts.py`,
  `verifier.py`, `templates.py`, and `cli.py` together. B-3 (container envelopes) is the
  next capability that will pay this cost, so measuring it before B-3 lands is the
  cheapest moment.
- **Duplicated placement logic, already partly addressed.** "Where does the payload go
  in argv" existed twice (verifier and script renderer) and drifted — that drift is
  round-3's H1. Wave 2/3 converged both on `DeliverySpec.build_argv()` via a throwaway
  sentinel. Whether that pattern should be generalized (one renderer, many back-ends)
  is a finding this assessment should reach.
- **The legacy engine is not behind an interface.** `EnhancedAutoExploiter` has **4
  construction sites** and no capability contract, which is why a declared vector could
  be laundered back to stdin by a fallback path. Any claim that the port is "modular"
  has to account for that.
- **Two engines, two verification paths.** `ExploitVerifier` (payload) and
  `PipelineVerifier.verify_script` (artifact) are both success oracles with different
  fd-0 semantics — see `G-W3-1`. Whether that is one abstraction or two is a
  modularity question, not only a correctness one.

**Explicitly out of scope for A-1:** tool hardening, and any refactor. A-1 produces a
finding and a proposal; the refactor, if any, becomes its own `G-` item with its own
plan and review round.

### Lane: `later`

#### G-2b — command-shell protocols are undriveable

| field | value |
|---|---|
| type | gap | relevance | 4 — unblocks `ancient_interface` |
| complexity | 4 — needs per-target protocol inference; approach unproven |
| priority | **P2** — **spike-first**: infer-the-protocol is the unproven part |
| lane | later | status | open |
| evidence | `docs/plans/2026-09-26-legacy-to-canonical-gap-analysis.md:77` |
| provenance | recorded |
| exit | a spike that drives one command-shell target end to end, or a written refutation |

#### G-2c — banner/handshake targets need pre-payload synchronization

| field | value |
|---|---|
| type | gap | relevance | 3 — partly handled by existing settle discipline |
| complexity | 2 — extends `deliver_parts()` |
| priority | **P1** | lane | later | status | open |
| evidence | `docs/plans/2026-09-26-legacy-to-canonical-gap-analysis.md:80` |
| provenance | recorded |
| exit | a banner target solves with the payload delivered only after the handshake, proven by a control that fails without the wait |

#### G-2d — network-input targets are unreachable

| field | value |
|---|---|
| type | gap | relevance | 2 — no target in this set exercises it |
| complexity | 4 — socket lifecycle, unproven |
| priority | **P3** | lane | later | status | open |
| evidence | `docs/plans/2026-09-26-legacy-to-canonical-gap-analysis.md:83`; the `socket` sink is *reserved* at `docs/plans/2026-09-26-sprint2prime-input-vector-plan.md:535` |
| provenance | inferred — **no target exercises it** |
| exit | a socket sink delivers to a listening target, with the reserved contract field honored |

#### G-3 — SROP three-stage script deadlocks under script verification

| field | value |
|---|---|
| type | gap | relevance | 4 — would add `sick_rop` toward `T-1` |
| complexity | 4 — root cause not yet diagnosed |
| priority | **P2** — **spike-first push-down**: no sprint until a reproduction isolates the deadlock |
| lane | later | status | open |
| evidence | `docs/plans/2026-09-26-legacy-to-canonical-gap-analysis.md:92` |
| provenance | recorded |
| exit | a minimal reproduction that names which side of the deadlock is waiting, then a fix |

#### I-1 — `test_i2_attempt_duration` fails on `main`

| field | value |
|---|---|
| type | issue (pre-existing) | relevance | 2 | complexity | 2 — test-construction fix |
| priority | **P2** | lane | later | status | open |
| evidence | **`measured` 2026-09-26**: with the repo's deselect expression overridden, 6 tests in `tests/test_i2_attempt_duration.py` fail with `AttributeError: 'CanonicalAutopwnEngine' object has no attribute '_force_all'`. This is why they are deselected. |
| provenance | measured |
| exit | the tests exercise the real force-all path under its current name, and are re-selected |

#### I-2 — `test_solve_command::test_guided_fallback_resumes_to_success_with_supplied_offset` times out

| field | value |
|---|---|
| type | issue (pre-existing) | relevance | 2 | complexity | 3 — 90s timeout, cause unknown |
| priority | **P3** | lane | later | status | open |
| evidence | **`measured` 2026-09-26**: `subprocess.TimeoutExpired` after 90s on `supwngo.cli solve … hardoffset` |
| provenance | measured |
| exit | the cause is named and either fixed or the budget justified in the test |

#### I-4 — provenance conflation + dead `instruction_address`

| field | value |
|---|---|
| type | issue | relevance | 2 — describes a win, cannot cause one; measured 0/6 corpus reachability |
| complexity | 3 — one contract change, 2 production consumers + 3 test refs + 1 benchmark tool |
| priority | **P2** | lane | later | status | open |
| evidence | `docs/plans/2026-09-26-legacy-to-canonical-gap-analysis.md:245` (raised by peer review round 1) |
| provenance | measured |
| exit | provenance kinds are distinguishable at the point of use, and the dead field is removed or populated |

#### I-5 — `record.offset` reads as minimal but is first-win-under-ordering

| field | value |
|---|---|
| type | issue | relevance | 1 | complexity | 1 — state the rationale at the loop |
| priority | **P3** | lane | **document-and-move-on** | status | open |
| evidence | `docs/plans/2026-09-26-legacy-to-canonical-gap-analysis.md:246` |
| provenance | measured |
| exit | the loop says what the value means; no behavior change |

#### G-W3-1 — the fd-0 discipline diverges between verification and the generated artifact

| field | value |
|---|---|
| type | gap | relevance | 3 — latent; no corpus or fixture target currently exercises it |
| complexity | 3 — plumbs the verification level into script generation, and must change all four sinks together |
| priority | **P2** | lane | later | status | open |
| evidence | **`measured`**: the subprocess path gives the child EOF (`input=payload` for stdin, `input=b""` for the non-stdin sinks) while every generated artifact leaves stdin open and goes to `io.interactive()`. Identical on HEAD for the stdin default, so the class is pre-existing, not introduced by Sprint 2′. Pinned as one rule by `TestFdZeroDisciplineIsOneRuleForEverySink`. |
| provenance | measured |
| exit | the artifact reproduces the fd-0 discipline of whichever spawn path actually won, for all four sinks, without starving `verify_script`'s `SHELL_ACCESS` oracle |
| blocked-by | a target that waits for EOF on stdin before opening its declared input — **that is what would flip this from latent to measured loss** |

#### I-3 — `explain` command probe hangs on interactive binaries

| field | value |
|---|---|
| type | issue | relevance | 1 — `explain` is not on the `T-1` path | complexity | 3 — unknown |
| priority | **P3** | lane | **document-and-move-on** | status | open |
| evidence | `docs/plans/2026-09-26-legacy-to-canonical-gap-analysis.md:225` |
| provenance | recorded |

#### Q-1 — the embedded-token transport form has no committed compiled fixture

| field | value |
|---|---|
| type | quality | relevance | 2 | complexity | 2 |
| priority | **P3** | lane | later | status | open |
| evidence | adding a 13th input-vector fixture ripples into the foundation suite's `EXPECTED_VERDICTS == FIXTURE_NAMES` table; the form is covered by a purpose-built ad-hoc target and by argv-parity tests, not by a committed fixture |
| provenance | measured |
| exit | either a committed fixture with the verdict table updated, or a recorded decision that argv-parity coverage is sufficient |

---

## 3. Gates (must pass before work ships)

#### T-1 — canonical pipeline solves ≥3/7 HTB targets without legacy fallback

| field | value |
|---|---|
| type | target | status | **met at 4/7 (2026-09-27 evening)** — was 1/7; ~~legacy solves 3/7~~ **legacy measures 0/7 attributed, 1/7 self-reported**. T-1's own ≥3/7 threshold is cleared; **T-1′ (≥5/7) is not** |
| evidence | `docs/plans/2026-09-26-legacy-to-canonical-gap-analysis.md:13`; legacy figure corrected by `docs/research/2026-09-27-legacy-baseline-measured.md` |
| provenance | measured |
| note | Sprint 2′ **does not advance T-1** — `snowscan` stays unsolved behind `B-3`. Said plainly rather than implied. |
| note | **Erratum 2026-09-27.** The ≥3/7 threshold was set to match legacy's recorded score; legacy is now measured at 0/7 attributed, so the *threshold's justification* is void even though the number stands. T-1 is superseded by **T-1′ (HTB ≥5/7)** and **T-2 (variations ≥5/7)** per the user's 2026-09-27 directive. Canonical at 1/7 is equal-or-ahead of legacy on both criteria — **there is no legacy capability to port**, so every remaining seat must come from new capability. |
| note | **Update 2026-09-27 evening.** Three seats added by three new executors, each on a bug class no existing executor could express: `container_file_rop` (`snow_scan`), `eintr_accumulator_rop` (`ancient_interface`), `srop_symtab_pivot` (`sick_rop`). All confirmed at `SHELL_ACCESS` under the re-score harness's behavioural attribution. **4/7.** The remaining three (`sabotage`, `bon-nie-appetit`, `auth-or-out`) are PIE + Full RELRO + canary heap challenges; the bug is located in two of the three. Deficiencies, measurement gaps and the per-target blockers are recorded in `docs/process/2026-09-27-deferred-deficiencies.md`. |
| note | **T-2 has a number for one category, 2026-09-27 late evening.** Per the user's directive to work category-by-category rather than chase target count, the container-file overflow category was taken end to end: variation corpus built (`benchmark/corpus_variants/`, manifest `benchmark/corpus_variants.yaml`), validated as an oracle *before* use by a deterministic reference exploit (all five positives RED, the negative control not), measured, and then generalised until the variants passed. **0/5 → 5/5 positives**, negative control still not solved, and `snow_scan` still solved (2/2) so the gain carries no regression. Full write-up in `docs/process/2026-09-27-deferred-deficiencies.md` §6. The other two categories have no variation corpus yet, so T-2 overall remains partial. |

#### M-1a — per-target corpus regression gate

| field | value |
|---|---|
| type | gate | status | **open — NOT YET RUN for Sprint 2′ Wave 3** |
| exit | 13/13 eligible targets SUCCESS at 5/5 reps, compared **per target** (never in aggregate) against `main` @ `311ff25`, run `20260926-164613Z`, with the two known VOID corpus faults excluded by name: `11_heap_uaf_leak` (`corpus_missing_liveness_gate`) and `13_off_by_one` (`corpus_trivially_solvable`) |
| provenance | baseline is `measured` |
| note | These two VOIDs are **corpus faults and must not be "fixed"** to make a number move. |

#### M-1b — challenge-alike variation benchmark *(user directive, 2026-09-26)*

| field | value |
|---|---|
| type | gate | status | **specified, not measured** |
| evidence | spec at `docs/plans/2026-09-26-sprint2prime-input-vector-plan.md`, section "M-1b" |
| provenance | the harness facts are `measured`; the matrix is unrun |
| exit | a `benchmark/corpus_vectors/` corpus run through the **same** `run_bench.py` verdict machinery, per variant, with the vulnerability held constant and only the ingress varied; and both negative controls (`90_neg_argv_echo_no_open`, `91_neg_config_flag_stdin_payload`) scoring **FAILED** |
| owes | an optional per-target `cli_args:` manifest key (measured gap: `run_supwngo` accepts `extra_args`, nothing supplies them per target) and builder `case` entries |
| note | **Every target in `benchmark/corpus/` takes its payload on stdin**, so M-1a structurally cannot measure this wave's capability. M-1b is the capability gate; M-1a is the regression gate. Neither substitutes for the other. |

---

## 4. Recently closed

| ID | what closed it |
|---|---|
| G-1 | Sprint 1 — disassembly-guided `variable_overwrite` (committed) |
| B-1 | merged-candidate cap + gate tests (`89dbbc9`) |
| B-2 | Sprint 2′ — operator-declared transport replaces inverted auto-detection; the probe is advisory-only |
| G-2′ | Sprint 2′ Waves 1–3 — declared vector now reaches a real spawn (6/6 mechanisms vs 0/6 on the default) |

---

## 5. Out of scope (declared here, repeated in every delegated prompt)

- Security, hardening, and trustworthiness **of the tool itself**.
- Compliance / control-framework findings.
- Deliberate constants — magic-value lists, cheat-sheet tables, technique allowlists —
  are **features**. Measurement problems get fixed in the **corpus**, never by
  weakening a gate or a corpus vulnerability.
- Self-scoring. A verdict comes from the harness, never from the engine's own report.

---

## Appendix A — items added after the queue's first publication

#### G-4 — SROP's read-return `rax` chain is composed against the wrong calling convention

> **ERRATUM, 2026-09-27 (same day as filing).** This item was originally filed as a
> **gap** titled *"SROP cannot use a syscall's return value as a register
> primitive"*, asserting that the capability did not exist and that "no increase in
> its budget or candidate list can reach it." **That assertion is false and the
> original title is withdrawn.** The capability is implemented: `SropExecutor`
> detects a `read` function, sets `use_read_for_rax` when no `pop rax` gadget is
> found, and dispatches `_script_read_rax`
> ([rop_techniques.py:794-800, 830-833, 905](../../supwngo/exploit/pipeline/executors/rop_techniques.py)).
> The 1/7 baseline of run `20260927-142133Z` was therefore measured **after** the
> proposed capability already existed, so building it again would have bought
> nothing. The real defect is narrower and is stated below. Caught by peer review
> (Daybreak Blue R1, finding 4 — see
> [the review](../plans/2026-09-27-5of7-plan-review-r1-daybreak.md)); the error was
> mine, from filing a "missing capability" without grepping for it first, which is
> the failure mode the methodology's Phase-1 rule exists to prevent.

| field | value |
|---|---|
| type | **bug** (was: gap) |
| relevance | **5** — it is the binding constraint on `sick_rop`, one of legacy's three solves, and therefore directly on **T-1** |
| complexity | 3 — repair the stack composition and the stage transition, not a new technique |
| priority | **P1** |
| lane | now (candidate for the next sprint) |
| status | open |
| provenance | **measured 2026-09-27**, run `20260927-142133Z` + disassembly + source read |
| exit | the generated script's **observed syscall sequence** on `sick_rop` contains `read(..., 15) = 15` followed by syscall 15 (`rt_sigreturn`), and `sick_rop` solves |

**Measured — the actual defect.** `_script_read_rax` emits

```
chain = p64(read_addr) + p64(syscall_gadget) + bytes(frame)
```

`sick_rop`'s `read` is a **stack-argument wrapper**, not a register-convention
function: `vuln` does `push $0x300; push %r10; call read`, and the wrapper loads
`rsi` from `0x8(%rsp)` and `rdx` from `0x10(%rsp)`. On entry via this chain,
`[rsp]` is `syscall_gadget` (the return address), so `[rsp+8]` and `[rsp+16]` are
the **first two quadwords of the sigreturn frame**, which are zero in a fresh
`SigreturnFrame`. The call therefore executes `read(0, 0, 0)`, which returns **0,
not 15**, and the following `syscall` runs with `rax=0` — `SYS_read` again, never
`rt_sigreturn`. The technique is right; its argument staging is wrong.

The fix is to compose the chain against the wrapper's measured ABI (place the
length where the wrapper reads it) and to assert the syscall sequence rather than
only the final shell, so a chain that silently degrades to `read(0,0,0)` cannot
read as "no offset candidate verified".

**Update, 2026-09-27 — the staging defect is a CLASS with ≥3 instances, not one line**
(measured; surfaced by peer review R3 finding 9). Every `SigreturnFrame` in the
multi-stage path sets `rax` for a syscall while pointing `rip` at a *function entry*
rather than a syscall *instruction*, so the syscall it staged never executes:

| frame | sets | points `rip` at | cite | consequence |
|---|---|---|---|---|
| `frame1` | `rax = SYS_mprotect` | `vuln_func` | `:991,996` | `mprotect` never runs |
| `frame2` | `rax = SYS_read` | `vuln_func` | `:1010,1014` | the `/bin/sh` plant never runs |

Plus a separate continuation bug: `frame1.rsp = rw_target + 0x400` (`:998`), so after
the `syscall; ret` gadget completes it returns through an **unstaged word** on the
newly-writable page — nothing placed a return target there.

**Consequence for the exit.** Repairing the argument staging alone would witness
`read(...,15) = 15` and syscall 15 and still crash before stage 2. The exit therefore
requires the trace **and** the stage transition **and** an attributed shell in ≥2/3
reps, and the repair must specify for every frame the complete continuation state:
syscall RIP, post-syscall return word, RSP location, re-entry, and where the next
chain is staged. My earlier characterisation of this item as "diagnosed to two lines"
is **withdrawn** — the confidence attached to the `sick_rop` seat was overstated.

**Measured.** `sick_rop` is 4832 bytes / **26 instructions**. The complete set of
instructions touching `rax`:

```
401000:  mov $0x0,%eax      (read)
401017:  mov $0x1,%eax      (write)
401045:  push %rax
401014, 40102b: syscall
```

There is **no `pop rax` gadget and no writable-section trick that helps**.
`rt_sigreturn` requires `rax == 15`, and the only primitive in the binary that can
produce an arbitrary `rax` is **`read`'s own return value**: invoke `read` and send
exactly 15 bytes, so the syscall returns 15 into `rax`, then transfer to `syscall`.
`SropExecutor` already selects exactly this route (`use_read_for_rax`); the
disassembly above establishes that the route is the only one available, **not** that
it is absent.

This is a semantic fact about syscall return values, not a search-space point. The
current executor sweeps *offsets*, so no increase in its budget or candidate list
can fix a chain whose arguments land in the wrong stack slots — which is why this is
a composition bug rather than a tuning issue.

Supporting measurement that rules out the competing explanation: `vuln` calls
`read` with length `$0x300` = **768 bytes** into a 32-byte frame
(`sub $0x20,%rsp`), and the epilogue is `leave; ret`, so the return address sits at
offset **40** — a value already in `COMMON_RET_OFFSETS`. Neither the frame size nor
the offset list is the constraint.

#### I-9 — SROP's failure_reason states a hypothesis the binary refutes

| field | value |
|---|---|
| type | bug |
| relevance | 3 — no effect on any solve, but it actively misdirects diagnosis, which is worse than saying nothing |
| complexity | 1 |
| priority | **P2** |
| lane | now (ride along with G-4) |
| status | open |
| provenance | **measured 2026-09-27** |
| exit | the reason either states a fact about the target or declines to speculate; it never asserts a bound it did not check |

`srop` on `sick_rop` reports:

> built a real rt_sigreturn frame and generated a script, but no offset candidate
> produced a verified shell (a 248-byte frame plus the offset may simply not fit in
> this target's read)

The parenthetical is **false for this target** and checkable from the binary: the
`read` accepts 768 bytes, so a 248-byte frame at offset 40 uses ~288 of 768. A
human following that hint would go looking for a size problem that does not exist,
and would not find G-4.

**Same defect class as I-6 and round-3 H3** — a failure of *measurement* rendered as
a failure of *the thing measured*. Here the executor did not measure the read
length at all; it guessed, and the guess is presented in the same voice as the
established facts around it. The fix is to gate the speculative clause on an actual
check of the target's input length, or drop it.

**Also recorded:** the same run shows `srop`'s recorded skip reason in
`docs/reports/2026-09-26-comprehensive-feature-retest.md` ("no '/bin/sh' string and
no writable section to plant one") is **out of date** — SROP no longer declines at
that gate, it builds a real frame and fails at offset verification. Erratum noted
here beside the claim rather than only in a chat message.

#### I-7 — an undeliverable candidate aborted the whole sweep instead of being pruned — **CLOSED**

| field | value |
|---|---|
| type | bug |
| relevance | 5 — it made an entire delivery transport read as non-functional |
| complexity | 1 — the search continues past an infeasible candidate instead of dying on it |
| priority | **P1** |
| lane | now (closed same day it was found) |
| status | **closed** |
| provenance | **measured 2026-09-27**, run `20260927-124751Z` |
| exit | met — `24_ingress_argv_direct` solves at `offset=64 magic=0x5afef11e`, provenance `recovered_immediate` |

**How it was found.** By the ingress corpus on its first clean run, which is the
concrete argument for having built it: row `24_ingress_argv_direct` scored
`FAILED (0/5 reps)` while the other four new transports scored `SUCCESS (5/5)`.
M-1a structurally could not have found this — every target in `benchmark/corpus/`
reads stdin, so the argv gate is unreachable from that corpus.

**Root cause.** `VariableOverwriteExecutor` swept candidate gate constants and
called `verifier.verify_payload` with no exception handling
(`stack_techniques.py:121-125` at `8d76e14`). `PipelineVerifier` correctly refuses
a NUL-bearing payload on `SINK_ARGV` — an argv token is a NUL-terminated C string
at the syscall boundary — but that `ValueError` propagated out of the sweep.
Candidates are ordered smallest-first, so a small recovered immediate (or the
fallback `0x1337` → `37 13 00 00`) killed the technique on an early candidate and
`0x5AFEF11E`, which is NUL-free and wins, was never reached. The technique
reported `ERROR` with an **empty** `failure_reason`, so the run was also
undiagnosable from its own report.

**Fix.** A single predicate, `contracts.payload_representable(sink, payload)`, now
owns the rule. The verifier asks it and raises; the executor asks it first and
prunes, counting what it pruned and reporting the count in `failure_reason` — an
exhausted search and a search that could not attempt N candidates over this
transport are different results, and the second is a transport limit rather than
an absent gate constant.

**The option not taken:** wrapping `verify_payload` in `except ValueError`. One
source of truth, and it would absorb future undeliverability reasons for free —
but `build_argv()`'s five configuration gates raise the same type, so a
misconfigured spec would be silently recorded as an exhausted search. That is the
same failure mode that made an invalid manifest row read as "the argv transport
does not work" earlier the same day. What would flip the decision: enough
distinct undeliverability reasons to make a predicate unwieldy, at which point a
dedicated exception type (not bare `ValueError`) becomes the better carrier.

**Red-proofed.** Deleting the prune fails
`test_it_reaches_a_later_candidate_after_pruning_an_earlier_one` and
`test_an_exhausted_argv_sweep_reports_how_many_it_could_not_try` (2 failed, 9
passed) on the assertion that the executor handed the verifier bytes the sink
cannot carry. A first draft of that test was **vacuous** — it used `0xdeadbeef`,
which sits at index 1 in `FALLBACK_MAGIC_VALUES`, ahead of the NUL-bearing
`0x1337` at index 4, so the sweep won before reaching the candidate it was
supposed to prune and passed with the prune deleted. Fixed by selecting a winner
that sits after it, plus
`test_the_ordering_this_module_depends_on_still_holds` to keep a future reorder
from quietly restoring the tautology.

**Left open deliberately.** `Ret2WinExecutor` has the same shape — it packs a
64-bit win address, which for a non-PIE binary always contains NUL bytes, so
`ret2win` is genuinely undeliverable over `SINK_ARGV` rather than merely
mispruned. That wants a clear SKIP with a stated reason, not a prune, and it is
not what the measurement demonstrated. Filed as **I-8** rather than fixed here.

#### I-13 — the T-1′ harness cannot enforce "without legacy fallback", so target timings are not canonical timings

| field | value |
|---|---|
| type | bug |
| relevance | **5** — it does not change the 1/7 score, but it invalidates every *diagnosis* drawn from per-target runtimes, which is what the next sprint's sequencing was built on |
| complexity | 2 — a canonical-only path plus an assertion in the harness |
| priority | **P0** |
| lane | now (must precede any budget or spike work) |
| status | open |
| provenance | **measured 2026-09-27** (source read + report JSON), surfaced by peer review of plan v2, finding 1 |
| exit | the harness runs a path that **cannot instantiate** `EnhancedAutoExploiter`, asserts no reported technique carries a `legacy:` prefix, preserves the canonical attempt report on timeout, and the HTB baseline is **re-measured** on it |

**Measured.** `scripts/htb_rescore.py` invokes `supwngo.cli solve`. That command runs
the legacy engine whenever the canonical pipeline fails and no `--input-vector` was
declared (`cli.py:3342-3366`; the same fallback exists in `autopwn` at `cli.py:2771`).
The harness passes no `--input-vector`, so **the legacy engine ran on all six
non-solving targets.** The docstring's claim that withholding `--libc` satisfies
T-1's "without legacy fallback" is a non-sequitur — `--libc` does not gate the
fallback — and is corrected in the same change.

**What survives and what does not.** The solve *count* is unaffected and this is
checkable, not assumed: a legacy success is labelled `engine.technique_used =
f"legacy:{...}"` (`cli.py:3362`), and the only technique string recorded anywhere in
run `20260927-142133Z` is `ret2libc_leak` ×3. **No target was credited to legacy, so
1/7 stands.** What does not survive is the diagnosis layered on the timings:

- "`ancient_interface` and `auth-or-out` exhaust the timeout in canonical search" is
  **not established** — the legacy sweep also ran inside that window. The budget
  sprint's justification must be re-derived after re-baselining.
- "four targets are declined by every executor in under 20s" is a claim about
  canonical **and** legacy combined. The conclusion that these are not budget-bound
  survives (both engines declined fast); the attribution to canonical does not.

**Class note.** This is the *measurement* side of the same defect class as I-6, I-9
and G-4: a property that was never checked, rendered in the same voice as the
properties that were. The harness observed the technique string but never *asserted*
on it, so "no legacy credit" was true by luck rather than by construction.

#### I-11 — one image-base fact, several producers and several consumers, none agreeing

| field | value |
|---|---|
| type | bug |
| relevance | **5** — it silently voids *any* future PIE-base recovery, so it blocks 3 of the 4 unsolved HTB targets before the first line of that work is written |
| complexity | 1 — canonicalize one key, or teach `needs_leak` both |
| priority | **P0** |
| lane | now (must precede any PIE work) |
| status | open |
| provenance | **measured 2026-09-27** (source read), surfaced by peer review R1 finding 6 |
| exit | a **planted, validated** base changes an executor's *resolved* gadget/GOT/control-target addresses and permits an attempt that otherwise skips; key canonicalization alone does **not** close this |

> **Correction, 2026-09-27 (same day as filing).** Filed originally as "a recovered
> image base is written to a key nothing reads", asserting that *every* consumer gates
> on `binary_base`. **That is overstated.** Consumers are split, not uniformly wrong,
> which makes the defect larger rather than smaller. Caught by peer review of plan v2,
> finding 3.

**Measured.** There is no single image-base fact. There are at least four views of it:

| site | keys on | cite |
|---|---|---|
| `ExploitContext.needs_leak()` | `leaks["binary_base"]` | `core/context.py:358-360`, again `:400` |
| orchestrator known-facts write | `leaks["pie"]` | `orchestrator.py:560` |
| handoff fact-checks | `leaks["pie"]` | `handoff.py:193-196` |
| `Ret2LibcLeakExecutor` | neither — probes and computes PIE info **privately** | `rop_techniques.py:421` |
| `tcache_poison_got` | neither — **refuses every PIE target outright**, whatever is stored | `heap_techniques.py:172` |

So a recovered base satisfies the handoff's view, leaves `needs_leak()` still
returning `True`, and is invisible to both executors that would have to consume it.
Known facts are additionally applied only **after** the profiling/leak prologue
(`orchestrator.py:303`), so the ordering is wrong even for the consumer that does read
the key.

**Why the obvious fix is not the fix.** Renaming one key would make the
`needs_leak()` red-proof pass while changing no executor's behaviour: the heap
executor still refuses PIE, and ret2libc still runs its own private probe. That is
the failure mode this item exists to prevent, so its exit criterion is deliberately
an *end-to-end* one — a planted base must change a resolved address and unlock an
attempt that otherwise skips. Recovery and consumption are separate facts and only
the second one is worth anything.

#### I-12 — `identify_leak_type` cannot distinguish a PIE image pointer from a heap pointer

| field | value |
|---|---|
| type | bug |
| relevance | 4 — it does not break a current solve (nothing consumes it yet, per I-11) but it is the classifier any PIE work would build on, and it is wrong in exactly the case that work needs |
| complexity | 2 — needs provenance, not a wider range check |
| priority | **P1** |
| lane | now (rides with I-11) |
| status | open |
| provenance | **measured 2026-09-27** (source read), surfaced by peer review R1 finding 6 |
| exit | **paired** controls on the *canonical* path: a provenance-correct code pointer is accepted **and consumed**, while a same-range heap pointer is rejected. Rejection alone does not pass — it is satisfiable by rejecting everything |

> **Correction, 2026-09-27 (same day as filing).** Filed originally against
> `remote/leak.py:identify_leak_type`. **The canonical pipeline does not call that
> function.** Fixing it would have left the live defect untouched. Caught by peer
> review of plan v2, finding 4.

**Measured — there are three independent overlapping-range classifiers**, and the
one I filed against is the only one the canonical engine never uses:

| classifier | used by | cite |
|---|---|---|
| `delivery.classify_address` | **the canonical profiler** — and `shellcode_techniques` | defined `delivery.py:322`; called `profile_stage.py:174,177`, `shellcode_techniques.py:68` |
| `AutoLeakFinder`'s own classifier | the active leak path | `auto_leak.py:339` |
| `remote/leak.py:identify_leak_type` | legacy / `remote` only — **not the canonical profiler** | `remote/leak.py:172,194-197` |

The defect is the same in each: on amd64 a PIE process's **heap is mapped
immediately after its image**, so the `0x55…` region a classifier labels "PIE" is
also where the heap lives, and the `"heap"` branch (`remote/leak.py:196`) only
catches `address < 0x100000000`, which a PIE-adjacent heap never satisfies. A leaked
heap pointer is therefore classified as an image pointer **unconditionally**, and
page-aligning it yields a heap page. Worse, the active PIE helper can then bind a
symbol to it on **matching low page bits alone** (`rop_techniques.py:119`), so a
page-offset coincidence produces a confidently wrong base.

Range classification cannot fix this, because the ranges genuinely overlap — no
choice of bounds separates them. The distinguishing information is **provenance**:
which action produced the pointer, which symbol it is expected to be, and that
symbol's static offset, so `base = leak - known_offset` can be validated against the
ELF's own segment layout. A classifier that can only say "this number looks like a
binary address" cannot make the judgement its callers need.

**Scope consequence:** the fix must route all three paths through one typed API, or
enumerate and replace each. Fixing one and testing that one is how a repair passes
while the live path stays broken.

#### I-8 — `ret2win` over `SINK_ARGV` should SKIP with a reason, not sweep and fail

| field | value |
|---|---|
| type | issue |
| relevance | 2 — affects report honesty, not any solve: the technique cannot work over this sink either way |
| complexity | 1 |
| priority | **P3** |
| lane | document-and-move-on |
| status | open |
| provenance | **inferred 2026-09-27** — reasoned from the pack width, not observed in a run |
| exit | `ret2win` on `SINK_ARGV` reports SKIPPED naming the 64-bit-address/NUL reason, instead of exhausting a sweep it could never win |

A 64-bit win address packs with high NUL bytes for any realistic non-PIE image
base, so every candidate is unrepresentable in an argv token. After I-7 the
sweep now prunes them all and reports an exhausted search with a full prune
count, which is accurate but reads as a failed attempt rather than an
inapplicable technique.

#### I-6 — walkthrough libc resolution is session-state dependent, and fails silently

| field | value |
|---|---|
| type | issue |
| relevance | 3 — it does not affect a solve, but it silently converts a *measurable* fact into "could not determine", which is exactly the claim the walkthrough family exists to make honestly |
| complexity | 2 — the fix is to distinguish the failure, not to change how resolution works |
| priority | **P2** |
| lane | later |
| status | open |
| provenance | **measured 2026-09-26** |
| exit | `_default_libc` distinguishes "this target has no libc" from "resolution did not complete", and the walkthrough renders the second as a *failed measurement* naming the cause, not as an absence |

**Evidence (measured, via a temporary instrumented build of `facts.py`):**

`collect_facts` resolves the libc through `_default_libc` (`facts.py:696`), which reads
pwntools' `ELF.libc`. That property reaches `pwnlib.elf.elf.ELF._populate_libraries` →
`_patch_elf_and_read_maps`, which **patches shellcode into the target's entry point,
executes the target, and parses `/proc/self/maps`**. Its own docstring says it returns
`{}` when it cannot inject — so on failure `libs` is empty, `libc` is `None`, and **no
exception is ever raised**. `_default_libc`'s `except Exception: return None` therefore
never fires, and there is nothing anywhere to attribute.

Instrumented full-suite run recorded 155 `NO-LIBC` events with no exceptions, e.g.
`NO-LIBC elf=ELF('benchmark/corpus/11_heap_uaf_leak/heap_uaf_leak')` ×7 — for a target
whose libc resolves fine when the same file runs alone.

Downstream, `probe_allocator` reports `safe_linking` as UNKNOWN with the reason
"no libc path was resolved for this target", which is **honest but indistinguishable
from a target that genuinely has no libc**, and it grows the rendered
"Could not determine:" list by one name.

**Why this is filed and not fixed in Sprint 2′:** the walkthrough family is outside this
sprint's scope, and nothing Sprint 2′ changed causes it. The demonstrated failure
(`tests/test_walkthrough_heap.py::test_the_final_summary_lists_what_could_not_be_determined`,
which failed only in full-suite context) was closed at the **test** boundary by pinning
the libc with `ldd` and skipping explicitly when `ldd` names none — three states, not
two. Red-proofed: an unreadable pinned libc reproduces the original failure signature
exactly (1 failed, 51 passed), so the pinning is load-bearing and the gate is not vacuous.

**Same defect class as round-3 H3** (`docs/plans/2026-09-26-wave2-impl-review-r3-daybreak.md`):
a failure of *delivery/measurement* rendered as a failure of *the thing being measured*.
H3 was fixed in production because it sat in the sprint's own code path; this one is
filed with its evidence.

---

#### D-1 — the legacy fallback's value is now an open decision, not an assumption

| field | value |
|---|---|
| type | issue (decision owed) |
| relevance | **4** — it does not change any score, but it decides whether a second exploitation engine stays on the operator path, and that engine is a live source of measurement contamination (see `I-13`) |
| complexity | 2 — the measurement is done; what remains is a recorded decision plus, if removal is chosen, deleting one block in each of two CLI commands |
| priority | **P2** |
| lane | later — **must not** ride along with any sprint that is being scored, because removing it changes the operator path mid-measurement |
| status | open |
| provenance | **measured 2026-09-27**, `docs/research/2026-09-27-legacy-baseline-measured.md` |
| exit | a recorded decision — keep, remove, or demote to an explicit `--legacy` opt-in — with the reason stated. "Keep because it might help" does not satisfy this; the measurement says it does not help on these seven targets. |

**Measured.** `EnhancedAutoExploiter` was run alone against all seven HTB targets with
a probe validated in both directions (negative control `/bin/true` → `NOT_SOLVED`;
positive control `benchmark/corpus/15_win_function` → `ret2win`/`FLAG_CAPTURED`). It
scored **0/7** under attributed crediting and **1/7** under the self-report criterion
the withdrawn "3/7" figure used. Two targets (`ancient_interface`, `auth-or-out`)
consumed the full 600 s timeout.

**Why this is a decision and not a fix.** Three facts pull in different directions and
none of them is mine to weigh unilaterally:

1. The fallback adds **no measured solve** on this corpus, and it is reached on every
   canonical failure (`cli.py:3393`, `cli.py:2799`), so it costs wall-clock on exactly
   the runs that are already slowest.
2. It is the mechanism behind `I-13` — it contaminated per-target timings and forced
   `--no-legacy` to exist so measurement could be structural.
3. But "0/7 on seven HTB targets" is **not** "worthless in general". The corpus is seven
   binaries; absence of benefit here is weak evidence about an arbitrary operator target,
   and `--no-legacy` already removes it from every *measured* path.

**Option not taken, and what would flip it.** I did not remove the fallback. Removing a
working operator code path on the strength of a seven-binary corpus would be scope creep
past what the measurement supports, and `--no-legacy` already closes the measurement
hole that actually mattered. What would flip it: a run of the ingress/variation corpora
showing the fallback also contributes nothing there, or a demonstration that its
unconditional invocation is what pushes a target over the harness timeout — either
would make removal a correctness fix rather than a preference.

**Deliberately not in scope here:** the fallback's *own* robustness. Per the standing
exclusion, hardening the tool is out of scope; this item is about whether the path
should exist at all.

---

#### I-14 — `test_guided_fallback_resumes_to_success_with_supplied_offset` fails, and did before this work

| field | value |
|---|---|
| type | issue (pre-existing failure) |
| relevance | 2 — it is not caused by the category work and must not be absorbed into it |
| complexity | 2 |
| priority | P2 |
| lane | later |
| status | open |
| evidence | `tests/test_solve_command.py::TestSolveEndToEnd::test_guided_fallback_resumes_to_success_with_supplied_offset`; **proven pre-existing** by running that file in a `git worktree` at `0c79463` — identical `1 failed, 15 passed` |
| provenance | measured |
| exit | the test passes, or is retired with a recorded reason |

Named here so `M-2` can exclude it **explicitly** rather than tolerating it quietly
(queue rule 5). `M-2` is green when pytest shows no failure *other than* this one.

#### I-15 — `eintr_accumulator_rop` delivers its signals out-of-band, so it is local-only

| field | value |
|---|---|
| type | issue (accepted narrowing) |
| relevance | 3 — the technique solves 6/6 locally; this bounds where that result transfers |
| complexity | 4 — an in-band path needs a re-armable timer the target may not expose |
| priority | P2 |
| lane | later |
| status | open |
| evidence | `signal_underflow_techniques.py` drives signals with `os.kill(pid, SIGALRM)`; arming `setitimer(ITIMER_REAL)` 16× in-band was **measured** to deliver 1 signal, not 16 |
| provenance | measured |
| exit | either an in-band delivery path that reaches the required signal count on `eintr_14`, or a recorded decision that local-only is the intended scope |

`G-5`'s 6/6 is a real result on local processes and nothing here retracts it. But the
exploit no longer uses the target's own timer command to generate the interrupts, so it
would not work against the same binary behind a socket. Recorded so the capability
claim stays the size of the evidence.

#### I-16 — `verify_script`'s shell oracle FALSE-POSITIVES on any target that echoes its input

| field | value |
|---|---|
| type | bug (success-oracle soundness) |
| relevance | **5** — it inflates the one number this whole run is judged by |
| complexity | 3 — the fix is a marker change, but every executor's generated script relies on the current contract |
| priority | P1 |
| lane | now |
| status | **mitigated** 2026-09-27 — labelled, not yet made strict |
| evidence | `verifier.py:~420` `stdin_data = (f"echo {token}\n" * 2)` and `shell_confirmed = token in output`. **Measured** against `benchmark/corpus_inject/inject_90_neg_execv_argv`, a target with no shell in its path at all: send `x; sh`, then `echo TOK_12345`; the target's own main loop prints `checking echo TOK_12345`; `token in output` → `True`, i.e. **SHELL reported where no shell exists** |
| provenance | measured |
| exit | the oracle distinguishes a shell from an echo — e.g. requires a marker the target cannot reproduce (`id` → `uid=`), or a token transformed by shell quote-removal (`PW"N"ED_x` → `PWNED_x`) |

This is the project's signature defect class (validation that cannot fail) in the
success oracle rather than in a test: an echo is credited as a shell. It is category-wide
for `G-8c`, where echoing the input **is** the target's job, and it is a latent hazard for
any other target that reflects input.

`G-8c` works around it locally: the script it generates proves a shell with `id`/`uid=`
before it forwards any stdin, so a failed rung closes its process and can never be
credited. That is a per-executor workaround, not a fix — the pipeline-wide oracle was
still unsound, and any future executor that bridges stdin naively would inherit the bug.

**Mitigated centrally, 2026-09-27.** `verify_script` now sends two additional probes
after the original two (which are sent unchanged, so existing generated scripts behave
identically): `id`, and `echo <token>""_STRICT` whose quote-stripped form only a shell
produces. Receipts carry `shell_proven` and `echo_ambiguous`.

`SHELL_ACCESS` is still credited when only the plain token returns. That is a deliberate
choice, not an oversight: making the oracle strict would silently reclassify every
previously recorded solve, and a score that moves because the ruler changed is worse than
one that is labelled. So the number is preserved and annotated instead — a receipt with
`echo_ambiguous` set is a **candidate** solve and any score counting it should say so.

Both directions are pinned by tests in `tests/test_subprocess_injection_executor.py`: a
deliberately naive stdin bridge against the no-shell control returns
`shell_confirmed=True, shell_proven=False, echo_ambiguous=True` (the RED proof — the flag
demonstrably fires on the real false positive), and a genuinely obtained shell returns
`shell_proven=True` (the positive control, so the flag is not simply always-on).

**Still owed:** nothing re-audits the existing 4/7 for `echo_ambiguous`. Until a rescore
runs with this build, whether any recorded solve is an echo is *unmeasured* — an open
question, not a clean bill of health. That audit belongs to `M-2`.

#### I-17 — four HTB challenge dirs ship a 0-byte dynamic loader

| field | value |
|---|---|
| type | issue (fixture integrity) |
| relevance | 3 — **downgraded after measurement**; the scored impact is one target, and it is now worked around |
| complexity | 1 |
| priority | P3 |
| lane | document-and-move-on |
| status | open (mitigated) |
| evidence | measured, `find tests/htb-targets -name ld-linux-x86-64.so.2 -printf '%s\t%p\n'`: `0` for `a12c733e`, `a12c7359`, `a12c7382` (`sabotage`), `a12c7383` (`bon-nie-appetit`); `240936` for `a12c7380` (`rocket_blaster_xxx`) |
| provenance | measured |
| exit | recorded, with the per-target impact resolved (done below) |

The RE cycle raised this as potentially invalidating a recorded `SOLVED`, on the grounds
that `rocket_blaster_xxx`'s loader is "byte-identical in size to this host's". **Measured
and resolved: it is not the host's loader.** `cmp` against
`/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2` differs at byte 729 — same size,
different build (bundled libc `2.35-0ubuntu3.6` vs host `2.35-0ubuntu3.15`). So
`rocket_blaster_xxx` has a genuine bundled runtime and **its `SOLVED` is not in
question.** Recording the resolution here rather than leaving the doubt open.

Scored-target impact, target by target: `sabotage` is unaffected (bundled 2.35 matches
the host closely enough to run, and it has been shelled). `bon-nie-appetit` *was* the
one real casualty and is now handled via the snap `core18` 2.27 loader — see `G-7a`.
`a12c733e` and `a12c7359` are **not among the seven scored targets** (they have no
`organized/` symlink), so their broken loaders cost nothing; note `a12c7359` bundles
glibc **2.39**, which this host could not run anyway.

#### I-18 — every unsolved HTB target spins its menu forever on EOF, at >20k redraws/s

| field | value |
|---|---|
| type | bug (harness robustness) |
| relevance | 4 — it is the **measured** cause of timeouts previously attributed to a missing search budget |
| complexity | 2 |
| priority | P1 |
| lane | next |
| status | **partially closed** 2026-09-27 — diagnosed, not yet prevented |
| evidence | measured over 5 s: `auth-or-out` 238,243 menu redraws, `bon-nie-appetit` 125,900, `sabotage` 109,995 |
| provenance | measured |
| exit | the pipeline detects an EOF spin and abandons the attempt, instead of filling a pipe until its timeout |

Cause is the same shape in all three: a number reader that cannot distinguish EOF from
`0` (`scanf("%32s")`, or `read(…,0x1f)`+`atoi`, or `fgets`+`strtol`) feeding a menu loop
that re-displays on an out-of-range choice. At EOF the buffer stays zeroed, the parse
yields 0, and the menu redraws forever.

Two consequences, both worth acting on. It **reattributes** a recorded diagnosis:
`auth-or-out`'s `TIMEOUT ×3 @300s` (and the 600 s retry) in
`docs/research/2026-09-27-legacy-baseline-measured.md:100` was read as GAP-B, "no
search-budget discipline". It is not — the process was alive and productive, printing
menus. And it is a live hazard for any harness that reads to EOF: hundreds of MB of
stdout for a target that is doing nothing.

Related input-shape landmine, same source: `bon-nie-appetit`'s `read_num` is a raw
31-byte `read`, so a batched "send every line at once" strategy is swallowed whole by the
first prompt and desyncs into "Invalid option" permanently. One prompt, one send.

**Diagnosed centrally, 2026-09-27.** `verify_script` receipts now carry an `OUTPUT SPIN`
note (`verifier._detect_output_spin`) when captured output is overwhelmingly repetition,
so a timeout no longer hides its cause. Measured: it fires on `auth-or-out` driven to EOF
(987,800 non-blank lines, **7** distinct, ratio ~141,000).

Worth recording how the first version failed, because it is this project's signature
defect class again. It required one line to be >50% of the output. The real spin is a
**six-line menu block**, so no single line exceeds ~17% and the check could never fire on
the case it was written for — it passed every synthetic test and was useless. It was
caught only by running the real target instead of a fixture. The detector now keys on a
repetition *ratio* (total non-blank lines / distinct non-blank lines) and
`tests/test_output_spin_detector.py::test_fires_on_a_multi_line_menu_block` is the
regression guard.

**Prevented as well as diagnosed, same day.** `verify_script` no longer uses
`subprocess.run`; `_run_script_bounded` reads incrementally, caps the capture at 4 MB,
and re-tests the spin ratio as output arrives, abandoning the run on detection. Measured
against `auth-or-out` driven to EOF with a **90 s** budget: abandoned in **0.6 s** with
the correct diagnosis, a 150x saving, and the normal path is unaffected (the injection
anchor still reaches a proven shell in 6.6 s).

**Known limit, measured, not glossed:** the guard only sees output that reaches
`verify_script`'s pipe. A generated script that buffers the target internally — e.g.
one whose driver does a single `recvrepeat(120)` and prints at the end — defeats it, and
that case was measured waiting out the full 120 s budget with only `script timed out` to
show for it. So the saving applies to scripts with an incremental driver loop, which is
most of them but not all. The residual fix is a convention for generated drivers (drain
and flush as you go), not more detector logic.

#### G-9 — no executor can express "leak first, then finish in libc"

| field | value |
|---|---|
| type | gap |
| relevance | **5** — it is the shape of *every* remaining HTB target, so it gates the score more than any single technique |
| complexity | 4 |
| priority | P0 |
| lane | now (next free slot after `G-7`) |
| status | open |
| evidence | grounded in source: `heap_techniques.py:174` `tcache_poison_got.is_applicable` returns False on `context.protections.pie` (`:189` skip reason "PIE enabled (GOT addresses not fixed)"); `heap_and_bypass.py:209,308` — `uaf` and `double_free` both require a `win_addr` symbol. All three remaining targets are PIE + Full RELRO with no `win()` |
| provenance | measured (read at the cited lines) |
| exit | an executor, or shared machinery, that chains: obtain a leak → resolve a base → build the finisher against the *resolved* library, with the libc release branching the choice of finisher |

Every heap executor in the set assumes a world these targets are not in: fixed GOT
addresses, or a `win()` symbol in the image. Full RELRO independently rules out the GOT
path. The consequence is not "these techniques fail" but "there is no way to *express*
the exploit at all", which is why the three targets read as three separate category gaps
when they share one missing capability.

Note this is a **shared-machinery** item, not a new technique: `G-7a`, `G-7c` and any
future PIE heap target all need the same leak→resolve→finish plumbing, and the libc
release must select the finisher (see the `__free_hook` precision note under `G-7a`).

---

## 6. Autonomous run log — 2026-09-27 onward

Chronological record for the `now`-lane capability run. One entry per observation that
moved an item; measured numbers only, no projections.

| # | when | item | observation |
|---|---|---|---|
| 1 | 2026-09-27 | container category | **closed.** `0/5 → 5/5` positives on `benchmark/corpus_variants`, control unsolved, `snow_scan` 2/2 unregressed. Landed `0c79463` + `0d4f0f2`, fast-forwarded to `main`, branch deleted. |
| 2 | 2026-09-27 | `G-5` | corpus `benchmark/corpus_eintr/` built: 5 positives + anchor + 1 negative control. Anchor reaches a **real shell** deterministically (`PWNED_OK` + `uid=…`), so the primitive is proven before the executor is asked to find it. |
| 3 | 2026-09-27 | `G-5`, `G-6` | both cycles dispatched in parallel on disjoint files; git, `CHANGELOG.md` and `docs/` held by the orchestrator so the two cycles land as separate commits. |
| 4 | 2026-09-27 | `A-2` | **partial.** `measured`: VRv5's `.claude/skills/` is empty and its `.claude/agents/` holds 2 files, so the survey material is the agent ROSTER, not that tree. Coverage table filed under `A-2`; three new categories accepted (`G-8a` weak PRNG, `G-8b` indirect-call hijack, `G-8c` subprocess injection) and six classes (kernel, browser, firmware, mobile, .NET, IIS) declared out of reach for a local C fixture corpus rather than faked. |
| 5 | 2026-09-27 | queue | parallelism raised 3 → 6 concurrent cycles on disjoint path sets. `M-2` re-ordered to last: it is a whole-tree gate and cannot measure a tree that no commit corresponds to. |
| 6 | 2026-09-27 | support session | the external support session `638c7654-…` is **not reachable** — absent from `ListAgents` (201 peers) and the raw id does not resolve, so its work item (the `scanf` corpus) was re-routed to an in-session agent instead of guessing at an unrelated session. |
| 7 | 2026-09-27 | `G-5` | **closed.** `0/6 → 6/6` positives at `SHELL_ACCESS` on `benchmark/corpus_eintr`, control gate-applicable but FAILED, `ancient_interface` unregressed (13.5 s). The baseline includes the anchor at **0**, so the executor had stopped working on a rebuild of the very target it was written for — one gcc's sign-extension order was load-bearing. Cost logged as `I-15` (out-of-band signal delivery ⇒ local-only). |
| 8 | 2026-09-27 | `G-8c` | orchestrator took the subprocess-injection category directly (6 targets built: anchor `system()`, `popen()`, hand-rolled `execl /bin/sh -c`, a blocklist with a command-substitution gap, a mid-pipeline injection position, and an `execv`-argv control). First **non-memory-safety** category in the set; its `cflags` deliberately enable the full modern protection set to make the point that none of them apply. |
| 9 | 2026-09-27 | `G-8c`, `I-16` | **closed, and it surfaced a tool bug worth more than the category.** Executor `subprocess_injection`: 5/5 positives at `SHELL_ACCESS` in 4.6 s each; control rejected by the gate AND failed when forced through all 14 rungs. On all five, the *first* rung tried was the winning one, so the derivations (command template + suffix, the reject set read from `.rodata`, decoder presence) did the work rather than the retries. Along the way, **measured** that `verify_script`'s `echo <token>` oracle reports SHELL_ACCESS on a target with no shell at all whenever the target echoes its input → filed as `I-16`, priority P1, because it inflates the run's headline metric. |
| 10 | 2026-09-27 | `G-7a`/`G-7b`/`G-7c` | **the RE cycle produced exploits, not just classifications.** `sabotage` and `auth-or-out` both at a real **shell, 3/3 reps**, by hand; `bon-nie-appetit`'s bug, chunk overlap and libc leak all measured 3/3. Two of the three classifications were **wrong** in the import-list reading: `sabotage`'s payoff is an environment/PATH hijack it performs on itself (no leak, no ASLR dependence), and `auth-or-out` is an indirect-call hijack over a stack-resident bump allocator, not a scanf/scalar bug — so `G-7c` and `G-8b` were merged into one cycle. All three exploits preserved under `benchmark/reference_exploits/` before `/tmp` could be cleaned. |
| 11 | 2026-09-27 | `I-17` | two claims from the RE cycle **checked and corrected.** `rocket_blaster_xxx`'s bundled loader is NOT the host's — same size, differs at byte 729, bundled libc `2.35-0ubuntu3.6` vs host `2.35-0ubuntu3.15` — so its recorded `SOLVED` stands and the doubt is closed rather than left open. And of the four 0-byte loaders, two belong to directories that are not scored targets at all. |
| 12 | 2026-09-27 | `G-7a` | **unblocked.** The RE cycle declared `bon-nie-appetit` out of reach pending acquisition of a real `ld-2.27.so`. Measured: snap `core18` ships one (`2.27-3ubuntu1.6+esm6`), and it loads the target's own bundled libc `2.27-3ubuntu1.5` — the target starts and reaches its menu. `__free_hook` is at `0x3ed8e8` in that libc. Also recorded: `__free_hook` is still an exported *symbol* in 2.35, so a grep-for-symbol capability test would wrongly pass — branch on the glibc release instead. |
| 13 | 2026-09-27 | `G-9` | new P0 filed: no executor can express "leak first, then finish in libc", which is the shape of all three remaining targets. Grounded at `heap_techniques.py:174/189` (refuses PIE) and `heap_and_bypass.py:209/308` (require a `win_addr` that none of these targets has). Filed as shared machinery, not a technique, because `G-7a`/`G-7c` need the same plumbing. |
| 15 | 2026-09-27 | `G-6` | **closed.** `1/5 → 5/5` positives on `benchmark/corpus_srop` (3 reps each), control `GATE_DECLINED` both runs, no false positives, and `sick_rop` unregressed *and faster* — 37 attempts/11.8 s → 23/7.1 s to the same offset and pivot. Confirmed at 5/5 through the real `htb_rescore.py` path with every solve attributed to the technique. Four hard-coded quantities became derived, each isolated by a variant that broke exactly one; a reversed wrapper argument order had previously made the gate **decline outright**, which a single-target corpus could never have surfaced. Independently re-verified by the orchestrator: corpus rebuilt from source alone, reference exploit 5 shells + control declined. |
| 16 | 2026-09-27 | `I-16` | the SROP cycle **independently reproduced** the echo-oracle hazard and found a better marker than the one I used. All six of its targets end `vuln` with `write(1, buf, rax)`, so all six reflect input, and its probe measured `reflected token=True, shell-marker=False` on every one — a token-only oracle would have credited SHELL_ACCESS on six unexploited processes *including the negative control*. Its marker, `echo SH$((6*7))OK` → `SH42OK`, is strictly better than `id`/`uid=`: pure POSIX arithmetic expansion needs no `PATH` and so survives `execve("/bin/sh", NULL, NULL)` with null envp, where `id` does not. Adopted centrally. |
| 17 | 2026-09-27 | repo hygiene | `tests/htb-targets/`, `solve_output/`, `report_output/` and `exploit.bin` were untracked **but not ignored**, so a single `git add -A` would have committed them — and the first ships the challenges' real flags. Now ignored. Surfaced by a category agent's note that `solve_output/` matched no rule it could find; the gap was wider than the one directory. |
| 14 | 2026-09-27 | `I-18` | `auth-or-out`'s recorded `TIMEOUT ×3 @300s` **reattributed**: not GAP-B search-budget indiscipline. All three targets spin their menu forever on EOF (238,243 / 125,900 / 109,995 redraws in 5 s) because their number readers cannot tell EOF from `0`. The process was alive and printing the whole time. |
| 18 | 2026-09-27 | `I-19` (new) | **closed, and it corrected one of my own claims.** The SROP cycle's `echo SH$((6*7))OK` → `SH42OK` marker is now a third probe in `verify_script`. The reason it matters: `id` is a separate binary, so the `uid=` probe cannot answer in the shell an SROP or syscall chain actually produces — `execve("/bin/sh", NULL, NULL)`, null envp, no `PATH`. **Measured**: given all four probes, `env -i PATH= /bin/sh` answers the `id` probe with `id: not found`. But the ranking I had written into the queue ("strictly better than `id`/`uid=`") overstated it against the *existing* oracle: the `_STRICT` quote-removal probe is also builtin-only and already survived a null-envp shell. The arithmetic probe's real value is a different axis — `_STRICT` depends on quote removal, so a reader that strips `"` defeats it while leaving this one intact. Comment and changelog now say what was observed. `tests/test_shell_proof_markers.py` (4 tests) red-proofs it on a real shell, on a `PATH`-less shell, and against a pure reflection — the last asserting the probe text *is* present before asserting the answer is not, so the proof cannot go vacuous. Landed `3b054d4`. |
| 19 | 2026-09-27 | `G-10` (new) | **closed.** `scanf_scalar_overwrite`: an unbounded `scanf("%s")`/`strtoull` value used as an unchecked subscript or as a length/bound. 6/6 positives reach a shell on `benchmark/corpus_scanf`, control declined — and the control's refusal is **distinguished**: handed the PIE base for free it still fails, so the bounds check is what stops it, not a missing leak. 3 RED-checks fire (wrong-but-present address, pad off by 8, one canary byte flipped). Verified here rather than relayed: every binary deleted and the family rebuilt from committed source alone before re-running. Two platform facts recorded in `corpus_scanf.yaml`: `-fstack-protector` hoists arrays above scalars, so only **struct members** — whose order C guarantees — are reachable from a `%s` write. Baseline stated honestly as "0 of the 3 measured", not "0 of 7". Landed `c04c8ff`. |
| 20 | 2026-09-27 | `G-8a` | **closed — second non-memory-safety category.** `weak_prng_replay`: 6/6 positives reproduce the per-run secret across five seed sources (`time`, `getpid`, *unseeded* implicit-1, hard-coded `0xc0ffee`, and a seed **recovered** from three published draws), plus `rand_r` with a hex encoding so the encoding is derived not assumed. The control's refusal is a measured exhaustion, not an early exit: **64/64 comparisons on a live process in each of 3 reps** over a full 64-second clock window. The family also proves the *distinguishing property* — the anchor's secret is a reproducible function of the clock (same token accepted by two independent processes in the same second); the control's is not a function of anything observable. Gate specificity **measured by the orchestrator across 68 binaries** (every `corpus*/` target + all 7 HTB targets): claims exactly its 6 positives, declines the other 62. Landed `fc8473e`. |
| 21 | 2026-09-27 | `I-20` (new) | **my own harness bug, recorded because it produced a plausible-looking false zero.** A first attempt to score `corpus_scanf` through `run_bench.py --corpus-root` returned 15 VOID: `--corpus-root` moves the corpus but **not the manifest**, so it looked for R1's fifteen slugs. The harness fail-closed correctly and withheld the rate — that is the design working. The replacement, `benchmark/measure_family.py`, then reported `0/6` in 0.0s per target with no stdout: it set `cwd` to the target directory (needed for a relative `PT_INTERP`) without putting the repo root on `PYTHONPATH`, so `supwngo` never imported. **A total failure to launch is indistinguishable from a pipeline that solves nothing** unless stderr is surfaced, so the harness now reports `rc=` and the stderr tail on that path. Both notes are in the file's docstring. |
| 22 | 2026-09-27 | `I-21` (new) | **closed, and it was worth more than the category that surfaced it.** The PRNG cycle reported `prng_10` INCONCLUSIVE at a 150 s budget while four siblings solved in 10-13 s. Cause was not the executor: `subprocess_injection`, `weak_prng_replay` and `scanf_scalar_overwrite` were all **registered but absent from `orchestrator.FIRST_TECHNIQUES`**, so the pipeline spent the budget on broad sweeps before reaching them. Added all three to the front, where the list's own stated rule already put them (narrow + cheap gates first). **Measured before/after on the same target at the same 150 s budget: INCONCLUSIVE → `FLAG_CAPTURED` by `weak_prng_replay`**, with exactly three cheap `SKIPPED` gates ahead of it. The general lesson, worth keeping: a capability that exists but is never reached inside the budget is indistinguishable from one that does not exist — so registering an executor is only half of adding a technique. Note this also means my earlier "5/5 in 4.6 s" figure for `subprocess_injection` was an **executor-direct** measurement, not an end-to-end one; through the real CLI it is 5/5 at 11.6-14.2 s, all `verified=SHELL_ACCESS`. |
| 23 | 2026-09-27 | `I-20` | `benchmark/measure_family.py` validated the only way a harness can be: **reproduced an independently-known result** (the inject family, 5/5 positives by `subprocess_injection`, control declined). Two of its own field bugs were caught by doing that rather than by review — there is no `verification_level` key (it is `verified`), and `legacy_fallback` is a **string** (`not_reached`/`disabled`/`skipped_vector`/`ran`) so a truthiness test warns on the *healthy* case. Only `"ran"` means the legacy engine executed. Both are now documented at the point of use in the file. |
| 24 | 2026-09-27 | `G-8a`, `G-10` | **both families re-measured END-TO-END by the orchestrator through the real `autopwn` CLI, after the ordering fix.** `corpus_prng`: 6/6 `FLAG_CAPTURED` by `weak_prng_replay`, 2.3-5.5s each, control declined. `corpus_scanf`: 6/6 `SHELL_ACCESS` by `scanf_scalar_overwrite`, ~101s each, control declined at 245s (it spends the budget rather than exiting early, which is the right shape for a bounds-checked control). `corpus_inject` re-measured on the same footing: 5/5 `SHELL_ACCESS`, 11.6-14.2s. These supersede every per-family number produced before `9ec2463`, because those were measured against an attempt ordering that no longer exists. |
| 25 | 2026-09-27 | `T-3` | **the teaching half opened.** Three categories were solved but not taught: `supwngo/exploit/walkthrough/families/` had 7 families and none for the new work. Added `subprocess_injection`, which **reuses the executor's own derivation helpers** rather than re-implementing them -- a walkthrough with a private parser can teach a payload the solver would never send, and the reader would learn a fiction adjacent to the truth. Measured: the family wins on all 3 injectable targets at score 0.98 (the highest in the tree, because with its chain complete the exploit needs no leak, no offset and no gadget) and **correctly declines the `execv`-argv control**, where `triage` takes over. Its `%s`-ladder head matches the executor's winning payload on every target. Four model guards fired during the build and each one was a real defect in my draft, not friction: a `MEASURED` fact with no `Evidence`, a hyphenated step id, a fact declared in both the constants table and a step's `produces`, and `OFFSET` carried in from `base_constants` while the family has no offset step -- which it should not, **because there is no offset: nothing here is overflowed**. The fix is the general rule (drop any base constant whose resolving step the family does not provide), not a special case. |
| 26 | 2026-09-28 | `T-3`, `I-22` (new) | **the teaching half advanced to three families, and the red-proof earned its keep inside my own code.** Landed the PRNG walkthrough (6 templates + `control_resists.py`, verified here: 4 templates re-run in the scorer's staging layout all exit 0 with a flag from the target's own success path; the control contrast holds at anchor-solved-on-candidate-1 vs control 64/64 rejections, and 2/2 vs 0/2 on the same-second token) and finished the scanf walkthrough from a partial state. **`I-22`:** all three scanf templates ended in `p.interactive(); return True`, which under a non-tty run returns immediately on EOF -- so they exited **0 having demonstrated nothing**, the worst outcome available to a teaching artifact because it looks like a pass. Replaced with a `prove_shell()` that requires `SH42OK` before claiming anything, then reads the flag *inside the obtained shell* (not laundering: the script never opens the file, and a failed overwrite leaves no shell to run it in). **My first version of that helper could not fail**: it wrapped `recvuntil` in try/except and treated no-exception as success, but pwntools' `recvuntil(timeout=)` RETURNS `b""` on timeout rather than raising -- so a mutation to `show_plain` (real symbol, wrong function) still printed "shell PROVEN". Caught only because I ran the wrong-but-present mutation instead of trusting a green result. Now measured both ways on all three: mutated rc=1 with zero "shell PROVEN"; unmutated rc=0, proven, flag printed. |
| 27 | 2026-09-28 | agents | **all five remaining cycles were killed mid-flight by the session rate limit** (resets 00:10 EDT). Two (`scanf`, `prng`) had already delivered and are landed. Three did not finish and their last-known states are recorded here rather than lost: `G-7a` bon -- "the key-read bag write clobbers C's size field, so C cannot be freed; adding a restore cycle"; `G-7c`+`G-8b` objptr -- corpus healthy, was making decline reasons precise so a non-solve names the missing capability; `G-7b` envpath -- **baseline in: 0/4 positives, control unsolved**, was starting the final measurement. Their uncommitted trees (`corpus_envpath/`, `corpus_objptr/`, `corpus_bon/`, `corpus_heap_variants/`, three reference exploits, two executors, and modifications to `heap_and_bypass.py`/`heap_techniques.py`) are left in place untouched so the work is resumable rather than re-done. |
| 28 | 2026-09-28 | `T-3` | **the PRNG walkthrough family landed; `supwngo explain` now teaches both new categories instead of falling to `triage`.** Verified across all 7 `corpus_prng` targets: the 6 positives select `family=weak_prng` at score 0.94 with the seed story **derived per target** (`time`, `getpid`, `unseeded`, `fixed` -- 4 distinct stories across 6 targets, so the narrative is a function of the binary and not a template), and `prng_90_neg_csprng` declines to `triage`. Walkthrough suites: **396 passed**, identical to the pre-change baseline -- so the new family steals no target from an existing route and the score-uniqueness invariant still holds (it must: `registry._families()` selects by `max()`, which keeps the FIRST maximum, so a tie would silently reassign a target by list position). **Five model guards fired in sequence on one fact, `TRY_BUDGET`, and the last one taught the real rule:** an UNKNOWN fact must state `plausible` AND `resolved_by`; it may not be `produces`d by the step it names as its resolver; it may not carry `runtime=True` (reserved for a leaked per-process address, which cannot be a module constant -- a try budget is a fixed program property observed once, the same shape as `OFFSET`); and finally **it may not be `consume`d either**, because `consumes` asserts an earlier step or constant supplies the value *as known*. That last rule is the one worth keeping: a declared dependency on a value nobody has obtained yet is exactly how a walkthrough ends up instructing the reader to use a number that was never measured. Also recorded a changelog gap honestly: `d51fff1`, `4d72e80` and `fd27baf` all shipped the teaching half with **no `CHANGELOG.md` entry**; one bullet now covers all of it. |
