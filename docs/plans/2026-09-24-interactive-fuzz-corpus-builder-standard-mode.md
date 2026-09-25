# Interactive fuzzer corpus builder (`supwngo fuzz-corpus`) — standard mode

**Date:** 2026-09-24
**Status:** **r4** — implementable. r3 was **NOT APPROVED** by independent
  review (7 High, 6 Medium, 2 Low); every finding is answered below and the
  mapping is in the Alignment log. Three findings changed the *design* rather
  than the prose: the success gate was unsatisfiable (H1), the escaper
  contradicted its own test (M3/H4.6), and seed sizing was unbounded (M6).
**Branch:** `feat/interactive-fuzz-corpus-builder-r3-20260924` (base `ef40e93`)
**Supersedes:** `docs/plans/2026-09-24-interactive-fuzz-corpus-builder.md`
  (r2, `abc7712`)
**Reviews:**
  `docs/plans/reviews/2026-09-24-interactive-fuzz-corpus-builder-review-r1.md`,
  `docs/plans/reviews/2026-09-24-interactive-fuzz-corpus-builder-review-r3.md`

## Scope

**Standard (interactive) mode only. `--auto` is not implemented.** `--auto`
consumes the standardized context schema, built concurrently on
`feat/context-schema-v4-20260924` and unfinished. Its seam is specified in
"The `--auto` seam", with an explicit ask-list for that branch and an honest
enumeration of the work `--auto` still needs beyond the adapter. Nothing here
stubs `--auto` into something that looks functional.

---

## What changed in the tree, and what it breaks in r2

r2's citations were read at `0997da5`; re-verified at `ef40e93`. **40 of 43
checkable claims still hold** (audit in "Verification log"). The three that do
not are each load-bearing, and two let r4 *delete* machinery r2 invented.

### D1. The walkthrough engine merged and already owns the provenance vocabulary

r2 invented five values (`measured > derived > asserted > assumed > unknown`)
"owned by `corpus.json` itself", citing `walkthrough/model.py` — a file the r1
reviewer noted was **absent** (L2), so r2 withdrew the citation.

It now exists. `supwngo/exploit/walkthrough/model.py:130-150`:

```python
class Confidence(enum.Enum):
    MEASURED = "measured"   # Observed directly from this binary.
    DERIVED  = "derived"    # Computed from other facts by a rule.
    ASSUMED  = "assumed"    # Convention-based default, not confirmed here.
    UNKNOWN  = "unknown"    # Not known.
```

Four values — **no `ASSERTED`** (zero matches in the package). Alongside it,
`Evidence` (`model.py:155-178`: `method`, `command`, `detail`, `.describe()`)
and `Fact`, whose field comment states the principle r1's reviewer demanded
under H3, already enforced in code:

> `#: Defaults to the *weakest* non-unknown level on purpose. If the default
> were MEASURED, a family that simply forgot the keyword would get the most
> trustworthy label for free -- the lazy path must not be the one that tells
> the reader "trust this".`

and `Fact.__post_init__` (`model.py:222-286`) **raises** when a
`MEASURED`/`DERIVED` fact carries no `Evidence`.

**r4 decision: reuse `Confidence` and `Evidence`.** Consequences:

- `asserted` is not introduced. An operator assertion is recorded as
  **`ASSUMED`** confidence with `Evidence(method="operator assertion", …)`.
  **The distinction is not lost** (review M1): confidence answers "how much
  trust", `Evidence.method` answers "where from", and both are serialized per
  evidence component in `corpus.json`. The manifest can therefore be filtered
  for operator-supplied values without the vocabulary carrying a fifth rank.
  The mapping is conservative (a downgrade) and disclosed.
- It repairs a latent r2 bug. The schema branch models provenance as a
  *partial* order (`supwngo/schema/resolve.py:782-787`: `measured>derived`,
  `derived>assumed`, `asserted>assumed`, `assumed>unknown`), with
  `compare_provenance()` returning `Ordering.INCOMPARABLE` for `asserted` vs
  `measured` and vs `derived`. r2's `min(e.provenance for e in evidence)`
  presumes totality and **is undefined as soon as an operator assertion meets
  a derived component** — exactly what `--input-channel` produces. Dropping
  `asserted` leaves a genuine total chain.
- **Scoped honestly** (review M1): the four-value rank is a **local policy of
  this feature**, not a property of the enum. `Confidence` is a plain
  `enum.Enum` with string values and no comparison operators; the ordering
  lives in `_CONFIDENCE_RANK` in `corpus.py` and is tested for exhaustiveness.
- **Accepted coupling** (review M1): `supwngo/fuzzing` importing from
  `supwngo/exploit/walkthrough` is new; `facts.py:32` is precedent for the
  import *spelling*, not for crossing that package boundary. The alternative —
  move `Confidence`/`Evidence` to a neutral module — is the better long-term
  shape but is a **cross-cutting refactor of a just-merged engine while many
  worktrees are live**, so r4 takes the coupling deliberately and records it as
  risk 8 with the neutral-module move named as the follow-up.

### D2. There is no TTY-refusal rule in this repo, so `--script` is unnecessary

r2 inherited from r1 a rule that `sys.stdin.isatty()` false must refuse before
the first prompt, then added `--script PATH|-` plus an `AnswerSource`
indirection so tests could drive the menu around that refusal. At `ef40e93`:

- **`isatty` appears nowhere in the repository.** Zero hits in any `.py`.
- **No command refuses on a non-TTY.** The one interactive flow,
  `solve --interactive` → `_guided_fallback()` (`cli.py:2806-2869`), gates on a
  *flag*. Its `UsageError` at `cli.py:2920` says `"--interactive requires a
  terminal"` and nothing verifies one.
- Its existing test drives `click.prompt` with **piped stdin**
  (`tests/test_solve_command.py:242`, `input_text=f"1\n{offset}\n"`).

**r4 decision: no isatty check; `--script` deleted.** The menu reads
`click.prompt` as `_guided_fallback` does; tests drive it with
`CliRunner(input=…)`. This removes a flag, a parser, a protocol, and r2's pty
test that existed only to guard `--script` drifting from the real path.

**Non-TTY behaviour is defined, not left to chance** (review M2, accepted):

| Condition | Behaviour |
|---|---|
| stdin at EOF when a prompt is issued | caught once; `click.Abort` is converted to "input ended before the corpus was written; nothing was saved", non-zero, **no output directory created** |
| stdin is a pipe with valid menu numbers | runs and can publish — this is the tested path |
| stdin is an inherited pipe that never closes | **blocks.** Known limitation, shared verbatim with `solve --interactive`; not introduced here |

**Documented disagreement with the review:** M2 proposes `--allow-non-tty` as
an opt-in preserving the same code path. Declined, because it reintroduces
exactly what D2 deletes — a flag whose only function is to satisfy a guard this
repo does not have, and which every test and every piped invocation would have
to pass. The open-pipe hang is a real residual risk and is recorded as risk 9
instead of being traded for a flag that does not fix it (an `--allow-non-tty`
run on an open pipe hangs identically).

### D3. `DetailedProtections.to_dict()` changed shape (`ef40e93` itself)

`supwngo/analysis/protections.py:67-104` now returns **16** keys (the inherited
six plus `full_relro`, `partial_relro`, `stack_protector`, `fortify_level`,
`pie_type`, `stripped`, `static`, `has_debug_info`, `libc_version`,
`uses_tcache`), and `protections.py:25-35` declares `_UNMEASURED = frozenset({
stack_clash_protection, safe_stack, cfi, shadow_stack, rpath, runpath})` —
fields deliberately not serialized because they are never measured.

r2 did not depend on this. It matters to r4 twice:

1. **`static` and `stripped` are now readable**, and they decide whether this
   feature has any evidence at all (statically linked + stripped is near-total
   loss). The header reports them *before* the table, so the operator learns
   why the table is empty instead of inferring it.
2. `_UNMEASURED` is the in-tree precedent for r4's central rule: **a field that
   was not measured is absent, not zero.**

`Binary.checksec()` and `StaticAnalyzer.analyze()["protections"]` still yield
six keys; the 16-key view exists only on the `DetailedProtections` path.

---

## Method: four forks, weighed

Each fork states the options, the tradeoff, the choice, and **what would flip
it**. r3's version was found to strawman three of the four rejected options
(review H5); the alternatives below are the strongest form of each.

### Fork 1 — session model

**Option A — guided, backtrackable state machine.** An ordered sequence of
named stages (target → candidates → strategies → measure → prune → write) with
explicit back/forward transitions and per-stage validation. *Not* a one-way
wizard: it permits revisiting a stage, and it can cache a stage's result so
re-entering is cheap.

**Option B — flat numbered menu loop (CHOSEN).** One menu re-printed after
every action; any action, any order; loop until write-or-abort.

| | A: backtrackable stages | B: flat menu |
|---|---|---|
| Teaches the intended order | **yes** — the order is the UI | no |
| Illegal transitions preventable by construction | **yes** | only by per-action guards |
| Test surface | stage graph, enumerable | any interleaving |
| "See the effect of each step" | yes, via backtracking | yes, natively |
| State needed | current stage + per-stage cache + transition table | one corpus object |
| Cost of adding an action | a stage + its edges | one dict entry |

**Chosen: B**, and the margin is narrower than r3 implied. A is genuinely
better at *teaching* the workflow and at making illegal transitions
unrepresentable. It loses on two specific grounds:

1. **There is no natural stage order to teach.** "Add seeds for candidate 3,
   measure, add seeds for candidate 1, measure again, prune" is not a detour
   from the intended path — it *is* the intended path, because each
   measurement informs the next choice. A stage graph whose every stage has an
   edge to every other stage is a menu with a transition table attached.
2. Precedent: `_guided_fallback` (`cli.py:2806-2869`) prints a numbered list
   and reads one `click.prompt(type=click.IntRange(0, n), default=0)`. B is the
   same shape; A would be the first state machine in this CLI.

**What would flip it to A:** if actions acquire real ordering constraints —
concretely, if a future action's precondition cannot be checked cheaply at
dispatch time (e.g. a harness-generation step that is only valid after
measurement and whose validity check costs a subprocess). Guard-per-action
scales badly once guards are expensive; a transition table then pays for
itself. Expensive *measurement* alone does **not** flip this fork (r3 claimed
it did; the review is right that the answer to expensive measurement is
caching and confirmation, not a one-way path).

**Option C, rejected: a full-screen TUI** (`rich.live`, curses). The repo has
no `rich.live`, no `rich.progress`, no full-screen UI; progress is
`console.status()` and one `end="\r"` print. Full-screen redraw also breaks
under `CliRunner`. Rejected on precedent and testability.

### Fork 2 — corpus state during the session

**Option A — in-memory, one atomic publish at the end (CHOSEN).**
**Option B — persist to the final output directory after every mutation.**
**Option C — journal to a private staging directory per mutation, then publish
atomically.** (r3 mentioned this only inside a flip condition; the review
correctly requires it as a first-class option.)

| | A: in-memory | B: persist in place | C: private journal + publish |
|---|---|---|---|
| Crash mid-session | **work lost** | survives | **survives** |
| Partial state visible at the output path | never | **always, during the session** | never |
| Can express "if nothing ran, create no `seeds/`" | **yes** | no | **yes** |
| Publish atomicity | yes | n/a | yes |
| Moving parts | one writer | writer + reconciler | writer + journal + replay-on-resume + staging GC |

**Chosen: A.** C is the technically superior design and is rejected only on
cost-for-benefit *at this scope*: it needs a journal format, a resume path, a
staging-directory lifecycle, and its own tests, to protect a session whose
total compute is seconds (replay only; no coverage — Fork 3). B is rejected
outright and for a feature-specific reason: `AFLFuzzer.setup()` backfills a
single `b"A" * 8` seed into an empty input directory (`afl.py:143-147`), so a
partially-built corpus that someone points `fuzz -i` at looks finished. B
guarantees that window on every run.

The cost of A is accepted and stated: **a crash or `^C` mid-session loses the
session.** Mitigation is proportionate, not architectural — the write action is
the menu's *default*, so the lowest-effort keystroke saves.

**What would flip it to C:** measurement becoming expensive. Once a measure
pass costs minutes (coverage via `afl-showmap` or angr emulation), the
*measurements* specifically are worth journaling — keyed by seed sha256, so the
journal is a cache and not a corpus. That is a narrower change than "adopt C
wholesale" and is the reason C is documented now rather than discovered later.

### Fork 3 — where seed bytes come from

**Option A — derive bytes from static analysis output; use execution as a
filter and witness (CHOSEN).**
**Option B — derive bytes from execution: a stdin-only dynamic generator that
observes the target's reads and grows inputs from what it consumed.**

**Chosen: A**, on two grounds. The request is static-evidence-shaped —
"picking functions flagged in earlier analysis" names detector output as the
input. And B's reach is narrow *here*: supwngo cannot drive a file-argument
target at all (`_build_command` never emits `@@`, `afl.py:219-220`) nor a
socket target (no `AFL_PRELOAD`, no desock shim), so B would only ever cover
stdin.

Execution's role is therefore **filter and witness, not generator**:
`measure_replay()` shows a seed spawns and terminates, and catches crashes
found at corpus-build time — which is a finding, not just a seed.

**What would flip it to B:** r3's flip was "an `strace` first-read
observation", and the review is right that this is insufficient — a requested
read length is neither the bytes nor the amount actually consumed. The flip
condition is therefore stronger and stated as a demonstration: **B becomes
correct when a stdin-only probe can show, for a compiled fixture, (i) which fd
the first read used, (ii) how many bytes were *returned* to the target, and
(iii) that a changed input changes the observed consumption** — i.e. an
observable input-consumption signal, not a syscall argument.
`DynamicAnalyzer.trace_strace()` (`dynamic.py:197-241`) plus `strace` on this
host is enough to attempt that demonstration; until it is demonstrated, B's
seeds would carry a `MEASURED` label its evidence does not support, which is
the very failure this plan exists to avoid.

### Fork 4 — how much interactive shares with `--auto`

**Option A — one `build()` with `interactive: bool`.** Rejected: prompts
become branches inside shared code, and the modes' failure semantics differ
(interactive may ask; auto must refuse), so the flag multiplies through the
call graph.

**Option B — two independent implementations.** Rejected: duplicates the
strategy set, dedup, provenance composition and the writer — everything that is
actually hard, and where divergence would be silent.

**Option C — shared orchestration engine plus pluggable policy/input
adapters.** (Raised by the review as the honest strong alternative to compare
against, in place of r3's strawman A.) One engine drives
discover → select → generate → measure → retain → publish; an adapter supplies
selection decisions, either by prompting or from evidence.

**Option D — three layers sharing the library and nothing else (CHOSEN).**

```
corpus.py          pure library. No prompts, no click, no printing.
                   Candidates, strategies, Seed, Corpus, provenance, writers.
                   <- the seam
corpus_replay.py   measure_replay(). Owns its subprocess.
corpus_session.py  the menu loop. The ONLY module that prompts.
cli.py             ~60 appended lines: decorators, validation, one call.

corpus_context.py  NOT IN THIS PASS. --auto's evidence adapter.
```

**Chosen: D over C** on a single concrete ground: C's engine must own the
retention policy, and the two modes' retention policies are genuinely
different, not parameterised. Interactive retention is "show the operator the
measurement and let them prune"; auto retention is "apply a fixed rule". An
engine that abstracts over both ends up with a policy object per decision
point — which is C's adapter interface growing until it is the library API of
D, reached by a longer route. D's seam is the library because that is the part
both modes provably share.

**What would flip it to C:** if `--auto` needs to make the *same* decisions in
the *same order* as the operator — i.e. if auto's retention becomes
"measure, then re-select" rather than a fixed rule. Note r3's flip condition
here was **wrong and self-contradictory**, as the review found (H5): it claimed
an unresolved fact would make auto prompt, but an unresolved fact must make
`--auto` **refuse** — `--auto` is defined as non-interactive, and
`resolve()` raising `FactUnresolved` is a refusal, not a question. The
corrected flip is about decision *sequencing*, not about prompting.

---

## The `--auto` seam, and what the schema branch must provide

`--auto` is registered and **refuses**, with a message that names a durable
capability rather than a branch (review L2):

```
$ supwngo fuzz-corpus ./binary_01 --auto -o ./corpus
Error: --auto is not available in this build.
  It builds the corpus from a context document, and context-document support
  is not implemented yet -- nothing in this build can read one.
  Use interactive mode meanwhile:  supwngo fuzz-corpus ./binary_01 -o ./corpus
```

Its test asserts non-zero exit **and that no output directory was created**.
`--help` labels it `(not available in this build)`, and the CHANGELOG entry
says so too, so the flag cannot be mistaken for working (review H6).

### What `--auto` still needs — honestly enumerated

r3 claimed "one new file, ~60 lines". The review is right that this is not
credible (H6). The real list:

| Work | Where | Why it is not just the adapter |
|---|---|---|
| `read_corpus_evidence` / `write_corpus_result` | `corpus_context.py` **new** | the only file importing `supwngo.schema` |
| `CorpusEvidence` — every field fully defined, carrying `(value, Confidence, Evidence)` and **not** just `(value, Confidence)`, so origin and detail survive the boundary | `corpus_context.py` | review H6/M1 |
| **A1 `crash-replay`** strategy | `corpus.py` | a new strategy, its evidence components, filenames and tests. Not adapter work |
| **A3 `offset-lengths`** strategy | `corpus.py` | same |
| The "evidence-backed only" threshold, as a named constant with a stated rule | `corpus.py` | currently an English phrase; auto needs it executable |
| Flag wiring, `--context` / `--context-out`, refusal paths | `cli.py` | |
| Scope/context on result writes | `corpus_context.py` | `Candidate.applies_to` is required by the schema |
| Tests for all of the above | `tests/` | |

So: **one new file plus two new strategies plus CLI wiring plus tests.** The
*seam* is one file; the *feature* is not.

### Requirements for `feat/context-schema-v4-20260924`

Read at `670e7f7`. The resolver is real code (`supwngo/schema/resolve.py`,
1319 lines): `FactStore`, `Candidate`, `resolve(store, key, ctx)`, and a closed
`FACT_KEYS` registry. `spec_for()` **raises `SchemaError` for any unknown key**
(`resolve.py:1033`), so this feature cannot invent key spellings — every key
must be registered there.

| `--auto` needs | Status on that branch | Ask |
|---|---|---|
| Overflow length for length-family seeds (A3) | **`stack.return_offset` exists** (`int`, `Scope.BUILD`, `depends_on="binary_bytes"`) | nothing — ready |
| Crash-input **bytes** — the only `MEASURED` seed source (A1) | **missing.** No key, and every registered `value_type` is `int`/`bool`/`str`; there is no `bytes` fact anywhere | (1) a registered key or prefix for crash witnesses, and (2) **a declared byte encoding**. r1/r2 assumed a `b64:` prefix; that spelling no longer appears on the branch. If bytes are out of scope as a fact value, say so and name the artifact path instead, so the adapter reads it without guessing |
| Input channel (stdin / file / socket) | **missing** | a registered key, or an explicit "out of scope". Standard mode survives without it — the channel stays `UNKNOWN` — but `--auto` cannot raise it above `UNKNOWN` without one |
| The dangerous-import set and input sources | missing, **and not wanted** | **nothing. Please do not add keys for these.** They are recomputed from `binary.plt` in ~20 lines and do not belong in a document |
| A published mapping for `Provenance.ASSERTED` | exists in `schema.Provenance`, absent from `walkthrough.Confidence` | confirm the intended mapping. This feature maps `ASSERTED → Confidence.ASSUMED` (a downgrade, fail-closed) and preserves the distinction in `Evidence.method`. `resolve.py:62-65` says "the plan carries the mapping table" — publishing that table is the ask |

Structural note for that branch's author, recorded so it is not later mistaken
for a gap: `resolve()` raises rather than returning a default
(`resolve.py:1028-1032`) across five declared refusals, so
`read_corpus_evidence()` will catch `FactUnavailable`, `FactUnresolved`,
`FactStale`, `PinInapplicable` and `SchemaError` **individually** and map each
to an absent-or-degraded field. That shape is correct and needs no change.

---

## Standard mode: behaviour

### Candidate discovery — dangerous *imports*, with the reason each was flagged

Terminology is deliberate (review M5): these are **dangerous imported
symbols**, not confirmed vulnerable call sites. Nothing here establishes
reachability or user control, and the table header, the manifest key
(`dangerous_imports`) and the printed caveat all say so. Presenting a PLT scan
as "the vulnerable functions" is the error this plan is structured to avoid.

Read `binary.plt` (`Dict[str, int]`, `core/binary.py:122`) directly. **Do not
call `StaticAnalyzer.analyze()`.** Re-verified at `ef40e93`: `_find_callers()`
cannot work — its first loop's body is literally `pass` (`static.py:252-255`)
and its second binds a `Symbol` object as `func_addr` and hands it to
`cfg.kb.functions.get()` where an address is required (`static.py:258-260`),
failure swallowed at `:266-267`. It always returns `[]`, the fallback at
`:218-227` always fires, and every `caller` is `"unknown"`. It is also called
once per dangerous import, each call building a fresh `CFGFast()`
(`static.py:206`, `:246`), plus another in `_analyze_functions` — seven CFGs
for a six-import binary, to produce no call sites.

`normalize_plt_name()` strips `__isoc99_` and `__…_chk` before any dict lookup.
Still necessary: neither `DANGEROUS_FUNCTIONS` (`static.py:16-62`) nor
`INPUT_SOURCES` (`static.py:65-77`) contains any `isoc99` or `_chk` spelling,
so on a normally-compiled glibc binary supwngo reports **no `scanf` dangerous
call and no `scanf` input source at all**.

Each candidate carries the reason it was flagged — a field, not a rendering
detail:

- the risk text from `DANGEROUS_FUNCTIONS`;
- a severity, from the same sets `find_vulnerability_sinks()` uses
  (`static.py:455-456`). That function is dead code — `static.py:446` is its
  only occurrence, no callers, no tests — so r4 lifts the two sets into named
  module constants rather than calling it;
- the original PLT spelling when normalisation changed it, so
  `__isoc99_scanf → scanf` is visible rather than silently rewritten;
- the `INPUT_SOURCES` type, if any;
- which strategies apply, and why each does or does not.

Reported rather than absorbed: `DANGEROUS_FUNCTIONS` has 34 literal entries but
**32 unique keys** — `sprintf` at both `static.py:21` and `:27`, `vsprintf` at
`:22` and `:31`, so the later format-string text wins and both lose their
overflow text. `INPUT_SOURCES` also lists `"argv"` (`static.py:76`), which can
never match a PLT entry. Separate `fix/` commits own the dicts.

### Provenance is composed; a strategy cannot assert its own

Each seed declares evidence components, each with its own `Confidence`. The
seed's provenance is the **weakest** component, computed in
`Seed.__post_init__`; declaring a level the evidence does not support
**raises** — mirroring `Fact.__post_init__` (`model.py:222-286`).

```python
BYTES_FROM_BINARY = ("bytes read from the target",       MEASURED)
IMPORT_PRESENT    = ("symbol present in the PLT",        MEASURED)
INPUT_RELEVANCE   = ("these bytes are an input token",   ASSUMED)   # see H1
FORMAT_FOR_SCANF  = ("format belongs to this scanf",     ASSUMED)
CHOICE_SEQUENCE   = ("this order of menu choices",       ASSUMED)
GENERIC_PRIOR     = ("common-case guess",                ASSUMED)
OPERATOR_ASSERTED = ("operator assertion",               ASSUMED)
SINK_CONTROLLED   = ("sink reached by user input",       UNKNOWN)   # never established
```

**`INPUT_RELEVANCE` is new in r4 and it is the review's most important
finding** (H1). r3 labelled A4 seeds `MEASURED` "for the bytes". But a *seed*
does not claim "these bytes exist in the target"; it claims "these bytes are a
useful input to it". The first is measured, the second never is. Conflating
them is precisely the r1-H3 error recurring in a new place, and it is why every
A4/A5 **seed** is now `ASSUMED`.

The distinction survives where it is genuinely true: a **dictionary token**
*does* only claim "these bytes appear in the target", so `dict/tokens.dict`
entries remain evidenced by `BYTES_FROM_BINARY` alone. Seeds and tokens are
different claims and now carry different provenance.

**Deduplication is deterministic and non-destructive** (review H1): identical
bytes are stored once; the surviving seed records every strategy that produced
it in `also_produced_by[]`, and its provenance is the **strongest** of the
duplicates — two independent derivations of the same bytes is more evidence,
not less. Strategies run in a fixed registry order so the result cannot depend
on iteration order, and a test asserts that reversing the registry produces a
byte-identical manifest.

### Strategies in this pass

| | Strategy | Seed provenance | Evidence, and why that level |
|---|---|---|---|
| A2 | `scanf-width` | `ASSUMED` | `BYTES_FROM_BINARY` + `IMPORT_PRESENT` + `FORMAT_FOR_SCANF`. Nothing ties a `"%31s"` in `.rodata` to the `scanf` import, and `31` is a maximum *field width*, not a buffer capacity. Emits exactly `width`, `width+1`, `width*2`. Parsed with `FORMAT_PATTERN` (`strings.py:94-102`) over `Binary.strings()` directly, because `StringAnalyzer` parses `width` (`strings.py:294`) then **omits** it from `details["specifiers"]` (`strings.py:330-346`) |
| A4 | `binary-strings` | `ASSUMED` (seeds) / `MEASURED` (dictionary tokens) | `BYTES_FROM_BINARY` + `INPUT_RELEVANCE` for seeds; `BYTES_FROM_BINARY` alone for tokens. Uses `Binary.strings()` (`core/binary.py:428-452`) — pure Python, no external `strings(1)`. **String *values* only, never addresses**: that function returns *file offsets* (`binary.py:450`), which both `_get_section_for_addr` and `StringAnalyzer._get_section` wrongly compare against section *virtual* addresses |
| A5 | `menu-token` | `ASSUMED` | `BYTES_FROM_BINARY` + `IMPORT_PRESENT` + `INPUT_RELEVANCE`; sequences add `CHOICE_SEQUENCE`. Nothing connects a token to a menu parser, so single tokens are no longer `DERIVED` (r3 had this wrong — review H1). Sequences capped at length 3 |
| A6 | `fmt-trigger` | `UNKNOWN` | `IMPORT_PRESENT` + `SINK_CONTROLLED`. **No format-literal gate** — re-verified that `benchmark/corpus/05_fmtstr_arbread/fmtstr_arbread.c:37` is `printf(name)` with no `"%`-literal in the file, so such a gate is *anti-correlated* with its own bug class. Generic payloads, labelled generic |
| C2 | `generic-boundary` | `ASSUMED` | `GENERIC_PRIOR`. **Off** unless `--include-generic` |

**Not in this pass**, each with a named reason:

- **A1 `crash-replay`** (`MEASURED`, the strongest available) needs crash bytes,
  which only a context document supplies. First thing `--auto` adds.
- **A3 `offset-lengths`** needs `stack.return_offset`, which *exists* on the
  schema branch — so A3 is the second thing `--auto` adds. Adding an
  `--offset` flag now would put a third spelling of the same fact in the CLI.
- **B1 `symbolic-reach`**: `path_finder.py:144` still raises `AttributeError`
  on every call (`self.binary.symbols.get(func_name, {}).address` — `{}` has no
  `.address`), and `concretize_state` returns `b""` on any exception while
  reading a private `_stored_solver._constraints`.
- **B2 `grammar`**: removed in r2 after the reviewer executed the shipped HTTP
  grammar and got `b'request_0request_1…'`. Still removed; no flag.
- **C1 `cmplog-operands`** would be strongest of all and cannot work:
  `extract_from_execution` looks for `/tmp/cmplog_{os.getpid()}`
  (`cmplog.py:289`) — the *Python* process's pid, a path nothing writes.
- **Coverage** (`--coverage`) — see "Measurement".
- **`strace` input-channel tracing** — Fork 3's flip; highest-value follow-up.

### Size bounds (review M6)

`--max-seeds` caps the seed *count* and nothing else, which leaves
`width * 2` from a `"%999999999s"` literal free to allocate gigabytes. Named,
enforced constants in `corpus.py`, each with a test at the boundary:

| Bound | Value | Rationale |
|---|---|---|
| `MAX_PARSED_WIDTH` | 65536 | a format width above this is not a buffer, it is a typo or an attack on us; the literal is skipped and a degradation recorded |
| `MAX_SEED_BYTES` | 65536 | per seed; longer candidates are skipped, not truncated — a truncated seed is a different input than the one the evidence justifies |
| `MAX_CORPUS_BYTES` | 8 MiB | aggregate; adding past it refuses with the total, rather than filling a disk |
| `MAX_TOKEN_BYTES` | 128 | per dictionary token; AFL ignores very long tokens anyway |
| `MAX_SEQUENCE_LEN` | 3 | A5 menu sequences (already present, now a named constant) |
| `MAX_DICT_TOKENS` | 512 | dictionary size |

### Measurement: replay only, and it proves less than "it ran"

`measure_replay()` in `corpus_replay.py` **owns its subprocess**
(`subprocess.run([target], input=seed, capture_output=True, timeout=t)`).

It must not wrap `DynamicAnalyzer.check_crash()`: re-verified that
`check_crash` catches `TimeoutExpired` **internally** and returns
`(False, trace)` with `exit_code = -1` (`dynamic.py:356-358`), so a timeout is
indistinguishable from a genuine `-1`. Only the code that catches the
exception can set `timed_out`.

**The field is named `spawned`, not `ran`** (review H2). Replay proves the
process started, was handed the seed on stdin, and terminated. It does **not**
prove the target read the seed — an exit-0 program that ignores stdin is
indistinguishable from one that consumed it. The manifest, the table header and
the operator-facing text all say "spawned", and no code path treats an exit-0
run as evidence that the seed was *consumed*.

```python
ReplayResult(spawned: bool, exit_code: int | None, signal: str | None,
             timed_out: bool, error: str | None)
```

Every state is defined, with its effect on retention (review H2, H3):

| State | `spawned` | Fields | Default `kept` | Discard reason recorded |
|---|---|---|---|---|
| clean exit | `True` | `exit_code >= 0`, `signal=None` | **keep** | — |
| non-zero exit | `True` | `exit_code > 0` | **keep** — a rejecting parser is still a reached parser | — |
| killed by signal | `True` | `exit_code < 0`, `signal="SIGSEGV"` | **keep, flagged** | — ; surfaced as "crashed the target on its own — that is a finding; run `supwngo triage`" |
| timed out | `True` | `timed_out=True`, `exit_code=None` | **keep, flagged** | — ; a hang is a finding too |
| could not spawn | `False` | `error` set (ENOENT, EACCES, not executable) | **discard** | `"target could not be executed: <error>"` |

Only `spawned=False` discards automatically. **The non-zero-exit row is a
deliberate reversal of the intuitive rule**: a target that rejects an input has
still parsed it, and discarding those would throw away exactly the seeds that
reach a parser.

**Coverage is not implemented in this pass**, and this is where a reader most
wants to believe a number, so:

- `afl-showmap` is real edge coverage but needs instrumentation — an
  `afl-cc`-built target or `-Q` with `afl-qemu-trace`. `benchmark/build_all.sh:179`
  compiles with plain `gcc`, so the repo's own corpus would not qualify.
- The no-instrumentation alternative cannot reuse `DynamicAnalyzer.get_coverage()`:
  it takes a **list** and returns **one union** `CoverageInfo`
  (`dynamic.py:266-319`), so per-seed deltas need a `CFGFast` per seed; its
  `timeout` parameter is accepted and never referenced; it records only
  `simgr.active`, never `deadended`, dropping every run's tail; and its
  percentage denominator counts unentered library stubs.

**Never fabricate a measurement**: if coverage was not obtained, `observed`
**omits** the field rather than writing `0`, because `0` and "unknown" drive
opposite keep/discard decisions. Same rule `_UNMEASURED` encodes in
`protections.py:25-35`.

### The menu state machine (review H3)

Actions, dispatched from a plain dict keyed by integer. The menu re-prints
after every action with the current corpus summary.

```
Corpus: N seeds (M measured/replayed, K crashing)
  [1] show candidate detail     [2] add seeds for a candidate
  [3] add a literal seed        [4] replay unmeasured seeds
  [5] show / prune corpus       [6] write corpus and exit
  [0] abort without writing
Action [6]:
```

| # | Action | Prompts | Effect | Notes |
|---|---|---|---|---|
| 1 | candidate detail | candidate number (`IntRange`) | prints per-strategy evidence and provenance for that candidate; **no state change** | safe to repeat |
| 2 | add seeds | candidate number, then strategies (`a` = evidence-backed only, or a comma list) | generates, dedups, appends | refuses past `--max-seeds` / `MAX_CORPUS_BYTES`, naming the cap |
| 3 | literal seed | the bytes (Python-style escapes accepted) | appends one seed, strategy `operator-literal`, evidence `OPERATOR_ASSERTED` → `ASSUMED` | the only operator-authored bytes |
| 4 | replay | none | replays every seed with no `observed` yet; prints the verdict table; then **one** prune confirmation for auto-discardable seeds | idempotent: already-measured seeds are skipped |
| 5 | show / prune | seed numbers to discard (blank = none) | moves to discarded with reason `"operator pruned"` | |
| 6 | write and exit | none | runs the publish gates, writes, prints "Next:" | **the default** — bare Enter saves |
| 0 | abort | confirm `y/n` | exits non-zero, writes nothing | |

Invalid input: `click.prompt(type=click.IntRange(0, 6))` re-prompts, which is
click's own behaviour and needs no code. EOF at any prompt → the D2 rule.
Default is `6` so the lowest-effort keystroke is the one that saves.

### The artifact

```
corpus_binary_01/
├── seeds/                  <- handed to `-i`; seed files ONLY
├── seeds.discarded/        <- rejected seeds, never deleted
├── dict/tokens.dict        <- AFL `-x` dictionary
└── corpus.json             <- the manifest
```

`corpus.json` lives in the parent, never inside `seeds/`: `-i` is passed
verbatim to `afl-fuzz` (`afl.py:182`), so anything in `seeds/` is fed to the
target as an input. Filenames are `NNN_<strategy>_<discriminator>`, ASCII only.

**Output-directory collision is defined** (review M4). `os.replace()` cannot
replace a non-empty directory, so the rule is explicit rather than emergent:

| Output path | Behaviour |
|---|---|
| does not exist | built in a sibling temp dir, then `os.replace` into place |
| exists and is empty | same |
| exists, non-empty, no `--force` | **refuse before any work**, exit non-zero, naming `--force`. Nothing is read or executed first |
| exists, non-empty, `--force` | build the temp dir fully, then swap: move the old aside, `os.replace` the new in, delete the old. A failure before the swap leaves the original **untouched** |
| any failure during the build | temp dir removed; output path untouched |

`corpus.json` carries `schema_version: "supwngo.corpus/v1"`, the target path
and sha256, per-seed `{file, sha256, size, strategy, also_produced_by,
provenance, rationale, evidence[], observed, kept, discard_reason}`, a
`provenance_tally`, the dictionary summary, and `degradations[]`. It records
**no schema-specific metadata** — it must stay readable with no context
document anywhere. `to_dict()` is hand-written and serializes enums as
`.value`, per house style (`asdict` appears nowhere in the package).

**`seeds/` is an artifact, not a working directory.** AFL is safe (`-i` is
read-only). libFuzzer writes discoveries **into** its first positional corpus
directory (`libfuzzer.py:211-212`). honggfuzz is safe when `--output` is
supplied, and the wrapper passes both (`honggfuzz.py:133-134`) — but it never
passes `--stdin_input`/`-s`, and `cli.py:189` still answers the honggfuzz
branch with "support coming soon".

**`--next-fuzzer` is warning-only for honggfuzz** (review L1). It is kept as a
choice, because refusing a fuzzer the operator legitimately uses teaches
nothing, but its output is exactly:

```
Next: honggfuzz cannot be driven by `supwngo fuzz` in this build
      (the wrapper omits --stdin_input and the CLI branch is a stub).
      Run it directly:
        honggfuzz -i ./corpus_binary_01/seeds --output ./hf_out -s -- ./binary_01
```

No `supwngo fuzz --fuzzer honggfuzz` line is printed anywhere. A test asserts
that string never appears in any `--next-fuzzer` output.

### The AFL dictionary: every byte canonically escaped

`DictionaryGenerator.export_afl_dict()` (`cmplog.py:353-366`) is malformed and
**must not be reused**. Verified by *execution*, not reading:

```
$ python3 -c "...g.entries.update([b'AB', b'menu']); g.export_afl_dict(p)..."
token_0="\x4142"
token_1="\x6d656e75"
```

AFL++ requires `\xNN` **per byte** (`"\x41\x42"`).

r3 specified "printable non-quote ASCII verbatim, everything else `\xNN`" and
then wrote a test demanding `b"AB"` → `"\x41\x42"`. **Those contradict; the
review caught it** (M3, H4.6). r4 resolves it by choosing the unambiguous
option: **every byte is escaped as `\xNN`, with no printable passthrough.** The
output is always valid, the escaper is four lines, the test is an exact string
comparison, and there is no second code path to get wrong. The cost is a
less human-readable dictionary file, which is accepted.

Fixing `export_afl_dict` itself is a separate `fix/` — it has other callers.
Generic magic bytes (`add_magic_bytes()`, 13 hardcoded file-format magics,
`cmplog.py:334-351`) are excluded from **both** seeds and the dictionary: they
are unrelated to the target, and if a magic genuinely is in the target's
strings then A4 already covers it.

### Publish gates and refusals

This CLI has **no `sys.exit` anywhere** and handles nearly everything
report-and-continue with exit 0. r4 raises `click.ClickException` (exit 1) for
runtime refusals, because a guard that cannot change the exit code is
unobservable to any caller and therefore is not a guard.

| Gate | Condition | Action |
|---|---|---|
| G1 empty corpus | zero seeds | refuse; write nothing |
| G2 nothing spawned | at least one seed, **none** with `spawned=True` | write `corpus.json` + `seeds.discarded/` for diagnosis; **do not create `seeds/`**; refuse |
| G3 all-filler | every kept seed is `UNKNOWN` | refuse, printing the tally |
| G4 output collision | non-empty output dir without `--force` | refuse **before any analysis** |

**G3 changed materially in r4, and it is the direct consequence of H1.** r3's
gate was "no seed better than `ASSUMED`". Once A4/A5 seeds are correctly
`ASSUMED` (not `MEASURED`/`DERIVED`), *no strategy in standard mode can ever
clear that bar* — the gate would have failed every honest run, which is worse
than no gate. The satisfiable, still-falsifiable line is `UNKNOWN`: a corpus
in which only `fmt-trigger` fired is generic filler and is refused. The
"better than `ASSUMED`" bar belongs to `--auto`, where A1's crash witnesses and
A3's measured offsets make `MEASURED` genuinely reachable, and it is recorded
there rather than dropped.

G2 is why the corpus is held in memory to the end (Fork 2): an absent `seeds/`
fails loudly at `fuzz -i`, whereas an *empty* one is silently backfilled with
`b"A" * 8` by `AFLFuzzer.setup()` (`afl.py:143-147`).

`click.UsageError` (exit 2) for bad flag combinations, matching `cli.py:2920`.

### Honest failure modes

| Situation | Behaviour |
|---|---|
| Statically linked + stripped | **Near-total evidence loss.** `binary.plt` is empty so A2/A5/A6 have nothing to fire on; only A4 survives. Reported from `DetailedProtections` (`static`, `stripped`) in the header, **before** the empty table |
| Dynamically stripped | Mostly fine — discovery is PLT-driven and the PLT survives stripping |
| Target reads a file named in argv | `_build_command` appends `--` then the binary path and **never emits `@@`** (`afl.py:219-220`), so supwngo cannot fuzz file-argument targets at all. Warn; claim no runnability. **Replay conclusions are suppressed**: a stdin replay says nothing about a file-reading target (review H2) |
| Target reads a socket | No `AFL_PRELOAD`, no desock shim in `afl.py:177-222`. Write, name `preeny`/`libdesock`, record a degradation, **suppress replay conclusions** |
| Input channel | **`UNKNOWN` by default.** `read` proves nothing: `read(0,…)` and `read(fd,…)` are the same import, and `read` simultaneously triggers the synthetic `file_io` rollup (`static.py:302-308`), so one import argues for two channels. `--input-channel` raises it to `ASSUMED` (an operator assertion), never higher |
| `afl-tmin`/`afl-showmap` absent | Not reachable in this pass — nothing shells out to either. Recorded so the absence of a "tool missing" degradation is not read as a gap |
| stdin EOF mid-session | Per D2: clean message, non-zero, no output directory |

---

## Files touched

`git worktree list` shows many live worktrees, several editing `cli.py` (now
**3024** lines, 32 commands, `def main()` at `cli.py:3018`).

| File | Change |
|---|---|
| `supwngo/fuzzing/corpus.py` | **new**. `normalize_plt_name`, `Candidate`, `discover_candidates`, `_CONFIDENCE_RANK` + `weakest()`, `SeedEvidence`, `Seed`, strategy registry, `Corpus`, `afl_dict_escape`, the writer, the size bounds |
| `supwngo/fuzzing/corpus_replay.py` | **new**. `ReplayResult`, `measure_replay`. The module `--coverage` extends later |
| `supwngo/fuzzing/corpus_session.py` | **new**. The menu loop and the rich tables. Deliberately not in `cli.py` |
| `supwngo/fuzzing/__init__.py` | +exports, matching the existing pattern |
| `supwngo/cli.py` | **+~60 lines appended immediately before `def main()`. No existing line modified** — the merge-conflict-minimising choice |
| `tests/test_fuzz_corpus.py` | **new** |
| `CHANGELOG.md` | `### Added` under `[Unreleased]`, same commit as the code |

`corpus_context.py` is **not** created in this pass.

```
supwngo fuzz-corpus BINARY
    -o, --output DIR                 default ./corpus_<name>
        --force                      overwrite a non-empty output directory
        --auto                       not available in this build; refuses
        --input-channel [stdin|file|socket]
                                     operator assertion; recorded ASSUMED
        --include-generic            enable C2 (ASSUMED)
        --max-seeds N                cap, default 64
        --next-fuzzer [afl|libfuzzer|honggfuzz]
                                     tailors the "Next:" line; warns when the
                                     named consumer would mutate seeds/
```

No short option but `-o`. Deliberately **not `-i`**: `fuzz -i` already means
"input corpus directory" (`cli.py:133`), and reusing the letter one command
over for a different meaning is how this CLI's `-o` file-vs-directory
ambiguity happened. Gone from r2: `--script` (D2), `--coverage`, `--symbolic`,
`--context`/`--context-out`, `--grammar`, `--resolve`.

---

## Test strategy

The project's stated failure pattern: a validation step that cannot fail is
worse than none, and **all seven instances found so far asserted absence**.
r3's test plan claimed each absence assertion had a positive counterpart; the
review found that claim false in nine specific places (H4). Every item below
now names the mutation it catches, and **the tests that assert absence are
paired with a positive assertion on the same code path**.

**Every test is to be mutated red once and reverted, and that reported.** The
mutations are enumerated, not left to judgement.

1. **Manifest is a golden contract, not self-consistent.** Assert an
   independently written expected structure: required top-level keys present,
   every seed carrying non-empty `evidence[]`, a `sha256` matching the file's
   real digest, `size` matching real length, and a `provenance_tally` whose
   counts sum to the seed count. A round-trip alone would accept `{}` or a
   manifest with evidence dropped (H4.1). *Mutation: delete `evidence` from the
   serializer → red.*
2. **`seeds/` purity, paired.** `assert not (out/"seeds"/"corpus.json").exists()`
   and no subdirectories — absence — **paired with** an exact equality on the
   seed filename set, which fails if the writer stops writing seeds (H4.1).
   *Mutation: write the manifest into `seeds/` → red; make the writer a no-op →
   red on the pair.*
3. **The session obeys its input.** Drive via `CliRunner(input=…)`. Assert
   per-action effects, the exit code, and — the one the review demanded —
   **that a different input sequence yields a different manifest** (two
   sessions choosing different candidates must not produce equal seed sets). A
   session that ignores input and writes a canned manifest passes item 3's
   naive form and fails this one (H4.2). Assert on `corpus.json`, never on
   printed tables.
4. **Provenance composition, non-vacuously.** Assert the fixture yields a
   **non-empty** seed set first — "for every seed" is vacuous at zero (H4.3).
   Positive: recompute `weakest(...)` from recorded components and assert
   equality, on a fixture with **mixed** confidences. Negative: a strategy
   declaring `MEASURED` with one `ASSUMED` component must be rejected; and a
   strategy that *omits* its weak component must be caught by the recomputation
   rather than only one that lies about its label. Plus
   `assert set(_CONFIDENCE_RANK) == set(Confidence)`, red if the reused enum
   grows a member.
5. **Strategies, with exact payloads and a negative target** (H4.4). `gcc`-gated
   via `GCC_AVAILABLE = shutil.which("gcc") is not None` (`test_solve_command.py:36`),
   compiling on demand because `benchmark/corpus/` ships 15 **sources**, no
   binaries.
   - `scanf("%31s", …)`: **first assert the compiled fixture really imports
     `__isoc99_scanf`** (otherwise a toolchain exposing plain `scanf` lets
     `normalize_plt_name` be deleted silently), then assert A2 emits exactly
     `{31, 32, 62}`-byte seeds — not merely "some seed" (H4.4) — and that they
     are `ASSUMED`, not `DERIVED`.
   - `05_fmtstr_arbread`: `fmt-trigger` fires and is labelled `UNKNOWN`
     — **paired with a negative target** (a binary importing no printf-family
     sink) where it must **not** fire; otherwise a strategy that fires for
     every binary passes (H4.4).
   - Positive coverage for A4, A5 and C2 individually, each asserting the
     strategy's own seeds appear, with `C2` absent by default and present
     `ASSUMED` under `--include-generic`.
   - Dedup determinism: reversing the registry order yields a byte-identical
     manifest.
6. **`measure_replay()` against input-sensitive targets** (H4.5). r3's three
   fixtures (exit 0, `abort()`, sleep) all pass even if `input=seed` is dropped,
   because none inspects stdin. So: a target that exits 0 on `"menu"` and 1
   otherwise, asserting the exit code **differs by seed** — the only test here
   that proves the seed is delivered at all. Plus `abort()` → `signal ==
   "SIGABRT"`; a sleeper → `timed_out is True`; a nonexistent path and a
   non-executable file → `spawned is False` with `error` set. Assert every
   field of `ReplayResult` in each case, not just one.
   Determine empirically whether `CliRunner` suffices for the end-to-end replay
   path or whether `_run_solve`-style `subprocess.run` is needed
   (`test_solve_command.py:157-174` documents `CliRunner`'s stdio lacking a
   usable `fileno()`, which broke pwntools). `measure_replay` uses plain
   `subprocess.run(input=…)`, not pwntools, so it is *expected* to be fine —
   **expected, not assumed**: run both and record which.
7. **The dictionary, exact bytes.** With canonical escaping (M3) the contract
   is unambiguous: `b"AB"` → `token_0="\x41\x42"` exactly, compared as a
   literal string with backslashes intact. Empty token dropped, not written.
   `MAX_TOKEN_BYTES` and `MAX_DICT_TOKENS` enforced at the boundary. Assert
   `cmplog.export_afl_dict()` is **not** called — pinning the broken dependency
   out is the only thing stopping a later "simplification" back to it. Assert
   no generic magic reaches `seeds/` or `dict/tokens.dict` — absence —
   **paired with** a positive case where a magic genuinely *is* in the target's
   strings and therefore *does* appear, so the exclusion cannot pass by
   producing nothing (H4.6).
8. **Refusals, and a success case** (H4.7). This is the pairing the review
   demanded: a plan whose only refusal tests are "exit non-zero" passes if
   *every* invocation refuses. So assert all four gates fire **and** that a
   normal mixed-provenance run exits **0** with a populated `seeds/` and a
   manifest. Plus: `--auto` → non-zero, message names no branch, **no output
   directory created**; G2 → `corpus.json` exists and `seeds/` does **not**;
   G4 → refuses before reading the binary; `--force` → replaces, and a failure
   injected before the swap leaves the original artifact intact (M4).
9. **Consumability, with a hash canary** (H4.8, H4.9). Point `AFLFuzzer.setup()`
   at our `seeds/`, assert it did **not** create its `seed_0` fallback
   (`afl.py:144-147`), and assert the **complete** `_build_command()` argv —
   not just the `-i` pair, which permits an argv missing the target (H4.8).
   For immutability, hash `seeds/` recursively, run setup + build, re-hash,
   assert unchanged — **and prove the oracle works** by mutating a seed file
   and asserting the same hash function reports a change; an unchanged hash is
   otherwise satisfied by a no-op (H4.9). Treat this as an immutability
   property, **not** as evidence AFL accepts the artifact. Assert
   `--next-fuzzer libfuzzer` prints the copy-first warning and that no
   `--next-fuzzer` value ever prints a `supwngo fuzz --fuzzer honggfuzz` line.

### The live AFL gate is an enforceable blocker, not a note

r2 required, before implementation, that (1) `afl-fuzz -i` accept the `seeds/`
layout and (2) `afl-fuzz -x` start with a dictionary from this escaper.
**Neither was run.** AFL++ is installed (`afl-fuzz`, `afl-cc`, `afl-showmap`,
`afl-tmin` on `PATH`) but invoking it is **denied by host policy** for this
work, and other agents hold gated measurements on this machine that must not
be perturbed.

The review is right that unit tests on supwngo's wrapper and byte-level tests
on the escaper do **not** establish that AFL accepts either artifact (H7). So
the gate is recorded as an **open acceptance gate with an owner and a
definition of done**, not as a disclaimer:

> **GATE-AFL-01 (open).** Owner: whoever next has authorization to run the
> fuzzers on an unloaded host, or a CI job. Done when, against a tiny
> `afl-cc`-built target, `afl-fuzz -i <corpus>/seeds -o /tmp/o` starts and
> completes its dry run, **and** `afl-fuzz -x <corpus>/dict/tokens.dict` starts
> without a dictionary parse error. Until then this feature is **not to be
> trusted at scale**, and that is stated in the CHANGELOG entry, not only here.

What stands in the meantime, with the gap named: the `-i` layout is verified
against `AFLFuzzer.setup()`/`_build_command()` (item 9), which is where
supwngo's own contract lives; the escaper is verified byte-for-byte against the
AFL++ format (item 7); and the bug it replaces was verified by execution, which
is the direction that mattered. **No output claims AFL has accepted the
artifact.**

---

## Risks

1. **A plausible corpus built from thin evidence is worse than no corpus**,
   because the operator fuzzes for hours and blames the target. After H1, the
   honest truth about standard mode is stark: **no seed it can produce is
   better than `ASSUMED`.** `MEASURED` requires a crash witness or a measured
   offset, and both arrive only with `--auto`. **Mitigation:** composed
   provenance a strategy cannot self-declare, a printed tally, gate G3, and the
   header saying so in words. The feature's value in this pass is *triage and
   scaffolding*, not evidence.
2. **GATE-AFL-01 is open** — the single largest unverified assumption in the
   deliverable.
3. **`cli.py` churn** — 3024 lines, many live worktrees. **Mitigation:** one
   appended block, zero modified lines, all logic in new modules.
4. **The reused `Confidence` enum is not ours.** If the walkthrough engine adds
   `ASSERTED`, the rank map must grow. **Mitigation:** item 4's exhaustiveness
   assertion goes red that day, which is the point.
5. **`--auto` may slip indefinitely**, on a contract already rejected and
   rewritten three times. Half the original request rides on it.
   **Mitigation:** standard mode is fully usable with no document; the seam is
   one file (though the feature is more — see H6's table).
6. **The analysis layer has defects this feature does not fix** —
   `_find_callers` cannot work; `analyze()` builds N+1 CFGs; `get_coverage` and
   `StaticAnalyzer` return empty results indistinguishable from failure;
   `path_finder.py:144` raises on every call; three public `cmplog.py` classes
   do not work. **Mitigation:** read `binary.plt` directly, own the replay
   subprocess, depend on none of them. Each gets its own `fix/` issue. Do not
   fix them here, and do not build a strategy that needs one working.
7. **The candidate list is thinner than a reader will assume.** The
   `__isoc99_`/`_chk` gap means `analyze` silently misses `scanf` and every
   fortified sink; `normalize_plt_name()` patches this for the corpus builder
   **only**. Reported as "dangerous imports", never as vulnerable call sites.
8. **New package coupling**: `supwngo/fuzzing` now imports from
   `supwngo/exploit/walkthrough`. Accepted deliberately (D1); the follow-up is
   to move `Confidence`/`Evidence` to a neutral module, which is a cross-cutting
   refactor of a just-merged engine and does not belong in this change.
9. **A non-TTY run on an inherited open pipe blocks indefinitely.** Shared with
   `solve --interactive`; not introduced here, and not fixed here. `--allow-non-tty`
   was considered and declined (D2) because it does not fix this case either.

## Verification log

Re-verified at `ef40e93`, by reading unless noted. **Verified by execution:**
`export_afl_dict()` emits `token_0="\x4142"` for `b"AB"`.

Still true, with current line numbers: `DANGEROUS_FUNCTIONS` 34 literal / 32
unique (`static.py:16-62`; `sprintf` `:21`+`:27`, `vsprintf` `:22`+`:31`), no
`isoc99`/`_chk` spellings; `INPUT_SOURCES` 11 entries incl. unreachable
`"argv"` (`static.py:65-77`), rollups `:292-298`, `:302-308`; `analyze()`
`:137-189` drops `caller_address`/`context`; `find_vulnerability_sinks()`
`:446-471` has no callers; `_find_callers` broken at `:252-255`, `:258-260`;
`export_afl_dict` `cmplog.py:353-366`; `add_magic_bytes` 13 magics `:334-351`;
`Binary.strings()` returns file offsets `binary.py:428-452`;
`plt: Dict[str, int]` `binary.py:122`; `symbols: Dict[str, Symbol]` `:120`;
`AFLFuzzer.setup()` `b"A"*8` backfill `afl.py:143-147`, no `@@` in
`_build_command` `:177-222`; honggfuzz passes `--input`+`--output`
`honggfuzz.py:133-134`, never `-s`; libFuzzer bare positional corpus
`libfuzzer.py:211-212`; `fuzz -i` required `cli.py:133`; honggfuzz "coming
soon" now `cli.py:189`; `StringAnalyzer` omits `width` `strings.py:330-346`;
`check_crash` swallows the timeout `dynamic.py:356-358`; `get_coverage`
list-in/union-out with unused `timeout` `:266-319`; `path_finder.py:144`
`AttributeError`; `benchmark/corpus/` 15 sources, no binaries,
`fmtstr_arbread.c:37` is `printf(name)` with no `%` literal,
`build_all.sh:179` plain `gcc`.

Changed: `cli.py` 2826 → **3024** lines, 31 → **32** commands, `def main()` at
**3018**; `DetailedProtections.to_dict()` 6 → **16** keys plus `_UNMEASURED`
(`protections.py:25-35`, `:67-104`); `Confidence`/`Evidence` now **present**
(`exploit/walkthrough/model.py:130-178`) with **no `ASSERTED`**; `isatty`
**nowhere** in the repo.

## Alignment log

| Date | Change |
|---|---|
| 2026-09-24 | r1 drafted against context-schema v1; **NOT APPROVED** (5H/6M/5L). |
| 2026-09-24 | r2: all five High findings applied; schema shape removed behind a `CorpusEvidence` adapter; own dictionary escaper; composed provenance; B2/`--grammar` deleted. Never reviewed — the tree moved first. |
| 2026-09-24 | r3, reconciled to `ef40e93`: scoped to standard mode; reuses merged `Confidence`/`Evidence`, repairing r2's `min()`-over-a-partial-order bug (D1); deletes the baseless isatty refusal and `--script` (D2); records the `DetailedProtections` reshape (D3); adds the four-fork comparison; drops `--coverage`, `--symbolic`, A1, A3. **NOT APPROVED** (7H/6M/2L). |
| 2026-09-24 | **r4, after the r3 review.** `INPUT_RELEVANCE` added and **A4/A5 seeds reclassified to `ASSUMED`** — "bytes are in the binary" is not "bytes are a useful input" (H1); **gate G3 changed from "better than ASSUMED" to "better than UNKNOWN"**, because the corrected labels made r3's gate unsatisfiable (H1); dedup made deterministic and non-destructive with `also_produced_by` and strongest-wins (H1); `ReplayResult.ran` → **`spawned`** with all five states and their retention effects tabulated, and replay conclusions suppressed for file/socket channels (H2); the menu state machine fully specified (H3); all nine test items tightened with the mutation each catches, adding the different-input-different-manifest test, the input-sensitive replay target, the negative `fmt-trigger` target, the exact A2 payload set, the `__isoc99_` fixture precondition, the hash-oracle canary, the complete-argv assertion and a **success** case beside the refusals (H4); all four forks re-argued against their strongest alternative and **Fork 4's self-contradictory flip corrected** — an unresolved fact makes `--auto` refuse, not prompt (H5); `--auto`'s remaining work enumerated honestly as "one file plus two strategies plus wiring plus tests" (H6); the live AFL gate promoted to **GATE-AFL-01** with an owner and a definition of done (H7); provenance rank scoped as local policy and the package coupling accepted as risk 8 (M1); non-TTY behaviour tabulated, `--allow-non-tty` declined with the reason recorded (M2); **escaper canonicalised to `\xNN` for every byte**, resolving r3's contradiction with its own test (M3); output-collision rules and `--force` defined (M4); "flagged functions" → **"dangerous imports"** throughout (M5); six named size bounds added (M6); `--next-fuzzer honggfuzz` output defined as warning-only (L1); the branch name removed from the `--auto` error (L2). |
