# Interactive fuzzer corpus builder (`supwngo fuzz-corpus`)

**Date:** 2026-09-24
**Status:** DRAFT **r2** — r1 was **NOT APPROVED** by independent review
  (5 High, 6 Medium, 5 Low). Every High was independently re-verified by the
  author as *correct*; this revision addresses them. Review recorded at
  `docs/plans/reviews/2026-09-24-interactive-fuzz-corpus-builder-review-r1.md`.
  **Requires a second review before implementation.**
**Branch:** `feat/interactive-fuzz-corpus-builder-20260924`
**Depends on:** `docs/plans/2026-09-24-standardized-context-schema.md` —
  currently **v3 DRAFT** (`d3c7607`, branch
  `docs/context-schema-plan-20260924`), which replaces key→value facts with
  **candidate sets** carrying `applies_to`, stable candidate IDs and
  `resolve(key, ctx)`.

  **That plan has now been rejected twice (v1 and v2) and rewritten twice
  while this one was being drafted.** r1 of this plan was written against v1,
  realigned to v2, and was immediately stale again. The conclusion is not
  "chase it a third time": it is that **this feature must not encode the
  schema's shape at all.** See "Context integration is deferred" below.

## Verification status of this plan

Citations were read at `integration/phases-0-4-7-20260923` (`0997da5`).
Claims that are **assumed** rather than verified are marked **[ASSUMED]**
inline.

**Verified by execution** (not just read):

- `scanf` is invisible to the analysis layer on modern glibc — the PLT name
  is `__isoc99_scanf` (compiled a probe; see that section).
- `DictionaryGenerator.export_afl_dict` emits **malformed** AFL
  dictionaries — `b"AB"` becomes `"\x4142"`, not `"\x41\x42"` (ran the
  writer's formatting). r1 called this writer "correct as written"; that
  was wrong. See H2 handling in strategy A4.
- `StringAnalyzer` **does not expose** `FormatSpecifier.width` in its
  returned `details["specifiers"]` (`strings.py:329-339` emits `position`,
  `specifier`, `type`, `dollar`, `is_write` only). r1's strategy A2 was
  built on a field the primitive never returns.
- `benchmark/corpus/05_fmtstr_arbread` contains **no `"%`-format literal** —
  the bug is `printf(name)` with a runtime format
  (`fmtstr_arbread.c:36`). r1's A6 evidence gate was therefore
  *anti-correlated* with the vulnerability class it targets.
- `_find_callers` is **fully broken**, not merely weak: `binary.symbols` is
  `Dict[str, Symbol]` (`core/binary.py:120`) but `static.py:258` passes the
  `Symbol` object where `cfg.kb.functions.get()` wants an address.

**Still read-from-source only, and gating Phase 0:**

- That `afl-fuzz -i` accepts the `seeds/` layout, and that `afl-fuzz -x`
  accepts our dictionary. Neither was run. Phase 0 must prove **both**.
- AFL++'s real CMPLOG shm format was not checked against AFL++ source; the
  verified claim is only that supwngo's reader cannot work as written.

## Goal

Produce a fuzzing corpus that is *justified by evidence supwngo already
gathered*, in two modes:

- **interactive** — present the functions and input sources that earlier
  analysis flagged, let the operator pick, add seeds, measure them, keep or
  discard, repeat; then write the corpus. Ships in Phase 3.
- **`--auto`** — build the same artifact with no interaction, from the
  evidence a prior analysis recorded in the context document. **Ships in
  Phase 4 and is gated on that schema being settled** — see "Context
  integration is deferred". Phases 1-3 ship interactive-only.

The corpus is a **directory of input files plus a manifest**, consumable
unchanged by `supwngo fuzz -i <dir>/seeds` and by `afl-fuzz -i` directly.

This closes a real gap: `fuzz` requires `-i/--input-dir`
(`supwngo/cli.py:133`, `required=True`), and if the directory is empty
`AFLFuzzer.setup()` writes a single `b"A" * 8` seed
(`supwngo/fuzzing/afl.py:143-147`). Today there is nothing in the framework
that turns analysis results into seeds. Every `analyze` finding is thrown
away before fuzzing starts.

## Non-goals

- **Not a fuzzer, and not a fuzzing campaign driver.** `fuzz` already does
  that. This command only produces the `-i` input.
- **Not a corpus minimiser.** `afl-cmin` does that better; we do exact
  sha256 dedup and nothing cleverer.
- **Not a harness generator.** `AFLFuzzer.generate_harness`
  (`supwngo/fuzzing/afl.py:380`) and `LibFuzzer.create_harness_template`
  (`supwngo/fuzzing/libfuzzer.py:129`) already exist and are out of scope.
- **Not a new state object.** No changes to `ExploitContext` — it has no
  corpus concept (`supwngo/core/context.py`, verified: no `fuzz`/`corpus`
  members) and does not need one. The corpus is recorded in the context
  document through one adapter whose shape this plan deliberately does not
  specify.
- **Not a fix for the analysis layer.** This plan documents five real defects
  it found in `static.py`, `cmplog.py`, `strings.py` and `path_finder.py` and
  works *around* them. Each gets its own `fix/` issue. Fixing them here would
  change `analyze`'s output for every existing consumer.
- **Not support for non-stdin input channels.** See "Honest failure modes" —
  supwngo's AFL wrapper cannot drive file-argument or socket targets at all
  today, and this plan does not fix that.

## What "the functions earlier analysis flagged" actually is

This is the primary input, so it is worth being exact about how thin it is.

`StaticAnalyzer.analyze()` (`supwngo/analysis/static.py:137-189`) returns
six keys. Two matter here:

**`dangerous_calls`** — built at `static.py:157-165`, each record is exactly
four fields:

```python
{"function": dc.function, "address": hex(dc.address),
 "caller": dc.caller, "risk": dc.risk}
```

The `DangerousCall` dataclass (`static.py:80-88`) also carries
`caller_address` and `context`, but `analyze()` drops both. `context` is only
populated by the separate `find_vulnerability_sinks()`
(`static.py:446-471`), which assigns `HIGH`/`MEDIUM`/`LOW` from two hardcoded
sets (`static.py:457-458`) and is **not** called by `analyze()`. So severity
is available but only via a second call.

Detection is **PLT-driven**: `find_dangerous_functions()` iterates
`self.binary.plt` against the `DANGEROUS_FUNCTIONS` dict
(`static.py:16-62`, `201-202`). That dict has **34 literal entries but only
32 unique keys** — `sprintf` is declared twice (`static.py:21` and `:27`)
and `vsprintf` twice (`static.py:22` and `:31`), so the later value wins and
both lose their "Stack buffer overflow" risk text in favour of the
format-string text. Consequence for the UX: the Risk column will describe
`sprintf` as a format-string risk only, never as an overflow risk. Worth a
separate one-line `fix/` commit; not fixed here.
**Call-site discovery is not weak — it cannot work.** `_find_callers()`
(`static.py:231-272`) has two loops and both are broken:

1. The first loop's body is literally `pass` (`static.py:252-255`).
2. The second iterates `self.binary.symbols.items()` binding the value as
   `func_addr` (`static.py:258`) and passes it to
   `cfg.kb.functions.get(func_addr)` (`static.py:260`). But `symbols` is
   `Dict[str, Symbol]` (`core/binary.py:120`) — the value is a `Symbol`
   object, not an address. The lookup can never match, and the
   `except Exception: continue` at `static.py:266-267` swallows it silently.
   The fix is `symbol.address`; it belongs in its own `fix/` commit.

So `_find_callers` **always returns `[]`**, which means the
`if not dangerous_calls:` fallback at `static.py:218-227` **always** fires:
one record per imported dangerous function, `caller="unknown"`,
`caller_address=0`. r1 described this as "usually"; it is "always" until
`static.py:258` is fixed.

It is also **expensive**: `_find_callers` is called once per dangerous PLT
import (`static.py:206`) and each call runs a fresh
`proj.analyses.CFGFast()` (`static.py:246`), with `_analyze_functions`
building yet another (`static.py:377`). A binary importing six dangerous
functions builds **seven** CFGs to produce no call sites. r1 claimed
`analyze` costs "one `CFGFast`" — wrong, and it is the dominant cost of the
interactive mode's startup.

**Consequences, both load-bearing:**

- The "Where" column is **always** `unknown`, so the candidate picker is
  keyed on *function*. The mockup below reflects this.
- `fuzz-corpus` must **not** call `StaticAnalyzer.analyze()` for candidate
  discovery. It reads `binary.plt` directly and applies
  `normalize_plt_name()` + the `DANGEROUS_FUNCTIONS`/`INPUT_SOURCES` dicts
  itself — same result, no angr, no seven CFG builds, and it sidesteps the
  `__isoc99_` gap in one place. `analyze()` is still used when a context
  document is unavailable and the operator passes `--analyze`, because that
  is what populates the document.

**`input_sources`** — `detect_input_sources()` (`static.py:274-311`), three
fields per record (`function`, `type`, `plt_address`), from an 11-entry
`INPUT_SOURCES` dict (`static.py:65-77`) plus two synthetic rollups:
`{"function": "networking", "type": "network socket"}` when any of
`socket/bind/listen/accept/connect` is imported (`static.py:291-299`), and
`{"function": "file_io", "type": "file input"}` when any of
`fopen/open/fread/read` is (`static.py:301-309`). Note `INPUT_SOURCES` lists
`"argv"` as a key (`static.py:76`) which can never match a PLT entry, so
argv is never reported.

**`interesting_strings`** — `get_interesting_strings()`
(`static.py:313-364`) regex-matches a 16-pattern list including
`%[0-9]*\$`, `%s`, `%n`, `%p` (`static.py:331-334`). Usable, but
`analysis/strings.py` has a strictly better primitive for the same job
(below), and `static.py` truncates the list to 100 entries at
`static.py:174`.

### `scanf` is invisible to supwngo on any modern glibc binary

This is the one claim in this plan that was **verified by execution**, and it
is load-bearing for strategies A2 and A5.

`find_dangerous_functions` matches PLT names against `DANGEROUS_FUNCTIONS`
by **exact string equality** (`static.py:202`), and `detect_input_sources`
does the same against `INPUT_SOURCES` (`static.py:284`). But glibc emits
`__isoc99_scanf`, not `scanf`, for a `scanf` call. Verified on this host:

```
$ printf '#include <stdio.h>\nint main(void){char b[32];scanf("%%31s",b);
  printf("%%s\\n",b);return 0;}\n' > p.c && gcc -o p p.c
$ objdump -R p | grep -i scanf
0000000000003fd0 R_X86_64_JUMP_SLOT  __isoc99_scanf@GLIBC_2.7
```

Neither `DANGEROUS_FUNCTIONS` (`static.py:16-62`) nor `INPUT_SOURCES`
(`static.py:65-77`) contains `__isoc99_scanf`, `__isoc99_sscanf`,
`__isoc99_fscanf` or `__isoc99_vscanf`. **So on a normally-compiled Linux
binary, supwngo reports no `scanf` dangerous call and no `scanf` input
source at all** — the exact case the interactive mockup below shows.

Consequence, and a hard requirement on this feature: the corpus builder
**must normalise PLT names before gating any strategy** — strip the
`__isoc99_` prefix, and also handle `_chk` variants (`__sprintf_chk`,
`__strcpy_chk`, `__printf_chk`) which `-D_FORTIFY_SOURCE` emits and which
are likewise absent from both dicts. This normalisation lives in
`supwngo/fuzzing/corpus.py` as `normalize_plt_name()`, **not** in
`static.py`: fixing the dicts is the correct long-term fix but it changes
`analyze`'s output for every existing consumer and belongs in its own
`fix/` commit, which other worktrees may be touching. A test asserts
`normalize_plt_name("__isoc99_scanf") == "scanf"` and that A2 fires on a
freshly compiled `scanf` target.

Without this, A2 and A5 would never fire in practice and `--auto` would
quietly fall back to `binary-strings` only. That failure would have looked
exactly like "the target has no interesting input", which is why it is
called out here rather than discovered during implementation.

**A better string primitive exists and should be used instead.**
`StringAnalyzer` (`supwngo/analysis/strings.py:105`) parses format
specifiers properly with `FORMAT_PATTERN` (`strings.py:94-102`) into
`FormatSpecifier` objects carrying `type_char`, `width`, `precision`,
`dollar_position`, `is_write` (`strings.py:55-65`, populated at
`strings.py:283-314`). That `width` field is the load-bearing one for seed
lengths — see strategy A2.

**A real bug that constrains what we can use.** `Binary.strings()`
(`supwngo/core/binary.py:428-454`) scans `self.path.read_bytes()` and
returns **file offsets** as the first tuple element. Both
`StaticAnalyzer._get_section_for_addr` (`static.py:366-371`) and
`StringAnalyzer._get_section` (`strings.py:501`) compare that offset against
section *virtual* addresses, so section attribution for strings is wrong on
any non-identity-mapped binary. **The corpus builder must use string
*values* only and never their addresses.** Filed as an observation, not
fixed here (out of scope; would touch `core/binary.py` which other
worktrees are editing).

## The corpus artifact

### Layout

```
corpus_binary_01/
├── seeds/                      <- this is the directory handed to `-i`
│   ├── 000_str_menu_1
│   ├── 001_scanf_width_31
│   ├── 002_scanf_width_32
│   ├── 003_fmt_pct_p_x8
│   └── 004_crash_replay_a3f1
├── seeds.discarded/            <- rejected seeds, kept for review
│   └── 000_generic_int_max
├── dict/
│   └── tokens.dict             <- AFL `-x` dictionary
└── corpus.json                 <- the manifest
```

**`corpus.json` lives in the parent, not in `seeds/`.** This is not
cosmetic. `AFLFuzzer.setup()` tests `if not any(input_path.iterdir())`
(`supwngo/fuzzing/afl.py:143-144`) to decide whether to inject its
`b"A" * 8` fallback, and `-i` is passed verbatim to `afl-fuzz`
(`afl.py:182`). A manifest or a subdirectory inside `seeds/` would be fed to
the target as an input. So `seeds/` contains nothing but seed files, and
pointing `supwngo fuzz -i corpus_binary_01/seeds` at it requires **zero
changes to `afl.py`**. The same directory is what `HonggfuzzFuzzer.setup()`
(`supwngo/fuzzing/honggfuzz.py:96-109`) and `LibFuzzer.setup()`
(`supwngo/fuzzing/libfuzzer.py:167-186`) want.

Filenames are `NNN_<strategy>_<discriminator>`: ordered, greppable, and
ASCII-only so `afl-fuzz` does not complain.

### `seeds/` is immutable, and two of the three fuzzers will mutate it

This is a design constraint the first draft of this plan missed, and it
matters because the manifest records a per-seed sha256 and the context doc
records a manifest sha256.

- **AFL is safe.** `-i` is read-only; AFL writes discoveries to `-o`
  (`supwngo/fuzzing/afl.py:182-183`). `supwngo fuzz -i corpus/seeds` does not
  disturb the artifact.
- **libFuzzer is not.** `LibFuzzer._build_command` passes `corpus_dir` as a
  bare positional argument (`supwngo/fuzzing/libfuzzer.py:209-212`), which
  libFuzzer treats as **read-write** and into which it writes every new
  coverage-increasing input. **[ASSUMED]** — this is libFuzzer's documented
  behaviour for a single positional corpus directory, not verified by
  running it here.
- **honggfuzz is safe *when a separate `--output` is supplied*.** r1 said
  honggfuzz "adds to" its `--input` directory; the reviewer corrected this
  against honggfuzz's documented behaviour — with `--output` set, new corpus
  data goes there, and the wrapper does pass both
  (`honggfuzz.py:129-136`). So the hazard is conditional, not inherent, and
  the correct statement is: **safe with `--output`, unsafe without.**

  Two separate honggfuzz problems do exist, and neither is this feature's to
  fix: the wrapper never passes `--stdin_input`/`-s`
  (`honggfuzz.py:129-136`), so a stdin-reading target gets no input at all;
  and `cli.py:188` still answers the honggfuzz branch with "support coming
  soon". Consequence for this plan: `--next-fuzzer honggfuzz` is accepted
  but prints the **raw `honggfuzz` invocation with `-s` and `--output`**, and
  explicitly *not* a `supwngo fuzz --fuzzer honggfuzz` line, because that
  path does not run. Do not print a command this repo cannot execute.

So the rule is: **`seeds/` is an artifact, not a working directory.**
`corpus.json` carries `"immutable": true` and
`"safe_direct_consumers": ["afl", "honggfuzz-with-output"]`, and the printed
"Next:" line recommends `-i corpus/seeds` for AFL but
`cp -r corpus/seeds work_corpus` first for libFuzzer. Test 10 below asserts
digests still verify after an AFL-style read, and asserts the warning is
printed when the operator names a mutating consumer. A `corpus verify` subcommand is *not*
added — out of scope; re-running `fuzz-corpus` on the same output directory
detects drift.

### `corpus.json`

```json
{
  "schema_version": "supwngo.corpus/v1",
  "tool_version": "1.0.0",
  "created": "2026-09-24T14:02:11Z",
  "target": {"path": "/abs/path/binary_01", "sha256": "<digest>"},
  "input_channel": {
    "value": "stdin",
    "provenance": "derived",
    "scope": "build",
    "depends_on": "binary_symbols",
    "method": "input_sources: fgets/read present, no socket* imports"
  },
  "generated_by": {"command": "fuzz-corpus", "mode": "auto",
                   "context": "ctx.json", "argv_digest": "<sha256>"},
  "strategy_tally": {
    "measured": 1, "derived": 7, "assumed": 0, "asserted": 2
  },
  "seeds": [
    {
      "file": "seeds/001_scanf_width_31",
      "sha256": "<digest>", "size": 31,
      "strategy": "scanf-width",
      "provenance": "derived",
      "rationale": "binary contains format string \"%31s\"; __isoc99_scanf imported",
      "evidence": {
        "source": "analysis.strings.FormatSpecifier",
        "format_string": "%31s", "width": 31, "type_char": "s"
      },
      "observed": {
        "exit_code": 0, "signal": null, "timed_out": false,
        "new_blocks": 12, "measured_by": "angr-emulated-blocks"
      },
      "kept": true
    }
  ],
  "dictionary": {
    "path": "dict/tokens.dict", "entries": 214,
    "sources": ["binary-strings"],
    "excluded": ["generic-magic-bytes"]
  },
  "degradations": [
    "afl-showmap not on PATH: coverage measured by angr emulation instead",
    "angr CFGFast failed: dangerous_calls has caller=unknown for all 6 entries"
  ]
}
```

Three deliberate choices:

1. **`provenance` is a five-value ordered vocabulary owned by `corpus.json`
   itself** — `measured > derived > asserted > assumed > unknown`. It happens
   to match the context schema's vocabulary today, and that is convenient,
   but `corpus.json` does **not** defer to it: this file must remain readable
   and meaningful with no context document anywhere. There is no per-seed
   `confidence` field; provenance is the decision variable and a numeric
   score adds nothing mergeable. (r1 justified this vocabulary as "the schema
   v2 vocabulary" and cited `walkthrough/model.py:124-143` for `unknown` —
   that file is absent from this worktree, reviewer L2, so the citation is
   withdrawn and the vocabulary stands on its own.)
2. **The manifest records no schema-specific metadata.** r1 gave each fact a
   `scope` and a `depends_on` copied from the dependency's v2 design; both
   spellings are gone in v3. `corpus.json` instead records, per seed, the
   `evidence[]` components that produced it — each with its own source and
   provenance — and leaves the translation of that into whatever the document
   wants entirely to `corpus_context.py`. The manifest is the durable format;
   the document mapping is the volatile one, and the volatile one is not
   allowed to leak into the durable one.
3. **`degradations[]` is part of the artifact.** Every angr path in this
   codebase swallows failure into a *debug* log (`static.py:399-400`,
   `static.py:269-270`, `analysis/dynamic.py:316-317`). A corpus built with
   angr silently broken looks identical to one built with it working. The
   manifest records the difference and the command prints it.

### Context integration is deferred, and the shape is not encoded here

r1 specified the exact facts, key spellings, block layout and `--resolve`
semantics this feature would write. The reviewer's H1 is correct: all of it
was already wrong, because the schema moved to v3 (candidate sets with
`applies_to`, stable candidate IDs, `resolve(key, ctx)`) while r1 was being
written. r1 was the *second* time that happened.

So r2 stops describing the schema. The rule for this feature is:

1. **`fuzz-corpus` owns `corpus.json` and nothing else.** That file is the
   feature's contract with itself and is fully specified above. It is not a
   context document and does not follow the context schema.
2. **All context I/O lives behind two functions** in
   `supwngo/fuzzing/corpus_context.py`, the only file in this feature that
   may import from `supwngo/schema/`:
   - `read_corpus_evidence(doc) -> CorpusEvidence` — a plain dataclass with
     the fields the strategies need (`crash_inputs: list[bytes]`,
     `return_offset: int | None`, `dangerous_functions: list[str]`,
     `input_sources: list[str]`, `input_channel: str | None`), each paired
     with the provenance the document reported.
   - `write_corpus_result(doc, corpus) -> doc` — records the corpus.
3. **Strategies consume `CorpusEvidence`, never the document.** No strategy
   knows whether a fact came from a v2 scalar or a v3 candidate set.
4. **Crash inputs come through `read_corpus_evidence`, not from a block.**
   r1 had strategy A1 reading the `crashes` block directly, which the
   schema forbids (consumers read facts, not blocks). Whether crashes
   surface as facts, as `artifacts[]` entries, or as a resolved candidate is
   the schema's problem; `CorpusEvidence.crash_inputs` is this feature's
   view. If the schema exposes no normative path to crash bytes, **A1 is
   disabled and says so** rather than reaching into a block.
5. **Phase 4 is blocked** until the schema plan is approved and non-DRAFT.
   Phases 1-3 ship a working command with `--context`/`--context-out`
   accepted and inert.

What this costs: `--auto` has no evidence source until Phase 4, so `--auto`
is **not shipped in Phases 1-3** — only the interactive mode with
`--analyze`. That is a real scope reduction and it is the honest consequence
of depending on an unsettled contract. What it buys: a v4 costs one file.

## Seed-generation strategies, ranked by evidence

The reviewer's H3 landed: r1 ranked strategies by a *label* the author chose
and then "enforced" the labels with a test that asserted the labels. That is
circular. r2 replaces it with a rule that can actually be violated.

### Provenance is composed, and takes the weakest component

Every strategy declares its evidence as a list of components, each with its
own provenance. **The seed's provenance is the weakest component's**, computed
by the framework — a strategy cannot assert its own provenance.

```python
BYTES_FROM_BINARY   = Evidence("bytes read from target", MEASURED)
IMPORT_PRESENT      = Evidence("symbol in PLT",          MEASURED)
CRASH_WITNESS       = Evidence("input crashed target",   MEASURED)
FACT_FROM_CONTEXT   = Evidence(...,  <provenance the document reported>)
SINK_IS_CONTROLLED  = Evidence("sink reached by input",  UNKNOWN)   # never proven
FORMAT_IS_FOR_SCANF = Evidence("format belongs to scanf", ASSUMED)  # not provable statically
CHOICE_SEQUENCE     = Evidence("this order of choices",   ASSUMED)
GENERIC_PRIOR       = Evidence("common-case guess",       ASSUMED)
```

`Seed.provenance = min(e.provenance for e in evidence)` over the order
`unknown < assumed < derived < measured`. Three consequences r1 got wrong:

- **A6 (format-string triggers) becomes `unknown`**, not `derived`, because
  it depends on `SINK_IS_CONTROLLED` and nothing in supwngo establishes that
  statically.
- **A2 becomes `assumed`**, not `derived`, because
  `FORMAT_IS_FOR_SCANF` is not provable from a string table.
- **A5's sequences become `assumed`**; only its single-token seeds stay above
  that.

The negative test is now meaningful: construct a strategy that returns
`provenance=MEASURED` with an `ASSUMED` component and assert the manifest
writer **rejects** it. That test can fail. r1's could not.

### Input channel is `unknown` unless traced

r1 claimed `input_channel: "derived"` from "`fgets`/`read` imported, no
socket imports". The reviewer is right that this proves nothing: `read(0,…)`
and `read(fd,…)` are the same import, and `read` *simultaneously* triggers
the synthetic `file_io` source (`static.py:301-309`), so the same evidence
argues for two different channels.

So: **`input_channel` is `unknown` by default.** It is raised only by
- `--input-channel stdin|file|socket` from the operator → `asserted`, or
- an `strace` observation that the first read is from fd 0 → `measured`
  (`DynamicAnalyzer.trace_strace`, `analysis/dynamic.py:197`, exists and
  shells out to `strace`; absent `strace`, unavailable).

A corpus whose channel is `unknown` is still written — seeds are bytes and
remain valid — but the "Next:" line says the channel is unverified.

### Tier A — every byte comes from the target, or the seed is a witness

**A1. `crash-replay` — `measured`. Strongest, and the only `measured` one.**
Crash inputs reached via `CorpusEvidence.crash_inputs` (never by reading a
block — see H1). Components: `CRASH_WITNESS`. Optional shrink via
`CrashTriager.minimize_crash` (`crash_triage.py:579`) or
`AFLFuzzer.minimize_crash` (`afl.py:340-378`), both needing `afl-tmin`
(`afl.py:351-353`); absence is a recorded degradation. If the context layer
exposes no normative path to crash bytes, **A1 is disabled and says so.**

**A2. `scanf-width` — `assumed` (was `derived` in r1).**
Two r1 errors, both confirmed:

1. **The advertised primitive does not expose the field.**
   `StringAnalyzer._check_format_string` builds `FormatSpecifier.width`
   (`strings.py:292-296`) but omits `width` and `precision` from the returned
   `details["specifiers"]` (`strings.py:329-339`). Workaround: the returned
   `specifier` string *is* the full match (`"%31s"`), so re-run
   `FORMAT_PATTERN` (`strings.py:94-102`) over it, or bypass
   `StringAnalyzer` and apply `FORMAT_PATTERN` to `Binary.strings()`
   directly. r2 does the latter — fewer moving parts, and `StringAnalyzer`
   discards the field anyway. Exposing `width` in `StringAnalyzer` is a
   separate `fix/`.
2. **`%31s` is a maximum field width, not a buffer capacity.** It is an upper
   bound on what `scanf` will *write*, which is evidence about the format
   string, not about the destination buffer. Correctly used it says "inputs
   longer than 31 get truncated here", which is still useful for choosing
   lengths — but it is not "the buffer is 32 bytes".

Components: `BYTES_FROM_BINARY` + `IMPORT_PRESENT` + `FORMAT_IS_FOR_SCANF`
→ `assumed`. Gated on the **normalised** PLT name (`__isoc99_scanf` → see
below). Emit `width`, `width + 1`, `width * 2`.

**A3. `context-offset-lengths` — provenance inherited from the fact.**
Only when `CorpusEvidence.return_offset` is present. Components:
`FACT_FROM_CONTEXT` with whatever provenance the document reported — so a
`measured` offset yields `measured`-adjacent lengths and an `assumed` one
does not get laundered. Emit `{N-1, N, N+1, N+8, N+16, N+64}`. Absent the
fact, **do not synthesise a threshold**; that is C2.

**A4. `binary-strings` — `measured` for the bytes, and it needs a new
dictionary writer.**
Strings come from `Binary.strings()` (`core/binary.py:428-454`, pure Python,
no external tool). Components: `BYTES_FROM_BINARY` → `measured` as *bytes
present in the target*; note that is a claim about the binary, not about the
input grammar, which is why they are dictionary tokens first and seeds only
when they look like input tokens.

**The dictionary writer in the repo is broken and must not be reused.**
`DictionaryGenerator.export_afl_dict` (`cmplog.py:353-366`) does
`hex_value = entry.hex()` then writes `token_{i}="\x{hex_value}"`, so
`b"AB"` becomes `token_0="\x4142"`. AFL++ requires `\xNN` **per byte**
(`"\x41\x42"`). Verified by running the formatting. r1 called this writer
"correct as written" — that was wrong, and it would have produced a
dictionary AFL either rejects or misreads.

r2 writes its own escaper in `supwngo/fuzzing/corpus.py`: printable
non-quote ASCII verbatim, everything else `\xNN`, with `"` and `\` escaped.
Fixing `export_afl_dict` itself is a separate `fix/` (it has other callers).
**Phase 0 must test `afl-fuzz -x` against the produced file**, not just
`-i` — and that needs an instrumented target, since `benchmark/build_all.sh`
uses ordinary `gcc`, so either `afl-cc` or `-Q` with `afl-qemu-trace`.

**A5. `menu-token` — single tokens `derived`, sequences `assumed`.**
Components for a single token: `BYTES_FROM_BINARY` + `IMPORT_PRESENT`
→ `derived`. Sequences add `CHOICE_SEQUENCE` → `assumed`. Capped at length 3.

**A6. `fmt-trigger` — `unknown`, and its r1 gate was actively wrong.**
r1 gated this on "a format-bearing string present in the binary". The
reviewer showed that gate is *anti-correlated* with the bug class, and it
checks out: `benchmark/corpus/05_fmtstr_arbread` is the canonical
format-string target and its vulnerability is `printf(name)`
(`fmtstr_arbread.c:36`) — a runtime format, with **no `"%`-literal anywhere
in the source**. A binary whose `printf` format comes from the user is
exactly the binary that lacks a compiled format literal.

So the gate is **removed**. A6 fires whenever a printf-family sink is
imported, its components are `IMPORT_PRESENT` + `SINK_IS_CONTROLLED`, and
its provenance is therefore `unknown`. Payloads (`b"%p"*8`, `b"%s"`, `b"%n"`,
`b"%7$p"`, `b"AAAA%p%p%p%p"`) are generic and labelled as such. They are
cheap and worth including; they are not analysis. Being honest about that is
the whole point of the provenance column.

### Tier B — needs a tool or primitive that is absent or broken

**B1. `symbolic-reach` — `derived`, default OFF (`--symbolic`).**
`PathFinder.find_path_to_function()` (`symbolic/path_finder.py:124-179`) is
the right shape but has three problems: it targets the **PLT address of the
sink** (`path_finder.py:142`), so it proves reaching `gets@plt`, rarely the
interesting thing; `concretize_state` returns `b""` on any exception and
falls back to the private `state.solver._stored_solver._constraints`
(`symbolic/angr_engine.py:398-413`); and `path_finder.py:144` is
`self.binary.symbols.get(func_name, {}).address`, which raises
`AttributeError` on `{}` instead of reaching the intended warning on line 146
(confirmed: `{}.get('x',{}).address` → `AttributeError`).

Every returned seed is replay-validated, and **replay does not validate
reachability** — the reviewer's M6 is correct. Executing successfully proves
the seed runs, not that it reached the sink the solver aimed at. Proving that
needs a breakpoint or instrumentation, which is not in scope, so the manifest
records `reached_sink: null` and the rationale says the reach claim is
unverified. Empty concretizations are dropped.

**B2. `grammar` — REMOVED from this feature.**
r1 proposed generating seeds from `GrammarGenerator` and the shipped
`HTTP_GRAMMAR`. The reviewer executed it: parser-created subrules are never
registered in `grammar.rules` (`grammar.py:121`) so `_expand`
(`grammar.py:287`) emits their *names* as literals, and the shipped HTTP
grammar yields `b'request_0request_1…request_9'` rather than HTTP.
`GrammarFuzzer.seed_corpus()` (`grammar.py:472`) is separately an in-memory
`List[bytes]`, not a corpus directory — a different concept with the same
name. Repairing nested subrule expansion is its own `fix/`. **No `--grammar`
flag ships.**

### Tier C — not implemented, and why

**C1. `cmplog-operands` — would be strongest; the code cannot work.**
`ComparisonExtractor.extract_from_execution` (`cmplog.py:254-298`) runs the
target then looks for `/tmp/cmplog_{os.getpid()}` (`cmplog.py:289`) — the
*Python* process's PID, a path nothing writes — so it returns `[]` forever
behind an `os.path.exists` guard. `parse_cmplog_output` (`cmplog.py:188-240`)
invents a `type|size|op1|op2` layout, commented "Format varies by AFL++
version" (`cmplog.py:204-206`); AFL++'s CMPLOG data is a shared-memory map.
**[ASSUMED]** as to AFL++'s real format — what is verified is that nothing
produces the file this parser reads. `InputToState.analyze`
(`cmplog.py:386-424`) compounds it with one subprocess per input byte.
Not built on, not claimed; one `fix/` issue covering all three classes.

**C2. `generic-boundary` — `assumed`, behind `--include-generic`.**
Integer boundaries as decimal text and `b"A" * {8,64,256,1024,4096}`.
Components: `GENERIC_PRIOR` → `assumed`. Excluded by default; a corpus made
only of these exits non-zero.

**C3. `structure-from-parsing-code` — no usable primitive. Future work.**
`Decompiler` exists (`analysis/decompile.py:52`) with Ghidra/RetDec/angr
backends and a `get_available_decompilers()` probe (`decompile.py:521`), but
inferring an input grammar from decompiled code is a research task and
Ghidra will not be installed for most users (`decompile.py:74-105`).

**C4. `generic-magic-bytes` — excluded from seeds *and* from the dictionary.**
`DictionaryGenerator.add_magic_bytes()` (`cmplog.py:334-351`) is 13 hardcoded
file-format magics with no relation to the target. r1 said they were harmless
in the dictionary; r2 drops them entirely, because r1's own manifest recorded
`excluded: ["generic-magic-bytes"]` while the prose said they were included —
the reviewer's L4. Excluding them is the choice consistent with the rest of
the design. They are emitted only if the magic appears in the target's own
strings, in which case A4 already covers it.

## UX walkthrough — interactive mode

Design rules, chosen for a plain terminal and for testability:

- `rich.table.Table` for tables (identical to `analyze`'s usage,
  `supwngo/cli.py:95-107`) and `click.prompt(type=click.IntRange(...))` /
  `click.confirm` for input — the same primitives `_guided_fallback` already
  uses (`cli.py:2682` and `cli.py:2689` — both are `click.prompt`;
  r1 mis-cited the second as a `click.confirm` precedent, which the
  reviewer caught (L1). There is no `click.confirm` precedent in the
  guided flow, so this feature uses `click.prompt` for confirmations too,
  with an explicit `y/n` in the prompt text.) **No `rich.live`, no curses, no
  full-screen redraw:** works over ssh, in a dumb terminal, and under
  `click.testing.CliRunner`.
- One flat numbered menu, re-printed after each action. Never a nested
  wizard — there is exactly one level of prompting below the menu.
- Every table row is addressable by its integer, so a whole session is a
  string of digits and newlines. That is what makes test strategy item 2
  possible.

```
$ supwngo fuzz-corpus ./binary_01 -o ./corpus_binary_01

Target: ./binary_01  (amd64, 64-bit, sha256 4f2a…9c1b)
No context document given (-c); running static analysis now.
  Running static analysis... done (4.1s)
  [!] angr CFGFast produced no call sites; 6 dangerous calls have
      caller=unknown. Candidates are keyed by function.
  Input channel: unknown  (fgets/read imported, but an import is not a
                 channel. Pass --input-channel stdin|file|socket to assert.)

┏━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┓
┃ # ┃ Function    ┃ Where    ┃ Risk                     ┃ Suggested          ┃
┡━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━┩
│ 1 │ gets        │ unknown  │ HIGH  no bounds checking │ A4 A5 (C2)         │
│ 2 │ printf      │ unknown  │ MED   format string if   │ A6                 │
│   │             │          │       user-controlled    │                    │
│ 3 │ __isoc99_   │ unknown  │ MED   overflow without   │ A2  "%31s" w=31    │
│   │ scanf       │          │       width specifier    │                    │
│ 4 │ strcpy      │ unknown  │ HIGH  no bounds checking │ A4 (C2)            │
└───┴─────────────┴──────────┴──────────────────────────┴────────────────────┘
  input sources: fgets (stdin/file), read (stdin/file), file_io (file input)

Corpus: 0 seeds.
  [1] show candidate detail   [2] add seeds for a candidate
  [3] add a literal seed      [4] measure seeds
  [5] show / prune corpus     [6] write corpus and exit
  [0] abort without writing
Action [6]: 2

Candidate # [1]: 3
  __isoc99_scanf  —  evidence for seed generation:
    A2 scanf-width   format "%31s" in .rodata, width=31        assumed
       (the string and the scanf import are separate observations;
        nothing ties them together, and 31 is a field width, not a
        buffer size)
    A4 binary-strings 214 strings, 11 look like input tokens   measured
       (bytes came out of the binary) / the "look like input" filter
       is itself assumed, so seeds are labelled assumed
    C2 generic-boundary  int boundaries as decimal text        EXCLUDED
       (no evidence; --include-generic to force, labelled assumed)
  Strategies to apply (comma-separated, or 'a' for evidence-backed only) [a]: a
  + 001_scanf_width_31   (31 B)  assumed
  + 002_scanf_width_32   (32 B)  assumed
  + 003_scanf_width_39   (39 B)  assumed
  + 004_scanf_width_62   (62 B)  assumed
  + 005_str_menu_1       (2 B)   derived
  2 strategies produced 5 seeds; 0 duplicates dropped.
  Nothing here is better than 'assumed' except 005. Consider `supwngo
  offset` first: one measured overflow length beats all four guesses.

Corpus: 5 seeds (0 replayed yet).
Action [6]: 4

Measuring 5 seeds  (replay: exit code + signal; coverage: emulated)
  [!] afl-showmap not on PATH — real edge coverage unavailable.
      Falling back to angr emulation: SLOW, approximate, and it
      under-counts (see corpus.json degradations).
┏━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━┓
┃ # ┃ Seed               ┃ Size ┃ Exit     ┃ New blocks ┃ Verdict    ┃
┡━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━┩
│ 1 │ 001_scanf_width_31 │   31 │ 0        │ 41 (new)   │ keep       │
│ 2 │ 002_scanf_width_32 │   32 │ 0        │ +3         │ keep       │
│ 3 │ 003_scanf_width_39 │   39 │ SIGSEGV  │ +1         │ keep (!)   │
│ 4 │ 004_scanf_width_62 │   62 │ SIGSEGV  │ +0         │ redundant  │
│ 5 │ 005_str_menu_1     │    2 │ 0        │ +0         │ redundant  │
└───┴────────────────────┴──────┴──────────┴────────────┴────────────┘
  Seed 3 crashed the target on its own — that is a finding, not just a seed.
  Run `supwngo triage` on it.
  Drop the 2 redundant seeds? [y/N]: y
  Moved 2 seeds to seeds.discarded/ (reason recorded in corpus.json).

Corpus: 3 seeds (3 replayed, 1 crashing).
Action [6]: 6

Wrote ./corpus_binary_01
  seeds/            3 files  (measured 0, derived 1, assumed 2)
  seeds.discarded/  2 files
  dict/tokens.dict  214 entries  (generic magics excluded)
  corpus.json       manifest, sha256 8b1e…40af
  2 degradations recorded — read them before trusting the corpus.

Context document: --context-out not given, nothing written.
  Re-run with --context-out ctx.json to record this corpus as a fact.

Next: supwngo fuzz ./binary_01 -i ./corpus_binary_01/seeds \
        -o ./fuzz_output -t 3600
```

Note what the walkthrough does *not* claim: no coverage percentage, no
"corpus is good", the `unknown` caller column is surfaced rather than hidden,
the input channel stays `unknown` rather than being guessed from imports, and
the strategy menu tells the operator that a cheaper command would produce
better evidence than the one they just ran. "3 replayed" means three seeds
executed — it does **not** mean three measured coverage results.

## UX walkthrough — `--auto` mode

`--auto` is **Phase 4** and does not ship in Phases 1-3 (it exits 2, "not
yet implemented, needs the context contract"). The walkthrough below is
therefore a *target*, and it is written deliberately without schema-shaped
detail: no fact key spellings, no block names, no `--resolve` syntax. Every
line that touches the document is produced by `corpus_context.py`, and what
it prints is whatever that adapter reports — see "Context integration is
deferred" above for why r1's version of this section had to be deleted.

```
$ supwngo --context ctx.json fuzz-corpus ./binary_01 --auto \
    -o ./corpus_binary_01 --context-out

Target: ./binary_01  (sha256 4f2a…9c1b, build-id 9d3c…)
Context: ctx.json  (identity OK)
  evidence available to this command:
    crash inputs        1   (measured)
    overflow length     72  (measured)
    input channel       not established -> unknown
  4 further facts present but not consumed by this command.

Strategies (evidence-backed only; --symbolic off, --include-generic off):
  A1 crash-replay          1 seed   measured
  A3 offset-lengths        6 seeds  measured  (inherited from the fact)
  A2 scanf-width           4 seeds  assumed   (format "%31s" and a scanf
                                               import are not the same
                                               evidence -- see r2 note)
  A4 binary-strings        3 seeds  measured  (bytes are from the binary)
  A5 menu-token            2 seeds  derived   (1 single-token) /
                                     assumed  (1 sequence)
  A6 fmt-trigger           5 seeds  unknown   (printf sink present; user
                                               control NOT established)
  C1 cmplog-operands       SKIPPED  — not implemented (see plan §Tier C)
  C4 generic-magic-bytes   excluded from both seeds and dictionary

Replay-validating 21 seeds (no coverage; --coverage=none is the default)
  21 executed, 0 failed to run, 2 crashed, 3 exact duplicates dropped.

Wrote ./corpus_binary_01  —  18 seeds
  provenance: measured 8, derived 1, assumed 5, unknown 4
  No seed's provenance is better than its weakest evidence component.
Updated ctx.json  (in place, atomic)
  recorded: this corpus as an artifact, its digest, and the run in history.
  1 fact the adapter could not express was dropped, and said so.

Next: supwngo fuzz ./binary_01 -i ./corpus_binary_01/seeds \
        -o ./fuzz_output -t 3600
$ echo $?
0
```

Read the provenance line, not the seed count: **8 of 18 seeds are better
than a guess.** r1's version of this walkthrough printed "derived 17", which
was the single most misleading line in the document — it laundered a
format-literal coincidence (A2) and a bare `printf` import (A6) into the same
rank as a replayed crash. That is exactly the failure the reviewer's H3
names, and the corrected output above is what honest evidence accounting
looks like: a smaller number, visibly.

Failure case, same command, no context:

```
$ supwngo fuzz-corpus ./binary_01 --auto -o ./corpus
Error: --auto needs evidence and there is none.
  No --context document was given.
  Without it --auto would emit generic filler, which is what
  `afl-fuzz -i <empty>` already does for free.
Do one of:
  supwngo analyze ./binary_01 --context-out ctx.json  # then re-run --context
  supwngo fuzz-corpus ./binary_01 --auto --analyze -o ./corpus
  supwngo fuzz-corpus ./binary_01 -o ./corpus         # interactive
$ echo $?
2
```

Failure case, a document whose stored evidence contradicts this run. r1
showed the schema's own contradiction abort and reproduced its `--resolve`
syntax; that syntax was invalidated by the dependency's rewrite and is
exactly the coupling r2 removes. What `fuzz-corpus` owns is one thing:
**do not silently pick a side, and do not let a raw schema error escape.**

```
$ supwngo --context ctx.json fuzz-corpus ./binary_01 --auto --context-out
Error: the context document and this run disagree about how the target
       reads input (stored: file, this run: stdin).
  One of them is wrong, and a corpus built on the wrong one is wasted time.
  fuzz-corpus will not choose for you.
Resolve with either:
  supwngo fuzz-corpus ./binary_01 --auto --input-channel stdin ...
      # you assert the answer; the seed set is rebuilt for it
  <the context command's own conflict-resolution flag>
      # settle it in the document, then re-run
$ echo $?
2
```

The second option is deliberately *not* spelled out here. Resolving a
document-level conflict is the context command's job and its flag spelling
is its own to define; `fuzz-corpus` names the conflict and defers. The only
resolution `fuzz-corpus` itself offers is `--input-channel`, which is an
operator assertion about the target — a fact this command legitimately owns.

## What "step by step building" means operationally

Menu action 4 measures every unmeasured seed. Two tiers, and the honest
answer to "which tool provides coverage" is the second bullet:

**Always available — replay probe, and `coverage.py` owns the subprocess.**
r1 proposed calling `DynamicAnalyzer.check_crash()`
(`analysis/dynamic.py:321-363`) while "timing the subprocess itself" to
disambiguate a hang. The reviewer's M5 is correct that this is impossible:
`check_crash` catches `TimeoutExpired` **internally** (`dynamic.py:356-358`)
and returns `(False, trace)` with `exit_code = -1`, so an outer caller never
sees the timeout and cannot distinguish it from a SIGHUP kill
(`returncode == -1`). The two requirements are incompatible.

So `measure_replay()` in `supwngo/fuzzing/coverage.py` **runs the subprocess
itself** — `subprocess.run([target], input=seed, capture_output=True,
timeout=t)` — and returns a structured result:

```python
ReplayResult(ran: bool, exit_code: int | None, signal: str | None,
             timed_out: bool, error: str | None)
```

`timed_out` comes from catching `TimeoutExpired` at this level; `signal` is
`signal.Signals(-rc).name` when `rc < 0`, the same decoding
`check_crash` does at `dynamic.py:349-354` — reimplemented in four lines
rather than borrowed from a method that hides the case we need. Requires
nothing but the ability to execute the target. Provenance `measured`.
**This alone makes the interactive loop worthwhile**: it catches seeds that
do not run, and crashes found at corpus-build time.

One thing deliberately not provided: `DynamicAnalyzer` passes
`capture_output=True` but never stores `result.stdout`/`stderr` on its trace
(`dynamic.py:339-346`). `measure_replay()` captures both but the interactive
table shows only exit status and coverage delta. Prompt-echo feedback ("the
program asked for a name") would be genuinely useful and is future work.

**Coverage — `--coverage={none|emulated|showmap}`, default `none`.**

- `emulated` → angr concrete-stdin emulation, **needing no instrumentation**,
  which is the only reason it is offered. **It cannot reuse
  `DynamicAnalyzer.get_coverage()`** — the reviewer's M2 is right that r1
  assumed an API shape that does not exist. That method takes a *list* of
  inputs and returns **one union** `CoverageInfo` for all of them
  (`dynamic.py:266-319`), so it cannot produce the per-seed deltas the
  mockup shows without re-running `CFGFast` per seed; its `timeout`
  parameter is accepted and never used; and it swallows every failure into a
  debug log and returns an empty result.

  `coverage.py` therefore implements `measure_emulated()` itself: build
  `CFGFast` **once**, cache it, and return a per-seed `set[int]` of block
  addresses. Four honest caveats remain, three of them inherent to the
  approach rather than to the old method:
  1. **Slow.** One `CFGFast` for the binary plus a bounded step loop per
     seed. r2 adds the wall-clock guard `get_coverage` lacks.
  2. **No percentage is reported at all.** r1 noted `coverage_percent`'s
     denominator is every `CFGFast` block including unentered library stubs
     (`dynamic.py:290`, `311-314`); rather than caveat a bad number, r2 does
     not compute one. Only the per-seed **delta in new blocks** is shown.
  3. **It under-counts.** `get_coverage` records only `simgr.active`
     addresses (`dynamic.py:306-307`) and never `deadended`, dropping the
     tail of every run; `measure_emulated()` must collect `deadended` too, or
     document that it inherits the same gap. This is an implementation
     decision for Phase 2, not a settled claim here.
  4. **It is emulation, not the process.** angr diverges from real execution
     on syscalls and library models it approximates.
- `showmap` → shell out to `afl-showmap` for real edge coverage. **This is
  the only real coverage option, and it needs instrumentation the user
  probably does not have:** either an `afl-cc`-built target, or
  `afl-showmap -Q` plus `afl-qemu-trace`. `afl-showmap` appears **nowhere**
  in this repo today (verified by grep across `supwngo/`) — it is entirely
  new code. If the tool is absent the command says so and falls back; it
  does not silently pretend.

**Never fabricate a measurement.** If coverage was not obtained, the seed
record omits `observed.new_blocks` and sets `measured_by: null`. It does
not write `0`, because `0` and "unknown" lead to opposite keep/discard
decisions.

**Keep / discard / minimize.** After measuring, the operator can drop seeds.
Discarded seeds move to `seeds.discarded/` with the reason in the manifest —
never deleted, so the decision is reviewable and reversible. Exact-sha256
dedup happens at add time, before measurement, so duplicates never cost a
replay.

## Honest failure modes

| Situation | Behaviour |
|---|---|
| **No context doc, interactive** | Works, and is the *normal* Phase-1-3 path. Candidates come from `binary.plt` + `normalize_plt_name()` directly — **not** from `StaticAnalyzer.analyze()`, which would build one `CFGFast` per dangerous import to produce no call sites (see `_find_callers`). `--analyze` opts into the full analysis when the operator wants a context document populated too. |
| **No context doc, `--auto`** | **Refuse, exit 2.** `--auto` without evidence is filler, and `AFLFuzzer.setup()` writes filler for free (`afl.py:143-147`). Note `--auto` does not exist before Phase 4 at all; until then the flag errors with "not yet implemented; use interactive mode". |
| **Context doc for a different binary** | **Entirely the schema layer's problem**, surfaced through `read_corpus_evidence()`. This plan deliberately does not restate the identity rules, which have already changed twice. What this feature guarantees regardless of which rule wins: it never *raises* the provenance of anything it read, and if the schema layer reports the document as identity-mismatched, every fact from it is clamped to at most `assumed`. A mismatched document can still contribute crash inputs — bytes are bytes — but nothing derived from its addresses or offsets stays `measured`. |
| **Dynamically stripped binary** | Mostly fine. Candidate discovery is PLT-driven and the PLT survives stripping. `binary.symbols` does not, so B1 cannot name non-PLT targets. String extraction is unaffected. |
| **Statically linked + stripped** | **Near-total evidence loss.** `binary.plt` is empty, so every import-gated strategy (A2/A5/A6) has nothing to fire on. Only A4 survives. The command says exactly this and, with no `--include-generic`, produces a strings-only corpus plus a loud warning. Do not pretend a corpus was built from analysis. |
| **Target reads a socket, not stdin** | Socket imports are *suggestive*, not conclusive — `static.py:291-299` reports a synthetic `networking` source, but so would a binary that only calls `connect()` for telemetry. So the channel stays `unknown` unless traced or asserted (see "Input channel is `unknown` unless traced"). Either way **refuse to claim the corpus is fuzzable**: `AFLFuzzer._build_command` (`afl.py:177-222`) emits no `AFL_PRELOAD` and no desock shim, so a seed directory cannot reach a socket target through supwngo. Write the corpus, print a blunt warning naming `preeny`/`libdesock` + `AFL_PRELOAD`, record it in `degradations[]`. |
| **Target reads a file named in argv** | Worse: `_build_command` appends `--` then the binary path (`afl.py:218-220`) and **never emits `@@`**, so supwngo cannot fuzz file-argument targets at all today. Warn, do not claim runnability. Adding `@@` support is a small change to `afl.py` but belongs in its own `fix/` commit. |
| **angr missing or `CFGFast` fails** | The reviewer's M2 is correct that r1 could not do what it claimed: `_find_callers` (`static.py:269`) and `get_coverage` (`dynamic.py:316`) swallow the exception and return an ordinary empty result, so a caller cannot tell failure from legitimate emptiness. r2 therefore **does not try to promote their internal errors**. Instead `supwngo/fuzzing/coverage.py` owns its own angr calls and returns an explicit `Availability(ok: bool, reason: str)`, so "angr unavailable" is a value this feature produced, not an inference about someone else's swallowed exception. `--coverage=emulated` reports unavailable with a reason. |
| **`afl-tmin` / `afl-showmap` absent** | Each step that needs them is skipped with a named degradation, except when the operator *asked* for it (`--coverage=showmap`), in which case the command fails rather than silently downgrading. **No strategy depends on the external `strings(1)`** — A4 uses `Binary.strings()` precisely so the most valuable strategy has no tool dependency, which is why r1's "strings missing" failure mode was removed as unreachable (reviewer L5). |
| **Every seed fails to execute** | **Do not publish a corpus at all.** r1 said "write it with `kept:false` and never leave `seeds/` empty" — the reviewer's M5 caught that those two demands contradict each other, since all-rejected means `seeds/` *is* empty. r2: write `corpus.json` and `seeds.discarded/` for diagnosis, do **not** create `seeds/`, print why, exit non-zero. An absent `seeds/` fails loudly at `fuzz -i`; an empty one gets silently backfilled with `b"A"*8` by `AFLFuzzer.setup()` (`afl.py:143-147`), which is the outcome to avoid. Note that backfill is supwngo's wrapper, not `afl-fuzz` itself — bare `afl-fuzz -i <empty>` errors out. |
| **Every seed is `assumed`** | Exit non-zero with the provenance tally. See risk 4. |
| **Not a TTY, no `--script`, no `--auto`** | `sys.stdin.isatty()` is false → refuse **before the first prompt**, exit 2, message names `--script -`. Do not block on `click.prompt` against a closed stdin. This rule is why test 2 drives `--script -` and not bare piped input — r1's test piped keystrokes into a command that would have refused them (reviewer H5). |

## Files touched

Sized to survive the concurrent-edit situation: `git worktree list` shows
**12 live worktrees** on this repo, several of them editing `cli.py`.

| File | Change | Why |
|---|---|---|
| `supwngo/fuzzing/corpus.py` | **new**, ~420 lines | `Seed`, `CorpusManifest`, `Corpus` (add/dedup/measure/write/load), the `SeedStrategy` registry, `build_auto_corpus()`. All logic. |
| `supwngo/fuzzing/corpus_interactive.py` | **new**, ~260 lines | The menu loop and the rich tables. Deliberately *not* in `cli.py`. |
| `supwngo/fuzzing/coverage.py` | **new**, ~120 lines | `measure_replay()`, `measure_emulated()`, `measure_showmap()` behind one interface, each reporting availability. New code because `afl-showmap` does not exist in this repo. |
| `supwngo/fuzzing/__init__.py` | +~8 lines | Exports, matching the existing pattern (`__init__.py:1-78`). |
| `supwngo/cli.py` | **+~50 lines, appended immediately before `def main()`** (currently `cli.py:2820`; 31 `@cli.command` blocks precede it) | Decorators, flag validation, two calls into the new modules. **No existing line is modified.** This is the merge-conflict-minimising choice. |
| `supwngo/fuzzing/corpus_context.py` | **new**, ~90 lines, **Phase 4 only** | The *only* file in this feature that imports `supwngo/schema/`. Exposes `read_corpus_evidence(doc) -> CorpusEvidence` and `write_corpus_result(doc, corpus)`. Nothing else in the feature knows the document exists. r1 instead planned a `+~40 lines` edit to `supwngo/schema/context_v1.py` naming three exact fact keys and a `fuzz` block; the dependency has since been rewritten twice and that edit would have been wrong both times. The adapter is the whole mitigation: a schema v4 changes one file. |
| `tests/test_fuzz_corpus.py` | **new**, ~380 lines | See below. |
| `CHANGELOG.md` | `### Added` under `[Unreleased]` | Same commit as the code, per the repo contract. |

New CLI surface:

```
supwngo [--context PATH] fuzz-corpus BINARY
    -o, --output DIR              corpus directory (default ./corpus_<name>)
        --auto                    no interaction; requires --context
                                  (or --analyze)
        --analyze                 run static analysis instead of requiring
                                  --context
        --context-out [PATH]      write results back; defaults to the
                                  --context path (Phase 4)
        --input-channel [stdin|file|socket]
                                  operator assertion about how the target
                                  reads input. Recorded as `asserted`.
                                  Without it the channel is `unknown` and
                                  channel-dependent strategies say so.
        --coverage [none|emulated|showmap]   default: none
        --symbolic                enable B1 (off by default; slow, fragile)
        --include-generic         enable C2 generic boundaries (assumed)
        --max-seeds N             cap (default 64)
        --next-fuzzer [afl|libfuzzer|honggfuzz]  tailors the printed "Next:"
                                  line and warns when the named consumer
                                  would mutate seeds/ (default: afl)
        --script PATH|-           replay a scripted session (testing)
```

`--context` is the *group-level* flag owned by the companion plan.
`fuzz-corpus` defines **no short option at all** — not `-c`, and deliberately
not `-i` either, even though `-i` would read naturally for "input", because
`fuzz -i` already means "input corpus directory" (`cli.py:133`) and reusing
the letter for a different meaning one command over is how the `-o`
directory-vs-file mess in this CLI happened in the first place. The only
short option is `-o`, matching every other command.

Two flags r1 listed are **gone**:

- **`--grammar`** is removed because B2 is removed. The reviewer executed
  `grammar.py`'s shipped HTTP grammar and got `b'request_0request_1…'` —
  parser-created subrules are never registered in `grammar.rules`, so
  generation expands their *names* as literals (`grammar.py:121`,
  `grammar.py:287`). Shipping a `--grammar` flag on top of that would have
  produced confident-looking garbage seeds.
- **`--resolve KEY:PROVENANCE`** is removed because it was a verbatim copy of
  a dependency flag that no longer exists in that form. Conflict resolution
  belongs to the context command; `fuzz-corpus` reports the conflict and
  exits 2. `--input-channel` covers the one conflict this command can
  legitimately settle itself.

## Test strategy

1. **Manifest and layout, no binary needed.** Round-trip
   `corpus.json` → `Corpus` → `corpus.json`. Assert `seeds/` contains
   *only* seed files — explicitly `assert not (out/"seeds"/"corpus.json").exists()`
   and no subdirectories — because that invariant is what makes the
   artifact safe for `afl-fuzz -i`. Assert sha256 dedup rejects identical
   bytes with different filenames, and that discards land in
   `seeds.discarded/` with a recorded reason.

2. **The interactive flow, driven non-interactively — via `--script`, not
   piped stdin.** r1 proposed `CliRunner(input="2\n3\n…")`, which the
   reviewer correctly rejected (H5): `CliRunner` pipes stdin, so
   `sys.stdin.isatty()` is false and the command refuses *before the first
   prompt*. The test would have asserted a successful session against a
   command designed to refuse it.

   `--script` is the sanctioned non-TTY path and exists for exactly this:

   ```python
   script = "2\n3\na\n4\ny\n6\n"    # add-for-candidate-3, measure, prune, write
   runner = CliRunner()
   result = runner.invoke(
       cli, ["fuzz-corpus", str(target), "-o", str(out), "--script", "-"],
       input=script,
   )
   assert result.exit_code == 0
   manifest = json.loads((out / "corpus.json").read_text())
   assert {s["strategy"] for s in manifest["seeds"]} == {"scanf-width", "menu-token"}
   ```

   `--script` reads the same numbered answers the prompts would consume, so
   one code path serves both modes: the menu loop pulls its next answer from
   an injected `AnswerSource` that is either `click.prompt` (TTY) or the
   script's next line. That indirection is the testability seam, and it is
   the reason the menu is numeric in the first place.

   **Assert on the artifact, not on printed text.** Table output is cosmetic
   and will churn; `corpus.json` is the contract.

   One real TTY test remains, as a subprocess with a pty, asserting the
   `isatty()`-true path actually prompts. Without it `--script` could drift
   from the interactive path and the suite would never notice.

3. **Measurement tests run as a real subprocess, not under `CliRunner`.**
   This repo already learned this the hard way:
   `tests/test_solve_command.py:159-181` documents that `CliRunner` replaces
   stdio and that end-to-end runs which execute the target must go through
   `subprocess.run([sys.executable, ...])` — the `_run_solve` precedent.
   Anything invoking `measure_replay()` follows it. Separately, unit-test
   `measure_replay()` directly against a tiny C target that (a) exits 0,
   (b) `abort()`s, and (c) sleeps past the timeout, asserting
   `signal == "SIGABRT"` and `timed_out is True` respectively — the
   distinction `check_crash` cannot express.

4. **Strategies against real compiled targets.** `benchmark/corpus/` ships
   15 hand-verified target *sources* plus `benchmark/build_all.sh` and
   `benchmark/corpus.yaml`; **the binaries are not checked in** (verified:
   `05_fmtstr_arbread/` contains only `fmtstr_arbread.c`). So tests compile
   what they need and skip when `gcc` is absent, matching
   `test_solve_command.py:36` (`GCC_AVAILABLE = shutil.which("gcc")`).
   - `05_fmtstr_arbread`: assert `fmt-trigger` seeds appear **and** that they
     are labelled `unknown`. r1's version asserted a `%`-bearing seed given a
     format-literal gate; since that target has **no** `"%`-literal
     (`fmtstr_arbread.c:36` is `printf(name)`), r1's test could not have
     passed. This is now the regression test for that mistake.
   - A freshly compiled `scanf("%31s", …)` target: assert A2 fires, proving
     `normalize_plt_name("__isoc99_scanf")` works, and assert the seeds are
     labelled `assumed` and not `derived`.
   - `01_shellcode_stack`: assert the run completes and produces a corpus.

5. **Refusals, and the context adapter in isolation (Phase 4).**
   Refusals: not-a-TTY without `--script`/`--auto` → exit 2 naming
   `--script`, asserted to happen *before* any prompt. `--auto` before
   Phase 4 → exit 2 "not yet implemented".
   Phase 4 tests the adapter, **not the schema**: feed
   `read_corpus_evidence()` a hand-written document and assert it yields the
   expected `CorpusEvidence`; assert an identity-mismatched document clamps
   every fact to at most `assumed`; assert that when the document exposes no
   normative path to crash bytes, `crash_inputs` is empty and A1 reports
   itself disabled rather than reaching into a block. Because these tests
   target the adapter's dataclass boundary, a schema v4 changes one file and
   these tests keep their meaning.

6. **Tool absence is a first-class test.** `monkeypatch` `shutil.which` to
   return `None` for `afl-tmin` and `afl-showmap` **independently**. r1 also
   tested a missing `strings`; that test is dropped (L5) because A4 reads
   `Binary.strings()` and no strategy depends on the external binary — the
   test asserted a degradation that cannot occur.
   Assert: the run still succeeds; the dependent step is skipped; a
   `degradations[]` entry names the tool; and — the important one —
   `observed.measured_by is None` with `new_blocks` **absent**, not `0`.
   Separately assert that with `--coverage=showmap` and no `afl-showmap`,
   the command **fails loudly** rather than silently downgrading: an
   explicitly requested measurement that cannot be taken is an error, not a
   degradation.

7. **The artifact really is consumable.** Point `AFLFuzzer.setup()` at our
   `seeds/` and assert it does **not** create its `seed_0` fallback
   (`afl.py:144-147`) — i.e. `any(input_path.iterdir())` was already true
   and nothing foreign was added. Then assert `_build_command()`
   (`afl.py:177`) contains `["-i", "<our seeds dir>"]`. This is a unit test
   on the wrapper, not a live `afl-fuzz` run; a live run is a manual smoke
   step in the implementation's Phase 0.

8. **B1 is guarded.** With `--symbolic` and angr importable, assert every
   written `symbolic-reach` seed passed replay validation, and that a
   monkeypatched `concretize_state` returning `b""` (its real failure mode,
   `angr_engine.py:413`) results in **zero** seeds written rather than an
   empty file. Also assert the `path_finder.py:144` `AttributeError` path is
   caught.

9. **Provenance discipline, mechanically and not by label.** r1's version
   of this test asserted the hardcoded per-strategy labels, which is
   circular — it could only ever confirm what the source already said
   (reviewer H3). The replacement tests the *composition rule*:

   - **Positive:** for every seed in a real run, recompute
     `min(e.provenance for e in seed.evidence)` from the recorded evidence
     components and assert it equals the recorded `provenance`. This catches
     a strategy that claims a rank its own evidence does not support, for
     any strategy, including ones added later.
   - **Negative (the one that matters):** construct a synthetic
     `SeedStrategy` that declares `measured` while returning one `assumed`
     evidence component, run it through the registry, and assert the
     framework **rejects it** — raises, or clamps to `assumed` and records a
     `degradations[]` entry. If this test can be made to pass by editing a
     label, the enforcement is still theatre.
   - Assert `generic-boundary` seeds are absent without `--include-generic`
     and `assumed` with it; assert `generic-magic-bytes` never appears in
     `seeds/` **or in `dict/tokens.dict`** (L4: r1 contradicted itself on
     whether C4 tokens reach the dictionary — they do not).

10. **The AFL dictionary is byte-correct.** This is a direct consequence of
    reviewer finding H2: `cmplog.py:353-366` hex-encodes a whole token and
    prefixes a single `\x`, so `b"AB"` is written as `token_0="\x4142"`,
    which is not the AFL format. r1 called that writer "correct". So:
    - Unit-test this feature's own escaper: `b"AB"` → `"\x41\x42"`;
      printable ASCII may stay literal but `"`, `\`, and every byte outside
      `0x20-0x7e` **must** be `\xNN`; an empty token is dropped, not
      written; and assert the total escape count equals `len(token)` for a
      non-printable token.
    - Assert we do **not** call `cmplog.export_afl_dict()`. A test that
      pins the dependency out is the only thing that stops a future
      contributor from "simplifying" back to it.
    - Phase 0 smoke step asserts `afl-fuzz -x dict/tokens.dict` **starts**,
      not merely that `-i` is accepted. A malformed dictionary is rejected
      at startup, so this is the only cheap way to catch the class of bug
      H2 describes. Note this needs an `afl-cc`-built target or `-Q`;
      `benchmark/build_all.sh:178` uses plain `gcc`, so the smoke step
      compiles its own target or passes `-Q`.

11. **Immutability.** Write a corpus, hash `seeds/` recursively, run
    `AFLFuzzer.setup()` + `_build_command()` against it, re-hash, assert
    unchanged. Then assert that requesting a mutating consumer
    (`--next-fuzzer libfuzzer`) prints the copy-first warning.

## Risks

1. **Coverage feedback is the weakest claim in this feature, and it is the
   one a reader will most want to believe.** Real edge coverage needs
   instrumentation: an `afl-cc`-built target, or `afl-showmap -Q` plus
   `afl-qemu-trace`. Neither `afl-showmap` nor any coverage tool exists in
   this repo today. The no-instrumentation alternative
   (`DynamicAnalyzer.get_coverage`, angr emulation) is slow, drops
   `deadended` states, and its percentage has a meaningless denominator.
   **Mitigation:** `--coverage=none` is the default; the step-by-step loop
   is justified by replay/crash detection alone, which needs nothing; the
   manifest never records coverage it did not obtain. If a reviewer takes
   one thing from this plan, it should be that "add a seed, see what it
   covers" is honestly "add a seed, see whether it runs and crashes" unless
   the user has AFL instrumentation.

2. **`cli.py` churn.** 2,826 lines, 12 live worktrees, at least two agents
   editing it (the companion plan flags the same risk at its lines 204-208).
   **Mitigation:** one appended block, zero modified lines, all logic in new
   modules. Sequence after the schema command lands.

3. **The dependency has been rewritten twice during the drafting of this
   plan, and each rewrite invalidated the parts of this plan that described
   it.** The context-schema plan was `v1 DRAFT` at first draft; v1 was
   rejected and became v2 (`c73ee05`), which changed the global flag, the
   identity-mismatch behaviour, the normativity of `blocks`, the provenance
   vocabulary, the merge semantics and the byte encoding. This plan was
   realigned to v2 — and then v2 was *also* rejected and replaced by **v3
   DRAFT** (`d3c7607`), which discards key→value facts entirely in favour of
   candidate sets with `applies_to`, stable candidate IDs and a
   `resolve(key, ctx)` call. Every schema-shaped sentence r1 contained was
   wrong within a day of being written, twice.
   **The mitigation is structural, and it is the main thing r2 changed:**
   this plan no longer describes the schema's shape *at all*. There are no
   fact keys, no block names, no resolution syntax anywhere in Phases 1-3.
   One file — `corpus_context.py` — imports `supwngo/schema/`, and it exposes
   a dataclass boundary (`CorpusEvidence`) that the strategies consume.
   `fuzz-corpus` is fully usable with no `--context` at all. Phase 4 is
   sequenced last and **gated on the schema plan reaching a reviewed,
   non-DRAFT state**. A v4 should cost one file.
   Honest residual risk: if v3 is rejected too, Phase 4 may never be worth
   building, and the "write results back into the context document" half of
   the original request would go unshipped. That is a real possibility and it
   is better stated than papered over.

4. **A plausible-looking corpus built from thin evidence is worse than no
   corpus**, because the operator will fuzz on it for hours and attribute
   the failure to the target. **Mitigation:** every seed carries
   `provenance`; the command prints a per-strategy tally; and the command
   **exits non-zero when no seed is better than `assumed`**. A corpus that
   is all guesses must not look like a success.

5. **The candidate list is thinner than the mockup implies.** Xref discovery
   is effectively non-functional (`static.py:252-255` is a `pass`-bodied
   loop), so `caller` is `unknown` in the common case and the picker is
   function-keyed to survive it. If someone fixes `_find_callers` later, the
   UX gets better for free — but nothing here depends on that.

6. **Three public classes in `cmplog.py` do not work** (`ComparisonExtractor`,
   `InputToState`, and `CMPLOGFuzzer.analyze_comparisons` which depends on
   them). A future contributor could reasonably assume they do and build the
   strongest strategy on sand. **Mitigation:** Tier C1 documents it with
   line references; file a separate issue. Do not "fix" it in this feature —
   a correct CMPLOG shm reader is its own piece of work.

7. **The evidence base is narrower than `DANGEROUS_FUNCTIONS` suggests.**
   The `__isoc99_`/`_chk` naming gap (verified above) means supwngo's own
   analysis silently misses `scanf` and every `_chk`-fortified sink on
   normally-compiled binaries. `normalize_plt_name()` patches this for the
   corpus builder only; `analyze`, `exploit` and the vuln detectors remain
   affected. **Mitigation:** the normalisation is unit-tested and a separate
   `fix/` issue is filed against `static.py`'s dicts. Do not assume the
   candidate table is a complete picture of the target's attack surface.

8. **Strategy inflation.** Seven implemented strategies (A1-A6 plus B1
   behind a flag) is already a lot, and each one is a place to fake evidence.
   r1 listed eleven; B2 was deleted outright and C1-C4 are explicitly not
   implemented. **Mitigation:** the `SeedStrategy` registry computes
   provenance as `min()` over declared evidence components rather than
   accepting a self-declared label, and test 9's negative case asserts a
   strategy that over-claims is rejected. A strategy cannot be added without
   supplying evidence objects.

9. **The plan's own evidence was wrong in five places, and a reviewer had to
   find them.** Independently re-verified: the AFL dictionary writer r1
   called "correct" is malformed (`cmplog.py:353-366`); A2's advertised
   primitive never returns the width it needed (`strings.py:329-339`); A6's
   evidence gate was anti-correlated with the bug class it targets
   (`fmtstr_arbread.c:36` is `printf(name)` with no `%` literal anywhere);
   the interactive test contradicted the command's own TTY refusal; and the
   grammar strategy produces literal rule names instead of protocol bytes.
   Four of the five were *citation-shaped* — a real file and line, with the
   wrong conclusion drawn from it. **Mitigation for the implementation:** the
   Phase 0 smoke step exists precisely because reading source is not
   verification. Anything in this plan not listed under "Verification status"
   as execution-verified should be treated as a claim to test, not a fact to
   build on.

10. **The analysis layer this feature reads from has defects this feature
    does not fix.** `_find_callers()` cannot work at all (`static.py:258`
    passes a `Symbol` object where an address is required, exception
    swallowed); `analyze()` builds one CFG per dangerous import plus another
    in `_analyze_functions`, not the single CFG r1 claimed; `StaticAnalyzer`
    and `get_coverage()` return empty results indistinguishable from
    failure; `path_finder.py:144` raises `AttributeError` on every call;
    three public classes in `cmplog.py` do not work. **Mitigation:**
    `fuzz-corpus` reads `binary.plt` directly and never calls
    `StaticAnalyzer.analyze()` for candidate discovery, and `coverage.py`
    implements its own measurement rather than wrapping `get_coverage()`.
    Each defect gets its own `fix/` issue. **Do not fix them inside this
    feature** — but equally, do not build a strategy that depends on one
    working.

## Implementation sequencing

- **Phase 0 (before writing the feature).** Two live checks, not one. r1 had
  only the first, and the reviewer's H2 is why the second exists:
  1. `afl-fuzz -i` accepts a hand-made `seeds/` directory of the exact shape
     above. This is the assumption the whole artifact format rests on and it
     is currently read-from-source only.
  2. `afl-fuzz -x dict/tokens.dict` **starts** with a dictionary written by
     this feature's escaper. A malformed dictionary is rejected at startup,
     which makes this the cheapest possible detector for the bug class
     `cmplog.py:353-366` already contains.
  Both need an instrumented or `-Q` target; `benchmark/build_all.sh:178`
  compiles with plain `gcc`, so Phase 0 builds its own target or uses `-Q`.
  If either check fails, **stop** — the artifact format is wrong and no
  amount of strategy work rescues it.
- **Phase 1:** `corpus.py` + `normalize_plt_name()` + the composed-provenance
  framework + Tier A strategies + tests 1/4/9/10/11. No CLI, no schema. This
  phase is independently useful and has **zero dependency on the context
  schema**. Write the provenance negative test *first*; it is the only thing
  standing between this design and the label-theatre the reviewer found.
- **Phase 2:** `coverage.py` — `measure_replay()` first (it needs nothing),
  `emulated` second, `showmap` last — + tests 3/6.
- **Phase 3:** `corpus_interactive.py` + the `cli.py` block + tests 2/7.
  `--context`/`--context-out` are accepted and inert here; `--auto` exits 2.
  **At the end of Phase 3 the feature is shippable** and answers the
  interactive half of the request in full.
- **Phase 4 (gated):** `corpus_context.py` + `--auto` + test 5.
  **Do not start until the context-schema plan is reviewed and non-DRAFT.**
  It is currently **v3 DRAFT** (`d3c7607`) after v1 and v2 were both
  rejected. If v3 is rejected as well, this phase should be re-planned, not
  retried.
- **Phase 5:** B1 behind `--symbolic` + test 8. B2 is not in any phase; it
  was removed.

Ordering rationale: the schema is the least stable input and is therefore
last, not first — the opposite of the natural instinct to build the data
contract before the feature. Phases 1-3 deliver a working `fuzz-corpus`
whose output `supwngo fuzz -i` can consume today. The cost of this ordering
is honest: **`--auto`, one of the two modes the request asked for, is the
part most likely to slip**, and the interactive mode's write-back to the
context document slips with it.

CHANGELOG entry lands in the same commit as each phase's code, per the repo
contract.

## Alignment log

| Date | Change |
|---|---|
| 2026-09-24 | First draft, written against context-schema **v1**. |
| 2026-09-24 | Realigned to context-schema **v2** (`c73ee05`) after v1 was rejected and rewritten: `-c` → `--context`; digest-refuse → warn-then-verify with `--target-identity`; `blocks` made non-normative so corpus data is promoted to three `fuzz.*` facts carrying `scope`/`depends_on`; `confidence` dropped; `unknown` added to the provenance vocabulary; merge-contradiction abort + `--resolve` documented as expected behaviour; byte fields pinned to `b64:`; `--context-out` defaults to the `--context` path; schema work resequenced to a gated Phase 4. |
| 2026-09-24 | Added the `__isoc99_scanf` finding (verified by compilation) and the `normalize_plt_name()` requirement it forces; added the `seeds/`-immutability constraint after finding libFuzzer/honggfuzz treat the corpus directory as read-write; corrected `DANGEROUS_FUNCTIONS` to 34 literal / 32 unique keys; switched the replay probe from `run_with_input` to `check_crash`; corrected the claim that `benchmark/corpus/` ships built binaries (it ships sources + a builder). |
| 2026-09-24 | **r2, after an independent peer review returned NOT APPROVED** (5 High / 6 Medium / 5 Low; recorded at `docs/plans/reviews/2026-09-24-interactive-fuzz-corpus-builder-review-r1.md`). Every High was independently re-verified as correct before being applied. Changes: retargeted to schema **v3** (`d3c7607`) by *removing* all schema shape from the plan — `corpus_context.py` adapter + `CorpusEvidence` dataclass, no fact keys, no block names, `--resolve` deleted (H1); r1's claim that `cmplog.export_afl_dict()` is correct **retracted** — it is malformed, this feature writes its own per-byte escaper and Phase 0 now smoke-tests `afl-fuzz -x` (H2); provenance composed as `min()` over declared evidence components with a negative test that rejects over-claiming, replacing r1's label-asserting test (H3); A2 re-derived from `FORMAT_PATTERN` over `Binary.strings()` because `StringAnalyzer` never returns width, and reclassified `derived` → `assumed`; A6's format-literal gate **removed** as anti-correlated with its own bug class and downgraded to `unknown` (H4); interactive tests driven by `--script -` instead of piped stdin, which the TTY rule would have refused (H5); **B2 and `--grammar` removed entirely** after the reviewer executed the shipped grammar and got literal rule names (M1); `coverage.py` implements its own per-seed measurement instead of wrapping `get_coverage()`, and reports no percentage (M2); honggfuzz corrected to safe-with-`--output`, and no runnable `supwngo fuzz --fuzzer honggfuzz` line is printed while `-s` and `cli.py:188` are broken (M3); `_find_callers` described as completely broken rather than weak, and candidate discovery moved to `binary.plt` directly (M4); `measure_replay()` owns the subprocess and returns `ReplayResult`, and an all-failed run creates no `seeds/` at all and exits non-zero (M5); replay described only as an execution sanity check, not sink-reachability proof (M6); `--input-channel` added and the channel left `unknown` unless traced or asserted; citations fixed or withdrawn (L1 `cli.py:2689`, L2 `walkthrough/model.py`, L3 stale schema lines, L4 C4-in-dictionary contradiction, L5 the `strings`-missing test). |
