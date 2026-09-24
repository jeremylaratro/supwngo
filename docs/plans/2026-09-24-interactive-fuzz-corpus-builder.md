# Interactive fuzzer corpus builder (`supwngo fuzz-corpus`)

**Date:** 2026-09-24
**Status:** DRAFT — realigned to context-schema v2; awaiting independent review
**Branch:** `feat/interactive-fuzz-corpus-builder-20260924`
**Depends on:** `docs/plans/2026-09-24-standardized-context-schema.md`
  **v2** (commit `c73ee05`). That plan's **v1 was rejected by two
  independent reviews and rewritten**, and v1 named this command in its
  target UX as `supwngo -c ctx.json fuzz-corpus binary_01 --auto`. **v2
  removed `-c` entirely** (`--context` is long-form only, because
  `exploit -c/--crash` is `type=click.Path(exists=True)` and would silently
  eat a context document as crash bytes). This plan is written against v2;
  every earlier `-c` spelling in it has been corrected. The command *name*
  `fuzz-corpus` is still pinned by the contract, not chosen here.

  This churn is the concrete instance of risk 3 below: it fired before
  implementation started. The mitigation held — the consumption surface is
  one adapter function — but it is why "consume the schema through exactly
  one function" is a hard requirement and not a stylistic preference.

## Verification status of this plan

Everything cited below with a `file:line` was read in this repo at
`integration/phases-0-4-7-20260923` (`0997da5`). Claims that are **assumed**
rather than verified are marked **[ASSUMED]** inline. Nothing was executed —
no fuzzer was run — so behavioural claims are read-from-source, not
observed, **with one exception**: the `__isoc99_scanf` PLT-naming finding
below was verified by compiling and inspecting a real binary, because two
strategies depend on it. The most important consequences:

- The "existing fuzzers can run this corpus" claim is derived from reading
  `AFLFuzzer._build_command` (`supwngo/fuzzing/afl.py:177-222`), not from a
  live `afl-fuzz` invocation. Phase 0 of implementation must prove it live.
- AFL++'s actual CMPLOG on-disk/shm format was **not** verified against
  AFL++ source; the claim below is only that supwngo's reader cannot be
  correct as written, which is verifiable from supwngo's own code.

## Goal

Produce a fuzzing corpus that is *justified by evidence supwngo already
gathered*, in two modes:

- **interactive** — present the functions and input sources that earlier
  analysis flagged, let the operator pick, add seeds, measure them, keep or
  discard, repeat; then write the corpus and record it in the context doc.
- **`--auto`** — read a `supwngo.context/v1` document (schema-plan **v2**)
  and build the same artifact with no interaction.

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
  members) and does not need one. Corpus data lives in the context doc as
  `facts` (normative), a `blocks.fuzz` evidence block, and an `artifacts[]`
  reference. This aligns with schema v2, which demoted `ExploitContext` to a
  read-only projection that is never written back.
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
Call-site discovery via `_find_callers()`
(`static.py:231-272`) tries an angr `CFGFast`, and its first loop body is
literally `pass` (`static.py:252-255`); the second loop depends on
`block.successors()` matching a PLT address. When it yields nothing —
which the code itself anticipates — `static.py:218-227` falls back to one
record per imported dangerous function with `caller="unknown"` and
`caller_address=0`.

**Consequence for the UX: the "where" column will usually say `unknown`.**
The candidate picker is therefore keyed on *function*, not call site. This
is the single biggest reason the interactive mockup below looks thinner than
a reader might expect.

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
- **honggfuzz is probably not either.** `--input` (`honggfuzz.py:134`) is
  honggfuzz's corpus directory and it adds to it. **[ASSUMED]**, same
  caveat.

So the rule is: **`seeds/` is an artifact, not a working directory.**
`corpus.json` carries `"immutable": true` and a
`"safe_direct_consumers": ["afl"]` note, and the printed "Next:" line
recommends `-i corpus/seeds` for AFL but `cp -r corpus/seeds work_corpus`
first for libFuzzer/honggfuzz. Test 10 below asserts digests still verify
after an AFL-style read, and asserts the warning is printed when the
operator names a mutating consumer. A `corpus verify` subcommand is *not*
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

1. **`provenance` uses the context schema v2 vocabulary** —
   `measured | derived | assumed | asserted | unknown`. v2 added `unknown`
   (carried over from `walkthrough/model.py:124-143`) and **removed
   `confidence` from facts entirely**, on the grounds that provenance is the
   decision variable and a numeric score merged nothing. `corpus.json`
   follows: no per-seed `confidence`. The block adapter is then a rename,
   not a translation.
2. **Facts carry `scope` and `depends_on`** — also v2 additions.
   `input_channel` is `scope: "build"` (valid for this build, not this
   process) and `depends_on: "binary_symbols"` (it is inferred from PLT
   imports, so a `strip` that removed them would invalidate it). Getting
   `scope` wrong is how a process-scoped fact leaks into a later run; v2
   refuses `process`/`attempt`-scoped facts on reuse, so this feature must
   never label a corpus fact as either.
3. **`degradations[]` is part of the artifact.** Every angr path in this
   codebase swallows failure into a *debug* log (`static.py:399-400`,
   `static.py:269-270`, `analysis/dynamic.py:316-317`). A corpus built with
   angr silently broken looks identical to one built with it working. The
   manifest records the difference and the command prints it.

### What goes into the context doc

v2 changed the rule that matters here: **`facts` is the only normative
store — a consumer reads `facts` and never a block**, and `blocks` are
non-normative evidence that must declare `produces: ["<fact_key>", …]`.
v1 allowed a consumer to read a block directly; v2 does not. So a corpus
cannot live only in `blocks.fuzz`: anything a downstream command needs to
*act* on must be a fact.

Three facts, one evidence block, one artifact reference:

```json
"facts": {
  "fuzz.input_channel@stdin": {
    "value": "stdin", "provenance": "derived",
    "scope": "build", "depends_on": "binary_symbols",
    "derived_from": [],
    "method": "input_sources: fgets/read imported, no socket* imports",
    "by": "supwngo fuzz-corpus", "at": "<ISO-8601>", "stale": false
  },
  "fuzz.corpus.dir": {
    "value": "./corpus_binary_01", "provenance": "measured",
    "scope": "build", "depends_on": "binary_bytes",
    "evidence": {"manifest_sha256": "<sha256 of corpus.json>",
                 "seed_count": 9},
    "by": "supwngo fuzz-corpus", "at": "<ISO-8601>", "stale": false
  },
  "fuzz.dictionary.path": {
    "value": "./corpus_binary_01/dict/tokens.dict",
    "provenance": "derived", "scope": "build",
    "depends_on": "binary_bytes",
    "by": "supwngo fuzz-corpus", "at": "<ISO-8601>", "stale": false
  }
},
"blocks": {
  "fuzz": {
    "produces": ["fuzz.input_channel@stdin", "fuzz.corpus.dir",
                 "fuzz.dictionary.path"],
    "corpus": {
      "dir": "./corpus_binary_01",
      "manifest_sha256": "<sha256 of corpus.json>",
      "seed_count": 11, "kept": 9,
      "strategies_used": ["crash-replay", "scanf-width", "fmt-trigger",
                          "binary-strings", "menu-token"],
      "strategy_tally": {"measured": 1, "derived": 8, "assumed": 0,
                         "asserted": 0, "unknown": 0},
      "degradations": ["afl-showmap absent; coverage via angr emulation"]
    }
  }
},
"artifacts": [
  {"kind": "fuzz_corpus", "path": "./corpus_binary_01",
   "sha256": "<manifest digest>"}
]
```

Notes forced by v2:

- **Seed bytes are never inlined**, per the artifacts rule. When *reading*
  crash inputs for strategy A1, decode v2's `b64:`-prefixed byte encoding —
  v2 pins bytes to base64 with that prefix precisely because the codebase's
  habit of `json.dump(..., default=str)` (e.g. `cli.py:126`) produces an
  irreversible repr. A1 must not `str()`-decode a crash input.
- **Key qualification.** v2 qualifies keys with `conditions` and an `@`
  suffix when a fact's validity depends on how input was supplied
  (`stack.return_offset@stdin`). `fuzz.input_channel` is itself the
  discriminator, so it carries the suffix and a matching `conditions`
  entry; `fuzz.corpus.dir` does not, because a corpus is per-target.
- **Re-running the command is a merge, and v2 can abort it.** Two
  `fuzz-corpus` runs that derive *different* `input_channel` values at equal
  rank and equal scope make the fact `unresolved` and **abort the command**
  until `--resolve` is passed. That is the correct behaviour — the two runs
  disagree about how the target reads input — but it must be *expected*, not
  a surprise, so `fuzz-corpus` prints the resolve hint rather than letting a
  bare schema error surface. Test 5 covers it.
- **`--context-out` defaults to the `--context` path** in v2 (in-place
  accumulate), so the common invocation is
  `supwngo --context ctx.json fuzz-corpus ./t --auto --context-out` with no
  second path. Writes are atomic (temp + `os.replace`) and `flock`-guarded
  by the schema layer; this feature does not implement its own locking.
- **Flags are facts.** v2's rule is that a CLI flag is an `asserted` fact
  scoped to the invocation. So `--grammar http` writes
  `fuzz.grammar = "http"` with `provenance: "asserted"` and an
  `asserted_for` identity; if a later run's target identity differs, v2
  demotes it to `assumed` automatically. Strategy B2's provenance claim is
  therefore enforced by the schema layer, not by this feature's honesty.

## Seed-generation strategies, ranked by evidence

Ranked strictly by *how much of the seed's content comes from the target*.
The `--auto` default set is **A only**. B requires an explicit flag. C is
not implemented.

### Tier A — content read out of the target or measured from it

**A1. `crash-replay` — provenance `measured`. Strongest.**
Any input in the context doc's `crashes` block is a proven reachability
witness. Copy each one in verbatim. Optionally shrink with
`CrashTriager.minimize_crash` (`supwngo/fuzzing/crash_triage.py:579`) or
`AFLFuzzer.minimize_crash` (`afl.py:340-378`) — both need `afl-tmin` on
PATH (`afl.py:351-353`, `crash_triage.py:599`), so minimisation is
best-effort and its absence is a recorded degradation, not a failure.
Evidence: the input demonstrably crashed the target.

**A2. `scanf-width` — provenance `derived`. The best length evidence
available.**
`StringAnalyzer` parses `"%31s"` into `FormatSpecifier(width=31,
type_char='s')` (`strings.py:283-314`). That number is a declared buffer
capacity, read out of the binary's own `.rodata`. Gated on a numeric/string
reader actually being imported — gated on the **normalised** PLT name
(`scanf`/`sscanf`/`fscanf` after stripping `__isoc99_`; see the
`normalize_plt_name` requirement above, without which this strategy never
fires). Emit `width`, `width + 1`, `width + 8`, `width * 2`.
Honest limit: `_check_format_string` does not distinguish a `scanf` format
from a `printf` format, so a `printf("%31s")` would mislead us. The
mitigation is the import gate plus recording the exact format string in
`evidence` so a reviewer can check. **[ASSUMED]** that `%<width>s` in a
binary importing `scanf` is usually a `scanf` format — plausible, not
verified.

**A3. `return-offset-lengths` — provenance `derived`, conditional.**
*Only* when the context doc carries a `stack.return_offset` fact — which is
the schema plan's own worked example (lines 112-121, `"value": 72,
"provenance": "measured"`). Then emit lengths
`{N-1, N, N+1, N+8, N+16, N+64}`. Refuse to synthesise this when the fact
is absent: a guessed threshold is strategy C2, not A3, and must be labelled
as such.

**A4. `binary-strings` — provenance `derived`.**
Every 4..32-byte string in the target becomes a dictionary token and a
candidate seed. Two implementations exist: `DictionaryGenerator.add_from_binary`
(`supwngo/fuzzing/cmplog.py:320-332`) shells out to `strings -n 4`, and
`Binary.strings()` (`core/binary.py:428-454`) is pure Python. **Prefer
`Binary.strings()`** — no external dependency, and `add_from_binary`
silently swallows `FileNotFoundError` (`cmplog.py:331-332`) so a missing
binutils would produce an empty dictionary with no signal. Export via
`DictionaryGenerator.export_afl_dict` (`cmplog.py:353-366`), which is
correct as written (`token_N="\xHEX"`).
As *seeds* (not just dictionary tokens), restrict to strings that look like
input the program expects: menu tokens, short commands, protocol verbs.
Anything else is noise and belongs in the dictionary only.

**A5. `menu-token` — provenance `derived`.**
When the binary's strings contain a menu shape (`"1. "`, `"2) "`, `"> "`,
`"Choice"`) *and* a numeric reader is imported, emit the literal choice
characters with newlines: `b"1\n"`, `b"2\n"`, and short sequences
`b"1\n1\n"`, `b"1\n2\n"`.
Honest limit: **the alphabet is evidence, the sequence is not.** Sequences
are capped at length 3 and their `rationale` says so explicitly.

**A6. `fmt-trigger` — provenance `derived`.**
Gated on a printf-family sink in `dangerous_calls` (`static.py:25-33` covers
`printf/fprintf/sprintf/snprintf/v*printf/syslog`) *and* a format-bearing
string reported by `StringAnalyzer`. Emit `b"%p" * 8`, `b"%s"`, `b"%n"`,
`b"%7$p"`, `b"AAAA%p%p%p%p"`.
Honest limit: the *sink exists* is measured (it is in the PLT); the sink
being *user-controlled* is not established by anything supwngo does
statically. So `derived`, never `measured` — and the rationale says
"printf-family sink present; user control NOT verified".

### Tier B — real, but needs a tool or primitive that may be absent or fragile

**B1. `symbolic-reach` — provenance `derived`. Default OFF (`--symbolic`).**
`PathFinder.find_path_to_function()` (`supwngo/symbolic/path_finder.py:124-179`)
is the right shape: symbolic stdin of `stdin_size` bytes
(`path_finder.py:150`), `explore(find=func_addr)` (`path_finder.py:154-158`),
then `concretize_state` → bytes (`path_finder.py:165`). Three honest
problems:

1. **It targets the PLT address of the sink** (`path_finder.py:142`).
   Reaching `gets@plt` is usually trivial and the resulting seed teaches the
   fuzzer nothing. The interesting target is the *caller*, and `caller` is
   usually `unknown` (see above), so we often cannot name it.
2. **`concretize_state` fails silently.** `supwngo/symbolic/angr_engine.py:398-413`
   returns `b""` on any exception, and its fallback iterates
   `state.solver._stored_solver._constraints` — a private claripy attribute,
   version-fragile. So a "successful" path can yield an empty seed with no
   error.
3. **A real bug in the lookup path.** `path_finder.py:144` is
   `self.binary.symbols.get(func_name, {}).address` — when the name is in
   neither `plt` nor `symbols` this raises `AttributeError` on `{}` instead
   of reaching the intended `logger.warning` on line 146. Any caller must
   wrap it.

Therefore: off by default, hard per-function timeout (`timeout=` is already
a parameter, `path_finder.py:128`), and **every returned seed is
replay-validated before being written** — an empty or non-executing
concretization is discarded, not shipped. `symbolic-reach` seeds that
survive are genuinely valuable; the machinery producing them is not
trustworthy enough to skip the check.

**B2. `grammar` — provenance `asserted` (user-chosen) or `derived`
(protocol string). Requires `--grammar`.**
`GrammarGenerator.generate()` (`supwngo/fuzzing/grammar.py:256`) with the
shipped `HTTP_GRAMMAR` / `JSON_GRAMMAR` (`grammar.py:527`, `540`) or a
user-supplied BNF via `GrammarParser.parse_bnf` (`grammar.py:84`) produces
structured seeds; we write them to `seeds/`.
**Do not confuse this with `GrammarFuzzer.seed_corpus()`**
(`grammar.py:472-474`) — that appends to an **in-memory `List[bytes]`** and
has nothing to do with a corpus directory. Different concept, same word.
Provenance is `asserted` when the operator names the format, `derived` only
when a protocol string (`"HTTP/1"`, `"Content-Length"`) is actually present
in the target.

### Tier C — not implemented, and why

**C1. `cmplog-operands` — would be the strongest strategy; the code that
claims to do it does not work.**
Real comparison operands (magic values, string compares, switch cases)
extracted at runtime are the gold standard for informed seeds. supwngo
appears to have this and does not:

- `ComparisonExtractor.extract_from_execution` (`supwngo/fuzzing/cmplog.py:254-298`)
  runs the target, then looks for `/tmp/cmplog_{os.getpid()}`
  (`cmplog.py:289`). That is the **Python process's** PID, and nothing in
  this repo or in AFL++ writes that path. The `if os.path.exists(...)`
  guard means it returns `[]` forever, silently.
- `parse_cmplog_output` (`cmplog.py:188-240`) invents a
  `type(1)|size(1)|op1|op2` record layout, with the comment "Format varies
  by AFL++ version" (`cmplog.py:204-206`). AFL++'s CMPLOG data is a
  shared-memory map, not that file in that layout. **[ASSUMED]** — I did
  not read AFL++'s source to confirm the exact real format; what *is*
  verified is that nothing produces the file this parser needs.
- `InputToState.analyze` (`cmplog.py:386-424`) builds on the same broken
  extractor and additionally re-executes the target once per input byte,
  so it would be O(len(input)) subprocess spawns even if the extractor
  worked.

So every comparison-derived strategy is future work requiring a real
CMPLOG shm reader or an `afl-showmap`-based extraction. **This plan does
not build on it and does not claim it.** A follow-up issue should be filed
noting that three public classes in `cmplog.py` are non-functional.

**C2. `generic-boundary` — behind `--include-generic`, provenance
`assumed`.**
`0`, `-1`, `2**31-1`, `4294967295`, `9223372036854775807` as decimal text,
and `b"A" * {8,64,256,1024,4096}`. These are cheap and empirically useful,
but they are a **generic prior, not target evidence**. They are labelled
`assumed`, excluded from the default set, and a corpus consisting only of
these causes a non-zero exit (see risk 4).

**C3. `structure-from-parsing-code` — no usable primitive. Future work.**
Deriving input structure from the parsing code is the thing that would make
this feature genuinely strong. `Decompiler` exists
(`supwngo/analysis/decompile.py:52`) with Ghidra / RetDec / angr backends
and a `get_available_decompilers()` probe (`decompile.py:521`), and
`_parse_variables_from_code` (`decompile.py:391`) extracts declared
variables — but turning that into an input grammar is a research task, and
Ghidra will not be installed for most users (`_find_ghidra`,
`decompile.py:74-105`). Not attempted.

**C4. `generic-magic-bytes` — deliberately refused as seeds.**
`DictionaryGenerator.add_magic_bytes()` (`cmplog.py:334-351`) is a
hardcoded list of 13 file-format magics (ELF, ZIP, PNG, …) with **zero
relationship to the target**. Emitting them as seeds would be exactly
"guesswork dressed up as analysis". They are cheap and harmless in the
*dictionary*, so they go there — and the manifest's
`dictionary.excluded: ["generic-magic-bytes"]` records the choice — but they
become seeds **only** if the magic actually appears in the target's strings.

## UX walkthrough — interactive mode

Design rules, chosen for a plain terminal and for testability:

- `rich.table.Table` for tables (identical to `analyze`'s usage,
  `supwngo/cli.py:95-107`) and `click.prompt(type=click.IntRange(...))` /
  `click.confirm` for input — the same primitives `_guided_fallback` already
  uses (`cli.py:2682`, `2689`). **No `rich.live`, no curses, no
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
  Input channel: stdin  (derived: fgets/read imported, no socket imports)

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
    A2 scanf-width   format "%31s" in .rodata, width=31        derived
    A4 binary-strings 214 strings, 11 look like input tokens   derived
    C2 generic-boundary  int boundaries as decimal text        ASSUMED
  Strategies to apply (comma-separated, or 'a' for evidence-backed only) [a]: a
  + 001_scanf_width_31   (31 B)  derived
  + 002_scanf_width_32   (32 B)  derived
  + 003_scanf_width_39   (39 B)  derived
  + 004_scanf_width_62   (62 B)  derived
  + 005_str_menu_1       (2 B)   derived
  4 strategies produced 5 seeds; 0 duplicates dropped.

Corpus: 5 seeds (0 measured).
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

Corpus: 3 seeds (3 measured, 1 crashing).
Action [6]: 6

Wrote ./corpus_binary_01
  seeds/            3 files  (measured 3, derived 3, assumed 0)
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
"corpus is good", and the `unknown` caller column is surfaced rather than
hidden.

## UX walkthrough — `--auto` mode

```
$ supwngo --context ctx.json fuzz-corpus ./binary_01 --auto \
    -o ./corpus_binary_01 --context-out

Target: ./binary_01  (sha256 4f2a…9c1b, build-id 9d3c…)
Context: ctx.json  (supwngo.context/v1, identity OK, 3 history entries)
  blocks present: protections, symbols, dangerous_calls, input_sources,
                  crashes(1), vulns(2)
  facts used: stack.return_offset@stdin = 72
              (measured, scope=build, by 'supwngo offset', stale=false)
  input channel: stdin (derived)

Strategies (evidence-backed only; --symbolic off, --include-generic off):
  A1 crash-replay          1 seed   measured
  A3 return-offset-lengths 6 seeds  derived   (from stack.return_offset=72)
  A2 scanf-width           4 seeds  derived   (format "%31s", width=31)
  A6 fmt-trigger           5 seeds  derived   (printf sink; user control
                                               NOT verified)
  A4 binary-strings        3 seeds  derived   (+214 dictionary tokens)
  A5 menu-token            2 seeds  derived
  C1 cmplog-operands       SKIPPED  — not implemented (see plan §Tier C)
  C4 generic-magic-bytes   dictionary only, not seeds

Replay-validating 21 seeds (no coverage; --coverage=none is the default)
  21 executed, 0 failed to run, 2 crashed, 3 exact duplicates dropped.

Wrote ./corpus_binary_01  —  18 seeds
  provenance: measured 1, derived 17, assumed 0, asserted 0, unknown 0
Updated ctx.json  (in place, atomic)
  + facts["fuzz.input_channel@stdin"]  derived  scope=build
  + facts["fuzz.corpus.dir"]           measured scope=build
  + facts["fuzz.dictionary.path"]      derived  scope=build
  + blocks.fuzz                        produces the 3 facts above
  + artifacts[]  kind=fuzz_corpus  sha256=8b1e…40af
  + history[]    command=fuzz-corpus
$ echo $?
0
```

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

Failure case, a second run that contradicts the stored fact — v2's merge
aborts, and `fuzz-corpus` must surface it legibly rather than let a raw
schema error escape:

```
$ supwngo --context ctx.json fuzz-corpus ./binary_01 --auto --context-out
Error: contradictory fact, refusing to guess.
  fuzz.input_channel@stdin
    stored:   "stdin"  (derived, scope=build, by 'supwngo fuzz-corpus')
    incoming: "socket" (derived, scope=build, this run)
  Equal provenance and equal scope, different value -> unresolved.
  This run and the stored fact disagree about how the target reads input;
  one of them is wrong and a corpus built on the wrong one is wasted time.
Resolve explicitly:
  --resolve fuzz.input_channel@stdin:measured   # trust this run
  --resolve fuzz.input_channel@stdin:asserted   # you know the answer
$ echo $?
2
```

## What "step by step building" means operationally

Menu action 4 measures every unmeasured seed. Two tiers, and the honest
answer to "which tool provides coverage" is the second bullet:

**Always available — replay probe.** Use
`DynamicAnalyzer.check_crash()` (`supwngo/analysis/dynamic.py:321-363`), not
`run_with_input()`: `check_crash` decodes the signal name from a negative
return code (`dynamic.py:349-354`, `signal.Signals(sig).name`) whereas
`run_with_input` (`dynamic.py:87-125`) only records the raw `exit_code`.
Requires nothing but the ability to run the target, and provenance is
`measured`. **This alone makes the interactive loop worthwhile** — it catches
seeds that don't run at all, and it catches crashes at corpus-build time.

Two real gotchas in that code that the corpus builder must work around:

1. **`exit_code == -1` is ambiguous.** Both methods set `exit_code = -1` on
   `subprocess.TimeoutExpired` (`dynamic.py:119`, `dynamic.py:357`), which is
   indistinguishable from a process killed by SIGHUP (`returncode == -1`).
   So the corpus builder must **time the subprocess itself** and set the
   manifest's separate `timed_out` boolean from its own measurement, never
   infer a hang from `exit_code`.
2. **stdout/stderr are discarded.** `capture_output=True` is passed but
   `result.stdout`/`result.stderr` are never stored on the trace
   (`dynamic.py:339-346`), so "what did the program print" is unavailable.
   The plan does **not** add it — the interactive table shows exit status and
   coverage delta only. If a later phase wants prompt-echo feedback, that is
   a separate change to `dynamic.py`.

**Coverage — `--coverage={none|emulated|showmap}`, default `none`.**

- `emulated` → `DynamicAnalyzer.get_coverage()`
  (`dynamic.py:266-319`). This is **angr concrete-stdin emulation** and
  needs **no instrumentation at all**, which is why it is offered. Four
  honest caveats, all read from the code:
  1. **Slow.** One `CFGFast` plus up to 1000 `simgr.step()` calls per seed
     (`dynamic.py:301-304`), with no wall-clock guard inside the loop.
  2. **`coverage_percent` is meaningless.** Its denominator is every
     `CFGFast` block in the whole binary (`dynamic.py:290`, `311-314`),
     including library stubs the program never enters. Only the *delta in
     `coverage.basic_blocks`* between seeds is usable, which is what the
     table shows as "New blocks".
  3. **It under-counts.** It records addresses only from `simgr.active`
     (`dynamic.py:306-307`) and never inspects `deadended`, so the tail of
     every run is dropped.
  4. **It is emulation, not the process.** angr can diverge from real
     execution on syscalls and library models.
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
| **No context doc, interactive** | Works. Runs `StaticAnalyzer.analyze()` live, costing one angr `CFGFast`. Prints what degraded. |
| **No context doc, `--auto`** | **Refuse, exit 2** with the message above. `--auto` without evidence is filler, and `AFLFuzzer.setup()` already writes filler for free (`afl.py:143-147`). `--auto --analyze` is the escape hatch. |
| **Context doc for a different binary** | Delegated entirely to the schema layer, and **v2 changed this behaviour**: a digest mismatch now **warns** and then *verifies* a sample of `binary_bytes` facts against the loaded binary, refusing only on verification failure. `--target-identity=sha256\|build-id\|none` replaces v1's blanket `--context-mismatch=allow`. For this feature that is strictly better — a stripped or rebuilt copy with identical code still yields valid seeds, and v1 would have refused it. Not re-implemented here. **But note the gap v2 leaves:** most corpus-relevant facts are not address-shaped, so instruction verification cannot vouch for them; `fuzz.input_channel` in particular would pass a verification sweep that never examined it. This feature therefore re-derives `input_channel` from the live binary rather than trusting the doc's copy when the digest mismatched, and records `provenance: "derived"` from the fresh derivation. |
| **Dynamically stripped binary** | Mostly fine. `dangerous_calls` and `input_sources` are PLT-driven (`static.py:201`, `284`) and the PLT survives stripping. `binary.symbols` does not, so the `caller` column is `unknown` (already usually true) and B1 cannot name non-PLT targets. `StringAnalyzer` is unaffected. |
| **Statically linked + stripped** | **Near-total evidence loss.** `binary.plt` is empty, so `dangerous_calls` and `input_sources` are both empty and A2/A5/A6 have nothing to gate on. Only A4 (`binary-strings`) survives. The command says exactly this, and with no `--include-generic` produces a strings-only corpus and a loud warning. Do not pretend a corpus was built from analysis. |
| **Target reads a socket, not stdin** | Detected — `static.py:291-299` reports `{"function": "networking", "type": "network socket"}`. Record `fuzz.input_channel = "socket"` and **refuse to claim the corpus is fuzzable**: `AFLFuzzer._build_command` (`afl.py:177-222`) emits no `AFL_PRELOAD` and no desock shim, so a seed directory cannot be driven into a socket target by anything in supwngo. Write the corpus (the seeds are still valid *inputs*), print a blunt warning naming `preeny`/`libdesock` + `AFL_PRELOAD` as the missing piece, exit 0 with the warning recorded in `degradations[]`. |
| **Target reads a file named in argv** | Same class of problem, and worse: `_build_command` appends `--` then the binary path (`afl.py:218-220`) and **never emits `@@`**, so supwngo cannot fuzz file-argument targets at all today. Record `input_channel="file"`, warn, do not claim runnability. Adding `@@` support is a one-line change to `afl.py` but belongs in a separate `fix/` commit, not here. |
| **angr missing or `CFGFast` fails** | Every angr call site already `try/except`s into a *debug* log (`static.py:399`, `static.py:269`, `dynamic.py:316`). The corpus builder **promotes these to visible degradation lines** and records them in `corpus.json`. `--coverage=emulated` becomes unavailable and says so. |
| **`strings` / `afl-tmin` / `afl-showmap` absent** | Each strategy that needs them is skipped with a named degradation. A4 prefers `Binary.strings()` (no external tool) precisely so the most valuable strategy has no dependency. |
| **Every seed fails to execute** | Write the corpus with all records `kept: false`, print why, **exit non-zero**. Never leave an empty `seeds/`: `afl-fuzz -i` on an empty directory silently gets `b"A" * 8` (`afl.py:144-147`) and the operator would never learn the builder did nothing. |
| **Every seed is `assumed`** | Exit non-zero with the provenance tally. See risk 4. |
| **Not a TTY and no `--auto`** | `sys.stdin.isatty()` is false → refuse with "pass --auto, or pipe a session script to --script -". Do **not** block on `click.prompt` against a closed stdin. |

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
| `supwngo/schema/context_v1.py` | +~40 lines | Register the `fuzz` block (with its `produces` list) and the three `fuzz.*` facts. **Owned by the companion plan**, which is still DRAFT and gated on two unmerged prerequisites — so this is Phase 4 and lands last. Until then `fuzz-corpus` works standalone and `--context`/`--context-out` are accepted-but-inert with a one-line notice. |
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
        --context-out [PATH]      write facts back; defaults to the
                                  --context path (v2 in-place accumulate)
        --resolve KEY:PROVENANCE  resolve a v2 merge contradiction
                                  (repeatable)
        --coverage [none|emulated|showmap]   default: none
        --symbolic                enable B1 (off by default; slow, fragile)
        --include-generic         enable C2 generic boundaries (assumed)
        --grammar [http|json|PATH] enable B2
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

## Test strategy

1. **Manifest and layout, no binary needed.** Round-trip
   `corpus.json` → `Corpus` → `corpus.json`. Assert `seeds/` contains
   *only* seed files — explicitly `assert not (out/"seeds"/"corpus.json").exists()`
   and no subdirectories — because that invariant is what makes the
   artifact safe for `afl-fuzz -i`. Assert sha256 dedup rejects identical
   bytes with different filenames, and that discards land in
   `seeds.discarded/` with a recorded reason.

2. **The interactive flow, driven non-interactively.** This is the answer
   to "how do you test an interactive flow". Because the menu is
   `click.prompt` + `IntRange`, a whole session is a keystroke string:

   ```python
   runner = CliRunner()
   result = runner.invoke(
       cli, ["fuzz-corpus", str(target), "-o", str(out)],
       input="2\n3\na\n4\ny\n6\n",      # add-for-candidate-3, measure, prune, write
   )
   assert result.exit_code == 0
   manifest = json.loads((out / "corpus.json").read_text())
   assert {s["strategy"] for s in manifest["seeds"]} == {"scanf-width", "menu-token"}
   ```

   **Assert on the artifact, not on printed text.** Table output is
   cosmetic and will churn; `corpus.json` is the contract.

3. **Measurement tests run as a real subprocess, not under `CliRunner`.**
   This repo already learned this the hard way:
   `tests/test_solve_command.py:159-181` documents that `CliRunner` replaces
   stdio and that end-to-end runs which execute the target must go through
   `subprocess.run([sys.executable, ...])` instead — the `_run_solve`
   precedent. Anything touching `DynamicAnalyzer.run_with_input` follows it.

4. **`--auto` against the existing benchmark corpus.** `benchmark/corpus/`
   ships 15 hand-verified target *sources* plus `benchmark/build_all.sh`
   and a `benchmark/corpus.yaml` manifest. **The binaries are not checked in**
   — verified: `benchmark/corpus/05_fmtstr_arbread/` contains only
   `fmtstr_arbread.c`. So these tests must either invoke `build_all.sh` or
   compile the one target they need, and skip when `gcc` is absent — matching
   this repo's existing pattern (`test_solve_command.py:36`,
   `GCC_AVAILABLE = shutil.which("gcc")`). Parametrise over
   `05_fmtstr_arbread` (assert a `%`-bearing seed with
   `strategy == "fmt-trigger"` appears) and `01_shellcode_stack`.
   Additionally compile a one-line `scanf("%31s", …)` target and assert A2
   fires on it — that is the regression test for the `__isoc99_` finding.

5. **Refusals and merges.** `--auto` with no `--context` → exit 2, message
   names `--analyze`. Not-a-TTY with no `--auto` → exit non-zero, does not
   hang. Identity mismatch → the schema layer warns and instruction-verifies
   (v2 behaviour), and this feature re-derives `input_channel` rather than
   trusting the stale copy. **Contradictory-fact abort:** run `fuzz-corpus`
   twice against docs that disagree on `fuzz.input_channel`, assert exit 2
   with the `--resolve` hint, then assert `--resolve <key>:measured`
   proceeds. Also assert the same-value re-run **dedupes** rather than
   growing `superseded[]` — v2 specifies equal-rank/equal-value as a
   no-history refresh, and a corpus rebuild is the commonest case of it.

6. **Tool absence is a first-class test.** `monkeypatch` `shutil.which` to
   return `None` for `strings`, `afl-tmin`, `afl-showmap` independently.
   Assert: the run still succeeds; the dependent strategy is skipped; a
   `degradations[]` entry names the tool; and — the important one —
   `observed.measured_by is None` with `new_blocks` **absent**, not `0`.

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

9. **Provenance discipline.** Assert no strategy in the default set ever
   emits `provenance: "measured"` except `crash-replay`; assert
   `generic-boundary` seeds are absent without `--include-generic` and are
   `assumed` with it; assert `generic-magic-bytes` never appears in
   `seeds/`.

10. **Immutability.** Write a corpus, hash `seeds/` recursively, run
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

3. **The dependency is unstable, and this already cost a revision.** The
   context-schema plan was `v1 DRAFT` when this plan was drafted; it was
   **rejected by two independent reviews and rewritten as v2** (`c73ee05`)
   mid-drafting. v2 removed `-c`, replaced `--context-mismatch=allow` with
   `--target-identity=`, made `blocks` non-normative, added `scope` /
   `depends_on` / `unknown`, removed `confidence`, added a fail-closed merge
   abort, and pinned bytes to base64. Every one of those touched this plan.
   v2 is *itself* still `DRAFT` and gated on two unmerged prerequisites
   (`feat/walkthrough-engine-20260923` and a `DetailedProtections.to_dict()`
   fix), so a v3 is entirely possible.
   **Mitigation, now load-bearing rather than stylistic:** all consumption
   and emission goes through exactly one adapter in
   `supwngo/fuzzing/corpus.py` (`from_context_doc()` / `to_context_facts()`);
   `fuzz-corpus` is fully usable with no `--context` at all; and Phase 4 —
   the only phase that touches the schema — is sequenced **last** so a v3
   costs one function, not a rewrite. Do not start Phase 4 until the schema
   plan reaches a reviewed, non-DRAFT state.

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

8. **Strategy inflation.** Eleven strategies is already a lot, and each one
   is a place to fake evidence. **Mitigation:** the `SeedStrategy` registry
   requires every strategy to declare its `provenance` and to return an
   `evidence` dict, and test 9 asserts the discipline mechanically rather
   than by review.

## Implementation sequencing

- **Phase 0 (before writing the feature):** manually confirm `afl-fuzz -i`
  accepts a hand-made `seeds/` directory of the exact shape above, on one
  `benchmark/corpus/` target. This is the one assumption the whole artifact
  format rests on and it is currently read-from-source only.
- **Phase 1:** `corpus.py` + `normalize_plt_name()` + Tier A strategies +
  tests 1/4/9/10. No CLI, no schema. This phase is independently useful and
  has **zero dependency on the context schema**.
- **Phase 2:** `coverage.py` (replay first, `emulated` second,
  `showmap` last) + tests 3/6.
- **Phase 3:** `corpus_interactive.py` + the `cli.py` block + tests 2/7.
  `--context`/`--context-out` are accepted and inert here.
- **Phase 4 (gated):** the schema `fuzz` block + facts adapter + test 5.
  **Do not start until the context-schema plan is reviewed and non-DRAFT**
  and its two prerequisites (`feat/walkthrough-engine-20260923`, the
  `DetailedProtections.to_dict()` fix) have merged. Phases 1-3 ship without
  it; if the schema slips to v3, only this phase changes.
- **Phase 5:** B1/B2 behind their flags + test 8.

Ordering rationale: the schema is the least stable input and is therefore
last, not first — the opposite of the natural instinct to build the data
contract before the feature. Phases 1-3 deliver a working `fuzz-corpus`
whose output `supwngo fuzz -i` can consume today.

CHANGELOG entry lands in the same commit as each phase's code, per the repo
contract.

## Alignment log

| Date | Change |
|---|---|
| 2026-09-24 | First draft, written against context-schema **v1**. |
| 2026-09-24 | Realigned to context-schema **v2** (`c73ee05`) after v1 was rejected and rewritten: `-c` → `--context`; digest-refuse → warn-then-verify with `--target-identity`; `blocks` made non-normative so corpus data is promoted to three `fuzz.*` facts carrying `scope`/`depends_on`; `confidence` dropped; `unknown` added to the provenance vocabulary; merge-contradiction abort + `--resolve` documented as expected behaviour; byte fields pinned to `b64:`; `--context-out` defaults to the `--context` path; schema work resequenced to a gated Phase 4. |
| 2026-09-24 | Added the `__isoc99_scanf` finding (verified by compilation) and the `normalize_plt_name()` requirement it forces; added the `seeds/`-immutability constraint after finding libFuzzer/honggfuzz treat the corpus directory as read-write; corrected `DANGEROUS_FUNCTIONS` to 34 literal / 32 unique keys; switched the replay probe from `run_with_input` to `check_crash`; corrected the claim that `benchmark/corpus/` ships built binaries (it ships sources + a builder). |
