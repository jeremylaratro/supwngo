## Verdict — APPROVE WITH CHANGES

- No new blocking B4 item was found.
- The revised bwrap mount order is correct for bubblewrap 0.6.1, and the GDB provenance assertion makes that route non-vacuous.
- All five changed mutant rows are consistent with §§2.1 and 3.6; the none-backend subreaper design is sound.
- The 39-read RELRO count is correct, but one read is misclassified; the lint can still become green.
- N3-1 remains unresolved because the governing roadmap contains neither §14 nor AMD-O1.

## Prior-item disposition table

| Item | Disposition | Evidence |
|---|---|---|
| B3-1 mount topology | **RESOLVED** | Hides precede the `/tmp` tmpfs and writable binds are last at [plan §3.3](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:184); the cell is independently mounted at `/tmp/cell` at [line 236](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:236). This avoids the former ancestor-overmount problem. |
| B3-2 answer-key/staging | **RESOLVED** | File-granular transitive staging is specified at [plan line 224](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:224), `benchmark/gen` is hidden at [line 241](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:241), and the fourth positive-controlled generator arm is at [line 366](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:366). The current cwd-relative template default remains at [cli.py:1245](/srv/share/dev/supwngo/supwngo/cli.py:1245). |
| B3-3 GDB under bwrap | **RESOLVED** | The private workspace and `_run_gdb` are specified at [plan line 397](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:397), with a GDB-provenance RED test at [line 457](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:457). Today the hidden host-temporary files are at [offset_finder.py:246](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:246) and [offset_finder.py:275](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:275), while fallback begins at [offset_finder.py:210](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:210). |
| B3-4 RELRO lint | **PARTIAL** | The AST count and green path are repaired at [plan §4.3](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:513), but [heap.py:864](/srv/share/dev/supwngo/supwngo/exploit/walkthrough/families/heap.py:864) passes the read through `_q()`, which is not one of the wrappers the display rule strips. Details are below. |
| B3-5 deterministic pins | **RESOLVED** | Subreaper detection is independent of sessions at [plan line 266](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:266); the corrected rows are at [lines 360–368](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:360). This replaces the current timeout-to-no-crash collapse at [offset_finder.py:502](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:502). |
| N3-1 confidence amendment | **NOT RESOLVED** | The plan defers the field at [plan line 439](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:439) and claims AMD-O1 at [line 748](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:748), but the roadmap still assigns `confidence` to SP-01 at [roadmap line 419](/srv/share/dev/supwngo/docs/roadmaps/2026-11-12-mythos-roadmap.md:419) and ends at §13. |
| N3-2 confidentiality boundary | **RESOLVED** | [Plan lines 201–206](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:201) now correctly limit read confidentiality to explicitly hidden paths. See N4-2 for a networking wording refinement. |
| N3-3 reviewed method truth | **RESOLVED** | The explicit S0 smoke exception is at [plan line 128](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:128), reconciling the generic rule at [roadmap line 81](/srv/share/dev/supwngo/docs/roadmaps/2026-11-12-mythos-roadmap.md:81). |
| B2-1 mutant oracle | **RESOLVED** | The previously confirmed arithmetic remains unchanged, and the last nondeterministic/inconsistent rows are corrected at [plan §3.7](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:337). The current family vocabulary begins at [strategy.py:34](/srv/share/dev/supwngo/supwngo/exploit/strategy.py:34). |
| B2-3 answer-key isolation | **RESOLVED** | All four leak arms now have outside-sandbox readability controls and inside denial at [plan line 366](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:366). |
| B2-4 product sandbox | **RESOLVED** | Every current `OffsetFinder` execution route is assigned to `_run_target` or `_run_gdb` at [plan line 411](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:411); the current routes are GDB at [offset_finder.py:280](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:280), core at [402](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:402), bisect at [502](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:502), and refine at [541](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:541). |
| N2-1 RELRO inventory/lint | **PARTIAL** | All 39 reads are present and classified, but the display classification of [heap.py:864](/srv/share/dev/supwngo/supwngo/exploit/walkthrough/families/heap.py:864) contradicts the stated AST rule. |
| B-1 scoring contract | **RESOLVED** | Per-kind OFF scoring remains explicit at [plan §2.1](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:50), including the mapping to today’s `offset` and `canary_offset` fields at [offset_finder.py:53](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:53). |
| B-4 RELRO migration | **RESOLVED** | The typed normalizer, source correction, migration set and attainable lint exit are now specified at [plan §4.3](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:475). The broken source remains [binary.py:368](/srv/share/dev/supwngo/supwngo/core/binary.py:368). |

## Mutant arithmetic

The round-3 `const`, `list_all`, `abstain_all`, and `truth_echo` arithmetic remains **CONSISTENT**. Only the five changed rows were rechecked:

| Changed row | Assessment |
|---|---|
| `traceback` | **CONSISTENT.** ROBUST fails 28/28. A missing parseable document is ERROR for every non-VOID semantic cell; the four truthless/preflight OFF cells remain VOID under [§2.1 precedence](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:73). |
| `hang` | **CONSISTENT.** Timeout likewise produces ROBUST FAIL and semantic ERROR only where the cell was not already VOID. |
| `grandchild` | **CONSISTENT.** Under bwrap, PID-namespace teardown removes the process before survivor scoring, so ROBUST PASS is correct. On `none`, reparenting to the subreaper produces ROBUST FAIL. |
| `answer_key` | **CONSISTENT.** Four failed, positive-controlled opens followed by valid decline envelopes yield exactly the `abstain_all` semantic/ROBUST split. |
| `time_quorum` | **CONSISTENT and deterministic.** With one repetition, a quorum of two cannot be met regardless of load; exit 3 is unavoidable. |

## Sandbox and offset routing

The new mount topology is valid for bubblewrap 0.6.1:

- Filesystem operations execute in argument order, as documented in the [v0.6.1 manual](https://github.com/containers/bubblewrap/blob/v0.6.1/bwrap.xml#L191-L250).
- Bind sources are resolved through `oldroot`, independently of previous destination mounts, in the [v0.6.1 setup loop](https://github.com/containers/bubblewrap/blob/v0.6.1/bubblewrap.c#L1060-L1120).
- Existing hide directories can receive tmpfs mounts over the read-only `/` bind. Missing targets must be skipped as planned because their creation would hit the read-only root.
- Mounting `/tmp` after hides and then creating all bind destinations beneath that fresh tmpfs is sound. Binding `/tmp/cell` last prevents the scratch-root hide or `/tmp` mount from obscuring it.

The self-check is functionally sufficient: bootstrap execution, a known-readable hidden sentinel, a live host TCP listener, and a writable bind round-trip. The network explanation is slightly wrong: bwrap 0.6.1 explicitly brings isolated loopback **up**; the connection fails because that loopback has no host listener, not because it is down ([network.c](https://github.com/containers/bubblewrap/blob/v0.6.1/network.c#L127-L185)).

The `outer` rule is adequate within the stated passcard trust boundary. The passcard controls both the marker and host namespace baseline, while the actual current PID namespace is kernel-provided; a target child cannot mutate its parent’s namespace or environment. It is not an authenticated assertion for arbitrary direct callers, so the passcard’s own bwrap result must remain authoritative.

The GDB route is non-vacuous: exact offset plus `method.startswith("GDB - ")` prevents the current fallback at [offset_finder.py:218](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:218) from satisfying the test. The separate bisect test also prevents conflating route coverage with offset accuracy.

The none-backend subreaper scan is deterministic once the emitting parent has exited: orphan reparenting occurs before that parent is reaped, and `setsid()` does not affect PPID adoption. The fixture should close inherited output descriptors and signal that the sleeper exists before emitting its final document; see N4-4.

## Claim checks table

| Claim | Status | Evidence |
|---|---|---|
| Exactly 39 non-core AST reads exist at `3b7e6b2`. | **CONFIRMED** | Read-only AST scan found 39: 20 intended migrations, 11 stated allowlist reads, and 8 stated display reads. The additions at [imports.py:524](/srv/share/dev/supwngo/supwngo/analysis/imports.py:524), [cli.py:1037](/srv/share/dev/supwngo/supwngo/cli.py:1037), [facts.py:376](/srv/share/dev/supwngo/supwngo/exploit/walkthrough/facts.py:376), [facts.py:388](/srv/share/dev/supwngo/supwngo/exploit/walkthrough/facts.py:388), and [finiarray_techniques.py:262](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/finiarray_techniques.py:262) are real. |
| The `20 / 11 / 8` classification follows the specified rule. | **PARTIAL** | [heap.py:864](/srv/share/dev/supwngo/supwngo/exploit/walkthrough/families/heap.py:864) is under `_q(...)`, which the rule does not strip. Literal classification is therefore `20 migrate / 12 allowlist / 7 display`, unless `_q` is explicitly recognized as a display wrapper. |
| The RELRO lint can become green. | **CONFIRMED** | The same `_weaponisation_step` qualname already needs a `ProtectionFacts` allowlist entry for [heap.py:860](/srv/share/dev/supwngo/supwngo/exploit/walkthrough/families/heap.py:860), so that typed entry can also cover line 864. No read remains unclassified. |
| GDB succeeds under bwrap rather than falling through. | **MEASURABLE** | The planned test asserts bwrap isolation, `GDB -` provenance, exact distance, and workspace-local script/pattern paths at [plan line 457](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:457). |
| The none-backend survivor test exercises subreaper detection. | **MEASURABLE** | The test requires ROBUST FAIL, records the survivor, kills it and verifies its PID is gone at [plan line 365](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:365). |
| AMD-O1 exists in the governing roadmap. | **FALSE** | The roadmap still contains the old SP-01 `confidence` requirement at [line 419](/srv/share/dev/supwngo/docs/roadmaps/2026-11-12-mythos-roadmap.md:419) and has no §14. |

## New blocking items (B4-n)

None.

## Non-blocking (N4-n)

### N4-1: One RELRO display read is misclassified

Reclassify [heap.py:864](/srv/share/dev/supwngo/supwngo/exploit/walkthrough/families/heap.py:864) as allowlisted `ProtectionFacts`, producing `20/12/7`, or explicitly add `_q()` to the recognized display wrappers.

### N4-2: Tighten the network/self-check wording

Loopback is isolated but up. Also, `--unshare-net` does not by itself hide pathname Unix sockets exposed by the read-only root. Describe the guarantee as IP-network isolation unless sensitive `/run` socket paths are hidden. If the exit criterion literally requires an unsandboxed positive for all four probes, spell out direct `true` and direct host-write/read controls for probes 1 and 4.

### N4-3: Pin the offset workspace’s inside path

`tempfile.mkdtemp(prefix=...)` can honor a caller-supplied `TMPDIR` outside `/tmp`. Either use `dir="/tmp"` or bind an arbitrary host directory to a fixed inside path such as `/tmp/supwngo-offset-work`.

### N4-4: Make the none-backend fixture mechanics explicit

Have the sleeper close inherited stdin/stdout/stderr and signal readiness before the parent emits its valid document and exits. Cleanup should rescan adopted children to a fixed point after killing any intermediate process.

## Required edits before implementation

1. Correct the RELRO classification for `heap.py:864`.
2. Land AMD-O1 in the governing roadmap.
3. Correct the loopback/network wording and make the four positive controls explicit.
4. Pin the workspace’s inside path and specify the survivor fixture’s readiness/FD-closing protocol.