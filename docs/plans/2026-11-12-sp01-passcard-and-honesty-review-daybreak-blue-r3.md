## Verdict — REJECT

- The requested §3.7 arithmetic is now correct: the `const`, `list_all`, `abstain_all`, and `truth_echo` expectations are internally consistent.
- B2-2 and N2-2–N2-5 are resolved. B2-1, B2-3, B2-4, and N2-1 remain partial or unresolved.
- The sandbox mount layout hides the scratch-root ancestor of the writable cell, potentially making the cell and `cwd` inaccessible.
- The generator-source answer-key arm is still absent, and the proposed RELRO lint cannot become green with its stated exact/stale-entry policy.
- The GDB route lacks a non-vacuous sandboxed positive control, while the TIME and `none`-backend survivor mutants are not deterministic/satisfiable as specified.

## Prior-item disposition table

| Item | Disposition | Evidence |
|---|---|---|
| B2-1 mutant oracle | **PARTIAL** | The requested arithmetic and ordering are corrected in [plan §3.7](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:289), against the 15-family vocabulary in [§2.2](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:82); the current upstream enum begins at [strategy.py:34](/srv/share/dev/supwngo/supwngo/exploit/strategy.py:34). However, the roadmap’s generator-source mutant is still missing, `--load-max 0` does not guarantee zero samples, and the `none` survivor test conflicts with session-only scanning. |
| B2-2 multiple distances | **RESOLVED** | [Plan §2.1](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:49) defines eight `(target, kind)` cells and maps `offset`/`canary_offset`. Current serialization has both value fields at [offset_finder.py:53](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:53), while `kind` is correctly identified as a field to add. |
| B2-3 answer-key isolation | **PARTIAL** | Accepted runs now require bwrap and use staged cells in [plan §3.3](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:171). But `benchmark/gen` and its generator-source probe from [roadmap §6](/srv/share/dev/supwngo/docs/roadmaps/2026-11-12-mythos-roadmap.md:383) are absent from the hide list and mutant at [plan line 318](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:318). The current template default really is cwd-relative at [cli.py:1245](/srv/share/dev/supwngo/supwngo/cli.py:1245). |
| B2-4 product sandbox | **PARTIAL** | All four current `OffsetFinder` routes are identified in [plan §4.1](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:339): GDB [offset_finder.py:280](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:280), core [402](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:402), bisect [502](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:502), and refine [541](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:541). GDB’s host-`/tmp` scripts are not accounted for, and no test proves the GDB method itself succeeded under bwrap. |
| N2-1 RELRO inventory/lint | **NOT RESOLVED** | The alias at [heap_techniques.py:251](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/heap_techniques.py:251) is now listed in [plan §4.3](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:409). The exact allowlist is nevertheless stale/incomplete; details are in the claim table and B3-4 below. |
| N2-2 identifier count | **RESOLVED** | [Plan §4.5](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:522) replaces the hand count with generated exact inventory. The two live non-docstring strings remain at [offset_finder.py:887](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:887) and [heap_strlen.py:598](/srv/share/dev/supwngo/supwngo/exploit/walkthrough/families/heap_strlen.py:598). |
| N2-3 command envelopes | **RESOLVED** | Success/failure pairs are command-specific in [plan §3.6](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:258). This addresses the always-present current `error` key at [offset_finder.py:53](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:53) and current decompile rc-0 error document at [cli.py:2129](/srv/share/dev/supwngo/supwngo/cli.py:2129). |
| N2-4 entry RVA scope | **RESOLVED** | [Plan §4.4](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:469) explicitly excludes prelinked ELF. The current Java fallback being replaced is at [SupwngoDecompile.java:87](/srv/share/dev/supwngo/supwngo/analysis/ghidra_scripts/SupwngoDecompile.java:87). |
| N2-5 roadmap path | **RESOLVED** | The canonical path cited at [plan line 3](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:3) now exists, with SP-01 beginning at [roadmap line 364](/srv/share/dev/supwngo/docs/roadmaps/2026-11-12-mythos-roadmap.md:364). |
| B-1 scoring contract | **PARTIAL** | Per-kind OFF scoring and the requested arithmetic are repaired in [§2.1](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:49) and [§3.7](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:289). The remaining mutant inconsistencies keep the overall oracle partial. |
| B-4 RELRO migration | **PARTIAL** | The typed source/migration design is substantially improved in [§4.3](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:409), and the broken current source remains visible at [binary.py:368](/srv/share/dev/supwngo/supwngo/core/binary.py:368). The lint inventory itself is still wrong. |
| N-1 roadmap reference | **RESOLVED** | Canonical file now exists at [mythos-roadmap.md](/srv/share/dev/supwngo/docs/roadmaps/2026-11-12-mythos-roadmap.md:1). |
| N-3 rc/envelope consistency | **RESOLVED** | Explicit envelope pairs and ROBUST validation appear at [plan lines 258–278](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:258). |
| N-6 copying is not sandboxing | **RESOLVED** | The accepted baseline now requires actual bwrap isolation, while `none` is only an unisolated observation, at [plan lines 207–212](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:207). The newly found mount-topology defects are separate B3 items. |

## Mutant arithmetic

### `const` OFF — **CONSISTENT**

There are eight OFF cells:

- Known: sick `buf_to_ret`, rocket `buf_to_ret`, ancient `buf_to_ret`, ancient `buf_to_canary`.
- VOID: snow, auth, sabotage, bon.

For `offset=0`, `canary_offset=null`:

- Three wrong numeric return offsets → **FAIL 3**.
- Missing ancient canary value → **ABSTAIN 1**.
- Four unscored cells → **VOID 4**.

Thus coverage is `3/8`, exact `0/8`, selective `0/3`, and net `−3/8`. This matches [§3.7 line 301](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:301).

### `list_all` — **CONSISTENT**

The ordered top three are `ret2win`, `ret2libc`, `rop_syscall`.

| Target | Accepted family in top 3? | METHOD-L |
|---|---:|---:|
| sick | No (`srop`) | FAIL |
| rocket | Yes (`ret2win`, `ret2libc`) | PASS |
| snow | Yes (`rop_syscall`) | PASS |
| ancient | Yes (`ret2libc`, `rop_syscall`) | PASS |
| auth | No (`objptr_hijack`) | FAIL |
| sabotage | No (`env_hijack`) | FAIL |
| bon | No (`heap_metadata`) | FAIL |

Split: **PASS 3 / FAIL 4**; exact and selective are `3/7`, net is `−1/7`.

Whole-list precision after deduplication:

- `1/15`: sick, auth, sabotage, bon.
- `2/15`: rocket, snow, ancient.
- Macro mean: `(4×1 + 3×2)/(7×15) = 10/105 = 2/21`.

This matches [§3.7 line 303](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:303).

### `abstain_all` — **CONSISTENT**

A well-formed rc-2 failure envelope is a semantic decline but a valid ROBUST envelope:

- METHOD-R0, METHOD-L, TEMPLATE, DECOMP: **ABSTAIN 7/7**.
- OFF: **ABSTAIN 4**, **VOID 4**.
- No semantic PASS; coverage and exact are zero.
- ROBUST: **PASS 28/28**.

This now correctly separates content from transport at [§3.6 lines 255–278](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:255).

### `truth_echo` — **CONSISTENT**

The OFF split is:

- PASS: sick return, rocket return, ancient return, ancient canary.
- VOID:
  - `snow_scan`: `no-truth`
  - `auth-or-out`: `no-truth`
  - `sabotage`: `interp_empty`
  - `bon-nie-appetit`: `interp_empty`

Preflight takes precedence for the latter two. The shipped relative-loader premise is documented at [test_fmtstr_probe_unspawnable.py:17](/srv/share/dev/supwngo/tests/test_fmtstr_probe_unspawnable.py:17).

OFF coverage/exact are `4/8`, selective is `4/4`, net is `4/8`; all other semantic cells PASS and ROBUST is **28/28**.

## Sandbox and offset routing

| Area | Assessment |
|---|---|
| bwrap flags | The basic 0.6.1-compatible design is sound: read-only root, private `/tmp`, `/dev`, `/proc`, PID/network namespaces, `--die-with-parent`, and `--new-session`. No unsupported overlay flag is assumed. |
| Mount layout | **Wrong as written.** The cell is beneath the scorer scratch root, yet the cell is bound writable and the scratch-root ancestor is then hidden with tmpfs at [plan lines 194–205](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:194). The parent overmount hides the child mount; `--chdir <cell>` can consequently fail. |
| Self-check | **Partial.** The hidden-file probe must target a known existing sentinel. The socket test needs a known-reachable parent listener and an unsandboxed positive control; merely connecting to an arbitrary unavailable endpoint is vacuous. |
| Staging allowlist | **Partial.** Copying only named files is good, but “RPATH directories” must mean resolved dependency files, not recursively copying a directory that could contain sources/debug siblings. `benchmark/gen` also needs an explicit hide/probe. |
| Acceptance | **Sound.** Only `isolation:"bwrap"` can satisfy exit; `none` cannot. |
| GDB | **Incomplete.** Current pattern and script files are created in host `/tmp` at [offset_finder.py:245](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:245) and [275](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:275), which is replaced by sandbox tmpfs. They must be created in a bound private directory. |
| Core method | **Sound.** Skipping core under bwrap is appropriate because `core_pattern=core`, the binary cwd is read-only, and bwrap 0.6.1 has no overlay. The proposed removal of the current cwd/global-`/tmp` scans at [offset_finder.py:432](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:432) is correct. |
| Tri-state bisect | **Sound.** Treating TIMEOUT/SPAWN_ERROR as UNKNOWN and aborting removes the current timeout-to-no-crash collapse at [offset_finder.py:502](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:502) and fabricated fallback at [565](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:565). |
| GDB RED proof | **Vacuous currently.** `find_offset()` falls through from GDB to core and bisect at [offset_finder.py:210](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:210). The relative-interpreter positive control can therefore pass without GDB working. It must assert the returned method/provenance is GDB under bwrap. |

## Claim checks table

| Claim | Status | Evidence |
|---|---|---|
| `heap_techniques.py:251-252` contains a local RELRO alias and comparison. | **CONFIRMED** | Assignment at [heap_techniques.py:251](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/heap_techniques.py:251), read/comparison at line 252. |
| The display-only RELRO rule and stated allowlist are complete and can green. | **WRONG** | The rule would catch the wrapper and alias, but the inventory is inconsistent. Missing non-display reads include [imports.py:524](/srv/share/dev/supwngo/supwngo/analysis/imports.py:524), [walkthrough/common.py:393](/srv/share/dev/supwngo/supwngo/exploit/walkthrough/common.py:393), and [walkthrough/facts.py:376](/srv/share/dev/supwngo/supwngo/exploit/walkthrough/facts.py:376) plus line 388. Conversely, `walkthrough/common.py:483` is text inside a generated-code string beginning at [line 461](/srv/share/dev/supwngo/supwngo/exploit/walkthrough/common.py:461), not an AST attribute read, while [cvss.py:453](/srv/share/dev/supwngo/supwngo/reporting/cvss.py:453) reads a local string parameter. Those exact entries would be stale, which the plan says must fail. `got_plt.py:105` also reads pwntools `elf.relro`, not `GOTAnalysis.relro`: [got_plt.py:105](/srv/share/dev/supwngo/supwngo/exploit/got_plt.py:105). |
| `template` defaults its output into the process cwd at `cli.py:1245-1249`. | **CONFIRMED** | The relative default is constructed at [cli.py:1245](/srv/share/dev/supwngo/supwngo/cli.py:1245) and opened without rebasing at line 1248. |
| The `offset_finder.py` references for GDB/core/bisect/refine are accurate. | **CONFIRMED** | GDB [280](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:280), core [402](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:402), bisect [502](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:502), refine [541](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:541); relative path retention is [173](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:173). |
| Exactly the two named non-docstring target-identifier strings remain. | **CONFIRMED** | `fill_ammo` is a live `WIN_NAMES` entry at [offset_finder.py:887](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:887); `bon-nie-appetit` is in the runtime `why=` string at [heap_strlen.py:598](/srv/share/dev/supwngo/supwngo/exploit/walkthrough/families/heap_strlen.py:598), with the token on line 606. |

## New blocking items (B3-n)

### B3-1: The sandbox hides its own cell

The scorer scratch root is an ancestor of the staged cell, but both the child cell and ancestor are mount targets. Hiding the ancestor after binding the child makes the child unreachable. Separate secret/scratch roots, or mount the cell at an independent in-sandbox path such as `/work` after all hides.

### B3-2: The answer-key proof still omits a required arm

The roadmap requires denial of a generator source and explicitly hides `benchmark/gen`; v3 substitutes a challenge source and omits `benchmark/gen` from both the hide list and mutant. Also, dependency staging must copy resolved files, not entire RPATH directories. Otherwise unrelated source/debug material can enter the cell.

### B3-3: GDB-under-bwrap can remain broken while every listed positive test passes

The proposed `_run_target(payload, input_method, args, timeout)` interface describes direct target execution, not the separate GDB command plus script/pattern files. Those current files live in host `/tmp`, hidden by sandbox tmpfs. Because the overall finder falls back to bisect, the positive control does not prove GDB routing. Add a GDB-specific sandbox test that asserts GDB provenance.

### B3-4: The RELRO lint exit criterion is presently impossible

The plan requires exact allowlists and says stale entries fail, yet it contains stale entries and omits real reads. Consequently “the lint is green” at [plan exit line 568](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:568) cannot be achieved by the stated migration.

### B3-5: Three §3.7 pins remain nondeterministic or inconsistent

- `--load-max 0` does not guarantee zero valid samples because the rule accepts load `≤ 0`; a genuinely idle host can report `0.0`.
- A survivor that escapes with `setsid()` is no longer in the original session, so the session scan at [plan line 225](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:225) cannot generically detect or kill it on the `none` backend.
- The `traceback`/`hang` rows cannot make the four truthless OFF cells ERROR; those cells remain VOID under §2.1 and preflight precedence.

## Non-blocking (N3-n)

### N3-1: The promised confidence roadmap amendment is absent

The plan defers `confidence` to SP-04 at [plan line 375](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:375), but the governing roadmap still says SP-01 adds it at [roadmap line 419](/srv/share/dev/supwngo/docs/roadmaps/2026-11-12-mythos-roadmap.md:419). The deferral remains technically sound; update the roadmap.

### N3-2: Clarify the sandbox’s confidentiality boundary

`--ro-bind / /` permits read access to most host files. That is adequate for write/network containment only because evaluation secrets are explicitly hidden. State this limitation so product `offset` is not presented as a general host-confidentiality sandbox.

### N3-3: Reconcile `reviewed` method truth with the generic roadmap metric

The plan labels S0 `method_basis: reviewed` at [plan line 35](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:35), while the generic roadmap metric says METHOD-R0 is scored only for solver-proven/construction truth at [roadmap line 81](/srv/share/dev/supwngo/docs/roadmaps/2026-11-12-mythos-roadmap.md:81). The sprint-specific seven-cell intent is otherwise clear, but the exception should be stated.

## Required edits before implementation

1. Fix the bwrap mount topology and give hidden-file/network self-checks controlled positive controls.
2. Restore the `benchmark/gen` generator-source mutant/hide and make dependency staging file-granular.
3. Specify GDB’s bound temp workspace and add a bwrap test asserting GDB provenance.
4. Regenerate the RELRO read inventory; remove stale allowlist entries and migrate or allow every real non-display read.
5. Make TIME and survivor mutants deterministic, correct ERROR-versus-VOID pins, and reconcile the two roadmap schema discrepancies.