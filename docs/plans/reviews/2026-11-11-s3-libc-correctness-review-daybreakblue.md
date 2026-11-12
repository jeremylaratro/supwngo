**BLOCKER — the plan’s core scope reduction is not sound.** The narrow claim that none of the seven named APIs consumes `DEFAULT_LIBC_VERSION` from a canonical executor is correct. However, the broader premise that the pipeline selects offsets from the libc the verifier actually loads is false, and the proposed ret2libc-only mismatch check leaves several exploit-producing paths unprotected.

1. **BLOCKER — “shipped libc == loaded libc” is false in an existing verifier branch.**

   `Binary.libc_env()` selects the shipped directory through `LD_LIBRARY_PATH` ([binary.py:448](/srv/share/dev/supwngo/supwngo/core/binary.py:448)). But before running a generated script, the verifier may strip that variable when it prevents Python from starting ([verifier.py:159](/srv/share/dev/supwngo/supwngo/exploit/pipeline/verifier.py:159)). The code explicitly warns that the script’s child will then load the host libc unless it consumes `SUPWNGO_TARGET_LD_LIBRARY_PATH` ([verifier.py:162](/srv/share/dev/supwngo/supwngo/exploit/pipeline/verifier.py:162)). Generated scripts do not consume it: `open_target()` simply calls `process(BINARY)` with inherited, cleaned environment ([script_builder.py:88](/srv/share/dev/supwngo/supwngo/exploit/pipeline/script_builder.py:88)).

   The existing regression test even documents this unresolved handoff ([test_verifier_loader_env.py:146](/srv/share/dev/supwngo/tests/test_verifier_loader_env.py:146)).

   Consequently:

   - Offset selection can use the shipped libc.
   - The verified target can actually load the host libc.
   - Comparing `--libc` only to the shipped libc can produce both false MATCH and false MISMATCH.

   Concrete fix: either bring target-only loader-environment threading into this sprint—make generated `open_target()` pass the republished loader variables—or define runtime-libc resolution from the exact environment/argv the generated target child receives. The current CG-04 deferral is incompatible with a sound mismatch detector.

2. **BLOCKER — the proposed mismatch API cannot represent its promised four states and version equality is insufficient for offsets.**

   The plan specifies `Optional[str]`, with `None` meaning match, no `--libc`, and unestablishable loaded libc ([plan:89](/srv/share/dev/supwngo/docs/plans/2026-11-11-s3-libc-correctness-plan.md:89)), while separately promising `NOT_APPLICABLE / UNVERIFIABLE / MISMATCH / MATCH` ([plan:102](/srv/share/dev/supwngo/docs/plans/2026-11-11-s3-libc-correctness-plan.md:102)). At the proposed call site, only a returned reason causes refusal ([plan:96](/srv/share/dev/supwngo/docs/plans/2026-11-11-s3-libc-correctness-plan.md:96)); therefore UNVERIFIABLE is indistinguishable from MATCH and proceeds.

   Banner-version equality also does not prove offset compatibility. Two distribution builds of glibc 2.31 can have different symbol/string offsets. A banner-only MATCH can still emit a wrong ret2libc chain.

   There is also no provenance bit for operator-supplied versus auto-detected libc: the orchestrator stores both through the same `context.set_libc()` field ([orchestrator.py:625](/srv/share/dev/supwngo/supwngo/exploit/pipeline/orchestrator.py:625)). Remote use is another false-positive case: `solve --remote --libc REMOTE_LIBC` still performs local attempts ([cli.py:3382](/srv/share/dev/supwngo/supwngo/cli.py:3382)), so local-version inequality may be expected rather than an invalid remote artifact.

   Concrete fix: return a typed result containing status, offset path, runtime path, provenance, versions, and identities. For symbol-offset consumers, MATCH should require identical build ID/content hash, not merely `major.minor`. Refuse both MISMATCH and UNVERIFIABLE when emitting a locally verified offset-dependent chain. Define separate semantics for remote-only artifacts.

3. **BLOCKER — the proposed guard misses multiple offset/feature-consuming executor paths.**

   `local_libc_path()` resolves in this exact order:

   1. `context.libc.path`, including `--libc` ([\_shared.py:208](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/_shared.py:208))
   2. detected shipped libc ([\_shared.py:211](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/_shared.py:211))
   3. `ldd` result ([\_shared.py:216](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/_shared.py:216))
   4. well-known host paths ([\_shared.py:228](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/_shared.py:228))

   Thus it cannot itself mean “libc actually loaded”; `--libc` explicitly wins.

   Missed consumers include:

   | Site | Unchecked libc-dependent behavior |
   |---|---|
   | [heap_strlen_ofb1_techniques.py:831](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/heap_strlen_ofb1_techniques.py:831) | Reads release and `system`; selects hooks at [line 978](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/heap_strlen_ofb1_techniques.py:978), safe-linking and offsets at [line 1063](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/heap_strlen_ofb1_techniques.py:1063). |
   | [heap_techniques.py:300](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/heap_techniques.py:300) | Selects plain versus safe-linked tcache pointer encoding and passes it into generated payloads. |
   | [fsop_techniques.py:136](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/fsop_techniques.py:136) | `resolve_libc_gate()` uses `local_libc_path`, so it reads `--libc`, not necessarily the loaded libc; the plan’s assertion that this already enforces the loaded path is false. |
   | [heap_and_bypass.py:129](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/heap_and_bypass.py:129) | Threads `context.libc.path` into a two-stage libc chain. The emitted script loads that ELF but starts the target normally ([canary_bypass.py:312](/srv/share/dev/supwngo/supwngo/exploit/canary_bypass.py:312)) and tries hardcoded one-gadget offsets ([canary_bypass.py:364](/srv/share/dev/supwngo/supwngo/exploit/canary_bypass.py:364)). |

   By contrast, `allocsize_techniques.py:1395` and `heap_techniques.py:2009` currently use the version only in notes, so they are not offset blockers. The signal-underflow route resolves `p.libc.path` at runtime ([signal_underflow_techniques.py:627](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/signal_underflow_techniques.py:627)), which is the safer model.

   Concrete fix: enforce one central libc-binding result at every symbol-offset, structure-layout, feature-gate, and one-gadget consumption site—not only `rop_techniques.py:563`. Remove the hardcoded one-gadget list or derive gadgets from the bound libc.

4. **BLOCKER — deleting `DEFAULT_LIBC_VERSION` as planned breaks imports and leaves a critical public offset consumer untreated.**

   `FSOPExploiter` is an omitted direct consumer: it imports the constant ([fsop.py:14](/srv/share/dev/supwngo/supwngo/exploit/fsop.py:14)) and uses it as its constructor default ([fsop.py:215](/srv/share/dev/supwngo/supwngo/exploit/fsop.py:215)). `supwngo.exploit` eagerly imports it ([exploit/\_\_init\_\_.py:12](/srv/share/dev/supwngo/supwngo/exploit/__init__.py:12)), so deleting the constant without updating FSOP breaks package import, including the pipeline FSOP executor.

   This is offset-critical: unknown/unlisted versions fall back to 2.31 hook offsets ([fsop.py:250](/srv/share/dev/supwngo/supwngo/exploit/fsop.py:250), [fsop.py:292](/srv/share/dev/supwngo/supwngo/exploit/fsop.py:292)).

   Concrete fix: include `FSOPExploiter` in CG-01a. Unknown version must be tri-state for feature reporting, while hook-address methods must require a bound libc symbol table or explicitly supported version—never default an unknown version to 2.31.

5. **MAJOR — `TcacheExploiter(None)` cannot both construct successfully and eagerly construct a refusing per-thread struct.**

   `TcacheExploiter.__init__` currently creates `TcachePerThreadStruct` immediately ([tcache.py:252](/srv/share/dev/supwngo/supwngo/exploit/heap/tcache.py:252), [tcache.py:268](/srv/share/dev/supwngo/supwngo/exploit/heap/tcache.py:268)). Therefore making `TcachePerThreadStruct.__post_init__` raise on `None` causes `TcacheExploiter()` to raise at construction, contradicting the plan’s promise that non-version-dependent methods remain usable.

   Bare construction is also used for version-independent `size_to_idx()` in [test_new_modules.py:36](/srv/share/dev/supwngo/tests/test_new_modules.py:36).

   Concrete fix: lazily instantiate the per-thread layout only from layout-consuming methods, and make size/index conversion static or independent of the layout object. Add tests proving:

   - `TcacheExploiter()` constructs.
   - Version-independent helpers work.
   - `tcache_perthread_poison()` refuses without a version.
   - Feature-dependent methods expose unknown/refuse rather than treating `None` as false.
   - `hook_overwrite_targets()` refuses fallback offsets without a bound libc; its fallback table is actually labelled glibc 2.27 ([tcache.py:401](/srv/share/dev/supwngo/supwngo/exploit/heap/tcache.py:401)).

6. **MAJOR — the “advisory-only” classification and `HeapExploiter` design do not match the current APIs.**

   `HouseOfSpirit` uses the version to choose tcache versus fastbin and validate allowable sizes ([house_of_spirit.py:78](/srv/share/dev/supwngo/supwngo/exploit/heap/house_of_spirit.py:78), [house_of_spirit.py:111](/srv/share/dev/supwngo/supwngo/exploit/heap/house_of_spirit.py:111)). `NullByteExploiter` emits a definite feasibility verdict from the version ([off_by_one.py:505](/srv/share/dev/supwngo/supwngo/vulns/off_by_one.py:505)), as does `HouseOfStorm` ([large_bin.py:501](/srv/share/dev/supwngo/supwngo/exploit/heap/large_bin.py:501)). These are more than notes.

   The proposed `result["version_known"]` is also incompatible with `HeapExploiter.select_technique()`, which returns `List[HeapTechnique]`, not a dictionary ([techniques.py:66](/srv/share/dev/supwngo/supwngo/exploit/heap/techniques.py:66)). Its configuration separately defaults `has_tcache=True` and `has_safe_linking=False` ([techniques.py:32](/srv/share/dev/supwngo/supwngo/exploit/heap/techniques.py:32)), preserving fabricated capabilities after `libc_version` becomes `None`.

   Concrete fix: specify a typed selection result or retain the list API with a separate diagnostic surface. Make capability flags tri-state and ensure unknown feasibility is represented as unknown, not true/false.

7. **MAJOR — the RED-proof strategy is incomplete and partly vacuous.**

   - Importing the new resolver or mismatch function is RED on base merely because the symbol does not exist; that does not prove the current exploit bug.
   - A crafted ret2libc test can pass vacuously if the executor fails earlier for missing output function, gadget, offset, or re-entry point. Assert that `_libc_offsets` and script generation are reached on the control case, then assert they are not reached on mismatch.
   - Testing only banner-version mismatch misses the same-version/different-build offset bug.
   - No test covers the verifier’s loader-variable stripping branch and then inspects the target child’s actual mapped libc.
   - No mismatch tests cover heap-strlen, tcache poison, FSOP, or scanf/one-gadget.
   - The CLI option-set test can pass after adding an ignored `--libc`. `heap_analysis` currently constructs `AdvancedHeapAnalyzer(bin_obj)` with no libc input ([cli.py:2316](/srv/share/dev/supwngo/supwngo/cli.py:2316)); the analyzer unconditionally emits tcache findings despite its “glibc >=2.26” comment ([heap_advanced.py:397](/srv/share/dev/supwngo/supwngo/vulns/heap_advanced.py:397)). Add a behavioral plumbing test.
   - Existing bare-default tests also include the House-of-Spirit and Large-Bin convenience APIs ([test_heap_modules.py:260](/srv/share/dev/supwngo/tests/test_heap_modules.py:260), [test_heap_modules.py:389](/srv/share/dev/supwngo/tests/test_heap_modules.py:389)), not just the approximately three tests listed in the plan.

8. **MINOR — the CLI inventory contains a factual error.**

   `onegadget` takes a required libc positional ([cli.py:946](/srv/share/dev/supwngo/supwngo/cli.py:946)); `libc_id` does not. It consumes optional leaked-address flags ([cli.py:644](/srv/share/dev/supwngo/supwngo/cli.py:644)). Correct the plan and encode that distinction in the command-set test.

9. **MINOR — normalized versions should be compared as tuples.**

   Several consumers branch only on `minor`, e.g. tcache layout at [tcache.py:50](/srv/share/dev/supwngo/supwngo/exploit/heap/tcache.py:50). A future `3.0` would be classified as older than 2.30. The new resolver should return or feed a `(major, minor)` comparison consistently, and malformed explicit versions must refuse rather than normalize to 2.31.

The seven-class reachability audit itself found no canonical executor call that consumes `DEFAULT_LIBC_VERSION` for offset selection. `ExploitTester` is reachable only through the explicitly non-default `verify_via_tester()` API, whose documentation says no native executor calls it ([verifier.py:840](/srv/share/dev/supwngo/supwngo/exploit/pipeline/verifier.py:840)); pipeline FSOP constructs `FSOPExploiter` with an explicit resolved version ([fsop_techniques.py:151](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/fsop_techniques.py:151)). So there is no hidden pipeline call site defaulting offsets to 2.31—but the loaded-libc and enforcement scope assumptions still fail.

---

## Round 2 — post-implementation diff review (Daybreak Blue, 2026-11-11)

Independent Tier-2 diff review of the CG-01a implementation (the `supwngo.utils.libc`
resolver plus the seven importer fixes), run against the working tree before the S3
commits. Five findings; all five accepted and fixed in the same CG-01a commit, with the
dispositions below. (The plan-review BLOCKERs above remain scoped to the deferred
`S-libc-binding` sprint — loaded-libc threading and the typed mismatch result — and are
out of scope for CG-01a.)

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | High | `select_technique` fabricated `has_tcache = True` on an unknown libc, so a UAF on a possible pre-2.26 target was offered tcache poisoning. | **Fixed.** Flag is now the honest tri-state `None`; tcache stays a *candidate* under `has_tcache is not False` (near-universal on supported glibc, and losing it on the common modern-glibc case is worse), but every offset-emitting method (`build_fake_struct`, `TcacheExploiter.*`) refuses on an unknown version, so a candidate can never become a fabricated payload. `last_libc_version_known` + a log line carry the uncertainty the `List` return cannot. |
| 2 | High | Prefix-only regex `^(\d+)\.(\d+)` resolved `2.31garbage`/`2.31.` as `(2, 31)`, unlocking 2.31 offsets from typo'd/garbage input. | **Fixed.** Regex now requires a real separator (`-`, `.`, `~`, `_`, `+`, whitespace) or end-of-string after the minor: distro suffixes and patch levels still parse; alphabetic garbage returns `None` (unknown). Grammar pinned in `test_parse_accepts_full_version_grammar` / `test_parse_malformed_is_none_never_231`. |
| 3 | Med | `HouseOfSpirit.validate_chunk_size` left `valid = True` after skipping the version-gated size-limit check on an unknown libc. | **Fixed — sharper than "always None".** The verdict is now decided against *both* possible bin maxima: within both → `True` (e.g. `0x40`), over even tcache's `0x410` → `False`, in between (fits tcache, over fastbin, e.g. `0x400`) → `None`. Version-independent failures (min-size/alignment) still decide `False`, never `None`. Pinned in `test_house_of_spirit_unknown_size_limit_is_indeterminate`. |
| 4 | Med | `build_fake_struct` required a version only when `total_size is None`, so explicit offsets with no version, or a version cleared after construction, emitted bytes without refusing. | **Fixed.** `build_fake_struct` now calls `require_libc_version(self.version)` unconditionally before emitting. Pinned in `test_build_fake_struct_refuses_explicit_offsets_without_version` / `..._version_cleared_after_construction`. |
| 5 | Med | Banner scan accepted any `release version N.N` / `GLIBC N.N-` in any file, so a stray app string (`release version 9.99`) resolved as glibc. | **Fixed.** Both banner patterns are anchored to the `GNU C Library` marker (bounded gap, `re.DOTALL`). Pinned in `test_read_banner_requires_gnu_c_library_context`; the real-banner positive test now carries the GNU C Library marker. |

Net: +5 tests (38 → 43 across the five S3 test files). The finding-3 addition is cleanly
RED on base `dc22067` (base defaulted 2.31 → tcache bin → `0x400` valid `True`, not `None`),
so the review-driven additions preserve the non-vacuous RED-proof property of the core
behavioral tests. No finding disputed the refusal contract or the explicitly-tabulated
(2.23/2.27/2.31/2.35) byte outputs.

**Overall verdict: REWORK.**