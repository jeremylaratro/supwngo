<!-- PROVENANCE
original path : /tmp/codex-out/constant-sweep-plan-review-round2.md
mtime         : 2026-09-24 21:20:04.532137479 -0400
sha256[:16]   : 19745e7580fbc606
bytes         : 16864
reviewer      : codex gpt-5.6-sol, model_reasoning_effort=xhigh, --sandbox read-only
subject       : docs/plans/2026-09-24-close-the-constant-sweep-before-r3.md at 91912ad
round         : 2 of 3 -- round 4 escalates, it does not proceed
verdict       : NOT-APPROVED. 9 of 10 round-1 findings marked RECURRENCE.
note          : preserved verbatim. Two of its claims I have independently confirmed
                against the repo: the printed nine-literal grep exits 123 with
                "Trailing backslash" and returns 0 files (I had reported 29 from the
                unwrapped single-line form, which is NOT what the document printed);
                and the round-counter criticism is correct.
-->

## Part 1 — Round-1 findings

B1 RECURRENCE - The unnamed universal sink and absent producer rewiring repeat the inventory-to-implementation gap; `enhanced_auto.py` still has no mandated disposition.

B2 RECURRENCE - Bare `0x1337` is added, but the displayed quoted multiline grep is malformed, prints no count, and excludes no held-out paths.

B3 RECURRENCE - Statuses omit target-path and malformed-output failures, while `CANDIDATES_FOUND` is inconsistently classified as both measurable and NOT MEASURABLE.

M4 CLOSED - The missed-gate observability claim is explicitly withdrawn; irrelevant recovered immediates are now documented as applicable-but-unsuccessful.

M5 RECURRENCE - The `movabs` erratum becomes another encoding-wide claim; the ceiling is not universally moot, and two matrix cells remain invalid.

M6 RECURRENCE - “Partitioned selection” specifies neither buckets nor quotas; one survival fixture still permits genuine low or high gates to be truncated.

M7 RECURRENCE - Timing covers only observed R1/R2 targets, and reducing `limit` lacks a coverage floor; zero candidates trivially satisfies the criterion.

M8 RECURRENCE - Numeric membership in recovery is not causal provenance; post-hoc annotation can satisfy the sink checks without proving source-to-delivery lineage.

M9 RECURRENCE - Freeze scope and re-verification are unspecified, while the global Python grep may inspect prohibited held-out paths before freezing.

M10 PARTIAL - The 117 count is inline-checkable; topology, 17/1, inventory, matrix, and baseline claims remain UNVERIFIABLE FROM BRIEF.

## Part 2 — New findings

FINDING  BLOCKING: The contract is a forgeable value allow-list at an unnamed sink, not causal provenance over every delivery route  
WHERE    §2A′, §4.1, §4.3, and §6 B1/M8  
CLASS    Outcome or membership testing substituted for an end-to-end causal invariant; inventory-to-implementation gap  
RECURRENCE? yes — round-1 B1 and M8  
SWEEP    Trace every candidate producer to every process-write API; inject recovered-only, folklore-only, same-value/different-source, fabricated-address, wrong-target, and alternate-sink candidates  
RESULT   A hardcoded list can select a value and have the sink join it post hoc to a legitimate tuple. `GateCandidate` carries no target digest or recovery identity and is freely constructible. No concrete sink or producer migration is named. UNVERIFIABLE FROM BRIEF; run `rg -n -C 12 'comparison_immediates|MAGIC_VALUES|FALLBACK_MAGIC_VALUES|GateCandidate|GateRecovery|send(line|after)?\(|process\(|communicate\(|stdin\.write' supwngo/exploit`.

FINDING  BLOCKING: The recovery status space still collapses unenumerated failures, and its `CANDIDATES_FOUND` semantics contradict themselves  
WHERE    §2A′, §4.2, and §6 B3  
CLASS    Error-as-empty or error-as-measurement collapse at a measurement boundary  
RECURRENCE? yes — round-1 B3  
SWEEP    Exercise path-resolution failure, missing executable, permission/exec failure, timeout, nonzero exit, empty valid output, truncated/malformed successful output, parser-format drift, and valid matches  
RESULT   Path resolution and malformed-success output have no status. A zero-return malformed stream can become `DISASSEMBLED_NO_MATCH`. §2/§6 say every status except no-match is NOT MEASURABLE, incorrectly including `CANDIDATES_FOUND`; §4.2 says only the first three are NOT MEASURABLE.

FINDING  MAJOR: The “corrected” nine-literal command cannot reproduce its claimed 29-file result  
WHERE    §0.1 and §4.8  
CLASS    Syntactic occurrence search used as proof of a successful enumeration  
RECURRENCE? yes — round-1 B2  
SWEEP    Execute the displayed command verbatim under zsh with `pipefail`, capture every stage’s status, use NUL-delimited filenames, and machine-count inputs and matches  
RESULT   The backslash-newline is inside single quotes, so it is preserved in the grep pattern; the first newline-separated BRE ends in a trailing escape and should error. The command contains no `wc` or equivalent, so it prints paths—not the asserted numerator or denominator.

FINDING  BLOCKING: The all-tracked-Python sweep has no exclusion for prohibited R3/R4/R5 material  
WHERE    §0.1 and §0.2a  
CLASS    Cold-corpus boundary not enforced by the measurement procedure  
RECURRENCE? yes — round-1 M9  
SWEEP    Compare the tracked-Python path list against an authoritative held-out-source/reference manifest before running any content search  
RESULT   Whether overlap occurred is UNVERIFIABLE FROM BRIEF. After creating the authoritative manifest, run `comm -12 <(git ls-files -- '*.py' | sort) <(sort docs/held-out-source-manifest.txt)`. Any output means the already-reported grep was unsafe and cold status needs adjudication.

FINDING  MAJOR: The `movabs` correction is locally true but generalized into another false instruction-class claim  
WHERE    §0.3, §0.4, §3, §4.4, and §6 M5  
CLASS    An extractor recognizes one encoding of a source construct and is described as recognizing the construct  
RECURRENCE? yes — round-1 M5  
SWEEP    Cover sign-extended imm32 comparisons, `movabs`, split high/low construction, constant-pool loads, optimized transformations, and dataflow from materialization to comparison  
RESULT   Scraping one `movabs` would recover this fixture’s raw number but not prove it feeds the gate. Some 64-bit values representable as sign-extended imm32 can remain comparison immediates, making the ceiling relevant. Two matrix cells are invalid, yet §3 still quotes 7/32 and §4.4 calls the matrix complete. §6 still says the limitation is structural and the matrix is owed. The 7/32 claim is UNVERIFIABLE FROM BRIEF; a checked-in matrix test runnable with one command is required.

FINDING  MAJOR: “Partitioned selection” is not an implementable or test-complete selection policy  
WHERE    §3 and §4.5  
CLASS    Truncation redesign claimed without specifying or testing its loss function  
RECURRENCE? yes — round-1 M6  
SWEEP    Define exact boundaries, quotas, deduplication, and ordering; place the genuine gate at every rank in every bucket with more-than-cap distractors  
RESULT   A zero-sized low bucket, one-slot high bucket, or arbitrary within-bucket ordering can pass the single high-gate fixture while dropping genuine gates elsewhere.

FINDING  MAJOR: The timing gate can be met by disabling useful search and is not a worst-case resource bound  
WHERE    §2A′ cost paragraph and §4.6  
CLASS    Resource acceptance criterion detached from required coverage  
RECURRENCE? yes — round-1 M7  
SWEEP    Cross candidate counts, bucket positions, maximum payload latency, recovery latency, and timeout behavior; require both a coverage floor and the 360-second ceiling  
RESULT   Repeatedly lowering `limit` can reach zero and pass. “Worst R1/R2 target” is worst observed, not a worst-case fixture. No rule resolves a conflict between timing and the truncation acceptance test.

FINDING  MAJOR: The sink mutation tests can pass without demonstrating that production traffic is protected  
WHERE    §4.3  
CLASS    Test-only fault injection substituted for production-path enforcement  
RECURRENCE? yes — round-1 M8  
SWEEP    Inject an invalid candidate through every real producer and sink route, while deriving the expected address/value relation from an independent fixture oracle  
RESULT   After deleting invalid producers, “accept anything” need not change behavior and therefore need not turn 4.1 red. Conversely, a test-only invalid producer can make it red even if a production route bypasses the sink. A fabricated recovery remains self-consistent with 4.1 unless address validation uses an independent oracle.

FINDING  MAJOR: Freeze-and-hash neither defines the frozen artifact nor verifies continuity through all three rounds  
WHERE    §2C  
CLASS    Adaptive-development control stated without a binding reproducibility boundary  
RECURRENCE? yes — round-1 M9  
SWEEP    Manifest code, dirty diff, configuration, dependencies, compiler/objdump versions, build flags, binaries, and corpus identifiers; verify one immutable artifact digest immediately before and after each round  
RESULT   The plan can hash an arbitrary subset once, record that old digest, and later alter un-hashed code, tools, build flags, or configuration. §0.4 says build flags affect recovery but does not explicitly place them inside the freeze.

FINDING  MAJOR: Revision 2 resets the review counter to round 1, defeating the stated three-round escalation control  
WHERE    Header, §6 recurrence check, and closing sweep table  
CLASS    Review-state accounting permits recurrence to evade escalation  
RECURRENCE? no — this class is new in round 2  
SWEEP    Reconcile revision number, independent-review number, finding history, and escalation threshold in every status/header/footer occurrence  
RESULT   This is round 2, yet the document twice declares round 1 and concludes that no recurrence can exist. That conclusion is false and materially affects round-4 escalation.

FINDING  MINOR: Several revised measurements remain assertions without independently reproducible evidence  
WHERE    §0, §0.2c, §0.4, §1, and §4.7  
CLASS    Scope premise asserted without the evidence needed for independent verification  
RECURRENCE? yes — round-1 M10  
SWEEP    Reproduce topology with the round-1 command and require checked-in one-command artifacts for the matrix and benchmark reruns  
RESULT   Only 13 offsets × 9 values = 117 is verifiable from the inline code. The three-source topology and 17/1 claim are UNVERIFIABLE FROM BRIEF; run `rg -n -C 80 '^(class .*Executor|[[:space:]]+def is_applicable)|MAGIC_VALUES|comparison_immediates|verify_payload|COMMON_.*OFFSET' supwngo/exploit/pipeline/executors supwngo/exploit/enhanced_auto.py`. No honest command for 7/32 or 13/13 and 4/15 can be derived because rev 2 names no fixture or benchmark invocation.

## Part 3 — Mandatory passes

### PASS 1 LETTER-VS-SPIRIT

| Requirement | Can it be satisfied hollowly? |
|---|---|
| Provenance contract | Yes. Reject every tagged gate payload, omit tagging on bypass routes, or join a hardcoded value afterward to any equal recovery record. |
| 4.1 sink invariant | Yes. It is vacuous with no recorded gate deliveries and does not prove that all actual payload writes were classified. |
| 4.2 status matrix | Partly. Real process-boundary induction is useful, but mocked result objects can satisfy it; path and malformed-output cells are omitted. |
| 4.3 mutations | Yes. A test-only invalid producer can turn the test red while production bypasses the sink. Without such a producer, the required mutant may not turn red at all. |
| 4.4 fixture matrix | Yes. Merely recording results changes no extractor; the current matrix is already called complete despite two invalid cells. |
| 4.5 truncation fixture | Yes. Preserve that one high gate while discarding other high gates or genuine low gates. |
| 4.6 budget | Yes. Lower `limit` to zero or disable the executor. No coverage floor prevents this. |
| 4.7 R1/R2 reproduction | Yes. Other executors can reproduce the aggregate solved set while this executor becomes inert or an invalid route survives. |
| 4.8 literal sweep | Yes. A clean incomplete spelling/file-universe search proves no runtime absence. The displayed command does not even print its claimed count. |
| 4.9 applicability | Yes. Hand-picked fixtures can exercise true and false without proving relevance or binding the predicate to production recovery. |
| Freeze-and-hash | Yes. Hash an incomplete tree once, record it, and never re-verify it while dependencies, tools, flags, or un-hashed configuration change. |

### PASS 2 FORWARD CONSISTENCY

No. Several dependent claims remain stale or contradictory:

- §0.4 says two matrix cells are degenerate and 7/32 must not be quoted elsewhere; §3 quotes 7/32 and §4.4 calls the matrix “run in full.”
- §0.4 retracts “absent entirely” and “structural”; §6 M5 repeats both claims and still says the matrix is owed.
- §2A′ and §6 B3 say only `DISASSEMBLED_NO_MATCH` is target evidence and the other four statuses are NOT MEASURABLE. That incorrectly includes `CANDIDATES_FOUND`; §4.2 instead applies NOT MEASURABLE only to the three infrastructure failures.
- §2A′ says the folklore lists can be deleted and need no producer-specific action, while its 312-delivery budget assumes executors were rewired to enumerate 24 recovered candidates. That rewiring is never prescribed.
- §4.3 expects the accept-any sink mutant to create an invalid delivery, but deleting all invalid producers can make that mutation behaviorally inert.
- §2 rejects C as preserving invalid guessing; §3 nevertheless calls 18 unrecovered matrix cells an argument for keeping C on the table. Those cells do not show that any folklore fallback would recover their gates.
- The header calls this revision 2, but the header and §6 reset the independent review to round 1.

### PASS 3 SUFFICIENCY

No, under the plan’s literal contract.

A hardcoded folklore list may still select or prioritize a value, after which the sink can locate an equal recovered tuple and annotate the delivery. An unrelated comparison containing the same number can therefore launder a folklore-derived guess. The contract proves numeric membership, not that candidate selection originated exclusively from target recovery.

The stated precondition would close only if:

- every relevant delivery route accepts a target-bound token issued by one authoritative recovery result;
- the token is bound to the exact binary digest and recovery run;
- candidate selection and ranking cannot consult folklore-value membership;
- every actual payload write is forced through the typed API; and
- negative fault injection proves that each real route rejects wrong-source, wrong-target, and fabricated tokens.

Even then, static-recovery blind spots remain a losslessness risk, not a credit-validity risk. Also still open are malformed recovery output, cap-induced misses, worst-case timing, and preservation of R3/R4/R5 cold status.

## Part 4 — Adversarial review of the self-corrections

| Self-correction | Correct? | Complete? |
|---|---|---|
| Add bare `0x1337` | Conceptually yes. | No. The displayed multiline command is malformed, does not count, and has no held-out exclusion. |
| 14 offsets → 13 | Yes; the inline list has 13 entries, so 117 is correct. | Only for the old unconditional sweep. The 312 figure is a maximum assumption, not proof of actual rewiring. |
| 17 executors, one missing `is_applicable` | UNVERIFIABLE FROM BRIEF. | Run the topology command in M10; the claim is not independently evidenced here. |
| Byte-gate example did not reproduce | Reasonable for that compiler/build. | Yes as a correction to the example, but it does not weaken the recognized mnemonic-class defect. |
| 64-bit constant exists as `movabs` | Correct for the shown fixture. | No. Scraping `movabs` does not prove comparison dataflow, and other code generation uses constant pools, split construction, or sign-extended imm32 comparisons. |
| The 32-bit ceiling is moot | No as a general claim. | A 64-bit value representable by a sign-extended imm32 can remain a comparison immediate and still be rejected by the ceiling. |
| Wider gates are reachable by scraping `movabs`/`mov` | Only locally. | It recovers possible numbers, not gate provenance; “only” also excludes other static and dynamic recovery methods. |
| Matrix is now run | Not fully. | Two cells are admitted invalid and were not rerun. Therefore 7/32, 14/32, and 18/32 are not final results. |
| Removing the floor changes the set, not merely order | Yes. | The proposed partition lacks enough detail to determine the resulting set. |
| Missed gates are not observable via `is_applicable` | Yes. | The retraction is sound, but the later `CANDIDATES_FOUND` claims and status classification remain confused. |
| `CANDIDATES_FOUND` is true for every binary | Not established. | At most, rev 2 claims it for 32 builds of one fixture family. Raw `cmp`/`cmpb`/`cmpq` presence does not prove a post-regex, post-filter candidate. It also cannot be universal because §4.2 requires a clean no-comparison binary. |
| R3-triggered policy adaptation is withdrawn | Yes. | The policy correction is right, but the freeze/hash mechanism does not actually enforce it. |
| This is round 1, so recurrence is impossible | No. | This is round 2, and multiple round-1 classes recur. |

NOT-APPROVED — Highest-value change: replace value-membership with one named, unavoidable delivery API accepting only binary-bound recovery-minted candidate tokens, and prove every real producer/write route rejects folklore-selected, fabricated, and wrong-target tokens.