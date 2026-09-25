<!-- PROVENANCE
original path : /tmp/codex-out/constant-sweep-plan-review-20260924.md
mtime         : 2026-09-24 20:58:09.124932425 -0400
sha256[:16]   : a2b4bc9d45efd453
bytes         : 10509
reviewer      : codex gpt-5.6-sol, model_reasoning_effort=xhigh, --sandbox read-only
subject       : docs/plans/2026-09-24-close-the-constant-sweep-before-r3.md at 3c2970d
round         : 1 of 3
verdict       : NOT-APPROVED
note          : preserved verbatim; my verification of its claims is recorded in the
                plan revision, not by editing this file.
-->

FINDING  BLOCKING: Option A does not prescribe a disposition for every live folklore candidate source
WHERE    §0 inventory, §2A, and §4.2
CLASS    Inventory-to-implementation gap: identified defect sources lack mandatory removal, replacement, and acceptance criteria
SWEEP    Trace every framework-generated gate value from its definition through every payload-delivery sink; require each source to have an explicit remove/replace action and an end-to-end test
RESULT   The unconditional fallback append is explicitly removed and VariableOverwriteExecutor is implicitly rewired; `enhanced_auto.py` receives no implementation action, while `strategy.py` is only to have its result “stated.” §4.2 does not require any particular result, so leaving a live source unchanged satisfies it.

FINDING  BLOCKING: The “class-wide” sweep is still a literal-shaped instance sweep and even omits one of the nine literals
WHERE    §0.1 wider-sweep command
CLASS    Syntactic occurrence search used as proof of semantic absence
SWEEP    Enumerate candidate-producing data flows into payload-delivery sinks, supplemented by an AST scan for equivalent integer values, aliases, imports, constant expressions, byte encodings, and non-Python configuration while excluding prohibited held-out source trees
RESULT   The pattern omits standalone `0x1337`; it also cannot see decimal forms, computed constants, imported aliases, packed bytes, generated values, or non-`.py` sources. The claimed “28 of 228” and “0 additional instances” are UNVERIFIABLE FROM BRIEF; `git grep -niE '0x1337([^0-9a-f]|$)|0x1337bab3|0xdeadbeef|0xcafebabe|0xbadc0de|0xfeedface|0x41414141|0xbaadf00d|0x0d15ea5e' -- '*.py'` would settle the corrected literal-only inventory, but not the behavioral class.

FINDING  BLOCKING: Removing the fallback turns infrastructure failures into semantic “not applicable” skips
WHERE    `comparison_immediates()` exception handling and §2A
CLASS    Error-as-empty collapse at a measurement boundary
SWEEP    Mutate each recovery outcome—missing executable, timeout, path failure, nonzero `objdump`, successful empty disassembly, malformed output, and successful candidates—and require distinct structured statuses
RESULT   Exceptions are caught and reduced to an empty list; `proc.returncode` is never checked, so nonzero `objdump` also becomes empty; successful recovery with no matches has the same result. After fallback deletion, all are reported as “no gate immediates recovered.”

FINDING  MAJOR: `is_applicable` cannot make an unrecovered gate observable because it tests for any immediate, not the relevant gate
WHERE    §2A’s observability claim and §3
CLASS    Proxy predicate conflates incidental evidence with the event it claims to observe
SWEEP    Test targets containing only irrelevant immediates, a relevant unsupported immediate, a relevant candidate truncated by the limit, and no immediates; record applicability and delivered candidate provenance
RESULT   `13_off_by_one` is the inlined counterexample: §1 says its gate is assignment-only but its binary has `0x0` and `0x20`; §3 makes those values recoverable, so the proposed predicate returns true and emits no explicit skip. Any target with an unrelated immediate has the same defect.

FINDING  MAJOR: The proposed small-constant fix leaves substantial `cmp`/`test` coverage holes
WHERE    §3 and the `comparison_immediates()` regex
CLASS    Enumerator claims an instruction class while recognizing only selected textual spellings
SWEEP    Compile fixtures covering operand widths, mnemonic suffixes, immediate formats, signed values, and 64-bit values; disassemble them with the exact `objdump` command and assert the expected recovered provenance
RESULT   The regex omits `cmpb` and `cmpw`, and suffix forms such as `testb`, `testw`, `testl`, and `testq`; it accepts only `$0x…` syntax; the numeric filter rejects values above `0xFFFFFFFF`. Thus even the example `if (x == 0x41)` remains invisible when compiled as a byte-width comparison.

FINDING  MAJOR: “Rank rather than exclude” retains an ordering that promotes noise into the 24-entry cap
WHERE    §3 and `sorted(found, key=lambda v: (v.bit_length(), v))[:limit]`
CLASS    Filter relaxation without redesigning the ranking and truncation policy
SWEEP    Use a fixture with more than 24 distinct low loop/size comparisons plus a real higher gate and assert that the gate survives selection
RESULT   Removing the floor places `0`, `1`, loop bounds, and size constants first by bit length; the actual gate can then be truncated. This is not merely an order change: it changes the candidate set, applicability, payloads, and possible credit. `13_off_by_one` changes from empty recovered candidates to at least `0x20`.

FINDING  MAJOR: The plan counts removed calls but does not account for the larger replacement search
WHERE    §2A, §3, and §4
CLASS    Gross-removal accounting presented without net resource analysis
SWEEP    Record candidate count, payload-delivery count, recovery time, and total wall time per executor and target; enforce the 360-second budget on worst-case fixtures and R1/R2
RESULT   Using the plan’s own 14-size premise, nine folklore values make 126 deliveries, while the 24-entry recovery limit permits 336 deliveries—a possible net increase of 210 before duplicate recovery costs. No wall-budget acceptance criterion is specified.

FINDING  MAJOR: Verification checks helper output and solved targets, not the provenance of values actually delivered
WHERE    §4.1–§4.4
CLASS    Outcome and component tests used in place of an end-to-end causal invariant
SWEEP    For every gate-value payload, capture the delivered value and require a matching instruction address and immediate from the same target’s successful disassembly; reconcile every credited strace with that record
RESULT   An objdump assertion does not prove the executor used that occurrence; the mutation requirement does not state a delivery-level oracle; literal sweeps do not prove runtime absence; and reproducing the solved-target set can succeed through a remaining invalid route. No stated check requires delivered candidates to be a subset of recovered candidates.

FINDING  MAJOR: The proposed “flip A to C if R3 produces a real one” uses held-out evaluation as a design-selection signal
WHERE    §2C
CLASS    Adaptive development on a corpus designated for cold measurement
SWEEP    Freeze and hash the implementation and configuration before R3, run R3/R4/R5 once, and defer all policy changes prompted by those results to a future corpus
RESULT   The plan does not prohibit changing policy between or rerunning held-out rounds. Moreover, an applicability skip cannot establish that a real folklore-reachable gate existed, so the stated flip condition is not observable without an additional invalid-guess experiment.

FINDING  MINOR: Several load-bearing topology and count claims cannot be checked from the supplied excerpts
WHERE    §0 and §2A
CLASS    Scope premise asserted without the code needed for independent verification
SWEEP    `rg -n -C 80 '^(class .*Executor|[[:space:]]+def is_applicable)|MAGIC_VALUES|comparison_immediates|verify_payload|COMMON_.*OFFSET' supwngo/exploit/pipeline/executors supwngo/exploit/enhanced_auto.py`
RESULT   “Three live candidate sources,” “14 sizes × 9 values,” and “only one of 17 executors without `is_applicable`” are UNVERIFIABLE FROM BRIEF; cannot run - requires repo access. The command above would expose the relevant definitions, consumers, loops, and predicates.

PASS 1 LETTER-VS-SPIRIT:

- “Delete the unconditional append”: delete that loop while retaining or reconstructing the same constants downstream.
- “Source candidates only from `cmp`/`test`”: call recovery, then union another source before delivery.
- “Add `is_applicable` with a reason”: return true for any incidental immediate, or label tool failure as “no gate.”
- “Rank rather than exclude”: include low values before `[:24]`, thereby still excluding later candidates.
- Positive-control provenance: separately show `0x1337` in objdump and in output without proving the output came from that instruction.
- “Sweep all four sites and state the result”: report that a site remains unchanged; no zero-instance acceptance criterion exists.
- Wider sweep: obtain a clean count from an incomplete spelling list or incomplete file universe.
- Wrong-but-present mutation: make only a helper-level assertion fail while the delivery path remains hardwired.
- Reproduce R1/R2 target-for-target: solve the same targets through another invalid route.
- Exercise `is_applicable` both ways: mock arbitrary lists without exercising objdump success, failure, relevance, or provenance.
- Print enumeration count and check status: accurately count an incomplete selector and check only the final pipeline status.

PASS 2 FORWARD CONSISTENCY:

- §1 relies on `13_off_by_one` having no recovered candidates; §3 makes its `0x20` comparison recoverable.
- Consequently, §2’s promised explicit skip for the motivating miss becomes a true applicability result.
- §2 emphasizes 126 removed deliveries, while §3 permits as many as 336 replacement deliveries; later verification has no budget check.
- §4.2 says to rerun the §0.1 command, but §5 later requires enumerators to print a count and prove successful enumeration; the displayed command does neither robustly.
- The plan blocks a cold run of all three corpora, yet §2C leaves open adaptation after observing R3.

PASS 3 SUFFICIENCY:

No. Even if every stated step is implemented literally, `enhanced_auto.py` has no required disposition, the sweep cannot prove behavioral absence, and no sink-level assertion forbids unproven gate values from being delivered. The plan also leaves recovery failure indistinguishable from semantic absence, does not actually observe missed gates, and does not establish the 360-second budget after candidate expansion. Losslessness on R3/R4/R5 necessarily remains unverified; it should be recorded as a residual risk, not claimed observable through the proposed predicate.

NOT-APPROVED — Highest-value change: make candidate provenance an enforced end-to-end contract: one cached structured recovery result containing status plus `(value, instruction address, mnemonic)` records, with every gate-value delivery required to reference such a record and all other candidate sources rejected.