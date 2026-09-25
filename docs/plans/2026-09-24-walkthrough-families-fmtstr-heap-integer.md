# Walkthrough second wave: format-string, integer, heap families

Status: DRAFT — requires review before implementation
Date: 2026-09-24
Depends on: `feat/walkthrough-engine-20260923` being merged

## Directive

Add walkthrough support for the three families currently served only by guided
triage, at three deliberately different ambition levels:

| family | bar | priority |
| --- | --- | --- |
| format string | full 0-to-pwn walkthrough | **highest** |
| integer | full 0-to-pwn walkthrough | normal |
| heap | **at minimum, potential detection** | lowest, hardest |

## This is a teaching gap, not a capability gap

Worth stating plainly because it sizes the work. The autopwn pipeline already
solves every one of these families on round 1, at 5/5 reliability under strict
attribution:

| target | family | result |
| --- | --- | --- |
| 05_fmtstr_arbread | format string | SUCCESS 5/5 |
| 06_fmtstr_arbwrite | format string | SUCCESS 5/5 |
| 10_int_overflow | integer | SUCCESS 5/5 |
| 14_negative_index | integer | SUCCESS 5/5 |
| 12_heap_tcache_poison | heap | SUCCESS 5/5 |

The executors exist and are proven: `fmtstr_techniques.py`, `heap_techniques.py`,
`heap_and_bypass.py`, and the integer paths. What is missing is the layer that
*explains* the exploitation, not the layer that performs it. So this is additive
work over working code, not new exploitation research.

## The architecture already accommodates all three, including heap

From `walkthrough/registry.py`, a family is a module exposing exactly:

```python
propose(facts) -> Route | None          # abstain with None
build(facts, routes) -> Walkthrough
```

registered in `_families()`. Two properties of the existing design matter here:

1. **Abstention is first-class.** The registry docstring is explicit that a family
   should only speak when it has something specific to say, precisely to avoid
   binary-independent filler like "not viable: no heap allocation primitive
   detected". A heap family that abstains on non-heap binaries is the intended
   usage, not a workaround.
2. **Selection is by score, and `triage` always applies at a low score.** This
   creates a natural slot for heap-at-detection: a route that scores *above*
   triage (it has something specific to say about this binary's allocator
   behaviour) but *below* a full technique family (it does not claim to reach a
   shell). No new dispatch concept is required.

So the work is three new modules under `walkthrough/families/` plus registration,
plus the facts each family needs. Not a redesign.

## Per-family scope

### Format string (full, highest priority)

Routes: arbitrary read (`%s` / `%p` chains) and arbitrary write (`%n` family).

The single most error-prone constant in this family is the **format-argument
index** — which varargs slot the attacker-controlled string lands in. It must be
`MEASURED` via an actual `%p`-chain probe against the binary and annotated with
the command that measured it. It must never be `ASSUMED` from a typical value.
Getting this wrong produces a walkthrough that is internally coherent and
completely wrong, which is worse than one that admits it does not know.

Also teach: the write-size decomposition (`%hhn`/`%hn`/`%n` and why byte-at-a-time
beats one wide write), stack-layout dependence, and the difference between a read
that leaks a canary and a write that redirects control flow.

### Integer (full, normal priority)

Routes: overflow/truncation into a size or index computation, and negative
indexing.

Teach the *arithmetic*, since that is what distinguishes this family: where the
signed/unsigned boundary is, which cast loses the sign, why a negative index
reaches memory before the buffer, and how a size computation wraps to a small
allocation followed by a large copy. The decisive check is the arithmetic
identity, not a crash.

### Heap (detection minimum, stretch to guided exploitation)

The floor, which must ship: **detection and characterisation**. Identify the
allocation/free primitives reachable from input, the chunk sizes in play, whether
a freed pointer remains reachable (UAF), whether the allocator is tcache-backed,
and whether safe-linking is in effect. Report what the primitive *is* and what it
would take to weaponise it, with each fact carrying its provenance.

Stretch, only if the detection layer is solid: a guided tcache-poisoning route.
Two facts already established in this work make heap walkthroughs unusually
failure-prone and must appear in any exploitation route:

- glibc honours a poisoned tcache entry only while `counts[tc_idx] > 0`.
- A single `leave; ret` loads `rbp`, not `rsp`; a stack pivot needs a second pass.

A heap route must not claim a shell it cannot demonstrate. Detection that is
honest about its limits is the deliverable; an overconfident heap walkthrough is
a regression even if it occasionally works.

## Interaction with the R5 walkthrough gate (must be resolved before R5)

The R5 spec gates walkthroughs at >= 85%, scored by blind-follower flag capture.
**A detection-only heap walkthrough cannot pass that test by construction** — it
does not reach a flag, so a blind follower will not capture one.

R5 is an even 5/5/5 split and heap is the canonical hard family, so this is not a
corner case: heap targets could silently drag the walkthrough figure below the
gate for a reason that has nothing to do with walkthrough quality.

Options, to be decided before R5 is generated:

1. Heap targets are excluded from the walkthrough-gate denominator and reported
   separately against a **detection-quality** criterion (did it correctly identify
   the primitive, the allocator, and the reachability?).
2. Heap targets stay in the denominator and the gate is stated as
   "85% of non-heap scored targets".

Recommendation is (1): it measures heap against the bar actually set for it,
rather than scoring it against a bar this directive explicitly did not set.
Either way the split must be declared before measuring, not chosen afterwards
once the number is known.

## Test strategy

- Each family's facts carry `MEASURED | DERIVED | ASSUMED | UNKNOWN` provenance
  (`walkthrough/model.py:124-143`), with the measuring command recorded.
- **Literal execution of every generated walkthrough.** The first wave's real
  defects were found only this way and were invisible to review: a false claim
  about a leading leak byte, `NameError` on undeclared constants at the reader's
  first command, a route made unreachable by a symbol-type filter, and protections
  silently defaulting to "unprotected" so the engine taught ret2shellcode on an
  NX binary. Rendering is not verification; running is.
- Preflight verifies instructions at claimed addresses; digest mismatch warns,
  verification failure refuses.
- No self-scoring anywhere: a walkthrough is never credited by `b"flag" in out`.

## Sequencing

1. Merge `feat/walkthrough-engine-20260923`.
2. Format string (full).
3. Integer (full).
4. Heap (detection floor; exploitation only if the floor is solid).
5. Resolve the R5 gate interaction above.
6. R5.
