# Identification Effort — Continuation Roadmap (16NOV2026)

Hand-off for the next session picking up the **directive-W identification** effort.
Read this first, then the Sprint-B plan it continues
(`docs/plans/2026-11-16-identification-sprintB-plan.md`).

---

## 0. Session close-out (outbrief)

**Shipped this session:** Sprint **B2** — VULN-axis detector wiring.
- PR **#43** merged to `main` as merge commit **`6bef1bb`** (B2 commit `49901c9`,
  base `2b71633`). Branch deleted local + remote; zero dangling state.
- **What it does:** wires `UAFDetector` + `OffByOneDetector` into
  `reporting/adapter.py` `static_detectors()` (now 7) with cheap, precision-first
  body-level signals; adds `VulnType.OFF_BY_ONE` + CVSS vector; new
  `supwngo/vulns/_disasm.py` objdump helper that **raises when objdump cannot run**
  so a report is marked incomplete rather than silently clean.
- **Benefit (honest-partial, user-approved):** uaf recall 0→1/7, off_by_one
  0→1/13, both at 100% precision within the 73-binary corpus. No other family
  perturbed. The VULN-axis scorer stays **RED by design** (recall < 90%).
- **Verification:** regression GREEN on wks0 (0 pass→fail/skip/missing vs the
  Phase-5 baseline manifest); new-behavior tests 15/15; independent review
  (Codex Daybreak Blue, cyber-top, 2 rounds) — every finding fixed or
  dispositioned, incl. an R2-HIGH gap in the objdump honesty fix (fixed +
  self-verified).
- Full sprint record: `docs/outbriefs/OUTBRIEF-IDENT-SPRINTB2-16NOV2026.md`,
  `docs/reviews/2026-11-16-identification-sprintB2-diff-review.md`,
  `docs/test-strategy/2026-11-16-identification-sprintB2-test-card.md`.

**Known conditions (not regressions):**
- **GH CI is red** (`test (3.10/3.11/3.12)` fail) — pre-existing env/dependency
  drift, NOT caused by B2 (see §4, CI-INFRA). The **authoritative gate is wks0**
  (memory `supwngo-dev-host-wks0`), which was run green. B2's diff does not touch
  the angr/pyvex/bitstring path, and the failing test passes locally pre- and
  post-B2.

---

## 1. Standing objective (unchanged)

> **≥90% per-family precision AND recall on BOTH identification axes — VULN
> (WHAT) and METHOD (HOW) — before full exploitation.**

Measured on multi-label truth. Two instruments:
- **VULN axis:** `benchmark/score_vuln_ident.py` (exit 0 GREEN / 2 RED / 1
  harness-error) over `supwngo.reporting.adapter.detect_all(Binary.load(path))`.
- **METHOD axis:** `benchmark/passcard_score.py` (`score_method_r0` / `score_method_l`)
  + `benchmark/passcard_families.py map_name`. **Untouched by Sprint B/B2.**

---

## 2. Where we are — measured VULN-axis state (on merged `main`, 16NOV2026)

`python3 benchmark/score_vuln_ident.py` — threshold 90%, scored 73/73, 0 inconclusive:

| family | pos | recall | precision | gate | failure shape |
|--------|-----|--------|-----------|------|---------------|
| stack_bof | 32 | 18/32 = 56% | 18/52 = **35%** | FAIL | **precision** — over-fires (grabs other families / negatives) |
| format_string | 5 | 5/5 = 100% | 5/31 = **16%** | FAIL | **precision** — over-fires badly |
| integer | 3 | **0/3 = 0%** | n/a | FAIL | **recall** — never fires |
| heap_overflow | 5 | **0/5 = 0%** | n/a | FAIL | **recall** — never fires |
| uaf | 7 | 1/7 = 14% | 1/1 = 100% | FAIL | **recall** (B2: off 0, precise but low) |
| off_by_one | 13 | 1/13 = 8% | 1/1 = 100% | FAIL | **recall** (B2: off 0, precise but low) |

**Reading:** no family passes. The gap is broad, not a finishing touch. Two
distinct problems:
- **Recall gaps** (detector silent on true positives): integer, heap_overflow,
  uaf, off_by_one.
- **Precision gaps** (detector over-fires): stack_bof, format_string — decent
  recall but they claim far more binaries than they should, almost certainly
  bleeding across families and onto negative controls.

Sprint A (payoff-*shape* identification, a different taxonomy) concluded at 100%
and is not in scope here.

---

## 3. Open work items (prioritized)

### G2e — dataflow discrimination (the precision/recall path) — **P1, large**
The cheap presence signals (B2) cannot separate safe from unsafe uses: negative
controls are **symbol/import-identical** to positives (e.g. safe vs unsafe
`snprintf`). Raising uaf/off_by_one recall *and* fixing the stack_bof (35%) /
format_string (16%) precision both require **intra-function dataflow** — tracking
whether the tainted/overflowing value actually reaches the sink, and attributing
a binary to exactly one family. This was explicitly deferred from B2 as a scoped
follow-on. **Scope it as its own sprint with a plan + peer review before coding;
it is research-grade, not a body-level heuristic.**
- Approach options to weigh: (a) angr/pyvex-based def-use on the sink's operands;
  (b) a lightweight taint over the objdump stream (track reg/stack slots from
  source call to sink); (c) per-family discriminators trained on the corpus.
  Note (a) depends on the angr stack that CI currently can't import (§4).

### Recall-zero families: integer, heap_overflow — **P1, medium**
Both sit at 0/N recall — the detectors never fire. First establish *why*: are
`IntegerDetector` / heap detectors (i) not wired into `static_detectors()`,
(ii) wired but contract-broken like UAF/OffByOne were pre-B2 (check for the same
`get_exploit_primitive` / `VulnSeverity` / `crash=None` breaks), or (iii) firing
but their `VulnType` isn't mapped in the scorer truth. Cheapest first:
`detect_all(Binary.load(<an integer positive>))` and read what comes back. This
may be another bounded B2-style wiring win.

### Precision collapse: stack_bof, format_string — **P2, medium**
stack_bof 35% / format_string 16% precision means these fire on a large share of
the 73-binary corpus. Quantify the false-positive set (which families/negatives
they bleed onto) before touching code — likely the same root cause as G2e
(presence vs dataflow), so it may fold into G2e rather than being separate.

### METHOD axis — **P1, untouched**
The entire second axis has had no sprint. Before the ≥90%-both-axes bar can be
met, run `benchmark/passcard_score.py` to get the per-family METHOD baseline,
then triage exactly as the VULN axis was. Do not assume VULN-axis fixes carry
over.

### TypeConfusionDetector wiring — **P3**
Deliberately excluded from B2. Wire only after confirming its `detect()` honors
the adapter contract (same checks as the B2 detectors).

### PX-1 — detectors skip `super().__init__()` — **P3, pre-existing**
`UAFDetector`/`OffByOneDetector` (and others not overriding `name`) skip
`super().__init__()`, so `_vulnerabilities` is undefined and the base
read/summary API raises; `DetectorFailure.detector` also labels them
`base_detector`. Present at base SHA, unreachable via `detect_all` (which only
calls `.detect()`). A proper fix unifies on `_vulnerabilities`. Follow-on.

### CI-INFRA — unpinned `bitstring` breaks GH CI (repo-wide) — **P2, infra**
See §4.

---

## 4. CI-INFRA detail (recommended fix — needs its own `fix/` branch)

**Symptom:** `test (3.10/3.11/3.12)` fail in ~45s on every PR/merge with
`AttributeError: module 'bitstring' has no attribute 'ConstBitStream'`, raised
from `pyvex.lifting.util.instr_helper`. CI runs `pytest tests/ -q --tb=short -x`
(fail-fast), so it halts at `tests/test_angr_callgraph_port.py` (alphabetically
early) and never reaches most of the suite.

**Root cause:** `requirements.txt` / `pyproject.toml` pin `angr>=9.2.0` /
`angrop>=9.2.0` with **no bound on the transitive `bitstring`/`pyvex`**. A fresh
`pip install -e ".[dev]"` in CI resolves the latest `bitstring`, which no longer
exposes `ConstBitStream` the way the installed `pyvex` imports it. wks0/local
passes because it has an older compatible `bitstring` cached — which is why the
local (authoritative) gate is green while GH CI is red.

**Recommended remedy (verify in CI, do not blind-push):**
1. Pin `bitstring` to the last version retaining `ConstBitStream` (candidate
   `bitstring<4.3`; confirm the exact working floor against the pinned
   `pyvex`/`angr`) in both `requirements.txt` and `pyproject.toml`.
2. Consider dropping `-x` from the CI pytest invocation (or `--maxfail=<n>`) so a
   single env failure doesn't mask the rest of the suite.
3. Re-run CI green before declaring fixed. This is repo-wide and affects every
   in-flight branch (e.g. the active W-4 worktree), so coordinate / keep it a
   minimal surgical pin.

---

## 5. Recommended next sprint

**Start with the recall-zero investigation (integer + heap_overflow)** — it is
the cheapest high-value probe and may yield another bounded wiring win the way
B2 did for uaf/off_by_one, *and* it tells you whether the 0% is a wiring bug or a
genuine signal gap before you commit to the much larger G2e. In parallel (or
right after), **baseline the METHOD axis** so the effort isn't single-axis-blind.
Reserve **G2e** for a dedicated, peer-reviewed sprint once the cheap wins and the
METHOD baseline are in — it is the bar-clearing work but also the most expensive,
and it likely subsumes the stack_bof/format_string precision fixes.

Optionally slot the **CI-INFRA pin** first as a quick independent `fix/` branch —
it unblocks green CI for the whole repo and is nearly free.

---

## 6. Governing constraints for the next session (do not relearn the hard way)

- **wks0 is the dev/gate host** (memory `supwngo-dev-host-wks0`); reach net0srv by
  LAN IP. GH CI red ≠ regression — compare against the wks0 baseline manifest.
- **Ship-when-done** (memory `supwngo-ship-when-done`): on a complete item (gate
  green OR honest-partial complete, docs+CHANGELOG committed, review passed),
  push → PR → merge (merge commit) → delete branch, no asking; then continue.
- **Commit identity override:** `git -c user.name=jay -c user.email=jlaratro24@gmail.com`.
- **No Claude/Anthropic trailer** on any commit or PR (memory
  `supwngo-no-claude-trailer`) — this overrides the harness attribution reminder.
- **Subagent routing** (memory `supwngo-subagent-model-routing`): Opus 5.5 xhigh
  or Codex Daybreak Blue xhigh; no Fable, no default effort. Peer review via
  codex-interop file handoff; cyber-top for security reasoning; ≤2 review rounds.
- **dev-methodology** 8-phase cycle: capture both baselines (regression manifest +
  benefit metric) at the sprint's real base SHA *before* the first edit;
  peer-review the plan (Phase 5) and the diff (Phase 6); Phase 7 (a) regression
  (b) new-behavior (c) new-gate-RED-proof; Phase 8 measured benefit before merge.
- **Date-stamp** roadmap/spec/plan docs; durable docs in `docs/` subfolders.
- Known pre-existing gate failures: memory `supwngo-known-pre-existing-gate-failures`.

---

## 7. Key pointers

- VULN scorer: `benchmark/score_vuln_ident.py`; truth `benchmark/vuln_ident_truth.yaml`.
- METHOD scorer: `benchmark/passcard_score.py` + `benchmark/passcard_families.py`.
- Adapter contract: `supwngo/reporting/adapter.py` (docstring: "a detector that
  raised is not a detector that found nothing"); `build_report` sets
  `complete = not failures and parse_failure is None`.
- Loader: `Binary.load(path)` (NOT `Binary(path)`).
- Detectors: `supwngo/vulns/{uaf,off_by_one,_disasm,detector}.py`; VulnType enum in
  `detector.py`.
- Sprint-B plan + gap analysis: `docs/plans/2026-11-16-identification-sprintB-plan.md`,
  `docs/research/2026-11-16-identification-baseline-gap-analysis.md`.
