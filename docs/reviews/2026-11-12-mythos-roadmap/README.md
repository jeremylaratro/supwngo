# Mythos 5-2 roadmap review (2026-11-12)

This folder is the record of the adversarial review that re-focused supwngo on the owner's PASS criteria (stated
2026-11-12). The criteria:
- the tool outputs the right method;
- it then either works with a supplied component, or emits a template that works with manual inputs;
- decompilation works on ELF and PE;
- the offset is visible on every target.

**Result:** `docs/roadmaps/2026-11-12-mythos-roadmap.md`.

## Pipeline

| Step | Model | Artefact | What it is |
|---|---|---|---|
| 0. Inputs | orchestrator (Opus 5.5) | `inputs/BRIEF.md`, `inputs/SCORECARD.md`, `inputs/SPOTCHECK.md` | The brief, the HTB scorecard on the PASS criteria at `1741b34`, and the orchestrator's spot-check experiments (Ghidra P-code frames, mingw PE fixtures, HYP-9 `solve` re-measure). |
| 1. Dimension reviews | Mythos 5-2 ×5, read-only | `dimension-reviews/D1.md`–`D5.md` | D1 architecture and scalability, D2 RE/VR depth and tools, D3 PASS-criteria gap, D4 LLM hooks and agent use, D5 evaluation and anti-overfitting. |
| 2. Synthesis | Mythos 5-2 | `synthesis-draft-mythos.md` | The draft roadmap, sprint map and plan. |
| 3. Peer review | Daybreak Blue (Codex, xhigh) | `peer-review-daybreak-blue-roadmap.md` | Adversarial review: 12 blocking and 8 non-blocking items. |
| 4. Fold | Mythos 5-2 | `roadmap-final-mythos.md` (§12 dispositions every item), `inputs/FOLD-NOTES.md` (facts supplied by the orchestrator) | The final roadmap. |
| 5. Verify | Mythos 5-2, single thread, **execution allowed** | `verify-mythos-execution.md` (follow-up PR) | Self-review of the final roadmap, run on a scratch copy of the repo. It runs the unit suite, the HTB scorecard from challenge-directory copies, cheap hypotheses and the SP-01/SP-02 RED tests, then writes amendments (AMD-n). This step was still running when this folder was first committed. Its record, prompt and launch script land in a follow-up docs PR, which also adds the amendments to roadmap §14. |

`prompts/` holds the prompt heads for steps 1–4.

## Superseded inputs

`inputs/S6-PLAN-DRAFT-superseded.md` is the S6 detector-depth draft that this review replaced. The roadmap's §5
gives the disposition of RT-08, RT-09 and RT-10.

## Conventions

**Citations.**
- `path:line` citations refer to commit `1741b34` unless stated otherwise.
- *(orchestrator-measured)* marks numbers from `inputs/SPOTCHECK.md` or the scorecard.

**Data handling.**
- No flag values, credentials or host secrets appear in these files. They were scanned before commit.
- Target binaries are not included. The HTB set lives under `tests/htb-targets/` and is used as smoke only
  (roadmap §1.4).
