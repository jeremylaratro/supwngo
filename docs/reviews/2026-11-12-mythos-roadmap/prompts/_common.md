
---
## How to work

1. Read `_review/BRIEF.md` first. It is the shared context for five parallel dimension reviews; you own
   only the dimension above. Other reviewers cover the rest, so go deep rather than wide.
2. Explore the code yourself with Read / Grep / Glob. Read real code before judging it. Cite `path:line`.
3. You are read-only and must stay inside the current directory. You cannot run anything.

## Output (markdown, this exact structure, ~2,500–4,500 words)

### 0. Verdict
Five bullets: the blunt state of this dimension and the single highest-leverage move.

### 1. Findings
Numbered `<DIM>-F<n>`. Each: **severity** (critical / high / medium / low), **evidence** (`path:line`,
quoted where short), **why it matters** for the owner's goals. Mark UNVERIFIED where you inferred.

### 2. Recommendations
Numbered `<DIM>-R<n>`, ordered by leverage. Each: what to do (concrete — modules, interfaces, tools),
**impact**, **effort** (S ≤ 2 days / M ≤ 2 weeks / L > 2 weeks), **dependencies** (other R-ids, any
dimension), **risk**, and a **falsifiable success measure** (a number or observable on a named set).

### 3. Hypotheses and experiments
Numbered `<DIM>-H<n>`. Each: hypothesis, the cheapest experiment that tests it, and the **falsifier**
(the result that would prove it wrong).

### 4. Best-in-class gap
What the strongest tools, research systems and teams do in this dimension that supwngo does not.
Name them specifically, and say which ideas are worth copying here and which are not (and why).

### 5. Questions for the owner
Only questions whose answers would change the roadmap.
