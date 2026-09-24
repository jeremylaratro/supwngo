NOT-APPROVED

1. [BLOCKING] `UNINFORMATIVE` creates denominator inflation. Example: 8/10 targets pass; if a bare-arm leak makes one failing target succeed, it is excluded and the score rises from 80% to 88.9%. Gate on `FOLLOWABLE / predeclared eligible targets`; count `UNINFORMATIVE` as non-passing. Determine `VOID` eligibility independently before follower execution.

2. [BLOCKING] Three unobserved bare successes do not establish necessity. The “paired” runs are independent samples, and the verdict does not use within-pair outcomes anyway: it applies any-walkthrough-success versus zero-bare-success across all reps. Replace the necessity claim with a predeclared randomized treatment-effect measurement, reporting walkthrough-minus-bare success rate and a confidence bound.

3. [BLOCKING] Giving the follower the real `flag.txt` defeats attribution. It can read the flag, send those bytes to an echoing/input-reflecting target, and receive credit because the target wrote them. Freeze `exploit.py`, then mint a new unknown flag for independent verification. Use only a decoy flag during follower debugging.

4. [BLOCKING] Blindness is not enforced by changing cwd. The agent can potentially read absolute host paths, `$HOME` configuration/memory, environment variables, `/tmp`, credentials, prior results, or use built-in/network tools. The walkthrough’s absolute corpus path directly exposes an escape route. Require OS-level filesystem isolation, fresh HOME/TMP, an environment allowlist, no host mounts or tool-network access, and sandbox-relative artifact paths.

5. [BLOCKING] The selftest does not test the claimed scorer. It exercises known Python artifacts, not follower isolation, both-arm aggregation, `UNINFORMATIVE`, `VOID`, denominator arithmetic, missing measurements, or fresh-secret verification. A filename-special-casing scorer—or one that merely rejects crashing scripts—could pass. Add black-box full-CLI tests with renamed/runtime-mutated fixtures, the complete verdict truth table, stale-secret and target-echo laundering controls, and `witness`/`witness_argv` differential tests.

6. [MAJOR] “Bare arm never credited” conflates genuine failure with missing evidence. A timeout, CLI crash, quota exhaustion, or attribution failure in the bare arm can enable `FOLLOWABLE`. Represent success, exploit failure, follower failure, and instrument invalidity separately; require every scheduled bare trial to be valid before credit is possible.

7. [MAJOR] Best-of-N is tunable and non-monotonic. Increasing N raises the chance of both walkthrough success and disqualifying bare success; arm order, retries, budgets, and selective reruns can change the result. Fix N and arm order/randomization policy before execution, prohibit unreported retries or early stopping, and include every scheduled trial in the result.

8. [MAJOR] The agent can copy or execute the embedded reference solution, so the gate can collapse to template validity despite the stated distinction. If prose followability is intended, run a prose-only/redacted-code arm. Otherwise rename the metric to artifact usability and explicitly accept that executable answers satisfy it.

9. [MAJOR] The canonical gate arithmetic is unspecified and contradictory: `TEMPLATE_BROKEN` allegedly counts against a “strict rate,” yet the verdict table depends only on the agent arm. Specify one machine-checkable gate formula, verdict precedence, eligible target manifest, family treatment, and rule that subset runs cannot produce an R5 gate result.

10. [MINOR] Reproducibility fields are descriptive, not pinned. `sonnet` is a mutable alias, and recording CLI version does not hold behavior fixed. Pin an immutable model identifier and execution image, and hash the prompts, inputs, tool policy, artifacts, and reports.