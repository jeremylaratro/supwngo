## BLOCKING

1. **Timeout cleanup can leak/zombify processes.**  
   [plan:76](/srv/share/dev/supwngo/docs/plans/2026-11-12-s5-ghidra-decompile-plan.md:76) kills the group and immediately returns. `TimeoutExpired` does not reap the child or close/drain its pipes. Also, `os.getpgid(p.pid)` can race with launcher exit and raise `ProcessLookupError`, potentially leaving Java descendants alive. Because `start_new_session=True` makes `pgid == pid`, call `os.killpg(p.pid, SIGKILL)`, catch `ProcessLookupError`/`OSError`, then always call `communicate()` or `wait()` to reap. Cleanup should also run for exceptions after `Popen` succeeds.

2. **Output validation can still report fake “Ghidra success.”**  
   [plan:82](/srv/share/dev/supwngo/docs/plans/2026-11-12-s5-ghidra-decompile-plan.md:82) must define `returncode == 0`, JSON type/schema validation, and a non-empty `code`. The unchanged parser accepts `[{}]` and returns a function with empty pseudo-C ([decompile.py:272](/srv/share/dev/supwngo/supwngo/analysis/decompile.py:272)). Set `analysis_backend="ghidra"` only after `_parse_ghidra_output()` returns a result whose `code.strip()` is non-empty.

3. **`[]` is not actually distinguished from failure in the described Python flow.**  
   The Java contract at [plan:67](/srv/share/dev/supwngo/docs/plans/2026-11-12-s5-ghidra-decompile-plan.md:67) enables the distinction, but [plan:82](/srv/share/dev/supwngo/docs/plans/2026-11-12-s5-ghidra-decompile-plan.md:82) treats every non-success generically. Branch explicitly:

   - missing/zero-byte/malformed/non-list output: script did not produce a usable result;
   - valid `[]` with exit 0: script ran, selector found/decompiled nothing;
   - non-empty list: validate first object and pseudo-C.

4. **Missing-resource fallback is asserted but not designed.**  
   [plan:70](/srv/share/dev/supwngo/docs/plans/2026-11-12-s5-ghidra-decompile-plan.md:70) only constructs a path; [plan:131](/srv/share/dev/supwngo/docs/plans/2026-11-12-s5-ghidra-decompile-plan.md:131) claims a missing resource returns `None`. Without an `is_file()` preflight, it launches Ghidra and may consume the full 180 seconds before falling back. Require an immediate guard. Add the Java glob to both packaging configurations ([pyproject.toml:102](/srv/share/dev/supwngo/pyproject.toml:102), [setup.py:75](/srv/share/dev/supwngo/setup.py:75)), preferably `MANIFEST.in`, and verify contents of built wheel and sdist. That also validates the stable on-disk path/cache assumption.

5. **Selector encoding is ambiguous and underspecified.**  
   A single content-discriminated arg makes numeric function names impossible to select, and the plan does not define precedence when both name and address are supplied—`decompile_all()` supplies both ([decompile.py:487](/srv/share/dev/supwngo/supwngo/analysis/decompile.py:487)). Use tagged selectors (`name:…`, `addr:…`) or explicitly preserve/test precedence. Address handling must use `is not None`, support unsigned 64-bit values, and avoid `Long.decode()` failure above `Long.MAX_VALUE`.

6. **The JSON escaper needs an explicit tested contract.**  
   “Hand-rolled” at [plan:66](/srv/share/dev/supwngo/docs/plans/2026-11-12-s5-ghidra-decompile-plan.md:66) is insufficient for the core interchange. It must escape quote, backslash, and every U+0000–U+001F character, and write UTF-8 explicitly. Test quotes, backslashes, newlines, tabs, and an uncommon control character.

7. **The environment override can defeat the claimed ceiling.**  
   [plan:79](/srv/share/dev/supwngo/docs/plans/2026-11-12-s5-ghidra-decompile-plan.md:79) needs finite-positive validation and a documented hard maximum or rejection of excessive values. `NaN`, infinity, negative values, malformed strings, or arbitrarily large values otherwise make “bounded” false. A 180-second default is defensible for this integration goal, but only with reliable kill-and-reap behavior.

8. **The RED proof is backwards, and slow tests will run by default.**  
   [plan:105](/srv/share/dev/supwngo/docs/plans/2026-11-12-s5-ghidra-decompile-plan.md:105) proposes asserting the broken behavior; that is green before the fix and red afterward. The committed test must assert desired Ghidra output and be shown failing on the old tree. Public `decompile()` can hide the defect via angr, so assert real Ghidra availability and `analysis_backend == "ghidra"` plus non-empty pseudo-C, or call `_decompile_ghidra()` directly. Also, `slow` is only a marker and is not excluded by default ([pyproject.toml:144](/srv/share/dev/supwngo/pyproject.toml:144)); two real Ghidra tests can add minutes to the normal suite. Make them explicitly opt-in.

## NON-BLOCKING

- Add hermetic tests for timeout kill/reap, `ProcessLookupError`, nonzero exit, missing/empty/malformed output, valid `[]`, empty code, and missing package resource.
- Log bounded tails of both stdout and stderr; Ghidra diagnostics are not guaranteed to use stderr.
- Use try/finally around `DecompInterface` disposal and try-with-resources for the writer.
- Document the no-selector behavior change: current code attempts up to 100 functions, whereas the plan selects `main`/entry/first, even though only the first parsed result was returned.