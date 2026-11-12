1. **[MINOR — sound] `iter_callees` preserves semantics.**  
   At [cfg.py:184](/srv/share/dev/supwngo/supwngo/analysis/cfg.py:184), [static.py:396](/srv/share/dev/supwngo/supwngo/analysis/static.py:396), and [decompile.py:384](/srv/share/dev/supwngo/supwngo/analysis/decompile.py:384), deduplication by target matches the old unique-`Function` result because the KB supplies the canonical function for each address.

   - Recursion at [cfg.py:190](/srv/share/dev/supwngo/supwngo/analysis/cfg.py:190): unchanged for resolved direct self-calls. Existing name-collision behavior is not introduced by the shim.
   - `is_leaf` at [static.py:401](/srv/share/dev/supwngo/supwngo/analysis/static.py:401): unchanged; unresolved calls were not returned as `Function` objects previously.
   - Call counts: no call-site-frequency consumer exists in the reviewed ranges. Deduplication correctly prevents repeated call sites from becoming duplicate callees.
   - Minor fix: at [plan:54](/srv/share/dev/supwngo/docs/plans/2026-11-12-s4-angr-analysis-robustness-plan.md:54), remove “library” from the skipped-target claim. The actual rule is “`None` or absent from the KB”; a library/PLT function present in the KB would be yielded.

2. **[BLOCKER] Use a subprocess isolate, not a thread watchdog.**  
   The design at [plan:81](/srv/share/dev/supwngo/docs/plans/2026-11-12-s4-angr-analysis-robustness-plan.md:81) only times out the wait; it cannot stop `CFGFast` at [cfg.py:141](/srv/share/dev/supwngo/supwngo/analysis/cfg.py:141).

   The leak is real:

   - A normal non-daemon worker can prevent CLI interpreter shutdown.
   - A daemon thread may let a short-lived CLI exit, but remains unsafe while fallback/output continues.
   - Under pytest, the process persists, so runaway workers consume CPU/memory across tests.
   - Because `_build_cfg_angr()` is bound to the same analyzer, a worker that eventually leaves `CFGFast` can mutate `self.blocks`, call graphs, and the project KB after fallback has begun.

   Specific fix: run each angr operation in a spawned child process that constructs its own project from serializable inputs. On timeout: terminate, allow a short grace period, kill if necessary, and join. Return only serialized result data over IPC; never pass `self`, an angr project, or KB objects into the child. Add a test asserting the timed-out child is no longer alive.

3. **[HIGH] Keep S4a, but separate the three timeout closures within S4b.**  
   The port-versus-budget split at [plan:43](/srv/share/dev/supwngo/docs/plans/2026-11-12-s4-angr-analysis-robustness-plan.md:43) and [plan:77](/srv/share/dev/supwngo/docs/plans/2026-11-12-s4-angr-analysis-robustness-plan.md:77) is correct. Grouping all command timeouts under one acceptance item is too vague: [plan:88](/srv/share/dev/supwngo/docs/plans/2026-11-12-s4-angr-analysis-robustness-plan.md:88) promises explain/decompile recovery, but [plan:104](/srv/share/dev/supwngo/docs/plans/2026-11-12-s4-angr-analysis-robustness-plan.md:104) tests only the generic helper and `cfg snow_scan`.

   Specific fix: retain a shared subprocess-budget utility, but create separate work items and integration acceptance tests:

   - RT-05: `cfg snow_scan` → bounded capstone fallback.
   - RT-04 residual: both explain targets → bounded completion preserving already-completed sections.
   - Decompile: `sick_rop` → independently budget CFG construction and `Decompiler` at [decompile.py:371](/srv/share/dev/supwngo/supwngo/analysis/decompile.py:371).

   “Best partial result” also needs an explicit IPC/stage-boundary design; killing a child cannot recover arbitrary in-memory partial state.

4. **[MINOR — sound] No other removed-API hazard is evident in the reviewed ranges.**  
   All three `functions_called()` sites are accounted for at [cfg.py:184](/srv/share/dev/supwngo/supwngo/analysis/cfg.py:184), [static.py:396](/srv/share/dev/supwngo/supwngo/analysis/static.py:396), and [decompile.py:384](/srv/share/dev/supwngo/supwngo/analysis/decompile.py:384). Nothing else shown is identified by the supplied ground truth as removed. No fix required.

5. **[MEDIUM] The RED proof is non-vacuous, but its oracle is too weak.**  
   The test at [plan:101](/srv/share/dev/supwngo/docs/plans/2026-11-12-s4-angr-analysis-robustness-plan.md:101) genuinely exercises the regression if it demonstrably fails on base. However, merely asserting “non-empty” could pass from an unrelated or spurious edge and does not prove the angr path avoided fallback.

   Specific fix: use a committed, non-skipped fixture with a known direct `caller → callee` edge; assert that exact edge and assert that capstone fallback was not invoked. Do not use the optional/xfail HTB-target path for the primary RED proof.