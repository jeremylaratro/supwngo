# Orchestrator fold notes (2026-11-12, after the draft)

Facts the final roadmap must carry (all measured or read by the orchestrator):

1. **HYP-9 MEASURED.** `htb_rescore --reps 3 --timeout 300` at 1741b34: 7/7, 21/21 reps `shell_proven`,
   0 hard errors. `solve` has not regressed. It is still smoke (DEC-5), not generalisation evidence.
2. **ancient_interface ground truth** (from disassembly):
   - Function `0x40189b` runs the loop `read(0, rbp-0x1010 + n, want - n)` at `0x401a00-0x401a36`. The
     canary is at `rbp-8`.
   - Distances: `buf_to_ret` = 4120, `buf_to_canary` = 4104.
   - The primitive is a signed-accumulator underflow into the cursor at `rbp-0x1020` (buffer − 16).
   - Ghidra frame local `-4120` agrees.
3. **snow_scan ground truth.** The primitive is a low-byte rewrite of the fill loop's base pointer in a VLA
   frame (`container_file_techniques.py:15-32`). There is no fixed saved-RIP offset. Distance kind is
   `indexed_base_ptr` (non-stack-ret), with frame-relative distances only.
4. **Leftovers from the previous gap-closure effort (S7) must have a home in the sprint map:**
   - **I-45**: in-place redaction of three captured-flag literals in corpus YAML comments. → **SP-01**.
   - **HO-01**: delete the dead `pie_base_offset()` (`rop_techniques.py:128`; zero callers, confirmed with
     `git grep`). → **SP-01**.
   - **HO-02**: the 2.2.0 tag → end of SP-02 (DEC-24 already).
   - **S-libc-binding**:
     - CG-04, run the target against a supplied libc/loader (patchelf), → SP-02/SP-06 (the patchelf row
       already exists);
     - CG-01b, the offset-libc vs loaded-libc mismatch detector, → SP-07 with the local libc-database.
     Make the placement explicit in the sprint map's "Closes" column.
5. **SP-01 is being implemented as two PRs**:
   - SP-01a: passcard v0 + truth + baseline + I-45;
   - SP-01b: the honesty fixes + HO-01.
   The detailed SP-01 plan is in the repo as `docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md`
   and is not in this tree. Keep the roadmap's SP-01 section consistent with that split.
