# supwngo Implementation Plan

## Overview

This plan organizes new exploit techniques into 8 phases, each designed to be:
- Completable in 1-3 hours
- Self-contained and testable
- Building on previous work where applicable

---

## Phase 1: Stack Exploitation Enhancements
**Estimated Time:** 2 hours | **Difficulty:** Easy-Medium

Building on existing stack exploitation, add techniques for bypassing modern protections.

| Feature | Description | Files to Create/Modify |
|---------|-------------|----------------------|
| Stack Pivoting | Redirect RSP to controlled buffer for extended ROP | `exploit/rop/pivot.py` |
| ret2reg | Find jmp/call reg gadgets, exploit when reg points to buffer | `exploit/rop/gadgets.py` |
| Partial Overwrite | Overwrite only lower bytes to bypass PIE (brute force last 12 bits) | `exploit/bypass.py` |

**Test Binary:** Create a PIE-enabled binary with small buffer that requires pivoting.

---

## Phase 2: Format String Automation
**Estimated Time:** 2 hours | **Difficulty:** Medium

Automate format string exploitation from detection to shell.

| Feature | Description | Files to Create/Modify |
|---------|-------------|----------------------|
| Blind Offset Finder | Automatically find format string offset via binary search | `vulns/format_string.py` |
| One-Shot Exploit | Generate single printf payload for GOT overwrite | `exploit/format_string.py` |
| Arbitrary Write Primitive | Abstracted write-what-where via format string | `exploit/format_string.py` |

**Test Binary:** Simple printf vulnerability with canary and Full RELRO.

---

## Phase 3: Heap Fundamentals
**Estimated Time:** 3 hours | **Difficulty:** Medium

Core heap exploitation techniques that form the foundation for advanced attacks.

| Feature | Description | Files to Create/Modify |
|---------|-------------|----------------------|
| House of Force | Overflow top chunk size, allocate at arbitrary address | `exploit/heap/house_of_force.py` |
| House of Spirit | Create fake chunk in stack/bss, free it for arbitrary alloc | `exploit/heap/house_of_spirit.py` |
| Unsorted Bin Attack | Corrupt unsorted bin to write main_arena pointer | `exploit/heap/unsorted_bin.py` |

**Test Binaries:** Three separate heap challenges, one per technique.

---

## Phase 4: Modern Heap Techniques
**Estimated Time:** 3 hours | **Difficulty:** Hard

Techniques for glibc 2.26+ with tcache and modern mitigations.

| Feature | Description | Files to Create/Modify |
|---------|-------------|----------------------|
| Tcache Poisoning v2 | Handle tcache key checks (glibc 2.32+) | `exploit/heap/tcache.py` |
| Large Bin Attack | Corrupt large bin for arbitrary write | `exploit/heap/large_bin.py` |
| Safe-Linking Bypass | Detect and demangle safe-linked pointers | `exploit/heap/safe_linking.py` |

**Test Binaries:** Challenges compiled with different glibc versions.

---

## Phase 5: Advanced ROP Techniques
**Estimated Time:** 2-3 hours | **Difficulty:** Medium-Hard

Universal ROP techniques that work across binaries.

| Feature | Description | Files to Create/Modify |
|---------|-------------|----------------------|
| ret2csu Automation | Auto-generate __libc_csu_init gadget chains | `exploit/rop/ret2csu.py` |
| ret2dlresolve Full | Complete implementation with fake link_map | `exploit/rop/ret2dlresolve.py` |
| Gadget Chain Optimizer | Find minimal gadget chains for common operations | `exploit/rop/optimizer.py` |

**Test Binary:** Statically-linked binary with minimal gadgets.

---

## Phase 6: Kernel Exploitation Basics
**Estimated Time:** 3-4 hours | **Difficulty:** Hard

Foundation for kernel exploitation (requires test VM setup).

| Feature | Description | Files to Create/Modify |
|---------|-------------|----------------------|
| ret2usr | Build payload that returns to userspace shellcode | `kernel/ret2usr.py` |
| modprobe_path | Overwrite modprobe_path for root shell | `kernel/modprobe.py` |
| Kernel ROP | Basic kernel ROP chain builder (commit_creds, etc.) | `kernel/krop.py` |

**Test Environment:** QEMU VM with vulnerable kernel module.

---

## Phase 7: Race Conditions & Misc
**Estimated Time:** 2 hours | **Difficulty:** Medium

Miscellaneous techniques for specific scenarios.

| Feature | Description | Files to Create/Modify |
|---------|-------------|----------------------|
| TOCTOU Detection | Detect time-of-check/time-of-use vulnerabilities | `vulns/race.py` |
| Signal Handler Exploit | Exploit async signal handler re-entrancy | `exploit/signal_handler.py` |
| LD_PRELOAD Generator | Generate malicious .so for LD_PRELOAD hijacking | `exploit/ld_preload.py` |

**Test Binaries:** SUID binary with race condition, signal handler vuln.

---

## Phase 8: Integration & Auto-Chaining
**Estimated Time:** 2-3 hours | **Difficulty:** Medium

Tie everything together with intelligent technique selection.

| Feature | Description | Files to Create/Modify |
|---------|-------------|----------------------|
| Technique Chainer | Automatically chain primitives (leak → write → exec) | `exploit/chainer.py` |
| Smart Auto-Exploit | Improved auto.py that tries all applicable techniques | `exploit/auto.py` |
| Comprehensive Tests | Full test suite for all implemented techniques | `tests/` |

---

## Implementation Schedule

| Phase | Cron Run | Features |
|-------|----------|----------|
| 1 | Run 1 | Stack Pivoting, ret2reg, Partial Overwrite |
| 2 | Run 2 | Blind Format String, One-Shot, Arbitrary Write |
| 3 | Run 3 | House of Force, House of Spirit, Unsorted Bin |
| 4 | Run 4 | Tcache v2, Large Bin, Safe-Linking |
| 5 | Run 5 | ret2csu, ret2dlresolve, Optimizer |
| 6 | Run 6 | ret2usr, modprobe_path, Kernel ROP |
| 7 | Run 7 | TOCTOU, Signal Handler, LD_PRELOAD |
| 8 | Run 8 | Chainer, Smart Auto, Tests |

---

## Success Criteria

Each phase must:
1. Pass import tests (no syntax errors)
2. Include at least one working example
3. Integrate with existing CLI where applicable
4. Update `__init__.py` exports
5. Add docstrings and type hints

---

## Dependencies

- **pwntools** - Core exploitation
- **ropper/ROPgadget** - Gadget finding
- **angr** - Symbolic execution (optional)
- **capstone** - Disassembly
- **keystone** - Assembly
- **QEMU** - Kernel testing (Phase 6 only)
