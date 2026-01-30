# supwngo Framework - Phased Implementation Plan V2

## Executive Summary

This plan builds on the existing 8-phase implementation (now complete) to:
1. Add reverse engineering and analysis features for improved detection
2. Increase exploitation success rates through reliability improvements
3. Add advanced techniques based on CTF writeup analysis (51 challenges analyzed)
4. Create exhaustive testing against real challenge binaries

---

## Analysis Summary

### Current State (from codebase exploration)
- **86 Python files**, ~41,304 LOC
- **All 8 original phases complete**
- **18 CLI commands** working
- **100% detection accuracy** on test set (per TEST_RESULTS.md)

### Gaps Identified from Challenge Writeups
Based on analysis of 51 CTF challenge writeups:

| Technique | Writeup Frequency | Current Support | Gap |
|-----------|-------------------|-----------------|-----|
| Stack BOF + ROP | 94% (48/51) | Good | Edge cases |
| Information Leaks | 26% (13/51) | Partial | Auto-leak detection weak |
| Heap Exploitation | 35% (18/51) | Good | House of X incomplete |
| Format String | 16% (8/51) | Good | Multi-write scenarios |
| Canary Bypass | 14% (7/51) | Partial | More bypass techniques |
| ret2csu | 4% (2/51) | Complete | - |
| SROP | 2% (1/51) | Complete | - |

---

## Phase 1: Reverse Engineering & Analysis Enhancements
**Priority:** HIGH | **New LOC:** ~2,500

### 1.1 Control Flow Graph Analysis
**File:** `supwngo/analysis/cfg.py`

| Feature | Description |
|---------|-------------|
| Basic Block Extraction | Identify all basic blocks in functions |
| Call Graph Generation | Map function call relationships |
| Loop Detection | Find loops that may indicate vulnerabilities |
| Dominator Analysis | Critical path identification |
| Dead Code Detection | Find unreachable code paths |

### 1.2 Data Flow Analysis
**File:** `supwngo/analysis/dataflow.py`

| Feature | Description |
|---------|-------------|
| Taint Tracking | Track user input through program |
| Use-Def Chains | Variable definition and use relationships |
| Reaching Definitions | What definitions reach each use |
| Live Variable Analysis | Variables live at each point |
| Constant Propagation | Identify constant values |

### 1.3 Binary Diffing
**File:** `supwngo/analysis/diff.py`

| Feature | Description |
|---------|-------------|
| Function Matching | Match functions between binary versions |
| Patch Analysis | Identify security patches |
| Similarity Scoring | Bindiff-like similarity metrics |
| Symbol Recovery | Recover symbols from similar binaries |

### 1.4 String Analysis Enhancement
**File:** `supwngo/analysis/strings.py`

| Feature | Description |
|---------|-------------|
| Format String Detection | Find printf format specifiers in strings |
| Path Detection | Identify file paths and URLs |
| Command Detection | Find shell command patterns |
| Crypto Constant Detection | Identify crypto S-boxes, magic numbers |
| Encoding Detection | Base64, hex, XOR patterns |

### 1.5 Decompilation Integration
**File:** `supwngo/analysis/decompile.py`

| Feature | Description |
|---------|-------------|
| Ghidra Integration | Headless Ghidra decompilation |
| RetDec Integration | Alternative decompiler |
| Output Parsing | Extract variables, types, control flow |
| Pseudo-code Generation | Human-readable representation |

### 1.6 Import/Export Analysis
**File:** `supwngo/analysis/imports.py`

| Feature | Description |
|---------|-------------|
| Dependency Mapping | Full import dependency tree |
| Weak Symbol Detection | Find overridable symbols |
| Lazy Binding Analysis | Identify lazy-bound functions |
| Version Requirements | Detect glibc version requirements |

---

## Phase 2: Detection Accuracy Improvements
**Priority:** HIGH | **New LOC:** ~2,000

### 2.1 Enhanced Leak Detection
**File:** `supwngo/vulns/leak_finder.py`

| Feature | Description |
|---------|-------------|
| Auto Leak Pattern Detection | Find print/write with controllable addresses |
| Format String Leak Chains | Identify %p chains for info disclosure |
| Partial Overwrite Detection | When only low bytes need leaking |
| Libc Fingerprinting | Identify libc from leaked addresses |
| Stack Leak Detection | Identify stack address leaks |

### 2.2 Improved Heap Analysis
**File:** `supwngo/vulns/heap_advanced.py`

| Feature | Description |
|---------|-------------|
| Allocation Site Tracking | Map malloc/free to call sites |
| Size Mismatch Detection | Find allocation vs use size mismatches |
| Double-Free Path Analysis | Trace paths leading to double-free |
| Chunk Corruption Detection | Identify metadata corruption |
| Tcache Count Analysis | Track tcache entry counts |

### 2.3 Integer Vulnerability Enhancement
**File:** `supwngo/vulns/integer_advanced.py`

| Feature | Description |
|---------|-------------|
| Arithmetic Chain Analysis | Track integer through operations |
| Truncation Detection | Find narrowing conversions |
| Signedness Analysis | Signed/unsigned comparison issues |
| Allocation Size Tracking | size_t calculations before malloc |

### 2.4 Race Condition Detection Enhancement
**File:** `supwngo/vulns/race_advanced.py`

| Feature | Description |
|---------|-------------|
| File Operation Races | TOCTOU on file operations |
| Signal Handler Analysis | Re-entrancy issues |
| Thread Safety Analysis | Shared variable access patterns |
| Atomic Operation Detection | Missing atomics |

---

## Phase 3: Exploit Reliability & Edge Cases
**Priority:** HIGH | **New LOC:** ~2,500

### 3.1 Robust Offset Finding
**File:** `supwngo/exploit/offset_finder.py` (enhance)

| Feature | Description |
|---------|-------------|
| Multi-Input Offset Finding | Handle binaries with multiple inputs |
| Partial Overwrite Offsets | Find offsets for partial overwrites |
| Canary Position Detection | Locate canary relative to buffer |
| Saved RBP/RIP Distinction | Differentiate saved frame pointer |

### 3.2 Gadget Quality Scoring
**File:** `supwngo/exploit/rop/scoring.py`

| Feature | Description |
|---------|-------------|
| Side Effect Analysis | Rate gadgets by side effects |
| Register Clobber Tracking | Which registers are destroyed |
| Stack Adjustment Scoring | Prefer minimal stack changes |
| Reliability Scoring | Based on alignment, constraints |

### 3.3 Exploit Verification
**File:** `supwngo/exploit/verify.py`

| Feature | Description |
|---------|-------------|
| Payload Validation | Verify payload before sending |
| Bad Character Detection | Find and report bad chars |
| Alignment Checking | Verify stack alignment |
| Constraint Satisfaction | Check one-gadget constraints |

### 3.4 Libc Offset Automation
**File:** `supwngo/exploit/libc_auto.py`

| Feature | Description |
|---------|-------------|
| Multi-Symbol Leak | Leak multiple symbols for accuracy |
| Libc Matching Confidence | Score libc matches |
| Offset Verification | Verify offsets before exploit |
| Fallback Strategies | Try multiple libc versions |

### 3.5 PIE Bypass Automation
**File:** `supwngo/exploit/pie_bypass.py`

| Feature | Description |
|---------|-------------|
| Partial Overwrite Automation | Auto-generate partial overwrites |
| Brute Force Integration | Smart brute forcing (4 bits) |
| Base Leak Detection | Find PIE base leaks |
| Relative Addressing | Use relative jumps when possible |

---

## Phase 4: Advanced Technique Integration
**Priority:** MEDIUM | **New LOC:** ~3,000

### 4.1 House of Techniques Completion
**Files:** `supwngo/exploit/heap/house_of_*.py`

| Technique | Status | Action |
|-----------|--------|--------|
| House of Force | Complete | Test thoroughly |
| House of Spirit | Complete | Test thoroughly |
| House of Lore | Missing | Implement |
| House of Orange | Missing | Implement |
| House of Einherjar | Missing | Implement |
| House of Roman | Missing | Implement |
| House of Rabbit | Missing | Implement |

### 4.2 Advanced ROP Techniques
**Files:** `supwngo/exploit/rop/advanced.py`

| Technique | Description |
|-----------|-------------|
| Blind ROP (BROP) | ROP without binary access |
| JOP (Jump-Oriented) | Jump-based chains |
| COP (Call-Oriented) | Call-based chains |
| COOP | Counterfeit OOP exploitation |

### 4.3 Seccomp Bypass Enhancement
**File:** `supwngo/exploit/seccomp_bypass.py`

| Feature | Description |
|---------|-------------|
| Rule Extraction | Parse seccomp rules from binary |
| Allowed Syscall Mapping | Find usable syscalls |
| ORW Chain Generation | open/read/write chains |
| Arch Switching | x86 vs x86_64 syscall differences |

### 4.4 ASLR Entropy Analysis
**File:** `supwngo/exploit/aslr_analysis.py`

| Feature | Description |
|---------|-------------|
| Entropy Calculation | Bits of entropy per region |
| Brute Force Feasibility | Calculate attempts needed |
| Partial Leak Value | How much partial leak helps |
| ASLR Weakness Detection | Find low-entropy scenarios |

---

## Phase 5: Exhaustive Testing Suite
**Priority:** HIGH | **New LOC:** ~1,500

### 5.1 Challenge Binary Test Suite
**Directory:** `tests/challenges/`

| Category | Test Binaries | Source |
|----------|---------------|--------|
| ret2win | 5 binaries | Custom + writeups |
| ret2libc | 5 binaries | Custom + writeups |
| ROP chain | 5 binaries | Custom + writeups |
| Format string | 5 binaries | Custom + writeups |
| Heap UAF | 5 binaries | Custom + writeups |
| Heap tcache | 5 binaries | Custom + writeups |
| Canary bypass | 3 binaries | Custom + writeups |
| PIE bypass | 3 binaries | Custom + writeups |
| SROP | 2 binaries | Custom |
| Kernel | 2 modules | Custom |

### 5.2 Regression Tests
**File:** `tests/test_regression.py`

| Test Type | Description |
|-----------|-------------|
| Detection Regression | Ensure no false negatives introduced |
| Exploit Regression | Verify exploits still work |
| Performance Regression | Track analysis time |
| Output Format Regression | CLI output consistency |

### 5.3 Integration Tests
**File:** `tests/test_integration.py`

| Test Type | Description |
|-----------|-------------|
| Full Pipeline Test | analyze -> detect -> exploit |
| Multi-Binary Test | Batch processing |
| Remote Exploitation | Local + remote targets |
| Libc Integration | End-to-end libc identification |

### 5.4 Fuzzing the Framework
**File:** `tests/fuzz_framework.py`

| Test Type | Description |
|-----------|-------------|
| Malformed ELF Handling | Corrupted binaries |
| Edge Case Inputs | Empty, huge, stripped binaries |
| Crash Recovery | Framework stability |

---

## Implementation Schedule

| Phase | Focus | Key Deliverables |
|-------|-------|------------------|
| **Phase 1** | RE & Analysis | CFG, dataflow, diffing, decompilation |
| **Phase 2** | Detection | Leak finder, heap analysis, integer vuln |
| **Phase 3** | Reliability | Offset finding, gadget scoring, verification |
| **Phase 4** | Advanced | House of X, BROP, seccomp bypass |
| **Phase 5** | Testing | 40+ test binaries, regression suite |

---

## Success Criteria

### Detection Metrics
- **Recall:** ≥ 98% (catch almost all vulnerabilities)
- **Precision:** ≥ 90% (minimize false positives)
- **F1 Score:** ≥ 94%

### Exploitation Metrics
- **ret2win:** 100% success on applicable binaries
- **ret2libc:** ≥ 90% success with leak available
- **ROP chains:** ≥ 85% success with gadgets available
- **Format string:** ≥ 90% success
- **Heap:** ≥ 80% success on standard patterns

### Performance Metrics
- **Analysis time:** < 30s for typical binary
- **Exploit generation:** < 60s for standard techniques
- **Memory usage:** < 2GB for any binary

---

## Dependencies

### Required Tools
- pwntools, angr, capstone, keystone-engine
- ropper, ROPgadget
- Ghidra (optional, for decompilation)
- GDB with pwndbg/gef

### Python Packages
- networkx (for CFG)
- z3-solver (for constraint solving)
- lief (for binary parsing)
- unicorn (for emulation)

---

## Notes

- Each phase builds on previous phases
- Testing integrated throughout, not just Phase 5
- Real CTF binaries used for validation
- Framework stability prioritized over feature count
