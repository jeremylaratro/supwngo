# supwngo - Cutting Edge Exploitation Roadmap

## Vision: The Definitive Binary Exploitation Framework

Transform supwngo into **the go-to framework** for binary exploitation, progressing from CTF dominance to real-world vulnerability research capability.

---

## Gap Analysis: What's Missing

Based on analysis of the current roadmap and 2023-2025 exploitation trends:

| Category | Current Coverage | Gap |
|----------|-----------------|-----|
| Heap (glibc 2.32+) | Basic House of X | Safe-linking bypass, modern tcache, new House techniques |
| Kernel | Basic concepts | msg_msg, io_uring, pipe_buffer, modprobe_path |
| Browser/V8 | None | Type confusion, JIT bugs, sandbox escape |
| Hardware-Assisted | None | Intel PT, side channels, hardware breakpoints |
| Container/Cloud | None | Container escape, K8s exploitation |
| Fuzzing | Basic AFL | Snapshot fuzzing, grammar-aware, CMPLOG |
| Real-World | CTF-focused | Patch diffing, 1-day development, exploit reliability |

---

## TIER 1: Modern Heap Exploitation (glibc 2.32+)

**Priority: CRITICAL** - Most CTFs and real-world targets use modern glibc

### 1.1 Safe-Linking Bypass

glibc 2.32+ introduced safe-linking (pointer mangling) in tcache and fastbins.

```python
# supwngo/exploit/heap/safe_linking.py

class SafeLinkingBypass:
    """
    Bypass glibc 2.32+ safe-linking protection.

    Safe-linking: P' = (P >> 12) ^ L
    Where P = pointer, L = storage location

    To bypass, we need:
    1. Heap address leak (to know L)
    2. Or brute-force 12 bits of entropy (4096 attempts)
    """

    def demangle_pointer(self, mangled: int, heap_base: int) -> int:
        """Demangle a safe-linked pointer."""
        # P = P' ^ (L >> 12)
        storage_addr = heap_base  # approximate location
        return mangled ^ (storage_addr >> 12)

    def mangle_pointer(self, ptr: int, storage_addr: int) -> int:
        """Mangle a pointer for safe-linking."""
        return (ptr >> 12) ^ storage_addr

    def find_heap_leak(self, binary: Binary) -> Optional[LeakPrimitive]:
        """Find primitives to leak heap addresses for demangling."""
        pass

    def brute_force_strategy(self) -> BruteForceConfig:
        """
        Configure brute-force approach (4096 attempts max).

        Viable when:
        - Process doesn't crash on failed attempt
        - Or can fork/respawn
        """
        return BruteForceConfig(
            bits=12,
            max_attempts=4096,
            expected_success=2048  # on average
        )
```

### 1.2 Tcache Key Bypass (glibc 2.34+)

glibc 2.34 added tcache key to detect double-free.

```python
# supwngo/exploit/heap/tcache_key.py

class TcacheKeyBypass:
    """
    Bypass tcache key double-free protection.

    The key is stored at chunk+0x8 (where fd would be in fastbin).
    Key = &tcache ^ random_value

    Bypass methods:
    1. Corrupt key field before second free
    2. Use House of Botcake (avoid tcache entirely)
    3. Chunk overlap to modify key
    4. UAF to modify key directly
    """

    def corrupt_key_via_overflow(
        self,
        overflow_size: int,
        target_chunk: int
    ) -> bytes:
        """Generate overflow payload to corrupt tcache key."""
        pass

    def house_of_botcake(
        self,
        alloc_primitive: Callable,
        free_primitive: Callable
    ) -> HeapExploit:
        """
        House of Botcake - double free via unsorted bin.

        Works against tcache key because unsorted bin
        doesn't have the same protection.

        Steps:
        1. Fill tcache (7 chunks)
        2. Free chunk A (goes to unsorted)
        3. Free chunk B (goes to unsorted, consolidates with A)
        4. Allocate from tcache (empties one slot)
        5. Free chunk B again (goes to tcache - double free!)
        """
        pass
```

### 1.3 Modern House of X Techniques

```python
# supwngo/exploit/heap/house_of_modern.py

class HouseOfKiwi:
    """
    House of Kiwi - Exploit via _IO_file_sync.

    Targets glibc 2.29+ where traditional FSOP is patched.
    Uses __malloc_assert path triggered by corrupted top chunk.

    Requirements:
    - Arbitrary write primitive
    - Can trigger __malloc_assert (corrupt top chunk size)
    - glibc < 2.36 (patched in 2.36)
    """

    def build_payload(
        self,
        rip_control_addr: int,
        rdx_value: int
    ) -> bytes:
        """
        Build House of Kiwi payload.

        Overwrites:
        - _IO_helper_jumps + 0xa0 (sync pointer)
        - _IO_file_jumps + 0x60 (sync offset)
        """
        pass


class HouseOfEmma:
    """
    House of Emma - vtable hijack via _IO_cookie_jumps.

    Bypass vtable verification by using _IO_cookie_jumps
    which calls a function pointer from the FILE structure.

    Requirements:
    - Heap overflow or UAF
    - Ability to trigger FILE operations
    """

    def build_fake_file(
        self,
        func_ptr: int,
        rdi_value: int
    ) -> bytes:
        """Build fake FILE structure for House of Emma."""
        pass


class HouseOfPig:
    """
    House of Pig - Combine Tcache Stashing Unlink with FSOP.

    Uses tcache stashing unlink attack to write to
    __free_hook (glibc < 2.34) or IO structures.
    """
    pass


class HouseOfBanana:
    """
    House of Banana - Exploit via _rtld_global._dl_ns.

    Targets ld.so's link_map structure for code execution.
    Works even with full RELRO.

    Requirements:
    - Large arbitrary write
    - Program calls exit() or returns from main
    """

    def find_link_map(self, binary: Binary) -> int:
        """Find _rtld_global address."""
        pass

    def build_fake_link_map(
        self,
        func_ptr: int,
        arg: int
    ) -> bytes:
        """Build fake link_map for l_info array hijack."""
        pass


class HouseOfHusk:
    """
    House of Husk - Exploit via __printf_function_table.

    Targets printf's custom format specifier mechanism.

    Requirements:
    - Two arbitrary writes (or large write)
    - Ability to call printf
    """
    pass


class HouseOfLore:
    """
    House of Lore - Small bin corruption attack.

    Corrupts small bin to return arbitrary addresses.
    Useful when tcache is full or for older glibc.
    """
    pass


class HouseOfRabbit:
    """
    House of Rabbit - fastbin consolidation attack.

    Triggers malloc_consolidate to move fastbin chunks
    to unsorted bin, bypassing fastbin size checks.
    """
    pass


class HouseOfRoman:
    """
    House of Roman - Create overlapping chunks without leaks.

    Uses fastbin dup + partial overwrite to achieve
    arbitrary allocation without info leaks.
    """
    pass
```

### 1.4 Tcache Stashing Unlink Attack

```python
class TcacheStashingUnlink:
    """
    Tcache Stashing Unlink Attack.

    When calloc triggers smallbin allocation and tcache refill,
    can cause arbitrary write via corrupted bk pointer.

    Target: Write to __free_hook, __malloc_hook (pre-2.34)
            Or IO structures (2.34+)
    """

    def setup_smallbin(
        self,
        target_addr: int,
        alloc_primitive: Callable,
        free_primitive: Callable
    ) -> None:
        """Setup smallbin with corrupted bk for attack."""
        pass
```

---

## TIER 2: Modern Kernel Exploitation

**Priority: HIGH** - Essential for real-world and advanced CTFs

### 2.1 msg_msg Exploitation

```python
# supwngo/kernel/msg_msg.py

class MsgMsgExploit:
    """
    Linux kernel msg_msg structure exploitation.

    msg_msg is a powerful primitive because:
    - Flexible size (allows cross-cache attacks)
    - Can leak kernel pointers via msg_copy
    - Can be used for UAF to arbitrary read/write

    Structure:
    struct msg_msg {
        struct list_head m_list;  // +0x00
        long m_type;              // +0x10
        size_t m_ts;              // +0x18 (total size)
        struct msg_msgseg *next;  // +0x20
        void *security;           // +0x28
        // data follows...
    };
    """

    def create_msg(self, size: int, mtype: int = 1) -> int:
        """Create msg_msg of specified size."""
        pass

    def spray_msg(self, count: int, size: int) -> List[int]:
        """Spray msg_msg structures for heap shaping."""
        pass

    def leak_via_msg_copy(
        self,
        corrupted_msg: int,
        fake_size: int
    ) -> bytes:
        """Exploit msg_copy to leak adjacent memory."""
        pass

    def arbitrary_read(
        self,
        target_addr: int,
        size: int
    ) -> bytes:
        """Use corrupted msg_msg->next for arbitrary read."""
        pass
```

### 2.2 io_uring Exploitation

```python
# supwngo/kernel/io_uring.py

class IoUringExploit:
    """
    io_uring subsystem exploitation.

    io_uring vulnerabilities are common because:
    - Complex async I/O subsystem (lots of code)
    - Runs in kernel context
    - Many object lifetimes to manage

    Common bug classes:
    - UAF in request handling
    - Race conditions in async operations
    - Reference counting bugs
    """

    def setup_ring(self, entries: int = 256) -> int:
        """Setup io_uring instance."""
        pass

    def exploit_uaf(
        self,
        alloc_target: int,
        payload: bytes
    ) -> None:
        """Exploit UAF in io_uring request."""
        pass
```

### 2.3 pipe_buffer Exploitation

```python
# supwngo/kernel/pipe_buffer.py

class PipeBufferExploit:
    """
    pipe_buffer structure exploitation.

    Made famous by Dirty Pipe (CVE-2022-0847).

    struct pipe_buffer {
        struct page *page;     // +0x00
        unsigned int offset;   // +0x08
        unsigned int len;      // +0x0c
        const struct pipe_buf_operations *ops;  // +0x10
        unsigned int flags;    // +0x18
        unsigned long private; // +0x20
    };

    Key insight: PIPE_BUF_FLAG_CAN_MERGE allows
    writing to page cache without proper checks.
    """

    def create_pipe_chain(self, length: int) -> int:
        """Create chain of pipe buffers."""
        pass

    def dirty_pipe_write(
        self,
        target_file: str,
        offset: int,
        data: bytes
    ) -> None:
        """
        Dirty Pipe style write to read-only file.

        Requirements:
        - Kernel 5.8+ (PIPE_BUF_FLAG_CAN_MERGE introduced)
        - Target file in page cache
        """
        pass
```

### 2.4 modprobe_path Overwrite

```python
# supwngo/kernel/modprobe.py

class ModprobePath:
    """
    modprobe_path overwrite technique.

    When kernel encounters unknown binary format,
    it executes modprobe_path (default: /sbin/modprobe).

    Overwrite to point to attacker script = root shell.

    Steps:
    1. Get arbitrary kernel write
    2. Overwrite modprobe_path with "/tmp/x"
    3. Write exploit script to /tmp/x
    4. Trigger unknown binary format (execute "\xff\xff\xff\xff")
    5. Script runs as root
    """

    def find_modprobe_path(self) -> int:
        """Find modprobe_path address (may need KASLR bypass)."""
        # Usually at fixed offset from kernel base
        pass

    def trigger_modprobe(self) -> None:
        """Trigger modprobe by executing invalid binary."""
        pass

    def build_rootkit_script(self, callback: str) -> str:
        """Generate script that will run as root."""
        return f"""#!/bin/sh
chmod 4755 /bin/bash
{callback}
"""
```

### 2.5 Cross-Cache Attacks

```python
# supwngo/kernel/cross_cache.py

class CrossCacheAttack:
    """
    Cross-cache exploitation techniques.

    Exploit UAF where vulnerable object and target object
    are in different SLUB caches.

    Key techniques:
    - Page-level UAF (free pages back to buddy allocator)
    - Cache aliasing
    - Slab merging exploitation
    """

    def find_compatible_caches(
        self,
        source_size: int,
        target_size: int
    ) -> List[CachePair]:
        """Find caches that might share pages."""
        pass

    def trigger_page_free(
        self,
        spray_count: int,
        free_func: Callable
    ) -> None:
        """Free enough objects to release page to buddy."""
        pass
```

### 2.6 userfaultfd Exploitation

```python
# supwngo/kernel/userfaultfd.py

class UserfaultfdExploit:
    """
    userfaultfd-based race condition exploitation.

    userfaultfd allows userspace to handle page faults,
    which can be used to pause kernel execution at
    precise points to win race conditions.

    Note: Requires CAP_SYS_PTRACE in kernel 5.11+
    """

    def setup_uffd(self, addr: int, size: int) -> int:
        """Setup userfaultfd region."""
        pass

    def race_window_exploit(
        self,
        setup_func: Callable,
        race_func: Callable
    ) -> None:
        """
        Use uffd to create race window.

        1. Map memory region with uffd
        2. Trigger kernel to access region
        3. Kernel blocks in uffd handler
        4. Run race_func while kernel paused
        5. Resume kernel with controlled data
        """
        pass
```

---

## TIER 3: Advanced Fuzzing Techniques

**Priority: HIGH** - Automation for vulnerability discovery

### 3.1 Snapshot Fuzzing

```python
# supwngo/fuzzing/snapshot.py

class SnapshotFuzzer:
    """
    Snapshot-based fuzzing for stateful protocols.

    Instead of restarting target each iteration:
    1. Run target to interesting state
    2. Take memory snapshot
    3. Fuzz from snapshot
    4. Restore and repeat

    10-100x faster than process restart.
    """

    def take_snapshot(self, pid: int) -> Snapshot:
        """Capture process memory state."""
        pass

    def restore_snapshot(self, snapshot: Snapshot) -> None:
        """Restore process to captured state."""
        pass

    def fuzz_from_snapshot(
        self,
        snapshot: Snapshot,
        input_generator: Callable,
        iterations: int
    ) -> List[Crash]:
        """Fuzz starting from snapshot state."""
        pass
```

### 3.2 Grammar-Aware Fuzzing

```python
# supwngo/fuzzing/grammar.py

class GrammarFuzzer:
    """
    Grammar-aware fuzzing for structured inputs.

    Define input grammar, generate valid mutations
    that stay syntactically correct.

    Essential for:
    - Protocol fuzzing
    - File format fuzzing
    - Compiler/interpreter fuzzing
    """

    def load_grammar(self, grammar_file: str) -> Grammar:
        """Load grammar definition (ANTLR, custom, etc.)."""
        pass

    def generate_valid_input(self) -> bytes:
        """Generate syntactically valid input."""
        pass

    def mutate_preserving_grammar(
        self,
        input: bytes,
        mutation_rate: float = 0.1
    ) -> bytes:
        """Mutate while preserving grammar structure."""
        pass
```

### 3.3 Structure-Aware Fuzzing

```python
# supwngo/fuzzing/structure_aware.py

class StructureAwareFuzzer:
    """
    Structure-aware fuzzing with custom mutators.

    Integrate with AFL++ custom mutator API for
    format-specific intelligent mutations.
    """

    def define_structure(
        self,
        name: str,
        fields: List[Field]
    ) -> Structure:
        """Define binary structure for mutation."""
        pass

    def afl_custom_mutator(
        self,
        data: bytes,
        max_size: int
    ) -> bytes:
        """AFL++ compatible custom mutator."""
        pass
```

### 3.4 CMPLOG / Input-to-State Correspondence

```python
# supwngo/fuzzing/cmplog.py

class CMPLOGFuzzer:
    """
    CMPLOG-based comparison solving.

    AFL++ CMPLOG instruments comparisons to help
    fuzzer solve magic byte checks automatically.

    Features:
    - Automatic dictionary generation
    - Comparison operand logging
    - Input-to-state correspondence
    """

    def instrument_binary(
        self,
        binary: Binary,
        mode: str = "cmplog"
    ) -> str:
        """Instrument binary with CMPLOG."""
        pass

    def extract_dictionary(
        self,
        cmplog_output: str
    ) -> Dict[str, bytes]:
        """Extract comparison operands for dictionary."""
        pass
```

### 3.5 Concolic Execution Enhancement

```python
# supwngo/fuzzing/concolic.py

class ConcolicEngine:
    """
    Enhanced concolic execution combining
    concrete execution with symbolic analysis.

    Improvements over basic driller:
    - Better state merging
    - Path prioritization
    - Constraint caching
    - Parallel solving
    """

    def hybrid_fuzz(
        self,
        binary: Binary,
        seeds: List[bytes],
        timeout: int
    ) -> List[Crash]:
        """
        Run hybrid fuzzing campaign.

        1. Fuzz with AFL until stuck
        2. Use symbolic execution to solve constraints
        3. Feed new inputs back to fuzzer
        4. Repeat
        """
        pass
```

---

## TIER 4: Container & Cloud Exploitation

**Priority: MEDIUM** - Growing importance for real-world

### 4.1 Container Escapes

```python
# supwngo/container/escape.py

class ContainerEscape:
    """
    Container escape techniques.

    Categories:
    1. Kernel vulnerabilities (escape via kernel exploit)
    2. Misconfigurations (privileged containers, capabilities)
    3. Mounted secrets/sockets
    4. Namespace escapes
    """

    def detect_container(self) -> ContainerInfo:
        """Detect container runtime and configuration."""
        pass

    def check_privileged(self) -> bool:
        """Check if running in privileged container."""
        pass

    def check_dangerous_mounts(self) -> List[Mount]:
        """Find dangerous mounted paths (docker.sock, etc.)."""
        pass

    def escape_via_cgroup(self) -> bool:
        """Escape via cgroup release_agent (privileged)."""
        pass

    def escape_via_docker_sock(self, socket_path: str) -> bool:
        """Escape via mounted Docker socket."""
        pass
```

### 4.2 Kubernetes Exploitation

```python
# supwngo/container/kubernetes.py

class KubernetesExploit:
    """
    Kubernetes-specific exploitation techniques.

    Attack vectors:
    - Service account token abuse
    - RBAC misconfigurations
    - etcd access
    - Node-level escapes
    """

    def check_sa_token(self) -> Optional[str]:
        """Check for mounted service account token."""
        pass

    def enumerate_permissions(self, token: str) -> List[str]:
        """Enumerate Kubernetes RBAC permissions."""
        pass

    def create_privileged_pod(self, token: str) -> bool:
        """Attempt to create privileged pod for escape."""
        pass
```

---

## TIER 5: Browser/V8 Exploitation Concepts

**Priority: MEDIUM** - High value targets, complex

### 5.1 Type Confusion Exploitation

```python
# supwngo/browser/type_confusion.py

class TypeConfusionExploit:
    """
    Type confusion exploitation concepts.

    Common in JavaScript engines where object types
    can be confused, leading to memory corruption.

    Primitives needed:
    1. addrof - get address of JS object
    2. fakeobj - create fake object at address
    3. arbitrary read/write from there
    """

    def build_addrof_primitive(
        self,
        confusion_trigger: str
    ) -> str:
        """Generate JS code for addrof primitive."""
        pass

    def build_fakeobj_primitive(
        self,
        confusion_trigger: str
    ) -> str:
        """Generate JS code for fakeobj primitive."""
        pass

    def build_arb_rw(
        self,
        addrof: Callable,
        fakeobj: Callable
    ) -> Tuple[Callable, Callable]:
        """Build arbitrary read/write from addrof/fakeobj."""
        pass
```

### 5.2 JIT Exploitation

```python
# supwngo/browser/jit.py

class JITExploit:
    """
    JIT compiler exploitation techniques.

    JIT bugs commonly involve:
    - Bounds check elimination
    - Type speculation failures
    - Incorrect optimization
    - Side effect modeling errors
    """

    def trigger_jit_compilation(
        self,
        function: str,
        iterations: int = 100000
    ) -> str:
        """Generate code to trigger JIT compilation."""
        pass

    def exploit_bounds_elimination(
        self,
        vulnerable_func: str
    ) -> str:
        """Exploit incorrect bounds check elimination."""
        pass
```

---

## TIER 6: Real-World Features

**Priority: HIGH** - Transition from CTF to real-world

### 6.1 Patch Diffing for 1-Days

```python
# supwngo/realworld/patch_diff.py

class PatchDiffer:
    """
    Automated patch diffing for 1-day development.

    Given patched and unpatched binaries:
    1. Identify changed functions
    2. Analyze what was fixed
    3. Generate vulnerability hypothesis
    4. Assist in trigger development
    """

    def diff_binaries(
        self,
        old_binary: Binary,
        new_binary: Binary
    ) -> List[FunctionDiff]:
        """Diff two binary versions."""
        pass

    def identify_security_fixes(
        self,
        diffs: List[FunctionDiff]
    ) -> List[SecurityFix]:
        """Identify which changes are security fixes."""
        pass

    def generate_vuln_hypothesis(
        self,
        fix: SecurityFix
    ) -> VulnerabilityHypothesis:
        """Generate hypothesis about original vulnerability."""
        pass
```

### 6.2 Exploit Reliability Engineering

```python
# supwngo/realworld/reliability.py

class ExploitReliability:
    """
    Make exploits reliable for real-world use.

    CTF: Works once = success
    Real-world: Needs 99%+ reliability

    Techniques:
    - Heap grooming for deterministic layout
    - Timing adjustments for race conditions
    - Error recovery and retry logic
    - Multi-attempt strategies
    """

    def analyze_reliability(
        self,
        exploit: Exploit,
        iterations: int = 100
    ) -> ReliabilityMetrics:
        """Test exploit reliability over many runs."""
        pass

    def optimize_heap_groom(
        self,
        exploit: HeapExploit,
        target_layout: HeapLayout
    ) -> HeapExploit:
        """Optimize heap grooming for reliability."""
        pass

    def add_retry_logic(
        self,
        exploit: Exploit,
        max_retries: int = 5
    ) -> Exploit:
        """Add intelligent retry logic to exploit."""
        pass
```

### 6.3 CVE to PoC Automation

```python
# supwngo/realworld/cve_poc.py

class CVEToPoc:
    """
    Semi-automated PoC generation from CVE descriptions.

    Input: CVE ID + affected binary
    Output: Working PoC or detailed analysis

    Uses:
    - NVD API for CVE details
    - Patch analysis if available
    - LLM for understanding descriptions
    - Automated trigger generation
    """

    def fetch_cve_info(self, cve_id: str) -> CVEInfo:
        """Fetch CVE information from NVD."""
        pass

    def find_patch_commit(
        self,
        cve_id: str,
        repo: str
    ) -> Optional[str]:
        """Find git commit that patched CVE."""
        pass

    def generate_trigger(
        self,
        cve_info: CVEInfo,
        binary: Binary
    ) -> Optional[bytes]:
        """Attempt to generate crash trigger."""
        pass
```

---

## TIER 7: Novel Mitigation Bypasses

### 7.1 FORTIFY_SOURCE Bypass

```python
# supwngo/exploit/bypass/fortify.py

class FortifyBypass:
    """
    Bypass glibc FORTIFY_SOURCE protections.

    FORTIFY_SOURCE adds runtime checks to dangerous functions.
    Bypass techniques:
    - Call unfortified version (__xxx_chk vs xxx)
    - Exploit edge cases in size calculation
    - Use functions without fortified versions
    """

    def find_unfortified_calls(
        self,
        binary: Binary
    ) -> List[int]:
        """Find calls to unfortified function versions."""
        pass
```

### 7.2 Stack Clash Exploitation

```python
# supwngo/exploit/bypass/stack_clash.py

class StackClash:
    """
    Stack clash exploitation techniques.

    Clash stack into other memory regions by:
    1. Large stack allocations to skip guard page
    2. Corrupt heap, mmap, or other regions

    Modern mitigations require careful probing.
    """

    def probe_stack_layout(self, binary: Binary) -> StackLayout:
        """Probe stack layout and guard pages."""
        pass

    def calculate_clash_size(
        self,
        target_region: str
    ) -> int:
        """Calculate allocation size needed for clash."""
        pass
```

---

## Implementation Phases

### Phase A: CTF Dominance (Next 3 months)
| Feature | Priority | Impact |
|---------|----------|--------|
| Safe-linking bypass | CRITICAL | Heap CTFs |
| House of Kiwi/Emma/Banana | HIGH | Modern heap |
| Tcache key bypass | HIGH | glibc 2.34+ |
| Snapshot fuzzing | HIGH | Faster vuln finding |
| CMPLOG integration | MEDIUM | Better fuzzing |

### Phase B: Kernel Capability (3-6 months)
| Feature | Priority | Impact |
|---------|----------|--------|
| msg_msg exploitation | HIGH | Universal primitive |
| pipe_buffer attacks | HIGH | Dirty Pipe class |
| modprobe_path | MEDIUM | Easy priv esc |
| Cross-cache attacks | MEDIUM | Complex UAF |
| userfaultfd | MEDIUM | Race conditions |

### Phase C: Real-World Transition (6-12 months)
| Feature | Priority | Impact |
|---------|----------|--------|
| Patch diffing | HIGH | 1-day development |
| Exploit reliability | HIGH | Production use |
| Container escapes | MEDIUM | Cloud targets |
| CVE to PoC | MEDIUM | Automation |
| Browser concepts | LOW | High-value targets |

---

## Dependencies & Tools

### New Dependencies
```
z3-solver          # Constraint solving
capstone>=5.0      # Better disassembly
unicorn            # Emulation
qemu-user          # Full system emulation
bindiff            # Binary diffing (optional)
ghidra             # Decompilation (optional)
```

### External Tools Integration
| Tool | Purpose | Integration |
|------|---------|-------------|
| AFL++ | Fuzzing | Deep integration with CMPLOG |
| KASAN | Kernel debugging | Crash analysis |
| GDB/pwndbg | Dynamic analysis | Automated debugging |
| QEMU | Kernel testing | Automated exploit testing |

---

## Success Metrics

### CTF Metrics
| Metric | Current | Target |
|--------|---------|--------|
| Auto-solve rate (easy) | ~70% | 95% |
| Auto-solve rate (medium) | ~40% | 75% |
| Auto-solve rate (hard) | ~10% | 40% |
| Heap challenge support | Basic | Complete |
| Kernel challenge support | Minimal | Good |

### Real-World Metrics
| Metric | Current | Target |
|--------|---------|--------|
| CVE rediscovery | N/A | 80%+ |
| Exploit reliability | N/A | 95%+ |
| 1-day development time | Manual | Semi-auto |
| Container escape detection | None | Comprehensive |

---

## Conclusion

This roadmap transforms supwngo from a capable CTF tool into **the definitive binary exploitation framework** by:

1. **Modern Heap Mastery** - Support for glibc 2.32+ with all modern bypass techniques
2. **Kernel Exploitation** - Comprehensive Linux kernel attack capabilities
3. **Advanced Fuzzing** - State-of-the-art vulnerability discovery
4. **Real-World Focus** - Reliability and automation for production use
5. **Continuous Evolution** - Framework to integrate new techniques as they emerge

The phased approach ensures immediate value for CTF players while building toward real-world capability.
