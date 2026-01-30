# supwngo Framework Development Guide

## Quick Start for Developers

### Installation
```bash
cd /home/jay/Documents/cyber/dev/supwngo
pip install -e ".[dev]"
```

### Running Commands
```bash
# Via module
python -m supwngo.cli <command> [options]

# Via script
python supwngo.py <command> [options]
```

---

## Architecture Overview

```
supwngo/
├── core/               # Core abstractions
│   ├── binary.py       # Binary class (ELF wrapper)
│   ├── context.py      # ExploitContext (state tracking)
│   └── database.py     # SQLite caching
├── analysis/           # Binary analysis
│   ├── static.py       # Dangerous function detection
│   ├── dynamic.py      # ltrace/strace/GDB
│   └── protections.py  # Security feature detection
├── exploit/            # Exploit generation (MAIN FOCUS)
│   ├── enhanced_auto.py    # PRIMARY: Enhanced auto-exploiter
│   ├── verification.py     # Exploit verification system
│   ├── generator.py        # Legacy exploit generator
│   ├── auto.py             # Legacy auto-exploiter
│   ├── rop/                # ROP chain building
│   ├── format_string.py    # Format string exploitation
│   └── ...                 # Many specialized modules
├── vulns/              # Vulnerability detection
├── fuzzing/            # Fuzzer integration
├── symbolic/           # angr symbolic execution
└── cli.py              # CLI commands
```

---

## Key Components

### 1. EnhancedAutoExploiter (`exploit/enhanced_auto.py`)

**This is the PRIMARY exploitation engine.** It tries multiple techniques automatically.

```python
from supwngo.core.binary import Binary
from supwngo.exploit.enhanced_auto import EnhancedAutoExploiter

binary = Binary.load("./vulnerable")
exploiter = EnhancedAutoExploiter(binary, timeout=5.0, libc_path="./libc.so.6")
exploiter.run()

if exploiter.successful:
    print(f"Technique: {exploiter.technique_used}")
    print(f"Flag: {exploiter._captured_flag}")
    print(f"Verification: {exploiter.verification_level}")
    print(exploiter.exploit_script)
else:
    print(exploiter.exploit_template)  # Always generated
```

**Techniques tried (in order):**
1. `variable_overwrite` - Overflow to overwrite magic value comparison
2. `ret2win` - Call win/flag function directly
3. `direct_shellcode` - Execute shellcode (NX disabled)
4. `negative_size_bypass` - Signed/unsigned comparison bypass
5. `stack_shellcode` - Shellcode with stack leak
6. `format_string` - Format string exploitation
7. `ret2libc` - Return to libc

**Key attributes after run():**
- `successful: bool` - Did exploitation work?
- `technique_used: str` - Which technique succeeded
- `final_payload: bytes` - The working payload
- `exploit_script: str` - Generated Python exploit script
- `exploit_template: str` - Template (always generated)
- `_captured_flag: str` - Flag if captured
- `verification_level: VerificationLevel` - How verified

### 2. ExploitVerifier (`exploit/verification.py`)

Verifies that exploits actually work.

```python
from supwngo.exploit.verification import ExploitVerifier, VerificationLevel

verifier = ExploitVerifier("/path/to/binary", timeout=5.0)

# Verify a payload
result = verifier.verify_payload(payload_bytes)
if result.success:
    print(f"Level: {result.level.name}")  # FLAG_CAPTURED, SHELL_ACCESS, etc.
    print(f"Flag: {result.flag}")

# Verify shell access (with pwntools process)
result = verifier.verify_shell_access(proc)
```

**Verification Levels:**
- `NONE` - No verification
- `OUTPUT_MATCH` - Found success pattern in output
- `FLAG_CAPTURED` - Captured a flag via regex
- `SHELL_ACCESS` - Created verification file via shell
- `FULL_CONTROL` - Ran commands (id, etc.)

**Flag Patterns Detected:**
- `flag{...}`, `ctf{...}`, `htb{...}`, `picoctf{...}`
- Case insensitive

**Shell Verification:**
- Creates file `pwned` with marker `SUPWNGO_PWNED_SUCCESS`
- Located in binary's directory

### 3. Binary (`core/binary.py`)

Wrapper around pwntools ELF with additional analysis.

```python
from supwngo.core.binary import Binary

binary = Binary.load("./vuln")
print(binary.protections)      # Protections dataclass
print(binary.symbols)          # Dict of symbols
print(binary.dangerous_functions)  # List of risky imports
print(binary.bits)             # 32 or 64
print(binary.path)             # Binary path
```

---

## CLI Commands

### Primary Commands

```bash
# Enhanced auto-exploitation (RECOMMENDED)
supwngo autopwn ./binary [--libc ./libc.so.6] [--json] [--timeout 5.0]

# Standard exploit generation (falls back to autopwn on failure)
supwngo exploit ./binary [--libc ./libc.so.6] [-o exploit.py]

# Binary analysis
supwngo analyze ./binary

# ROP gadget finding
supwngo rop ./binary [--chain shell|execve|mprotect]
```

### Output Examples

**Successful exploitation:**
```
SUCCESS! Technique: variable_overwrite
Payload length: 64 bytes

FLAG: flag{example_flag_here}
Exploitation verified by flag capture
```

**JSON output:**
```json
{
  "binary": "./vuln",
  "success": true,
  "verified": "FLAG_CAPTURED",
  "flag": "flag{...}",
  "technique": "variable_overwrite",
  "payload_length": 64
}
```

---

## Adding New Exploitation Techniques

### 1. Add to EnhancedAutoExploiter

In `exploit/enhanced_auto.py`:

```python
class EnhancedAutoExploiter:
    def _rank_strategies(self) -> List[ExploitStrategy]:
        strategies = [
            # Add your new technique here
            ExploitStrategy(
                name="my_new_technique",
                priority=5,  # Lower = tried first
                applicable=self._check_if_applicable(),
            ),
            # ... existing strategies
        ]
        return sorted(strategies, key=lambda s: s.priority)

    def _try_my_new_technique(self):
        """Try my new exploitation technique."""
        attempt = {"technique": "my_new_technique", "result": "failed"}

        # Build payload
        payload = self._build_payload()

        # Test with verification
        verifier = ExploitVerifier(self._binary_path, self.timeout)
        result = verifier.verify_payload(payload)

        if result.success:
            self.successful = True
            self.technique_used = "my_new_technique"
            self.final_payload = payload

            if result.flag:
                self._captured_flag = result.flag
            if result.level.value > self.verification_level.value:
                self.verification_level = result.level

            attempt["result"] = "success"
            self._generate_my_technique_script()

        self.attempts.append(attempt)
```

### 2. Always Use Verification

When testing payloads, always use `ExploitVerifier`:

```python
verifier = ExploitVerifier(self._binary_path, self.timeout)
result = verifier.verify_payload(payload + b'\n')

if result.success:
    if result.flag:
        self._captured_flag = result.flag
    if result.level.value > self.verification_level.value:
        self.verification_level = result.level
    return True
return False
```

---

## Testing Challenges

### Test Binaries Location
```
challenges/new_challenges/
├── jeeves          # Variable overwrite (0x1337bab3)
├── format          # Format string vulnerability
├── pwnshop         # Stack buffer overflow
├── reconstruction/ # Shellcode runner with byte restrictions
└── ...
```

### Creating Test Flags
```bash
echo 'flag{test_flag}' > challenges/new_challenges/flag.txt
```

### Running Tests
```bash
# Test on specific binary
python -m supwngo.cli autopwn challenges/new_challenges/jeeves

# With JSON output
python -m supwngo.cli autopwn challenges/new_challenges/jeeves --json

# With libc
python -m supwngo.cli autopwn ./binary --libc ./libc.so.6
```

---

## Module Exports

### Main Imports (`from supwngo.exploit import ...`)

```python
# Enhanced auto-exploit
from supwngo.exploit import (
    EnhancedAutoExploiter,
    BinaryProfile,
    ExploitStrategy,
    auto_exploit,
)

# Verification
from supwngo.exploit.verification import (
    ExploitVerifier,
    VerificationResult,
    VerificationLevel,
    verify_exploit,
)

# ROP
from supwngo.exploit import (
    GadgetFinder,
    Gadget,
    ROPChainBuilder,
    ROPChain,
)

# Format string
from supwngo.exploit import (
    FormatStringExploiter,
    FormatStringAutoExploit,
    find_fmt_offset,
)
```

---

## Common Patterns

### Win Function Detection
```python
WIN_FUNCTIONS = [
    "win", "flag", "shell", "get_flag", "print_flag",
    "give_shell", "spawn_shell", "backdoor", "secret",
    "cat_flag", "system_shell", "getshell", "hidden",
]
```

### Magic Values (Variable Overwrite)
```python
MAGIC_VALUES = [
    0x1337bab3, 0xdeadbeef, 0xcafebabe, 0xbadc0de,
    0x1337, 0xfeedface, 0x41414141, 0xbaadf00d,
]
```

### Flag Regex Patterns
```python
FLAG_PATTERNS = [
    r'flag\{[^}]+\}',
    r'ctf\{[^}]+\}',
    r'htb\{[^}]+\}',
    r'picoctf\{[^}]+\}',
]
```

---

## Debugging

### Enable Debug Logging
```python
import logging
logging.getLogger('supwngo').setLevel(logging.DEBUG)
```

### Check Verification File
```bash
# After running exploit, check if shell was verified
cat ./pwned  # Should contain SUPWNGO_PWNED_SUCCESS
```

### Manual Testing
```python
from pwn import *
from supwngo.exploit.verification import ExploitVerifier

# Run binary
p = process("./vuln")
p.sendline(payload)

# Verify
verifier = ExploitVerifier("./vuln")
result = verifier.verify_shell_access(p)
print(result.success, result.level, result.flag)
```

---

## File Locations

| Component | Path |
|-----------|------|
| Enhanced Auto-Exploit | `supwngo/exploit/enhanced_auto.py` |
| Verification System | `supwngo/exploit/verification.py` |
| CLI Commands | `supwngo/cli.py` |
| Binary Wrapper | `supwngo/core/binary.py` |
| ROP Chain Builder | `supwngo/exploit/rop/chain.py` |
| Format String | `supwngo/exploit/format_string.py` |
| Test Challenges | `challenges/new_challenges/` |

---

## Current State (Dec 2024)

### Working Features
- Variable overwrite exploitation (jeeves pattern)
- ret2win detection and exploitation
- Direct shellcode execution
- Exploit verification with flag capture
- Shell verification via file creation
- Fallback from standard exploit to enhanced auto-exploit
- JSON output for automation

### Known Limitations
- Format string challenges need more work
- Reconstruction-style (shellcode runner) challenges not fully automated
- ret2dlresolve fails on some PIE binaries (falls back to enhanced)
- Heap exploitation techniques exist but less tested

### Priority Improvements
1. Format string auto-detection and exploitation
2. Shellcode runner/reconstruction challenge support
3. Better offset finding via crash analysis
4. More magic value patterns
