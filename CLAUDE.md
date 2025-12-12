# supwngo Framework
 
Automated binary exploitation framework for CTF challenges and security research.
 
## Project Overview
 
supwngo provides a modular pipeline for analyzing binaries, finding vulnerabilities, and generating exploits automatically. It integrates with pwntools, angr, and various fuzzers.
 
## Directory Structure
 
```
supwngo/
├── core/           # Core abstractions
│   ├── binary.py   # Binary class wrapping pwntools ELF + pyelftools
│   ├── context.py  # ExploitContext tracking exploitation state
│   └── database.py # SQLite persistence for caching results
├── analysis/       # Binary analysis
│   ├── static.py   # Dangerous function detection, string analysis
│   ├── dynamic.py  # ltrace/strace/GDB integration
│   └── protections.py # Detailed RELRO/canary/NX/PIE detection
├── fuzzing/        # Fuzzer integration
│   ├── afl.py      # AFL++ wrapper
│   ├── honggfuzz.py
│   ├── libfuzzer.py
│   └── crash_triage.py # Exploitability scoring, deduplication
├── symbolic/       # Symbolic execution
│   ├── angr_engine.py # angr Project wrapper
│   ├── path_finder.py # Find paths to dangerous functions
│   ├── constraint.py  # Constraint solving helpers
│   └── driller.py     # Hybrid fuzzing (AFL + symbolic)
├── vulns/          # Vulnerability detection
│   ├── detector.py    # Base classes, Vulnerability dataclass
│   ├── stack_bof.py   # Stack buffer overflow
│   ├── heap.py        # Heap vulnerabilities
│   ├── format_string.py
│   └── integer.py     # Integer overflows
├── exploit/        # Exploit generation
│   ├── generator.py   # Main ExploitGenerator class
│   ├── primitives.py  # Write/read/leak primitives
│   ├── bypass.py      # Protection bypass strategies
│   ├── shellcode.py   # Shellcode generation/encoding
│   ├── rop/           # ROP chain building
│   │   ├── gadgets.py # GadgetFinder (pwntools, ropper, ROPgadget)
│   │   ├── chain.py   # ROPChainBuilder (ret2libc, syscall)
│   │   └── techniques.py # ret2csu, SROP, ret2dlresolve
│   └── heap/          # Heap exploitation
│       ├── techniques.py # tcache poisoning, fastbin dup, House of
│       └── layout.py     # Heap feng shui builder
├── payloads/       # Payload templates
│   └── loader.py   # Exploit script generation
├── remote/         # Remote exploitation
│   ├── interaction.py # Tube wrapper for local/remote/SSH
│   ├── libc_db.py     # Libc identification via libc.rip
│   └── leak.py        # Automated leak finding
├── utils/          # Utilities
│   ├── logging.py  # Structured logging
│   ├── config.py   # Configuration management
│   └── helpers.py  # p64/u64, cyclic patterns, etc.
└── cli.py          # Click-based CLI interface
```
 
## Key Classes
 
### Binary (`supwngo/core/binary.py`)
Main abstraction for loaded binaries. Combines pwntools ELF with pyelftools.
```python
from supwngo import Binary
binary = Binary("/path/to/vuln")
binary.protections  # Protections dataclass
binary.symbols      # Dict of symbols
binary.dangerous_functions  # List of risky imports
```
 
### ExploitContext (`supwngo/core/context.py`)
Tracks all exploitation state: leaks, gadgets, libc info, stack layout.
```python
from supwngo import ExploitContext
ctx = ExploitContext(arch="amd64", bits=64)
ctx.add_leak("puts", 0x7ffff7a62000)
ctx.libc_base  # Calculated from leaks
```
 
### Database (`supwngo/core/database.py`)
SQLite caching for analysis results, gadgets, crashes.
```python
from supwngo import Database
db = Database("supwngo.db")
db.store_gadget(binary_id, address, "pop rdi; ret")
```
 
## CLI Commands
 
```bash
# Analyze binary
supwngo analyze ./vuln
 
# Start fuzzing campaign
supwngo fuzz ./vuln --fuzzer afl --timeout 3600
 
# Triage crashes
supwngo triage ./crashes/
 
# Generate exploit
supwngo exploit ./vuln --vuln-type bof
 
# Find ROP gadgets
supwngo rop ./vuln --find "pop rdi"
 
# Symbolic execution
supwngo symbolic ./vuln --find-unconstrained
 
# Identify libc
supwngo libc-id --puts 0x7ffff7a62000
```
 
## Development
 
### Install for development
```bash
pip install -e ".[dev]"
```
 
### Run tests
```bash
pytest tests/ -v
```
 
### Code style
- Uses Black for formatting (line length 88)
- Type hints encouraged but not strictly enforced
- Docstrings for public methods
 
## Architecture Patterns
 
### Detectors
All vulnerability detectors inherit from `VulnerabilityDetector`:
```python
class MyDetector(VulnerabilityDetector):
    def detect(self, binary: Binary, context: ExploitContext) -> List[Vulnerability]:
        ...
```
 
### Exploit Techniques
Exploit techniques return payloads or ROP chains:
```python
chain = rop_builder.build_ret2libc_chain(
    libc_base=ctx.libc_base,
    binsh_offset=0x1b3e1a,
    system_offset=0x4f550
)
```
 
### Protection Bypass
`ProtectionBypass` provides strategies based on detected protections:
```python
bypass = ProtectionBypass(binary, context)
strategies = bypass.get_applicable_strategies()
```
 
## Dependencies
 
Core: pwntools, angr, angrop, capstone, keystone-engine, ropper
CLI: click, rich
DB: sqlalchemy
 
## Important Notes
 
- Framework designed for Linux ELF binaries (x86/x86_64 primary)
- Requires GDB, ltrace, strace for dynamic analysis
- AFL++/Honggfuzz must be installed separately for fuzzing
- Some features require root (ptrace, ASLR control)
 
## Common Workflows
 
### CTF Binary Exploitation
1. `supwngo analyze ./challenge` - Get protections and dangerous functions
2. `supwngo rop ./challenge` - Find useful gadgets
3. Use library API to build exploit with detected primitives
 
### Automated Fuzzing Pipeline
1. `supwngo fuzz ./target --timeout 7200`
2. `supwngo triage ./afl_out/crashes/`
3. `supwngo exploit ./target --crash ./crash_input`

The supwngo framework implementation is complete. Here's a summary of what was built:
Implementation Summary

57 files added with ~15,000 lines of code implementing:
Core Modules

    supwngo/core/binary.py - Binary abstraction with ELF parsing
    supwngo/core/context.py - Exploitation state tracking
    supwngo/core/database.py - SQLite persistence layer

Analysis

    supwngo/analysis/static.py - Dangerous function detection
    supwngo/analysis/dynamic.py - ltrace/strace/GDB integration
    supwngo/analysis/protections.py - Detailed protection analysis

Fuzzing

    supwngo/fuzzing/afl.py - AFL++ integration
    supwngo/fuzzing/honggfuzz.py - Honggfuzz integration
    supwngo/fuzzing/libfuzzer.py - LibFuzzer integration
    supwngo/fuzzing/crash_triage.py - Crash analysis and deduplication

Symbolic Execution

    supwngo/symbolic/angr_engine.py - angr wrapper
    supwngo/symbolic/path_finder.py - Vulnerability path discovery
    supwngo/symbolic/driller.py - Hybrid fuzzing integration

Vulnerability Detection

    supwngo/vulns/stack_bof.py - Stack overflow detection
    supwngo/vulns/heap.py - Heap vulnerability detection
    supwngo/vulns/format_string.py - Format string detection
    supwngo/vulns/integer.py - Integer overflow detection

Exploit Generation

    supwngo/exploit/rop/ - ROP chain building (ret2libc, SROP, ret2csu, ret2dlresolve)
    supwngo/exploit/heap/ - Heap exploitation (tcache, fastbin, House of)
    supwngo/exploit/shellcode.py - Shellcode generation/encoding
    supwngo/exploit/bypass.py - Protection bypass strategies

Remote

    supwngo/remote/libc_db.py - Libc identification via libc.rip
    supwngo/remote/leak.py - Automated information leaking
    supwngo/remote/interaction.py - Remote connection wrapper

CLI

    supwngo/cli.py - Click-based CLI with commands: analyze, fuzz, triage, exploit, rop, symbolic, libc_id

Packaging

    setup.py and pyproject.toml for installation
    Tests in tests/test_core.py
