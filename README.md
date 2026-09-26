# supwngo

**Automated Binary Exploitation Framework**

> From vulnerability discovery to working exploit—automatically.

supwngo is a comprehensive binary exploitation framework that combines static analysis, fuzzing, symbolic execution, and exploit generation into a unified pipeline. Built for CTF competitors, security researchers, and penetration testers who need to move fast.

## Why supwngo?

Traditional binary exploitation requires juggling multiple tools: disassemblers, debuggers, ROP gadget finders, and custom scripts. supwngo unifies this workflow into a single framework that can:

- Analyze binaries and detect security mitigations in seconds
- Automatically discover vulnerabilities through fuzzing and symbolic execution
- Generate working exploits with ROP chains, shellcode, and heap techniques
- Identify remote libc versions from leaked addresses

## Quick Start

```bash
# Install
pip install supwngo

# Analyze a binary
supwngo analyze ./challenge

# Auto-exploit with detected vulnerabilities
supwngo exploit ./challenge --auto

# Find ROP gadgets
supwngo rop ./challenge --find "pop rdi"

# Fuzz for crashes
supwngo fuzz ./challenge --timeout 3600

# Write a SARIF report for CI to ingest (also html/markdown/json/text)
supwngo report ./challenge -o findings.sarif
```

## Features

### Analysis
- Protection detection (RELRO, Stack Canary, NX, PIE, ASLR)
- Dangerous function identification (gets, strcpy, sprintf, etc.)
- Dynamic tracing with ltrace/strace/GDB

### Vulnerability Detection
- Stack buffer overflows
- Heap corruption (use-after-free, double-free, overflow)
- Format string vulnerabilities
- Integer overflows

### Exploit Generation
- Automatic ROP chain building (ret2libc, ret2csu, SROP, ret2dlresolve)
- Heap exploitation techniques (tcache poisoning, fastbin dup, House of *)
- Shellcode generation with encoder support
- Protection bypass strategies

### Reporting
- SARIF v2.1.0 export for CI and code-scanning tools
- CVSS v3.1 scoring per finding
- HTML / Markdown / JSON / text reports
- Reports state what could *not* be measured: a detector that failed is named,
  and an unparsed target is refused rather than reported as having no findings

### Fuzzing Integration
- AFL++ / Honggfuzz / LibFuzzer wrappers
- Crash triage and exploitability scoring
- Hybrid fuzzing with symbolic execution (Driller)

### Remote Exploitation
- Libc identification via libc.rip/libc.blukat.me
- Automated leak detection and parsing
- Local/remote/SSH connection handling

## Usage Examples

### CTF Workflow
```bash
# 1. Analyze the challenge
supwngo analyze ./pwn_challenge

# 2. Generate exploit automatically
supwngo exploit ./pwn_challenge --auto

# 3. Or build manually with the API
python3 exploit.py
```

### Python API
```python
from supwngo import Binary, ExploitContext
from supwngo.exploit.rop import ROPChainBuilder

# Load and analyze
binary = Binary("./vuln")
print(binary.protections)

# Build exploit context
ctx = ExploitContext(arch="amd64")
ctx.add_leak("puts", 0x7ffff7a62000)

# Generate ROP chain
rop = ROPChainBuilder(binary, ctx)
chain = rop.build_ret2libc_chain()
```

## Requirements

- Python 3.8+
- Linux (primary support for ELF binaries)
- Optional: GDB, AFL++, Honggfuzz for extended features

## Installation

```bash
# From PyPI
pip install supwngo

# From source
git clone https://github.com/jeremylaratro/supwngo.git
cd supwngo
pip install -e ".[dev]"
```

## Documentation

- [Development Guide](docs/internal/DEVELOPMENT.md)
- [Manual Exploitation Guide](docs/internal/MANUAL_EXPLOITATION_GUIDE.md)

## License

[PolyForm Strict 1.0.0](https://polyformproject.org/licenses/strict/1.0.0) — see [`LICENSE`](LICENSE)
for the full text.

**Free** for any noncommercial purpose: personal study, research, experiment, testing, hobby
projects, amateur pursuits, and use by charitable, educational, public-research, public-safety,
health, environmental and government organizations.

**A separate license is required** to use the software commercially, to redistribute it (modified or
not), or to create derivative works, forks or ports. The copyright grant in PolyForm Strict
deliberately excludes distribution and modification. Requests are welcome and granted routinely for
reasonable ones — contact Jeremy Laratro <jlaratro24@gmail.com>.

PolyForm Strict is a *source-available* license, not an OSI-approved open-source license, because it
does not permit redistribution or modification by default.

## Disclaimer

This tool is intended for authorized security testing, CTF competitions, and educational purposes only. Users are responsible for ensuring they have proper authorization before testing any systems.
