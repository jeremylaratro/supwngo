# supwngo Quick Reference

## CLI Commands

| Command | Purpose |
|---------|---------|
| `supwngo analyze <bin>` | Static analysis, protections, dangerous funcs |
| `supwngo exploit <bin>` | Auto-generate exploit script |
| `supwngo rop <bin>` | Find ROP gadgets |
| `supwngo fuzz <bin>` | Launch fuzzing campaign |
| `supwngo triage <dir>` | Analyze crashes for exploitability |
| `supwngo libc-id --puts ADDR` | Identify libc from leaked address |
| `supwngo strategy <bin>` | Suggest exploit strategies |

## Core Classes

| Class | Import | When to Use |
|-------|--------|-------------|
| `Binary` | `supwngo` | Load/parse ELF, access symbols/sections |
| `ExploitContext` | `supwngo` | Track leaks, libc base, stack layout |
| `Database` | `supwngo` | Cache gadgets, crashes, exploits |

## Analysis

| Function/Class | Purpose |
|----------------|---------|
| `ProtectionAnalyzer(binary)` | Detailed protection analysis (canary, NX, PIE, RELRO, FORTIFY) |
| `StaticAnalyzer(binary)` | Find dangerous functions (gets, strcpy, printf, etc.) |
| `find_one_gadgets(libc)` | Find magic gadgets in libc |
| `find_useful_addresses(binary)` | Find /bin/sh, BSS, writable regions |

## Exploitation

| Function/Class | Purpose |
|----------------|---------|
| `GadgetFinder(binary)` | Find ROP gadgets (`find_pop_gadgets()`, `find_syscall()`) |
| `ROPChainBuilder(ctx)` | Build chains (`build_ret2libc_chain()`, `build_execve_chain()`) |
| `OffsetFinder(binary)` | Find buffer overflow offset (`find_gdb()`, `find_cyclic_pattern()`) |
| `cyclic(len)` / `cyclic_find(data)` | Generate/find de Bruijn patterns |
| `FormatStringAutoExploit(ctx)` | Format string: `find_offset()`, `leak_addresses()`, `got_overwrite()` |
| `ShellcodeGenerator(arch)` | Generate shellcode: `execve_shellcode()`, `mprotect_shellcode()` |
| `AutoExploiter(binary)` | Auto-try multiple techniques |
| `TemplateGenerator(ctx)` | Generate exploit templates |

## Vulnerability Detection

| Detector | Vuln Type |
|----------|-----------|
| `StackBufferOverflowDetector(binary)` | Stack BOF, gets/strcpy/read |
| `FormatStringDetector(binary)` | printf with user input |
| `HeapVulnerabilityDetector(binary)` | UAF, double-free, heap overflow |

## Remote

| Function/Class | Purpose |
|----------------|---------|
| `LibcDatabase()` | Query libc.rip: `identify({symbol: offset})` |
| `LeakFinder(ctx)` | Auto-leak addresses via format string or puts |

## Common Patterns

### Quick Analysis
```python
from supwngo import Binary
from supwngo.analysis.protections import ProtectionAnalyzer

b = Binary.load("./vuln")
pa = ProtectionAnalyzer(b)
print(pa.checksec_report())
```

### Find Offset
```python
from supwngo.exploit.offset_finder import cyclic, cyclic_find
pattern = cyclic(500)  # Send this to crash
offset = cyclic_find(leaked_rip)  # From crash
```

### ROP Chain
```python
from supwngo.exploit.rop.gadgets import GadgetFinder
from supwngo.exploit.rop.chain import ROPChainBuilder

gf = GadgetFinder(binary)
pop_rdi = gf.find("pop rdi")[0]
builder = ROPChainBuilder(context)
chain = builder.build_ret2libc_chain(libc_base, system_off, binsh_off)
```

### Format String
```python
from supwngo.exploit.format_string import FormatStringAutoExploit
fs = FormatStringAutoExploit(ctx, io.sendline, io.recvline)
offset = fs.find_offset()
leaks = fs.leak_addresses(range(1, 20))
```

### Libc ID
```python
from supwngo.remote.libc_db import LibcDatabase
db = LibcDatabase()
matches = db.identify({"puts": leaked_puts_addr})
```

## Key Gaps Found

1. **Binary.imports/symbols empty** - Use CLI `analyze` instead or pwntools ELF directly
2. **Detector API requires crash** - Static detection works, dynamic needs CrashCase object
3. **ret2dlresolve fails on small binaries** - Needs sufficient gadgets
4. **Shellcode exec (fleet_management)** - Works but seccomp bypass not automated
5. **Canary bypass detection works** - Generates working scanf skip exploits
6. **Variable overwrite patterns not detected** - Jeeves-style "overwrite magic value" not found
7. **RUNPATH binaries** - Binaries with `./glibc/` RUNPATH need cwd set to binary dir

## Shell Verification

When exploitation succeeds, a `pwned` file is created containing `SUPWNGO_PWNED_SUCCESS`.
This confirms shell access was obtained. Check for this file after running exploits.

Generated exploit scripts also attempt to create this file automatically.
