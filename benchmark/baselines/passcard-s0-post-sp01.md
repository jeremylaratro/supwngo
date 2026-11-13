# Passcard report

**ACCEPTED.** Every cell ran under `bwrap` and the control cell passed.

## Header

| field | value |
|---|---|
| git sha | 11e80b3351f9913017600c731c2babaaf5f2103e |
| schema | passcard-report/1 |
| started | 2026-11-13T17:22:05+00:00 |
| python | 3.11.15 |
| pwntools / angr / ghidra | 4.15.0 / 9.2.213 / 12.1.3 |
| host arch | x86_64 |
| isolation backend | bwrap (observed: bwrap) |
| subreaper | True |
| load at start / end | 2.65 3.13 2.42 / 32.67 31.31 20.60 |
| reps / timeout | 3 / 1500.0s |
| core/proc.py sha256 | f6eee3425a06ffe09e003486b4953fd56e3fe67efc20f23bd59325b816277b8a |
| core/sandbox.py sha256 | cb6b9981712802f48bc5d2110f887b1bd790a4fb171dc4dc0de1f7b8be17d3ad |
| argv | `benchmark/passcard.py --reps 3 --timeout 1500 --solve-artifact benchmark/baselines/solve-hyp9-278c0e8.json --solve-commit 278c0e8 --solve-command python3 -B scripts/htb_rescore.py --reps 3 --timeout 300 --solve-cwd-convention each rep in a throwaway copy of the challenge directory --out benchmark/baselines/passcard-s0-post-sp01` |
| cli | `/home/net0ruser/.pyenv/versions/3.11.15/bin/python3 -m supwngo.cli` |
| cell env passthrough | `JAVA_TOOL_OPTIONS=-Duser.home=/tmp/cell/home` `LANG=en_US.UTF-8` `PATH=/home/net0ruser/.pyenv/versions/3.11.15/bin:/home/net0ruser/.pyenv/libexec:/home/net0ruser/.pyenv/plugins/python-build/bin:/home/net0ruser/.pyenv/plugins/pyenv-virtualenv/bin:/home/net0ruser/.pyenv/plugins/pyenv-update/bin:/home/net0ruser/.pyenv/plugins/pyenv-doctor/bin:/home/net0ruser/.cargo/bin:/home/net0ruser/.local/bin:/home/net0ruser/.pyenv/shims:/home/net0ruser/.pyenv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin` `SUPWNGO_GHIDRA_TIMEOUT=600` |

v0 limits: TEMPLATE trusts the `technique` field. OFF trusts the integer, with no RIP proof. Anchors are textual after comment stripping.

## Ghidra control cell (V-2)

PASS. sha256 ad1c6feef649a5b769a324ff92a75124b54eb9b32a1e13334b0c0bdd89572d57, expected ad1c6feef649a5b769a324ff92a75124b54eb9b32a1e13334b0c0bdd89572d57. 

## S0 matrix (7 ELF targets, smoke, never a gate)

| target | METHOD-R0 | METHOD-L | TEMPLATE | OFF | DECOMP | ROBUST | preflight | solve (HYP-9) |
|---|---|---|---|---|---|---|---|---|
| sick_rop | FAIL | FAIL p=0.00 s=2 | FAIL | buf_to_ret:PASS | PASS | 4/4 | ok | SOLVED: srop_symtab_pivot x3 18s median |
| rocket_blaster_xxx | FAIL | PASS p=0.17 s=6 | PASS | buf_to_ret:PASS | PASS | 4/4 | ok | SOLVED: ret2libc_leak x3 68s median |
| snow_scan | PASS | PASS p=0.40 s=5 | FAIL | indexed_base_ptr:VOID(no-truth) | PASS | 4/4 | ok | SOLVED: container_file_rop x3 80s median |
| ancient_interface | PASS | PASS p=0.29 s=7 | PASS | buf_to_ret:ABSTAIN; buf_to_canary:ABSTAIN | PASS | 4/4 | ok | SOLVED: eintr_accumulator_rop x3 28s median |
| auth-or-out | FAIL | FAIL p=0.00 s=6 | FAIL | record_to_fnptr:VOID(no-truth) | PASS | 4/4 | ok | SOLVED: objptr_hijack x3 24s median |
| sabotage | FAIL | FAIL p=0.00 s=6 | FAIL | buf_to_var:VOID(interp_empty) | PASS | 4/4 | interp_empty | SOLVED: env_path_hijack x3 12s median |
| bon-nie-appetit | FAIL | FAIL p=0.00 s=6 | FAIL | chunk_to_next_size:VOID(interp_empty) | PASS | 4/4 | interp_empty | SOLVED: heap_strlen_ofb1 x3 23s median |

### S0 metrics

| metric | n | PASS | FAIL | ABSTAIN | ERROR | VOID | coverage | exact | selective | net |
|---|---|---|---|---|---|---|---|---|---|---|
| METHOD-R0 | 7 | 2 | 5 | 0 | 0 | 0 | 1.00 | 0.29 | 0.29 | -0.43 |
| METHOD-L | 7 | 3 | 4 | 0 | 0 | 0 | 1.00 | 0.43 | 0.43 | -0.14 |
| TEMPLATE | 7 | 2 | 5 | 0 | 0 | 0 | 1.00 | 0.29 | 0.29 | -0.43 |
| OFF | 8 | 2 | 0 | 2 | 0 | 4 | 0.25 | 0.25 | 1.00 | 0.25 |
| DECOMP | 7 | 7 | 0 | 0 | 0 | 0 | 1.00 | 1.00 | 1.00 | 1.00 |
| ROBUST | 28 | 28 | 0 | 0 | 0 | 0 | 1.00 | 1.00 | 1.00 | 1.00 |

METHOD-L precision macro mean: 0.12 over 7 of 7 targets. METHOD-SPAM: sick_rop=2, rocket_blaster_xxx=6, snow_scan=5, ancient_interface=7, auth-or-out=6, sabotage=6, bon-nie-appetit=6.
VULN column: none. off_unscored_numbers: 0.
VOID cells: snow_scan/indexed_base_ptr: no-truth; auth-or-out/record_to_fnptr: no-truth; sabotage/buf_to_var: interp_empty; bon-nie-appetit/chunk_to_next_size: interp_empty

## S0-PE (separate table: DECOMP and ROBUST only)

| target | DECOMP | ROBUST | preflight |
|---|---|---|---|
| pe_sym | PASS | 4/4 | unsupported_format |
| pe_strip | PASS | 4/4 | unsupported_format |

| metric | n | PASS | FAIL | ABSTAIN | ERROR | VOID | coverage | exact | selective | net |
|---|---|---|---|---|---|---|---|---|---|---|
| DECOMP | 2 | 2 | 0 | 0 | 0 | 0 | 1.00 | 1.00 | 1.00 | 1.00 |
| ROBUST | 8 | 8 | 0 | 0 | 0 | 0 | 1.00 | 1.00 | 1.00 | 1.00 |

## Cell notes (non-PASS cells)

- sick_rop METHOD-R0 FAIL: method:stack_pivot
- sick_rop METHOD-L FAIL: top3:method:stack_pivot,method:data_only
- sick_rop TEMPLATE FAIL: method:ret2libc
- rocket_blaster_xxx METHOD-R0 FAIL: method:rop_syscall
- snow_scan TEMPLATE FAIL: method:ret2libc
- snow_scan OFF/indexed_base_ptr VOID: no-truth
- auth-or-out METHOD-R0 FAIL: method:rop_syscall
- auth-or-out METHOD-L FAIL: top3:method:rop_syscall,method:ret2libc,method:stack_pivot
- auth-or-out TEMPLATE FAIL: method:ret2libc
- auth-or-out OFF/record_to_fnptr VOID: no-truth
- sabotage METHOD-R0 FAIL: method:rop_syscall
- sabotage METHOD-L FAIL: top3:method:rop_syscall,method:ret2libc,method:stack_pivot
- sabotage TEMPLATE FAIL: method:ret2libc
- sabotage OFF/buf_to_var VOID: interp_empty
- bon-nie-appetit METHOD-R0 FAIL: method:rop_syscall
- bon-nie-appetit METHOD-L FAIL: top3:method:rop_syscall,method:ret2libc,method:stack_pivot
- bon-nie-appetit TEMPLATE FAIL: method:ret2libc
- bon-nie-appetit OFF/chunk_to_next_size VOID: interp_empty

## TIME

| command | valid/samples | median wall s | max wall s | median load1 |
|---|---|---|---|---|
| pwn | 27/27 | 4.78 | 35.26 | 5.10 |
| template | 27/27 | 2.39 | 17.10 | 4.62 |
| decompile | 27/27 | 38.05 | 105.16 | 4.72 |
| offset | 27/27 | 2.25 | 38.48 | 4.44 |

## HYP-9 solve artefact

commit 278c0e8; command `python3 -B scripts/htb_rescore.py --reps 3 --timeout 300`; cwd convention each rep in a throwaway copy of the challenge directory; sha256 69f112568f579870e93c2d72993d4bafa807763d3322ef7c64ebc482c1cea44b
