# Passcard report

**ACCEPTED.** Every cell ran under `bwrap` and the control cell passed.

## Header

| field | value |
|---|---|
| git sha | 992986e44ff33c4f3e947cbeeaa07a1c3f7b5734 |
| schema | passcard-report/1 |
| started | 2026-11-13T11:45:21+00:00 |
| python | 3.11.15 |
| pwntools / angr / ghidra | 4.15.0 / 9.2.213 / 12.1.3 |
| host arch | x86_64 |
| isolation backend | bwrap (observed: bwrap) |
| subreaper | True |
| load at start / end | 24.35 26.12 32.17 / 63.45 52.52 45.87 |
| reps / timeout | 3 / 1500.0s |
| core/proc.py sha256 | f6eee3425a06ffe09e003486b4953fd56e3fe67efc20f23bd59325b816277b8a |
| core/sandbox.py sha256 | cb6b9981712802f48bc5d2110f887b1bd790a4fb171dc4dc0de1f7b8be17d3ad |
| argv | `benchmark/passcard.py --reps 3 --timeout 1500 --solve-artifact benchmark/baselines/solve-hyp9-278c0e8.json --solve-commit 278c0e8 --solve-command python3 -B scripts/htb_rescore.py --reps 3 --timeout 300 --solve-cwd-convention each rep in a throwaway copy of the challenge directory --out benchmark/baselines/passcard-s0-pre-sp01` |
| cli | `/home/net0ruser/.pyenv/versions/3.11.15/bin/python3 -m supwngo.cli` |
| cell env passthrough | `JAVA_TOOL_OPTIONS=-Duser.home=/tmp/cell/home` `LANG=en_US.UTF-8` `PATH=/home/net0ruser/.pyenv/versions/3.11.15/bin:/home/net0ruser/.pyenv/libexec:/home/net0ruser/.pyenv/plugins/python-build/bin:/home/net0ruser/.pyenv/plugins/pyenv-virtualenv/bin:/home/net0ruser/.pyenv/plugins/pyenv-update/bin:/home/net0ruser/.pyenv/plugins/pyenv-doctor/bin:/home/net0ruser/.cargo/bin:/home/net0ruser/.local/bin:/home/net0ruser/.pyenv/shims:/home/net0ruser/.pyenv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin` `SUPWNGO_GHIDRA_TIMEOUT=600` |

v0 limits: TEMPLATE trusts the `technique` field. OFF trusts the integer, with no RIP proof. Anchors are textual after comment stripping.

## Ghidra control cell (V-2)

PASS. sha256 ad1c6feef649a5b769a324ff92a75124b54eb9b32a1e13334b0c0bdd89572d57, expected ad1c6feef649a5b769a324ff92a75124b54eb9b32a1e13334b0c0bdd89572d57. 

## S0 matrix (7 ELF targets, smoke, never a gate)

| target | METHOD-R0 | METHOD-L | TEMPLATE | OFF | DECOMP | ROBUST | preflight | solve (HYP-9) |
|---|---|---|---|---|---|---|---|---|
| sick_rop | FAIL | FAIL p=0.00 s=2 | FAIL | buf_to_ret:PASS | ABSTAIN | 3/4 (fail: decompile) | ok | SOLVED: srop_symtab_pivot x3 18s median |
| rocket_blaster_xxx | FAIL | PASS p=0.14 s=7 | PASS | buf_to_ret:PASS | PASS | 4/4 | ok | SOLVED: ret2libc_leak x3 68s median |
| snow_scan | PASS | PASS p=0.40 s=5 | FAIL | indexed_base_ptr:VOID(no-truth) | PASS | 3/4 (fail: offset) | ok | SOLVED: container_file_rop x3 80s median |
| ancient_interface | PASS | PASS p=0.29 s=7 | PASS | buf_to_ret:ABSTAIN; buf_to_canary:ABSTAIN | FAIL | 3/4 (fail: offset) | ok | SOLVED: eintr_accumulator_rop x3 28s median |
| auth-or-out | FAIL | FAIL p=0.00 s=7 | FAIL | record_to_fnptr:VOID(no-truth) | FAIL | 3/4 (fail: offset) | ok | SOLVED: objptr_hijack x3 24s median |
| sabotage | FAIL | FAIL p=0.00 s=7 | FAIL | buf_to_var:VOID(interp_empty) | FAIL | 3/4 (fail: offset) | interp_empty | SOLVED: env_path_hijack x3 12s median |
| bon-nie-appetit | FAIL | FAIL p=0.00 s=7 | FAIL | chunk_to_next_size:VOID(interp_empty) | FAIL | 3/4 (fail: offset) | interp_empty | SOLVED: heap_strlen_ofb1 x3 23s median |

### S0 metrics

| metric | n | PASS | FAIL | ABSTAIN | ERROR | VOID | coverage | exact | selective | net |
|---|---|---|---|---|---|---|---|---|---|---|
| METHOD-R0 | 7 | 2 | 5 | 0 | 0 | 0 | 1.00 | 0.29 | 0.29 | -0.43 |
| METHOD-L | 7 | 3 | 4 | 0 | 0 | 0 | 1.00 | 0.43 | 0.43 | -0.14 |
| TEMPLATE | 7 | 2 | 5 | 0 | 0 | 0 | 1.00 | 0.29 | 0.29 | -0.43 |
| OFF | 8 | 2 | 0 | 2 | 0 | 4 | 0.25 | 0.25 | 1.00 | 0.25 |
| DECOMP | 7 | 2 | 4 | 1 | 0 | 0 | 0.86 | 0.29 | 0.33 | -0.29 |
| ROBUST | 28 | 22 | 6 | 0 | 0 | 0 | 1.00 | 0.79 | 0.79 | 0.57 |

METHOD-L precision macro mean: 0.12 over 7 of 7 targets. METHOD-SPAM: sick_rop=2, rocket_blaster_xxx=7, snow_scan=5, ancient_interface=7, auth-or-out=7, sabotage=7, bon-nie-appetit=7.
VULN column: none. off_unscored_numbers: 0.
VOID cells: snow_scan/indexed_base_ptr: no-truth; auth-or-out/record_to_fnptr: no-truth; sabotage/buf_to_var: interp_empty; bon-nie-appetit/chunk_to_next_size: interp_empty

## S0-PE (separate table: DECOMP and ROBUST only)

| target | DECOMP | ROBUST | preflight |
|---|---|---|---|
| pe_sym | PASS | 3/4 (fail: offset) | unsupported_format |
| pe_strip | ABSTAIN | 2/4 (fail: decompile,offset) | unsupported_format |

| metric | n | PASS | FAIL | ABSTAIN | ERROR | VOID | coverage | exact | selective | net |
|---|---|---|---|---|---|---|---|---|---|---|
| DECOMP | 2 | 1 | 0 | 1 | 0 | 0 | 0.50 | 0.50 | 1.00 | 0.50 |
| ROBUST | 8 | 5 | 3 | 0 | 0 | 0 | 1.00 | 0.62 | 0.62 | 0.25 |

## Cell notes (non-PASS cells)

- sick_rop METHOD-R0 FAIL: method:stack_pivot
- sick_rop METHOD-L FAIL: top3:method:stack_pivot,method:data_only
- sick_rop TEMPLATE FAIL: method:ret2libc
- sick_rop ROBUST/decompile FAIL: rc_envelope:0/failure
- rocket_blaster_xxx METHOD-R0 FAIL: method:rop_syscall
- snow_scan TEMPLATE FAIL: method:ret2libc
- snow_scan OFF/indexed_base_ptr VOID: no-truth
- snow_scan ROBUST/offset FAIL: rc_envelope:0/unrecognised
- ancient_interface DECOMP FAIL: empty_or_sentinel;anchors_missing:read,strcmp;min_calls
- ancient_interface ROBUST/offset FAIL: rc_envelope:0/unrecognised
- auth-or-out METHOD-R0 FAIL: method:rop_syscall
- auth-or-out METHOD-L FAIL: top3:method:rop_syscall,method:ret2libc,method:stack_pivot
- auth-or-out TEMPLATE FAIL: method:ret2libc
- auth-or-out DECOMP FAIL: address
- auth-or-out OFF/record_to_fnptr VOID: no-truth
- auth-or-out ROBUST/offset FAIL: rc_envelope:0/unrecognised
- sabotage METHOD-R0 FAIL: method:rop_syscall
- sabotage METHOD-L FAIL: top3:method:rop_syscall,method:ret2libc,method:stack_pivot
- sabotage TEMPLATE FAIL: method:ret2libc
- sabotage DECOMP FAIL: address
- sabotage OFF/buf_to_var VOID: interp_empty
- sabotage ROBUST/offset FAIL: rc_envelope:0/unrecognised
- bon-nie-appetit METHOD-R0 FAIL: method:rop_syscall
- bon-nie-appetit METHOD-L FAIL: top3:method:rop_syscall,method:ret2libc,method:stack_pivot
- bon-nie-appetit TEMPLATE FAIL: method:ret2libc
- bon-nie-appetit DECOMP FAIL: address
- bon-nie-appetit OFF/chunk_to_next_size VOID: interp_empty
- bon-nie-appetit ROBUST/offset FAIL: rc_envelope:0/unrecognised
- pe_sym ROBUST/offset FAIL: rc_envelope:0/unrecognised
- pe_strip ROBUST/decompile FAIL: rc_envelope:0/failure
- pe_strip ROBUST/offset FAIL: rc_envelope:0/unrecognised

## TIME

| command | valid/samples | median wall s | max wall s | median load1 |
|---|---|---|---|---|
| pwn | 27/27 | 7.08 | 35.08 | 43.48 |
| template | 27/27 | 2.79 | 17.64 | 42.81 |
| decompile | 27/27 | 32.66 | 148.32 | 40.72 |
| offset | 27/27 | 1.90 | 103.99 | 43.04 |

## HYP-9 solve artefact

commit 278c0e8; command `python3 -B scripts/htb_rescore.py --reps 3 --timeout 300`; cwd convention each rep in a throwaway copy of the challenge directory; sha256 69f112568f579870e93c2d72993d4bafa807763d3322ef7c64ebc482c1cea44b
