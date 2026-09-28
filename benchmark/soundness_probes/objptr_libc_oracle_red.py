#!/usr/bin/env python3
"""Prove the menu_libc chain's validators can go RED before trusting them green.

Every mutation below replaces ONE recovered constant with a value that is REAL
and PRESENT in the image -- a genuine symbol, a genuine member offset, a genuine
COPY slot -- not an absent or obviously-bogus one. An absent value proves
nothing: any code path that dereferences it dies for the wrong reason.

Each row is (name, mutation, what should stop it). A row that still reaches a
proved shell means the constant it mutates is NOT load-bearing, i.e. the green
result did not depend on recovering it, and the chain's evidence is weaker than
it looks.

Run:  PYTHONPATH=. python3 benchmark/soundness_probes/objptr_libc_oracle_red.py
"""
from __future__ import annotations

import pathlib
import subprocess
import sys
import tempfile
import time

REPO = pathlib.Path(__file__).resolve().parents[2]
GEN = REPO / "scripts" / "objptr_render_script.py"
TARGET = REPO / "tests" / "htb-targets" / "organized" / "auth-or-out"

# Addresses taken from `readelf -sW auth-or-out` (measured 2026-09-28): every
# mutated value below is a real symbol or a real member of the real record.
CASES = [
    ("BASELINE (no mutation)", [], True,
     "the unmutated chain must be GREEN, or the RED rows below prove nothing"),
    ("installed_fn -> get_number@0x1240", ["installed_fn=0x1240"], False,
     "a real, wrong function address: the low-12-bit check on the value read "
     "back must reject it instead of deriving an image base from it"),
    ("ptr_member -> 0x28 (the `age` member)", ["ptr_member=0x28"], False,
     "a real, wrong member: system lands in `age`, the callback stays "
     "PrintNote, and no shell can appear"),
    ("arg_member -> 0x28 (the `age` member)", ["arg_member=0x28"], False,
     "a real, wrong member: the read oracle aims at `age`, so the image base "
     "is never recovered"),
    ("record_size -> 0x30", ["record_size=0x30"], False,
     "a plausible, wrong record size: every arena offset shifts by 8 and the "
     "installed-callback check must catch it"),
    ("leak_span -> 0xf (the create op's span)", ["leak_span=0xf"], False,
     "the OTHER read of the same member, which leaves room for a NUL: the "
     "leak must produce nothing"),
    ("libc_slot -> stdout@0x203060 with stdin's symbol", ["libc_slot=0x203060"], False,
     "a real COPY slot holding the wrong pointer: the page-alignment check on "
     "the libc base must reject it"),
]

TIMEOUT = 200
rows = []
for name, muts, expect_green, why in CASES:
    with tempfile.TemporaryDirectory() as tmp:
        script = pathlib.Path(tmp) / "gen.py"
        gen = subprocess.run(
            [sys.executable, str(GEN), str(TARGET), str(script)] + muts,
            capture_output=True, cwd=str(REPO),
            env={"PYTHONPATH": str(REPO), "PATH": "/usr/bin:/bin",
                 "HOME": str(pathlib.Path.home())},
            timeout=300)
        if gen.returncode != 0 or not script.exists():
            rows.append((name, "GEN-FAILED", expect_green, False))
            print("[gen failed] %s: %s" % (name, gen.stdout.decode()[-300:]))
            continue
        started = time.time()
        try:
            run = subprocess.run([sys.executable, str(script)],
                                 capture_output=True, stdin=subprocess.DEVNULL,
                                 timeout=TIMEOUT, cwd=str(REPO))
            out = (run.stdout + run.stderr).decode("latin-1")
        except subprocess.TimeoutExpired as exc:
            out = ((exc.stdout or b"") + (exc.stderr or b"")).decode("latin-1")
        green = b"SH42OK".decode() in out or "shell proved" in out
        rows.append((name, "GREEN" if green else "RED", expect_green,
                     green == expect_green))
        print("%-52s %-5s expected=%-5s %.1fs  %s"
              % (name, "GREEN" if green else "RED",
                 "GREEN" if expect_green else "RED", time.time() - started,
                 "OK" if green == expect_green else "*** MISMATCH ***"))
        print("    reason: %s" % why)

bad = [r for r in rows if not r[3]]
print()
print("rows: %d   as expected: %d   mismatched: %d" % (len(rows), len(rows) - len(bad), len(bad)))
if bad:
    print("MISMATCHED (these constants are not load-bearing, or the baseline broke):")
    for r in bad:
        print("  ", r)
sys.exit(1 if bad else 0)
