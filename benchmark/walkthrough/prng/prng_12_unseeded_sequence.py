#!/usr/bin/env python3
"""0-to-pwn: predictable PRNG secret, NO srand() at all (corpus_prng/prng_12).

ONE PARTICULAR vs the anchor: the generator is never seeded, and five
consecutive draws must be predicted in one shot. Self-contained.

================================ DERIVATION ================================
1. GENERATOR: `rand` is UND in .dynsym...

2. ...but `srand` is NOT:

     $ readelf --dyn-syms prng_12_unseeded_sequence | grep -c ' UND .*srand'
     0

   An absence is the finding here, so it is worth being explicit about what was
   searched: the whole dynamic symbol table, not just main's disassembly. No
   srand, no srandom, no seeding anywhere in the image.

   C says an unseeded rand() behaves as if srand(1) had been called. So the
   "random" sequence is a CONSTANT OF THE C LIBRARY, identical in every run, on
   every machine with the same libc -- the first three values are the very ones
   this file's model check asserts.

3. HOW MANY DRAWS: the round counter's bound is in the loop test

     cmp    DWORD PTR [rbp-0x4],0x5       <-- 5 rounds

   and each round reads one line and compares one fresh draw, so we must predict
   draws #0..#4 IN ORDER.

4. ONE SHOT: a wrong round returns immediately ("streak lost"), so there is no
   try allowance to spend. Either the sequence is right or the connection is over.
   That is fine: we are not guessing.

Run: cd benchmark/corpus_prng/prng_12_unseeded_sequence && python3 <this file>
"""
import ctypes
import os
import re
import select
import subprocess
import sys
import time

BINARY = os.path.join(os.getcwd(), "prng_12_unseeded_sequence")
ROUNDS = 5                       # derived: cmp [rbp-0x4],0x5
IMPLICIT_SEED = 1                # C standard: unseeded rand() == srand(1)
FLAG_RE = re.compile(rb"(?:FLAG|HTB|flag)\{[^}\n]{1,80}\}")

_libc = ctypes.CDLL("libc.so.6", use_errno=True)


def model_selfcheck():
    _libc.srand(1)
    got = [_libc.rand() for _ in range(3)]
    want = [1804289383, 846930886, 1681692777]
    if got != want:
        sys.exit("model check FAILED: srand(1) -> %r, expected %r" % (got, want))
    print("[*] model check ok: srand(1) -> %s" % (got,))


def draws(seed, n):
    _libc.srand(seed & 0xFFFFFFFF)
    return [_libc.rand() for _ in range(n)]


def drain(proc, timeout=0.6, idle=0.08):
    out = b""
    end = time.time() + timeout
    while True:
        left = end - time.time()
        if left <= 0:
            break
        ready, _, _ = select.select([proc.stdout], [], [],
                                    min(left, idle) if out else left)
        if not ready:
            break
        chunk = os.read(proc.stdout.fileno(), 65536)
        if not chunk:
            break
        out += chunk
    return out


def read_to_end(proc, timeout=3.0):
    """print_flag() writes AFTER the final "five in a row" line, so on the last
    round we keep reading until the process ends."""
    out = b""
    end = time.time() + timeout
    while time.time() < end:
        ready, _, _ = select.select([proc.stdout], [], [], 0.2)
        if ready:
            chunk = os.read(proc.stdout.fileno(), 65536)
            if not chunk:
                break
            out += chunk
            continue
        if proc.poll() is not None:
            break
    return out


def main():
    model_selfcheck()

    sequence = draws(IMPLICIT_SEED, ROUNDS)
    print("[*] unseeded stream, draws #0..#%d = %s" % (ROUNDS - 1, sequence))

    proc = subprocess.Popen([BINARY], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            cwd=os.path.dirname(BINARY) or ".", bufsize=0)
    seen = drain(proc, timeout=1.0)
    sys.stdout.write(seen.decode("utf-8", "replace"))

    for i, value in enumerate(sequence):
        try:
            proc.stdin.write(b"%d\n" % value)
            proc.stdin.flush()
        except (BrokenPipeError, OSError):
            break
        out = drain(proc, timeout=1.0)
        if i == len(sequence) - 1:
            out += read_to_end(proc)
        seen += out
        sys.stdout.write(out.decode("utf-8", "replace"))
        if b"streak lost" in seen:
            print("[-] wrong on round %d -- the libc stream does not match the "
                  "target's (different libc implementation?)" % (i + 1))
            return 1

    m = FLAG_RE.search(seen)
    if m:
        print("\n[+] all %d rounds predicted with zero guessing" % ROUNDS)
        print("[+] flag: %s" % m.group(0).decode())
        return 0
    print("[-] streak completed but no flag seen")
    return 1


if __name__ == "__main__":
    sys.exit(main())
