#!/usr/bin/env python3
"""0-to-pwn: predictable PRNG secret, compile-time literal seed
(corpus_prng/prng_13).

ONE PARTICULAR vs the anchor: the seed is an immediate in the instruction
stream, and the secret is a STRING built from eight draws. Self-contained.

================================ DERIVATION ================================
1. GENERATOR: `rand` + `srand` UND in .dynsym.

2. THE SEED IS IN THE CODE. The producer feeding srand is not a call at all, it
   is an immediate:

     mov    edi,0xc0ffee              <-- the seed, 12648430
     call   401080 <srand@plt>

   No bracket, no pid, no clock: this password is a constant of the BINARY. Every
   deployment of this build has the same "generated" password.

3. THE ALPHABET. The indexing load names the symbol it reads from:

     lea    rdx,[rip+0xca5]        # 402020 <ALPHABET>
     $ objdump -s -j .rodata prng_13_fixed_seed_password   # at 402020:
       abcdefghijklmnopqrstuvwxyz0123456789

   36 bytes plus the NUL. The modulus in the index expression is `sizeof
   ALPHABET - 1` == 36, and at -O0 that constant is visible the same way the
   anchor's divisor is.

4. HOW MANY DRAWS. The build loop's bound:

     cmp    DWORD PTR [rbp-0x24],0x7    <-- i <= 7, i.e. PW_LEN == 8

   so the password is ALPHABET[draw_i % 36] for i in 0..7 -- eight draws from
   one seeded stream, consumed in order.

5. TRIES: `cmp ...,0x8` => 8. We need one.

WHY THIS IS NOT `strings`. The password is not in .rodata -- only the alphabet
is. The password exists solely as the output of the generator, which is why
reproducing the stream is the only way to get it (and why the corpus keeps its
flag in ./flag.txt, so no `strings` shortcut can fake a solve either).

Run: cd benchmark/corpus_prng/prng_13_fixed_seed_password && python3 <this file>
"""
import ctypes
import os
import re
import select
import subprocess
import sys
import time

BINARY = os.path.join(os.getcwd(), "prng_13_fixed_seed_password")
FIXED_SEED = 0xC0FFEE                                  # derived: mov edi,0xc0ffee
ALPHABET = b"abcdefghijklmnopqrstuvwxyz0123456789"     # derived: <ALPHABET> in .rodata
PW_LEN = 8                                             # derived: cmp [rbp-0x24],0x7
MAX_TRIES = 8                                          # derived: cmp [rbp-0x2c],0x8
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
    """print_flag() writes AFTER the acceptance line, so keep reading to the end
    instead of stopping at the first idle gap."""
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

    n = len(ALPHABET)
    password = bytes(ALPHABET[d % n] for d in draws(FIXED_SEED, PW_LEN))
    print("[*] srand(0x%x); %d x ALPHABET[rand()%%%d]  ->  %s"
          % (FIXED_SEED, PW_LEN, n, password.decode()))

    proc = subprocess.Popen([BINARY], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            cwd=os.path.dirname(BINARY) or ".", bufsize=0)
    seen = drain(proc, timeout=1.0)
    sys.stdout.write(seen.decode("utf-8", "replace"))

    proc.stdin.write(password + b"\n")
    proc.stdin.flush()
    out = drain(proc, timeout=1.0) + read_to_end(proc)
    seen += out
    sys.stdout.write(out.decode("utf-8", "replace"))

    m = FLAG_RE.search(seen)
    if m:
        print("\n[+] login accepted on try 1 of %d" % MAX_TRIES)
        print("[+] flag: %s" % m.group(0).decode())
        return 0
    print("[-] rejected -- re-check the alphabet bytes and the modulus; an "
          "off-by-one in `sizeof ALPHABET - 1` changes every character")
    return 1


if __name__ == "__main__":
    sys.exit(main())
