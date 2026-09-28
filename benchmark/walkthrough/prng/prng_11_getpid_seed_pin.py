#!/usr/bin/env python3
"""0-to-pwn: predictable PRNG secret, seed = getpid() (corpus_prng/prng_11).

ONE PARTICULAR vs the anchor: the seed source is the pid, and the draw is
truncated by a modulus. Self-contained (the scorer stages one file).

================================ DERIVATION ================================
1. GENERATOR: `rand` + `srand` UND in .dynsym (same readelf line as the anchor).

2. SEED SOURCE -- the producer feeding srand is getpid, not time:

     call   401060 <getpid@plt>
     mov    edi,eax
     call   401080 <srand@plt>

   This is the EASIEST seed class in the family: no bracket at all. We are the
   parent that spawns the process, so the pid is not a guess, it is a fact we
   are handed by fork(). (Remote, you would bracket a pid range instead; the
   same code works with `for pid in range(lo, hi)`.)

3. THE MODULUS -- gcc at -O0 does not emit `div` for a constant divisor, it
   emits a reciprocal multiply followed by a multiply-back, and the multiply-back
   carries the divisor as a literal:

     imul   edx,edx,0xf4240          <-- 0xf4240 == 1000000 == PIN_MOD

   So the secret is `rand() % 1000000`, i.e. a 6-digit PIN.

4. TRIES: `cmp DWORD PTR [rbp-0x8],0x3` => only 3. Blind guessing a 6-digit PIN
   in 3 tries is 3e-6; with the seed known we need exactly ONE try.

Run: cd benchmark/corpus_prng/prng_11_getpid_seed_pin && python3 <this file>
"""
import ctypes
import os
import re
import select
import subprocess
import sys
import time

BINARY = os.path.join(os.getcwd(), "prng_11_getpid_seed_pin")
PIN_MOD = 1000000                # derived: imul edx,edx,0xf4240
MAX_TRIES = 3                    # derived: cmp [rbp-0x8],0x3
FLAG_RE = re.compile(rb"(?:FLAG|HTB|flag)\{[^}\n]{1,80}\}")

_libc = ctypes.CDLL("libc.so.6", use_errno=True)


def model_selfcheck():
    _libc.srand(1)
    got = [_libc.rand() for _ in range(3)]
    want = [1804289383, 846930886, 1681692777]
    if got != want:
        sys.exit("model check FAILED: srand(1) -> %r, expected %r" % (got, want))
    print("[*] model check ok: srand(1) -> %s" % (got,))


def first_draw(seed):
    _libc.srand(seed & 0xFFFFFFFF)
    return _libc.rand()


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
    """print_flag() writes AFTER the acceptance line, so once an answer lands we
    keep reading until the process ends rather than stopping at the first gap."""
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

    proc = subprocess.Popen([BINARY], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            cwd=os.path.dirname(BINARY) or ".", bufsize=0)
    # The seed, handed to us by the kernel. No search, no bracket.
    pin = first_draw(proc.pid) % PIN_MOD
    print("[*] child pid = %d  ->  srand(%d); rand() %% %d = %06d"
          % (proc.pid, proc.pid, PIN_MOD, pin))

    seen = drain(proc, timeout=1.0)
    sys.stdout.write(seen.decode("utf-8", "replace"))

    # %06d matters: atoi() would read "1234" for a PIN of 001234 just fine, but
    # printing it zero-padded is what the operator would type, so keep it honest.
    proc.stdin.write(b"%06d\n" % pin)
    proc.stdin.flush()
    out = drain(proc, timeout=1.0) + read_to_end(proc)
    seen += out
    sys.stdout.write(out.decode("utf-8", "replace"))

    m = FLAG_RE.search(seen)
    if m:
        print("\n[+] PIN accepted on try 1 of %d" % MAX_TRIES)
        print("[+] flag: %s" % m.group(0).decode())
        return 0
    print("[-] PIN rejected -- if this fails the pid->seed link is broken "
          "(e.g. the binary re-execs, so getpid() is not the pid we spawned)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
