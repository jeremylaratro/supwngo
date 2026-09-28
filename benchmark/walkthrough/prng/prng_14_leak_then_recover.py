#!/usr/bin/env python3
"""0-to-pwn: predictable PRNG secret, seed RECOVERED from published draws
(corpus_prng/prng_14).

ONE PARTICULAR vs the anchor: the target publishes three draws from the same
stream before the secret, so the seed is not guessed -- it is solved for. Also a
different generator pair (random/srandom instead of rand/srand). Self-contained.

================================ DERIVATION ================================
1. GENERATOR: the UND names are `random` and `srandom`, not rand/srand:

     $ readelf --dyn-syms prng_14_leak_then_recover | grep -E ' UND .*random'
       ... UND srandom@GLIBC_2.2.5 (2)
       ... UND random@GLIBC_2.2.5 (2)

   These share ONE state with rand()/srand() in glibc -- same TYPE_3 additive
   feedback, so srandom(s) then random() gives the same values as srand(s) then
   rand(). `random` returns long, so the printf format is %ld.

2. SEED SOURCE: time(NULL) -> srandom, same producer/consumer shape as the anchor.

3. THE LEAK. There are TWO call sites of random@plt: one inside a loop whose
   bound is `cmp DWORD PTR [rbp-0x14],0x2` (3 iterations, each printed as
   "nonce %ld"), then one more after the loop whose result is the secret. So the
   stream is:

       draw #0, #1, #2  -> PRINTED TO US
       draw #3          -> the token we must produce

4. WHY THIS IS THE STRONGEST CASE IN THE FAMILY. We do not bracket the clock to
   GUESS; we search a wide window and CONFIRM against three published 31-bit
   values. A false seed would have to reproduce 93 bits of published output, so
   the recovered seed is certain, not probable (1 in 2^93 per candidate). That
   also makes this target the positive control for the generator model itself:
   if our libc stream did not match the target's, NO seed in the window would
   reproduce the nonces, and we would find out instead of guessing wrong quietly.

   RECOVERY_WINDOW is therefore generous (+/-60s) -- it costs nothing to widen a
   search that is verified, unlike a bracket that is merely tried.

5. TRIES: `cmp ...,0x4` => 4. We need one.

Run: cd benchmark/corpus_prng/prng_14_leak_then_recover && python3 <this file>
"""
import ctypes
import os
import re
import select
import subprocess
import sys
import time

BINARY = os.path.join(os.getcwd(), "prng_14_leak_then_recover")
NONCES = 3                       # derived: cmp [rbp-0x14],0x2  -> 3 iterations
RECOVERY_WINDOW = 60             # seconds either side; verified, so it can be wide
MAX_TRIES = 4                    # derived: cmp [rbp-0x18],0x4
FLAG_RE = re.compile(rb"(?:FLAG|HTB|flag)\{[^}\n]{1,80}\}")
NONCE_RE = re.compile(rb"nonce\s+(-?\d+)")

_libc = ctypes.CDLL("libc.so.6", use_errno=True)
_libc.random.restype = ctypes.c_long     # random() returns long, not int


def model_selfcheck():
    """srand/rand and srandom/random must agree -- that is the claim we rely on."""
    _libc.srand(1)
    a = [_libc.rand() for _ in range(3)]
    want = [1804289383, 846930886, 1681692777]
    if a != want:
        sys.exit("model check FAILED: srand(1) -> %r, expected %r" % (a, want))
    _libc.srandom(1)
    b = [int(_libc.random()) for _ in range(3)]
    if b != want:
        sys.exit("model check FAILED: srandom(1) -> %r, expected %r" % (b, want))
    print("[*] model check ok: srand(1) == srandom(1) == %s (one shared state)" % (a,))


def random_draws(seed, n):
    _libc.srandom(seed & 0xFFFFFFFF)
    return [int(_libc.random()) for _ in range(n)]


def recover_seed(nonces, centre, window):
    """Solve for the seed instead of guessing it. Returns None if nothing matches,
    which is a real answer: it means the model is wrong, not that we were unlucky."""
    for d in range(0, window + 1):
        for seed in ({centre} if d == 0 else {centre - d, centre + d}):
            if random_draws(seed, len(nonces)) == nonces:
                return seed
    return None


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

    proc = subprocess.Popen([BINARY], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            cwd=os.path.dirname(BINARY) or ".", bufsize=0)
    seen = drain(proc, timeout=1.5)
    sys.stdout.write(seen.decode("utf-8", "replace"))

    nonces = [int(x) for x in NONCE_RE.findall(seen)][:NONCES]
    if len(nonces) < 2:
        print("[-] only %d published draw(s) -- need >= 2 to pin a seed"
              % len(nonces))
        return 1
    print("[*] published draws: %s" % nonces)

    seed = recover_seed(nonces, int(time.time()), RECOVERY_WINDOW)
    if seed is None:
        print("[-] no seed in +/-%ds reproduces those draws -- the generator "
              "model does not match this target" % RECOVERY_WINDOW)
        return 1

    token = random_draws(seed, len(nonces) + 1)[-1]
    print("[*] seed = %d (confirmed against %d published draws, ~2^-%d by chance)"
          % (seed, len(nonces), 31 * len(nonces)))
    print("[*] next draw (#%d) = %d  <- the token" % (len(nonces), token))

    proc.stdin.write(b"%d\n" % token)
    proc.stdin.flush()
    out = drain(proc, timeout=1.0) + read_to_end(proc)
    seen += out
    sys.stdout.write(out.decode("utf-8", "replace"))

    m = FLAG_RE.search(seen)
    if m:
        print("\n[+] token accepted on try 1 of %d" % MAX_TRIES)
        print("[+] flag: %s" % m.group(0).decode())
        return 0
    print("[-] rejected despite a confirmed seed -- check the draw INDEX "
          "(how many draws the target consumed before the secret)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
