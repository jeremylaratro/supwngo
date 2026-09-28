#!/usr/bin/env python3
"""0-to-pwn: predictable PRNG secret from rand_r(), answered in hex
(corpus_prng/prng_15).

ONE PARTICULAR vs the anchor: a DIFFERENT generator (rand_r, a small LCG over a
caller-held state, not the shared TYPE_3 state) and a hex answer encoding. The
secret is framed as a canary substitute -- a "session guard" cookie. Self-contained.

================================ DERIVATION ================================
1. GENERATOR: the only PRNG name UND in .dynsym is `rand_r`:

     $ readelf --dyn-syms prng_15_rand_r_hex_guard | grep ' UND .*rand'
       ... UND rand_r@GLIBC_2.2.5 (2)

   No srand/srandom, because rand_r does not use the global state: it takes a
   pointer to the caller's `unsigned int` and advances it in place. So there is
   no "seeding call" to look for -- the seed is whatever is stored at that
   address before the call, which is why step 2 looks at the argument, not at a
   seeding function.

2. SEED SOURCE: the value stored into the state slot comes from time():

     call   401060 <time@plt>
     mov    DWORD PTR [rbp-0x14],eax      <-- the state variable
     lea    rax,[rbp-0x14]
     mov    rdi,rax
     call   401070 <rand_r@plt>           <-- guard = rand_r(&state)

   time(NULL) again, so the same +/-3s bracket as the anchor applies.

3. ANSWER ENCODING -- this is the one that silently defeats a decimal replay.
   strtoul's base argument is 16 here, not 10:

     mov    edx,0x10                      <-- base 16, answer in HEX

   The right number in the wrong encoding is simply a wrong answer, so the
   encoding has to be derived, not assumed. (The anchor's is `mov edx,0xa`.)

4. TRIES: `cmp ...,0x40` => 64, which pays for the clock bracket.

WHY NOT JUST CALL libc's rand_r? We do -- through ctypes, with an explicit
POINTER(c_uint) argtype so the state is advanced in OUR copy exactly as it is in
the target's. The three-step LCG is also written out below as a comment, because
the point of the walkthrough is that you can see it is not magic:
    next = state*1103515245 + 12345 (mod 2^31), three times, folded together.

Run: cd benchmark/corpus_prng/prng_15_rand_r_hex_guard && python3 <this file>
"""
import ctypes
import os
import re
import select
import subprocess
import sys
import time

BINARY = os.path.join(os.getcwd(), "prng_15_rand_r_hex_guard")
SECONDS_EITHER_SIDE = 3          # same clock bracket as the anchor
MAX_TRIES = 64                   # derived: cmp [rbp-0x18],0x40
ANSWER_BASE = 16                 # derived: mov edx,0x10 (strtoul base)
FLAG_RE = re.compile(rb"(?:FLAG|HTB|flag)\{[^}\n]{1,80}\}")

_libc = ctypes.CDLL("libc.so.6", use_errno=True)
_libc.rand_r.argtypes = [ctypes.POINTER(ctypes.c_uint)]
_libc.rand_r.restype = ctypes.c_int


def model_selfcheck():
    """Two checks: the shared-state generator against its documented constants
    (proves ctypes reached the real libc), and rand_r against a hand-rolled
    reimplementation of its LCG (proves we are modelling the RIGHT generator --
    rand_r's output for seed s is NOT rand()'s output for seed s)."""
    _libc.srand(1)
    got = [_libc.rand() for _ in range(3)]
    want = [1804289383, 846930886, 1681692777]
    if got != want:
        sys.exit("model check FAILED: srand(1) -> %r, expected %r" % (got, want))

    def rand_r_pure(seed):
        """glibc's rand_r, transcribed: three LCG steps, the first folded in
        mod 2048 and the next two XORed in mod 1024 after a 10-bit shift."""
        s = seed & 0xFFFFFFFF
        s = (s * 1103515245 + 12345) & 0xFFFFFFFF
        result = (s >> 16) % 2048
        s = (s * 1103515245 + 12345) & 0xFFFFFFFF
        result = (result << 10) ^ ((s >> 16) % 1024)
        s = (s * 1103515245 + 12345) & 0xFFFFFFFF
        result = (result << 10) ^ ((s >> 16) % 1024)
        return result

    for probe in (1, 2, 12345, 1700000000):
        if guard_for(probe) != rand_r_pure(probe):
            sys.exit("model check FAILED: libc rand_r(%d)=%d disagrees with the "
                     "documented LCG (%d)"
                     % (probe, guard_for(probe), rand_r_pure(probe)))
    if guard_for(1) == got[0]:
        sys.exit("model check FAILED: rand_r and rand agree, so one of them is "
                 "not the generator it claims to be")
    print("[*] model check ok: rand()/srand(1) constants match, and libc rand_r "
          "matches its LCG while differing from rand() (distinct generators)")


def guard_for(seed):
    state = ctypes.c_uint(seed & 0xFFFFFFFF)
    return _libc.rand_r(ctypes.byref(state)) & 0xFFFFFFFF


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


def bracket(centre, half):
    yield centre
    for d in range(1, half + 1):
        yield centre - d
        yield centre + d


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


def main():
    model_selfcheck()

    proc = subprocess.Popen([BINARY], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            cwd=os.path.dirname(BINARY) or ".", bufsize=0)
    seen = drain(proc, timeout=1.0)
    sys.stdout.write(seen.decode("utf-8", "replace"))

    candidates = [guard_for(s) for s in bracket(int(time.time()),
                                                SECONDS_EITHER_SIDE)]
    print("[*] %d candidate guards from a +/-%ds bracket, sent in base %d"
          % (len(candidates), SECONDS_EITHER_SIDE, ANSWER_BASE))

    for i, guard in enumerate(candidates[:MAX_TRIES]):
        try:
            proc.stdin.write(b"%x\n" % guard)        # hex, because edx was 0x10
            proc.stdin.flush()
        except (BrokenPipeError, OSError):
            break
        out = drain(proc)
        if b"matched" in out or proc.poll() is not None:
            out += read_to_end(proc)
        seen += out
        sys.stdout.write(out.decode("utf-8", "replace"))
        m = FLAG_RE.search(seen)
        if m:
            print("\n[+] guard 0x%x (candidate %d/%d) matched"
                  % (guard, i + 1, len(candidates)))
            print("[+] flag: %s" % m.group(0).decode())
            return 0
        if proc.poll() is not None:
            break

    print("[-] no candidate matched -- if the values look plausible, check the "
          "ENCODING first (decimal vs hex is the usual cause here)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
