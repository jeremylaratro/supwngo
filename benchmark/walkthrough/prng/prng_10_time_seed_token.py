#!/usr/bin/env python3
"""0-to-pwn: predictable PRNG secret, ANCHOR (benchmark/corpus_prng/prng_10).

Self-contained on purpose: benchmark/walkthrough/score.py stages exactly ONE .py
file into the follower's sandbox, so a sibling import would not resolve there.

================================ DERIVATION ================================
Everything below was read out of the binary. Nothing was read out of the source.

1. WHICH GENERATOR.  The dynamic symbol table names it:

     $ readelf --dyn-syms prng_10_time_seed_token | grep -E ' UND .*(rand|random)'
       ... FUNC GLOBAL DEFAULT UND srand@GLIBC_2.2.5 (2)
       ... FUNC GLOBAL DEFAULT UND rand@GLIBC_2.2.5 (2)

   `rand` present => the secret comes from glibc's TYPE_3 additive-feedback
   generator. (Parse note: the LAST field of that line is the version index
   "(2)", not the name -- anchor on the UND binding and take the field after it.)

2. WHERE THE SEED COMES FROM.  Disassemble main and look at what feeds srand:

     $ objdump -d --no-show-raw-insn prng_10_time_seed_token | sed -n '/<main>:/,/ret/p'
       mov    edi,0x0
       call   401050 <time@plt>        <-- argument producer
       mov    edi,eax
       call   401080 <srand@plt>       <-- consumer
       call   401090 <rand@plt>        <-- draw #0 is the secret

   time(NULL) -> srand -> rand. The seed is a wall-clock second.

3. HOW MANY DRAWS.  One `call rand@plt` between srand and the compare, so the
   secret is draw #0.

4. HOW THE ANSWER IS ENCODED.  The compare is fed by strtoul, and strtoul's
   third argument is the base:

       mov    edx,0xa                  <-- base 10, so answer in DECIMAL

5. HOW MANY TRIES.  `cmp DWORD PTR [rbp-0x4],0x40` => 64.

================================ THE BRACKET ===============================
We do not know WHICH second the process was started in, so the seed is bracketed
around our own clock: SECONDS_EITHER_SIDE = 3 gives 7 candidates, ordered
centre-out because the true seed is almost always "now". The bracket is bounded
by the try allowance, not by patience: 7 <= 64.

Blind guessing is NOT what is happening here. rand()'s range is 2^31, so 64
random guesses would win with probability 3e-8. The 64 tries buy the CLOCK
UNCERTAINTY; the replay buys the secret.

Run: cd benchmark/corpus_prng/prng_10_time_seed_token && python3 <this file>
"""
import ctypes
import os
import re
import select
import subprocess
import sys
import time

BINARY = os.path.join(os.getcwd(), "prng_10_time_seed_token")
SECONDS_EITHER_SIDE = 3          # bracket half-width, in seconds
MAX_TRIES = 64                   # derived: cmp [rbp-0x4],0x40
FLAG_RE = re.compile(rb"(?:FLAG|HTB|flag)\{[^}\n]{1,80}\}")

_libc = ctypes.CDLL("libc.so.6", use_errno=True)


def model_selfcheck():
    """POSITIVE CONTROL FOR THE ORACLE, and it runs first.

    The model here is not a reimplementation: it is libc itself, called through
    ctypes, so it cannot drift from the target's generator. We still check it
    against the three documented first outputs of glibc srand(1) -- if this
    check ever fails, every "solve" below would be meaningless.
    """
    _libc.srand(1)
    got = [_libc.rand() for _ in range(3)]
    want = [1804289383, 846930886, 1681692777]
    if got != want:
        sys.exit("model check FAILED: srand(1) -> %r, expected %r" % (got, want))
    print("[*] model check ok: srand(1) -> %s" % (got,))


def first_draw(seed):
    _libc.srand(seed & 0xFFFFFFFF)
    return _libc.rand()


def bracket(centre, half):
    """centre, centre-1, centre+1, centre-2, centre+2, ... -- most likely first."""
    yield centre
    for d in range(1, half + 1):
        yield centre - d
        yield centre + d


def drain(proc, timeout=0.6, idle=0.08):
    """Read what is there. Returns as soon as the stream goes idle, which is why
    this whole walkthrough finishes in about a second instead of 64 timeouts."""
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
    """drain() stops at the first idle gap, which is what makes 64 tries cheap --
    but the flag is written by a SECOND write (print_flag opens ./flag.txt after
    printing the acceptance line), so once an answer lands we must keep reading
    until the process actually ends."""
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
    seen = drain(proc, timeout=1.0)
    sys.stdout.write(seen.decode("utf-8", "replace"))

    candidates = [first_draw(s) for s in bracket(int(time.time()),
                                                 SECONDS_EITHER_SIDE)]
    print("[*] %d candidate tokens from a +/-%ds seed bracket (allowance %d)"
          % (len(candidates), SECONDS_EITHER_SIDE, MAX_TRIES))

    for i, token in enumerate(candidates[:MAX_TRIES]):
        try:
            proc.stdin.write(b"%d\n" % token)
            proc.stdin.flush()
        except (BrokenPipeError, OSError):
            break
        out = drain(proc)
        if b"accepted" in out or proc.poll() is not None:
            out += read_to_end(proc)
        seen += out
        sys.stdout.write(out.decode("utf-8", "replace"))
        m = FLAG_RE.search(seen)
        if m:
            print("\n[+] token %d (candidate %d/%d) accepted"
                  % (token, i + 1, len(candidates)))
            print("[+] flag: %s" % m.group(0).decode())
            # Hand the process over. The harness injects its own stdin, and if a
            # solve ever ends in a shell instead of a print this is where it is
            # read. We never open flag.txt ourselves: the TARGET printed it.
            try:
                proc.stdin.write(b"\n")
                proc.stdin.flush()
            except (BrokenPipeError, OSError):
                pass
            return 0
        if proc.poll() is not None:
            break

    print("[-] no candidate accepted -- widen SECONDS_EITHER_SIDE, or the clock "
          "moved more than the bracket between spawn and send")
    return 1


if __name__ == "__main__":
    sys.exit(main())
