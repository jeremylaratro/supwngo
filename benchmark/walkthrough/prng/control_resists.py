#!/usr/bin/env python3
"""WHY THE CONTROL CANNOT BE BRUTE-FORCED -- run it and watch the difference.

This is the teaching half of the category. Not a walkthrough artifact: it is
deliberately NOT named after any corpus slug, so benchmark/walkthrough/score.py
will never resolve it as one target's walkthrough.

It runs the SAME attack shape against two binaries that differ in exactly one
line of C:

  prng_10_time_seed_token   token = rand()  after  srand(time(NULL))
  prng_90_neg_csprng        token = getrandom(2), masked to the same 31 bits

Both accept a decimal token, both allow 64 tries, both print the flag on a
match. Same banner, same prompt, same arithmetic range. If a "PRNG technique"
solves the second one, it did not exploit a PRNG -- it found some other way in,
and every positive result in the family would be void. That is what a negative
control is for.

WHAT MAKES THE ANCHOR SOLVABLE IS NOT A SMALL VALUE SPACE.
Both secrets live in the same 2^31 space, so 64 blind guesses win with
probability 64/2^31 = 3.0e-8 against EITHER of them. The anchor is solvable
because its secret is a FUNCTION OF A GUESSABLE INPUT: seed -> secret, with the
seed drawn from ~7 plausible wall-clock seconds. The control's secret is not a
function of anything we can observe, so there is no bracket to walk -- widening
the search does not help, because there is no relationship to search over.

Two properties are measured below, and the second is the one that matters:

  1. REFUSAL. 64 candidate tokens, none accepted, "out of tries" reached.
     On its own this is weak evidence: "did not solve it" also describes a
     broken exploit.

  2. DETERMINISM ACROSS PROCESSES (the DISTINGUISHING property). One predicted
     token is offered to two INDEPENDENT anchor processes started in the same
     second, and both accept it. The control cannot do that by construction --
     two of its runs in the same second hold different tokens. This is a
     property the control provably lacks, not merely an outcome it failed to
     produce.

Run from anywhere: python3 benchmark/walkthrough/prng/control_resists.py
"""
import ctypes
import os
import re
import select
import subprocess
import sys
import time
from pathlib import Path

CORPUS = Path(__file__).resolve().parents[2] / "corpus_prng"
ANCHOR = "prng_10_time_seed_token"
CONTROL = "prng_90_neg_csprng"
MAX_TRIES = 64                   # both binaries: cmp [rbp-0x4],0x40
WIDE_BRACKET = 32                # centre +/- 32 = 65 candidates, sliced to the
                                 # 64-try allowance so it is spent EXACTLY, which
                                 # is what makes "out of tries" a measured refusal
                                 # rather than an exploit that simply stopped early
FLAG_RE = re.compile(rb"(?:FLAG|HTB|flag)\{[^}\n]{1,80}\}")

_libc = ctypes.CDLL("libc.so.6", use_errno=True)


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


def read_to_end(proc, timeout=2.0):
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


def spawn(slug):
    path = CORPUS / slug / slug
    if not path.is_file():
        sys.exit("missing %s -- build it first:\n  SUPWNGO_BENCH_CORPUS="
                 "benchmark/corpus_prng benchmark/build_all.sh" % path)
    return subprocess.Popen([str(path)], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            cwd=str(path.parent), bufsize=0)


def bracket(centre, half):
    yield centre
    for d in range(1, half + 1):
        yield centre - d
        yield centre + d


def attack(slug):
    """The identical attack, whichever binary it is pointed at."""
    proc = spawn(slug)
    seen = drain(proc, timeout=1.0)
    candidates = [first_draw(s) for s in bracket(int(time.time()), WIDE_BRACKET)]
    candidates = candidates[:MAX_TRIES]
    sent = 0
    for token in candidates:
        try:
            proc.stdin.write(b"%d\n" % token)
            proc.stdin.flush()
        except (BrokenPipeError, OSError):
            break
        sent += 1
        out = drain(proc)
        if b"accepted" in out or proc.poll() is not None:
            out += read_to_end(proc)
        seen += out
        if FLAG_RE.search(seen):
            return {"slug": slug, "solved": True, "sent": sent,
                    "rejections": seen.count(b"rejected"),
                    "out_of_tries": b"out of tries" in seen}
        if proc.poll() is not None:
            break
    try:
        proc.kill()
    except OSError:
        pass
    return {"slug": slug, "solved": False, "sent": sent,
            "rejections": seen.count(b"rejected"),
            "out_of_tries": b"out of tries" in seen}


def determinism(slug, procs=2):
    """Offer ONE predicted token to `procs` independent processes started in the
    same second. Returns how many accepted it."""
    second = int(time.time())
    token = first_draw(second)
    children = [spawn(slug) for _ in range(procs)]
    accepted = 0
    for p in children:
        drain(p, timeout=1.0)
        try:
            p.stdin.write(b"%d\n" % token)
            p.stdin.flush()
        except (BrokenPipeError, OSError):
            continue
        out = drain(p) + read_to_end(p)
        if FLAG_RE.search(out) or b"accepted" in out:
            accepted += 1
        try:
            p.kill()
        except OSError:
            pass
    return second, token, accepted


def main():
    print("== 1. the same attack, both binaries ==")
    rows = [attack(ANCHOR), attack(CONTROL)]
    for r in rows:
        print("  %-24s solved=%-5s candidates_sent=%-3d rejections=%-3d "
              "out_of_tries=%s"
              % (r["slug"], r["solved"], r["sent"], r["rejections"],
                 r["out_of_tries"]))

    print("\n== 2. the distinguishing property: one token, two processes ==")
    verdicts = {}
    for slug in (ANCHOR, CONTROL):
        second, token, accepted = determinism(slug)
        verdicts[slug] = accepted
        print("  %-24s second=%d token=%-11d accepted_by=%d/2"
              % (slug, second, token, accepted))

    ok = (rows[0]["solved"] and not rows[1]["solved"]
          and rows[1]["out_of_tries"]
          and verdicts[ANCHOR] == 2 and verdicts[CONTROL] == 0)
    print("\n%s: the anchor's secret is reproducible from the seed and the "
          "control's is not." % ("AS EXPECTED" if ok else "UNEXPECTED"))
    if not ok:
        print("  -> Do not trust any positive result in this family until this "
              "prints AS EXPECTED. Either the attack is broken (anchor should "
              "solve) or the control leaks (control must not).")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
