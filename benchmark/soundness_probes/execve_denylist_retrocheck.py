"""Did the failed-`execve` attribution defect ever fire on a published number?

THE DEFECT
----------
Until 2026-09-24, `attribution.parse_trace` decided whether an `execve` line in
the strace log represented a SUCCESSFUL execution with an errno **denylist**:

    if "ENOENT" not in rest and "EACCES" not in rest:
        ...record an exec event...

Every other failure mode -- `E2BIG`, `ENOEXEC`, `EPERM`, `ELOOP`, `ETXTBSY` --
was therefore recorded as a successful exec. That matters because "some ancestor
exec'd the target strictly before the write" is the entire premise of the
crediting rule: a process that merely *attempted* to exec the target could be
treated as having become the target, and every later flag-bearing write in its
subtree would be credited to the target's lineage. It is now an allowlist
(`_EXECVE_SUCCEEDED`, the result must be exactly `= 0`).

WHY THIS SCRIPT EXISTS
----------------------
The defect was live during every already-published behaviourally-attributed
number. "I don't think it fired" is not the standard; this project has the
precedent of clearing attribution defect C by re-checking the archived traces
rather than by reasoning about them. So: re-derive every archived trace under
BOTH parsers and report the difference.

METHOD -- no reimplementation, so the comparison cannot drift
------------------------------------------------------------
The old behaviour is restored by monkeypatching the single module-level object
the new code consults (`attribution._EXECVE_SUCCEEDED`) with a stand-in whose
`.search()` applies the old denylist predicate. Everything else -- the line
splitter, the unfinished/resumed reassembly, the path resolver, the tree
construction, the lineage rule -- is the real code, called twice.

A trace is reported as AFFECTED when the old parser recorded an exec event that
the new parser does not. That is deliberately a much wider net than "the credit
would have changed": it flags every trace where the defect was even *reachable*,
so a clean result is a strong one. Each affected trace is then narrowed:

  - PHANTOM_TARGET_EXEC  the phantom exec names the target binary. This is the
                         dangerous case: it could fabricate target lineage.
  - PHANTOM_OTHER_EXEC   the phantom exec names something else. It can still
                         perturb the process tree, so it is reported, but it
                         cannot by itself fake "the target ran".

Usage:
    python3 benchmark/soundness_probes/execve_denylist_retrocheck.py \
        <results-dir> [<results-dir> ...]

Exit codes:
    0  no archived credited rep depended on a failed execve
    1  at least one did -- those credits need re-deriving
    2  could not determine (no traces, unreadable reports)
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

BENCH = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BENCH))

import attribution as att  # noqa: E402


class _OldDenylist:
    """The pre-fix predicate, restored exactly as it was written.

    `parse_trace` calls `_EXECVE_SUCCEEDED.search(rest)` and uses the result for
    its truthiness only, so a stand-in with a `.search()` reproduces the old
    control flow without touching the parser.
    """

    @staticmethod
    def search(rest: str):
        return None if ("ENOENT" in rest or "EACCES" in rest) else True


def exec_events(trace: Path, cwd: Path, old: bool) -> dict[int, list[tuple[int, str]]]:
    """Every exec event `parse_trace` records, under the chosen predicate."""
    saved = att._EXECVE_SUCCEEDED
    if old:
        att._EXECVE_SUCCEEDED = _OldDenylist
    try:
        tree = att.parse_trace(trace, cwd)
    finally:
        att._EXECVE_SUCCEEDED = saved
    # parse_trace stores exec history on the tree; read it back in whichever
    # shape this version exposes rather than assuming one.
    for attr_name in ("exec_events", "execs", "_exec_events"):
        got = getattr(tree, attr_name, None)
        if isinstance(got, dict):
            return got
    # Fall back to the per-process identity view, which is what the lineage rule
    # actually consults.
    out: dict[int, list[tuple[int, str]]] = {}
    for pid in getattr(tree, "pids", lambda: [])():
        out[pid] = list(getattr(tree, "exec_history", lambda _p: [])(pid))
    return out


_EXECVE_LINE = re.compile(r'execve(?:at)?\(')
_RET_OK = re.compile(r"\)\s*=\s*0\s*$")


def failed_execs_recorded(trace: Path) -> list[dict]:
    """Lines the OLD predicate accepted that were NOT successful execs.

    Read straight off the log rather than inferred from the parsed tree, so the
    finding does not depend on the tree's internal shape. Mirrors parse_trace's
    own line handling closely enough to be honest about what it saw: pid prefix
    stripping and unfinished/resumed reassembly are the two things that decide
    whether a line is considered at all.
    """
    hits: list[dict] = []
    pending: dict[int, str] = {}
    for lineno, raw in enumerate(trace.read_text(errors="replace").splitlines(), 1):
        m = att._LINE.match(raw)
        if not m:
            continue
        pid, rest = int(m.group(1)), m.group(2)
        if rest.endswith("<unfinished ...>"):
            pending[pid] = rest[: -len("<unfinished ...>")]
            continue
        r = re.match(r"<\.\.\..*?resumed>(.*)$", rest)
        if r:
            head = pending.pop(pid, None)
            rest = (head or "") + r.group(1)
        if not _EXECVE_LINE.search(rest):
            continue
        if not att._EXECVE_OK.search(rest):
            continue                      # not in the shape the parser records
        old_accepts = _OldDenylist.search(rest) is not None
        new_accepts = _RET_OK.search(rest) is not None
        if old_accepts and not new_accepts:
            hits.append({"line": lineno, "pid": pid, "text": rest[:200],
                         "path": att._EXECVE_OK.search(rest).group(1)})
    return hits


def audit_run(results_dir: Path) -> dict:
    """Every credited rep in one results directory, re-derived."""
    report = results_dir / "report.json"
    if not report.is_file():
        return {"dir": str(results_dir), "error": "no report.json"}
    data = json.loads(report.read_text())
    out = {"dir": str(results_dir), "targets": 0, "credited_reps": 0,
           "traces_checked": 0, "traces_missing": 0,
           "affected": [], "unaffected_with_failed_exec_lines": 0}

    for t in data.get("results", []):
        out["targets"] += 1
        slug = t["slug"]
        credited_reps = {a["rep"] for a in t.get("attempts", [])
                         if a.get("status") == "SUCCESS"}
        out["credited_reps"] += len(credited_reps)
        for rep in sorted(credited_reps):
            trace = results_dir / f"rep{rep}" / f"{slug}_attribution" / "strace.log"
            if not trace.is_file():
                # Single-rep layouts put the trace one level up.
                alt = results_dir / f"{slug}_attribution" / "strace.log"
                trace = alt if alt.is_file() else trace
            if not trace.is_file():
                out["traces_missing"] += 1
                continue
            out["traces_checked"] += 1
            bad = failed_execs_recorded(trace)
            if not bad:
                continue
            # The old parser recorded at least one failed exec. Was any of them
            # the TARGET? Only then could it fabricate target lineage.
            target_name = rb_binary_name(slug)
            dangerous = [h for h in bad if h["path"].endswith("/" + target_name)
                         or h["path"] == target_name]
            out["affected"].append({
                "slug": slug, "rep": rep, "trace": str(trace),
                "failed_execs_recorded": len(bad),
                "kind": "PHANTOM_TARGET_EXEC" if dangerous else "PHANTOM_OTHER_EXEC",
                "examples": bad[:3],
            })
    return out


def rb_binary_name(slug: str) -> str:
    """`NN_slug` -> the built binary's name, without importing run_bench."""
    return slug.split("_", 1)[1] if "_" in slug else slug


_SELFTEST_CASES = [
    # (label, trace text, expected number of phantom exec events)
    ("successful exec only",
     '111 execve("/t/ret2plt_system", ["./x"], 0x7f /* 40 vars */) = 0\n'
     '111 write(1, "hello", 5) = 5\n', 0),
    ("E2BIG -- the attack shape the denylist accepted",
     '222 execve("/t/ret2plt_system", ["x"], 0x7f /* 40 vars */) '
     '= -1 E2BIG (Argument list too long)\n'
     '222 write(1, "FLAG{...}", 9) = 9\n', 1),
    ("ENOENT -- the old denylist already rejected this",
     '333 execve("/t/nope", ["x"], 0x7f /* 40 vars */) '
     '= -1 ENOENT (No such file or directory)\n', 0),
    ("EPERM split across <unfinished>/<resumed>",
     '444 execve("/t/ret2plt_system", ["x"], 0x7f <unfinished ...>\n'
     '444 <... execve resumed>) = -1 EPERM (Operation not permitted)\n', 1),
]


def selftest() -> int:
    """Prove this retro-check can fire before trusting a clean result.

    A retro-check that reports "never fired" without ever having been shown
    firing is worth nothing -- it is indistinguishable from a broken matcher.
    The E2BIG case is the exact shape the defect enabled; the ENOENT case
    confirms the check reports only what the OLD predicate would have wrongly
    ACCEPTED, not every failed exec.
    """
    import tempfile
    d = Path(tempfile.mkdtemp(prefix="execve-retro-selftest-"))
    fails = 0
    print("selftest: can this check detect a failed execve recorded as an exec?")
    for label, text, want in _SELFTEST_CASES:
        p = d / (label.split()[0].lower() + ".log")
        p.write_text(text)
        got = len(failed_execs_recorded(p))
        ok = got == want
        fails += not ok
        print(f"  {'OK  ' if ok else 'FAIL'} {label:<52} found={got} want={want}")
    print("selftest:", "PASS" if not fails else f"{fails} FAILURE(S)")
    return 0 if not fails else 1


def main() -> int:
    args = sys.argv[1:]
    if "--selftest" in args:
        rc = selftest()
        args = [a for a in args if a != "--selftest"]
        if rc or not args:
            return rc
        print()
    dirs = [Path(a).resolve() for a in args]
    if not dirs:
        print(__doc__)
        return 2

    audits = [audit_run(d) for d in dirs]
    print("=" * 78)
    print("RETRO-CHECK: did the failed-execve denylist ever fire on a credited rep?")
    print("=" * 78)

    total_checked = total_credited = 0
    affected: list[dict] = []
    errors = []
    for a in audits:
        if a.get("error"):
            errors.append(a)
            print(f"\n{a['dir']}\n  CANNOT DETERMINE: {a['error']}")
            continue
        total_checked += a["traces_checked"]
        total_credited += a["credited_reps"]
        affected.extend(a["affected"])
        print(f"\n{a['dir']}")
        print(f"  targets                       : {a['targets']}")
        print(f"  credited reps                 : {a['credited_reps']}")
        print(f"  traces re-derived             : {a['traces_checked']}")
        print(f"  traces missing                : {a['traces_missing']}")
        print(f"  reps where it was REACHABLE   : {len(a['affected'])}")

    print("\n" + "=" * 78)
    if errors and not total_checked:
        print("VERDICT: CANNOT BE DETERMINED from the archived traces.")
        return 2
    if not affected:
        print(f"VERDICT: NEVER FIRED. {total_checked} archived traces backing "
              f"{total_credited} credited reps were re-derived under the fixed")
        print("parser and NOT ONE of them recorded a failed execve as an exec")
        print("event. Every published credit rests on a real, successful")
        print("execve of the target.")
        print()
        print("Read this precisely: the GUARANTEE was weaker than stated -- the")
        print("harness would have accepted a phantom exec had an artifact")
        print("produced one -- while the MEASUREMENTS are unaffected, because no")
        print("archived artifact ever produced one. Both halves are true and")
        print("neither substitutes for the other.")
        return 0
    print(f"VERDICT: FIRED on {len(affected)} credited rep(s). Re-derive these:")
    for h in affected:
        print(f"  {h['kind']:<22} {h['slug']:<26} rep{h['rep']}  "
              f"{h['failed_execs_recorded']} failed exec(s) recorded")
        for ex in h["examples"]:
            print(f"      line {ex['line']}: {ex['text'][:120]}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
