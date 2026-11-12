"""Budgeted angr operations in a spawned subprocess (S4b-i, RT-05).

angr's ``CFGFast`` runs uninterruptible C-level work. On a large statically
linked binary it never returns within budget, and no Python-level watchdog can
stop it: a watchdog thread cannot interrupt the C work, and a leaked thread
keeps mutating the knowledge base after any in-process fallback begins. The only
way to truly cancel it is to run the op in a *separate process* and kill that
process -- the OS then reclaims the C-level work.

This module runs each angr op in a **spawned** child (a fresh interpreter, no
inherited angr state), hands the result back through a parent-created temp file,
and on timeout kills the child's whole process group so any descendant angr may
have spawned dies with it.

Public surface:

``AnalysisBudgetExceeded``
    The op exceeded its wall-clock budget. Callers should catch this
    *specifically*, run their existing non-angr fallback, and mark the result's
    analysis backend as degraded (so the degradation is machine-visible, which a
    broad ``except`` alone cannot express).

``AngrSubprocessError``
    The child raised or crashed (a real error, not a budget). Callers should
    still fall back, but this is not the "binary too big" signal.

``run_angr_op(binary_path, op, seconds, **op_kwargs) -> Any``
    Run one named op under a budget and return its plain-data result.

``DEFAULT_ANGR_TIMEOUT``
    The budget used when a caller/CLI does not supply one. Overridable with the
    ``SUPWNGO_ANGR_TIMEOUT`` environment variable. Kept well under the 60 s
    retest harness cut so the spawn/import/reap/fallback tail still fits.
"""

from __future__ import annotations

import math
import multiprocessing
import os
import pickle
import signal
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable, Dict

#: Budget (seconds) used when no explicit timeout is given. 30 s leaves ample
#: reserve under the ~60 s retest harness cut for parent load, child spawn +
#: angr import, terminate/kill/reap (<=3 s), the capstone/symbol fallback, and
#: output. Measured worst-case snow_scan timeout path fits well inside 60 s.
DEFAULT_ANGR_TIMEOUT: float = float(os.environ.get("SUPWNGO_ANGR_TIMEOUT", "30"))

#: Grace period (seconds) for a killed child to actually die before escalating.
_REAP_GRACE: float = 3.0


class AnalysisBudgetExceeded(Exception):
    """An angr op did not finish within its wall-clock budget."""


class AngrSubprocessError(Exception):
    """An angr op failed in, or could not be run by, the child process."""


# ---------------------------------------------------------------------------
# Child side (runs in the spawned process; every entry here must be importable
# by qualified name, because spawn pickles targets by reference).
# ---------------------------------------------------------------------------

def _load_project(binary_path: str):
    """Build a fresh angr Project in the child, matching Binary.get_angr_project."""
    import angr  # local import: the parent must not require angr to import this module

    return angr.Project(binary_path, auto_load_libs=False)


def _op_cfg(binary_path: str, **_kwargs) -> Dict[str, Any]:
    """CFGFast over the whole binary, serialized to plain dicts.

    Mirrors ``CFGAnalyzer._build_cfg_angr`` field-for-field so the parent can
    reconstruct ``BasicBlock``/``Function`` objects and recompute the call graph
    and cyclomatic complexity exactly as the in-process path did.
    """
    from supwngo.analysis._angr_callgraph import iter_callees

    proj = _load_project(binary_path)
    cfg = proj.analyses.CFGFast(normalize=True)

    blocks = []
    for node in cfg.graph.nodes():
        if node.block is None:
            continue
        instructions = []
        calls = []
        try:
            for insn in node.block.capstone.insns:
                instructions.append((insn.address, insn.mnemonic, insn.op_str))
                if insn.mnemonic in ("call", "bl", "blx"):
                    try:
                        target = int(insn.op_str, 16) if insn.op_str.startswith("0x") else 0
                        if target:
                            calls.append(target)
                    except ValueError:
                        calls.append(0)  # indirect call
        except Exception:
            pass
        blocks.append(
            {
                "address": node.addr,
                "size": node.size,
                "successors": [succ.addr for succ in cfg.graph.successors(node)],
                "predecessors": [pred.addr for pred in cfg.graph.predecessors(node)],
                "instructions": instructions,
                "calls": calls,
            }
        )

    functions = []
    for func_addr, func in cfg.kb.functions.items():
        callees = [
            (callee.name or f"sub_{callee.addr:x}", callee.addr)
            for callee in iter_callees(func, cfg.kb.functions)
        ]
        functions.append(
            {
                "address": func_addr,
                "name": func.name or f"sub_{func_addr:x}",
                "size": func.size,
                "block_addrs": [b.addr for b in func.blocks],
                "callees": callees,
            }
        )

    return {"blocks": blocks, "functions": functions}


def _op_selftest(binary_path: str, mode: str = "echo", sentinel_path: str = "", **kwargs) -> Any:
    """Internal hook used only by ``tests/test_angr_subprocess.py``.

    It exercises the subprocess *machinery* (happy path, child error, and the
    timeout group-kill) without importing angr, so those tests stay fast and
    deterministic. ``mode``:

    * ``"echo"``  -- return ``kwargs`` (round-trips the pickle handoff);
    * ``"raise"`` -- raise, to prove the child-error path surfaces cleanly;
    * ``"sleep"`` -- spawn a grandchild in this child's new session, record both
      PIDs to ``sentinel_path``, then block forever, so the parent's timeout path
      must group-kill to reap the descendant.
    """
    if mode == "echo":
        return dict(kwargs)
    if mode == "raise":
        raise RuntimeError("selftest raise")
    if mode == "sleep":
        grandchild = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"])
        with open(sentinel_path, "w") as fh:
            fh.write(f"{os.getpid()} {grandchild.pid}")
            fh.flush()
            os.fsync(fh.fileno())
        time.sleep(600)
    raise AngrSubprocessError(f"unknown selftest mode: {mode!r}")


#: Registry of ops the child can dispatch. Commits 2-3 of S4b-i add
#: ``static_functions``, ``dataflow``, ``strings_xrefs`` and ``decompile``.
_OPS: Dict[str, Callable[..., Any]] = {
    "cfg": _op_cfg,
    "_selftest": _op_selftest,
}


def _write_payload(out_path: str, payload) -> None:
    try:
        with open(out_path, "wb") as fh:
            pickle.dump(payload, fh)
            fh.flush()
            os.fsync(fh.fileno())
    except Exception:
        pass


def _angr_child(binary_path: str, op: str, op_kwargs: Dict[str, Any], out_path: str) -> None:
    """Child entry point: own session, run the op, write a tagged result, exit."""
    try:
        os.setsid()  # become group leader so the parent can group-kill the tree
    except OSError:
        pass

    import logging

    for name in ("angr", "cle", "pyvex", "claripy"):
        logging.getLogger(name).setLevel(logging.CRITICAL)

    try:
        builder = _OPS.get(op)
        if builder is None:
            raise AngrSubprocessError(f"unknown angr op: {op!r}")
        data = builder(binary_path, **op_kwargs)
        _write_payload(out_path, ("ok", data))
        os._exit(0)
    except BaseException as exc:  # noqa: BLE001 - must report any failure, incl. angr's
        _write_payload(out_path, ("error", f"{type(exc).__name__}: {exc}"))
        os._exit(1)


# ---------------------------------------------------------------------------
# Parent side
# ---------------------------------------------------------------------------

def _validate_seconds(seconds) -> float:
    try:
        value = float(seconds)
    except (TypeError, ValueError):
        raise ValueError(f"angr timeout must be a number, got {seconds!r}")
    if not math.isfinite(value) or value <= 0:
        raise ValueError(f"angr timeout must be finite and > 0, got {value!r}")
    return value


def _kill_tree(proc: "multiprocessing.process.BaseProcess") -> None:
    """Kill the child and any descendants in its session, safely.

    Only group-kills once the child has established its *own* process group
    (``pgid == pid``, which only the child's ``setsid`` can produce). Before that
    the child still shares the parent's group, so group-killing would signal the
    parent too; in that window we kill just the child PID (it has spawned nothing
    yet, since ``setsid`` is the child's first action).
    """
    pid = proc.pid
    if pid is None:
        return

    group_killed = False
    try:
        child_pgid = os.getpgid(pid)
        if child_pgid == pid:  # child is its own group leader -> safe to group-kill
            os.killpg(child_pgid, signal.SIGKILL)
            group_killed = True
    except OSError:
        pass

    if not group_killed:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass

    proc.join(_REAP_GRACE)
    if proc.is_alive():
        try:
            proc.kill()
        except Exception:
            pass
        proc.join()


def run_angr_op(binary_path: str, op: str, seconds=DEFAULT_ANGR_TIMEOUT, **op_kwargs) -> Any:
    """Run one angr ``op`` on ``binary_path`` under a wall-clock budget.

    Returns the op's plain-data result. Raises :class:`AnalysisBudgetExceeded`
    if the budget elapses (the child is killed), or :class:`AngrSubprocessError`
    if the child reports/encounters an error or produces no result.
    """
    seconds = _validate_seconds(seconds)
    ctx = multiprocessing.get_context("spawn")

    # mkstemp creates the file 0600 and O_EXCL; close the parent fd before spawn
    # (the child reopens by path) and unlink in finally on every exit path.
    fd, out_path = tempfile.mkstemp(prefix="supwngo-angr-", suffix=".pkl")
    os.close(fd)

    proc = ctx.Process(target=_angr_child, args=(binary_path, op, dict(op_kwargs), out_path))
    try:
        proc.start()
        proc.join(seconds)

        if proc.is_alive():
            _kill_tree(proc)
            raise AnalysisBudgetExceeded(
                f"angr op {op!r} exceeded {seconds:g}s on {binary_path}"
            )

        payload = _read_payload(out_path)
        if payload is None:
            raise AngrSubprocessError(
                f"angr op {op!r} produced no result (child exit code {proc.exitcode})"
            )
        status, data = payload
        if status == "ok":
            return data
        raise AngrSubprocessError(f"angr op {op!r} failed in child: {data}")
    finally:
        if proc.is_alive():
            _kill_tree(proc)
        try:
            os.unlink(out_path)
        except OSError:
            pass


def _read_payload(out_path: str):
    try:
        with open(out_path, "rb") as fh:
            return pickle.load(fh)
    except Exception:
        return None
