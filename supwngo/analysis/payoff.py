"""Payoff ("win function") ranker — directive W, phase W-1.

Identifies the payoff/win function of a binary from *static evidence* rather than
from hardcoded names, and returns a ranked candidate list whose top entry is the
payoff. See ``docs/plans/2026-11-13-w1-payoff-ranker-design.md`` (Rev 3).

Built up across the W-1 commits (plan §7):

* **Commit 1** — the address-normalization primitive ``to_corpus_rva``.
* **Commit 2** — the backend-independent evidence model: the ``PayoffStatus`` /
  evidence / candidate dataclasses, the scorer (fixed-target sink + disqualifiers +
  reachability, per refinements R1–R3), the ``COMPLETE``-invariant predicate, and
  the pure import/name canonicalizers. No backend is invoked here; a backend
  (Ghidra in commit 4, angr in commit 8) produces :class:`FunctionEvidence` records
  that this module scores and ranks.

Why ``to_corpus_rva`` exists: ``Decompiler._to_file_address`` returns
``file_base + (address - backend_base)`` — the *link-time VADDR*, which for a
non-PIE ELF or a PE differs from the corpus truth ``payoff_rva = address -
image_base`` (``benchmark/gen/payoff/generate.py``) by ``image_base``.
"""

from __future__ import annotations

import enum
import json
import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Sequence, Tuple

__all__ = [
    "to_corpus_rva",
    "PayoffStatus",
    "TargetTrace",
    "SinkObservation",
    "FunctionEvidence",
    "PayoffEvidence",
    "PayoffCandidate",
    "PayoffReport",
    "CompletionMarker",
    "EXEC_FAMILY",
    "FILE_OPEN_FAMILY",
    "READ_FAMILY",
    "ATOM_EXEC_CONST",
    "ATOM_FILE_FIXED",
    "ATOM_TARGET_IS_PARAM",
    "ATOM_NO_SINK",
    "ATOM_UNREFERENCED",
    "SCRIPT_VERSION",
    "CACHE_ENVELOPE_VERSION",
    "canonical_import",
    "display_name",
    "score_function",
    "rank_candidates",
    "marker_is_complete",
    "report_to_json",
    "report_from_json",
    "ghidra_version",
    "angr_version",
    "backend_version",
]


# --------------------------------------------------------------------------- #
# Commit 1 — address normalization
# --------------------------------------------------------------------------- #
def to_corpus_rva(backend_addr: int, backend_base: int) -> int:
    """Map a backend-reported address to the corpus-truth RVA convention.

    ``rva = backend_addr - backend_base`` — equivalently
    ``Decompiler._to_file_address(addr, backend_base, file_base) - file_base``.

    ``backend_base`` is the backend's own image base (Ghidra's reported image base
    or angr's ``mapped_base``); for a non-relocated static load it equals the
    file's ``image_base`` (ELF lowest ``PT_LOAD`` vaddr / PE ``ImageBase``), so the
    result equals the truth ``payoff_rva``. No architecture constant is assumed.

    Raises :class:`TypeError` for non-int inputs (``bool`` rejected) and
    :class:`ValueError` for implausible bases (negative, or an address below the
    image base). Callers turn these into an ``ERROR``/``DEGRADED`` report rather
    than silently dropping a found payoff — a normalization failure must never
    masquerade as a legitimate empty (negative) result.
    """
    for name, value in (("backend_addr", backend_addr), ("backend_base", backend_base)):
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if backend_addr < 0 or backend_base < 0:
        raise ValueError(
            f"addresses must be non-negative "
            f"(addr=0x{backend_addr:x}, base=0x{backend_base:x})"
        )
    rva = backend_addr - backend_base
    if rva < 0:
        raise ValueError(
            f"address 0x{backend_addr:x} is below image base 0x{backend_base:x}"
        )
    return rva


# --------------------------------------------------------------------------- #
# Commit 2 — evidence model
# --------------------------------------------------------------------------- #
class PayoffStatus(enum.Enum):
    """Outcome of a ranking pass. ``candidates`` is authoritative-empty (a true
    negative) *only* under :data:`COMPLETE`; every other status means the pass did
    not produce a trustworthy result and must never be cached as a negative."""

    COMPLETE = "complete"
    NO_BACKEND = "no_backend"
    DEGRADED = "degraded"
    TIMEOUT = "timeout"
    ERROR = "error"


# Sink API families (canonical names; see ``canonical_import``). The *path/command*
# argument of each is at a fixed position (refinement R1): arg0 for all of these
# except ``openat`` (arg1). The backend records the traced target of that specific
# argument, so position handling lives in the extractor, not here.
EXEC_FAMILY = frozenset(
    {
        "system",
        "execve",
        "execl",
        "execlp",
        "execle",
        "execv",
        "execvp",
        "execvpe",
        "popen",
    }
)
FILE_OPEN_FAMILY = frozenset({"open", "openat", "fopen"})
READ_FAMILY = frozenset({"read", "fread", "pread", "fgets", "fscanf"})

ATOM_EXEC_CONST = "EXEC_CONST"
ATOM_FILE_FIXED = "FILE_FIXED"
ATOM_TARGET_IS_PARAM = "TARGET_IS_PARAM"
ATOM_NO_SINK = "NO_SINK"
ATOM_UNREFERENCED = "UNREFERENCED"

_SYNTHETIC_NAME = re.compile(r"(?:FUN|SUB|LAB)_[0-9a-fA-F]+$")


@dataclass(frozen=True)
class TargetTrace:
    """Provenance of a sink's path/command argument (tri-state, fail-closed)."""

    kind: str  # "const_string" | "param" | "unknown"
    address: Optional[int] = None  # for const_string
    value: Optional[str] = None  # decoded string, when available

    CONST_STRING = "const_string"
    PARAM = "param"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class SinkObservation:
    """One sink call seen in a function: the canonical API and the traced target of
    its path/command argument."""

    api: str
    path_target: TargetTrace


@dataclass(frozen=True)
class FunctionEvidence:
    """Raw per-function facts a backend emits; the scorer's input. ``rva`` is
    already in the corpus-truth convention (the backend applies ``to_corpus_rva``)."""

    rva: int
    name: Optional[str]
    sinks: tuple[SinkObservation, ...] = ()
    has_read: bool = False
    has_stdout_output: bool = False
    unreferenced: bool = False


@dataclass(frozen=True)
class PayoffEvidence:
    """Scored evidence for one function."""

    atoms: tuple[str, ...]
    sink_api: Optional[str]
    target: Optional[TargetTrace]
    rank_key: tuple
    score: int


@dataclass(frozen=True)
class PayoffCandidate:
    rva: int
    name: Optional[str]
    evidence: PayoffEvidence


@dataclass(frozen=True)
class CompletionMarker:
    """The extractor's self-report of completeness. A pass is ``COMPLETE`` only
    when this is present, ``failed == 0`` and ``analyzed == enumerated``."""

    enumerated: int
    analyzed: int
    failed: int
    script_version: str = ""


def canonical_import(raw: str) -> str:
    """Normalize a backend callee name to a canonical import identity (R4/MAJOR 6):
    drop a ``@plt`` / ``@GLIBC_*`` version suffix, a PE ``__imp_`` prefix and a
    single leading underscore, and lowercase nothing (names are case-significant).
    Matching against the families is done on this canonical form so PLT/IAT/thunk
    spellings all resolve."""
    if not raw:
        return ""
    name = raw.split("@", 1)[0].strip()
    if name.startswith("__imp_"):
        name = name[len("__imp_") :]
    if name.startswith("_") and len(name) > 1:
        name = name[1:]
    return name


def display_name(raw: Optional[str]) -> Optional[str]:
    """Return a real symbol name, or ``None`` for a Ghidra synthetic label
    (``FUN_*``/``SUB_*``/``LAB_*``) — the ranker never consumes the recovered name,
    so a stripped function presents as ``None`` (MINOR 10)."""
    if not raw:
        return None
    if _SYNTHETIC_NAME.fullmatch(raw):
        return None
    return raw


def score_function(fe: FunctionEvidence) -> PayoffEvidence:
    """Derive atoms and a ranking key for one function.

    A function is **hypothesis-tier** iff it has ``EXEC_CONST`` or ``FILE_FIXED``.
    Fail-closed: a sink whose path argument is ``unknown`` yields *no* fixed atom;
    a param-targeted sink yields ``TARGET_IS_PARAM`` (and, alone, is not a
    candidate); a file sink needs the light-disclosure signals to be ``FILE_FIXED``.
    """
    atoms: list[str] = []
    sink_api: Optional[str] = None
    target: Optional[TargetTrace] = None
    has_exec_const = has_file_fixed = has_param = has_any_sink = False

    for s in fe.sinks:
        api = canonical_import(s.api)
        tk = s.path_target.kind
        if api in EXEC_FAMILY:
            has_any_sink = True
            if tk == TargetTrace.CONST_STRING:
                has_exec_const = True
                if sink_api is None:
                    sink_api, target = api, s.path_target
            elif tk == TargetTrace.PARAM:
                has_param = True
        elif api in FILE_OPEN_FAMILY:
            has_any_sink = True
            if tk == TargetTrace.CONST_STRING and fe.has_read and fe.has_stdout_output:
                has_file_fixed = True
                if sink_api is None:
                    sink_api, target = api, s.path_target
            elif tk == TargetTrace.PARAM:
                has_param = True

    hypothesis = has_exec_const or has_file_fixed
    if has_exec_const:
        atoms.append(ATOM_EXEC_CONST)
    if has_file_fixed:
        atoms.append(ATOM_FILE_FIXED)
    if has_param:
        atoms.append(ATOM_TARGET_IS_PARAM)
    if not has_any_sink:
        atoms.append(ATOM_NO_SINK)
    if fe.unreferenced:
        atoms.append(ATOM_UNREFERENCED)

    has_sink = 1 if hypothesis else 0
    is_unref = 1 if fe.unreferenced else 0
    rank_key = (has_sink, is_unref)
    # Monotone with rank_key; weights documented. Only hypothesis-tier functions
    # become candidates, so the sink term dominates.
    score = 100 * has_sink + 10 * is_unref
    return PayoffEvidence(
        atoms=tuple(atoms),
        sink_api=sink_api,
        target=target,
        rank_key=rank_key,
        score=score,
    )


def rank_candidates(fes: Sequence[FunctionEvidence]) -> tuple[PayoffCandidate, ...]:
    """Score every function and return the hypothesis-tier candidates, ranked.

    Order: higher ``rank_key`` first (sink, then unreferenced), ties broken by
    ascending RVA (deterministic). On a corpus positive exactly one function is
    hypothesis-tier (the payoff); decoys/fillers/negatives yield none."""
    cands: list[PayoffCandidate] = []
    for fe in fes:
        ev = score_function(fe)
        if ATOM_EXEC_CONST in ev.atoms or ATOM_FILE_FIXED in ev.atoms:
            cands.append(
                PayoffCandidate(rva=fe.rva, name=display_name(fe.name), evidence=ev)
            )
    cands.sort(key=lambda c: (-c.evidence.rank_key[0], -c.evidence.rank_key[1], c.rva))
    return tuple(cands)


def marker_is_complete(marker: Optional[CompletionMarker]) -> bool:
    """The ``COMPLETE`` invariant (round-2 BLOCKER 1): a valid marker with no
    failed functions and every enumerated function analyzed. An empty candidate
    list is a legitimate negative only when this holds."""
    if marker is None:
        return False
    if not all(
        isinstance(v, int) and not isinstance(v, bool)
        for v in (marker.enumerated, marker.analyzed, marker.failed)
    ):
        return False
    if marker.enumerated < 0 or marker.analyzed < 0 or marker.failed < 0:
        return False
    return marker.failed == 0 and marker.analyzed == marker.enumerated


# --------------------------------------------------------------------------- #
# Commit 3 — report, cache serialization, process-free version discovery
# --------------------------------------------------------------------------- #

# Bump SCRIPT_VERSION when the Ghidra extractor's output contract changes; bump
# CACHE_ENVELOPE_VERSION when this serialization changes. Either invalidates cache
# entries (the former via the key, the latter via from_json returning None).
SCRIPT_VERSION = "w1.1"
CACHE_ENVELOPE_VERSION = 1


@dataclass(frozen=True)
class PayoffReport:
    """Result of a ranking pass. ``candidates`` is authoritative-empty (a true
    negative) only when ``status is PayoffStatus.COMPLETE``."""

    status: PayoffStatus
    candidates: Tuple[PayoffCandidate, ...]
    backend: str
    attempts: Tuple[Dict[str, Any], ...] = ()
    counts: Dict[str, int] = None  # type: ignore[assignment]
    elapsed_s: float = 0.0
    budget_s: float = 0.0
    from_cache: bool = False


def report_to_json(report: PayoffReport) -> str:
    """Serialize a report to the versioned cache envelope string.

    ``from_cache`` is not persisted (it is set True on read). The version key
    ``(sha256, script_version, backend_version)`` lives in the DB columns, not the
    envelope."""
    body = {
        "status": report.status.value,
        "backend": report.backend,
        "attempts": list(report.attempts),
        "counts": dict(report.counts or {}),
        "elapsed_s": report.elapsed_s,
        "budget_s": report.budget_s,
        "candidates": [
            {
                "rva": c.rva,
                "name": c.name,
                "evidence": {
                    "atoms": list(c.evidence.atoms),
                    "sink_api": c.evidence.sink_api,
                    "target": (
                        None
                        if c.evidence.target is None
                        else {
                            "kind": c.evidence.target.kind,
                            "address": c.evidence.target.address,
                            "value": c.evidence.target.value,
                        }
                    ),
                    "rank_key": list(c.evidence.rank_key),
                    "score": c.evidence.score,
                },
            }
            for c in report.candidates
        ],
    }
    return json.dumps({"envelope_version": CACHE_ENVELOPE_VERSION, "report": body})


def report_from_json(text: Optional[str]) -> Optional[PayoffReport]:
    """Deserialize a cache envelope, or return ``None`` for anything malformed,
    stale or the wrong envelope version — a bad row is a miss, never trusted."""
    if not text:
        return None
    try:
        env = json.loads(text)
    except (TypeError, ValueError):
        return None
    if (
        not isinstance(env, dict)
        or env.get("envelope_version") != CACHE_ENVELOPE_VERSION
    ):
        return None
    body = env.get("report")
    if not isinstance(body, dict):
        return None
    try:
        status = PayoffStatus(body["status"])
        candidates = []
        for c in body["candidates"]:
            ct = c["evidence"]["target"]
            target = (
                None
                if ct is None
                else TargetTrace(ct["kind"], ct.get("address"), ct.get("value"))
            )
            evidence = PayoffEvidence(
                atoms=tuple(c["evidence"]["atoms"]),
                sink_api=c["evidence"]["sink_api"],
                target=target,
                rank_key=tuple(c["evidence"]["rank_key"]),
                score=c["evidence"]["score"],
            )
            candidates.append(
                PayoffCandidate(rva=c["rva"], name=c["name"], evidence=evidence)
            )
        return PayoffReport(
            status=status,
            candidates=tuple(candidates),
            backend=body["backend"],
            attempts=tuple(body.get("attempts", ())),
            counts=dict(body.get("counts", {})),
            elapsed_s=body["elapsed_s"],
            budget_s=body["budget_s"],
            from_cache=True,
        )
    except (KeyError, TypeError, ValueError):
        return None


def _ghidra_roots() -> list:
    """Candidate Ghidra install roots, from env and the ``analyzeHeadless`` path —
    no process is launched."""
    roots = []
    for var in ("GHIDRA_HOME", "GHIDRA_INSTALL_DIR"):
        val = os.environ.get(var)
        if val:
            roots.append(Path(val))
    for exe in (shutil.which("analyzeHeadless"), "/opt/ghidra/support/analyzeHeadless"):
        if exe and os.path.exists(exe):
            roots.append(Path(os.path.realpath(exe)).parent.parent)
    return roots


def ghidra_version() -> str:
    """Read Ghidra's ``application.version`` from ``application.properties`` without
    launching Ghidra (round-2 MAJOR 6 — launching it would break the Ghidra-spawn
    counts). Returns ``"unknown"`` if it cannot be found."""
    for root in _ghidra_roots():
        for props in (
            root / "Ghidra" / "application.properties",
            root / "application.properties",
        ):
            try:
                for line in props.read_text(encoding="utf-8").splitlines():
                    if line.startswith("application.version="):
                        return line.split("=", 1)[1].strip()
            except OSError:
                continue
    return "unknown"


def angr_version() -> str:
    """angr's version via in-process metadata (no subprocess)."""
    try:
        from importlib import metadata

        return metadata.version("angr")
    except Exception:
        return "unknown"


def backend_version(backend: str) -> str:
    """Process-free backend version for the cache key."""
    if backend == "ghidra":
        return ghidra_version()
    if backend == "angr":
        return angr_version()
    return "unknown"
