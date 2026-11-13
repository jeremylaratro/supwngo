"""Pure scoring for the passcard (SP-01 plan sections 2.1, 2.2 and 3.6).

Everything here is a function of already-captured data: no files, no processes,
no clock. The harness (``passcard.py``) runs each command, records a ``Run``, and
hands runs plus a truth document to ``score_target``.

Field-name assumptions (the real keys, read from ``supwngo/cli.py`` at the SP-01a
merge base; the commands were not run end to end here, SP-01b does that):

* ``pwn --json``: ``recommended`` (null, or an object with ``approach``) and
  ``strategies`` (a list of objects with ``approach``, ``confidence``,
  ``priority``). ``approach`` is an ``ExploitApproach`` member name.
* ``template --json``: ``technique`` (the resolved template name), ``output``,
  ``script_length``.
* ``decompile --json``: ``function``, ``address`` (a hex string), ``calls``
  (truncated to 20), ``code``, ``selected_by`` (absent until SP-01b). Failure is
  ``{"error": ...}`` with no ``code``.
* ``offset --json``: ``offset``, ``success``, ``error``, ``canary_offset``,
  ``method``, plus ``kind`` and ``error_code`` once SP-01b adds them.

A run that did not end in state ``EXITED`` never yields a document: the harness
killed it, so its output is not trusted. A decline is a failure envelope judged
by content alone (``is_decline``); ROBUST alone judges the exit code.
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

_HERE = str(Path(__file__).resolve().parent)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from passcard_families import METHOD, UNSCORED, VULN, map_name  # noqa: E402

PASS, FAIL, ABSTAIN, ERROR, VOID = "PASS", "FAIL", "ABSTAIN", "ERROR", "VOID"
VERDICTS = (PASS, FAIL, ABSTAIN, ERROR, VOID)

COMMANDS = ("pwn", "template", "decompile", "offset")
VERDICT_METRICS = ("METHOD-R0", "METHOD-L", "TEMPLATE", "OFF", "DECOMP", "ROBUST")

EXITED = "EXITED"
SUCCESS_RC, FAILURE_RC = 0, 2
TOP_K = 3
TRACEBACK = "Traceback (most recent call last)"

# The keys that make a pwn/template document "the command's document".
REQUIRED_KEYS = {"pwn": ("recommended", "strategies"), "template": ("technique",)}

# OFF kinds that have a field in ``offset --json`` today; others wait for SP-04.
OFF_KINDS = ("buf_to_ret", "buf_to_canary")
TRUTH_STATES = ("known_value", "unknown", "not_applicable", "known_absent")

_SENTINEL = re.compile(r"\s*//\s*Decompilation failed")


@dataclass
class Run:
    """One command execution, as the harness records it."""

    state: str = EXITED  # EXITED | SIGNALED | TIMEOUT | SPAWN_ERROR
    rc: Optional[int] = 0
    stdout: str = ""
    stderr: str = ""
    survivors: int = 0
    wall_s: float = 0.0
    load1: Optional[float] = None


@dataclass
class Parsed:
    """The single document of a run, or ``None`` with the reasons there is none."""

    doc: Optional[Dict[str, Any]]
    problems: Tuple[str, ...] = ()


@dataclass
class Cell:
    """One verdict. ``kind`` is the OFF kind; ``command`` is set for ROBUST."""

    metric: str
    verdict: str
    target: str = ""
    kind: Optional[str] = None
    command: Optional[str] = None
    reason: str = ""
    warnings: Tuple[str, ...] = ()
    info: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TargetScore:
    """Every verdict and informational column for one target."""

    target: str
    cells: List[Cell]
    precision: Optional[float]
    spam: Optional[int]
    vuln: Optional[str]
    off_unscored_numbers: int
    time: Dict[str, Dict[str, Any]]


# --- parsing and envelopes ---------------------------------------------------


def _documents(text: str) -> Tuple[List[Any], bool]:
    """Split ``text`` into JSON documents; the flag is True on trailing garbage."""
    decoder, docs, pos = json.JSONDecoder(), [], 0
    while True:
        while pos < len(text) and text[pos].isspace():
            pos += 1
        if pos >= len(text):
            return docs, False
        try:
            doc, pos = decoder.raw_decode(text, pos)
        except ValueError:
            return docs, True
        docs.append(doc)


def parse_run(run: Run) -> Parsed:
    """Extract the one JSON object a command must print, or say why there is none."""
    problems: List[str] = []
    if run.state != EXITED:
        problems.append(run.state.lower())
    if TRACEBACK in run.stderr or TRACEBACK in run.stdout:
        problems.append("traceback")
    docs, garbage = _documents(run.stdout)
    if garbage:
        problems.append("non_json_output")
    if len(docs) > 1:
        problems.append("multiple_documents")
    elif not docs and not garbage:
        problems.append("no_document")
    doc = None
    if len(docs) == 1 and not garbage and run.state == EXITED:
        if isinstance(docs[0], dict):
            doc = docs[0]
        else:
            problems.append("not_an_object")
    return Parsed(doc, tuple(problems))


def _blank(value: Any) -> bool:
    return value is None or value == ""


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def is_decline(command: str, doc: Mapping[str, Any]) -> bool:
    """A failure envelope judged by content alone (the exit code is ignored)."""
    if command == "offset":
        return doc.get("success") is False
    return not _blank(doc.get("error")) and not _text(doc.get("code"))


def envelope_kind(command: str, doc: Mapping[str, Any]) -> Optional[str]:
    """Classify ``doc`` as the command's ``success`` or ``failure`` envelope."""
    error = doc.get("error")
    if command == "offset":
        if doc.get("success") is True and _blank(error):
            return "success" if _blank(doc.get("error_code")) else None
        if doc.get("success") is False and not _blank(doc.get("error_code")):
            return "failure"
        return None
    if command == "decompile":
        if _text(doc.get("code")) and _blank(error):
            return "success"
        if not _blank(error) and not _text(doc.get("code")):
            return "failure"
        return None
    if _blank(error) and all(key in doc for key in REQUIRED_KEYS[command]):
        return "success"
    return None if _blank(error) else "failure"


def _error_cell(metric: str, parsed: Parsed, **keys: Any) -> Cell:
    return Cell(
        metric, ERROR, reason=",".join(parsed.problems) or "no_document", **keys
    )


# --- method metrics ----------------------------------------------------------


def _resolve(name: Any) -> Tuple[Tuple[str, str], Optional[str]]:
    """Return ``(token, warning)``; the token is the family used for deduping."""
    mapping = map_name(name)
    if mapping is None:
        return ("unmapped", str(name).strip().lower()), f"unmapped:{name}"
    if mapping[0] == UNSCORED:
        return (UNSCORED, str(name).strip().lower()), None
    return mapping, None


def _judge_name(metric: str, name: Any, accept: Sequence[str]) -> Cell:
    """Score one tool-named method (shared by METHOD-R0 and TEMPLATE)."""
    if name is None:
        return Cell(metric, FAIL, reason="no_name")
    mapping = map_name(name)
    if mapping is None:
        return Cell(metric, FAIL, reason="unmapped", warnings=(f"unmapped:{name}",))
    axis, family = mapping
    if axis == METHOD:
        verdict = PASS if family in accept else FAIL
        return Cell(metric, verdict, reason=f"method:{family}")
    if axis == VULN:
        return Cell(metric, FAIL, reason=f"vuln_axis:{family}", info={"vuln": family})
    return Cell(metric, FAIL, reason=f"unscored:{family}")


def score_method_r0(parsed: Parsed, accept: Sequence[str]) -> Cell:
    """METHOD-R0: does the single recommendation map to an accepted family."""
    if parsed.doc is None:
        return _error_cell("METHOD-R0", parsed)
    if is_decline("pwn", parsed.doc):
        return Cell("METHOD-R0", ABSTAIN, reason="decline")
    recommended = parsed.doc.get("recommended")
    name = recommended.get("approach") if isinstance(recommended, dict) else None
    if name is None:
        return Cell("METHOD-R0", FAIL, reason="no_recommendation")
    return _judge_name("METHOD-R0", name, accept)


def _number(value: Any, default: float) -> float:
    ok = isinstance(value, (int, float)) and not isinstance(value, bool)
    return float(value) if ok else default


def ranked_names(doc: Mapping[str, Any]) -> List[Any]:
    """Listed approach names ordered by ``(-confidence, priority)``, then position."""
    items = doc.get("strategies")
    keyed = []
    for position, item in enumerate(items if isinstance(items, list) else []):
        entry = item if isinstance(item, dict) else {}
        keyed.append(
            (
                -_number(entry.get("confidence"), 0.0),
                _number(entry.get("priority"), float("inf")),
                position,
                entry.get("approach"),
            )
        )
    return [key[3] for key in sorted(keyed)]


def score_method_l(parsed: Parsed, accept: Sequence[str]) -> Cell:
    """METHOD-L: an accepted family among the top three ranked strategies."""
    if parsed.doc is None:
        return _error_cell("METHOD-L", parsed)
    if is_decline("pwn", parsed.doc):
        return Cell("METHOD-L", ABSTAIN, reason="decline")
    names = ranked_names(parsed.doc)
    warnings = tuple(dict.fromkeys(w for _, w in map(_resolve, names) if w))
    if not names:
        return Cell("METHOD-L", FAIL, reason="empty_list")
    top = [_resolve(name)[0] for name in names[:TOP_K]]
    hit = any(axis == METHOD and family in accept for axis, family in top)
    return Cell(
        "METHOD-L",
        PASS if hit else FAIL,
        reason="top3:" + ",".join(f"{a}:{f}" for a, f in top),
        warnings=warnings,
    )


def _listed_tokens(parsed: Parsed) -> Optional[List[Tuple[str, str]]]:
    """Deduplicated families of the whole list; ``None`` for no list at all."""
    if parsed.doc is None or is_decline("pwn", parsed.doc):
        return None
    return list(dict.fromkeys(_resolve(n)[0] for n in ranked_names(parsed.doc)))


def method_l_precision(parsed: Parsed, accept: Sequence[str]) -> Optional[float]:
    """|families(listed) & accept| / |families(listed)|; ``None`` when undefined."""
    tokens = _listed_tokens(parsed)
    if not tokens:
        return None
    hits = sum(1 for axis, family in tokens if axis == METHOD and family in accept)
    return hits / len(tokens)


def method_spam(parsed: Parsed) -> Optional[int]:
    """Number of distinct listed families; ``None`` for an error or a decline."""
    tokens = _listed_tokens(parsed)
    return None if tokens is None else len(tokens)


def score_template(parsed: Parsed, accept: Sequence[str]) -> Cell:
    """TEMPLATE: the emitted technique maps to an accepted family."""
    if parsed.doc is None:
        return _error_cell("TEMPLATE", parsed)
    if is_decline("template", parsed.doc):
        return Cell("TEMPLATE", ABSTAIN, reason="decline")
    return _judge_name("TEMPLATE", parsed.doc.get("technique"), accept)


# --- OFF ---------------------------------------------------------------------


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def off_value(doc: Mapping[str, Any], kind: str) -> Any:
    """The tool's value for ``kind`` under the 2.1 field mapping, else ``None``."""
    if kind == "buf_to_ret":
        if doc.get("success") is not True:
            return None
        # A missing ``kind`` is pre-fix output, which claims a return-address offset.
        if doc.get("kind") not in (None, "buf_to_ret"):
            return None
        return doc.get("offset")
    if kind == "buf_to_canary":
        return doc.get("canary_offset")
    return None


def score_off(
    parsed: Parsed, entry: Mapping[str, Any], preflight_void: Optional[str] = None
) -> Optional[Cell]:
    """OFF for one truth ``distance`` entry; ``None`` when it is not a cell.

    VOID is decided from the truth state and the preflight alone, before the
    output is read, and a failed preflight wins over ``no-truth``.
    """
    state, kind = entry["state"], entry["kind"]
    if state not in TRUTH_STATES:
        raise ValueError(f"unknown truth state {state!r} for kind {kind!r}")
    if state in ("not_applicable", "known_absent"):
        return None
    if preflight_void:
        return Cell("OFF", VOID, kind=kind, reason=preflight_void)
    if state == "unknown":
        return Cell("OFF", VOID, kind=kind, reason="no-truth")
    if parsed.doc is None:
        return _error_cell("OFF", parsed, kind=kind)
    if is_decline("offset", parsed.doc):
        return Cell("OFF", ABSTAIN, kind=kind, reason="decline")
    value = off_value(parsed.doc, kind)
    if value is None:
        return Cell("OFF", ABSTAIN, kind=kind, reason="no_value")
    if not _is_int(value):
        return Cell("OFF", FAIL, kind=kind, reason="non_integer", info={"tool": value})
    verdict = PASS if value == entry["value"] else FAIL
    return Cell(
        "OFF", verdict, kind=kind, info={"tool": value, "truth": entry["value"]}
    )


def off_unscored_number(parsed: Parsed, kind: str) -> int:
    """1 when the tool printed a saved-RIP number for a kind that has no field."""
    if parsed.doc is None or kind in OFF_KINDS:
        return 0
    return 1 if _is_int(off_value(parsed.doc, "buf_to_ret")) else 0


# --- DECOMP ------------------------------------------------------------------


def strip_comments(code: str) -> str:
    """Remove C comments, leaving string and character literals untouched."""
    out: List[str] = []
    i, n = 0, len(code)
    while i < n:
        char, pair = code[i], code[i : i + 2]
        if char in "\"'":
            j = i + 1
            while j < n and code[j] != char:
                j += 2 if code[j] == "\\" else 1
            out.append(code[i : j + 1])
            i = j + 1
        elif pair == "//":
            end = code.find("\n", i)
            i = n if end < 0 else end
            out.append(" ")
        elif pair == "/*":
            end = code.find("*/", i + 2)
            i = n if end < 0 else end + 2
            out.append(" ")
        else:
            out.append(char)
            i += 1
    return "".join(out)


def _address(value: Any) -> Optional[int]:
    if _is_int(value):
        return value
    try:
        return int(value, 0) if isinstance(value, str) else None
    except ValueError:
        return None


def score_decomp(
    parsed: Parsed, truth: Mapping[str, Any], require_selected_by: bool = False
) -> Cell:
    """DECOMP: right address, real code, and every anchor call present."""
    if parsed.doc is None:
        return _error_cell("DECOMP", parsed)
    doc = parsed.doc
    if is_decline("decompile", doc):
        return Cell("DECOMP", ABSTAIN, reason="decline")
    problems: List[str] = []
    allowed = {_address(a) for a in truth["default_function_any_of"]}
    if _address(doc.get("address")) not in allowed:
        problems.append("address")
    code = doc.get("code") if isinstance(doc.get("code"), str) else ""
    body = strip_comments(code).strip()
    if not body or _SENTINEL.match(code):
        problems.append("empty_or_sentinel")
    anchors = truth["anchors"]
    missing = [
        name
        for name in anchors["calls"]
        if not re.search(rf"(?<![A-Za-z0-9_]){re.escape(name)}\s*\(", body)
    ]
    if missing:
        problems.append("anchors_missing:" + ",".join(missing))
    if len(anchors["calls"]) - len(missing) < anchors["min_calls"]:
        problems.append("min_calls")
    if require_selected_by and not doc.get("selected_by"):
        problems.append("selected_by")
    return Cell(
        "DECOMP",
        FAIL if problems else PASS,
        reason=";".join(problems),
        info={"selected_by": doc.get("selected_by"), "address": doc.get("address")},
    )


# --- ROBUST and TIME ---------------------------------------------------------


def score_robust(command: str, run: Run, parsed: Parsed) -> Cell:
    """ROBUST: one document, no traceback, no timeout, no survivor, a legal pair."""
    problems = list(parsed.problems)
    if run.survivors:
        problems.append(f"survivors:{run.survivors}")
    if parsed.doc is not None:
        kind = envelope_kind(command, parsed.doc)
        legal = (run.rc == SUCCESS_RC and kind == "success") or (
            run.rc == FAILURE_RC and kind == "failure"
        )
        if not legal:
            problems.append(f"rc_envelope:{run.rc}/{kind or 'unrecognised'}")
    return Cell(
        "ROBUST",
        FAIL if problems else PASS,
        command=command,
        reason=";".join(problems),
    )


def time_sample(run: Run, load_max: float) -> Dict[str, Any]:
    """TIME for one cell: wall seconds, 1-minute load, and whether it is valid."""
    quiet = run.load1 is not None and run.load1 < load_max
    return {
        "wall_s": run.wall_s,
        "load1": run.load1,
        "valid": run.state == EXITED and quiet,
    }


def time_quorum_met(
    samples: Mapping[str, Sequence[Mapping[str, Any]]], quorum: int
) -> bool:
    """True when every command has at least ``quorum`` valid TIME samples."""
    return all(
        sum(1 for s in samples.get(command, ()) if s["valid"]) >= quorum
        for command in COMMANDS
    )


# --- per-target and aggregate ------------------------------------------------


def score_target(
    truth: Mapping[str, Any],
    runs: Mapping[str, Run],
    *,
    preflight_void: Optional[str] = None,
    load_max: float = float("inf"),
    require_selected_by: bool = False,
) -> TargetScore:
    """Score every metric for one target from its four command runs."""
    slug, accept = truth["slug"], truth["method_accept"]
    parsed = {command: parse_run(runs[command]) for command in COMMANDS}
    r0 = score_method_r0(parsed["pwn"], accept)
    cells = [
        r0,
        score_method_l(parsed["pwn"], accept),
        score_template(parsed["template"], accept),
        score_decomp(parsed["decompile"], truth["decompile"], require_selected_by),
    ]
    unscored = 0
    for entry in truth["distance"]:
        off = score_off(parsed["offset"], entry, preflight_void)
        if off is not None:
            cells.append(off)
            # Under a preflight VOID the target cannot execute; offset still runs
            # for ROBUST, but any number it prints says nothing about the target.
            if not preflight_void:
                unscored += off_unscored_number(parsed["offset"], entry["kind"])
    cells += [
        score_robust(command, runs[command], parsed[command]) for command in COMMANDS
    ]
    return TargetScore(
        target=slug,
        cells=[replace(cell, target=slug) for cell in cells],
        precision=method_l_precision(parsed["pwn"], accept),
        spam=method_spam(parsed["pwn"]),
        vuln=r0.info.get("vuln"),
        off_unscored_numbers=unscored,
        time={c: time_sample(runs[c], load_max) for c in COMMANDS},
    )


def _ratio(numerator: int, denominator: int) -> Optional[float]:
    return numerator / denominator if denominator else None


def summarize(cells: Sequence[Cell]) -> Dict[str, Any]:
    """Coverage, exact, selective and net over ALL cells; VOIDs listed."""
    counts = Counter(cell.verdict for cell in cells)
    passed, failed, errored = counts[PASS], counts[FAIL], counts[ERROR]
    total = len(cells)
    return {
        "n": total,
        "counts": {verdict: counts[verdict] for verdict in VERDICTS},
        "coverage": _ratio(passed + failed, total),
        "exact": _ratio(passed, total),
        "selective": _ratio(passed, passed + failed),
        "net": _ratio(passed - failed - errored, total),
        "voids": [
            {"target": c.target, "kind": c.kind, "reason": c.reason}
            for c in cells
            if c.verdict == VOID
        ],
    }


def aggregate(scores: Sequence[TargetScore]) -> Dict[str, Any]:
    """The report body: per-metric summaries and the informational columns."""
    cells = [cell for score in scores for cell in score.cells]
    defined = [s.precision for s in scores if s.precision is not None]
    return {
        "metrics": {
            metric: summarize([c for c in cells if c.metric == metric])
            for metric in VERDICT_METRICS
        },
        "method_l_precision": {
            "per_target": {s.target: s.precision for s in scores},
            "macro_mean": sum(defined) / len(defined) if defined else None,
            "n_defined": len(defined),
            "n_targets": len(scores),
        },
        "method_spam": {s.target: s.spam for s in scores},
        "vuln_column": {s.target: s.vuln for s in scores if s.vuln},
        "off_unscored_numbers": sum(s.off_unscored_numbers for s in scores),
        "warnings": [f"{c.target}/{c.metric}: {w}" for c in cells for w in c.warnings],
    }
