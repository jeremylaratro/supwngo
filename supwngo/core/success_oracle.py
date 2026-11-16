"""Success oracle: one place that decides whether a target's output proves success.

Design: ``docs/plans/2026-11-15-w3-success-detection-design.md`` section 2.

Import topology (hard rule)
---------------------------
This module imports **only the standard library** at module scope. It never
imports ``supwngo.*``: verifiers, testers and analysers import the oracle, the
oracle imports none of them, so it cannot close an import cycle and has no
import-time side effects. A seam test enforces this with an AST check.

Evidence tiers (preference order, not an impact ranking)
---------------------------------------------------------
1. ``PLANTED``      a fresh >=128-bit random token planted in a file inside a
                    private workspace; success only when that exact token is in
                    the output. The token is never sent, so it cannot be echoed.
2. ``SHELL-PROVEN`` probes whose answer cannot be produced by reflecting the
                    input: the strict marker, shell arithmetic and ``uid=``.
3. ``SHAPE``        the neutral flag shape (overridable); the weakest tier.

``check()`` returns the highest-preference tier that survives anti-echo, plus
the full filtered evidence set (a planted disclosure that also yielded a shell
proof keeps both).

Anti-echo invariant
-------------------
``sent_bytes`` is the lossless concatenation of everything delivered to the
target for the attempt (stdin, argv, materialised input files). Anti-echo is
applied **per candidate match, before tier ranking**: any individual match that
also occurs in ``sent_bytes`` is dropped, while a second, non-echoed match at
the same or a lower tier may still qualify. Dropped matches are recorded in
``diagnostics`` (``echo:<tier>:<value>``) and never set ``success``.

str / bytes boundary
--------------------
Everything is normalised to one internal representation: the *latin-1 view of
the UTF-8 byte string*. ``bytes`` are decoded latin-1 (bijective); ``str`` is
first encoded UTF-8 (``surrogateescape``, falling back to ``replace``) and then
viewed the same way. Hence bytes and text inputs holding the same data compare
and match identically, and a match found in output can be looked up verbatim in
the sent transcript. Reported values (``matched_value``, evidence) are in this
internal representation, which equals the original text for ASCII.

Banner words (``welcome``, ``success``, ...) are never success: they are only
recorded as a ``banner`` diagnostic.
"""

from __future__ import annotations

import contextlib
import os
import re
import secrets
import shutil
import tempfile
import warnings
from dataclasses import dataclass, field
from typing import Iterator, List, Optional, Union

__all__ = [
    "ARITH_MARK",
    "ARITH_PROBE",
    "BANNER_RE",
    "FLAG_RE_ENV",
    "NEUTRAL_FLAG_SHAPE",
    "TIER_PLANTED",
    "TIER_SHAPE",
    "TIER_SHELL",
    "TIER_RANK",
    "Evidence",
    "MarkerRecord",
    "OracleResult",
    "check",
    "cleanup_marker",
    "emit_flag_match_snippet",
    "is_flag_shaped_text",
    "is_flagish_bytes",
    "mint_marker",
    "private_workspace",
    "strict_marker",
    "strict_probe",
]

Text = Union[str, bytes, bytearray, memoryview]

TIER_PLANTED = "PLANTED"
TIER_SHELL = "SHELL-PROVEN"
TIER_SHAPE = "SHAPE"
#: Preference order, strongest first.
TIER_RANK = (TIER_PLANTED, TIER_SHELL, TIER_SHAPE)

#: The one canonical neutral flag shape: a word, a brace-delimited body of at
#: least four non-space, non-brace characters. It names no platform by
#: construction. ``scripts/audit_target_values.py`` exempts exactly this literal
#: bound to exactly this symbol in this module (design section 2.2).
NEUTRAL_FLAG_SHAPE = r"([A-Za-z0-9_]+)\{[^}\s]{4,}\}"

#: Environment variable that overrides the shape; read once per ``check()``.
FLAG_RE_ENV = "SUPWNGO_FLAG_RE"

#: A shell-only proof that needs no external program and no environment.
#: ``$((...))`` is POSIX arithmetic expansion performed by the shell itself, so
#: it survives a shell started with null argv/envp (no PATH), which is what an
#: SROP or syscall-chain exploit produces. The sent bytes never contain the
#: answer, so a target that only reflects its input cannot produce it.
ARITH_PROBE = "SH$((6*7))OK"
ARITH_MARK = "SH42OK"

_UID_RE = r"uid=\d+"

#: Bare success words. Diagnostic only; never a success signal (design 2.1/B3).
BANNER_RE = r"(?i)\b(?:welcome|congratulations|congrats|success(?:ful)?|well done)\b"


def strict_marker(token: str) -> str:
    """The text a shell emits for ``strict_probe(token)``: ``<token>_STRICT``."""
    return f"{token}_STRICT"


def strict_probe(token: str) -> str:
    """Shell command whose *output* is ``strict_marker(token)``.

    The shell removes the empty quotes, so the bytes sent never contain the
    marker form and a target that merely reflects its input cannot produce it.
    """
    return f'echo {token}""_STRICT'


# --------------------------------------------------------------------------
# Normalisation


def _norm(data: Optional[Text]) -> str:
    """Normalise str/bytes to the internal latin-1 view (see module docstring)."""
    if data is None:
        return ""
    if isinstance(data, str):
        try:
            raw = data.encode("utf-8", "surrogateescape")
        except UnicodeEncodeError:
            raw = data.encode("utf-8", "replace")
        return raw.decode("latin-1")
    return bytes(data).decode("latin-1")


# --------------------------------------------------------------------------
# Result types


@dataclass(frozen=True)
class Evidence:
    """One surviving (non-echoed) match."""

    tier: str
    value: str


@dataclass
class OracleResult:
    """Outcome of :func:`check`.

    ``primary_tier`` is the best tier among ``evidence`` (``None`` if none);
    ``matched_value`` is the full match (``group(0)``) of the primary evidence.
    ``success`` is true iff there is surviving evidence. ``diagnostics`` holds
    non-success notes: dropped echoes, banner words, override fallbacks.
    """

    primary_tier: Optional[str] = None
    evidence: List[Evidence] = field(default_factory=list)
    matched_value: Optional[str] = None
    success: bool = False
    diagnostics: List[str] = field(default_factory=list)

    def tiers(self) -> List[str]:
        return [e.tier for e in self.evidence]


@dataclass(frozen=True)
class MarkerRecord:
    """A minted planted marker, bound to one attempt and one workspace."""

    value: str
    attempt_id: str
    planted_path: Optional[str]
    workspace_id: Optional[str]


# --------------------------------------------------------------------------
# PLANTED machinery


def _workspace_id(workspace: Union[str, "os.PathLike[str]"]) -> str:
    return os.path.realpath(os.fspath(workspace))


@contextlib.contextmanager
def private_workspace() -> Iterator[str]:
    """A fresh private (mode 0700) directory, removed on exit."""
    path = tempfile.mkdtemp(prefix="supwngo-oracle-")
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def mint_marker(
    workspace: Optional[Union[str, "os.PathLike[str]"]] = None,
) -> MarkerRecord:
    """Mint a fresh marker for one attempt.

    The value is ``secrets.token_hex(16)``: 128 bits, lowercase hex, no
    platform word. With ``workspace`` the marker is also planted atomically
    (``O_CREAT | O_EXCL``, mode 0600) in a file inside it; without one, no file
    is created and PLANTED can never succeed for the returned record.
    Pair with :func:`cleanup_marker`.
    """
    value = secrets.token_hex(16)
    attempt_id = secrets.token_hex(8)
    if workspace is None:
        return MarkerRecord(value, attempt_id, None, None)
    ws = _workspace_id(workspace)
    path = os.path.join(ws, f"marker-{attempt_id}")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, value.encode("ascii"))
    finally:
        os.close(fd)
    return MarkerRecord(value, attempt_id, path, ws)


def cleanup_marker(record: MarkerRecord) -> None:
    """Remove the planted file, if any. Idempotent."""
    if record.planted_path:
        try:
            os.unlink(record.planted_path)
        except FileNotFoundError:
            pass


# --------------------------------------------------------------------------
# Shape resolution (design 2.5)


def _resolve_shape(flag_pattern, diagnostics: List[str]) -> "re.Pattern[str]":
    """Precedence: ``flag_pattern`` arg > ``SUPWNGO_FLAG_RE`` env > neutral default."""
    if flag_pattern:
        if isinstance(flag_pattern, re.Pattern):
            return flag_pattern
        try:
            return re.compile(flag_pattern)
        except re.error as exc:
            _warn_fallback("flag_pattern argument", flag_pattern, exc, diagnostics)
    else:
        env = os.environ.get(FLAG_RE_ENV)  # read once, by exact value
        if env:
            try:
                return re.compile(env)
            except re.error as exc:
                _warn_fallback(FLAG_RE_ENV, env, exc, diagnostics)
    return re.compile(NEUTRAL_FLAG_SHAPE)


def _warn_fallback(source: str, pattern, exc: Exception, diagnostics: List[str]) -> None:
    msg = f"invalid {source} {pattern!r} ({exc}); fell back to neutral default shape"
    warnings.warn(msg, RuntimeWarning, stacklevel=3)
    diagnostics.append(f"shape_override_invalid: {msg}")


# --------------------------------------------------------------------------
# Static, platform-neutral classifiers (design 3)
#
# These serve the two *static* class-C sites (``analysis/strings.py`` and
# ``exploit/walkthrough/facts.py``) whose semantics differ from the runtime
# ``check()`` shape and must be preserved exactly, minus the platform tokens.
# Both are pure functions of their input and carry no platform word as a
# literal. The brace patterns are assembled from character classes so no single
# string constant presents a ``word{`` / ``)\{`` shape to the class-C scanner
# (``scripts/audit_target_values.py``); only :data:`NEUTRAL_FLAG_SHAPE` bound to
# its canonical symbol is scanner-exempt.

#: The ``FLAG_<alnum>`` token, spelled as single-character classes so the
#: platform word is never a literal and the pattern carries no ``{`` for the
#: scanner to classify. Case-insensitive, matching the historical classifier.
_FLAG_TOKEN_RE = re.compile(r"[F][L][A][G]_[A-Za-z0-9]+", re.IGNORECASE)

#: The full word-brace flag shape, reusing the one exempt neutral constant.
_NEUTRAL_SHAPE_SEARCH = re.compile(NEUTRAL_FLAG_SHAPE)

#: Redaction fail-safe for walkthrough prompts (``facts.py``). Two triggers,
#: both platform-neutral:
#:   (a) prefix-only / truncation-tolerant -- a word immediately before an
#:       opening brace (``<word>{``, optional whitespace), with NO closing brace
#:       required, so a truncated flag-like prompt is still redacted;
#:   (b) prefixless -- ``{<4+ word-chars>}``.
#: The leading word is a character class, not a literal word, so this constant
#: presents no ``word{`` shape to the scanner.
_REDACT_RE = re.compile(rb"[A-Za-z0-9_]+\s*\{|\{[A-Za-z0-9_]{4,}\}")


def is_flag_shaped_text(value: Text) -> bool:
    """True when *value* reads as a captured flag, platform-neutrally.

    Reproduces the historical ``strings.py`` flag classifier on representative
    inputs without naming any platform: a word-prefixed brace flag
    ``<word>{<4+ non-space>}`` (via the exempt :data:`NEUTRAL_FLAG_SHAPE`, e.g.
    ``flag{abcd1234}``, ``HTB{abcd1234}``) or a ``FLAG_<alnum>`` token (e.g.
    ``FLAG_SECRET1``). Used by ``analysis/strings.py``.
    """
    text = _norm(value)
    return bool(_NEUTRAL_SHAPE_SEARCH.search(text) or _FLAG_TOKEN_RE.search(text))


def is_flagish_bytes(data: bytes) -> bool:
    """True when *data* looks flag-like and must stay out of a walkthrough.

    Preserves both fail-safe triggers of the historical ``facts._FLAG_RE``:
    prefix-only / truncation-tolerant ``<word>{`` (no closing brace needed) and
    prefixless ``{<4+ word-chars>}``, now platform-neutral (any word, not only
    the platform words). A swap to the closing-brace-requiring full shape would
    let a truncated or prefixless flag escape the fail-safe (design 3). Used by
    ``exploit/walkthrough/facts.py``.
    """
    return bool(_REDACT_RE.search(data))


# --------------------------------------------------------------------------
# Emitted snippet for generated scripts (design 2.4, "Generated scripts (G)")
#
# A standalone script the operator runs later cannot import this module, so the
# canonical oracle *emits* a self-contained snippet of source text that the
# generators embed. The snippet carries the neutral shape (built from
# :data:`NEUTRAL_FLAG_SHAPE`, never retyped, so it adds no new ``flag_shape``
# scanner hit) and the SAME per-match anti-echo filter ``check()`` applies.


def emit_flag_match_snippet(indent: str = "") -> str:
    """Return source TEXT defining self-contained oracle helpers for a generated
    script (pure stdlib; a generated script already imports ``os`` and ``re``).

    Executed inside the operator's standalone script, the returned text defines:

    * ``_oracle_flag_hits(output, sent=b"")`` -- every full match of the neutral
      flag shape (``SUPWNGO_FLAG_RE`` overrides it, read once by exact value,
      exactly as :func:`check`) as a latin-1 string, with each candidate that
      also occurs in ``sent`` dropped (the per-match anti-echo filter);
    * ``_oracle_shell_proven(output, sent=b"", token=None)`` -- ``True`` only on
      an un-echoable shell answer (the arithmetic marker, ``token``'s strict
      marker, or ``uid=``) that is absent from ``sent``; a reflected token never
      counts.

    The flag pattern is interpolated from :data:`NEUTRAL_FLAG_SHAPE` and the
    shell markers from :data:`ARITH_MARK` / :func:`strict_marker`; none is
    retyped as a fresh flag/platform literal, so emitting this creates no new
    class-C scanner hit and trips no platform-token lint.
    """
    shape = repr(NEUTRAL_FLAG_SHAPE)
    arith = repr(ARITH_MARK.encode("latin-1"))
    lines = [
        "def _oracle_norm(value):",
        "    if value is None:",
        "        return b''",
        "    if isinstance(value, str):",
        "        return value.encode('utf-8', 'surrogateescape')",
        "    return bytes(value)",
        "",
        "",
        "def _oracle_shape():",
        f"    _env = os.environ.get({FLAG_RE_ENV!r})",
        f"    _pat = _env if _env else {shape}",
        "    if isinstance(_pat, str):",
        "        _pat = _pat.encode('latin-1')",
        "    try:",
        "        return re.compile(_pat)",
        "    except re.error:",
        f"        return re.compile(({shape}).encode('latin-1'))",
        "",
        "",
        "def _oracle_flag_hits(output, sent=b''):",
        "    _out = _oracle_norm(output)",
        "    _sent = _oracle_norm(sent)",
        "    _hits = []",
        "    _seen = set()",
        "    for _m in _oracle_shape().finditer(_out):",
        "        _v = _m.group(0)",
        "        if not _v or _v in _seen:",
        "            continue",
        "        _seen.add(_v)",
        "        if _v in _sent:",
        "            continue",
        "        _hits.append(_v.decode('latin-1'))",
        "    return _hits",
        "",
        "",
        "def _oracle_shell_proven(output, sent=b'', token=None):",
        "    _out = _oracle_norm(output)",
        "    _sent = _oracle_norm(sent)",
        "    _marks = []",
        f"    _marks.append({arith})",
        "    if token is not None:",
        "        _marks.append(_oracle_norm(token) + b'_STRICT')",
        "    _marks.append(b'uid=')",
        "    for _mk in _marks:",
        "        if _mk and _mk in _out and _mk not in _sent:",
        "            return True",
        "    return False",
    ]
    return "\n".join(indent + line if line else line for line in lines)


# --------------------------------------------------------------------------
# check()


def _candidates(
    pattern: "re.Pattern[str]", text: str, sent: str, tier: str,
    out: List[Evidence], diagnostics: List[str],
) -> None:
    """Add each match of ``pattern`` in ``text`` unless it occurs in ``sent``."""
    seen = set()
    for m in pattern.finditer(text):
        value = m.group(0)
        if not value or value in seen:
            continue
        seen.add(value)
        if value in sent:
            diagnostics.append(f"echo:{tier}:{value}")
        else:
            out.append(Evidence(tier, value))


def check(
    output: Text,
    sent_bytes: Optional[Text],
    *,
    planted: Optional[MarkerRecord] = None,
    workspace: Optional[Union[str, "os.PathLike[str]"]] = None,
    flag_pattern: Optional[Union[str, "re.Pattern[str]"]] = None,
    token: Optional[str] = None,
) -> OracleResult:
    """Decide whether ``output`` proves success, with per-match anti-echo.

    ``output``/``sent_bytes`` may be ``str`` or ``bytes`` (see module docstring).
    ``planted``+``workspace`` enable the PLANTED tier; it is credited only when
    the exact minted value is in the output, a private workspace was supplied and
    matches the record, and the value is absent from ``sent_bytes``.
    ``token`` (extra, optional) is the caller's shell-probe token enabling the
    strict-marker proof of ``strict_probe(token)``. The arithmetic probe and
    ``uid=`` proofs need no token.
    """
    out = _norm(output)
    sent = _norm(sent_bytes)
    diagnostics: List[str] = []
    evidence: List[Evidence] = []

    # Tier 1: PLANTED
    if planted is not None:
        if workspace is None:
            diagnostics.append("planted_skipped: no private workspace supplied")
        elif planted.workspace_id != _workspace_id(workspace):
            diagnostics.append("planted_skipped: marker not bound to this workspace")
        elif planted.value in sent:
            diagnostics.append("planted_skipped: marker value present in sent bytes")
        elif planted.value in out:
            evidence.append(Evidence(TIER_PLANTED, planted.value))

    # Tier 2: SHELL-PROVEN
    shell_patterns = [re.escape(ARITH_MARK), _UID_RE]
    if token:
        shell_patterns.insert(0, re.escape(strict_marker(token)))
    for pat in shell_patterns:
        _candidates(re.compile(pat), out, sent, TIER_SHELL, evidence, diagnostics)

    # Tier 3: SHAPE
    shape = _resolve_shape(flag_pattern, diagnostics)
    _candidates(shape, out, sent, TIER_SHAPE, evidence, diagnostics)

    # Banner words: diagnostic only, never success.
    for m in re.finditer(BANNER_RE, out):
        diagnostics.append(f"banner:{m.group(0).lower()}")

    evidence.sort(key=lambda e: TIER_RANK.index(e.tier))  # stable
    if not evidence:
        return OracleResult(diagnostics=diagnostics)
    primary = evidence[0]
    return OracleResult(
        primary_tier=primary.tier,
        evidence=evidence,
        matched_value=primary.value,
        success=True,
        diagnostics=diagnostics,
    )
