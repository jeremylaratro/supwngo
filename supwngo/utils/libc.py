"""Honest libc-version resolution for version-dependent exploit offsets.

Several technique classes pick glibc-version-dependent values -- tcache
``tcache_perthread_struct`` field offsets, ``__malloc_hook``/``__free_hook``
displacements, safe-linking behaviour, feasibility verdicts. Historically these
defaulted an *unknown* version to a hardcoded ``"2.31"`` (the retired
``DEFAULT_LIBC_VERSION``), so a caller who did not know the target's libc
silently got 2.31's layout -- a confidently-wrong payload against any other
glibc.

This module makes "unknown" an explicit, first-class state. A version is either
a known ``(major, minor)`` or it is unknown; unknown must never be silently
coerced to a specific release. Callers that need a version to place an *offset*
use :func:`require_libc_version`, which raises :class:`LibcVersionUnknown`
rather than fabricate one; callers that only report a *capability* keep the
``None``/unknown tri-state.
"""
from __future__ import annotations

import re
from typing import Optional, Tuple

__all__ = [
    "LibcVersionUnknown",
    "parse_libc_version",
    "resolve_libc_version",
    "require_libc_version",
    "read_libc_release_version",
]

#: ``2.31`` or ``2.31-0ubuntu9.9`` or ``2.35.1`` -> capture ``major.minor``.
#: The trailing group requires that ``major.minor`` is followed by a real
#: separator (``-``, ``.``, ``~``, ``_``, ``+``, or whitespace) or end-of-string,
#: so a distro suffix (``2.31-0ubuntu9.9``) or patch level (``2.35.1``) still
#: parses, but alphabetic garbage glued on (``2.31garbage``) does NOT silently
#: resolve to ``(2, 31)`` -- it is unknown.
_VERSION_RE = re.compile(r"^(\d+)\.(\d+)(?:[-+.~_\s].*)?$")

#: glibc *release* banner inside a libc ELF, e.g.
#: ``GNU C Library (Ubuntu GLIBC 2.31-0ubuntu9.9) stable release version 2.31.``
#: Both patterns are anchored to the ``GNU C Library`` banner marker so a stray
#: ``release version 9.99`` or ``GLIBC 9.99-`` in an unrelated application binary
#: is NOT mistaken for the runtime libc version. Bare ``GLIBC_2.x`` symbol-version
#: tags (minimum-ABI requirements, not the runtime version) are likewise ignored.
_BANNER_RES = (
    re.compile(rb"GNU C Library.{0,256}?release version (\d+)\.(\d+)", re.DOTALL),
    re.compile(rb"GNU C Library.{0,128}?GLIBC[ _](\d+)\.(\d+)-", re.DOTALL),
)


class LibcVersionUnknown(ValueError):
    """Raised when a version-dependent *offset* is requested without a known
    libc version. Deliberately a hard failure: fabricating a version here is the
    exact confidently-wrong behaviour this module exists to prevent."""


def parse_libc_version(version: Optional[str]) -> Optional[Tuple[int, int]]:
    """``"2.31"`` / ``"2.31-0ubuntu9"`` -> ``(2, 31)``.

    Returns ``None`` for ``None`` or any malformed value -- never a ``(2, 31)``
    fallback. Callers compare the returned tuple, so ``(3, 0)`` sorts correctly
    above ``(2, 30)`` (a bare-``minor`` comparison would misclassify it).
    """
    if not version:
        return None
    match = _VERSION_RE.match(version.strip())
    if not match:
        return None
    return int(match.group(1)), int(match.group(2))


def read_libc_release_version(libc_path: Optional[str]) -> Optional[str]:
    """``"major.minor"`` read from a libc ELF's release banner, else ``None``.

    Only a real release banner is trusted (see ``_BANNER_RES``). Returns ``None``
    when the path is missing/unreadable or carries no banner.
    """
    if not libc_path:
        return None
    try:
        with open(libc_path, "rb") as handle:
            blob = handle.read()
    except OSError:
        return None
    for pattern in _BANNER_RES:
        match = pattern.search(blob)
        if match:
            return f"{int(match.group(1))}.{int(match.group(2))}"
    return None


def resolve_libc_version(
    version: Optional[str] = None, libc_path: Optional[str] = None
) -> Optional[str]:
    """Resolve a libc version ``"major.minor"`` string, or ``None`` if unknown.

    Precedence: an explicit (well-formed) ``version`` wins; else the release
    banner read from ``libc_path``; else ``None``. A *malformed* explicit version
    is treated as unknown (``None``), never normalized to a default.
    """
    parsed = parse_libc_version(version)
    if parsed is not None:
        return f"{parsed[0]}.{parsed[1]}"
    return read_libc_release_version(libc_path)


def require_libc_version(version: Optional[str], *, what: str) -> Tuple[int, int]:
    """Return ``(major, minor)`` for ``version`` or raise :class:`LibcVersionUnknown`.

    ``what`` names the offset/layout being placed, for the error message. Use at
    every point that turns a version into concrete offset bytes, so an unknown
    version fails loudly instead of fabricating a 2.31 layout.
    """
    parsed = parse_libc_version(version)
    if parsed is None:
        raise LibcVersionUnknown(
            f"{what} needs a known libc version; none was supplied or resolvable"
        )
    return parsed
