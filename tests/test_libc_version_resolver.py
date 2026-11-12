"""Unit tests for the honest libc-version resolver (``supwngo.utils.libc``).

These pin the contract that an *unknown* libc version is a first-class state:
it is parsed to ``None`` (never coerced to the retired ``2.31`` default), and
any request for a version-dependent *offset* raises rather than fabricating a
release.
"""

import pytest

from supwngo.utils.libc import (
    LibcVersionUnknown,
    parse_libc_version,
    read_libc_release_version,
    require_libc_version,
    resolve_libc_version,
)


def test_parse_wellformed():
    assert parse_libc_version("2.31") == (2, 31)
    assert parse_libc_version("2.35-0ubuntu3.4") == (2, 35)
    assert parse_libc_version("  2.27  ") == (2, 27)


def test_parse_accepts_full_version_grammar():
    # ``major.minor`` followed by a real separator (distro suffix, patch level,
    # Debian ``~``) must still parse to ``(major, minor)``.
    assert parse_libc_version("2.31-0ubuntu9.9") == (2, 31)
    assert parse_libc_version("2.35.1") == (2, 35)
    assert parse_libc_version("2.34~rc1") == (2, 34)
    assert parse_libc_version("2.27_custom") == (2, 27)


def test_parse_malformed_is_none_never_231():
    # The whole point of CG-01: malformed/unknown must be None, not (2, 31).
    # ``2.31garbage``/``2.31x`` are the review's regression cases: a prefix-only
    # regex would have unlocked 2.31 offsets from alphabetic garbage.
    for bad in (None, "", "garbage", "2", "glibc", "v2.31", "2.31garbage", "2.31x"):
        assert parse_libc_version(bad) is None, bad


def test_parse_tuple_orders_major_above_minor():
    # (3, 0) must sort above (2, 30); a bare-minor comparison would misrank it.
    assert parse_libc_version("3.0") > parse_libc_version("2.30")
    assert parse_libc_version("2.9") < parse_libc_version("2.31")


def test_resolve_precedence_explicit_wins():
    assert resolve_libc_version("2.27") == "2.27"
    # A malformed explicit version is unknown, not normalized to a default.
    assert resolve_libc_version("nonsense") is None


def test_resolve_falls_back_to_release_banner(tmp_path):
    libc = tmp_path / "libc.so.6"
    libc.write_bytes(
        b"\x00pad GNU C Library (Ubuntu GLIBC 2.31-0ubuntu9.9) "
        b"stable release version 2.31.\x00more"
    )
    assert resolve_libc_version(None, str(libc)) == "2.31"


def test_resolve_unknown_is_none():
    assert resolve_libc_version(None, None) is None
    assert resolve_libc_version(None, "/nonexistent/libc.so.6") is None


def test_read_banner_ignores_symbol_version_tags(tmp_path):
    # Bare ``GLIBC_2.34`` symbol-version tags are minimum-ABI requirements, not
    # the runtime libc version; they must NOT be read as a version.
    libc = tmp_path / "libc.so.6"
    libc.write_bytes(b"\x00GLIBC_2.34\x00GLIBC_2.2.5\x00GLIBC_PRIVATE\x00")
    assert read_libc_release_version(str(libc)) is None


def test_read_banner_reads_real_release_line(tmp_path):
    libc = tmp_path / "libc.so.6"
    libc.write_bytes(
        b"\x00GNU C Library (GNU libc) stable release version 2.35.\x00"
    )
    assert read_libc_release_version(str(libc)) == "2.35"


def test_read_banner_requires_gnu_c_library_context(tmp_path):
    # Review finding 5: a stray ``release version N.N`` / ``GLIBC N.N-`` in an
    # unrelated application binary (no GNU C Library banner) must NOT be read as
    # the libc version.
    app = tmp_path / "app"
    app.write_bytes(
        b"\x00MyApp release version 9.99 build\x00see Ubuntu GLIBC 9.99-x\x00"
    )
    assert read_libc_release_version(str(app)) is None


def test_require_raises_on_unknown():
    with pytest.raises(LibcVersionUnknown):
        require_libc_version(None, what="unit-test offset")
    with pytest.raises(LibcVersionUnknown):
        require_libc_version("garbage", what="unit-test offset")


def test_require_returns_tuple_on_known():
    assert require_libc_version("2.31", what="x") == (2, 31)
    assert require_libc_version("2.27-0ubuntu3", what="x") == (2, 27)
