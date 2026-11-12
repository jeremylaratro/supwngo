"""CG-01a: tcache offset/layout emission refuses an unknown libc version.

On base ``dc22067`` an unknown version silently resolved to glibc 2.31's
``0x80/0x290`` layout and 2.27 fallback hook offsets -- a confidently-wrong
payload against any other glibc. These tests pin that:

* bare construction still works (no raise) -- so unknown-version callers can
  build the object and use version-independent helpers;
* every *offset/layout/payload* method refuses on unknown;
* explicit known versions are unchanged.
"""

import pytest

from supwngo.exploit.heap.tcache import TcacheExploiter, TcachePerThreadStruct
from supwngo.utils.libc import LibcVersionUnknown

TARGET = 0x404000
LIBC_BASE = 0x7F0000000000


def test_exploiter_constructs_with_unknown_version():
    # MAJOR-5 guard: unknown version must not raise at construction time.
    tc = TcacheExploiter()
    assert tc.version is None
    assert tc.has_tcache is None
    assert tc.has_key is None
    assert tc.has_safe_linking is None


def test_size_to_idx_is_version_independent():
    # Version-independent helper still works with no bound libc.
    assert TcachePerThreadStruct().size_to_idx(0x90) == 7
    assert TcacheExploiter().perthread.size_to_idx(0x20) == 0


def test_build_fake_struct_refuses_unknown_version():
    # RED on base: base silently returns a 0x290-byte 2.31 struct.
    with pytest.raises(LibcVersionUnknown):
        TcachePerThreadStruct().build_fake_struct(7, TARGET, target_count=1)


def test_build_fake_struct_refuses_explicit_offsets_without_version():
    # Review finding 4: supplying public layout fields with no version must not
    # bypass the refusal -- emission requires a *known version*, not merely a
    # populated ``total_size``.
    struct = TcachePerThreadStruct(
        version=None, counts_offset=0, entries_offset=0x80, total_size=0x290
    )
    with pytest.raises(LibcVersionUnknown):
        struct.build_fake_struct(7, TARGET, target_count=1)


def test_build_fake_struct_refuses_version_cleared_after_construction():
    # Review finding 4: constructing with a known version then clearing it must
    # refuse at emission rather than emit the cached (now-foreign) layout.
    struct = TcachePerThreadStruct(version="2.31")
    assert struct.total_size == 0x290  # resolved at construction
    struct.version = None
    with pytest.raises(LibcVersionUnknown):
        struct.build_fake_struct(7, TARGET, target_count=1)


def test_perthread_poison_refuses_unknown_version():
    with pytest.raises(LibcVersionUnknown):
        TcacheExploiter().tcache_perthread_poison(TARGET)


def test_hook_overwrite_targets_refuses_unknown_version():
    # RED on base: base returned 2.27 fallback offsets (e.g. __free_hook 0x3ed8e8).
    with pytest.raises(LibcVersionUnknown):
        TcacheExploiter().hook_overwrite_targets(libc_base=LIBC_BASE)


def test_double_free_bypass_refuses_unknown_version():
    with pytest.raises(LibcVersionUnknown):
        TcacheExploiter().double_free_with_key_bypass(TARGET)


def test_generate_exploit_code_refuses_unknown_version():
    with pytest.raises(LibcVersionUnknown):
        TcacheExploiter().generate_exploit_code("double_free", TARGET)


def test_explicit_versions_unchanged():
    s27 = TcachePerThreadStruct(version="2.27")
    assert (s27.entries_offset, s27.total_size) == (0x40, 0x250)
    s31 = TcachePerThreadStruct(version="2.31")
    assert (s31.entries_offset, s31.total_size) == (0x80, 0x290)
    assert len(s31.build_fake_struct(7, TARGET, target_count=1)) == 0x290


def test_explicit_version_hook_targets_still_resolve():
    tc = TcacheExploiter(libc_version="2.31")
    targets = tc.hook_overwrite_targets(libc_base=LIBC_BASE)
    assert targets  # non-empty: known version resolves hook offsets
