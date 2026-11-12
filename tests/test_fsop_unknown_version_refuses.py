"""CG-01a: FSOP hook-offset emission refuses an unknown libc version.

On base ``dc22067`` ``malloc_hook_attack`` / ``free_hook_attack`` with an
unknown version silently used glibc 2.31's ``0x3ed8e8`` offset
(``hook_offsets.get(self.version, 0x3ed8e8)``). These pin that an unknown (or
untabulated) version returns an explicit error dict with no fabricated
``target``, while known tabulated versions are unchanged.
"""

from supwngo.exploit.fsop import FSOPExploiter

LIBC_BASE = 0x7F0000000000
ONE_GADGET = 0x4F432
SYSTEM = 0x52290
BASE_231_OFFSET = 0x3ED8E8  # the offset base silently fabricated for unknown


def test_malloc_hook_unknown_returns_error_not_231_offset():
    res = FSOPExploiter().malloc_hook_attack(LIBC_BASE, one_gadget=ONE_GADGET)
    assert "error" in res
    assert "target" not in res  # no fabricated offset emitted
    # RED on base: base returned target == LIBC_BASE + 0x3ed8e8.
    assert res.get("target") != LIBC_BASE + BASE_231_OFFSET


def test_free_hook_unknown_returns_error_not_231_offset():
    res = FSOPExploiter().free_hook_attack(LIBC_BASE, system_addr=SYSTEM)
    assert "error" in res
    assert "target" not in res
    assert res.get("target") != LIBC_BASE + BASE_231_OFFSET


def test_explicit_227_malloc_hook_unchanged():
    res = FSOPExploiter(libc_version="2.27").malloc_hook_attack(
        LIBC_BASE, one_gadget=ONE_GADGET
    )
    assert res["target"] == LIBC_BASE + 0x3EBC30


def test_explicit_223_free_hook_unchanged():
    res = FSOPExploiter(libc_version="2.23").free_hook_attack(
        LIBC_BASE, system_addr=SYSTEM
    )
    assert res["target"] == LIBC_BASE + 0x3C67A8


def test_removed_hooks_234_plus_still_reported():
    res = FSOPExploiter(libc_version="2.35").malloc_hook_attack(
        LIBC_BASE, one_gadget=ONE_GADGET
    )
    assert "error" in res and "removed" in res["error"]
    assert "target" not in res


def test_feature_flags_tristate_on_unknown():
    ex = FSOPExploiter()
    assert ex.has_hooks is None
    assert ex.has_vtable_check is None
