"""`I-28`: a target we cannot SPAWN must end the probe, not kill `explain`.

WHAT BROKE
----------
`supwngo explain` on HTB `sabotage` -- a target the pipeline SOLVES in ~10s,
3/3 reps SHELL_ACCESS -- died with an uncaught ``PermissionError``. The probe
ran the image directly with ``subprocess.Popen([path])`` and nothing caught the
spawn failure, so a fact-collection step that is allowed to return "I don't
know" instead took down the whole command.

WHY THE FIXTURE IS BUILT AND NOT MOCKED
---------------------------------------
Monkeypatching ``Popen`` to raise ``OSError`` would prove only that
``except OSError`` catches ``OSError``. The interesting part of `I-28` is the
*shape* of the real failure, which is `I-17`:

  * four HTB challenge dirs ship a **0-byte, non-executable**
    ``glibc/ld-linux-x86-64.so.2`` (measured: mode 664 on the shipped copies);
  * the image's ``PT_INTERP`` is the **relative** path
    ``./glibc/ld-linux-x86-64.so.2`` (measured on `sabotage`,
    `rocket_blaster_xxx` and `bon-nie-appetit`; the other three HTB ELFs carry
    the normal absolute ``/lib64/...`` and are unaffected);
  * the kernel reports **EACCES against the EXECUTABLE's own path** -- so the
    exception names a file that is plainly mode-755, which is what sent the
    original diagnosis to the wrong file.

So this builds that exact shape from a real ELF: patch ``.interp`` in place to
the relative path, drop a 0-byte non-executable loader there, and keep the image
itself executable. If the kernel ever stopped producing EACCES for that shape,
``test_the_premise_holds`` goes red and says so, rather than leaving the tests
below quietly asserting nothing.
"""

from __future__ import annotations

import glob
import os
import shutil
import subprocess

import pytest

from supwngo.exploit.walkthrough import fmtstr_probe

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: The relative interp `I-17` ships, minus its `./` prefix. The real string is
#: `./glibc/ld-linux-x86-64.so.2` (28 chars), which does NOT fit in the donor's
#: 27-char `/lib64/ld-linux-x86-64.so.2` field; dropping `./` gives 26 chars,
#: resolves identically (both are relative to cwd), and lets the patch happen in
#: place with no program-header surgery and no offset moving anywhere.
BROKEN_INTERP = b"glibc/ld-linux-x86-64.so.2"
REAL_INTERP = b"/lib64/ld-linux-x86-64.so.2"


def _donor() -> str:
    """Any dynamically linked corpus ELF. Found by glob, not pinned."""
    for pattern in ("benchmark/corpus*/*/*", "tests/htb-targets/*/*/*"):
        for path in sorted(glob.glob(os.path.join(REPO, pattern))):
            if not (os.path.isfile(path) and os.access(path, os.X_OK)):
                continue
            with open(path, "rb") as handle:
                blob = handle.read()
            if blob[:4] == b"\x7fELF" and REAL_INTERP in blob:
                return path
    pytest.skip("no dynamically linked ELF available to build the fixture from")


@pytest.fixture
def unspawnable(tmp_path) -> str:
    """A mode-755 ELF whose relative PT_INTERP is a 0-byte, non-executable file."""
    donor = _donor()
    target = tmp_path / "unspawnable"
    shutil.copy(donor, target)

    blob = target.read_bytes()
    assert blob.count(REAL_INTERP) >= 1
    # Same length field, shorter string: pad the remainder with NUL so p_filesz
    # still ends on a terminator and no program header needs touching.
    patched = blob.replace(
        REAL_INTERP + b"\x00",
        BROKEN_INTERP + b"\x00" * (len(REAL_INTERP) - len(BROKEN_INTERP) + 1),
        1,
    )
    assert len(patched) == len(blob), "the patch must not move a single offset"
    target.write_bytes(patched)
    target.chmod(0o755)

    loader = tmp_path / "glibc" / "ld-linux-x86-64.so.2"
    loader.parent.mkdir()
    loader.write_bytes(b"")  # 0 bytes, exactly as `I-17` ships it
    loader.chmod(0o644)  # non-executable, which is the property the kernel objects to
    return str(target)


# --------------------------------------------------------------------------
# positive control FIRST: the premise these tests rest on
# --------------------------------------------------------------------------


def test_the_premise_holds(unspawnable: str) -> None:
    """The fixture really is unspawnable, and really does name the wrong file.

    Asserted before anything trusts it. Without this, a fixture that quietly
    became runnable would make every test below pass while measuring nothing.
    """
    assert os.access(unspawnable, os.X_OK), "the image itself must be executable"

    # cwd is load-bearing and this control is what proved it. Run from anywhere
    # else and the RELATIVE interp resolves nowhere, giving ENOENT (2) instead of
    # EACCES (13) -- a different kernel answer, and not the one `I-17` describes.
    # `_deliver` passes cwd=Path(path).parent, so it is the EACCES path that the
    # guard has to survive; this control must match it or it measures the wrong
    # failure.
    with pytest.raises(OSError) as caught:
        subprocess.Popen(
            [unspawnable],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            cwd=os.path.dirname(unspawnable),
        )

    assert caught.value.errno == 13, (
        f"expected EACCES (13), got errno={caught.value.errno}. The kernel's answer "
        "to an unreadable PT_INTERP has changed; re-derive `I-17` before trusting "
        "the tests below."
    )
    # The finding that cost the most time: the error names the EXECUTABLE, not
    # the loader that is actually at fault.
    assert unspawnable in str(caught.value)
    assert "ld-linux" not in str(caught.value), (
        "if the kernel now names the loader, the misdirection half of `I-17` is "
        "gone and that comment should be corrected at the source"
    )


# --------------------------------------------------------------------------
# the fix
# --------------------------------------------------------------------------


def test_deliver_reports_the_spawn_failure_instead_of_raising(unspawnable: str) -> None:
    out, rc = fmtstr_probe._deliver(unspawnable, [b"%1$p\n"], timeout=2.0)
    assert out == b""
    assert rc == fmtstr_probe._SPAWN_FAILED


def test_the_sentinel_cannot_be_confused_with_a_real_run(unspawnable: str) -> None:
    """Pins *why* the sentinel is not ``0``.

    ``(b"", 0)`` is already the budget-exhausted answer AND what a silent clean
    exit produces. Folding three situations into one value is how a reader
    concludes the probe ran and found nothing.
    """
    _, rc = fmtstr_probe._deliver(unspawnable, [b"%1$p\n"], timeout=2.0)
    assert rc != 0, "a spawn failure must not look like a clean, silent exit"
    assert rc < -64, (
        f"rc={rc} is inside the range a real process can report (exit 0..255, "
        "signal death -1..-64), so it is ambiguous by construction"
    )

    exhausted = fmtstr_probe._Budget(max_runs=0)
    assert fmtstr_probe._deliver(
        unspawnable, [b"%1$p\n"], timeout=2.0, budget=exhausted
    ) == (b"", 0), "budget exhaustion is a different outcome and keeps its own code"


def test_probing_an_unspawnable_target_abstains_rather_than_crashing(
    unspawnable: str,
) -> None:
    """The user-visible half: the probe returns an honest UNKNOWN.

    This is the assertion that would have caught `I-28` -- the unit test above
    would not, because the crash happened a frame up from `_deliver`, inside the
    probe that calls it in a loop.

    ``probe_arg_index`` returns a positional tuple; only the three fields this
    test is about are named here, deliberately, so that adding a field to the
    tuple cannot silently shift what is being asserted.
    """
    result = fmtstr_probe.probe_arg_index(unspawnable, b"")
    reachable, arg_index, failure_reason = result[0], result[2], result[4]

    assert reachable is False
    assert arg_index is None, (
        "the target never ran, so any index here would be invented -- exactly the "
        "'confidently wrong' outcome this module's docstring forbids"
    )
    assert failure_reason, (
        "an abstention with no reason is indistinguishable from 'probed, found "
        "nothing', which is the wrong conclusion here"
    )


def test_explain_does_not_crash_on_an_unspawnable_target(unspawnable: str) -> None:
    """End to end, on the path that actually broke.

    `I-28` was not a probe bug in isolation; it was `supwngo explain` dying. So
    assert the whole selection path survives and still produces a walkthrough.
    """
    from supwngo.exploit.walkthrough.registry import walkthrough_for_binary

    w = walkthrough_for_binary(unspawnable)
    assert w is not None
    assert w.family, "a surviving run must still name a family, even if it is triage"
