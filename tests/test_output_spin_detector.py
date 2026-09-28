"""Proofs for `verifier._detect_output_spin` -- the EOF-spin diagnosis (I-18).

Why this exists: a `subprocess.TimeoutExpired` reports the symptom and hides two
opposite causes. A target wedged on a blocking read and a target cheerfully
redrawing its menu forever are indistinguishable from the timeout alone, but they
want opposite responses -- the first may deserve a bigger budget, the second will
never succeed with one. A recorded `TIMEOUT x3 @300s` for `auth-or-out` was read as
missing search-budget discipline; measured, the process was alive and printing the
whole time.

**The bug these tests were written after, because it is the instructive part.** The
first version of the detector required one line to be >50% of the output. The real
spin is a SIX-line menu block, so no single line exceeds ~17% and the check could
never fire on the very case it was written for -- it passed every synthetic test and
was useless. It was caught only by running the actual target. The detector now keys
on a *repetition ratio* (total non-blank lines / distinct non-blank lines), and
`test_fires_on_a_multi_line_menu_block` is the regression guard for that mistake.

Measured against the real target (not asserted here -- it needs the gitignored HTB
tree and produces ~14 MB): `auth-or-out` driven to EOF emits 987,800 non-blank lines
made of **7** distinct ones, a ratio of ~141,000, and the detector fires.
"""

from __future__ import annotations

from supwngo.exploit.pipeline.verifier import (
    _SPIN_MIN_REPEATS,
    _SPIN_MIN_REPETITION_RATIO,
    _detect_output_spin,
)

MENU = "1 - Add Author\n2 - Modify\n3 - Print\n4 - Delete\n5 - Exit\nChoice:\n"


# --------------------------------------------------------------------------
# Must NOT fire -- a detector that flags everything is not a diagnosis
# --------------------------------------------------------------------------


def test_silent_on_empty_output():
    assert _detect_output_spin("") is None


def test_silent_on_ordinary_short_output():
    assert _detect_output_spin("hello\nworld\n$ ") is None


def test_silent_below_the_repeat_threshold():
    assert _detect_output_spin("> \n" * (_SPIN_MIN_REPEATS - 1)) is None


def test_silent_on_high_volume_but_diverse_output():
    """A long, legitimately noisy run reprints some banners a lot. That is content,
    not a spin, and the repetition ratio is what tells them apart."""
    noisy = ("banner\n" * 600) + "".join(f"line{i}\n" for i in range(2000))
    assert _detect_output_spin(noisy) is None


# --------------------------------------------------------------------------
# Must fire
# --------------------------------------------------------------------------


def test_fires_on_a_single_repeated_line():
    note = _detect_output_spin("> \n" * (_SPIN_MIN_REPEATS + 100))
    assert note is not None
    assert "OUTPUT SPIN" in note


def test_fires_on_a_multi_line_menu_block():
    """Regression guard for the original defect: with a 6-line block no single line
    reaches 20% of the output, so any dominance-based test fails here while the real
    target spins. This is the shape that actually occurs."""
    note = _detect_output_spin(MENU * 500)
    assert note is not None, (
        "a repeated multi-line menu block is the real spin shape -- a detector that "
        "misses it is measuring nothing"
    )
    assert "distinct" in note


def test_note_reports_the_numbers_it_judged_on():
    """The note has to carry its own evidence, or a reader cannot tell a spin from a
    threshold artefact."""
    note = _detect_output_spin(MENU * 500)
    assert note is not None
    assert "6 distinct" in note  # the 6 unique lines of MENU
    assert "I-18" in note


def test_thresholds_are_actually_load_bearing():
    """Positive control for the two constants: if either were ignored, output that
    sits just inside one bound and outside the other would still fire."""
    # Enough repeats, but diverse: ratio blocks it.
    diverse = "".join(f"u{i}\n" for i in range(_SPIN_MIN_REPEATS + 100))
    assert _detect_output_spin(diverse) is None
    # Highly repetitive, but too few lines: the repeat threshold blocks it.
    assert _detect_output_spin("x\n" * 10) is None
    assert _SPIN_MIN_REPETITION_RATIO > 1
