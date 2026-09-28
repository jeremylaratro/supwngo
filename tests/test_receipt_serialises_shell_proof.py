"""A receipt's shell-vs-echo flags must survive serialisation (`I-27`).

THE DEFECT
----------
`VerificationReceipt` has carried `shell_proven` and `echo_ambiguous` since `I-16`.
The verifier sets them, the dataclass documents them at length, and
`tests/test_subprocess_injection_executor.py` pins BOTH directions -- the RED case
(a naive stdin bridge against a target with no shell yields
`shell_confirmed=True, shell_proven=False, echo_ambiguous=True`) and the positive
control (a real shell yields `shell_proven=True`).

And `to_dict()` dropped both. So the flags never left the process: every JSON report
ever written recorded `shell_confirmed` and said nothing about whether that shell was
real. The owed `M-2` audit -- "does any recorded HTB solve carry `echo_ambiguous`?"
-- was therefore IMPOSSIBLE to perform, not merely un-performed, and nothing said so.

The existing tests could not catch it because they inspect the receipt OBJECT. That
is the same defect class as `I-23`, where three walkthrough families were selected,
scored and route-swept while the suite stayed 396 green, because nothing ever
rendered them. A field that is set, documented and unit-tested can still be absent
from the only artifact a human reads.

WHY THESE TESTS ARE SHAPED THIS WAY
-----------------------------------
The obvious assertion -- "the key is present" -- is satisfied by a hardcoded
`False`, which is the *dangerous* wrong answer: it reads as "measured, and clean".
So each flag is asserted to round-trip in BOTH states, and the crediting test is
written against the state that matters (`echo_ambiguous=True` on a receipt whose
`shell_confirmed` is also True), because that is the combination a real false
positive produces.
"""

from __future__ import annotations

from supwngo.exploit.pipeline.contracts import VerificationReceipt
from supwngo.exploit.verification import VerificationLevel


def _receipt(**kw) -> VerificationReceipt:
    base = dict(
        token="tok-i27",
        technique="probe_technique",
        level=VerificationLevel.SHELL_ACCESS,
        binary_path="/nonexistent/probe",
    )
    base.update(kw)
    return VerificationReceipt(**base)


def test_an_echo_ambiguous_receipt_says_so_after_serialisation() -> None:
    """The case that matters: a credited shell that nothing proved was a shell."""
    d = _receipt(shell_confirmed=True, shell_proven=False, echo_ambiguous=True).to_dict()

    assert d["shell_confirmed"] is True, "precondition: this receipt credits a shell"
    assert d["echo_ambiguous"] is True, (
        "a receipt whose shell was never distinguished from an echo must carry that "
        "through to_dict() -- otherwise a report can credit the solve and stay silent "
        "about the doubt, which is exactly what made the M-2 audit impossible"
    )
    assert d["shell_proven"] is False


def test_a_proven_shell_also_round_trips() -> None:
    """The paired control. Without it, a hardcoded ``False`` would pass the test
    above and still be wrong in the direction that inflates a score."""
    d = _receipt(shell_confirmed=True, shell_proven=True, echo_ambiguous=False).to_dict()

    assert d["shell_proven"] is True, (
        "a genuinely proven shell must serialise as proven; if this is hardcoded "
        "False, every real solve is reported as doubtful"
    )
    assert d["echo_ambiguous"] is False


def test_both_flags_are_actually_present_in_the_payload() -> None:
    """Names the subject of the absence, so a rename cannot make this vacuous."""
    d = _receipt().to_dict()
    for key in ("shell_confirmed", "shell_proven", "echo_ambiguous"):
        assert key in d, f"{key} missing from the serialised receipt: {sorted(d)}"


def test_the_flags_are_not_welded_to_shell_confirmed() -> None:
    """They must be independent fields, not aliases.

    If `shell_proven` were derived from `shell_confirmed` the payload would look
    populated while carrying no new information at all -- the failure mode that is
    hardest to notice, because every key is present and every value is plausible.
    """
    ambiguous = _receipt(shell_confirmed=True, shell_proven=False, echo_ambiguous=True).to_dict()
    proven = _receipt(shell_confirmed=True, shell_proven=True, echo_ambiguous=False).to_dict()

    assert ambiguous["shell_confirmed"] == proven["shell_confirmed"] is True
    assert ambiguous["shell_proven"] != proven["shell_proven"], (
        "two receipts that differ ONLY in whether the shell was proven must "
        "serialise differently; if they do not, the flag carries no information"
    )
    assert ambiguous["echo_ambiguous"] != proven["echo_ambiguous"]
