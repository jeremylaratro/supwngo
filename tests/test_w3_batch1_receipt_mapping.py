"""W-3 batch 1: oracle -> receipt mapping (design 2.5) and the R shell-fallback seam.

No Ghidra, no corpus: the receipt adapter is exercised on synthetic transcripts,
and one seam test runs a real ``/bin/sh`` for the positive control.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

from supwngo.core import success_oracle as so
from supwngo.exploit.pipeline.verifier import receipt_fields_from_oracle
from supwngo.exploit.tester import ExploitTester, TestConfig, TestResult
from supwngo.exploit.verification import ExploitVerifier, VerificationLevel

TOKEN = "RCPT0123abcd"


def _sent(token: str = TOKEN) -> str:
    return (
        f"echo {token}\n" * 2 + "id\n" + f"{so.strict_probe(token)}\n"
        + f"echo {so.ARITH_PROBE}\n"
    )


def _fields(output: str, token: str = TOKEN, **kw):
    res = so.check(output, _sent(token), token=token, **kw)
    return res, receipt_fields_from_oracle(res, output, token)


# ---- (a) one test per table row -------------------------------------------


def test_row_planted():
    with so.private_workspace() as ws:
        rec = so.mint_marker(ws)
        out = f"leaked {rec.value}\n"
        res = so.check(out, _sent(), planted=rec, workspace=ws, token=TOKEN)
        f = receipt_fields_from_oracle(res, out, TOKEN)
    assert res.primary_tier == so.TIER_PLANTED
    assert f["level"] is VerificationLevel.FLAG_CAPTURED
    assert f["flag"] == rec.value
    assert f["shell_confirmed"] is False and f["shell_proven"] is False
    assert f["matched_requested_token"] is True
    assert f["echo_ambiguous"] is False


def test_row_planted_with_shell_evidence_keeps_both():
    with so.private_workspace() as ws:
        rec = so.mint_marker(ws)
        out = f"{rec.value}\n{so.ARITH_MARK}\n"
        res = so.check(out, _sent(), planted=rec, workspace=ws, token=TOKEN)
        f = receipt_fields_from_oracle(res, out, TOKEN)
    assert f["level"] is VerificationLevel.FLAG_CAPTURED
    assert f["shell_confirmed"] is True and f["shell_proven"] is True


def test_row_shell_proven_with_strict_marker():
    out = f"{TOKEN}\n{TOKEN}\nuid=0(root)\n{so.strict_marker(TOKEN)}\n{so.ARITH_MARK}\n"
    res, f = _fields(out)
    assert res.primary_tier == so.TIER_SHELL
    assert f["level"] is VerificationLevel.SHELL_ACCESS
    assert f["flag"] is None
    assert f["shell_confirmed"] and f["shell_proven"]
    assert f["matched_requested_token"] is True
    assert f["echo_ambiguous"] is False


def test_row_shell_proven_without_token_in_output():
    res, f = _fields(f"{so.ARITH_MARK}\n")
    assert f["level"] is VerificationLevel.SHELL_ACCESS
    assert f["shell_proven"] is True
    assert f["matched_requested_token"] is False


def test_row_shape_non_echo():
    res, f = _fields("you win: ab_c{d3adb33f}\n")
    assert res.primary_tier == so.TIER_SHAPE
    assert f["level"] is VerificationLevel.FLAG_CAPTURED
    assert f["flag"] == "ab_c{d3adb33f}"
    assert f["shell_confirmed"] is False and f["shell_proven"] is False
    assert f["matched_requested_token"] is False and f["echo_ambiguous"] is False


def test_row_echoed_token_only_is_a_diagnostic_not_a_solve():
    """R1: the one deliberate behaviour change."""
    res, f = _fields(f"checking echo {TOKEN}\n{TOKEN}\n{TOKEN}\n")
    assert res.success is False
    assert f["level"] is VerificationLevel.NONE
    assert f["flag"] is None
    assert f["shell_confirmed"] is True and f["shell_proven"] is False
    assert f["matched_requested_token"] is False
    assert f["echo_ambiguous"] is True
    assert any("token echoed back; no un-echoed proof" in n for n in f["notes"])


def test_row_banner_only():
    res, f = _fields("Welcome! Congratulations, success\n")
    assert f["level"] is VerificationLevel.NONE
    assert not any(
        f[k] for k in ("flag", "shell_confirmed", "shell_proven",
                       "matched_requested_token", "echo_ambiguous")
    )


def test_row_no_match():
    res, f = _fields("nothing interesting\n")
    assert f["level"] is VerificationLevel.NONE
    assert f["echo_ambiguous"] is False and f["shell_confirmed"] is False


def test_echo_ambiguous_receipt_serialises_with_success_false():
    from supwngo.exploit.pipeline.contracts import VerificationReceipt

    _, f = _fields(f"{TOKEN}\n")
    r = VerificationReceipt(
        token=TOKEN, technique="t", level=f["level"],
        shell_confirmed=f["shell_confirmed"], shell_proven=f["shell_proven"],
        echo_ambiguous=f["echo_ambiguous"], notes=f["notes"],
    )
    d = r.to_dict()
    assert d["success"] is False and d["level"] == "NONE"
    assert d["shell_confirmed"] is True and d["echo_ambiguous"] is True
    assert d["notes"]


# ---- (b) R shell-fallback seam: reflecting decoy vs real shell -------------


def test_reflecting_decoy_is_not_credited():
    """A target that reflects the whole transcript (probes, token, even the
    arithmetic probe text) must not be credited."""
    reflected = _sent()
    res, f = _fields(reflected)
    assert res.success is False
    assert f["level"] is VerificationLevel.NONE
    assert f["shell_proven"] is False


@pytest.mark.skipif(shutil.which("sh") is None, reason="needs sh")
def test_real_shell_answers_are_credited():
    proc = subprocess.run(
        ["sh"], input=_sent().encode(), capture_output=True, timeout=10,
    )
    out = proc.stdout.decode()
    res, f = _fields(out)
    assert res.primary_tier == so.TIER_SHELL
    assert f["level"] is VerificationLevel.SHELL_ACCESS
    assert f["shell_proven"] is True and f["matched_requested_token"] is True


# ---- verification.py / tester.py routing ----------------------------------


def test_verify_output_no_longer_credits_banner_words(tmp_path):
    v = ExploitVerifier(str(tmp_path / "bin"))
    r = v.verify_output("Congratulations! Welcome, access granted, success")
    assert r.success is False and r.level is VerificationLevel.NONE


def test_verify_output_captures_neutral_shape_but_not_an_echo(tmp_path):
    v = ExploitVerifier(str(tmp_path / "bin"))
    assert v.verify_output("x aa_b{c0ffee} y").flag == "aa_b{c0ffee}"
    echoed = v.verify_output("x aa_b{c0ffee} y", sent=b"aa_b{c0ffee}")
    assert echoed.success is False


def test_tester_flag_pattern_precedence(monkeypatch):
    class _B:  # minimal binary stand-in
        path = "/bin/true"
        bits = 64

    monkeypatch.setenv(so.FLAG_RE_ENV, r"ENVFLAG<\d+>")
    # default config -> env wins over the neutral default
    t = ExploitTester(_B())
    assert t._evaluate_output("ENVFLAG<42>")[2] == "ENVFLAG<42>"
    # caller-set instance pattern wins over env
    t2 = ExploitTester(_B(), TestConfig(flag_pattern=r"INST\[\w+\]"))
    r, _, flag = t2._evaluate_output("INST[abc] ENVFLAG<42>")
    assert flag == "INST[abc]" and r == TestResult.SUCCESS
    monkeypatch.delenv(so.FLAG_RE_ENV)
    assert t._evaluate_output("ab{cdefg}")[2] == "ab{cdefg}"


def test_tester_uid_and_platform_words_are_partial_only():
    class _B:
        path = "/bin/true"
        bits = 64

    t = ExploitTester(_B())
    r, shell, flag = t._evaluate_output("uid=0(root) banner")
    assert r == TestResult.PARTIAL and flag is None and shell is False
    assert t._evaluate_output("flag{")[0] == TestResult.FAILED
