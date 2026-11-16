"""Step 1 of W-3: the pure-stdlib success oracle (design sections 2.1-2.5, 5)."""

from __future__ import annotations

import ast
import os
import subprocess
import sys
import textwrap
import warnings
from pathlib import Path

import pytest

from supwngo.core import success_oracle as so
from supwngo.core.success_oracle import (
    TIER_PLANTED,
    TIER_SHAPE,
    TIER_SHELL,
    check,
    cleanup_marker,
    mint_marker,
    private_workspace,
    strict_probe,
)

ORACLE_FILE = Path(so.__file__)


@pytest.fixture(autouse=True)
def _no_env(monkeypatch):
    monkeypatch.delenv(so.FLAG_RE_ENV, raising=False)


def _run_py(code: str, stdin: bytes, cwd: str) -> bytes:
    return subprocess.run(
        [sys.executable, "-c", code], input=stdin, cwd=cwd,
        capture_output=True, timeout=30, check=True,
    ).stdout


# --- import topology -------------------------------------------------------


def test_oracle_imports_no_supwngo_module():
    tree = ast.parse(ORACLE_FILE.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [node.module or ""]
        else:
            continue
        for name in names:
            assert not name.split(".")[0] == "supwngo", name


# --- PLANTED ---------------------------------------------------------------


def test_oracle_planted_positive_and_echo_decoy():
    with private_workspace() as ws:
        rec = mint_marker(ws)
        # Positive control: a real program reads the marker from the planted file.
        reader = "import sys;print(open(sys.argv[1]).read())"
        out = subprocess.run(
            [sys.executable, "-c", reader, rec.planted_path],
            capture_output=True, check=True, timeout=30,
        ).stdout
        res = check(out, b"hello\n", planted=rec, workspace=ws)
        assert res.success and res.primary_tier == TIER_PLANTED
        assert res.matched_value == rec.value

        # Echo decoy: reflects input that contains a qualifying shape and probe.
        sent = b"AAAA{abcd1234} SH42OK uid=0\n"
        reflected = _run_py(
            "import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())", sent, ws
        )
        assert sent in reflected  # the reflected subject is present
        res = check(reflected, sent, planted=rec, workspace=ws)
        assert not res.success and res.primary_tier is None and res.evidence == []
        cleanup_marker(rec)
        assert not os.path.exists(rec.planted_path)


def test_oracle_planted_requires_workspace_and_absence_from_sent():
    with private_workspace() as ws:
        rec = mint_marker(ws)
        res = check(rec.value, b"", planted=rec)  # no workspace
        assert not res.success
        assert any("no private workspace" in d for d in res.diagnostics)
        res = check(rec.value, rec.value.encode(), planted=rec, workspace=ws)
        assert not res.success
        assert any("present in sent" in d for d in res.diagnostics)
        with private_workspace() as other:
            res = check(rec.value, b"", planted=rec, workspace=other)
            assert not res.success
        cleanup_marker(rec)


# --- anti-echo / precedence -----------------------------------------------


def test_oracle_anti_echo_per_match():
    sent = b"ECHO{aaaa1111}"
    out = b"ECHO{aaaa1111} then REAL{bbbb2222}"
    res = check(out, sent)
    assert res.success and res.primary_tier == TIER_SHAPE
    assert res.matched_value == "REAL{bbbb2222}"
    assert [e.value for e in res.evidence] == ["REAL{bbbb2222}"]
    assert any(d.startswith("echo:SHAPE:ECHO{") for d in res.diagnostics)
    # Only the echoed match: no success at any tier.
    assert not check(b"ECHO{aaaa1111}", sent).success
    # Shell tier: an echoed arithmetic answer is dropped too.
    assert not check("SH42OK", "SH42OK").success
    assert check("SH42OK", "SH$((6*7))OK").primary_tier == TIER_SHELL
    # Second uid line survives while the echoed one is dropped.
    res = check("uid=0 uid=1000(x)", "uid=0")
    assert res.matched_value == "uid=1000"


def test_oracle_tier_precedence():
    with private_workspace() as ws:
        rec = mint_marker(ws)
        out = f"{rec.value} uid=1000 FLAG{{abcdef}}"
        res = check(out, b"", planted=rec, workspace=ws)
        assert res.primary_tier == TIER_PLANTED
        assert res.tiers() == [TIER_PLANTED, TIER_SHELL, TIER_SHAPE]
        # Higher match echoed -> yields to a lower clean match.
        res = check(out, f"uid=1000 {rec.value}", planted=rec, workspace=ws)
        assert res.primary_tier == TIER_SHAPE
        cleanup_marker(rec)
    res = check("uid=1000 FLAG{abcdef}", b"")
    assert res.primary_tier == TIER_SHELL and len(res.evidence) == 2


# --- shell proof -----------------------------------------------------------


def test_oracle_shell_proof():
    tok = "tok123"
    probe = strict_probe(tok)
    assert so.strict_marker(tok) not in probe  # the probe never contains the answer
    assert so.ARITH_MARK not in so.ARITH_PROBE
    sent = f"echo {tok}\n{probe}\necho {so.ARITH_PROBE}\nid\n"
    # A reflecting target produces nothing creditable.
    assert not check(sent, sent, token=tok).success
    # A real shell does.
    assert check(f"{tok}_STRICT\n", sent, token=tok).primary_tier == TIER_SHELL
    assert check("SH42OK\n", sent).primary_tier == TIER_SHELL
    assert check("uid=1000(u) gid=1000", sent).primary_tier == TIER_SHELL
    # Plain token echo is not proof.
    assert not check(f"{tok}\n", sent, token=tok).success


# --- shape / override ------------------------------------------------------


def test_oracle_shape_override(monkeypatch):
    assert check("X{abcd}", b"").matched_value == "X{abcd}"
    assert not check("X{abc}", b"").success  # body too short
    # Default carries no platform token and exposes a capture group, not required.
    assert "flag" not in so.NEUTRAL_FLAG_SHAPE.lower()
    monkeypatch.setenv(so.FLAG_RE_ENV, r"PWN-\d+")
    res = check("PWN-42 X{abcd}", b"")
    assert res.evidence[0].value == "PWN-42"
    assert [e.value for e in res.evidence] == ["PWN-42"]  # neutral shape replaced
    # Arg beats env.
    res = check("PWN-42 ZZ-7", b"", flag_pattern=r"ZZ-\d")
    assert res.matched_value == "ZZ-7"
    # Invalid env warns, falls back, visible in diagnostics.
    monkeypatch.setenv(so.FLAG_RE_ENV, "([unclosed")
    with pytest.warns(RuntimeWarning):
        res = check("X{abcd}", b"")
    assert res.matched_value == "X{abcd}"
    assert any(d.startswith("shape_override_invalid") for d in res.diagnostics)
    # Invalid arg also falls back visibly.
    monkeypatch.delenv(so.FLAG_RE_ENV)
    with pytest.warns(RuntimeWarning):
        res = check("X{abcd}", b"", flag_pattern="(")
    assert any("shape_override_invalid" in d for d in res.diagnostics)
    assert res.success


def test_oracle_override_does_not_need_capture_group(monkeypatch):
    monkeypatch.setenv(so.FLAG_RE_ENV, r"zz\d+")
    assert check("zz99", b"").matched_value == "zz99"


# --- result shape ----------------------------------------------------------


def test_oracle_result_and_receipt():
    res = check("nothing here", b"")
    assert res.primary_tier is None and res.success is False
    assert res.evidence == [] and res.matched_value is None
    # bytes / text parity, including non-ASCII.
    for out, sent in [("X{abcd}", ""), ("é X{abcd}", "é")]:
        a = check(out, sent)
        b = check(out.encode(), sent.encode())
        assert (a.primary_tier, a.matched_value, a.success) == (
            b.primary_tier, b.matched_value, b.success)
    assert not check("é-é{abcd}".encode(), "é-é{abcd}").success  # echo across types
    assert check(bytearray(b"X{abcd}"), None).success


# --- marker ----------------------------------------------------------------


def test_oracle_marker_entropy_and_binding():
    with private_workspace() as ws:
        a, b = mint_marker(ws), mint_marker(ws)
        assert len(a.value) >= 32 and int(a.value, 16) >= 0  # 128-bit hex
        assert a.value != b.value and a.attempt_id != b.attempt_id
        assert a.workspace_id is not None and os.path.exists(a.planted_path)
        # Marker from attempt A does not satisfy attempt B.
        assert not check(b.value, b"", planted=a, workspace=ws).success
        assert check(a.value, b"", planted=a, workspace=ws).success
        cleanup_marker(a)
        cleanup_marker(a)  # idempotent
        assert not os.path.exists(a.planted_path) and os.path.exists(b.planted_path)
        cleanup_marker(b)
        assert os.listdir(ws) == []
    assert not os.path.exists(ws)  # workspace removed on exit
    bare = mint_marker()
    assert bare.planted_path is None
    assert not check(bare.value, b"", planted=bare).success


# --- banner words ----------------------------------------------------------


def test_banner_words_are_not_success():
    res = check("Welcome! Congratulations, success!", b"")
    assert res.success is False and res.primary_tier is None and res.evidence == []
    assert {"banner:welcome", "banner:congratulations", "banner:success"} <= set(
        res.diagnostics
    )
