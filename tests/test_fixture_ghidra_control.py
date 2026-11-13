"""Integrity of the Ghidra control-cell fixture (plan §8.1 V-2, N5-6).

This pins the committed bytes and the facts the passcard control cell will rely
on. It never invokes Ghidra: that is slow and gated, and it is the control
cell's own job at run time.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

FIXTURE_DIR = Path(__file__).resolve().parent.parent / (
    "benchmark/fixtures/ghidra_control"
)
EXPECT = yaml.safe_load((FIXTURE_DIR / "expect.yaml").read_text())
BINARY = FIXTURE_DIR / EXPECT["binary"]

needs_nm = pytest.mark.skipif(shutil.which("nm") is None, reason="nm not installed")


def _nm(*args: str) -> str:
    result = subprocess.run(
        ["nm", *args, str(BINARY)], capture_output=True, text=True, timeout=30
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


def test_expect_yaml_carries_every_field_the_control_cell_needs():
    assert EXPECT["selector"] == "ghidra_control"
    assert EXPECT["analysis_backend"] == "ghidra"
    assert EXPECT["rc"] == 0
    assert EXPECT["json_documents"] == 1
    assert EXPECT["anchors"]["calls"] == ["puts"]
    assert isinstance(EXPECT["address"], int)
    assert len(EXPECT["sha256"]) == 64


def test_committed_binary_matches_the_pinned_sha256():
    digest = hashlib.sha256(BINARY.read_bytes()).hexdigest()
    assert digest == EXPECT["sha256"], (
        "ghidra_control.elf changed: rebuild per the commands in expect.yaml "
        "and re-pin, or restore the committed binary"
    )


def test_binary_is_non_pie():
    # ET_EXEC (2), not ET_DYN (3): the nm address is the Ghidra address.
    header = BINARY.read_bytes()[:20]
    assert header[:4] == b"\x7fELF"
    assert int.from_bytes(header[16:18], "little") == 2


@needs_nm
def test_nm_reports_the_pinned_address_for_the_selector():
    symbols = {}
    for line in _nm().splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] == "T":
            symbols[parts[2]] = int(parts[0], 16)
    assert symbols.get(EXPECT["selector"]) == EXPECT["address"]


@needs_nm
def test_binary_imports_the_anchor_call():
    imported = {
        line.split()[-1].split("@")[0]
        for line in _nm("-D").splitlines()
        if line.split()[:1] == ["U"]
    }
    for anchor in EXPECT["anchors"]["calls"]:
        assert anchor in imported
