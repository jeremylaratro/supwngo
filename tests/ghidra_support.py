"""Gate for tool-tier tests that need a real Ghidra (not a test module).

Import with ``sys.path.insert(0, str(Path(__file__).parent))`` first, as the
passcard tests import ``passcard_support``.

A tool-tier test calls :func:`need_ghidra` first. It runs when
``SUPWNGO_REQUIRE_GHIDRA=1`` (the gate run) or ``SUPWNGO_GHIDRA_TESTS=1`` (the
existing opt-in) is set, and otherwise skips, because each one costs a JVM start.
When Ghidra is missing it **fails** under ``SUPWNGO_REQUIRE_GHIDRA=1`` instead of
skipping, so a gate run cannot pass by silently not running them.
"""

from __future__ import annotations

import os
import types
from pathlib import Path
from typing import Optional

import pytest

from supwngo.analysis.decompile import Decompiler

REQUIRE_VAR = "SUPWNGO_REQUIRE_GHIDRA"
OPT_IN_VAR = "SUPWNGO_GHIDRA_TESTS"


def ghidra_headless() -> Optional[Path]:
    """The ``analyzeHeadless`` the product would use, or ``None``."""
    return Decompiler(types.SimpleNamespace(path=""))._ghidra_path


def need_ghidra() -> Path:
    """Return ``analyzeHeadless`` or skip/fail the calling test (see module doc)."""
    required = os.environ.get(REQUIRE_VAR) == "1"
    if not (required or os.environ.get(OPT_IN_VAR)):
        pytest.skip(f"tool-tier Ghidra test: set {REQUIRE_VAR}=1 (or {OPT_IN_VAR}=1)")
    path = ghidra_headless()
    if path is None:
        if required:
            pytest.fail(f"{REQUIRE_VAR}=1 but analyzeHeadless was not found")
        pytest.skip("analyzeHeadless not installed")
    return path
