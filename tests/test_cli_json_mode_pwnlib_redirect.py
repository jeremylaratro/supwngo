"""RT-02 regression: ``--json`` commands must emit exactly one JSON document.

The defect: ``heap-analysis``/``integer-analysis`` (and any analyzer that probes
addresses outside the ELF) printed pwntools log lines like
``[ERROR] Address 0x402000 is not contained in ELF(...)`` to **stdout** ahead of
the JSON object, so the output did not parse. ``_json_mode`` muted supwngo's own
Rich loggers and angr/cle/claripy, but pwnlib's console handler streams to
``context.log_console`` (default ``sys.stdout``) and ``ELF.read`` logs at ERROR
level before raising -- which ``log_level="error"`` does not filter.

The fix repoints ``context.log_console`` to ``sys.stderr`` inside ``_json_mode``
and restores it in ``_reset_console``. These tests pin both halves: the redirect
(so stdout stays pure JSON) and the symmetric restore (so a ``--json`` command
cannot leave pwnlib logging pinned to stderr for a later human-mode command in
the same process).
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from pwnlib.context import context

from supwngo.cli import _json_mode, _reset_console

_HTB = Path(__file__).parent / "htb-targets" / "organized"
# Binaries whose analysis probes an out-of-ELF address and so reproduced the
# original stdout contamination.
_CONTAMINATING = ["sick_rop", "snow_scan", "bon-nie-appetit"]


@pytest.fixture(autouse=True)
def _restore_streams():
    """Keep this module's console surgery from leaking into other tests."""
    saved = context.log_console
    try:
        yield
    finally:
        context.log_console = saved
        _reset_console()


def test_json_mode_redirects_pwnlib_console_to_stderr():
    """RED on base: ``_json_mode`` never touched ``context.log_console``, so it
    stayed ``sys.stdout`` and pwnlib errors corrupted the JSON."""
    _reset_console()
    assert context.log_console is sys.stdout
    _json_mode()
    assert context.log_console is sys.stderr


def test_reset_console_restores_pwnlib_console_to_stdout():
    """The symmetric undo: after a --json command, the next command's
    ``_reset_console`` must hand stdout back to pwnlib for human output."""
    _json_mode()
    assert context.log_console is sys.stderr
    _reset_console()
    assert context.log_console is sys.stdout


@pytest.mark.parametrize("binary", _CONTAMINATING)
@pytest.mark.parametrize("command", ["heap-analysis", "integer-analysis"])
def test_json_command_stdout_is_single_json_document(binary, command):
    """End-to-end at the file-descriptor level (as the retest matrix measures):
    the real stdout of a ``--json`` run must be exactly one parseable JSON object
    with no leading log lines. Skips when the (gitignored) HTB target is absent."""
    target = _HTB / binary
    if not target.exists():
        pytest.skip(f"HTB target {binary} not present (gitignored)")

    proc = subprocess.run(
        [sys.executable, "-m", "supwngo.cli", command, str(target), "--json"],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=str(Path(__file__).parent.parent),
    )
    out = proc.stdout.strip()
    assert out, f"empty stdout; stderr tail: {proc.stderr[-300:]}"
    # Exactly one JSON document: json.loads consumes the whole string.
    data = json.loads(out)
    assert isinstance(data, dict)
    assert "error" not in data
    assert "[ERROR]" not in proc.stdout
