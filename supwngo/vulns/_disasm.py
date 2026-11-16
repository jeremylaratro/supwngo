"""Shared objdump-based disassembly helper for the cheap body-level vuln
detectors (Sprint B2).

Isolated here so ``UAFDetector`` and ``OffByOneDetector`` share one
implementation.

**Honesty contract.** A binary objdump *could not analyze* must not be
indistinguishable from one it analyzed and found nothing in -- otherwise a
host without objdump produces a clean zero-finding report that the adapter
marks ``complete`` (see ``supwngo/reporting/adapter.py``: "a detector that
raised is not a detector that found nothing"). So this helper draws the line:

* objdump ran and produced disassembly  -> the parsed rows (possibly ``[]``);
* the binary has no path (never parsed)  -> ``[]`` (the adapter already reports
  the parse failure separately);
* objdump is absent, not executable (or any other launch ``OSError``), timed
  out, or exited non-zero -> raise :class:`DisassemblyUnavailable`, which the
  detectors let propagate so ``detect_all`` records a ``DetectorFailure`` and the
  report is marked incomplete.
"""
from __future__ import annotations

import re
import subprocess
from typing import List

from supwngo.core.binary import Binary

# A store of an immediate to a memory operand: ``mov [BYTE|DWORD|QWORD] PTR [..],0xNN``.
IMM_STORE = re.compile(r"^mov\s+(?:BYTE|DWORD|QWORD) PTR \[[^\]]+\],0x([0-9a-f]+)$")
# A store clearing a pointer-sized slot to NULL: ``mov QWORD PTR [..],0x0``.
NULL_QWORD_STORE = re.compile(r"^mov\s+QWORD PTR \[[^\]]+\],0x0$")


class DisassemblyUnavailable(RuntimeError):
    """objdump could not be run or did not complete.

    Raised (not swallowed into ``[]``) so a genuinely un-analyzed binary surfaces
    as a ``DetectorFailure`` rather than a silent "found nothing" pass.
    """


def objdump_intel(binary: Binary, timeout: int = 20) -> List[str]:
    """Disassemble ``binary`` with objdump (Intel syntax) and return the list of
    instruction texts (mnemonic + operands) in program order.

    Returns ``[]`` when the binary has no path (it was never parsed; the adapter
    reports that separately) or when objdump produced no matching rows. Raises
    :class:`DisassemblyUnavailable` when objdump is absent, cannot be launched,
    times out, or exits non-zero -- i.e. the analysis did not actually happen.
    """
    path = getattr(binary, "path", None)
    if path is None:
        return []
    try:
        proc = subprocess.run(
            ["objdump", "-d", "-M", "intel", str(path)],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise DisassemblyUnavailable("objdump is not installed") from exc
    except subprocess.TimeoutExpired as exc:
        raise DisassemblyUnavailable(f"objdump timed out after {timeout}s") from exc
    except OSError as exc:
        # Any other launch failure (not executable -> PermissionError, fd or
        # memory exhaustion, ...) still means the binary was not analyzed.
        raise DisassemblyUnavailable(f"objdump could not be launched: {exc}") from exc
    if proc.returncode != 0:
        detail = (proc.stderr or "").strip().splitlines()
        raise DisassemblyUnavailable(
            f"objdump exited {proc.returncode}"
            + (f": {detail[-1]}" if detail else "")
        )

    rows: List[str] = []
    for line in proc.stdout.splitlines():
        # objdump -d rows are "  <addr>:\t<bytes>\t<insn>".
        parts = line.split("\t")
        if len(parts) >= 3 and ":" in parts[0]:
            rows.append(parts[2].strip())
    return rows
