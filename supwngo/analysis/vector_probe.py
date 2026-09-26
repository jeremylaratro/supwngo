"""
Advisory input-vector probe (S2, docs/plans/2026-09-26-sprint2prime-input-vector-plan.md,
REVISION 3).

``classify_input_vector()`` is a **behavioral, advisory-only** heuristic for
guessing whether a target's exploitable input arrives on stdin or via a file
named in argv. It exists because ``detect_input_sources()``
(``supwngo/analysis/static.py``) cannot serve as a vector oracle: a
statically-linked target has no PLT entries at all, and ``read`` -- the
stdin primitive -- is indistinguishable there from real file I/O (see B-2,
``docs/plans/2026-09-26-legacy-to-canonical-gap-analysis.md``).

**THIS PROBE MUST NEVER BE TREATED AS AUTHORITATIVE.** It never touches, and
must never be given, an ``ExploitContext`` or any other mutable pipeline
state -- it takes a binary path and returns a plain, inert result object.
A ``"file-candidate"`` verdict is a *report*, not a decision: only an
explicit operator option (e.g. engine ``input_vector="file"`` /
CLI ``--input-vector file``) may ever commit a ``DeliverySpec`` to one of
the file sinks (``SINK_FILE_ARGV``/``SINK_FILE_FIXED`` --
``supwngo.exploit.pipeline.contracts``). This split exists because a false
positive here does **not** degrade safely -- it would silently suppress a
target's working stdin delivery and could regress an otherwise-solvable
target. Rounds 2 and 3 of this sprint's peer review both returned
NOT-APPROVED on exactly this class (an authoritative probe with a real,
reproducible false-positive fixture: ``neg_argv_config_stdin_payload`` was
misclassified as a file vector under the 3-stage design). The design that
survived review removes the probe's authority rather than chasing further
accuracy fixes -- see REVISION 3 in the plan doc for the full history.

There is also a known, *undefended* residual gap, stated rather than hidden:
a target that gates on file **format** (e.g. rejects a payload before
opening it based on a signature check) can present identically for a
32-byte and a 4096-byte probe file, masking the content-volume signal stage
3 relies on, and will be classified ``argv-only-config`` rather than
``file-candidate`` even though it genuinely is a file-vector target. That
class of target is solvable only via the explicit operator option -- this
probe will not and cannot flag it, by design (see B-3 in the gap analysis).

Algorithm (this exact 4-stage form is the one that survived round-3 review;
it is deliberately not "improved" here):

- Run the target **directly** (never through a bundled loader -- production
  spawns targets directly, so the probe must match that construction) with
  stdin redirected from ``/dev/null``, capturing stdout+stderr combined,
  and comparing only the first 300 bytes of that combined output.
- **Stage 0 (determinism):** run the no-argv condition twice. If the two
  runs differ, the target is not a pure function of its input under this
  harness and no later stage's difference is attributable --
  ``"inconclusive-nondeterministic"``. If the launch itself fails (OSError,
  including ENOENT/EACCES) or times out, ``"inconclusive-launch"``.
- **Extension discovery:** search the no-argv output and the output of a
  bogus, nonexistent-path run for a ``\\.([a-z]{2,4})\\b`` token; the first
  match found (e.g. ``.bmp``) is used, else the probe defaults to ``.bin``.
- **Stage 1 (argv sensitivity):** compare the no-argv output against the
  output when given a *missing* path bearing the discovered extension. If
  identical, the target never even looks at argv for this purpose --
  ``"stdin"``.
- **Stage 2 (causal file open):** compare the missing-path output against
  an *existing, readable* path of the same extension (32 bytes of ``b"A"``).
  If identical, the target counted argv but never opened/read the file --
  ``"argv-only-not-opened"``.
- **Stage 3 (content volume):** compare a 32-byte file against a 4096-byte
  file of the same extension, comparing both output *and* return code. If
  they differ, the target's behavior depends on file content, not just its
  presence -- ``"file-candidate"``. If identical, the file is read but only
  used as configuration, not as the payload sink -- ``"argv-only-config"``.

Every stage's raw evidence (booleans + truncated outputs) is recorded on the
returned result's ``.evidence`` so a human can audit exactly which
comparison produced the verdict, rather than trusting the label alone.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

#: How many bytes of combined stdout+stderr are compared/recorded per run.
TRUNCATE_BYTES = 300

#: Fallback extension when no ``\.([a-z]{2,4})\b`` token is found in either
#: probe output.
DEFAULT_EXTENSION = ".bin"

_EXTENSION_RE = re.compile(r"\.([a-z]{2,4})\b")

VERDICT_STDIN = "stdin"
VERDICT_ARGV_ONLY_NOT_OPENED = "argv-only-not-opened"
VERDICT_ARGV_ONLY_CONFIG = "argv-only-config"
VERDICT_FILE_CANDIDATE = "file-candidate"
VERDICT_INCONCLUSIVE_LAUNCH = "inconclusive-launch"
VERDICT_INCONCLUSIVE_NONDETERMINISTIC = "inconclusive-nondeterministic"


@dataclass
class VectorProbeResult:
    """Advisory result of ``classify_input_vector()``.

    ``verdict`` is one of the module-level ``VERDICT_*`` strings.
    ``evidence`` carries the per-stage booleans and truncated outputs that
    produced the verdict, for human audit. ``extension`` is the
    (auto-discovered, or default) extension used for the probe's temp
    files -- callers that go on to build a real ``DeliverySpec`` after an
    explicit operator decision may reuse it as a starting point for
    ``payload_filename``, but nothing here commits to it.
    """
    verdict: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    extension: str = DEFAULT_EXTENSION


def _run(argv, timeout: float, env: Optional[Dict[str, str]]):
    """Launch ``argv`` directly (no bundled loader), stdin from
    ``/dev/null``, capturing stdout+stderr combined. Returns
    ``(returncode, first_300_bytes_as_text)``. Raises ``OSError`` (including
    ``FileNotFoundError``/``PermissionError``) or
    ``subprocess.TimeoutExpired`` on launch failure -- callers route both to
    ``"inconclusive-launch"``."""
    with open(os.devnull, "rb") as devnull:
        proc = subprocess.run(
            list(argv),
            stdin=devnull,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            env=env,
        )
    text = proc.stdout[:TRUNCATE_BYTES].decode("latin-1", "replace")
    return proc.returncode, text


#: Sentinel (returncode, output) pair used by ``_run_tolerant`` when the
#: process hangs or fails to launch past stage 0. ``None`` is never a real
#: ``subprocess`` returncode, so it compares unequal to every genuine
#: ``(rc, text)`` pair -- exactly what a stage-1..3 comparison needs.
_UNREACHABLE_RC = None


def _run_tolerant(argv, timeout: float, env: Optional[Dict[str, str]]):
    """Like ``_run``, but never raises.

    Past stage 0, a target that hangs or fails to launch on one probe file
    but not another is not a probe malfunction -- it *is* the behavioral
    signal stage 2/3 are looking for (e.g. ``mech_line_text``: an
    unbounded, unterminated ``fgets()`` read on a 4096-byte no-newline file
    smashes the stack badly enough to hang rather than segfault, while the
    32-byte file returns cleanly -- that difference is exactly what should
    surface as ``"file-candidate"``, not crash the probe). Only stage 0's
    own launch (see ``_run``'s callers) is treated as disqualifying --
    ``"inconclusive-launch"`` establishes the binary runs at all; everything
    after that has already cleared that bar, so a later timeout is data,
    not an error to propagate.
    """
    try:
        return _run(argv, timeout, env)
    except subprocess.TimeoutExpired:
        return _UNREACHABLE_RC, "<TIMEOUT: process did not exit within timeout>"
    except OSError as exc:
        return _UNREACHABLE_RC, f"<LAUNCH ERROR: {exc!r}>"


def classify_input_vector(
    binary_path: str,
    *,
    timeout: float = 5.0,
    env: Optional[Dict[str, str]] = None,
) -> VectorProbeResult:
    """Advisory-only classification of ``binary_path``'s input vector.

    See the module docstring: this is a heuristic report, never an
    authoritative decision. It takes no ``ExploitContext`` and mutates
    nothing -- callers must not wire a ``"file-candidate"`` verdict
    straight into a ``DeliverySpec`` without an explicit operator option in
    between.
    """
    evidence: Dict[str, Any] = {}
    tmpdir = tempfile.mkdtemp(prefix="supwngo_vector_probe_")
    try:
        # --- Stage 0: determinism of the no-argv launch. ---
        try:
            rc1, out1 = _run([binary_path], timeout, env)
            rc2, out2 = _run([binary_path], timeout, env)
        except (OSError, subprocess.TimeoutExpired) as exc:
            evidence["launch_error"] = repr(exc)
            return VectorProbeResult(
                verdict=VERDICT_INCONCLUSIVE_LAUNCH,
                evidence=evidence,
                extension=DEFAULT_EXTENSION,
            )

        evidence["no_argv_run1"] = {"rc": rc1, "output": out1}
        evidence["no_argv_run2"] = {"rc": rc2, "output": out2}
        deterministic = (rc1, out1) == (rc2, out2)
        evidence["stage0_deterministic"] = deterministic
        if not deterministic:
            return VectorProbeResult(
                verdict=VERDICT_INCONCLUSIVE_NONDETERMINISTIC,
                evidence=evidence,
                extension=DEFAULT_EXTENSION,
            )

        # --- Extension discovery: a bogus, nonexistent path. ---
        bogus_path = os.path.join(tmpdir, "bogus_nonexistent_probe")
        try:
            rc_bogus, out_bogus = _run([binary_path, bogus_path], timeout, env)
        except (OSError, subprocess.TimeoutExpired) as exc:
            evidence["launch_error"] = repr(exc)
            return VectorProbeResult(
                verdict=VERDICT_INCONCLUSIVE_LAUNCH,
                evidence=evidence,
                extension=DEFAULT_EXTENSION,
            )
        evidence["bogus_path_run"] = {"rc": rc_bogus, "output": out_bogus}

        match = _EXTENSION_RE.search(out1) or _EXTENSION_RE.search(out_bogus)
        extension = ("." + match.group(1)) if match else DEFAULT_EXTENSION
        evidence["extension_match"] = match.group(0) if match else None
        evidence["extension"] = extension

        # --- Stage 1: argv sensitivity -- a missing path with the
        # discovered extension. ---
        missing_path = os.path.join(tmpdir, "missing_input" + extension)
        rc_missing, out_missing = _run_tolerant([binary_path, missing_path], timeout, env)
        evidence["missing_path_run"] = {"rc": rc_missing, "output": out_missing}
        stage1_argv_sensitive = (rc1, out1) != (rc_missing, out_missing)
        evidence["stage1_argv_sensitive"] = stage1_argv_sensitive
        if not stage1_argv_sensitive:
            return VectorProbeResult(
                verdict=VERDICT_STDIN, evidence=evidence, extension=extension,
            )

        # --- Stage 2: causal file open -- existing, readable, same
        # extension, 32 bytes. ---
        small_path = os.path.join(tmpdir, "existing_small" + extension)
        with open(small_path, "wb") as fh:
            fh.write(b"A" * 32)
        rc_small, out_small = _run_tolerant([binary_path, small_path], timeout, env)
        evidence["small_file_run"] = {"rc": rc_small, "output": out_small}
        stage2_opened = (rc_missing, out_missing) != (rc_small, out_small)
        evidence["stage2_opened"] = stage2_opened
        if not stage2_opened:
            return VectorProbeResult(
                verdict=VERDICT_ARGV_ONLY_NOT_OPENED,
                evidence=evidence,
                extension=extension,
            )

        # --- Stage 3: content volume -- 32-byte vs 4096-byte, same
        # extension, comparing output AND return code. ---
        large_path = os.path.join(tmpdir, "existing_large" + extension)
        with open(large_path, "wb") as fh:
            fh.write(b"A" * 4096)
        rc_large, out_large = _run_tolerant([binary_path, large_path], timeout, env)
        evidence["large_file_run"] = {"rc": rc_large, "output": out_large}
        stage3_volume_sensitive = (rc_small, out_small) != (rc_large, out_large)
        evidence["stage3_volume_sensitive"] = stage3_volume_sensitive

        if stage3_volume_sensitive:
            return VectorProbeResult(
                verdict=VERDICT_FILE_CANDIDATE, evidence=evidence, extension=extension,
            )
        return VectorProbeResult(
            verdict=VERDICT_ARGV_ONLY_CONFIG, evidence=evidence, extension=extension,
        )
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
