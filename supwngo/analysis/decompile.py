"""
Decompilation integration module.

Provides integration with decompilers including:
- Ghidra headless decompilation
- RetDec integration
- Output parsing for variables, types, control flow
- Pseudo-code generation
"""

import json
import math
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from supwngo.core import fileformat, proc
from supwngo.core.binary import Binary
from supwngo.core.proc import ProcState
from supwngo.utils.logging import get_logger

logger = get_logger(__name__)

#: File name of the shipped Ghidra decompilation GhidraScript (see
#: ``supwngo/analysis/ghidra_scripts/``). A ``.java`` script is used because
#: Ghidra 12.x without PyGhidra cannot run ``.py`` scripts.
GHIDRA_SCRIPT_NAME = "SupwngoDecompile.java"

#: Hard ceiling (seconds) for the Ghidra headless budget regardless of the
#: ``SUPWNGO_GHIDRA_TIMEOUT`` override, so "bounded" stays true.
GHIDRA_TIMEOUT_HARD_MAX = 900.0

#: Statuses of the angr decompile op: the worker's tagged union plus the
#: parent-only ``timeout``. Only ``ok`` carries pseudo-C.
ANGR_STATUSES = ("ok", "missing_function", "decompiler_failed", "exception", "timeout")

#: Prefix of the placeholder angr used to emit in place of code. It is never a
#: decompilation, whatever status accompanies it.
ANGR_SENTINEL_PREFIX = "// Decompilation failed"


def _resolve_ghidra_timeout(raw: Any, default: float = 180.0) -> float:
    """Return a finite, positive, hard-capped Ghidra budget in seconds.

    ``raw`` may be ``None`` (use ``default``), a number, or a string from the
    ``SUPWNGO_GHIDRA_TIMEOUT`` environment variable. ``NaN``, infinity, zero,
    negative, or unparseable values fall back to ``default``; anything above
    :data:`GHIDRA_TIMEOUT_HARD_MAX` is clamped, so an override can never defeat
    the bounded-and-killable guarantee.
    """
    if raw is None:
        return default
    try:
        val = float(raw)
    except (TypeError, ValueError):
        return default
    if not math.isfinite(val) or val <= 0:
        return default
    return min(val, GHIDRA_TIMEOUT_HARD_MAX)


#: Default Ghidra budget, resolved once from the environment at import time.
DEFAULT_GHIDRA_TIMEOUT = _resolve_ghidra_timeout(
    os.environ.get("SUPWNGO_GHIDRA_TIMEOUT")
)


#: Longest stdout/stderr tail (characters) a :class:`GhidraRun` keeps.
GHIDRA_TAIL_CHARS = 2000

#: Longest ``ERROR`` line (characters) a :class:`GhidraRun` keeps.
GHIDRA_ERROR_MAX_CHARS = 400

_GHIDRA_ERROR_LINE = re.compile(r"^\s*ERROR\b")
#: Ghidra prefixes a script's own ``printerr`` with its file name.
_GHIDRA_SCRIPT_ERROR_LINE = re.compile(r"^\s*ERROR\s+SupwngoDecompile\.java>")
#: A benign analyzer complaint (e.g. MinGW's pseudo-relocation list) ends with
#: ``(<Name>Analyzer)``. ``(HeadlessAnalyzer)`` is the headless runner, not an
#: analyzer, and is a real failure.
_GHIDRA_ANALYZER_LINE = re.compile(r"\((?!Headless)\w*Analyzer\)\s*$")


def _ghidra_error_line(stdout: str) -> str:
    """The ``ERROR`` line of a Ghidra run that explains a failure, bounded.

    In order of preference: a line our own script emitted; the first line that
    is not an analyzer message; the first ``ERROR`` line. The length bound
    applies to what is kept, not to what is matched.
    """
    errors = [ln.strip() for ln in stdout.splitlines() if _GHIDRA_ERROR_LINE.match(ln)]
    for keep in (
        lambda ln: _GHIDRA_SCRIPT_ERROR_LINE.match(ln),
        lambda ln: not _GHIDRA_ANALYZER_LINE.search(ln),
        lambda ln: True,
    ):
        for ln in errors:
            if keep(ln):
                return ln[:GHIDRA_ERROR_MAX_CHARS]
    return ""


def _is_int(value: Any) -> bool:
    """True for an ``int`` that is not a ``bool``."""
    return isinstance(value, int) and not isinstance(value, bool)


@dataclass
class GhidraRun:
    """Structured outcome of one ``analyzeHeadless`` run (SP-01b V-11).

    ``state`` is the :class:`~supwngo.core.proc.ProcState` of the process;
    ``rc``/``signal``/``errno`` are set as ``ProcResult`` sets them. The tails
    are bounded to :data:`GHIDRA_TAIL_CHARS`; ``first_error`` is the
    ``ERROR`` line of the *whole* stdout (not just the tail) that best explains
    the failure, which is where Ghidra reports why it refused to run: our own
    script's line, else the first non-analyzer line, else the first one.
    """

    state: ProcState
    rc: Optional[int] = None
    signal: Optional[int] = None
    errno: Optional[int] = None
    stdout_tail: str = ""
    stderr_tail: str = ""
    first_error: str = ""
    wall_s: float = 0.0
    timeout_s: float = 0.0

    @property
    def finished(self) -> bool:
        """True when the process ran to an end the output file can be read after.

        Ghidra's return code is unreliable (the postScript may have written its
        output before a non-zero exit), so any ended process counts; only a
        timeout kill or a failed launch does not.
        """
        return self.state in (ProcState.EXITED, ProcState.SIGNALED)

    @property
    def error(self) -> str:
        """Why the run failed, or ``""`` for a clean exit with no ``ERROR`` line."""
        if self.state is ProcState.SPAWN_ERROR:
            return f"could not launch Ghidra (errno {self.errno})"
        if self.state is ProcState.TIMEOUT:
            return f"Ghidra timed out after {self.timeout_s:g}s and was killed"
        if self.first_error:
            return self.first_error
        if self.state is ProcState.SIGNALED:
            return f"Ghidra was killed by signal {self.signal}"
        if self.rc:
            last = next(
                (ln.strip() for ln in reversed(self.stderr_tail.splitlines())
                 if ln.strip()),
                "",
            )
            return f"Ghidra exited {self.rc}" + (f": {last}" if last else "")
        return ""


@dataclass
class DecompiledVariable:
    """Variable extracted from decompilation."""
    name: str
    type_str: str
    offset: Optional[int] = None  # Stack offset if local
    size: int = 0
    is_parameter: bool = False
    is_local: bool = False
    is_global: bool = False


@dataclass
class DecompiledFunction:
    """Decompiled function information."""
    name: str
    address: int
    return_type: str
    parameters: List[DecompiledVariable] = field(default_factory=list)
    locals: List[DecompiledVariable] = field(default_factory=list)
    code: str = ""
    calls: List[str] = field(default_factory=list)
    strings_used: List[str] = field(default_factory=list)
    complexity_hints: Dict[str, Any] = field(default_factory=dict)
    #: How the function was chosen: ``name``/``addr`` for an explicit request, or
    #: the default-selection step that matched (``symbol``, ``libc_start_main_arg``,
    #: ``mingw_crt_main_arg``, ``entry``, ``first_reachable``). ``""`` if unknown.
    selected_by: str = ""


class Decompiler:
    """
    Decompiler integration for binary analysis.

    Integrates with Ghidra and RetDec to provide:
    - Human-readable pseudo-code
    - Variable and type information
    - Control flow insights
    """

    def __init__(self, binary: Binary, angr_timeout: Optional[float] = None,
                 ghidra_timeout: Optional[float] = None):
        """
        Initialize decompiler.

        Args:
            binary: Binary instance to decompile
            angr_timeout: Wall-clock budget (seconds) for the angr decompilation
                fallback before giving up. ``None`` uses the module default
                (``SUPWNGO_ANGR_TIMEOUT`` or 30 s).
            ghidra_timeout: Wall-clock budget (seconds) for the Ghidra headless
                subprocess before it is force-killed. ``None`` uses the module
                default (``SUPWNGO_GHIDRA_TIMEOUT`` or 180 s); any value is
                validated and hard-capped by :func:`_resolve_ghidra_timeout`.
        """
        from supwngo.analysis._angr_subprocess import DEFAULT_ANGR_TIMEOUT

        self.binary = binary
        self.decompiled_functions: Dict[str, DecompiledFunction] = {}
        self._ghidra_path = self._find_ghidra()
        self._retdec_path = self._find_retdec()
        self._angr_timeout = DEFAULT_ANGR_TIMEOUT if angr_timeout is None else angr_timeout
        self._ghidra_timeout = (
            DEFAULT_GHIDRA_TIMEOUT if ghidra_timeout is None
            else _resolve_ghidra_timeout(ghidra_timeout)
        )
        #: Provenance of the decompilation backend actually used. Starts at the
        #: angr fallback; flips to ``"ghidra"`` only when Ghidra returns usable
        #: pseudo-C.
        self.analysis_backend: str = "angr"
        self.angr_budget_exceeded: bool = False
        #: Outcome of the last angr decompile (one of :data:`ANGR_STATUSES`), and
        #: the worker's diagnostic for a failure. Empty until angr has run.
        self.angr_status: str = ""
        self.angr_error: str = ""
        #: The last Ghidra run (``None`` until Ghidra has been launched) and why
        #: the last Ghidra attempt produced nothing (``""`` after a success). Kept
        #: through the RetDec and angr fallbacks so the cause is not lost when a
        #: later backend also fails.
        self.ghidra_run: Optional[GhidraRun] = None
        self.ghidra_error: str = ""
        #: The loader's verdict on the entry point the default selection used
        #: (``"ok"``, a mismatch note, or ``""`` when no default was selected).
        self.ghidra_entry_check: str = ""

    def _find_ghidra(self) -> Optional[Path]:
        """Find Ghidra installation."""
        # Check environment variable
        ghidra_home = os.environ.get("GHIDRA_HOME")
        if ghidra_home:
            path = Path(ghidra_home) / "support" / "analyzeHeadless"
            if path.exists():
                return path

        # Check common locations
        common_paths = [
            Path("/opt/ghidra/support/analyzeHeadless"),
            Path("/usr/share/ghidra/support/analyzeHeadless"),
            Path.home() / "ghidra" / "support" / "analyzeHeadless",
            Path.home() / ".local" / "share" / "ghidra" / "support" / "analyzeHeadless",
        ]

        for path in common_paths:
            if path.exists():
                return path

        # Try to find via which
        try:
            result = subprocess.run(["which", "analyzeHeadless"],
                                  capture_output=True, text=True)
            if result.returncode == 0:
                return Path(result.stdout.strip())
        except Exception:
            pass

        return None

    def _find_retdec(self) -> Optional[Path]:
        """Find RetDec installation."""
        # Check environment
        retdec_path = os.environ.get("RETDEC_PATH")
        if retdec_path:
            path = Path(retdec_path) / "bin" / "retdec-decompiler"
            if path.exists():
                return path

        # Check common locations
        common_paths = [
            Path("/usr/bin/retdec-decompiler"),
            Path("/usr/local/bin/retdec-decompiler"),
            Path.home() / ".local" / "bin" / "retdec-decompiler",
        ]

        for path in common_paths:
            if path.exists():
                return path

        # Try which
        try:
            result = subprocess.run(["which", "retdec-decompiler"],
                                  capture_output=True, text=True)
            if result.returncode == 0:
                return Path(result.stdout.strip())
        except Exception:
            pass

        return None

    def decompile(self, func_name: Optional[str] = None,
                  func_addr: Optional[int] = None,
                  use_ghidra: bool = True) -> Optional[DecompiledFunction]:
        """
        Decompile a function.

        Args:
            func_name: Function name to decompile
            func_addr: Function address to decompile
            use_ghidra: Prefer Ghidra over RetDec

        Returns:
            DecompiledFunction or None
        """
        if use_ghidra and self._ghidra_path:
            result = self._decompile_ghidra(func_name, func_addr)
            if result:
                return result

        # RetDec has no default-function search: for an empty selector it would
        # fabricate ``main``, so it only runs when a function was asked for.
        explicit = bool(func_name) or func_addr is not None
        if self._retdec_path and explicit:
            result = self._decompile_retdec(func_name, func_addr)
            if result:
                return result

        # Fallback to angr decompilation
        return self._decompile_angr(func_name, func_addr)

    def _file_base(self) -> Optional[int]:
        """The file's link-time base: the address convention ``objdump``/``nm`` use.

        ``min(PT_LOAD.p_vaddr)`` for an ELF, ``ImageBase`` for a PE, ``None`` for
        anything else (or a truncated file), in which case a backend's address is
        reported as the backend gave it.
        """
        path = self.binary.path
        kind = fileformat.detect_format(path)
        if kind == fileformat.ELF:
            elf = fileformat.elf_info(path)
            return elf.min_load_vaddr if elf else None
        if kind == fileformat.PE:
            pe = fileformat.pe_info(path)
            return pe.image_base if pe else None
        return None

    def _entry_info(self) -> Tuple[str, Optional[int]]:
        """``(format, entry offset from the file base)`` for the default search.

        The offset is ``e_entry - min(PT_LOAD.p_vaddr)`` for an ELF and
        ``AddressOfEntryPoint`` for a PE, so a backend can add it to its own
        image base. ``None`` when the file has no usable entry point.
        """
        path = self.binary.path
        kind = fileformat.detect_format(path)
        if kind == fileformat.ELF:
            elf = fileformat.elf_info(path)
            if elf and elf.e_entry and elf.min_load_vaddr is not None:
                return kind, elf.e_entry - elf.min_load_vaddr
        elif kind == fileformat.PE:
            pe = fileformat.pe_info(path)
            if pe and pe.entry_rva:
                return kind, pe.entry_rva
        return (kind if kind in (fileformat.ELF, fileformat.PE) else "unknown"), None

    @staticmethod
    def _explicit_selected_by(func_name: Optional[str],
                              func_addr: Optional[int]) -> str:
        """``selected_by`` of an explicit request: the name wins, as in the selector."""
        if func_name:
            return "name"
        return "addr" if func_addr is not None else ""

    @staticmethod
    def _to_file_address(address: int, backend_base: int,
                         file_base: Optional[int]) -> int:
        """Map a backend address to the file convention (SP-01b V-10).

        ``file_base + (address - backend_base)``: each backend reports its own
        base (Ghidra's image base, angr's ``mapped_base``), so no constant such
        as ``0x100000`` or ``0x400000`` is assumed. With no file base the address
        is returned unchanged.
        """
        if file_base is None:
            return address
        return file_base + (address - backend_base)

    def _ghidra_scripts_dir(self) -> Path:
        """Directory holding the shipped Ghidra GhidraScript(s).

        A dedicated, near-empty directory is mandatory: Ghidra enumerates every
        file in each ``-scriptPath`` dir to classify scripts, so pointing it at a
        crowded directory wedges postScript resolution.
        """
        return Path(__file__).resolve().parent / "ghidra_scripts"

    @staticmethod
    def _ghidra_selector(func_name: Optional[str],
                         func_addr: Optional[int]) -> str:
        """Build the tagged selector argument for the GhidraScript.

        Name takes precedence over address (``decompile_all`` passes both), so a
        function is selected by name when one is given. An empty selector lets
        the script fall back to ``main``/first function.
        """
        if func_name:
            return f"name:{func_name}"
        if func_addr is not None:
            return f"addr:{hex(func_addr)}"
        return ""

    def _run_ghidra_headless(self, cmd: List[str], timeout: float) -> GhidraRun:
        """Run ``analyzeHeadless`` in its own process group, killable on timeout.

        Returns a :class:`GhidraRun` carrying the process state, bounded
        stdout/stderr tails and the first ``ERROR`` line of stdout. A caller
        reads the output file after any run that ``finished`` (Ghidra's return
        code is unreliable); a timeout or a failed launch did not. The runner
        (``supwngo.core.proc.run``) SIGKILLs and reaps the whole process group on
        timeout, so no JVM or native-decompiler descendant is left behind.
        """
        try:
            cwd = os.getcwd()
        except OSError:
            cwd = tempfile.gettempdir()
        result = proc.run(cmd, cwd=cwd, timeout=timeout)

        stdout = result.stdout.decode("utf-8", errors="replace")
        stderr = result.stderr.decode("utf-8", errors="replace")
        first_error = _ghidra_error_line(stdout)
        return GhidraRun(
            state=result.state,
            rc=result.rc,
            signal=result.signal,
            errno=result.errno,
            stdout_tail=stdout[-GHIDRA_TAIL_CHARS:],
            stderr_tail=stderr[-GHIDRA_TAIL_CHARS:],
            first_error=first_error,
            wall_s=result.wall_s,
            timeout_s=float(timeout),
        )

    @staticmethod
    def _read_ghidra_output(output_file: Path) -> Optional[List[Dict]]:
        """Read and validate the GhidraScript's JSON array.

        Returns the parsed list (possibly empty) on success, or ``None`` when the
        file is missing, empty, malformed, or not a JSON array — i.e. the script
        never produced a usable result.
        """
        if not output_file.exists():
            logger.warning("Ghidra produced no output file")
            return None
        raw = output_file.read_text(encoding="utf-8", errors="replace").strip()
        if not raw:
            logger.warning("Ghidra output file was empty")
            return None
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            logger.warning(f"Ghidra output was not valid JSON: {exc}")
            return None
        if not isinstance(data, list):
            logger.warning("Ghidra output was not a JSON array")
            return None
        return data

    def _ghidra_failed(self, reason: str) -> None:
        """Record why Ghidra produced nothing and log it; always returns ``None``."""
        self.ghidra_error = reason
        logger.warning("Ghidra produced no pseudo-C: %s", reason)
        return None

    def _decompile_ghidra(self, func_name: Optional[str],
                          func_addr: Optional[int]) -> Optional[DecompiledFunction]:
        """Decompile using Ghidra headless.

        Drives the shipped ``SupwngoDecompile.java`` GhidraScript from its own
        directory, with a bounded, killable budget. On success sets
        ``analysis_backend = "ghidra"`` and returns the function; on any failure
        mode (missing script, launch failure, timeout, no/empty/malformed output,
        or output with no usable pseudo-C) returns ``None`` so the caller degrades
        to RetDec/angr. The structured run and the reason are kept in
        ``ghidra_run`` / ``ghidra_error`` for the caller to report.
        """
        if not self._ghidra_path:
            return None

        self.ghidra_run, self.ghidra_error = None, ""
        script_path = self._ghidra_scripts_dir() / GHIDRA_SCRIPT_NAME
        if not script_path.is_file():
            return self._ghidra_failed(f"decompile script missing: {script_path}")

        logger.info("Decompiling with Ghidra...")
        selector = self._ghidra_selector(func_name, func_addr)
        file_base = self._file_base()
        # The script maps an explicit address into Ghidra's own base with the file
        # base, and adds the entry offset to that base to find the entry function.
        file_base_arg = "none" if file_base is None else hex(file_base)
        file_format, entry_rva = self._entry_info()
        entry_arg = "none" if entry_rva is None else hex(entry_rva)
        self.ghidra_entry_check = ""

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                project_dir = Path(tmpdir) / "project"
                project_dir.mkdir()
                output_file = Path(tmpdir) / "decompiled.json"

                cmd = [
                    str(self._ghidra_path),
                    str(project_dir),
                    "SupwngoTmp",
                    "-import", str(self.binary.path),
                    "-scriptPath", str(script_path.parent),
                    "-postScript", GHIDRA_SCRIPT_NAME, selector, str(output_file),
                    file_base_arg, entry_arg, file_format,
                    "-deleteProject",
                ]

                run = self._run_ghidra_headless(cmd, self._ghidra_timeout)
                self.ghidra_run = run
                if not run.finished:
                    return self._ghidra_failed(run.error)

                data = self._read_ghidra_output(output_file)
                if data is None:
                    return self._ghidra_failed(
                        run.error or "Ghidra wrote no usable output file"
                    )
                if not data:
                    # Script ran cleanly but selected/decompiled nothing.
                    logger.info("Ghidra ran but produced no decompiled function")
                    return self._ghidra_failed(
                        run.first_error or "Ghidra selected no function to decompile"
                    )

                result = self._parse_ghidra_output(data)
                if result is None or not (result.code and result.code.strip()):
                    return self._ghidra_failed("Ghidra output had no usable pseudo-C")

                backend_base = data[0].get("backend_base")
                if not _is_int(backend_base) or not _is_int(result.address):
                    return self._ghidra_failed(
                        "Ghidra output has no integer address/backend_base, "
                        "so its address cannot be normalised"
                    )
                result.address = self._to_file_address(
                    result.address, backend_base, file_base
                )

                self.ghidra_entry_check = str(data[0].get("entry_check") or "")
                if self.ghidra_entry_check not in ("", "ok"):
                    logger.warning(
                        "Ghidra entry point check: %s", self.ghidra_entry_check
                    )
                self.analysis_backend = "ghidra"
                return result
        except Exception as exc:
            return self._ghidra_failed(f"{type(exc).__name__}: {exc}")

    def _parse_ghidra_output(self, data: List[Dict]) -> Optional[DecompiledFunction]:
        """Parse Ghidra JSON output."""
        if not data:
            return None

        func_data = data[0]

        # Parse code for variables and calls
        code = func_data.get("code", "")
        variables = self._parse_variables_from_code(code)
        calls = self._parse_calls_from_code(code)
        strings = self._parse_strings_from_code(code)

        return DecompiledFunction(
            name=func_data.get("name", "unknown"),
            address=func_data.get("address", 0),
            return_type=func_data.get("return_type", "void"),
            parameters=[v for v in variables if v.is_parameter],
            locals=[v for v in variables if v.is_local],
            code=code,
            calls=calls,
            strings_used=strings,
            selected_by=str(func_data.get("selected_by") or ""),
        )

    def _decompile_retdec(self, func_name: Optional[str],
                          func_addr: Optional[int]) -> Optional[DecompiledFunction]:
        """Decompile using RetDec."""
        if not self._retdec_path:
            return None

        logger.info("Decompiling with RetDec...")

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                output_c = Path(tmpdir) / "output.c"

                cmd = [
                    str(self._retdec_path),
                    str(self.binary.path),
                    "-o", str(output_c),
                ]

                if func_addr:
                    cmd.extend(["--select-ranges", f"{hex(func_addr)}-{hex(func_addr + 0x1000)}"])

                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

                if output_c.exists():
                    code = output_c.read_text()
                    return self._parse_retdec_output(code, func_name, func_addr)

        except subprocess.TimeoutExpired:
            logger.warning("RetDec decompilation timed out")
        except Exception as e:
            logger.warning(f"RetDec decompilation failed: {e}")

        return None

    def _parse_retdec_output(self, code: str, func_name: Optional[str],
                             func_addr: Optional[int]) -> Optional[DecompiledFunction]:
        """Parse RetDec C output."""
        # Extract specific function if requested
        if func_name:
            pattern = rf'{func_name}\s*\([^)]*\)\s*\{{[^}}]*\}}'
            match = re.search(pattern, code, re.DOTALL)
            if match:
                code = match.group()

        variables = self._parse_variables_from_code(code)
        calls = self._parse_calls_from_code(code)
        strings = self._parse_strings_from_code(code)

        return DecompiledFunction(
            name=func_name or "main",
            address=func_addr or 0,
            return_type="int",
            parameters=[v for v in variables if v.is_parameter],
            locals=[v for v in variables if v.is_local],
            code=code,
            calls=calls,
            strings_used=strings,
            selected_by=self._explicit_selected_by(func_name, func_addr),
        )

    def _decompile_angr(self, func_name: Optional[str],
                        func_addr: Optional[int]) -> Optional[DecompiledFunction]:
        """Fallback decompilation using angr, isolated in a budgeted subprocess.

        Both the ``CFGFast`` build and the ``Decompiler`` analysis run in a
        spawned child (either can run unbounded C-level work on a large binary);
        on a budget blow-out the child's process group is killed and this returns
        ``None`` -- the prior failure behaviour -- while recording that it
        degraded via ``analysis_backend`` / ``angr_budget_exceeded`` (RT-05).

        The child replies with a tagged union (see ``_op_decompile``). The reply
        is validated here, the outcome is recorded in ``angr_status`` /
        ``angr_error``, and every status but ``ok`` returns ``None``: a reply
        that is not the union, or an ``ok`` whose body is empty or the
        ``// Decompilation failed`` placeholder, is never a function.
        """
        from supwngo.analysis._angr_subprocess import (
            AnalysisBudgetExceeded,
            run_angr_op,
        )

        self.angr_status, self.angr_error = "", ""
        file_base = self._file_base()
        file_format, _entry = self._entry_info()
        try:
            data = run_angr_op(str(self.binary.path), "decompile", self._angr_timeout,
                               func_name=func_name, func_addr=func_addr,
                               file_base=file_base, file_format=file_format)
        except AnalysisBudgetExceeded as e:
            logger.warning(
                f"angr decompilation exceeded its {self._angr_timeout:g}s budget "
                f"({e}); no pseudo-C produced"
            )
            self.angr_budget_exceeded = True
            self.analysis_backend = "none"
            self.angr_status, self.angr_error = "timeout", str(e)
            return None
        except Exception as e:
            logger.warning(f"angr decompilation failed: {e}")
            self.analysis_backend = "none"
            self.angr_status, self.angr_error = "exception", str(e)
            return None

        status, error = self._check_angr_reply(data)
        self.angr_status, self.angr_error = status, error
        if status != "ok":
            if status == "exception":
                self.analysis_backend = "none"
            logger.warning(f"angr decompilation produced no pseudo-C: {status}: {error}")
            return None

        self.analysis_backend = "angr"
        return DecompiledFunction(
            name=data["name"],
            address=self._to_file_address(
                data["address"], data["backend_base"], file_base
            ),
            return_type=data["return_type"],
            code=data["code"],
            calls=list(data["calls"]),
            selected_by=data["selected_by"],
        )

    @staticmethod
    def _check_angr_reply(data: Any) -> Tuple[str, str]:
        """Classify a worker reply as ``(status, error)``.

        ``("ok", "")`` only for a well-formed ``ok`` reply. A failure status is
        passed through with the worker's ``error``. Anything that is not the
        union (a non-dict, an unknown or missing status such as the legacy
        ``found`` shape, an ``ok`` without its fields) is ``exception``; an
        ``ok`` whose code is empty or the placeholder is ``decompiler_failed``.
        """
        if not isinstance(data, dict):
            return "exception", f"worker reply is not an object: {type(data).__name__}"
        status = data.get("status")
        if status not in ANGR_STATUSES or status == "timeout":
            return "exception", f"worker reply has no valid status: {status!r}"
        if status != "ok":
            return status, str(data.get("error") or "")

        name, address = data.get("name"), data.get("address")
        code, calls = data.get("code"), data.get("calls")
        if (
            not isinstance(name, str)
            or not _is_int(address)
            or not _is_int(data.get("backend_base"))
            or not isinstance(data.get("selected_by"), str)
            or not data.get("selected_by")
            or not isinstance(data.get("return_type"), str)
            or not isinstance(code, str)
            or not isinstance(calls, list)
        ):
            return "exception", "ok reply is missing or mistypes its fields"
        if not code.strip() or code.lstrip().startswith(ANGR_SENTINEL_PREFIX):
            return "decompiler_failed", "ok reply carries no real pseudo-C"
        return "ok", ""

    def _parse_variables_from_code(self, code: str) -> List[DecompiledVariable]:
        """Parse variable declarations from C code."""
        variables = []

        # Pattern for local variable declarations
        # Matches: type name; or type name = value;
        local_pattern = r'^\s*(\w+(?:\s*\*)*)\s+(\w+)(?:\s*=\s*[^;]+)?;'

        # Pattern for parameters
        param_pattern = r'\(([^)]*)\)'

        # Extract parameters from function signature
        param_match = re.search(param_pattern, code)
        if param_match:
            params_str = param_match.group(1)
            for param in params_str.split(','):
                param = param.strip()
                if param and param != 'void':
                    parts = param.rsplit(None, 1)
                    if len(parts) == 2:
                        type_str, name = parts
                        variables.append(DecompiledVariable(
                            name=name.strip('*'),
                            type_str=type_str,
                            is_parameter=True,
                        ))

        # Extract local variables
        for line in code.split('\n'):
            if '=' in line or ';' in line:
                match = re.match(local_pattern, line)
                if match:
                    type_str = match.group(1)
                    name = match.group(2)
                    # Skip if it's a function call
                    if '(' not in line.split('=')[0] if '=' in line else '(' not in line:
                        variables.append(DecompiledVariable(
                            name=name,
                            type_str=type_str,
                            is_local=True,
                        ))

        return variables

    def _parse_calls_from_code(self, code: str) -> List[str]:
        """Parse function calls from C code."""
        calls = []

        # Pattern for function calls
        call_pattern = r'\b(\w+)\s*\('

        for match in re.finditer(call_pattern, code):
            func_name = match.group(1)
            # Skip C keywords
            if func_name not in ('if', 'while', 'for', 'switch', 'return', 'sizeof'):
                if func_name not in calls:
                    calls.append(func_name)

        return calls

    def _parse_strings_from_code(self, code: str) -> List[str]:
        """Parse string literals from C code."""
        strings = []

        # Pattern for string literals
        string_pattern = r'"([^"\\]*(?:\\.[^"\\]*)*)"'

        for match in re.finditer(string_pattern, code):
            string_value = match.group(1)
            if string_value and string_value not in strings:
                strings.append(string_value)

        return strings

    def decompile_all(self, max_functions: int = 100) -> Dict[str, DecompiledFunction]:
        """
        Decompile all functions in the binary.

        Args:
            max_functions: Maximum number of functions to decompile

        Returns:
            Dictionary mapping function names to decompiled functions
        """
        logger.info(f"Decompiling up to {max_functions} functions...")

        # Get function list
        functions = list(self.binary.symbols.items())[:max_functions]

        for name, symbol in functions:
            result = self.decompile(func_name=name, func_addr=symbol.address)
            if result:
                self.decompiled_functions[name] = result

        return self.decompiled_functions

    def find_vulnerabilities_in_decompiled(self) -> List[Dict[str, Any]]:
        """
        Find potential vulnerabilities in decompiled code.

        Returns:
            List of potential vulnerability findings
        """
        vulns = []

        dangerous_patterns = [
            (r'\bgets\s*\(', "gets() - Buffer overflow", "CRITICAL"),
            (r'\bstrcpy\s*\(', "strcpy() - Buffer overflow", "HIGH"),
            (r'\bsprintf\s*\(', "sprintf() - Buffer overflow", "HIGH"),
            (r'\bstrcat\s*\(', "strcat() - Buffer overflow", "HIGH"),
            (r'\bscanf\s*\([^,]*,\s*[^,]*\)', "scanf() without width", "MEDIUM"),
            (r'\bsystem\s*\(', "system() - Command injection", "HIGH"),
            (r'\bpopen\s*\(', "popen() - Command injection", "HIGH"),
            (r'\bprintf\s*\([^"]*\)', "printf() with non-literal format", "MEDIUM"),
            (r'\bfree\s*\([^)]+\).*\bfree\s*\(', "Double free pattern", "HIGH"),
        ]

        for name, func in self.decompiled_functions.items():
            for pattern, description, severity in dangerous_patterns:
                if re.search(pattern, func.code):
                    vulns.append({
                        "function": name,
                        "address": hex(func.address),
                        "pattern": pattern,
                        "description": description,
                        "severity": severity,
                    })

        return vulns

    def get_available_decompilers(self) -> List[str]:
        """Get list of available decompilers."""
        available = []

        if self._ghidra_path:
            available.append(f"ghidra ({self._ghidra_path})")
        if self._retdec_path:
            available.append(f"retdec ({self._retdec_path})")

        # angr is always available if installed
        try:
            import angr
            available.append("angr (builtin)")
        except ImportError:
            pass

        return available

    def summary(self) -> str:
        """Get decompilation summary."""
        lines = [
            "Decompilation Summary",
            "=" * 40,
            f"Available Decompilers: {', '.join(self.get_available_decompilers()) or 'None'}",
            f"Decompiled Functions: {len(self.decompiled_functions)}",
            "",
        ]

        if self.decompiled_functions:
            lines.append("Decompiled:")
            for name, func in list(self.decompiled_functions.items())[:10]:
                lines.append(f"  {name} @ 0x{func.address:x} ({len(func.code)} chars)")

        return "\n".join(lines)
