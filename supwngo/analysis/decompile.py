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
import signal
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from supwngo.core.binary import Binary
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


def _kill_process_group(proc: "subprocess.Popen") -> None:
    """SIGKILL a Popen's whole process group, then reap it.

    ``analyzeHeadless`` spawns a JVM (and the JVM a native decompiler), so
    killing only the launcher leaves those descendants alive. The process is
    started with ``start_new_session=True`` (pgid == pid), so ``killpg`` takes
    the whole tree; fall back to a plain kill if the group is already gone, then
    drain and reap so no zombie or dangling pipe is left.
    """
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except Exception:
            pass
    try:
        proc.communicate(timeout=5)
    except Exception:
        try:
            proc.wait(timeout=5)
        except Exception:
            pass


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

        if self._retdec_path:
            result = self._decompile_retdec(func_name, func_addr)
            if result:
                return result

        # Fallback to angr decompilation
        return self._decompile_angr(func_name, func_addr)

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

    def _run_ghidra_headless(self, cmd: List[str], timeout: float) -> bool:
        """Run ``analyzeHeadless`` in its own process group, killable on timeout.

        Returns ``True`` if the process finished within ``timeout`` (the caller
        then inspects the output file — Ghidra's returncode is unreliable), or
        ``False`` if it could not be launched or was force-killed on timeout.
        The whole process group is SIGKILLed and reaped on timeout so no JVM or
        native-decompiler descendant is left behind.
        """
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
        except (OSError, ValueError) as exc:
            logger.warning(f"Could not launch Ghidra: {exc}")
            return False

        try:
            _out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            logger.warning("Ghidra decompilation timed out after %ss; killing", timeout)
            _kill_process_group(proc)
            return False
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning(f"Ghidra decompilation errored: {exc}")
            _kill_process_group(proc)
            return False

        if proc.returncode not in (0, None):
            # A non-zero rc may still have run the postScript (which writes the
            # output file), so do not hard-fail here; just record a bounded tail.
            logger.warning(
                "Ghidra exited %s: %s", proc.returncode, (err or "")[-300:]
            )
        return True

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

    def _decompile_ghidra(self, func_name: Optional[str],
                          func_addr: Optional[int]) -> Optional[DecompiledFunction]:
        """Decompile using Ghidra headless.

        Drives the shipped ``SupwngoDecompile.java`` GhidraScript from its own
        directory, with a bounded, killable budget. On success sets
        ``analysis_backend = "ghidra"`` and returns the function; on any failure
        mode (missing script, launch failure, timeout, no/empty/malformed output,
        or output with no usable pseudo-C) returns ``None`` so the caller degrades
        to RetDec/angr.
        """
        if not self._ghidra_path:
            return None

        script_path = self._ghidra_scripts_dir() / GHIDRA_SCRIPT_NAME
        if not script_path.is_file():
            logger.warning("Ghidra decompile script missing: %s", script_path)
            return None

        logger.info("Decompiling with Ghidra...")
        selector = self._ghidra_selector(func_name, func_addr)

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
                    "-deleteProject",
                ]

                if not self._run_ghidra_headless(cmd, self._ghidra_timeout):
                    return None

                data = self._read_ghidra_output(output_file)
                if data is None:
                    return None
                if not data:
                    # Script ran cleanly but selected/decompiled nothing.
                    logger.info("Ghidra ran but produced no decompiled function")
                    return None

                result = self._parse_ghidra_output(data)
                if result is None or not (result.code and result.code.strip()):
                    logger.warning("Ghidra output had no usable pseudo-C")
                    return None

                self.analysis_backend = "ghidra"
                return result
        except Exception as exc:
            logger.warning(f"Ghidra decompilation failed: {exc}")

        return None

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
        try:
            data = run_angr_op(str(self.binary.path), "decompile", self._angr_timeout,
                               func_name=func_name, func_addr=func_addr)
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
            address=data["address"],
            return_type=data["return_type"],
            code=data["code"],
            calls=list(data["calls"]),
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
            or not isinstance(address, int)
            or isinstance(address, bool)
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
