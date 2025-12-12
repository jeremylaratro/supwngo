"""
Dynamic binary analysis using tracing and instrumentation.
"""

import os
import re
import signal
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from autopwn.core.binary import Binary
from autopwn.utils.logging import get_logger
from autopwn.utils.helpers import run_command

logger = get_logger(__name__)


@dataclass
class LibraryCall:
    """Represents a library function call."""
    function: str
    args: List[str]
    return_value: Optional[str] = None
    address: int = 0


@dataclass
class SystemCall:
    """Represents a system call."""
    name: str
    args: List[str]
    return_value: str = ""
    errno: Optional[str] = None


@dataclass
class MemoryAccess:
    """Represents a memory access."""
    address: int
    size: int
    type: str  # read, write, exec
    value: Optional[bytes] = None


@dataclass
class CoverageInfo:
    """Code coverage information."""
    basic_blocks: set = field(default_factory=set)
    edges: set = field(default_factory=set)
    functions: set = field(default_factory=set)
    coverage_percent: float = 0.0


@dataclass
class ExecutionTrace:
    """Complete execution trace."""
    library_calls: List[LibraryCall] = field(default_factory=list)
    system_calls: List[SystemCall] = field(default_factory=list)
    memory_accesses: List[MemoryAccess] = field(default_factory=list)
    signals: List[Tuple[int, str]] = field(default_factory=list)
    exit_code: Optional[int] = None
    crashed: bool = False
    crash_address: int = 0
    crash_signal: str = ""


class DynamicAnalyzer:
    """
    Dynamic binary analysis through execution tracing.

    Uses ltrace, strace, and GDB for dynamic analysis.
    """

    def __init__(self, binary: Binary):
        """
        Initialize dynamic analyzer.

        Args:
            binary: Binary to analyze
        """
        self.binary = binary
        self.traces: List[ExecutionTrace] = []

    def run_with_input(
        self,
        input_data: bytes,
        timeout: int = 30,
        env: Optional[Dict[str, str]] = None,
    ) -> ExecutionTrace:
        """
        Run binary with input and collect trace.

        Args:
            input_data: Input to send to stdin
            timeout: Execution timeout
            env: Environment variables

        Returns:
            ExecutionTrace with execution information
        """
        trace = ExecutionTrace()

        try:
            # Run with timeout
            result = subprocess.run(
                [str(self.binary.path)],
                input=input_data,
                capture_output=True,
                timeout=timeout,
                env=env,
            )
            trace.exit_code = result.returncode

        except subprocess.TimeoutExpired:
            logger.debug("Execution timed out")
            trace.exit_code = -1

        except Exception as e:
            logger.error(f"Execution failed: {e}")

        self.traces.append(trace)
        return trace

    def trace_ltrace(
        self,
        input_data: bytes,
        timeout: int = 30,
    ) -> List[LibraryCall]:
        """
        Trace library calls using ltrace.

        Args:
            input_data: Input to send to stdin
            timeout: Execution timeout

        Returns:
            List of LibraryCall instances
        """
        calls = []

        # Create temp file for input
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(input_data)
            input_file = f.name

        try:
            result = subprocess.run(
                ["ltrace", "-e", "*", str(self.binary.path)],
                stdin=open(input_file, "rb"),
                capture_output=True,
                timeout=timeout,
                text=True,
            )

            # Parse ltrace output
            for line in result.stderr.split("\n"):
                call = self._parse_ltrace_line(line)
                if call:
                    calls.append(call)

        except FileNotFoundError:
            logger.warning("ltrace not found")
        except subprocess.TimeoutExpired:
            logger.debug("ltrace timed out")
        except Exception as e:
            logger.error(f"ltrace failed: {e}")
        finally:
            os.unlink(input_file)

        return calls

    def _parse_ltrace_line(self, line: str) -> Optional[LibraryCall]:
        """Parse a line of ltrace output."""
        # Pattern: function(args...) = return_value
        pattern = r"(\w+)\((.*?)\)\s*=\s*(.+)"
        match = re.match(pattern, line)

        if match:
            func_name = match.group(1)
            args_str = match.group(2)
            ret_val = match.group(3).strip()

            # Parse arguments (simplified)
            args = [a.strip() for a in args_str.split(",")] if args_str else []

            return LibraryCall(
                function=func_name,
                args=args,
                return_value=ret_val,
            )

        return None

    def trace_strace(
        self,
        input_data: bytes,
        timeout: int = 30,
    ) -> List[SystemCall]:
        """
        Trace system calls using strace.

        Args:
            input_data: Input to send to stdin
            timeout: Execution timeout

        Returns:
            List of SystemCall instances
        """
        syscalls = []

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(input_data)
            input_file = f.name

        try:
            result = subprocess.run(
                ["strace", "-f", str(self.binary.path)],
                stdin=open(input_file, "rb"),
                capture_output=True,
                timeout=timeout,
                text=True,
            )

            for line in result.stderr.split("\n"):
                syscall = self._parse_strace_line(line)
                if syscall:
                    syscalls.append(syscall)

        except FileNotFoundError:
            logger.warning("strace not found")
        except subprocess.TimeoutExpired:
            logger.debug("strace timed out")
        except Exception as e:
            logger.error(f"strace failed: {e}")
        finally:
            os.unlink(input_file)

        return syscalls

    def _parse_strace_line(self, line: str) -> Optional[SystemCall]:
        """Parse a line of strace output."""
        # Pattern: syscall(args...) = return_value
        pattern = r"(\w+)\((.*?)\)\s*=\s*(-?\d+|0x[0-9a-f]+)(?:\s+(\w+))?"
        match = re.match(pattern, line)

        if match:
            syscall_name = match.group(1)
            args_str = match.group(2)
            ret_val = match.group(3)
            errno = match.group(4)

            args = [a.strip() for a in args_str.split(",")] if args_str else []

            return SystemCall(
                name=syscall_name,
                args=args,
                return_value=ret_val,
                errno=errno,
            )

        return None

    def get_coverage(
        self,
        inputs: List[bytes],
        timeout: int = 30,
    ) -> CoverageInfo:
        """
        Collect code coverage information.

        Args:
            inputs: List of inputs to test
            timeout: Timeout per input

        Returns:
            CoverageInfo with coverage data
        """
        coverage = CoverageInfo()

        # Try to use angr for coverage collection
        try:
            import angr

            proj = self.binary.get_angr_project()
            cfg = proj.analyses.CFGFast()

            total_blocks = len(list(cfg.graph.nodes()))
            total_functions = len(cfg.kb.functions)

            # Track covered blocks
            for input_data in inputs:
                state = proj.factory.entry_state(
                    stdin=angr.SimFile(name="stdin", content=input_data)
                )
                simgr = proj.factory.simgr(state)

                # Run with step limit
                for _ in range(1000):
                    if not simgr.active:
                        break
                    simgr.step()

                    for s in simgr.active:
                        coverage.basic_blocks.add(s.addr)
                        if s.addr in cfg.kb.functions:
                            coverage.functions.add(s.addr)

            if total_blocks > 0:
                coverage.coverage_percent = (
                    len(coverage.basic_blocks) / total_blocks * 100
                )

        except Exception as e:
            logger.debug(f"Could not collect coverage with angr: {e}")

        return coverage

    def check_crash(
        self,
        input_data: bytes,
        timeout: int = 10,
    ) -> Tuple[bool, Optional[ExecutionTrace]]:
        """
        Check if input causes a crash.

        Args:
            input_data: Input to test
            timeout: Execution timeout

        Returns:
            Tuple of (crashed, trace)
        """
        trace = ExecutionTrace()

        try:
            result = subprocess.run(
                [str(self.binary.path)],
                input=input_data,
                capture_output=True,
                timeout=timeout,
            )

            trace.exit_code = result.returncode

            # Check for crash signals
            if result.returncode < 0:
                sig = -result.returncode
                trace.crashed = True
                trace.crash_signal = signal.Signals(sig).name
                logger.debug(f"Crash detected: {trace.crash_signal}")
                return True, trace

        except subprocess.TimeoutExpired:
            trace.exit_code = -1
            return False, trace

        except Exception as e:
            logger.error(f"Error checking crash: {e}")

        return False, trace

    def analyze_crash_gdb(
        self,
        input_data: bytes,
        timeout: int = 30,
    ) -> Dict[str, Any]:
        """
        Analyze crash with GDB to get detailed information.

        Args:
            input_data: Crashing input
            timeout: GDB timeout

        Returns:
            Dictionary with crash analysis
        """
        result = {
            "crashed": False,
            "signal": "",
            "address": 0,
            "registers": {},
            "backtrace": [],
            "instruction": "",
            "exploitability": "UNKNOWN",
        }

        # Create input file
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(input_data)
            input_file = f.name

        # GDB commands
        gdb_commands = """
set pagination off
set confirm off
run < {input_file}
info registers
bt
x/i $pc
quit
""".format(input_file=input_file)

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.gdb') as f:
            f.write(gdb_commands)
            gdb_script = f.name

        try:
            proc = subprocess.run(
                ["gdb", "-batch", "-x", gdb_script, str(self.binary.path)],
                capture_output=True,
                timeout=timeout,
                text=True,
            )

            output = proc.stdout + proc.stderr

            # Parse signal
            sig_match = re.search(r"Program received signal (\w+)", output)
            if sig_match:
                result["crashed"] = True
                result["signal"] = sig_match.group(1)

            # Parse registers
            reg_pattern = r"(\w+)\s+0x([0-9a-f]+)"
            for match in re.finditer(reg_pattern, output):
                result["registers"][match.group(1)] = int(match.group(2), 16)

            # Get PC/RIP for crash address
            if "rip" in result["registers"]:
                result["address"] = result["registers"]["rip"]
            elif "eip" in result["registers"]:
                result["address"] = result["registers"]["eip"]
            elif "pc" in result["registers"]:
                result["address"] = result["registers"]["pc"]

            # Parse backtrace
            bt_pattern = r"#(\d+)\s+0x([0-9a-f]+)\s+in\s+(\S+)"
            for match in re.finditer(bt_pattern, output):
                result["backtrace"].append({
                    "frame": int(match.group(1)),
                    "address": int(match.group(2), 16),
                    "function": match.group(3),
                })

            # Simple exploitability heuristic
            result["exploitability"] = self._assess_exploitability(result)

        except subprocess.TimeoutExpired:
            logger.warning("GDB analysis timed out")
        except FileNotFoundError:
            logger.warning("GDB not found")
        except Exception as e:
            logger.error(f"GDB analysis failed: {e}")
        finally:
            os.unlink(input_file)
            os.unlink(gdb_script)

        return result

    def _assess_exploitability(self, crash_info: Dict[str, Any]) -> str:
        """
        Assess exploitability of a crash.

        Args:
            crash_info: Crash analysis dictionary

        Returns:
            Exploitability string
        """
        signal = crash_info.get("signal", "")
        regs = crash_info.get("registers", {})

        # Check for PC control
        pc = crash_info.get("address", 0)
        if pc:
            # Pattern suggesting controlled PC
            if pc == 0x41414141 or pc == 0x4141414141414141:
                return "EXPLOITABLE"
            if pc & 0xFFFF == 0x4141:
                return "PROBABLY_EXPLOITABLE"

        # SIGSEGV on write
        if signal == "SIGSEGV":
            # Check if we control destination of write
            # This is a simplified heuristic
            return "PROBABLY_EXPLOITABLE"

        # SIGABRT often indicates heap corruption
        if signal == "SIGABRT":
            return "PROBABLY_EXPLOITABLE"

        # SIGFPE might be integer overflow
        if signal == "SIGFPE":
            return "PROBABLY_NOT_EXPLOITABLE"

        return "UNKNOWN"

    def find_format_string_offset(
        self,
        prefix: bytes = b"",
        suffix: bytes = b"\n",
    ) -> Optional[int]:
        """
        Find format string argument offset.

        Args:
            prefix: Bytes before format string
            suffix: Bytes after format string

        Returns:
            Argument offset or None
        """
        # Try different offsets
        for offset in range(1, 50):
            # Create test payload
            payload = prefix + f"AAAA%{offset}$x".encode() + suffix

            try:
                result = subprocess.run(
                    [str(self.binary.path)],
                    input=payload,
                    capture_output=True,
                    timeout=5,
                )

                # Check if we see our marker
                if b"41414141" in result.stdout:
                    logger.debug(f"Found format string offset: {offset}")
                    return offset

            except Exception:
                continue

        return None

    def find_buffer_overflow_offset(
        self,
        pattern_length: int = 500,
    ) -> Optional[int]:
        """
        Find buffer overflow offset using cyclic pattern.

        Args:
            pattern_length: Length of cyclic pattern

        Returns:
            Offset to return address or None
        """
        from autopwn.utils.helpers import cyclic, cyclic_find

        pattern = cyclic(pattern_length)

        crash_info = self.analyze_crash_gdb(pattern)

        if crash_info["crashed"]:
            pc = crash_info.get("address", 0)
            if pc:
                offset = cyclic_find(pc, pattern_length)
                if offset >= 0:
                    logger.debug(f"Found overflow offset: {offset}")
                    return offset

        return None

    def summary(self) -> str:
        """Get dynamic analysis summary."""
        lines = [
            "Dynamic Analysis Summary",
            "=" * 40,
            f"Traces collected: {len(self.traces)}",
        ]

        for i, trace in enumerate(self.traces):
            lines.append(f"\nTrace {i + 1}:")
            lines.append(f"  Exit code: {trace.exit_code}")
            lines.append(f"  Crashed: {trace.crashed}")
            if trace.crashed:
                lines.append(f"  Signal: {trace.crash_signal}")
                lines.append(f"  Address: 0x{trace.crash_address:x}")
            lines.append(f"  Library calls: {len(trace.library_calls)}")
            lines.append(f"  System calls: {len(trace.system_calls)}")

        return "\n".join(lines)
