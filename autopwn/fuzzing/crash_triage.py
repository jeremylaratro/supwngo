"""
Crash triage, deduplication, and exploitability analysis.
"""

import hashlib
import os
import re
import signal
import subprocess
import tempfile
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from autopwn.core.binary import Binary
from autopwn.utils.logging import get_logger
from autopwn.utils.helpers import hash_crash

logger = get_logger(__name__)


class Exploitability(Enum):
    """Crash exploitability rating."""
    EXPLOITABLE = auto()
    PROBABLY_EXPLOITABLE = auto()
    PROBABLY_NOT_EXPLOITABLE = auto()
    NOT_EXPLOITABLE = auto()
    UNKNOWN = auto()


class CrashType(Enum):
    """Type of crash."""
    STACK_BUFFER_OVERFLOW = auto()
    HEAP_BUFFER_OVERFLOW = auto()
    USE_AFTER_FREE = auto()
    DOUBLE_FREE = auto()
    NULL_DEREFERENCE = auto()
    INVALID_READ = auto()
    INVALID_WRITE = auto()
    STACK_EXHAUSTION = auto()
    INTEGER_OVERFLOW = auto()
    FORMAT_STRING = auto()
    UNKNOWN = auto()


@dataclass
class CrashCase:
    """
    Represents a unique crash with full analysis.
    """
    # Identification
    crash_hash: str = ""
    input_data: bytes = b""
    input_file: Optional[Path] = None

    # Crash details
    crash_address: int = 0
    crash_type: CrashType = CrashType.UNKNOWN
    signal: str = ""
    signal_code: int = 0

    # Register state
    registers: Dict[str, int] = field(default_factory=dict)

    # Stack information
    backtrace: List[Dict[str, Any]] = field(default_factory=list)
    stack_data: bytes = b""

    # Memory access details
    access_type: str = ""  # read, write, exec
    access_address: int = 0
    access_size: int = 0

    # Exploitability
    exploitability: Exploitability = Exploitability.UNKNOWN
    exploitability_reason: str = ""

    # Control indicators
    pc_control: bool = False
    write_target: Optional[int] = None
    controlled_data: bytes = b""

    # Metadata
    minimized: bool = False
    original_size: int = 0

    def __post_init__(self):
        """Generate hash if not provided."""
        if not self.crash_hash and self.input_data:
            self.crash_hash = hash_crash(self.input_data, self.registers)
        if self.input_data:
            self.original_size = len(self.input_data)


@dataclass
class TriageResult:
    """Results from crash triage."""
    total_crashes: int = 0
    unique_crashes: int = 0
    exploitable: int = 0
    probably_exploitable: int = 0
    crashes: List[CrashCase] = field(default_factory=list)

    def get_best_crashes(self, limit: int = 10) -> List[CrashCase]:
        """Get most promising crashes."""
        # Sort by exploitability
        priority = {
            Exploitability.EXPLOITABLE: 0,
            Exploitability.PROBABLY_EXPLOITABLE: 1,
            Exploitability.UNKNOWN: 2,
            Exploitability.PROBABLY_NOT_EXPLOITABLE: 3,
            Exploitability.NOT_EXPLOITABLE: 4,
        }

        sorted_crashes = sorted(
            self.crashes,
            key=lambda c: (priority.get(c.exploitability, 5), -len(c.input_data))
        )

        return sorted_crashes[:limit]


class CrashTriager:
    """
    Crash triage and exploitability analysis.

    Features:
    - Crash deduplication by hash
    - Crash minimization
    - Exploitability scoring
    - Root cause classification
    """

    def __init__(self, binary: Binary):
        """
        Initialize crash triager.

        Args:
            binary: Target binary
        """
        self.binary = binary
        self._crashes: Dict[str, CrashCase] = {}

    def triage_directory(
        self,
        crash_dir: str,
        minimize: bool = True,
    ) -> TriageResult:
        """
        Triage all crashes in a directory.

        Args:
            crash_dir: Directory containing crash files
            minimize: Whether to minimize crashes

        Returns:
            TriageResult with analyzed crashes
        """
        result = TriageResult()
        crash_path = Path(crash_dir)

        if not crash_path.exists():
            logger.error(f"Crash directory not found: {crash_dir}")
            return result

        # Process each crash file
        crash_files = list(crash_path.glob("*"))
        result.total_crashes = len(crash_files)

        for crash_file in crash_files:
            if crash_file.is_file() and not crash_file.name.startswith("."):
                crash = self.analyze_crash(crash_file)

                if crash and crash.crash_hash not in self._crashes:
                    self._crashes[crash.crash_hash] = crash

                    if minimize:
                        crash = self.minimize_crash(crash)

                    result.crashes.append(crash)

                    if crash.exploitability == Exploitability.EXPLOITABLE:
                        result.exploitable += 1
                    elif crash.exploitability == Exploitability.PROBABLY_EXPLOITABLE:
                        result.probably_exploitable += 1

        result.unique_crashes = len(result.crashes)
        logger.info(
            f"Triaged {result.total_crashes} crashes, "
            f"{result.unique_crashes} unique, "
            f"{result.exploitable} exploitable"
        )

        return result

    def analyze_crash(
        self,
        crash_input: Path | bytes,
    ) -> Optional[CrashCase]:
        """
        Analyze a single crash.

        Args:
            crash_input: Path to crash file or crash bytes

        Returns:
            CrashCase with analysis or None
        """
        # Get input data
        if isinstance(crash_input, Path):
            input_data = crash_input.read_bytes()
            input_file = crash_input
        else:
            input_data = crash_input
            input_file = None

        crash = CrashCase(
            input_data=input_data,
            input_file=input_file,
        )

        # Run with GDB to get crash details
        gdb_info = self._analyze_with_gdb(input_data)

        if not gdb_info.get("crashed", False):
            return None

        # Populate crash details
        crash.signal = gdb_info.get("signal", "")
        crash.crash_address = gdb_info.get("crash_address", 0)
        crash.registers = gdb_info.get("registers", {})
        crash.backtrace = gdb_info.get("backtrace", [])
        crash.access_type = gdb_info.get("access_type", "")
        crash.access_address = gdb_info.get("access_address", 0)

        # Determine crash type and exploitability
        crash.crash_type = self._classify_crash(crash, gdb_info)
        crash.exploitability, crash.exploitability_reason = self._assess_exploitability(
            crash, gdb_info
        )

        # Check for PC control
        crash.pc_control = self._check_pc_control(crash)

        # Generate hash
        crash.crash_hash = self._generate_crash_hash(crash)

        return crash

    def _analyze_with_gdb(self, input_data: bytes) -> Dict[str, Any]:
        """
        Analyze crash using GDB.

        Args:
            input_data: Crashing input

        Returns:
            Dictionary with crash information
        """
        result = {
            "crashed": False,
            "signal": "",
            "crash_address": 0,
            "registers": {},
            "backtrace": [],
            "access_type": "",
            "access_address": 0,
            "instruction": "",
        }

        # Create input file
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(input_data)
            input_file = f.name

        # GDB commands for crash analysis
        gdb_script = f'''
set pagination off
set confirm off
set print repeats 0
run < {input_file}
if $_siginfo
    printf "SIGNAL:%s\\n", $_siginfo.si_signo
    printf "SIGCODE:%d\\n", $_siginfo.si_code
    printf "ADDR:0x%lx\\n", $_siginfo.si_addr
end
printf "PC:0x%lx\\n", $pc
info registers
bt 20
x/i $pc
quit
'''
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.gdb') as f:
            f.write(gdb_script)
            gdb_script_path = f.name

        try:
            proc = subprocess.run(
                ["gdb", "-batch", "-x", gdb_script_path, str(self.binary.path)],
                capture_output=True,
                timeout=30,
                text=True,
            )

            output = proc.stdout + proc.stderr

            # Check for crash
            if "Program received signal" in output:
                result["crashed"] = True

                # Parse signal
                sig_match = re.search(r"Program received signal (\w+)", output)
                if sig_match:
                    result["signal"] = sig_match.group(1)

                # Parse signal info
                sig_addr = re.search(r"ADDR:(0x[0-9a-f]+)", output)
                if sig_addr:
                    result["access_address"] = int(sig_addr.group(1), 16)

                # Parse PC
                pc_match = re.search(r"PC:(0x[0-9a-f]+)", output)
                if pc_match:
                    result["crash_address"] = int(pc_match.group(1), 16)

                # Parse registers
                reg_pattern = r"(\w+)\s+0x([0-9a-f]+)"
                for match in re.finditer(reg_pattern, output):
                    reg_name = match.group(1).lower()
                    reg_value = int(match.group(2), 16)
                    result["registers"][reg_name] = reg_value

                # Parse backtrace
                bt_pattern = r"#(\d+)\s+(?:0x([0-9a-f]+)\s+in\s+)?(\S+)"
                for match in re.finditer(bt_pattern, output):
                    frame = {
                        "frame": int(match.group(1)),
                        "address": int(match.group(2), 16) if match.group(2) else 0,
                        "function": match.group(3),
                    }
                    result["backtrace"].append(frame)

                # Determine access type from signal
                if "SIGSEGV" in result["signal"]:
                    # Try to determine read vs write
                    if "Cannot access memory" in output:
                        result["access_type"] = "read"
                    else:
                        result["access_type"] = "unknown"

        except subprocess.TimeoutExpired:
            logger.debug("GDB analysis timed out")
        except FileNotFoundError:
            logger.warning("GDB not found")
        except Exception as e:
            logger.error(f"GDB analysis failed: {e}")
        finally:
            os.unlink(input_file)
            os.unlink(gdb_script_path)

        return result

    def _classify_crash(
        self,
        crash: CrashCase,
        gdb_info: Dict[str, Any],
    ) -> CrashType:
        """
        Classify crash type.

        Args:
            crash: CrashCase being analyzed
            gdb_info: GDB analysis results

        Returns:
            CrashType classification
        """
        signal = crash.signal
        access_addr = crash.access_address or gdb_info.get("access_address", 0)

        # Check backtrace for hints
        bt_funcs = [frame.get("function", "") for frame in crash.backtrace]
        bt_str = " ".join(bt_funcs)

        # NULL dereference
        if access_addr < 0x1000:
            return CrashType.NULL_DEREFERENCE

        # Heap-related crashes
        if any(f in bt_str for f in ["malloc", "free", "realloc", "__libc_malloc"]):
            if "double free" in bt_str.lower():
                return CrashType.DOUBLE_FREE
            if "free" in bt_str:
                return CrashType.USE_AFTER_FREE
            return CrashType.HEAP_BUFFER_OVERFLOW

        # Stack smashing detection
        if "__stack_chk_fail" in bt_str:
            return CrashType.STACK_BUFFER_OVERFLOW

        # SIGABRT often indicates heap corruption
        if signal == "SIGABRT":
            return CrashType.HEAP_BUFFER_OVERFLOW

        # Check if PC is controlled (likely stack overflow)
        if crash.pc_control:
            return CrashType.STACK_BUFFER_OVERFLOW

        # Default based on signal
        if signal == "SIGSEGV":
            return CrashType.INVALID_READ
        elif signal == "SIGFPE":
            return CrashType.INTEGER_OVERFLOW
        elif signal == "SIGBUS":
            return CrashType.INVALID_READ

        return CrashType.UNKNOWN

    def _assess_exploitability(
        self,
        crash: CrashCase,
        gdb_info: Dict[str, Any],
    ) -> Tuple[Exploitability, str]:
        """
        Assess crash exploitability.

        Based on GDB exploitable plugin methodology.

        Args:
            crash: CrashCase being analyzed
            gdb_info: GDB analysis results

        Returns:
            Tuple of (Exploitability, reason string)
        """
        signal = crash.signal
        regs = crash.registers
        crash_addr = crash.crash_address

        # EXPLOITABLE conditions

        # 1. PC control with pattern
        if crash_addr:
            # Check for controlled PC patterns
            patterns = [0x41414141, 0x4141414141414141, 0x42424242]
            if any(crash_addr == p for p in patterns):
                return (
                    Exploitability.EXPLOITABLE,
                    "Instruction pointer controlled by user input"
                )

            # Partial control
            if crash_addr & 0xFFFF == 0x4141:
                return (
                    Exploitability.EXPLOITABLE,
                    "Partial instruction pointer control"
                )

        # 2. Stack smashing
        bt_funcs = " ".join(f.get("function", "") for f in crash.backtrace)
        if "__stack_chk_fail" in bt_funcs:
            return (
                Exploitability.EXPLOITABLE,
                "Stack buffer overflow detected"
            )

        # 3. Write to controlled address
        if crash.access_type == "write" and crash.access_address:
            if crash.access_address & 0xFFFF == 0x4141:
                return (
                    Exploitability.EXPLOITABLE,
                    "Write to user-controlled address"
                )

        # PROBABLY_EXPLOITABLE conditions

        # 4. Heap corruption (SIGABRT from allocator)
        if signal == "SIGABRT":
            if any(f in bt_funcs for f in ["malloc", "free", "realloc"]):
                return (
                    Exploitability.PROBABLY_EXPLOITABLE,
                    "Heap corruption detected"
                )

        # 5. SIGSEGV with non-null address
        if signal == "SIGSEGV" and crash.access_address:
            if crash.access_address > 0x10000:
                return (
                    Exploitability.PROBABLY_EXPLOITABLE,
                    "Segfault at non-null address"
                )

        # PROBABLY_NOT_EXPLOITABLE conditions

        # 6. NULL pointer dereference
        if crash.access_address and crash.access_address < 0x1000:
            return (
                Exploitability.PROBABLY_NOT_EXPLOITABLE,
                "Near-null pointer dereference"
            )

        # 7. SIGFPE
        if signal == "SIGFPE":
            return (
                Exploitability.PROBABLY_NOT_EXPLOITABLE,
                "Floating point exception"
            )

        # Default
        return (Exploitability.UNKNOWN, "Unable to determine exploitability")

    def _check_pc_control(self, crash: CrashCase) -> bool:
        """
        Check if we control the program counter.

        Args:
            crash: CrashCase to analyze

        Returns:
            True if PC appears controlled
        """
        pc = crash.crash_address
        if not pc:
            return False

        # Check for common patterns
        patterns = [
            0x41414141,  # AAAA
            0x4141414141414141,  # AAAAAAAA
            0x42424242,  # BBBB
            0x43434343,  # CCCC
        ]

        # Direct match
        if pc in patterns:
            return True

        # Partial match (lower bytes)
        if pc & 0xFFFFFFFF == 0x41414141:
            return True
        if pc & 0xFFFF == 0x4141:
            return True

        # Check if PC is in input data
        if crash.input_data:
            pc_bytes_le = pc.to_bytes(8 if self.binary.bits == 64 else 4, 'little')
            if pc_bytes_le in crash.input_data:
                return True

        return False

    def _generate_crash_hash(self, crash: CrashCase) -> str:
        """
        Generate unique hash for crash deduplication.

        Uses crash address + top 3 backtrace frames.

        Args:
            crash: CrashCase to hash

        Returns:
            Hash string
        """
        hasher = hashlib.sha256()

        # Include crash address
        hasher.update(f"addr:{crash.crash_address}".encode())

        # Include signal
        hasher.update(f"sig:{crash.signal}".encode())

        # Include top backtrace frames
        for frame in crash.backtrace[:3]:
            hasher.update(f"bt:{frame.get('function', '')}".encode())

        return hasher.hexdigest()[:16]

    def minimize_crash(
        self,
        crash: CrashCase,
        output_dir: Optional[str] = None,
    ) -> CrashCase:
        """
        Minimize crash input.

        Args:
            crash: CrashCase to minimize
            output_dir: Directory for minimized output

        Returns:
            CrashCase with minimized input
        """
        if crash.minimized:
            return crash

        # Try afl-tmin if available
        import shutil
        afl_tmin = shutil.which("afl-tmin")

        if afl_tmin and crash.input_file:
            with tempfile.NamedTemporaryFile(delete=False) as f:
                min_path = f.name

            try:
                result = subprocess.run(
                    [
                        afl_tmin,
                        "-i", str(crash.input_file),
                        "-o", min_path,
                        "--",
                        str(self.binary.path),
                    ],
                    capture_output=True,
                    timeout=120,
                )

                if result.returncode == 0 and os.path.exists(min_path):
                    min_data = Path(min_path).read_bytes()
                    if len(min_data) < len(crash.input_data):
                        crash.input_data = min_data
                        crash.minimized = True
                        logger.debug(
                            f"Minimized crash: {crash.original_size} -> {len(min_data)}"
                        )

            except Exception as e:
                logger.debug(f"afl-tmin failed: {e}")
            finally:
                if os.path.exists(min_path):
                    os.unlink(min_path)

        return crash

    def deduplicate(
        self,
        crashes: List[CrashCase],
    ) -> List[CrashCase]:
        """
        Remove duplicate crashes.

        Args:
            crashes: List of crashes to deduplicate

        Returns:
            Deduplicated list
        """
        seen_hashes = set()
        unique = []

        for crash in crashes:
            if crash.crash_hash not in seen_hashes:
                seen_hashes.add(crash.crash_hash)
                unique.append(crash)

        return unique

    def generate_report(self, result: TriageResult) -> str:
        """
        Generate triage report.

        Args:
            result: TriageResult to report

        Returns:
            Formatted report string
        """
        lines = [
            "=" * 60,
            "CRASH TRIAGE REPORT",
            "=" * 60,
            f"Binary: {self.binary.path}",
            f"Total crashes: {result.total_crashes}",
            f"Unique crashes: {result.unique_crashes}",
            f"Exploitable: {result.exploitable}",
            f"Probably exploitable: {result.probably_exploitable}",
            "",
            "-" * 60,
            "TOP CRASHES",
            "-" * 60,
        ]

        for i, crash in enumerate(result.get_best_crashes(10), 1):
            lines.extend([
                f"\n[{i}] {crash.crash_hash}",
                f"    Signal: {crash.signal}",
                f"    Address: 0x{crash.crash_address:x}",
                f"    Type: {crash.crash_type.name}",
                f"    Exploitability: {crash.exploitability.name}",
                f"    Reason: {crash.exploitability_reason}",
                f"    Input size: {len(crash.input_data)} bytes",
                f"    PC Control: {'Yes' if crash.pc_control else 'No'}",
            ])

            if crash.backtrace:
                lines.append("    Backtrace:")
                for frame in crash.backtrace[:5]:
                    lines.append(
                        f"      #{frame['frame']} {frame.get('function', '??')}"
                    )

        lines.extend([
            "",
            "=" * 60,
        ])

        return "\n".join(lines)
