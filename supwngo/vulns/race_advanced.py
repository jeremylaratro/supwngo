"""
Advanced race condition detection module.

Provides comprehensive race condition analysis including:
- File operation races (TOCTOU)
- Signal handler analysis
- Thread safety analysis
- Atomic operation detection
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from enum import Enum, auto

from supwngo.core.binary import Binary
from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


class AdvancedRaceType(Enum):
    """Types of advanced race conditions."""
    FILE_TOCTOU = auto()
    SIGNAL_HANDLER = auto()
    THREAD_UNSAFE = auto()
    MISSING_ATOMIC = auto()
    DOUBLE_FETCH = auto()
    LOCK_BYPASS = auto()
    REENTRANCY = auto()


class ThreadContext(Enum):
    """Thread context for race analysis."""
    MAIN_THREAD = auto()
    WORKER_THREAD = auto()
    SIGNAL_HANDLER = auto()
    UNKNOWN = auto()


@dataclass
class RaceWindow:
    """Represents a race window between operations."""
    start_addr: int
    end_addr: int
    start_op: str
    end_op: str
    shared_resource: str
    window_size: int  # Instructions between check and use
    exploitability: str


@dataclass
class SignalHandlerInfo:
    """Information about a signal handler."""
    handler_addr: int
    signal_num: int
    signal_name: str
    is_reentrant: bool
    async_unsafe_calls: List[str]
    shared_vars: List[str]


@dataclass
class ThreadUnsafeCall:
    """Thread-unsafe function call."""
    address: int
    function: str
    caller: str
    reason: str
    safe_alternative: Optional[str] = None


@dataclass
class AdvancedRaceVuln:
    """Advanced race condition vulnerability."""
    race_type: AdvancedRaceType
    severity: str
    address: int
    function: str
    description: str
    window: Optional[RaceWindow] = None
    signal_info: Optional[SignalHandlerInfo] = None
    thread_call: Optional[ThreadUnsafeCall] = None
    exploit_template: str = ""
    confidence: float = 0.5


class AdvancedRaceAnalyzer:
    """
    Advanced race condition analyzer.

    Analyzes binaries for:
    - TOCTOU vulnerabilities in file operations
    - Signal handler re-entrancy issues
    - Thread-unsafe function usage
    - Missing atomic operations
    """

    # Thread-unsafe functions and their safe alternatives
    THREAD_UNSAFE_FUNCS = {
        'strtok': ('strtok_r', 'Uses static buffer'),
        'localtime': ('localtime_r', 'Uses static buffer'),
        'gmtime': ('gmtime_r', 'Uses static buffer'),
        'ctime': ('ctime_r', 'Uses static buffer'),
        'asctime': ('asctime_r', 'Uses static buffer'),
        'rand': ('rand_r', 'Uses global state'),
        'getenv': (None, 'Environment may change'),
        'setenv': (None, 'Modifies global environment'),
        'gethostbyname': ('getaddrinfo', 'Uses static buffer'),
        'gethostbyaddr': ('getnameinfo', 'Uses static buffer'),
        'inet_ntoa': ('inet_ntop', 'Uses static buffer'),
        'readdir': ('readdir_r', 'Uses static buffer'),
        'getpwnam': ('getpwnam_r', 'Uses static buffer'),
        'getpwuid': ('getpwuid_r', 'Uses static buffer'),
        'getgrnam': ('getgrnam_r', 'Uses static buffer'),
        'getgrgid': ('getgrgid_r', 'Uses static buffer'),
    }

    # Async-signal-unsafe functions
    ASYNC_UNSAFE_FUNCS = {
        'printf', 'fprintf', 'sprintf', 'snprintf',
        'malloc', 'free', 'realloc', 'calloc',
        'fopen', 'fclose', 'fread', 'fwrite',
        'exit', 'abort',
        'pthread_mutex_lock', 'pthread_mutex_unlock',
        'dlopen', 'dlsym', 'dlclose',
        'getenv', 'setenv',
    }

    # File operation pairs that could be TOCTOU
    TOCTOU_PAIRS = [
        ('access', 'open'),
        ('stat', 'open'),
        ('lstat', 'open'),
        ('access', 'fopen'),
        ('stat', 'fopen'),
        ('access', 'chmod'),
        ('stat', 'chmod'),
        ('access', 'chown'),
        ('access', 'unlink'),
        ('access', 'rename'),
        ('readlink', 'open'),
    ]

    def __init__(self, binary: Binary):
        """
        Initialize race analyzer.

        Args:
            binary: Binary instance to analyze
        """
        self.binary = binary
        self.vulnerabilities: List[AdvancedRaceVuln] = []
        self.signal_handlers: List[SignalHandlerInfo] = []
        self.thread_unsafe_calls: List[ThreadUnsafeCall] = []

    def analyze(self) -> List[AdvancedRaceVuln]:
        """
        Perform comprehensive race condition analysis.

        Returns:
            List of detected race vulnerabilities
        """
        logger.info("Starting advanced race condition analysis...")

        # Analyze different race types
        self._detect_toctou()
        self._detect_signal_races()
        self._detect_thread_unsafe()
        self._detect_double_fetch()

        logger.info(f"Found {len(self.vulnerabilities)} race vulnerabilities")
        return self.vulnerabilities

    def _detect_toctou(self) -> None:
        """Detect TOCTOU vulnerabilities in file operations."""
        try:
            import capstone
            cs = capstone.Cs(capstone.CS_ARCH_X86,
                           capstone.CS_MODE_64 if self.binary.bits == 64 else capstone.CS_MODE_32)

            for func_name, sym in self.binary.symbols.items():
                addr = sym.address if hasattr(sym, 'address') else sym
                if not addr:
                    continue

                try:
                    data = self.binary.read(addr, 0x500)
                    instructions = list(cs.disasm(data, addr))

                    # Look for TOCTOU patterns
                    for check_func, use_func in self.TOCTOU_PAIRS:
                        check_addr = self._find_call_to(instructions, check_func)
                        use_addr = self._find_call_to(instructions, use_func)

                        if check_addr and use_addr and check_addr < use_addr:
                            # Found potential TOCTOU
                            window_size = self._count_instructions_between(
                                instructions, check_addr, use_addr
                            )

                            window = RaceWindow(
                                start_addr=check_addr,
                                end_addr=use_addr,
                                start_op=check_func,
                                end_op=use_func,
                                shared_resource="file",
                                window_size=window_size,
                                exploitability="HIGH" if window_size > 10 else "MEDIUM",
                            )

                            vuln = AdvancedRaceVuln(
                                race_type=AdvancedRaceType.FILE_TOCTOU,
                                severity="HIGH",
                                address=check_addr,
                                function=func_name,
                                description=f"TOCTOU: {check_func}() then {use_func}() with {window_size} instruction window",
                                window=window,
                                confidence=0.8 if window_size > 5 else 0.6,
                                exploit_template=self._gen_toctou_template(check_func, use_func),
                            )
                            self.vulnerabilities.append(vuln)

                except Exception:
                    continue

        except Exception as e:
            logger.debug(f"TOCTOU detection failed: {e}")

    def _find_call_to(self, instructions: list, func_name: str) -> Optional[int]:
        """Find call to a specific function."""
        if func_name not in self.binary.plt:
            return None

        plt_addr = self.binary.plt[func_name]
        for insn in instructions:
            if insn.mnemonic == 'call':
                if str(plt_addr) in insn.op_str or func_name in insn.op_str:
                    return insn.address
        return None

    def _count_instructions_between(self, instructions: list, start: int, end: int) -> int:
        """Count instructions between two addresses."""
        count = 0
        counting = False
        for insn in instructions:
            if insn.address == start:
                counting = True
            elif insn.address == end:
                return count
            elif counting:
                count += 1
        return count

    def _detect_signal_races(self) -> None:
        """Detect signal handler race conditions."""
        # Look for signal() or sigaction() calls
        signal_funcs = ['signal', 'sigaction', '__sysv_signal', 'bsd_signal']

        try:
            import capstone
            cs = capstone.Cs(capstone.CS_ARCH_X86,
                           capstone.CS_MODE_64 if self.binary.bits == 64 else capstone.CS_MODE_32)

            for func_name, sym in self.binary.symbols.items():
                addr = sym.address if hasattr(sym, 'address') else sym
                if not addr:
                    continue

                try:
                    data = self.binary.read(addr, 0x300)
                    instructions = list(cs.disasm(data, addr))

                    for insn in instructions:
                        if insn.mnemonic == 'call':
                            for sig_func in signal_funcs:
                                if sig_func in self.binary.plt:
                                    if str(self.binary.plt[sig_func]) in insn.op_str:
                                        # Found signal registration
                                        handler_info = self._analyze_signal_handler(
                                            instructions, insn.address
                                        )
                                        if handler_info:
                                            self.signal_handlers.append(handler_info)

                                            if not handler_info.is_reentrant:
                                                vuln = AdvancedRaceVuln(
                                                    race_type=AdvancedRaceType.SIGNAL_HANDLER,
                                                    severity="MEDIUM",
                                                    address=insn.address,
                                                    function=func_name,
                                                    description=f"Signal handler uses async-unsafe functions: {', '.join(handler_info.async_unsafe_calls[:3])}",
                                                    signal_info=handler_info,
                                                    confidence=0.7,
                                                    exploit_template=self._gen_signal_template(),
                                                )
                                                self.vulnerabilities.append(vuln)

                except Exception:
                    continue

        except Exception as e:
            logger.debug(f"Signal race detection failed: {e}")

    def _analyze_signal_handler(self, instructions: list, call_addr: int) -> Optional[SignalHandlerInfo]:
        """Analyze a signal handler for safety."""
        # Look for handler address being loaded (typically in rsi for signal())
        handler_addr = None

        for i, insn in enumerate(instructions):
            if insn.address == call_addr:
                # Check previous instructions for handler address
                for j in range(max(0, i-5), i):
                    prev = instructions[j]
                    if prev.mnemonic in ('mov', 'lea'):
                        if 'rsi' in prev.op_str or 'esi' in prev.op_str:
                            # Try to extract address
                            parts = prev.op_str.split(',')
                            if len(parts) == 2:
                                try:
                                    handler_addr = int(parts[1].strip(), 16)
                                except ValueError:
                                    pass
                break

        if not handler_addr:
            return None

        # Analyze handler for async-unsafe calls
        async_unsafe = []
        try:
            import capstone
            cs = capstone.Cs(capstone.CS_ARCH_X86,
                           capstone.CS_MODE_64 if self.binary.bits == 64 else capstone.CS_MODE_32)

            handler_data = self.binary.read(handler_addr, 0x200)
            for insn in cs.disasm(handler_data, handler_addr):
                if insn.mnemonic == 'call':
                    for unsafe_func in self.ASYNC_UNSAFE_FUNCS:
                        if unsafe_func in self.binary.plt:
                            if str(self.binary.plt[unsafe_func]) in insn.op_str:
                                async_unsafe.append(unsafe_func)

        except Exception:
            pass

        return SignalHandlerInfo(
            handler_addr=handler_addr,
            signal_num=0,  # Would need more analysis
            signal_name="unknown",
            is_reentrant=len(async_unsafe) == 0,
            async_unsafe_calls=async_unsafe,
            shared_vars=[],
        )

    def _detect_thread_unsafe(self) -> None:
        """Detect thread-unsafe function usage."""
        for func_name, (safe_alt, reason) in self.THREAD_UNSAFE_FUNCS.items():
            if func_name in self.binary.plt:
                # Find all calls to this function
                try:
                    import capstone
                    cs = capstone.Cs(capstone.CS_ARCH_X86,
                                   capstone.CS_MODE_64 if self.binary.bits == 64 else capstone.CS_MODE_32)

                    for caller_name, sym in self.binary.symbols.items():
                        addr = sym.address if hasattr(sym, 'address') else sym
                        if not addr:
                            continue

                        try:
                            data = self.binary.read(addr, 0x300)
                            for insn in cs.disasm(data, addr):
                                if insn.mnemonic == 'call':
                                    if str(self.binary.plt[func_name]) in insn.op_str:
                                        call = ThreadUnsafeCall(
                                            address=insn.address,
                                            function=func_name,
                                            caller=caller_name,
                                            reason=reason,
                                            safe_alternative=safe_alt,
                                        )
                                        self.thread_unsafe_calls.append(call)

                                        vuln = AdvancedRaceVuln(
                                            race_type=AdvancedRaceType.THREAD_UNSAFE,
                                            severity="LOW",
                                            address=insn.address,
                                            function=caller_name,
                                            description=f"Thread-unsafe {func_name}(): {reason}",
                                            thread_call=call,
                                            confidence=0.5,
                                        )
                                        self.vulnerabilities.append(vuln)

                        except Exception:
                            continue

                except Exception:
                    continue

    def _detect_double_fetch(self) -> None:
        """Detect double-fetch vulnerabilities (memory read twice)."""
        try:
            import capstone
            cs = capstone.Cs(capstone.CS_ARCH_X86,
                           capstone.CS_MODE_64 if self.binary.bits == 64 else capstone.CS_MODE_32)
            cs.detail = True

            for func_name, sym in self.binary.symbols.items():
                addr = sym.address if hasattr(sym, 'address') else sym
                if not addr:
                    continue

                try:
                    data = self.binary.read(addr, 0x500)
                    instructions = list(cs.disasm(data, addr))

                    # Track memory reads
                    memory_reads: Dict[str, List[int]] = {}

                    for insn in instructions:
                        # Check for memory read operations
                        if insn.mnemonic in ('mov', 'movzx', 'movsx'):
                            if '[' in insn.op_str:
                                # Extract memory operand
                                mem_op = self._extract_memory_operand(insn.op_str)
                                if mem_op:
                                    if mem_op not in memory_reads:
                                        memory_reads[mem_op] = []
                                    memory_reads[mem_op].append(insn.address)

                    # Check for double fetches
                    for mem_op, addrs in memory_reads.items():
                        if len(addrs) >= 2:
                            # Check if there's a significant gap
                            for i in range(1, len(addrs)):
                                gap = self._count_instructions_between(
                                    instructions, addrs[i-1], addrs[i]
                                )
                                if gap > 3:  # Significant gap suggests double-fetch
                                    window = RaceWindow(
                                        start_addr=addrs[i-1],
                                        end_addr=addrs[i],
                                        start_op="fetch1",
                                        end_op="fetch2",
                                        shared_resource=mem_op,
                                        window_size=gap,
                                        exploitability="MEDIUM" if gap > 10 else "LOW",
                                    )

                                    vuln = AdvancedRaceVuln(
                                        race_type=AdvancedRaceType.DOUBLE_FETCH,
                                        severity="MEDIUM",
                                        address=addrs[0],
                                        function=func_name,
                                        description=f"Double-fetch of {mem_op} with {gap} instruction gap",
                                        window=window,
                                        confidence=0.4,
                                        exploit_template=self._gen_double_fetch_template(),
                                    )
                                    self.vulnerabilities.append(vuln)
                                    break  # Only report once per location

                except Exception:
                    continue

        except Exception as e:
            logger.debug(f"Double-fetch detection failed: {e}")

    def _extract_memory_operand(self, op_str: str) -> Optional[str]:
        """Extract memory operand from instruction operand string."""
        import re
        match = re.search(r'\[([^\]]+)\]', op_str)
        if match:
            mem_op = match.group(1).strip()
            # Normalize by removing size prefixes
            mem_op = re.sub(r'(byte|word|dword|qword)\s+ptr\s*', '', mem_op)
            return mem_op
        return None

    def _gen_toctou_template(self, check_func: str, use_func: str) -> str:
        """Generate TOCTOU exploit template."""
        return f'''
# TOCTOU Exploit Template
# Target: {check_func}() -> {use_func}()
import os
import threading
import time

TARGET_PATH = "/tmp/target"
LINK_TARGET = "/etc/passwd"  # Or other sensitive file

def create_race_condition():
    """Create race condition by rapidly switching symlink."""
    while True:
        try:
            os.unlink(TARGET_PATH)
            os.symlink("/tmp/safe_file", TARGET_PATH)
            os.unlink(TARGET_PATH)
            os.symlink(LINK_TARGET, TARGET_PATH)
        except:
            pass

def exploit():
    # Start race thread
    race_thread = threading.Thread(target=create_race_condition)
    race_thread.daemon = True
    race_thread.start()

    # Trigger vulnerable operation many times
    for _ in range(10000):
        # Trigger the {check_func}() -> {use_func}() sequence
        # by providing TARGET_PATH as input
        pass  # Add interaction with target binary

if __name__ == "__main__":
    exploit()
'''

    def _gen_signal_template(self) -> str:
        """Generate signal race exploit template."""
        return '''
# Signal Handler Race Exploit Template
import signal
import os
import time

def exploit_signal_race(pid):
    """Exploit signal handler race condition."""
    # Send signals rapidly to trigger race
    for _ in range(1000):
        os.kill(pid, signal.SIGUSR1)
        time.sleep(0.0001)

# Note: This requires knowing the target process behavior
# The race window is when the signal handler uses non-reentrant functions
'''

    def _gen_double_fetch_template(self) -> str:
        """Generate double-fetch exploit template."""
        return '''
# Double-Fetch Exploit Template
import threading
import time

# Shared memory location that gets fetched twice
shared_mem = bytearray(8)

def modify_between_fetches():
    """Modify value between the two fetches."""
    while True:
        shared_mem[:] = b"\\x00" * 8  # Safe value for check
        time.sleep(0.0000001)
        shared_mem[:] = b"\\xff" * 8  # Malicious value for use

# In kernel exploits, this often involves:
# 1. copy_from_user() checking a size
# 2. copy_from_user() using that size later
# The race is to change the size between check and use
'''

    def get_high_severity(self) -> List[AdvancedRaceVuln]:
        """Get high severity race conditions."""
        return [v for v in self.vulnerabilities
                if v.severity == "HIGH" or v.race_type == AdvancedRaceType.FILE_TOCTOU]

    def summary(self) -> str:
        """Get race analysis summary."""
        lines = [
            "Advanced Race Condition Analysis",
            "=" * 40,
            f"Total Vulnerabilities: {len(self.vulnerabilities)}",
            f"Signal Handlers Analyzed: {len(self.signal_handlers)}",
            f"Thread-Unsafe Calls: {len(self.thread_unsafe_calls)}",
            "",
        ]

        # Count by type
        type_counts: Dict[AdvancedRaceType, int] = {}
        for vuln in self.vulnerabilities:
            type_counts[vuln.race_type] = type_counts.get(vuln.race_type, 0) + 1

        if type_counts:
            lines.append("By Type:")
            for race_type, count in sorted(type_counts.items(), key=lambda x: -x[1]):
                lines.append(f"  {race_type.name}: {count}")

        high_sev = self.get_high_severity()
        if high_sev:
            lines.append("")
            lines.append(f"HIGH Severity: {len(high_sev)}")
            for vuln in high_sev[:5]:
                lines.append(f"  [{hex(vuln.address)}] {vuln.description}")

        return "\n".join(lines)
