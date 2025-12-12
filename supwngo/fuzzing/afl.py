"""
AFL++ fuzzing integration.
"""

import json
import os
import shutil
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from supwngo.core.binary import Binary
from supwngo.utils.logging import get_logger
from supwngo.utils.config import get_config

logger = get_logger(__name__)


@dataclass
class AFLStats:
    """AFL fuzzer statistics."""
    execs_done: int = 0
    execs_per_sec: float = 0.0
    paths_total: int = 0
    paths_found: int = 0
    pending_favs: int = 0
    pending_total: int = 0
    crashes_total: int = 0
    hangs_total: int = 0
    cycles_done: int = 0
    bitmap_cvg: float = 0.0
    stability: float = 0.0
    last_update: float = 0.0


@dataclass
class AFLConfig:
    """AFL fuzzer configuration."""
    binary_path: str = ""
    input_dir: str = ""
    output_dir: str = ""

    # Execution options
    timeout: int = 1000  # ms
    memory_limit: int = 200  # MB

    # Mode options
    qemu_mode: bool = False
    frida_mode: bool = False
    unicorn_mode: bool = False
    persistent_mode: bool = False

    # Fuzzing options
    dictionary: Optional[str] = None
    crash_mode: bool = False
    cmplog_mode: bool = False
    sync_dir: Optional[str] = None

    # Parallel fuzzing
    instance_id: int = 0
    is_master: bool = True

    # Extra arguments
    extra_args: List[str] = field(default_factory=list)


class AFLFuzzer:
    """
    AFL++ fuzzing integration.

    Supports:
    - Standard fuzzing
    - QEMU mode for closed-source binaries
    - Crash exploration mode
    - Parallel fuzzing
    - Campaign monitoring
    """

    def __init__(self, binary: Binary, config: Optional[AFLConfig] = None):
        """
        Initialize AFL fuzzer.

        Args:
            binary: Target binary
            config: Fuzzer configuration
        """
        self.binary = binary
        self.config = config or AFLConfig(binary_path=str(binary.path))
        self._process: Optional[subprocess.Popen] = None
        self._stats = AFLStats()

        # Detect AFL path
        self.afl_path = self._find_afl()

    def _find_afl(self) -> str:
        """Find AFL binary path."""
        # Check common names
        for name in ["afl-fuzz", "afl++-fuzz", "AFLplusplus/afl-fuzz"]:
            path = shutil.which(name)
            if path:
                return path

        # Check config
        cfg = get_config()
        if cfg.afl_path and os.path.exists(cfg.afl_path):
            return cfg.afl_path

        return "afl-fuzz"

    def setup(
        self,
        input_dir: str,
        output_dir: str,
        timeout: int = 1000,
        memory_limit: int = 200,
        qemu_mode: bool = False,
    ) -> None:
        """
        Setup fuzzing campaign.

        Args:
            input_dir: Input corpus directory
            output_dir: Output directory for crashes/queue
            timeout: Execution timeout in ms
            memory_limit: Memory limit in MB
            qemu_mode: Enable QEMU mode for closed-source
        """
        self.config.input_dir = input_dir
        self.config.output_dir = output_dir
        self.config.timeout = timeout
        self.config.memory_limit = memory_limit
        self.config.qemu_mode = qemu_mode

        # Create directories
        Path(input_dir).mkdir(parents=True, exist_ok=True)
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        # Create initial seed if input dir is empty
        input_path = Path(input_dir)
        if not any(input_path.iterdir()):
            seed_file = input_path / "seed_0"
            seed_file.write_bytes(b"A" * 8)
            logger.debug("Created initial seed file")

    def start(self) -> subprocess.Popen:
        """
        Start fuzzing campaign.

        Returns:
            Subprocess handle
        """
        cmd = self._build_command()
        logger.info(f"Starting AFL: {' '.join(cmd)}")

        # Set AFL environment
        env = os.environ.copy()
        env["AFL_NO_UI"] = "1"  # Disable UI for non-interactive
        env["AFL_SKIP_CPUFREQ"] = "1"
        env["AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"] = "1"

        if self.config.qemu_mode:
            env["AFL_INST_LIBS"] = "1"

        self._process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )

        return self._process

    def _build_command(self) -> List[str]:
        """Build AFL command line."""
        cmd = [self.afl_path]

        # Input/output directories
        cmd.extend(["-i", self.config.input_dir])
        cmd.extend(["-o", self.config.output_dir])

        # Timeout and memory
        cmd.extend(["-t", str(self.config.timeout)])
        cmd.extend(["-m", str(self.config.memory_limit)])

        # Mode options
        if self.config.qemu_mode:
            cmd.append("-Q")

        if self.config.frida_mode:
            cmd.append("-O")

        if self.config.crash_mode:
            cmd.append("-C")

        if self.config.cmplog_mode:
            cmd.extend(["-c", self.config.binary_path])

        # Dictionary
        if self.config.dictionary:
            cmd.extend(["-x", self.config.dictionary])

        # Parallel fuzzing
        if self.config.is_master:
            cmd.extend(["-M", f"fuzzer{self.config.instance_id:02d}"])
        else:
            cmd.extend(["-S", f"fuzzer{self.config.instance_id:02d}"])

        if self.config.sync_dir:
            cmd.extend(["-F", self.config.sync_dir])

        # Extra arguments
        cmd.extend(self.config.extra_args)

        # Target binary
        cmd.append("--")
        cmd.append(self.config.binary_path)

        return cmd

    def stop(self) -> None:
        """Stop fuzzing campaign."""
        if self._process:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
            self._process = None
            logger.info("AFL fuzzer stopped")

    def is_running(self) -> bool:
        """Check if fuzzer is running."""
        if self._process:
            return self._process.poll() is None
        return False

    def get_stats(self) -> AFLStats:
        """
        Get current fuzzer statistics.

        Returns:
            AFLStats instance
        """
        stats_file = Path(self.config.output_dir) / "default" / "fuzzer_stats"

        # Try master fuzzer first
        if not stats_file.exists():
            for name in ["fuzzer00", "fuzzer01"]:
                alt_path = Path(self.config.output_dir) / name / "fuzzer_stats"
                if alt_path.exists():
                    stats_file = alt_path
                    break

        if not stats_file.exists():
            return self._stats

        try:
            content = stats_file.read_text()
            for line in content.split("\n"):
                if ":" in line:
                    key, value = line.split(":", 1)
                    key = key.strip()
                    value = value.strip()

                    if key == "execs_done":
                        self._stats.execs_done = int(value)
                    elif key == "execs_per_sec":
                        self._stats.execs_per_sec = float(value)
                    elif key == "paths_total":
                        self._stats.paths_total = int(value)
                    elif key == "paths_found":
                        self._stats.paths_found = int(value)
                    elif key == "pending_favs":
                        self._stats.pending_favs = int(value)
                    elif key == "pending_total":
                        self._stats.pending_total = int(value)
                    elif key == "unique_crashes":
                        self._stats.crashes_total = int(value)
                    elif key == "unique_hangs":
                        self._stats.hangs_total = int(value)
                    elif key == "cycles_done":
                        self._stats.cycles_done = int(value)
                    elif key == "bitmap_cvg":
                        self._stats.bitmap_cvg = float(value.rstrip("%"))
                    elif key == "stability":
                        self._stats.stability = float(value.rstrip("%"))

            self._stats.last_update = time.time()

        except Exception as e:
            logger.warning(f"Failed to parse fuzzer stats: {e}")

        return self._stats

    def get_crashes(self) -> List[Path]:
        """
        Get list of crash files.

        Returns:
            List of crash file paths
        """
        crashes = []
        output_path = Path(self.config.output_dir)

        # Check all fuzzer directories
        for fuzzer_dir in output_path.iterdir():
            if fuzzer_dir.is_dir():
                crash_dir = fuzzer_dir / "crashes"
                if crash_dir.exists():
                    for crash_file in crash_dir.iterdir():
                        if crash_file.is_file() and not crash_file.name.startswith("."):
                            crashes.append(crash_file)

        return crashes

    def get_queue(self) -> List[Path]:
        """
        Get list of queue (interesting inputs).

        Returns:
            List of queue file paths
        """
        queue = []
        output_path = Path(self.config.output_dir)

        for fuzzer_dir in output_path.iterdir():
            if fuzzer_dir.is_dir():
                queue_dir = fuzzer_dir / "queue"
                if queue_dir.exists():
                    for queue_file in queue_dir.iterdir():
                        if queue_file.is_file() and not queue_file.name.startswith("."):
                            queue.append(queue_file)

        return queue

    def minimize_crash(self, crash_path: Path, output_path: Path) -> bool:
        """
        Minimize crash input using afl-tmin.

        Args:
            crash_path: Path to crash input
            output_path: Path for minimized output

        Returns:
            True if minimization succeeded
        """
        afl_tmin = shutil.which("afl-tmin")
        if not afl_tmin:
            logger.warning("afl-tmin not found")
            return False

        cmd = [afl_tmin]

        if self.config.qemu_mode:
            cmd.append("-Q")

        cmd.extend([
            "-i", str(crash_path),
            "-o", str(output_path),
            "--",
            self.config.binary_path,
        ])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=300,
            )
            return result.returncode == 0

        except Exception as e:
            logger.error(f"afl-tmin failed: {e}")
            return False

    def generate_harness(
        self,
        input_method: str = "stdin",
        template: Optional[str] = None,
    ) -> str:
        """
        Generate fuzzing harness.

        Args:
            input_method: How binary receives input (stdin, file, argv)
            template: Optional custom template

        Returns:
            Harness source code
        """
        if template:
            return template

        # Basic AFL harness template
        harness = '''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// AFL persistence mode
#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

int main(int argc, char **argv) {
    // Read input
    char buf[4096];
    size_t len;

#ifdef __AFL_LOOP
    while (__AFL_LOOP(1000)) {
#endif
'''

        if input_method == "stdin":
            harness += '''
        len = read(0, buf, sizeof(buf) - 1);
        if (len <= 0) continue;
        buf[len] = 0;
'''
        elif input_method == "file":
            harness += '''
        if (argc < 2) return 1;
        FILE *f = fopen(argv[1], "rb");
        if (!f) continue;
        len = fread(buf, 1, sizeof(buf) - 1, f);
        fclose(f);
        buf[len] = 0;
'''

        harness += '''
        // Call target function here
        // target_function(buf, len);

#ifdef __AFL_LOOP
    }
#endif

    return 0;
}
'''
        return harness

    def run_campaign(
        self,
        duration: int = 3600,
        callback: Optional[callable] = None,
    ) -> Dict[str, Any]:
        """
        Run complete fuzzing campaign.

        Args:
            duration: Campaign duration in seconds
            callback: Optional progress callback

        Returns:
            Campaign results
        """
        start_time = time.time()
        end_time = start_time + duration

        self.start()
        logger.info(f"Starting {duration}s fuzzing campaign")

        try:
            while time.time() < end_time and self.is_running():
                time.sleep(10)
                stats = self.get_stats()

                if callback:
                    callback(stats)

                logger.debug(
                    f"Execs: {stats.execs_done}, "
                    f"Crashes: {stats.crashes_total}, "
                    f"Coverage: {stats.bitmap_cvg}%"
                )

        finally:
            self.stop()

        # Collect results
        crashes = self.get_crashes()
        stats = self.get_stats()

        return {
            "duration": time.time() - start_time,
            "execs_total": stats.execs_done,
            "crashes": len(crashes),
            "crash_files": [str(c) for c in crashes],
            "coverage": stats.bitmap_cvg,
            "paths_found": stats.paths_total,
        }

    def summary(self) -> str:
        """Get campaign summary."""
        stats = self.get_stats()
        crashes = self.get_crashes()

        return f"""
AFL Campaign Summary
====================
Binary: {self.config.binary_path}
Output: {self.config.output_dir}

Statistics:
  Executions: {stats.execs_done}
  Speed: {stats.execs_per_sec:.1f} execs/sec
  Coverage: {stats.bitmap_cvg}%
  Stability: {stats.stability}%
  Cycles: {stats.cycles_done}

Findings:
  Crashes: {stats.crashes_total}
  Hangs: {stats.hangs_total}
  Paths: {stats.paths_total}
"""
