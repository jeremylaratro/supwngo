"""
Honggfuzz fuzzing integration.
"""

import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from supwngo.core.binary import Binary
from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class HonggfuzzStats:
    """Honggfuzz statistics."""
    iterations: int = 0
    speed: float = 0.0
    crashes: int = 0
    timeouts: int = 0
    coverage_blocks: int = 0
    coverage_branches: int = 0
    coverage_percent: float = 0.0


@dataclass
class HonggfuzzConfig:
    """Honggfuzz configuration."""
    binary_path: str = ""
    input_dir: str = ""
    output_dir: str = ""

    # Execution options
    timeout: int = 10  # seconds
    threads: int = 4

    # Fuzzing options
    mutations_per_run: int = 6
    dictionary: Optional[str] = None

    # Instrumentation
    use_perf: bool = True
    use_intel_pt: bool = False

    # Output
    save_all: bool = False


class HonggfuzzFuzzer:
    """
    Honggfuzz fuzzing integration.

    Features:
    - Software and hardware-based coverage
    - Persistent mode support
    - Multi-threaded fuzzing
    """

    def __init__(self, binary: Binary, config: Optional[HonggfuzzConfig] = None):
        """
        Initialize Honggfuzz fuzzer.

        Args:
            binary: Target binary
            config: Fuzzer configuration
        """
        self.binary = binary
        self.config = config or HonggfuzzConfig(binary_path=str(binary.path))
        self._process: Optional[subprocess.Popen] = None
        self._stats = HonggfuzzStats()

        # Detect honggfuzz path
        self.honggfuzz_path = shutil.which("honggfuzz") or "honggfuzz"

    def setup(
        self,
        input_dir: str,
        output_dir: str,
        timeout: int = 10,
        threads: int = 4,
    ) -> None:
        """
        Setup fuzzing campaign.

        Args:
            input_dir: Input corpus directory
            output_dir: Output directory
            timeout: Execution timeout in seconds
            threads: Number of fuzzing threads
        """
        self.config.input_dir = input_dir
        self.config.output_dir = output_dir
        self.config.timeout = timeout
        self.config.threads = threads

        # Create directories
        Path(input_dir).mkdir(parents=True, exist_ok=True)
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        # Create initial seed if needed
        input_path = Path(input_dir)
        if not any(input_path.iterdir()):
            seed_file = input_path / "seed"
            seed_file.write_bytes(b"AAAA")

    def start(self) -> subprocess.Popen:
        """
        Start fuzzing campaign.

        Returns:
            Subprocess handle
        """
        cmd = self._build_command()
        logger.info(f"Starting Honggfuzz: {' '.join(cmd)}")

        self._process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        return self._process

    def _build_command(self) -> List[str]:
        """Build Honggfuzz command line."""
        cmd = [self.honggfuzz_path]

        # Input/output
        cmd.extend(["--input", self.config.input_dir])
        cmd.extend(["--output", self.config.output_dir])

        # Execution options
        cmd.extend(["--timeout", str(self.config.timeout)])
        cmd.extend(["--threads", str(self.config.threads)])

        # Fuzzing options
        cmd.extend(["--mutations_per_run", str(self.config.mutations_per_run)])

        if self.config.dictionary:
            cmd.extend(["--dict", self.config.dictionary])

        # Coverage options
        if self.config.use_intel_pt:
            cmd.append("--linux_perf_instr")

        if self.config.save_all:
            cmd.append("--save_all")

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
            logger.info("Honggfuzz stopped")

    def is_running(self) -> bool:
        """Check if fuzzer is running."""
        if self._process:
            return self._process.poll() is None
        return False

    def get_stats(self) -> HonggfuzzStats:
        """
        Get current fuzzer statistics.

        Returns:
            HonggfuzzStats instance
        """
        # Honggfuzz writes stats to stdout
        # Parse from report file if available
        report_file = Path(self.config.output_dir) / "HONGGFUZZ.REPORT.TXT"

        if report_file.exists():
            try:
                content = report_file.read_text()
                for line in content.split("\n"):
                    if "Iterations" in line:
                        self._stats.iterations = int(
                            line.split(":")[1].strip()
                        )
                    elif "Crashes" in line:
                        self._stats.crashes = int(line.split(":")[1].strip())
                    elif "Timeouts" in line:
                        self._stats.timeouts = int(line.split(":")[1].strip())
            except Exception as e:
                logger.debug(f"Failed to parse honggfuzz stats: {e}")

        return self._stats

    def get_crashes(self) -> List[Path]:
        """
        Get list of crash files.

        Returns:
            List of crash file paths
        """
        crashes = []
        output_path = Path(self.config.output_dir)

        if output_path.exists():
            for f in output_path.iterdir():
                if f.is_file() and ("SIGABRT" in f.name or "SIGSEGV" in f.name):
                    crashes.append(f)

        return crashes

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

        try:
            while time.time() < end_time and self.is_running():
                time.sleep(10)
                stats = self.get_stats()

                if callback:
                    callback(stats)

        finally:
            self.stop()

        crashes = self.get_crashes()
        stats = self.get_stats()

        return {
            "duration": time.time() - start_time,
            "iterations": stats.iterations,
            "crashes": len(crashes),
            "crash_files": [str(c) for c in crashes],
        }

    def summary(self) -> str:
        """Get campaign summary."""
        stats = self.get_stats()
        crashes = self.get_crashes()

        return f"""
Honggfuzz Campaign Summary
==========================
Binary: {self.config.binary_path}
Output: {self.config.output_dir}

Statistics:
  Iterations: {stats.iterations}
  Speed: {stats.speed:.1f} iter/sec

Findings:
  Crashes: {stats.crashes}
  Timeouts: {stats.timeouts}
"""
