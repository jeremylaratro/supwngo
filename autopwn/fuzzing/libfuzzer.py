"""
LibFuzzer integration for source-available fuzzing.
"""

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from autopwn.core.binary import Binary
from autopwn.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class LibFuzzerConfig:
    """LibFuzzer configuration."""
    target_path: str = ""
    corpus_dir: str = ""
    output_dir: str = ""

    # Fuzzing options
    max_len: int = 4096
    max_total_time: int = 0  # 0 = unlimited
    runs: int = -1  # -1 = unlimited
    jobs: int = 1

    # Coverage
    use_counters: bool = True

    # Dictionary
    dictionary: Optional[str] = None

    # Sanitizers (compile-time)
    use_asan: bool = True
    use_msan: bool = False
    use_ubsan: bool = True


class LibFuzzer:
    """
    LibFuzzer integration for coverage-guided fuzzing.

    Requires source code and clang compiler.
    """

    def __init__(self, config: Optional[LibFuzzerConfig] = None):
        """
        Initialize LibFuzzer.

        Args:
            config: Fuzzer configuration
        """
        self.config = config or LibFuzzerConfig()
        self._process: Optional[subprocess.Popen] = None

        # Check for clang
        self.clang_path = shutil.which("clang++") or shutil.which("clang")

    def compile_target(
        self,
        source_files: List[str],
        output_path: str,
        extra_flags: Optional[List[str]] = None,
    ) -> bool:
        """
        Compile fuzzing target with sanitizers.

        Args:
            source_files: Source files to compile
            output_path: Output binary path
            extra_flags: Additional compiler flags

        Returns:
            True if compilation succeeded
        """
        if not self.clang_path:
            logger.error("clang not found")
            return False

        cmd = [self.clang_path]

        # Add fuzzer flag
        cmd.append("-fsanitize=fuzzer")

        # Add sanitizers
        sanitizers = []
        if self.config.use_asan:
            sanitizers.append("address")
        if self.config.use_msan:
            sanitizers.append("memory")
        if self.config.use_ubsan:
            sanitizers.append("undefined")

        if sanitizers:
            cmd.append(f"-fsanitize={','.join(sanitizers)}")

        # Coverage flags
        cmd.extend(["-fprofile-instr-generate", "-fcoverage-mapping"])

        # Optimization
        cmd.extend(["-O2", "-g"])

        # Extra flags
        if extra_flags:
            cmd.extend(extra_flags)

        # Source files and output
        cmd.extend(source_files)
        cmd.extend(["-o", output_path])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                logger.error(f"Compilation failed: {result.stderr}")
                return False

            self.config.target_path = output_path
            return True

        except Exception as e:
            logger.error(f"Compilation error: {e}")
            return False

    def create_harness_template(self, function_signature: str = "") -> str:
        """
        Generate LibFuzzer harness template.

        Args:
            function_signature: Target function signature

        Returns:
            Harness source code
        """
        harness = '''
#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Include your target header here
// #include "target.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Don't process empty inputs
    if (size == 0) {
        return 0;
    }

    // Ensure null-termination for string functions
    // char *str = (char *)malloc(size + 1);
    // memcpy(str, data, size);
    // str[size] = '\\0';

    // Call your target function here
    // target_function(data, size);

    // free(str);
    return 0;
}
'''
        return harness

    def setup(
        self,
        corpus_dir: str,
        output_dir: str,
        max_len: int = 4096,
    ) -> None:
        """
        Setup fuzzing.

        Args:
            corpus_dir: Corpus directory
            output_dir: Output directory for crashes
            max_len: Maximum input length
        """
        self.config.corpus_dir = corpus_dir
        self.config.output_dir = output_dir
        self.config.max_len = max_len

        # Create directories
        Path(corpus_dir).mkdir(parents=True, exist_ok=True)
        Path(output_dir).mkdir(parents=True, exist_ok=True)

    def start(self) -> subprocess.Popen:
        """
        Start fuzzing.

        Returns:
            Subprocess handle
        """
        cmd = self._build_command()
        logger.info(f"Starting LibFuzzer: {' '.join(cmd)}")

        self._process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        return self._process

    def _build_command(self) -> List[str]:
        """Build LibFuzzer command."""
        cmd = [self.config.target_path]

        # Corpus directory
        cmd.append(self.config.corpus_dir)

        # Options
        cmd.append(f"-max_len={self.config.max_len}")

        if self.config.max_total_time > 0:
            cmd.append(f"-max_total_time={self.config.max_total_time}")

        if self.config.runs > 0:
            cmd.append(f"-runs={self.config.runs}")

        if self.config.jobs > 1:
            cmd.append(f"-jobs={self.config.jobs}")

        if self.config.dictionary:
            cmd.append(f"-dict={self.config.dictionary}")

        # Output artifacts to specific directory
        cmd.append(f"-artifact_prefix={self.config.output_dir}/")

        # Use value profile for better coverage
        if self.config.use_counters:
            cmd.append("-use_value_profile=1")

        return cmd

    def stop(self) -> None:
        """Stop fuzzing."""
        if self._process:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
            self._process = None

    def is_running(self) -> bool:
        """Check if fuzzer is running."""
        if self._process:
            return self._process.poll() is None
        return False

    def get_crashes(self) -> List[Path]:
        """
        Get crash files.

        Returns:
            List of crash file paths
        """
        crashes = []
        output_path = Path(self.config.output_dir)

        if output_path.exists():
            for f in output_path.iterdir():
                if f.name.startswith("crash-") or f.name.startswith("oom-"):
                    crashes.append(f)

        return crashes

    def minimize_crash(
        self,
        crash_path: Path,
        output_path: Path,
    ) -> bool:
        """
        Minimize crash input.

        Args:
            crash_path: Path to crash file
            output_path: Path for minimized output

        Returns:
            True if minimization succeeded
        """
        cmd = [
            self.config.target_path,
            f"-minimize_crash=1",
            f"-exact_artifact_path={output_path}",
            str(crash_path),
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=300,
            )
            return output_path.exists()

        except Exception as e:
            logger.error(f"Minimization failed: {e}")
            return False

    def merge_corpora(
        self,
        output_dir: str,
        input_dirs: List[str],
    ) -> bool:
        """
        Merge multiple corpora into one.

        Args:
            output_dir: Output corpus directory
            input_dirs: Input corpus directories

        Returns:
            True if merge succeeded
        """
        cmd = [
            self.config.target_path,
            "-merge=1",
            output_dir,
        ]
        cmd.extend(input_dirs)

        try:
            result = subprocess.run(cmd, capture_output=True, timeout=600)
            return result.returncode == 0
        except Exception as e:
            logger.error(f"Merge failed: {e}")
            return False

    def summary(self) -> str:
        """Get fuzzing summary."""
        crashes = self.get_crashes()
        return f"""
LibFuzzer Summary
=================
Target: {self.config.target_path}
Corpus: {self.config.corpus_dir}

Crashes found: {len(crashes)}
"""
