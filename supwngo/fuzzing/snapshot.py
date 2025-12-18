"""
Snapshot-based fuzzing for stateful targets.

Snapshot fuzzing captures process state at a specific point
and restores it for each iteration, avoiding expensive restarts.

Benefits:
- 10-100x faster than process restart
- Maintains state for stateful protocols
- Supports persistent mode without modification

Techniques:
1. In-process snapshotting (fork-based)
2. Full VM snapshots (QEMU/KVM)
3. Memory-only snapshots (custom implementation)

References:
- AFL++ snapshot mode
- WinAFL DynamoRIO instrumentation
- kAFL kernel fuzzing snapshots
"""

import os
import mmap
import ctypes
import signal
import struct
import tempfile
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


class SnapshotMethod(Enum):
    """Snapshot implementation methods."""
    FORK = auto()       # fork() based (fast, Unix only)
    MEMORY = auto()     # Manual memory snapshot
    QEMU = auto()       # Full QEMU VM snapshot
    KVM = auto()        # KVM snapshot (requires kernel support)


@dataclass
class ProcessSnapshot:
    """Captured process state."""
    pid: int
    timestamp: float
    memory_regions: List['MemoryRegion'] = field(default_factory=list)
    registers: Optional[Dict[str, int]] = None
    files: List[int] = field(default_factory=list)  # Open file descriptors
    checkpoint_id: str = ""

    def size_bytes(self) -> int:
        """Calculate total snapshot size."""
        return sum(r.size for r in self.memory_regions)


@dataclass
class MemoryRegion:
    """A captured memory region."""
    start: int
    end: int
    size: int
    permissions: str
    data: bytes = b""
    path: str = ""  # Mapped file if any

    def is_writable(self) -> bool:
        return 'w' in self.permissions

    def is_executable(self) -> bool:
        return 'x' in self.permissions


@dataclass
class SnapshotConfig:
    """Configuration for snapshot fuzzing."""
    method: SnapshotMethod = SnapshotMethod.FORK
    snapshot_point: str = ""  # Function or address to snapshot at
    restore_writable_only: bool = True  # Optimization
    preserve_signals: bool = True
    timeout_ms: int = 1000
    max_iterations: int = 0  # 0 = unlimited


class ForkBasedSnapshot:
    """
    Fork-based snapshot implementation.

    Uses fork() to create copy-on-write snapshot.
    Very fast but limited to Unix and single-process targets.
    """

    def __init__(self):
        self.parent_pid: int = 0
        self.child_pid: int = 0
        self.iteration_count: int = 0

    def setup(self, target_func: Callable) -> bool:
        """
        Setup fork-based fuzzing.

        Args:
            target_func: Function to call after forking

        Returns:
            True if setup successful
        """
        self.parent_pid = os.getpid()
        return True

    def snapshot_and_fuzz(
        self,
        fuzz_func: Callable[[bytes], bool],
        input_generator: Callable[[], bytes],
        max_iterations: int = 0,
    ) -> List['FuzzResult']:
        """
        Run snapshot-based fuzzing loop.

        Args:
            fuzz_func: Function that takes input, returns True if interesting
            input_generator: Generates fuzz inputs
            max_iterations: Max iterations (0 = unlimited)

        Returns:
            List of interesting results
        """
        results = []
        iteration = 0

        while max_iterations == 0 or iteration < max_iterations:
            # Fork to create snapshot
            pid = os.fork()

            if pid == 0:
                # Child: execute fuzz iteration
                try:
                    test_input = input_generator()
                    is_interesting = fuzz_func(test_input)
                    # Exit with code indicating result
                    os._exit(1 if is_interesting else 0)
                except Exception:
                    os._exit(2)  # Crash
            else:
                # Parent: wait and collect result
                _, status = os.waitpid(pid, 0)

                if os.WIFEXITED(status):
                    exit_code = os.WEXITSTATUS(status)
                    if exit_code == 1:
                        results.append(FuzzResult(
                            iteration=iteration,
                            interesting=True,
                            crash=False,
                        ))
                    elif exit_code == 2:
                        results.append(FuzzResult(
                            iteration=iteration,
                            interesting=True,
                            crash=True,
                        ))
                elif os.WIFSIGNALED(status):
                    sig = os.WTERMSIG(status)
                    results.append(FuzzResult(
                        iteration=iteration,
                        interesting=True,
                        crash=True,
                        signal=sig,
                    ))

            iteration += 1
            self.iteration_count = iteration

        return results


@dataclass
class FuzzResult:
    """Result from a single fuzz iteration."""
    iteration: int
    interesting: bool
    crash: bool = False
    signal: int = 0
    input_data: bytes = b""
    coverage_delta: int = 0


class MemorySnapshot:
    """
    Manual memory snapshot implementation.

    Directly captures and restores process memory regions.
    More flexible than fork but slower.
    """

    def __init__(self, pid: Optional[int] = None):
        """
        Initialize memory snapshotter.

        Args:
            pid: Target process ID (None = self)
        """
        self.pid = pid or os.getpid()
        self.snapshots: Dict[str, ProcessSnapshot] = {}

    def get_memory_maps(self) -> List[MemoryRegion]:
        """
        Get process memory mappings from /proc/[pid]/maps.

        Returns:
            List of memory regions
        """
        regions = []
        maps_path = f"/proc/{self.pid}/maps"

        try:
            with open(maps_path, 'r') as f:
                for line in f:
                    parts = line.split()
                    addr_range = parts[0].split('-')
                    start = int(addr_range[0], 16)
                    end = int(addr_range[1], 16)
                    perms = parts[1]
                    path = parts[-1] if len(parts) > 5 else ""

                    regions.append(MemoryRegion(
                        start=start,
                        end=end,
                        size=end - start,
                        permissions=perms,
                        path=path,
                    ))
        except (FileNotFoundError, PermissionError) as e:
            logger.error(f"Cannot read memory maps: {e}")

        return regions

    def capture(
        self,
        checkpoint_id: str,
        writable_only: bool = True,
    ) -> ProcessSnapshot:
        """
        Capture memory snapshot.

        Args:
            checkpoint_id: Identifier for this snapshot
            writable_only: Only capture writable regions (optimization)

        Returns:
            ProcessSnapshot
        """
        regions = self.get_memory_maps()
        captured_regions = []

        mem_path = f"/proc/{self.pid}/mem"

        try:
            with open(mem_path, 'rb') as mem:
                for region in regions:
                    # Skip non-writable if optimizing
                    if writable_only and not region.is_writable():
                        continue

                    # Skip special regions
                    if '[vvar]' in region.path or '[vsyscall]' in region.path:
                        continue

                    try:
                        mem.seek(region.start)
                        data = mem.read(region.size)
                        region.data = data
                        captured_regions.append(region)
                    except (OSError, ValueError):
                        # Cannot read this region
                        pass

        except (FileNotFoundError, PermissionError) as e:
            logger.error(f"Cannot read process memory: {e}")

        snapshot = ProcessSnapshot(
            pid=self.pid,
            timestamp=time.time(),
            memory_regions=captured_regions,
            checkpoint_id=checkpoint_id,
        )

        self.snapshots[checkpoint_id] = snapshot
        logger.info(f"Captured snapshot '{checkpoint_id}': {len(captured_regions)} regions, "
                   f"{snapshot.size_bytes()} bytes")

        return snapshot

    def restore(self, checkpoint_id: str) -> bool:
        """
        Restore memory to snapshot state.

        Args:
            checkpoint_id: Snapshot to restore

        Returns:
            True if successful
        """
        if checkpoint_id not in self.snapshots:
            logger.error(f"Snapshot '{checkpoint_id}' not found")
            return False

        snapshot = self.snapshots[checkpoint_id]
        mem_path = f"/proc/{self.pid}/mem"

        try:
            with open(mem_path, 'r+b') as mem:
                for region in snapshot.memory_regions:
                    if region.data:
                        mem.seek(region.start)
                        mem.write(region.data)

            logger.debug(f"Restored snapshot '{checkpoint_id}'")
            return True

        except (FileNotFoundError, PermissionError, OSError) as e:
            logger.error(f"Cannot restore memory: {e}")
            return False


class SnapshotFuzzer:
    """
    High-level snapshot fuzzing orchestrator.

    Combines snapshot methods with fuzzing logic.
    """

    def __init__(self, config: Optional[SnapshotConfig] = None):
        self.config = config or SnapshotConfig()
        self.stats = FuzzingStats()

        # Initialize appropriate snapshot method
        if self.config.method == SnapshotMethod.FORK:
            self.snapshotter = ForkBasedSnapshot()
        else:
            self.snapshotter = MemorySnapshot()

    def run(
        self,
        target: Callable[[bytes], int],
        corpus: List[bytes],
        mutator: Callable[[bytes], bytes],
        duration_seconds: int = 0,
        max_iterations: int = 0,
    ) -> 'FuzzingStats':
        """
        Run snapshot fuzzing campaign.

        Args:
            target: Function to fuzz (takes input, returns status)
            corpus: Initial input corpus
            mutator: Input mutation function
            duration_seconds: Time limit (0 = unlimited)
            max_iterations: Iteration limit (0 = unlimited)

        Returns:
            Fuzzing statistics
        """
        start_time = time.time()
        iteration = 0
        queue = list(corpus)

        while True:
            # Check limits
            if max_iterations > 0 and iteration >= max_iterations:
                break
            if duration_seconds > 0 and time.time() - start_time >= duration_seconds:
                break

            # Get next input
            if not queue:
                queue = list(corpus)
            base_input = queue.pop(0)

            # Mutate
            test_input = mutator(base_input)

            # Execute with snapshot
            if isinstance(self.snapshotter, ForkBasedSnapshot):
                pid = os.fork()
                if pid == 0:
                    try:
                        result = target(test_input)
                        os._exit(result)
                    except Exception:
                        os._exit(255)
                else:
                    _, status = os.waitpid(pid, 0)
                    self._process_result(status, test_input, iteration)
            else:
                # Memory snapshot method
                try:
                    result = target(test_input)
                    self.stats.total_executions += 1
                except Exception as e:
                    self.stats.crashes += 1
                    self._save_crash(test_input, str(e), iteration)

            iteration += 1

        self.stats.duration = time.time() - start_time
        return self.stats

    def _process_result(self, status: int, input_data: bytes, iteration: int):
        """Process execution result."""
        self.stats.total_executions += 1

        if os.WIFSIGNALED(status):
            sig = os.WTERMSIG(status)
            if sig in (signal.SIGSEGV, signal.SIGABRT, signal.SIGFPE):
                self.stats.crashes += 1
                self._save_crash(input_data, f"Signal {sig}", iteration)
        elif os.WIFEXITED(status):
            exit_code = os.WEXITSTATUS(status)
            if exit_code != 0:
                self.stats.unique_paths += 1

    def _save_crash(self, input_data: bytes, reason: str, iteration: int):
        """Save crash-inducing input."""
        crash_dir = Path("crashes")
        crash_dir.mkdir(exist_ok=True)

        crash_file = crash_dir / f"crash_{iteration:06d}"
        crash_file.write_bytes(input_data)
        logger.info(f"Saved crash: {crash_file} ({reason})")


@dataclass
class FuzzingStats:
    """Statistics from fuzzing campaign."""
    total_executions: int = 0
    crashes: int = 0
    unique_paths: int = 0
    duration: float = 0.0

    @property
    def exec_per_second(self) -> float:
        if self.duration > 0:
            return self.total_executions / self.duration
        return 0.0


def generate_snapshot_fuzzer_template(
    target_binary: str,
    snapshot_at: str,
) -> str:
    """Generate snapshot fuzzer template code."""
    return f'''
#!/usr/bin/env python3
"""
Snapshot fuzzer for {target_binary}
Snapshot point: {snapshot_at}
"""

from supwngo.fuzzing.snapshot import SnapshotFuzzer, SnapshotConfig, SnapshotMethod
import random

def target(input_data: bytes) -> int:
    """Target function to fuzz."""
    # Parse input and call target
    # Return 0 for normal, non-zero for interesting
    return 0

def mutate(data: bytes) -> bytes:
    """Mutate input data."""
    data = bytearray(data)
    if data:
        pos = random.randint(0, len(data) - 1)
        data[pos] = random.randint(0, 255)
    return bytes(data)

if __name__ == "__main__":
    config = SnapshotConfig(
        method=SnapshotMethod.FORK,
        snapshot_point="{snapshot_at}",
    )

    fuzzer = SnapshotFuzzer(config)

    corpus = [
        b"seed1",
        b"seed2",
    ]

    stats = fuzzer.run(
        target=target,
        corpus=corpus,
        mutator=mutate,
        duration_seconds=3600,
    )

    print(f"Executions: {{stats.total_executions}}")
    print(f"Crashes: {{stats.crashes}}")
    print(f"Speed: {{stats.exec_per_second:.1f}} exec/s")
'''
