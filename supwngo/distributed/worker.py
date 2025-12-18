"""
Distributed Fuzzing Worker.

Worker node that connects to coordinator, receives seeds,
runs fuzzing, and reports crashes/coverage.
"""

import asyncio
import hashlib
import os
import shutil
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import uuid
import socket

from supwngo.utils.logging import get_logger

logger = get_logger(__name__)

# Try to import HTTP client
try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False


class FuzzerType(Enum):
    """Supported fuzzer types."""
    AFL = "afl"
    AFLPP = "afl++"
    HONGGFUZZ = "honggfuzz"
    LIBFUZZER = "libfuzzer"
    CUSTOM = "custom"


class WorkerState(Enum):
    """Worker states."""
    IDLE = 1
    FUZZING = 2
    SYNCING = 3
    ERROR = 4


@dataclass
class FuzzerConfig:
    """Configuration for fuzzer instance."""
    fuzzer_type: FuzzerType = FuzzerType.AFLPP
    binary_path: str = ""
    input_dir: str = ""
    output_dir: str = ""
    timeout: int = 1000  # ms per execution
    memory_limit: int = 512  # MB
    extra_args: List[str] = field(default_factory=list)
    dictionary: Optional[str] = None
    cores: int = 1


@dataclass
class CrashReport:
    """Report for a discovered crash."""
    input_data: bytes
    signal: int = 0
    crash_type: str = "unknown"
    stack_trace: str = ""
    timestamp: float = field(default_factory=time.time)


class FuzzingWorker:
    """
    Distributed fuzzing worker node.

    Connects to coordinator, receives work, runs fuzzer,
    and reports results.

    Example:
        worker = FuzzingWorker(
            coordinator_url="http://coordinator:8080",
            fuzzer_type=FuzzerType.AFLPP
        )

        # Start worker
        await worker.start()

        # Worker runs until stopped
        await worker.join_campaign(campaign_id)
    """

    def __init__(
        self,
        coordinator_url: str,
        fuzzer_type: FuzzerType = FuzzerType.AFLPP,
        cores: int = 1,
        work_dir: Optional[str] = None
    ):
        """
        Initialize worker.

        Args:
            coordinator_url: URL of coordinator server
            fuzzer_type: Type of fuzzer to use
            cores: Number of CPU cores to use
            work_dir: Working directory for fuzzer
        """
        if not AIOHTTP_AVAILABLE:
            raise ImportError("aiohttp required. Install with: pip install aiohttp")

        self.coordinator_url = coordinator_url.rstrip('/')
        self.fuzzer_type = fuzzer_type
        self.cores = cores
        self.work_dir = Path(work_dir or tempfile.mkdtemp(prefix="supwngo_worker_"))

        self.worker_id = str(uuid.uuid4())
        self.hostname = socket.gethostname()
        self.state = WorkerState.IDLE

        # Session for HTTP requests
        self._session: Optional[aiohttp.ClientSession] = None

        # Current campaign
        self.current_campaign: Optional[str] = None
        self._fuzzer_process: Optional[subprocess.Popen] = None

        # Statistics
        self.executions = 0
        self.crashes_found = 0
        self._last_sync = 0

        # Control
        self._running = False
        self._tasks: List[asyncio.Task] = []

    async def start(self):
        """Start the worker and register with coordinator."""
        self._session = aiohttp.ClientSession()
        self._running = True

        # Register with coordinator
        await self._register()

        # Start background tasks
        self._tasks.append(asyncio.create_task(self._heartbeat_loop()))
        self._tasks.append(asyncio.create_task(self._sync_loop()))

        logger.info(f"Worker started: {self.worker_id}")

    async def stop(self):
        """Stop the worker."""
        self._running = False

        # Stop fuzzer
        if self._fuzzer_process:
            self._fuzzer_process.terminate()
            self._fuzzer_process.wait()

        # Cancel background tasks
        for task in self._tasks:
            task.cancel()

        # Close session
        if self._session:
            await self._session.close()

        logger.info(f"Worker stopped: {self.worker_id}")

    async def _register(self):
        """Register with coordinator."""
        try:
            async with self._session.post(
                f"{self.coordinator_url}/api/worker/register",
                json={
                    "worker_id": self.worker_id,
                    "hostname": self.hostname,
                    "fuzzer_type": self.fuzzer_type.value,
                    "cores": self.cores,
                }
            ) as resp:
                data = await resp.json()
                if data.get("status") == "ok":
                    self.worker_id = data.get("worker_id", self.worker_id)
                    logger.info(f"Registered with coordinator: {self.worker_id}")
                else:
                    raise Exception(f"Registration failed: {data}")
        except Exception as e:
            logger.error(f"Failed to register: {e}")
            raise

    async def _heartbeat_loop(self):
        """Send periodic heartbeats to coordinator."""
        while self._running:
            try:
                await self._send_heartbeat()
            except Exception as e:
                logger.warning(f"Heartbeat failed: {e}")

            await asyncio.sleep(10)

    async def _send_heartbeat(self):
        """Send heartbeat to coordinator."""
        async with self._session.post(
            f"{self.coordinator_url}/api/worker/heartbeat",
            json={
                "worker_id": self.worker_id,
                "state": self.state.value,
                "executions": self.executions,
                "crashes_found": self.crashes_found,
            }
        ) as resp:
            await resp.json()

    async def _sync_loop(self):
        """Periodically sync seeds and coverage with coordinator."""
        while self._running:
            if self.state == WorkerState.FUZZING and self.current_campaign:
                try:
                    await self._sync_seeds()
                    await self._sync_coverage()
                except Exception as e:
                    logger.warning(f"Sync failed: {e}")

            await asyncio.sleep(30)

    async def join_campaign(self, campaign_id: str, binary_path: str):
        """
        Join a fuzzing campaign.

        Args:
            campaign_id: Campaign to join
            binary_path: Path to binary to fuzz
        """
        self.current_campaign = campaign_id
        self.state = WorkerState.FUZZING

        # Set up directories
        campaign_dir = self.work_dir / campaign_id
        input_dir = campaign_dir / "input"
        output_dir = campaign_dir / "output"

        input_dir.mkdir(parents=True, exist_ok=True)
        output_dir.mkdir(parents=True, exist_ok=True)

        # Get initial seeds from coordinator
        await self._fetch_initial_seeds(input_dir)

        # Create fuzzer config
        config = FuzzerConfig(
            fuzzer_type=self.fuzzer_type,
            binary_path=binary_path,
            input_dir=str(input_dir),
            output_dir=str(output_dir),
            cores=self.cores,
        )

        # Start fuzzer
        await self._start_fuzzer(config)

        # Monitor fuzzer
        await self._monitor_fuzzer(config)

    async def _fetch_initial_seeds(self, input_dir: Path):
        """Fetch initial seeds from coordinator."""
        # Create at least one seed if empty
        seed_file = input_dir / "seed_0"
        if not any(input_dir.iterdir()):
            seed_file.write_bytes(b"AAAA")

        # Try to get seeds from coordinator
        for _ in range(10):
            try:
                async with self._session.get(
                    f"{self.coordinator_url}/api/worker/seed",
                    params={"campaign_id": self.current_campaign}
                ) as resp:
                    data = await resp.json()
                    seed_hex = data.get("seed_hex")
                    if seed_hex:
                        seed_data = bytes.fromhex(seed_hex)
                        seed_hash = hashlib.sha256(seed_data).hexdigest()[:8]
                        seed_file = input_dir / f"seed_{seed_hash}"
                        seed_file.write_bytes(seed_data)
                    else:
                        break
            except Exception as e:
                logger.warning(f"Failed to fetch seed: {e}")
                break

    async def _start_fuzzer(self, config: FuzzerConfig):
        """Start the fuzzer process."""
        if config.fuzzer_type in (FuzzerType.AFL, FuzzerType.AFLPP):
            cmd = self._build_afl_command(config)
        elif config.fuzzer_type == FuzzerType.HONGGFUZZ:
            cmd = self._build_honggfuzz_command(config)
        elif config.fuzzer_type == FuzzerType.LIBFUZZER:
            cmd = self._build_libfuzzer_command(config)
        else:
            raise ValueError(f"Unsupported fuzzer: {config.fuzzer_type}")

        logger.info(f"Starting fuzzer: {' '.join(cmd)}")

        self._fuzzer_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(self.work_dir),
        )

    def _build_afl_command(self, config: FuzzerConfig) -> List[str]:
        """Build AFL/AFL++ command."""
        afl_bin = "afl-fuzz"

        cmd = [
            afl_bin,
            "-i", config.input_dir,
            "-o", config.output_dir,
            "-t", str(config.timeout),
            "-m", str(config.memory_limit),
        ]

        if config.dictionary:
            cmd.extend(["-x", config.dictionary])

        cmd.extend(config.extra_args)
        cmd.append("--")
        cmd.append(config.binary_path)

        return cmd

    def _build_honggfuzz_command(self, config: FuzzerConfig) -> List[str]:
        """Build Honggfuzz command."""
        cmd = [
            "honggfuzz",
            "-i", config.input_dir,
            "-o", config.output_dir,
            "--timeout", str(config.timeout // 1000),
            "-n", str(config.cores),
        ]

        cmd.extend(config.extra_args)
        cmd.append("--")
        cmd.append(config.binary_path)

        return cmd

    def _build_libfuzzer_command(self, config: FuzzerConfig) -> List[str]:
        """Build LibFuzzer command."""
        cmd = [
            config.binary_path,
            config.input_dir,
            f"-max_total_time={config.timeout}",
            f"-rss_limit_mb={config.memory_limit}",
            f"-jobs={config.cores}",
        ]

        cmd.extend(config.extra_args)

        return cmd

    async def _monitor_fuzzer(self, config: FuzzerConfig):
        """Monitor fuzzer for crashes and new coverage."""
        output_dir = Path(config.output_dir)
        crashes_dir = output_dir / "crashes" if config.fuzzer_type in (FuzzerType.AFL, FuzzerType.AFLPP) else output_dir
        queue_dir = output_dir / "queue" if config.fuzzer_type in (FuzzerType.AFL, FuzzerType.AFLPP) else output_dir

        seen_crashes: Set[str] = set()
        seen_seeds: Set[str] = set()

        while self._running and self._fuzzer_process and self._fuzzer_process.poll() is None:
            # Check for new crashes
            if crashes_dir.exists():
                for crash_file in crashes_dir.glob("id:*" if config.fuzzer_type in (FuzzerType.AFL, FuzzerType.AFLPP) else "*"):
                    if crash_file.name not in seen_crashes:
                        seen_crashes.add(crash_file.name)
                        await self._report_crash(crash_file)

            # Check for new seeds
            if queue_dir.exists():
                for seed_file in queue_dir.glob("id:*" if config.fuzzer_type in (FuzzerType.AFL, FuzzerType.AFLPP) else "*"):
                    if seed_file.name not in seen_seeds:
                        seen_seeds.add(seed_file.name)
                        await self._submit_seed(seed_file)

            # Update stats
            await self._update_stats(output_dir, config)

            await asyncio.sleep(5)

        logger.info("Fuzzer process ended")

    async def _report_crash(self, crash_file: Path):
        """Report crash to coordinator."""
        crash_data = crash_file.read_bytes()
        self.crashes_found += 1

        # Analyze crash (simplified)
        crash_type = "unknown"
        if b"SEGV" in crash_file.name.encode() or "sig:11" in crash_file.name:
            crash_type = "segfault"
        elif b"ABRT" in crash_file.name.encode() or "sig:06" in crash_file.name:
            crash_type = "abort"

        try:
            async with self._session.post(
                f"{self.coordinator_url}/api/worker/crash",
                json={
                    "worker_id": self.worker_id,
                    "campaign_id": self.current_campaign,
                    "input_hex": crash_data.hex(),
                    "crash_type": crash_type,
                    "signal": 11 if crash_type == "segfault" else 6,
                }
            ) as resp:
                data = await resp.json()
                logger.info(f"Crash reported: unique={data.get('is_unique')}")
        except Exception as e:
            logger.warning(f"Failed to report crash: {e}")

    async def _submit_seed(self, seed_file: Path):
        """Submit new seed to coordinator."""
        seed_data = seed_file.read_bytes()

        try:
            async with self._session.post(
                f"{self.coordinator_url}/api/worker/seed",
                json={
                    "worker_id": self.worker_id,
                    "campaign_id": self.current_campaign,
                    "seed_hex": seed_data.hex(),
                }
            ) as resp:
                await resp.json()
        except Exception as e:
            logger.warning(f"Failed to submit seed: {e}")

    async def _sync_seeds(self):
        """Sync seeds from coordinator."""
        try:
            async with self._session.get(
                f"{self.coordinator_url}/api/worker/seed",
                params={"campaign_id": self.current_campaign}
            ) as resp:
                data = await resp.json()
                seed_hex = data.get("seed_hex")
                if seed_hex:
                    seed_data = bytes.fromhex(seed_hex)
                    # Add to local queue
                    seed_hash = hashlib.sha256(seed_data).hexdigest()[:8]
                    input_dir = self.work_dir / self.current_campaign / "input"
                    seed_file = input_dir / f"sync_{seed_hash}"
                    if not seed_file.exists():
                        seed_file.write_bytes(seed_data)
        except Exception as e:
            logger.warning(f"Failed to sync seeds: {e}")

    async def _sync_coverage(self):
        """Sync coverage with coordinator."""
        # Read AFL bitmap if available
        bitmap_path = self.work_dir / self.current_campaign / "output" / "fuzz_bitmap"
        if bitmap_path.exists():
            coverage_data = bitmap_path.read_bytes()

            try:
                async with self._session.post(
                    f"{self.coordinator_url}/api/worker/coverage",
                    json={
                        "worker_id": self.worker_id,
                        "campaign_id": self.current_campaign,
                        "coverage_hex": coverage_data.hex(),
                    }
                ) as resp:
                    await resp.json()
            except Exception as e:
                logger.warning(f"Failed to sync coverage: {e}")

    async def _update_stats(self, output_dir: Path, config: FuzzerConfig):
        """Update execution statistics."""
        # Try to read AFL stats
        stats_file = output_dir / "fuzzer_stats"
        if stats_file.exists():
            try:
                stats_text = stats_file.read_text()
                for line in stats_text.split('\n'):
                    if line.startswith("execs_done"):
                        self.executions = int(line.split(':')[1].strip())
                        break
            except:
                pass


# Convenience function to run worker
async def run_worker(
    coordinator_url: str,
    campaign_id: str,
    binary_path: str,
    fuzzer_type: str = "afl++",
    cores: int = 1
):
    """
    Run a fuzzing worker.

    Args:
        coordinator_url: URL of coordinator server
        campaign_id: Campaign to join
        binary_path: Path to binary to fuzz
        fuzzer_type: Fuzzer type (afl, afl++, honggfuzz, libfuzzer)
        cores: Number of cores to use
    """
    ftype = FuzzerType(fuzzer_type) if fuzzer_type in [f.value for f in FuzzerType] else FuzzerType.AFLPP

    worker = FuzzingWorker(
        coordinator_url=coordinator_url,
        fuzzer_type=ftype,
        cores=cores,
    )

    await worker.start()

    try:
        await worker.join_campaign(campaign_id, binary_path)
    except KeyboardInterrupt:
        pass
    finally:
        await worker.stop()
