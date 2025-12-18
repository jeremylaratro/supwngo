"""
Distributed Fuzzing Coordinator.

Central coordination server for distributed fuzzing campaigns.
Manages workers, seed distribution, crash collection, and coverage tracking.
"""

import asyncio
import hashlib
import json
import os
import pickle
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
import uuid

from supwngo.utils.logging import get_logger

logger = get_logger(__name__)

# Try to import networking libraries
try:
    import aiohttp
    from aiohttp import web
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

try:
    import redis.asyncio as aioredis
    REDIS_AVAILABLE = True
except ImportError:
    try:
        import aioredis
        REDIS_AVAILABLE = True
    except ImportError:
        REDIS_AVAILABLE = False


class WorkerState(Enum):
    """Worker connection states."""
    IDLE = auto()
    FUZZING = auto()
    SYNCING = auto()
    ERROR = auto()
    OFFLINE = auto()


class CampaignState(Enum):
    """Fuzzing campaign states."""
    CREATED = auto()
    RUNNING = auto()
    PAUSED = auto()
    COMPLETED = auto()
    FAILED = auto()


@dataclass
class WorkerInfo:
    """Information about a connected worker."""
    worker_id: str
    hostname: str
    ip_address: str
    state: WorkerState = WorkerState.IDLE
    fuzzer_type: str = "afl"
    cores: int = 1
    last_heartbeat: float = 0.0
    executions: int = 0
    crashes_found: int = 0
    coverage_bitmap: Optional[bytes] = None
    current_seed: Optional[str] = None

    def is_alive(self, timeout: float = 60.0) -> bool:
        """Check if worker is still alive based on heartbeat."""
        return time.time() - self.last_heartbeat < timeout

    def to_dict(self) -> Dict[str, Any]:
        return {
            "worker_id": self.worker_id,
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "state": self.state.name,
            "fuzzer_type": self.fuzzer_type,
            "cores": self.cores,
            "last_heartbeat": self.last_heartbeat,
            "executions": self.executions,
            "crashes_found": self.crashes_found,
        }


@dataclass
class CrashInfo:
    """Information about a discovered crash."""
    crash_id: str
    worker_id: str
    timestamp: float
    input_hash: str
    input_data: bytes
    signal: int = 0
    crash_type: str = "unknown"
    stack_trace: str = ""
    is_unique: bool = True
    exploitability: str = "unknown"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "crash_id": self.crash_id,
            "worker_id": self.worker_id,
            "timestamp": self.timestamp,
            "input_hash": self.input_hash,
            "signal": self.signal,
            "crash_type": self.crash_type,
            "exploitability": self.exploitability,
            "is_unique": self.is_unique,
        }


@dataclass
class FuzzingCampaign:
    """A fuzzing campaign configuration."""
    campaign_id: str
    binary_path: str
    binary_hash: str
    state: CampaignState = CampaignState.CREATED
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    ended_at: Optional[float] = None

    # Configuration
    timeout: int = 3600  # seconds
    memory_limit: int = 512  # MB
    fuzzer_args: Dict[str, Any] = field(default_factory=dict)

    # Statistics
    total_executions: int = 0
    total_crashes: int = 0
    unique_crashes: int = 0
    coverage_percentage: float = 0.0

    # Seeds
    initial_seeds: List[str] = field(default_factory=list)
    corpus_size: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "binary_path": self.binary_path,
            "state": self.state.name,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "timeout": self.timeout,
            "total_executions": self.total_executions,
            "total_crashes": self.total_crashes,
            "unique_crashes": self.unique_crashes,
            "coverage_percentage": self.coverage_percentage,
            "corpus_size": self.corpus_size,
        }


class FuzzingCoordinator:
    """
    Central coordinator for distributed fuzzing.

    Manages:
    - Worker registration and health monitoring
    - Seed distribution and synchronization
    - Crash collection and deduplication
    - Coverage aggregation
    - Campaign lifecycle

    Example:
        coordinator = FuzzingCoordinator()

        # Start coordinator server
        await coordinator.start(host='0.0.0.0', port=8080)

        # Create fuzzing campaign
        campaign = await coordinator.create_campaign(
            binary_path='/path/to/binary',
            initial_seeds=['seed1', 'seed2']
        )

        # Start campaign
        await coordinator.start_campaign(campaign.campaign_id)
    """

    def __init__(
        self,
        data_dir: Optional[str] = None,
        redis_url: Optional[str] = None
    ):
        """
        Initialize coordinator.

        Args:
            data_dir: Directory for storing campaign data
            redis_url: Redis URL for distributed state (optional)
        """
        self.data_dir = Path(data_dir or "/tmp/supwngo_fuzzing")
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.redis_url = redis_url
        self._redis = None

        # In-memory state
        self.workers: Dict[str, WorkerInfo] = {}
        self.campaigns: Dict[str, FuzzingCampaign] = {}
        self.crashes: Dict[str, List[CrashInfo]] = defaultdict(list)
        self.seed_queue: Dict[str, asyncio.Queue] = {}

        # Coverage tracking
        self.global_coverage: Dict[str, bytes] = {}  # campaign_id -> bitmap

        # Web server
        self._app = None
        self._runner = None

        # Background tasks
        self._tasks: List[asyncio.Task] = []

    async def start(self, host: str = '0.0.0.0', port: int = 8080):
        """
        Start the coordinator server.

        Args:
            host: Host to bind to
            port: Port to listen on
        """
        if not AIOHTTP_AVAILABLE:
            raise ImportError("aiohttp required. Install with: pip install aiohttp")

        # Connect to Redis if configured
        if self.redis_url and REDIS_AVAILABLE:
            self._redis = await aioredis.from_url(self.redis_url)
            logger.info(f"Connected to Redis: {self.redis_url}")

        # Create web application
        self._app = web.Application()
        self._setup_routes()

        # Start background tasks
        self._tasks.append(asyncio.create_task(self._heartbeat_monitor()))
        self._tasks.append(asyncio.create_task(self._stats_aggregator()))

        # Start server
        self._runner = web.AppRunner(self._app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, host, port)
        await site.start()

        logger.info(f"Coordinator started on {host}:{port}")

    async def stop(self):
        """Stop the coordinator server."""
        # Cancel background tasks
        for task in self._tasks:
            task.cancel()

        # Stop web server
        if self._runner:
            await self._runner.cleanup()

        # Close Redis connection
        if self._redis:
            await self._redis.close()

        logger.info("Coordinator stopped")

    def _setup_routes(self):
        """Set up HTTP API routes."""
        self._app.router.add_post('/api/worker/register', self._handle_worker_register)
        self._app.router.add_post('/api/worker/heartbeat', self._handle_worker_heartbeat)
        self._app.router.add_post('/api/worker/crash', self._handle_crash_report)
        self._app.router.add_post('/api/worker/seed', self._handle_seed_submit)
        self._app.router.add_get('/api/worker/seed', self._handle_seed_request)
        self._app.router.add_post('/api/worker/coverage', self._handle_coverage_update)

        self._app.router.add_post('/api/campaign/create', self._handle_campaign_create)
        self._app.router.add_post('/api/campaign/start', self._handle_campaign_start)
        self._app.router.add_post('/api/campaign/stop', self._handle_campaign_stop)
        self._app.router.add_get('/api/campaign/status', self._handle_campaign_status)

        self._app.router.add_get('/api/stats', self._handle_stats)
        self._app.router.add_get('/api/crashes', self._handle_crashes)
        self._app.router.add_get('/api/workers', self._handle_workers)

    # === Worker Management ===

    async def _handle_worker_register(self, request: web.Request) -> web.Response:
        """Handle worker registration."""
        data = await request.json()

        worker_id = data.get('worker_id') or str(uuid.uuid4())
        worker = WorkerInfo(
            worker_id=worker_id,
            hostname=data.get('hostname', 'unknown'),
            ip_address=request.remote or 'unknown',
            fuzzer_type=data.get('fuzzer_type', 'afl'),
            cores=data.get('cores', 1),
            last_heartbeat=time.time(),
        )

        self.workers[worker_id] = worker
        logger.info(f"Worker registered: {worker_id} ({worker.hostname})")

        return web.json_response({
            "status": "ok",
            "worker_id": worker_id,
        })

    async def _handle_worker_heartbeat(self, request: web.Request) -> web.Response:
        """Handle worker heartbeat."""
        data = await request.json()
        worker_id = data.get('worker_id')

        if worker_id not in self.workers:
            return web.json_response({"status": "error", "message": "Unknown worker"}, status=404)

        worker = self.workers[worker_id]
        worker.last_heartbeat = time.time()
        worker.state = WorkerState(data.get('state', WorkerState.IDLE.value))
        worker.executions = data.get('executions', worker.executions)
        worker.crashes_found = data.get('crashes_found', worker.crashes_found)

        return web.json_response({"status": "ok"})

    async def _heartbeat_monitor(self):
        """Background task to monitor worker health."""
        while True:
            await asyncio.sleep(30)

            dead_workers = []
            for worker_id, worker in self.workers.items():
                if not worker.is_alive():
                    worker.state = WorkerState.OFFLINE
                    dead_workers.append(worker_id)
                    logger.warning(f"Worker offline: {worker_id}")

            # Optionally remove dead workers after some time
            # for worker_id in dead_workers:
            #     del self.workers[worker_id]

    # === Crash Handling ===

    async def _handle_crash_report(self, request: web.Request) -> web.Response:
        """Handle crash report from worker."""
        data = await request.json()
        worker_id = data.get('worker_id')
        campaign_id = data.get('campaign_id')

        if worker_id not in self.workers:
            return web.json_response({"status": "error", "message": "Unknown worker"}, status=404)

        # Decode crash input
        input_data = bytes.fromhex(data.get('input_hex', ''))
        input_hash = hashlib.sha256(input_data).hexdigest()[:16]

        # Check for duplicate
        is_unique = self._is_unique_crash(campaign_id, input_hash)

        crash = CrashInfo(
            crash_id=str(uuid.uuid4()),
            worker_id=worker_id,
            timestamp=time.time(),
            input_hash=input_hash,
            input_data=input_data,
            signal=data.get('signal', 0),
            crash_type=data.get('crash_type', 'unknown'),
            stack_trace=data.get('stack_trace', ''),
            is_unique=is_unique,
            exploitability=data.get('exploitability', 'unknown'),
        )

        self.crashes[campaign_id].append(crash)

        # Save crash input
        crash_dir = self.data_dir / campaign_id / "crashes"
        crash_dir.mkdir(parents=True, exist_ok=True)
        crash_file = crash_dir / f"crash_{input_hash}"
        crash_file.write_bytes(input_data)

        # Update campaign stats
        if campaign_id in self.campaigns:
            self.campaigns[campaign_id].total_crashes += 1
            if is_unique:
                self.campaigns[campaign_id].unique_crashes += 1

        logger.info(f"Crash reported: {crash.crash_id} (unique={is_unique})")

        return web.json_response({
            "status": "ok",
            "crash_id": crash.crash_id,
            "is_unique": is_unique,
        })

    def _is_unique_crash(self, campaign_id: str, input_hash: str) -> bool:
        """Check if crash is unique based on input hash."""
        existing_hashes = {c.input_hash for c in self.crashes.get(campaign_id, [])}
        return input_hash not in existing_hashes

    # === Seed Management ===

    async def _handle_seed_submit(self, request: web.Request) -> web.Response:
        """Handle new seed submission from worker."""
        data = await request.json()
        campaign_id = data.get('campaign_id')
        seed_data = bytes.fromhex(data.get('seed_hex', ''))

        if campaign_id not in self.campaigns:
            return web.json_response({"status": "error", "message": "Unknown campaign"}, status=404)

        # Save seed
        seed_hash = hashlib.sha256(seed_data).hexdigest()[:16]
        seed_dir = self.data_dir / campaign_id / "corpus"
        seed_dir.mkdir(parents=True, exist_ok=True)
        seed_file = seed_dir / f"seed_{seed_hash}"

        if not seed_file.exists():
            seed_file.write_bytes(seed_data)
            self.campaigns[campaign_id].corpus_size += 1

            # Add to queue for distribution
            if campaign_id in self.seed_queue:
                await self.seed_queue[campaign_id].put(seed_data)

            logger.debug(f"New seed added: {seed_hash}")

        return web.json_response({"status": "ok", "seed_hash": seed_hash})

    async def _handle_seed_request(self, request: web.Request) -> web.Response:
        """Handle seed request from worker."""
        campaign_id = request.query.get('campaign_id')

        if campaign_id not in self.campaigns:
            return web.json_response({"status": "error", "message": "Unknown campaign"}, status=404)

        # Try to get seed from queue
        if campaign_id in self.seed_queue:
            try:
                seed_data = await asyncio.wait_for(
                    self.seed_queue[campaign_id].get(),
                    timeout=1.0
                )
                return web.json_response({
                    "status": "ok",
                    "seed_hex": seed_data.hex(),
                })
            except asyncio.TimeoutError:
                pass

        return web.json_response({"status": "ok", "seed_hex": None})

    # === Coverage Tracking ===

    async def _handle_coverage_update(self, request: web.Request) -> web.Response:
        """Handle coverage bitmap update from worker."""
        data = await request.json()
        campaign_id = data.get('campaign_id')
        coverage_hex = data.get('coverage_hex', '')

        if campaign_id not in self.campaigns:
            return web.json_response({"status": "error", "message": "Unknown campaign"}, status=404)

        worker_coverage = bytes.fromhex(coverage_hex)

        # Merge with global coverage
        if campaign_id not in self.global_coverage:
            self.global_coverage[campaign_id] = worker_coverage
        else:
            global_cov = bytearray(self.global_coverage[campaign_id])
            for i, b in enumerate(worker_coverage):
                if i < len(global_cov):
                    global_cov[i] |= b
            self.global_coverage[campaign_id] = bytes(global_cov)

        # Calculate coverage percentage
        total_bits = len(self.global_coverage[campaign_id]) * 8
        set_bits = sum(bin(b).count('1') for b in self.global_coverage[campaign_id])
        coverage_pct = (set_bits / total_bits * 100) if total_bits > 0 else 0

        self.campaigns[campaign_id].coverage_percentage = coverage_pct

        return web.json_response({
            "status": "ok",
            "global_coverage_pct": coverage_pct,
        })

    # === Campaign Management ===

    async def _handle_campaign_create(self, request: web.Request) -> web.Response:
        """Create a new fuzzing campaign."""
        data = await request.json()

        campaign_id = str(uuid.uuid4())
        binary_path = data.get('binary_path')

        # Hash binary
        binary_hash = ""
        if binary_path and os.path.exists(binary_path):
            with open(binary_path, 'rb') as f:
                binary_hash = hashlib.sha256(f.read()).hexdigest()[:16]

        campaign = FuzzingCampaign(
            campaign_id=campaign_id,
            binary_path=binary_path,
            binary_hash=binary_hash,
            timeout=data.get('timeout', 3600),
            memory_limit=data.get('memory_limit', 512),
            fuzzer_args=data.get('fuzzer_args', {}),
            initial_seeds=data.get('initial_seeds', []),
        )

        self.campaigns[campaign_id] = campaign
        self.seed_queue[campaign_id] = asyncio.Queue()

        # Create campaign directory
        campaign_dir = self.data_dir / campaign_id
        campaign_dir.mkdir(parents=True, exist_ok=True)

        logger.info(f"Campaign created: {campaign_id}")

        return web.json_response({
            "status": "ok",
            "campaign_id": campaign_id,
        })

    async def _handle_campaign_start(self, request: web.Request) -> web.Response:
        """Start a fuzzing campaign."""
        data = await request.json()
        campaign_id = data.get('campaign_id')

        if campaign_id not in self.campaigns:
            return web.json_response({"status": "error", "message": "Unknown campaign"}, status=404)

        campaign = self.campaigns[campaign_id]
        campaign.state = CampaignState.RUNNING
        campaign.started_at = time.time()

        # Seed the queue with initial seeds
        for seed_path in campaign.initial_seeds:
            if os.path.exists(seed_path):
                with open(seed_path, 'rb') as f:
                    await self.seed_queue[campaign_id].put(f.read())

        logger.info(f"Campaign started: {campaign_id}")

        return web.json_response({"status": "ok"})

    async def _handle_campaign_stop(self, request: web.Request) -> web.Response:
        """Stop a fuzzing campaign."""
        data = await request.json()
        campaign_id = data.get('campaign_id')

        if campaign_id not in self.campaigns:
            return web.json_response({"status": "error", "message": "Unknown campaign"}, status=404)

        campaign = self.campaigns[campaign_id]
        campaign.state = CampaignState.COMPLETED
        campaign.ended_at = time.time()

        logger.info(f"Campaign stopped: {campaign_id}")

        return web.json_response({"status": "ok"})

    async def _handle_campaign_status(self, request: web.Request) -> web.Response:
        """Get campaign status."""
        campaign_id = request.query.get('campaign_id')

        if campaign_id not in self.campaigns:
            return web.json_response({"status": "error", "message": "Unknown campaign"}, status=404)

        return web.json_response({
            "status": "ok",
            "campaign": self.campaigns[campaign_id].to_dict(),
        })

    # === Statistics ===

    async def _stats_aggregator(self):
        """Background task to aggregate statistics."""
        while True:
            await asyncio.sleep(10)

            for campaign_id, campaign in self.campaigns.items():
                if campaign.state != CampaignState.RUNNING:
                    continue

                # Aggregate executions from workers
                total_execs = sum(
                    w.executions for w in self.workers.values()
                    if w.state == WorkerState.FUZZING
                )
                campaign.total_executions = total_execs

    async def _handle_stats(self, request: web.Request) -> web.Response:
        """Get overall statistics."""
        stats = {
            "workers": {
                "total": len(self.workers),
                "active": sum(1 for w in self.workers.values() if w.state == WorkerState.FUZZING),
                "idle": sum(1 for w in self.workers.values() if w.state == WorkerState.IDLE),
                "offline": sum(1 for w in self.workers.values() if w.state == WorkerState.OFFLINE),
            },
            "campaigns": {
                "total": len(self.campaigns),
                "running": sum(1 for c in self.campaigns.values() if c.state == CampaignState.RUNNING),
            },
            "crashes": {
                "total": sum(len(crashes) for crashes in self.crashes.values()),
                "unique": sum(sum(1 for c in crashes if c.is_unique) for crashes in self.crashes.values()),
            },
        }

        return web.json_response({"status": "ok", "stats": stats})

    async def _handle_crashes(self, request: web.Request) -> web.Response:
        """Get crash list."""
        campaign_id = request.query.get('campaign_id')

        if campaign_id:
            crashes = [c.to_dict() for c in self.crashes.get(campaign_id, [])]
        else:
            crashes = [c.to_dict() for crashes in self.crashes.values() for c in crashes]

        return web.json_response({"status": "ok", "crashes": crashes})

    async def _handle_workers(self, request: web.Request) -> web.Response:
        """Get worker list."""
        workers = [w.to_dict() for w in self.workers.values()]
        return web.json_response({"status": "ok", "workers": workers})


# Convenience function to run coordinator
async def run_coordinator(host: str = '0.0.0.0', port: int = 8080, **kwargs):
    """
    Run the fuzzing coordinator.

    Args:
        host: Host to bind to
        port: Port to listen on
        **kwargs: Additional arguments for FuzzingCoordinator
    """
    coordinator = FuzzingCoordinator(**kwargs)
    await coordinator.start(host, port)

    # Keep running
    try:
        while True:
            await asyncio.sleep(3600)
    except asyncio.CancelledError:
        await coordinator.stop()
