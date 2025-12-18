"""
Distributed Fuzzing Infrastructure for supwngo.

Provides scalable fuzzing across multiple machines with:
- Central coordinator for campaign management
- Worker nodes running various fuzzers
- Intelligent seed sharing and synchronization
- Distributed coverage tracking and merging

Example:
    # Start coordinator
    from supwngo.distributed import FuzzingCoordinator, run_coordinator

    coordinator = FuzzingCoordinator(host="0.0.0.0", port=8080)
    campaign = coordinator.create_campaign(
        name="my_campaign",
        binary_path="/path/to/target"
    )
    await coordinator.start()

    # Start workers (on different machines)
    from supwngo.distributed import FuzzingWorker, FuzzerType, run_worker

    worker = FuzzingWorker(
        coordinator_url="http://coordinator:8080",
        fuzzer_type=FuzzerType.AFLPP,
        cores=4
    )
    await worker.start()
    await worker.join_campaign(campaign_id, binary_path)

    # Or use convenience functions
    await run_coordinator(host="0.0.0.0", port=8080)
    await run_worker("http://coordinator:8080", campaign_id, binary_path)
"""

from supwngo.distributed.coordinator import (
    FuzzingCoordinator,
    FuzzingCampaign,
    WorkerInfo,
    CrashInfo,
    CampaignStatus,
    run_coordinator,
)

from supwngo.distributed.worker import (
    FuzzingWorker,
    FuzzerType,
    FuzzerConfig,
    WorkerState,
    CrashReport,
    run_worker,
)

from supwngo.distributed.seed_sharing import (
    SeedPool,
    SeedEntry,
    SeedScorer,
    SeedSynchronizer,
    AdaptiveSeedScheduler,
    SyncDelta,
    SchedulingDecision,
)

from supwngo.distributed.coverage_merge import (
    CoverageMerger,
    CoverageBitmap,
    CoverageAggregator,
    CoverageStats,
    CoverageEntry,
    CoverageType,
    DistributedCoverageTracker,
)

__all__ = [
    # Coordinator
    "FuzzingCoordinator",
    "FuzzingCampaign",
    "WorkerInfo",
    "CrashInfo",
    "CampaignStatus",
    "run_coordinator",
    # Worker
    "FuzzingWorker",
    "FuzzerType",
    "FuzzerConfig",
    "WorkerState",
    "CrashReport",
    "run_worker",
    # Seed Sharing
    "SeedPool",
    "SeedEntry",
    "SeedScorer",
    "SeedSynchronizer",
    "AdaptiveSeedScheduler",
    "SyncDelta",
    "SchedulingDecision",
    # Coverage Merging
    "CoverageMerger",
    "CoverageBitmap",
    "CoverageAggregator",
    "CoverageStats",
    "CoverageEntry",
    "CoverageType",
    "DistributedCoverageTracker",
]
