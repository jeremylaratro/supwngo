"""
Intelligent Seed Sharing for Distributed Fuzzing.

Implements smart seed synchronization strategies:
- Coverage-based seed prioritization
- Mutation scoring
- Cross-pollination between workers
"""

import hashlib
import heapq
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple
import random

from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


class SeedPriority(Enum):
    """Seed priority levels."""
    CRITICAL = 5    # Found new crashes
    HIGH = 4        # Significant new coverage
    MEDIUM = 3      # Some new coverage
    LOW = 2         # Minor coverage increase
    MINIMAL = 1     # No new coverage but interesting


@dataclass(order=True)
class SeedEntry:
    """A seed in the shared pool."""
    priority: int
    seed_id: str = field(compare=False)
    data: bytes = field(compare=False)
    coverage_hash: str = field(compare=False, default="")
    source_worker: str = field(compare=False, default="")
    timestamp: float = field(compare=False, default_factory=time.time)
    execution_count: int = field(compare=False, default=0)
    crash_count: int = field(compare=False, default=0)
    coverage_bits: int = field(compare=False, default=0)
    mutation_depth: int = field(compare=False, default=0)

    def __hash__(self):
        return hash(self.seed_id)


@dataclass
class CoverageInfo:
    """Coverage information for a seed."""
    bitmap: bytes
    edge_count: int = 0
    unique_edges: Set[int] = field(default_factory=set)
    hit_counts: Dict[int, int] = field(default_factory=dict)


class SeedScorer:
    """
    Scores seeds based on various metrics.

    Higher scores indicate more valuable seeds for fuzzing.
    """

    # Weights for different scoring factors
    WEIGHTS = {
        'coverage': 0.4,      # New coverage is most important
        'uniqueness': 0.25,   # Unique paths are valuable
        'freshness': 0.15,    # Newer seeds may be more interesting
        'size': 0.1,          # Smaller seeds are generally better
        'mutation': 0.1,      # Mutation depth affects exploration
    }

    def __init__(self, global_coverage: Optional[bytes] = None):
        """
        Initialize scorer.

        Args:
            global_coverage: Global coverage bitmap for comparison
        """
        self.global_coverage = global_coverage or bytes(65536)
        self._coverage_seen: Set[str] = set()

    def score(self, seed: SeedEntry, coverage: Optional[CoverageInfo] = None) -> float:
        """
        Calculate overall score for a seed.

        Args:
            seed: Seed entry to score
            coverage: Optional coverage information

        Returns:
            Score between 0.0 and 1.0
        """
        scores = {
            'coverage': self._score_coverage(seed, coverage),
            'uniqueness': self._score_uniqueness(seed),
            'freshness': self._score_freshness(seed),
            'size': self._score_size(seed),
            'mutation': self._score_mutation(seed),
        }

        total = sum(scores[k] * self.WEIGHTS[k] for k in scores)
        return min(1.0, max(0.0, total))

    def _score_coverage(self, seed: SeedEntry, coverage: Optional[CoverageInfo]) -> float:
        """Score based on coverage contribution."""
        if not coverage:
            return 0.5  # Unknown coverage

        # Calculate new edges found
        new_edges = 0
        for i, b in enumerate(coverage.bitmap):
            if b > 0 and (i >= len(self.global_coverage) or self.global_coverage[i] == 0):
                new_edges += 1

        # Normalize by typical bitmap size
        return min(1.0, new_edges / 100)

    def _score_uniqueness(self, seed: SeedEntry) -> float:
        """Score based on uniqueness of coverage pattern."""
        if seed.coverage_hash in self._coverage_seen:
            return 0.2
        self._coverage_seen.add(seed.coverage_hash)
        return 1.0

    def _score_freshness(self, seed: SeedEntry) -> float:
        """Score based on how recent the seed is."""
        age = time.time() - seed.timestamp
        # Decay over 1 hour
        return max(0.1, 1.0 - (age / 3600))

    def _score_size(self, seed: SeedEntry) -> float:
        """Score based on seed size (smaller is better)."""
        size = len(seed.data)
        # Prefer seeds under 1KB
        if size < 256:
            return 1.0
        elif size < 1024:
            return 0.8
        elif size < 4096:
            return 0.5
        else:
            return 0.2

    def _score_mutation(self, seed: SeedEntry) -> float:
        """Score based on mutation depth."""
        # Seeds with moderate mutation depth are interesting
        if seed.mutation_depth == 0:
            return 0.5  # Initial seed
        elif seed.mutation_depth < 10:
            return 1.0  # Early mutations
        elif seed.mutation_depth < 50:
            return 0.7  # Mid-depth
        else:
            return 0.3  # Deep mutations may be less effective


class SeedPool:
    """
    Shared seed pool for distributed fuzzing.

    Manages seed storage, prioritization, and distribution
    across multiple workers.
    """

    def __init__(self, max_size: int = 10000):
        """
        Initialize seed pool.

        Args:
            max_size: Maximum number of seeds to store
        """
        self.max_size = max_size
        self.seeds: Dict[str, SeedEntry] = {}
        self._priority_queue: List[SeedEntry] = []
        self._by_worker: Dict[str, Set[str]] = defaultdict(set)
        self._by_coverage: Dict[str, Set[str]] = defaultdict(set)

        self.scorer = SeedScorer()

        # Statistics
        self.total_added = 0
        self.total_distributed = 0

    def add_seed(
        self,
        data: bytes,
        source_worker: str = "",
        coverage: Optional[CoverageInfo] = None,
        priority: Optional[SeedPriority] = None
    ) -> Optional[SeedEntry]:
        """
        Add a seed to the pool.

        Args:
            data: Seed data
            source_worker: Worker that found this seed
            coverage: Coverage information
            priority: Override automatic priority

        Returns:
            SeedEntry if added, None if duplicate
        """
        seed_id = hashlib.sha256(data).hexdigest()[:16]

        # Check for duplicate
        if seed_id in self.seeds:
            return None

        # Calculate coverage hash
        coverage_hash = ""
        if coverage:
            coverage_hash = hashlib.sha256(coverage.bitmap).hexdigest()[:16]

        # Calculate priority
        if priority is None:
            score = self.scorer.score(
                SeedEntry(priority=0, seed_id=seed_id, data=data, coverage_hash=coverage_hash),
                coverage
            )
            if score > 0.8:
                priority = SeedPriority.HIGH
            elif score > 0.5:
                priority = SeedPriority.MEDIUM
            elif score > 0.2:
                priority = SeedPriority.LOW
            else:
                priority = SeedPriority.MINIMAL

        entry = SeedEntry(
            priority=-priority.value,  # Negative for max-heap behavior
            seed_id=seed_id,
            data=data,
            coverage_hash=coverage_hash,
            source_worker=source_worker,
            coverage_bits=coverage.edge_count if coverage else 0,
        )

        # Add to pool
        self.seeds[seed_id] = entry
        heapq.heappush(self._priority_queue, entry)
        self._by_worker[source_worker].add(seed_id)
        if coverage_hash:
            self._by_coverage[coverage_hash].add(seed_id)

        self.total_added += 1

        # Enforce size limit
        self._enforce_size_limit()

        logger.debug(f"Added seed {seed_id} with priority {priority.name}")
        return entry

    def get_seed(self, worker_id: str = "") -> Optional[SeedEntry]:
        """
        Get next seed for a worker.

        Args:
            worker_id: Worker requesting seed

        Returns:
            SeedEntry or None if pool is empty
        """
        if not self._priority_queue:
            return None

        # Get highest priority seed
        entry = heapq.heappop(self._priority_queue)

        # Re-add with lower priority for round-robin
        entry.execution_count += 1
        entry.priority = min(entry.priority + 1, -SeedPriority.MINIMAL.value)
        heapq.heappush(self._priority_queue, entry)

        self.total_distributed += 1
        return entry

    def get_seeds_for_worker(
        self,
        worker_id: str,
        count: int = 10,
        exclude_own: bool = True
    ) -> List[SeedEntry]:
        """
        Get multiple seeds for a worker.

        Args:
            worker_id: Worker requesting seeds
            count: Number of seeds to get
            exclude_own: Exclude seeds from this worker

        Returns:
            List of seed entries
        """
        seeds = []
        own_seeds = self._by_worker.get(worker_id, set()) if exclude_own else set()

        # Get seeds by priority, excluding own
        candidates = [s for s in self.seeds.values() if s.seed_id not in own_seeds]
        candidates.sort(key=lambda s: s.priority)

        for seed in candidates[:count]:
            seeds.append(seed)
            seed.execution_count += 1

        return seeds

    def get_cross_pollination_seeds(
        self,
        worker_id: str,
        count: int = 5
    ) -> List[SeedEntry]:
        """
        Get seeds from other workers for cross-pollination.

        This helps share interesting seeds between workers
        running different fuzzer configurations.

        Args:
            worker_id: Worker requesting seeds
            count: Number of seeds to get

        Returns:
            List of seeds from other workers
        """
        other_workers = [w for w in self._by_worker.keys() if w != worker_id]
        if not other_workers:
            return []

        seeds = []
        for _ in range(count):
            # Pick random other worker
            source = random.choice(other_workers)
            source_seeds = list(self._by_worker[source])
            if source_seeds:
                seed_id = random.choice(source_seeds)
                if seed_id in self.seeds:
                    seeds.append(self.seeds[seed_id])

        return seeds

    def mark_crash(self, seed_id: str):
        """Mark that a seed found a crash."""
        if seed_id in self.seeds:
            self.seeds[seed_id].crash_count += 1
            # Boost priority
            self.seeds[seed_id].priority = -SeedPriority.CRITICAL.value

    def update_coverage(self, global_coverage: bytes):
        """Update global coverage for scoring."""
        self.scorer.global_coverage = global_coverage

    def _enforce_size_limit(self):
        """Remove low-priority seeds if over limit."""
        while len(self.seeds) > self.max_size:
            # Remove lowest priority (highest value due to negation)
            worst = max(self.seeds.values(), key=lambda s: s.priority)
            del self.seeds[worst.seed_id]
            self._by_worker[worst.source_worker].discard(worst.seed_id)
            self._by_coverage[worst.coverage_hash].discard(worst.seed_id)

    def get_stats(self) -> Dict[str, Any]:
        """Get pool statistics."""
        priority_dist = defaultdict(int)
        for seed in self.seeds.values():
            priority_dist[-seed.priority] += 1

        return {
            "total_seeds": len(self.seeds),
            "total_added": self.total_added,
            "total_distributed": self.total_distributed,
            "workers": len(self._by_worker),
            "unique_coverage_patterns": len(self._by_coverage),
            "priority_distribution": dict(priority_dist),
            "avg_execution_count": (
                sum(s.execution_count for s in self.seeds.values()) / max(len(self.seeds), 1)
            ),
        }


class SeedSynchronizer:
    """
    Synchronizes seeds between coordinator and workers.

    Handles:
    - Batched seed transfers
    - Delta synchronization
    - Conflict resolution
    """

    def __init__(self, pool: SeedPool):
        """
        Initialize synchronizer.

        Args:
            pool: Seed pool to synchronize
        """
        self.pool = pool
        self._worker_versions: Dict[str, int] = defaultdict(int)
        self._version = 0

    def get_delta(self, worker_id: str, since_version: int) -> Tuple[List[SeedEntry], int]:
        """
        Get seeds added since a version.

        Args:
            worker_id: Worker requesting delta
            since_version: Last version worker had

        Returns:
            Tuple of (new seeds, current version)
        """
        # For simplicity, return all seeds newer than worker's last sync
        new_seeds = [
            s for s in self.pool.seeds.values()
            if s.timestamp > self._worker_versions.get(worker_id, 0)
            and s.source_worker != worker_id
        ]

        self._worker_versions[worker_id] = time.time()
        return new_seeds, self._version

    def sync_from_worker(
        self,
        worker_id: str,
        seeds: List[Tuple[bytes, Optional[bytes]]]  # (data, coverage_bitmap)
    ) -> int:
        """
        Sync seeds from a worker.

        Args:
            worker_id: Worker sending seeds
            seeds: List of (seed_data, coverage_bitmap) tuples

        Returns:
            Number of new seeds added
        """
        added = 0
        for data, coverage_bitmap in seeds:
            coverage = None
            if coverage_bitmap:
                coverage = CoverageInfo(
                    bitmap=coverage_bitmap,
                    edge_count=sum(1 for b in coverage_bitmap if b > 0)
                )

            if self.pool.add_seed(data, worker_id, coverage):
                added += 1

        self._version += 1
        return added

    def get_sync_batch(
        self,
        worker_id: str,
        max_seeds: int = 100
    ) -> List[bytes]:
        """
        Get a batch of seeds for worker synchronization.

        Args:
            worker_id: Worker to sync to
            max_seeds: Maximum seeds in batch

        Returns:
            List of seed data
        """
        seeds = self.pool.get_seeds_for_worker(worker_id, max_seeds)
        return [s.data for s in seeds]


class AdaptiveSeedScheduler:
    """
    Adaptive seed scheduling based on coverage feedback.

    Adjusts seed selection strategy based on:
    - Coverage progress
    - Crash discovery rate
    - Worker utilization
    """

    def __init__(self, pool: SeedPool):
        """
        Initialize scheduler.

        Args:
            pool: Seed pool to schedule from
        """
        self.pool = pool
        self._history: List[Tuple[float, int, int]] = []  # (time, coverage, crashes)
        self._strategy = "balanced"

    def schedule(self, worker_id: str) -> List[SeedEntry]:
        """
        Schedule seeds for a worker.

        Args:
            worker_id: Worker to schedule for

        Returns:
            List of seeds to fuzz
        """
        # Adapt strategy based on progress
        self._update_strategy()

        if self._strategy == "exploration":
            # Focus on coverage - get diverse seeds
            return self._schedule_exploration(worker_id)
        elif self._strategy == "exploitation":
            # Focus on crashes - get seeds near crashes
            return self._schedule_exploitation(worker_id)
        else:
            # Balanced approach
            return self._schedule_balanced(worker_id)

    def _update_strategy(self):
        """Update scheduling strategy based on progress."""
        if len(self._history) < 2:
            return

        recent = self._history[-10:]
        old = self._history[:-10] if len(self._history) > 10 else []

        if not old:
            return

        # Calculate coverage progress rate
        recent_cov_rate = (recent[-1][1] - recent[0][1]) / max(len(recent), 1)
        old_cov_rate = (old[-1][1] - old[0][1]) / max(len(old), 1) if old else 0

        # Calculate crash rate
        recent_crash_rate = (recent[-1][2] - recent[0][2]) / max(len(recent), 1)

        # Adjust strategy
        if recent_cov_rate < old_cov_rate * 0.5:
            # Coverage slowing - try exploitation
            self._strategy = "exploitation"
        elif recent_crash_rate > 0:
            # Finding crashes - continue exploitation
            self._strategy = "exploitation"
        else:
            # Default to balanced
            self._strategy = "balanced"

    def _schedule_exploration(self, worker_id: str) -> List[SeedEntry]:
        """Schedule for coverage exploration."""
        # Get seeds with unique coverage patterns
        seeds = self.pool.get_seeds_for_worker(worker_id, 20)
        # Prioritize diversity
        seen_coverage: Set[str] = set()
        diverse = []
        for seed in seeds:
            if seed.coverage_hash not in seen_coverage:
                diverse.append(seed)
                seen_coverage.add(seed.coverage_hash)
        return diverse[:10]

    def _schedule_exploitation(self, worker_id: str) -> List[SeedEntry]:
        """Schedule for crash exploitation."""
        # Get seeds that have found crashes
        crash_seeds = [s for s in self.pool.seeds.values() if s.crash_count > 0]
        if crash_seeds:
            return crash_seeds[:10]
        # Fall back to high priority
        return self.pool.get_seeds_for_worker(worker_id, 10)

    def _schedule_balanced(self, worker_id: str) -> List[SeedEntry]:
        """Balanced scheduling."""
        seeds = []
        # Mix of strategies
        seeds.extend(self.pool.get_seeds_for_worker(worker_id, 5))
        seeds.extend(self.pool.get_cross_pollination_seeds(worker_id, 3))
        return seeds

    def record_progress(self, coverage: int, crashes: int):
        """Record progress for strategy adaptation."""
        self._history.append((time.time(), coverage, crashes))
        # Keep last 1000 entries
        if len(self._history) > 1000:
            self._history = self._history[-1000:]
