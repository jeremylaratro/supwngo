"""
Distributed Coverage Tracking and Merging.

Handles merging coverage bitmaps from multiple fuzzing workers,
tracking global coverage state, and identifying coverage frontiers.
"""

import hashlib
import struct
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import threading

from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


class CoverageType(Enum):
    """Types of coverage tracking."""
    EDGE = auto()      # AFL-style edge coverage
    BLOCK = auto()     # Basic block coverage
    PATH = auto()      # Full path coverage
    FUNCTION = auto()  # Function-level coverage


@dataclass
class CoverageEntry:
    """A single coverage entry from a worker."""
    worker_id: str
    timestamp: float
    coverage_type: CoverageType
    bitmap: bytes
    edge_count: int = 0
    new_edges: int = 0


@dataclass
class CoverageStats:
    """Statistics about coverage state."""
    total_edges: int = 0
    total_workers: int = 0
    coverage_percent: float = 0.0
    edges_per_worker: Dict[str, int] = field(default_factory=dict)
    unique_contributions: Dict[str, int] = field(default_factory=dict)
    last_new_coverage: float = 0.0
    stale_workers: List[str] = field(default_factory=list)


class CoverageBitmap:
    """
    Coverage bitmap with efficient merging operations.

    Uses AFL-style 64KB bitmap with hit counts bucketed.
    """

    MAP_SIZE = 65536  # 64KB standard AFL size

    # Hit count buckets (AFL-style)
    BUCKET_THRESHOLDS = [1, 2, 3, 4, 8, 16, 32, 128]

    def __init__(self, size: int = MAP_SIZE):
        """
        Initialize empty bitmap.

        Args:
            size: Bitmap size in bytes
        """
        self.size = size
        self._bitmap = bytearray(size)
        self._virgin_bits = bytearray(b'\xff' * size)  # Track new coverage
        self._lock = threading.Lock()

    def merge(self, other: bytes) -> int:
        """
        Merge another bitmap into this one.

        Args:
            other: Bitmap bytes to merge

        Returns:
            Number of new edges discovered
        """
        if len(other) != self.size:
            # Handle size mismatch by padding/truncating
            if len(other) < self.size:
                other = other + bytes(self.size - len(other))
            else:
                other = other[:self.size]

        new_edges = 0

        with self._lock:
            for i in range(self.size):
                if other[i]:
                    # Check if this is new coverage
                    if self._virgin_bits[i] & other[i]:
                        new_edges += 1
                        self._virgin_bits[i] &= ~other[i]

                    # Merge hit counts (max)
                    self._bitmap[i] = max(self._bitmap[i], other[i])

        return new_edges

    def get_edge_count(self) -> int:
        """Get total number of edges hit."""
        return sum(1 for b in self._bitmap if b)

    def get_coverage_percent(self) -> float:
        """Get coverage percentage (edges hit / map size)."""
        return (self.get_edge_count() / self.size) * 100

    def has_new_bits(self, other: bytes) -> bool:
        """
        Check if another bitmap has new coverage.

        Args:
            other: Bitmap to check

        Returns:
            True if other has bits not in this bitmap
        """
        if len(other) != self.size:
            if len(other) < self.size:
                other = other + bytes(self.size - len(other))
            else:
                other = other[:self.size]

        with self._lock:
            for i in range(self.size):
                if other[i] and (self._virgin_bits[i] & other[i]):
                    return True
        return False

    def get_new_bits_mask(self, other: bytes) -> bytes:
        """
        Get mask of new bits from another bitmap.

        Args:
            other: Bitmap to compare

        Returns:
            Bitmap showing only new bits
        """
        if len(other) != self.size:
            if len(other) < self.size:
                other = other + bytes(self.size - len(other))
            else:
                other = other[:self.size]

        result = bytearray(self.size)

        with self._lock:
            for i in range(self.size):
                if other[i] and (self._virgin_bits[i] & other[i]):
                    result[i] = other[i]

        return bytes(result)

    def to_bytes(self) -> bytes:
        """Get bitmap as bytes."""
        with self._lock:
            return bytes(self._bitmap)

    def from_bytes(self, data: bytes):
        """Load bitmap from bytes."""
        if len(data) != self.size:
            if len(data) < self.size:
                data = data + bytes(self.size - len(data))
            else:
                data = data[:self.size]

        with self._lock:
            self._bitmap = bytearray(data)

    def reset(self):
        """Reset bitmap to empty state."""
        with self._lock:
            self._bitmap = bytearray(self.size)
            self._virgin_bits = bytearray(b'\xff' * self.size)

    def get_frontier_edges(self) -> Set[int]:
        """
        Get edges that are at coverage frontier.

        These are edges with low hit counts that might lead to new coverage.

        Returns:
            Set of edge indices at frontier
        """
        frontier = set()

        with self._lock:
            for i in range(self.size):
                # Edges with exactly 1 hit are frontier candidates
                if self._bitmap[i] == 1:
                    frontier.add(i)

        return frontier

    @staticmethod
    def bucket_hit_count(count: int) -> int:
        """
        Convert hit count to AFL bucket value.

        Args:
            count: Raw hit count

        Returns:
            Bucketed value
        """
        for i, threshold in enumerate(CoverageBitmap.BUCKET_THRESHOLDS):
            if count <= threshold:
                return 1 << i
        return 128


class CoverageMerger:
    """
    Merges coverage from multiple distributed workers.

    Tracks global coverage state and identifies which workers
    are contributing unique coverage.

    Example:
        merger = CoverageMerger()

        # Worker reports coverage
        new_edges = merger.add_worker_coverage(
            worker_id="worker_1",
            coverage=bitmap_bytes
        )

        # Get global coverage
        global_bitmap = merger.get_global_coverage()

        # Check coverage stats
        stats = merger.get_stats()
        print(f"Total edges: {stats.total_edges}")
    """

    def __init__(
        self,
        map_size: int = CoverageBitmap.MAP_SIZE,
        stale_threshold: float = 300.0
    ):
        """
        Initialize merger.

        Args:
            map_size: Size of coverage bitmap
            stale_threshold: Seconds after which worker is considered stale
        """
        self.map_size = map_size
        self.stale_threshold = stale_threshold

        # Global merged coverage
        self._global_bitmap = CoverageBitmap(map_size)

        # Per-worker coverage tracking
        self._worker_bitmaps: Dict[str, CoverageBitmap] = {}
        self._worker_timestamps: Dict[str, float] = {}
        self._worker_unique_edges: Dict[str, Set[int]] = {}

        # Coverage history
        self._coverage_timeline: List[Tuple[float, int]] = []
        self._last_new_coverage_time = 0.0

        self._lock = threading.Lock()

    def add_worker_coverage(
        self,
        worker_id: str,
        coverage: bytes,
        coverage_type: CoverageType = CoverageType.EDGE
    ) -> int:
        """
        Add coverage from a worker.

        Args:
            worker_id: ID of reporting worker
            coverage: Coverage bitmap bytes
            coverage_type: Type of coverage

        Returns:
            Number of new globally unique edges
        """
        now = time.time()

        with self._lock:
            # Initialize worker tracking if needed
            if worker_id not in self._worker_bitmaps:
                self._worker_bitmaps[worker_id] = CoverageBitmap(self.map_size)
                self._worker_unique_edges[worker_id] = set()

            self._worker_timestamps[worker_id] = now

            # Merge into worker's local bitmap
            self._worker_bitmaps[worker_id].merge(coverage)

            # Check for globally new edges
            new_edges = self._global_bitmap.merge(coverage)

            if new_edges > 0:
                self._last_new_coverage_time = now
                self._coverage_timeline.append((now, self._global_bitmap.get_edge_count()))

                # Track unique contribution
                for i in range(self.map_size):
                    if coverage[i] if i < len(coverage) else 0:
                        # Check if this worker was first to find this edge
                        found_by_others = False
                        for other_id, other_bitmap in self._worker_bitmaps.items():
                            if other_id != worker_id:
                                if other_bitmap._bitmap[i]:
                                    found_by_others = True
                                    break
                        if not found_by_others:
                            self._worker_unique_edges[worker_id].add(i)

            logger.debug(f"Worker {worker_id} contributed {new_edges} new edges")
            return new_edges

    def get_global_coverage(self) -> bytes:
        """Get the global merged coverage bitmap."""
        return self._global_bitmap.to_bytes()

    def get_worker_coverage(self, worker_id: str) -> Optional[bytes]:
        """Get a specific worker's coverage bitmap."""
        with self._lock:
            if worker_id in self._worker_bitmaps:
                return self._worker_bitmaps[worker_id].to_bytes()
        return None

    def get_coverage_delta(self, worker_id: str) -> bytes:
        """
        Get coverage that worker is missing compared to global.

        Args:
            worker_id: Worker to get delta for

        Returns:
            Bitmap of edges worker hasn't found yet
        """
        with self._lock:
            if worker_id not in self._worker_bitmaps:
                return self._global_bitmap.to_bytes()

            global_bytes = self._global_bitmap.to_bytes()
            worker_bytes = self._worker_bitmaps[worker_id].to_bytes()

            delta = bytearray(self.map_size)
            for i in range(self.map_size):
                if global_bytes[i] and not worker_bytes[i]:
                    delta[i] = global_bytes[i]

            return bytes(delta)

    def get_stats(self) -> CoverageStats:
        """Get comprehensive coverage statistics."""
        now = time.time()

        with self._lock:
            stats = CoverageStats(
                total_edges=self._global_bitmap.get_edge_count(),
                total_workers=len(self._worker_bitmaps),
                coverage_percent=self._global_bitmap.get_coverage_percent(),
                last_new_coverage=self._last_new_coverage_time,
            )

            for worker_id, bitmap in self._worker_bitmaps.items():
                stats.edges_per_worker[worker_id] = bitmap.get_edge_count()
                stats.unique_contributions[worker_id] = len(self._worker_unique_edges.get(worker_id, set()))

                # Check for stale workers
                last_seen = self._worker_timestamps.get(worker_id, 0)
                if now - last_seen > self.stale_threshold:
                    stats.stale_workers.append(worker_id)

            return stats

    def get_frontier_workers(self) -> List[str]:
        """
        Get workers that are exploring coverage frontier.

        Returns:
            List of worker IDs at frontier
        """
        frontier_edges = self._global_bitmap.get_frontier_edges()
        frontier_workers = []

        with self._lock:
            for worker_id, bitmap in self._worker_bitmaps.items():
                worker_frontier = 0
                for edge in frontier_edges:
                    if bitmap._bitmap[edge]:
                        worker_frontier += 1

                # Worker is at frontier if they cover frontier edges
                if worker_frontier > 0:
                    frontier_workers.append(worker_id)

        return frontier_workers

    def has_coverage_plateau(self, window_seconds: float = 600.0) -> bool:
        """
        Check if coverage has plateaued.

        Args:
            window_seconds: Time window to check

        Returns:
            True if no new coverage in window
        """
        now = time.time()
        return (now - self._last_new_coverage_time) > window_seconds

    def remove_worker(self, worker_id: str):
        """Remove a worker from tracking."""
        with self._lock:
            self._worker_bitmaps.pop(worker_id, None)
            self._worker_timestamps.pop(worker_id, None)
            self._worker_unique_edges.pop(worker_id, None)

    def export_coverage_map(self, path: Path):
        """
        Export global coverage to file.

        Args:
            path: Path to write coverage file
        """
        path.write_bytes(self._global_bitmap.to_bytes())

    def import_coverage_map(self, path: Path):
        """
        Import coverage from file.

        Args:
            path: Path to read coverage from
        """
        if path.exists():
            self._global_bitmap.from_bytes(path.read_bytes())


class CoverageAggregator:
    """
    Higher-level coverage aggregation with multiple merge strategies.

    Supports different aggregation policies:
    - Union: All edges from all workers
    - Intersection: Only edges found by all workers
    - Weighted: Weight by worker productivity
    """

    class MergeStrategy(Enum):
        UNION = auto()
        INTERSECTION = auto()
        WEIGHTED = auto()
        FRONTIER_FOCUS = auto()

    def __init__(
        self,
        strategy: 'CoverageAggregator.MergeStrategy' = None,
        map_size: int = CoverageBitmap.MAP_SIZE
    ):
        """
        Initialize aggregator.

        Args:
            strategy: Merge strategy to use
            map_size: Coverage map size
        """
        self.strategy = strategy or self.MergeStrategy.UNION
        self.map_size = map_size
        self._merger = CoverageMerger(map_size)

        # Worker weights for weighted strategy
        self._worker_weights: Dict[str, float] = {}

    def set_worker_weight(self, worker_id: str, weight: float):
        """Set weight for a worker (for weighted strategy)."""
        self._worker_weights[worker_id] = max(0.0, min(1.0, weight))

    def add_coverage(
        self,
        worker_id: str,
        coverage: bytes
    ) -> int:
        """Add coverage from a worker."""
        return self._merger.add_worker_coverage(worker_id, coverage)

    def get_aggregated_coverage(self) -> bytes:
        """
        Get aggregated coverage based on strategy.

        Returns:
            Aggregated coverage bitmap
        """
        if self.strategy == self.MergeStrategy.UNION:
            return self._merger.get_global_coverage()

        elif self.strategy == self.MergeStrategy.INTERSECTION:
            return self._get_intersection_coverage()

        elif self.strategy == self.MergeStrategy.WEIGHTED:
            return self._get_weighted_coverage()

        elif self.strategy == self.MergeStrategy.FRONTIER_FOCUS:
            return self._get_frontier_coverage()

        return self._merger.get_global_coverage()

    def _get_intersection_coverage(self) -> bytes:
        """Get coverage found by ALL workers."""
        result = bytearray(b'\xff' * self.map_size)

        worker_bitmaps = list(self._merger._worker_bitmaps.values())
        if not worker_bitmaps:
            return bytes(self.map_size)

        for bitmap in worker_bitmaps:
            for i in range(self.map_size):
                result[i] &= bitmap._bitmap[i]

        return bytes(result)

    def _get_weighted_coverage(self) -> bytes:
        """Get weighted coverage based on worker weights."""
        result = bytearray(self.map_size)

        for worker_id, bitmap in self._merger._worker_bitmaps.items():
            weight = self._worker_weights.get(worker_id, 1.0)
            for i in range(self.map_size):
                if bitmap._bitmap[i]:
                    # Add weighted contribution
                    weighted_val = int(bitmap._bitmap[i] * weight)
                    result[i] = max(result[i], weighted_val)

        return bytes(result)

    def _get_frontier_coverage(self) -> bytes:
        """Get coverage focusing on frontier edges."""
        global_cov = bytearray(self._merger.get_global_coverage())
        frontier = self._merger._global_bitmap.get_frontier_edges()

        # Boost frontier edges
        for edge in frontier:
            if global_cov[edge]:
                global_cov[edge] = min(255, global_cov[edge] * 2)

        return bytes(global_cov)

    def get_stats(self) -> CoverageStats:
        """Get coverage statistics."""
        return self._merger.get_stats()

    def recommend_worker_action(self, worker_id: str) -> Dict[str, Any]:
        """
        Recommend action for a worker based on coverage.

        Args:
            worker_id: Worker to get recommendation for

        Returns:
            Recommendation dictionary
        """
        stats = self._merger.get_stats()
        delta = self._merger.get_coverage_delta(worker_id)
        frontier_workers = self._merger.get_frontier_workers()

        recommendation = {
            "worker_id": worker_id,
            "action": "continue",
            "priority_edges": [],
            "is_stale": worker_id in stats.stale_workers,
            "is_frontier": worker_id in frontier_workers,
        }

        # Count edges worker is missing
        missing_edges = sum(1 for b in delta if b)

        if missing_edges > stats.total_edges * 0.3:
            # Worker is behind - should sync more
            recommendation["action"] = "sync"
            recommendation["sync_priority"] = "high"

        elif worker_id in stats.stale_workers:
            recommendation["action"] = "restart"

        elif worker_id in frontier_workers:
            recommendation["action"] = "boost"
            recommendation["boost_reason"] = "frontier_exploration"

        # Get priority edges to focus on
        frontier_edges = list(self._merger._global_bitmap.get_frontier_edges())[:10]
        recommendation["priority_edges"] = frontier_edges

        return recommendation


class DistributedCoverageTracker:
    """
    End-to-end distributed coverage tracking system.

    Integrates with coordinator to provide coverage-based decisions.

    Example:
        tracker = DistributedCoverageTracker()

        # Workers report coverage
        tracker.report_coverage("worker_1", coverage_bytes)
        tracker.report_coverage("worker_2", coverage_bytes)

        # Get coverage-based seed recommendations
        seeds = tracker.get_priority_seeds(worker_id="worker_1")

        # Check if campaign is making progress
        if tracker.is_plateaued():
            tracker.trigger_diversification()
    """

    def __init__(
        self,
        aggregator: Optional[CoverageAggregator] = None,
        plateau_threshold: float = 600.0
    ):
        """
        Initialize tracker.

        Args:
            aggregator: Coverage aggregator to use
            plateau_threshold: Seconds to consider coverage plateaued
        """
        self.aggregator = aggregator or CoverageAggregator()
        self.plateau_threshold = plateau_threshold

        # Seed to coverage mapping
        self._seed_coverage: Dict[str, bytes] = {}
        self._seed_edges: Dict[str, int] = {}

        # Coverage goals
        self._target_edges: Optional[Set[int]] = None

    def report_coverage(
        self,
        worker_id: str,
        coverage: bytes,
        seed_hash: Optional[str] = None
    ) -> int:
        """
        Report coverage from a worker.

        Args:
            worker_id: Reporting worker
            coverage: Coverage bitmap
            seed_hash: Optional hash of seed that produced coverage

        Returns:
            Number of new edges found
        """
        new_edges = self.aggregator.add_coverage(worker_id, coverage)

        # Track seed coverage
        if seed_hash:
            if seed_hash not in self._seed_coverage:
                self._seed_coverage[seed_hash] = coverage
                self._seed_edges[seed_hash] = sum(1 for b in coverage if b)
            else:
                # Merge additional coverage for same seed
                existing = bytearray(self._seed_coverage[seed_hash])
                for i in range(min(len(existing), len(coverage))):
                    existing[i] |= coverage[i]
                self._seed_coverage[seed_hash] = bytes(existing)
                self._seed_edges[seed_hash] = sum(1 for b in existing if b)

        return new_edges

    def get_global_coverage(self) -> bytes:
        """Get aggregated global coverage."""
        return self.aggregator.get_aggregated_coverage()

    def get_coverage_for_seed(self, seed_hash: str) -> Optional[bytes]:
        """Get coverage produced by a specific seed."""
        return self._seed_coverage.get(seed_hash)

    def is_plateaued(self) -> bool:
        """Check if coverage has plateaued."""
        return self.aggregator._merger.has_coverage_plateau(self.plateau_threshold)

    def get_stats(self) -> CoverageStats:
        """Get coverage statistics."""
        return self.aggregator.get_stats()

    def set_coverage_targets(self, target_edges: Set[int]):
        """
        Set specific coverage targets.

        Args:
            target_edges: Set of edge indices to target
        """
        self._target_edges = target_edges

    def get_target_progress(self) -> float:
        """
        Get progress toward coverage targets.

        Returns:
            Percentage of targets hit (0-100)
        """
        if not self._target_edges:
            return 0.0

        global_cov = self.get_global_coverage()
        hit = sum(1 for edge in self._target_edges if global_cov[edge] if edge < len(global_cov) else False)

        return (hit / len(self._target_edges)) * 100

    def get_priority_seeds(
        self,
        worker_id: str,
        count: int = 10
    ) -> List[str]:
        """
        Get seeds that would help a worker improve coverage.

        Args:
            worker_id: Worker to get seeds for
            count: Number of seeds to return

        Returns:
            List of seed hashes sorted by priority
        """
        worker_cov = self.aggregator._merger.get_worker_coverage(worker_id)
        if not worker_cov:
            # Worker has no coverage - return highest coverage seeds
            sorted_seeds = sorted(
                self._seed_edges.items(),
                key=lambda x: x[1],
                reverse=True
            )
            return [h for h, _ in sorted_seeds[:count]]

        # Find seeds with edges worker is missing
        seed_scores = []

        for seed_hash, seed_cov in self._seed_coverage.items():
            new_edges = 0
            for i in range(min(len(seed_cov), len(worker_cov))):
                if seed_cov[i] and not worker_cov[i]:
                    new_edges += 1

            if new_edges > 0:
                seed_scores.append((seed_hash, new_edges))

        # Sort by new edges
        seed_scores.sort(key=lambda x: x[1], reverse=True)

        return [h for h, _ in seed_scores[:count]]

    def trigger_diversification(self) -> Dict[str, Any]:
        """
        Trigger diversification when coverage plateaus.

        Returns:
            Diversification strategy
        """
        stats = self.get_stats()
        frontier_workers = self.aggregator._merger.get_frontier_workers()

        strategy = {
            "action": "diversify",
            "reason": "coverage_plateau",
            "recommendations": [],
        }

        # Recommend actions for workers
        for worker_id in stats.edges_per_worker.keys():
            rec = self.aggregator.recommend_worker_action(worker_id)
            strategy["recommendations"].append(rec)

        # Suggest increasing mutation intensity
        strategy["mutation_boost"] = True
        strategy["sync_frequency"] = "increase"

        # Suggest adding havoc mode
        if stats.total_edges > 0 and stats.coverage_percent < 50:
            strategy["enable_havoc"] = True

        return strategy

    def export_report(self) -> Dict[str, Any]:
        """
        Export comprehensive coverage report.

        Returns:
            Report dictionary
        """
        stats = self.get_stats()

        return {
            "timestamp": time.time(),
            "total_edges": stats.total_edges,
            "coverage_percent": stats.coverage_percent,
            "total_workers": stats.total_workers,
            "edges_per_worker": stats.edges_per_worker,
            "unique_contributions": stats.unique_contributions,
            "stale_workers": stats.stale_workers,
            "plateaued": self.is_plateaued(),
            "target_progress": self.get_target_progress() if self._target_edges else None,
            "total_seeds_tracked": len(self._seed_coverage),
            "frontier_workers": self.aggregator._merger.get_frontier_workers(),
        }
