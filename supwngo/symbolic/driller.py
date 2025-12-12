"""
Driller-style hybrid fuzzing integration.

Combines AFL fuzzing with angr symbolic execution to discover
new paths past magic bytes and checksums.
"""

import os
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from supwngo.core.binary import Binary
from supwngo.symbolic.angr_engine import AngrEngine
from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class DrillerConfig:
    """Driller configuration."""
    afl_output_dir: str = ""
    driller_output_dir: str = ""

    # Thresholds
    stuck_threshold: int = 300  # seconds without new paths
    max_drill_time: int = 120   # max time per drill attempt

    # Limits
    max_inputs_per_round: int = 10
    max_symbolic_steps: int = 50000


@dataclass
class DrillResult:
    """Result from drilling operation."""
    new_inputs: List[bytes] = field(default_factory=list)
    paths_discovered: int = 0
    time_elapsed: float = 0.0
    success: bool = False


class DrillerIntegration:
    """
    Hybrid fuzzing: AFL + symbolic execution.

    Monitors AFL campaign and uses symbolic execution when fuzzer
    gets stuck to find inputs that pass magic byte checks.
    """

    def __init__(
        self,
        binary: Binary,
        config: Optional[DrillerConfig] = None,
    ):
        """
        Initialize Driller integration.

        Args:
            binary: Target binary
            config: Driller configuration
        """
        self.binary = binary
        self.config = config or DrillerConfig()
        self.engine = AngrEngine(binary)
        self._drilled_inputs: Set[bytes] = set()
        self._last_paths: int = 0
        self._stuck_since: float = 0.0

    def is_fuzzer_stuck(
        self,
        afl_output: str,
    ) -> bool:
        """
        Check if AFL is stuck (no new paths).

        Args:
            afl_output: AFL output directory

        Returns:
            True if fuzzer appears stuck
        """
        stats_file = Path(afl_output) / "default" / "fuzzer_stats"

        # Try different fuzzer directories
        if not stats_file.exists():
            for name in ["fuzzer00", "fuzzer01"]:
                alt = Path(afl_output) / name / "fuzzer_stats"
                if alt.exists():
                    stats_file = alt
                    break

        if not stats_file.exists():
            return False

        try:
            content = stats_file.read_text()
            current_paths = 0
            pending_favs = 0

            for line in content.split("\n"):
                if "paths_total" in line:
                    current_paths = int(line.split(":")[1].strip())
                elif "pending_favs" in line:
                    pending_favs = int(line.split(":")[1].strip())

            # Check for stuck condition
            if pending_favs == 0:
                if current_paths == self._last_paths:
                    if self._stuck_since == 0:
                        self._stuck_since = time.time()
                    elif time.time() - self._stuck_since > self.config.stuck_threshold:
                        return True
                else:
                    self._stuck_since = 0.0
                    self._last_paths = current_paths

            return False

        except Exception as e:
            logger.debug(f"Error checking fuzzer status: {e}")
            return False

    def get_interesting_inputs(
        self,
        afl_output: str,
        limit: int = None,
    ) -> List[bytes]:
        """
        Get interesting inputs from AFL queue.

        Args:
            afl_output: AFL output directory
            limit: Maximum inputs to return

        Returns:
            List of input bytes
        """
        limit = limit or self.config.max_inputs_per_round
        inputs = []

        output_path = Path(afl_output)

        # Find queue directories
        for fuzzer_dir in output_path.iterdir():
            if fuzzer_dir.is_dir():
                queue_dir = fuzzer_dir / "queue"
                if queue_dir.exists():
                    # Get newest files
                    queue_files = sorted(
                        queue_dir.iterdir(),
                        key=lambda f: f.stat().st_mtime,
                        reverse=True,
                    )

                    for queue_file in queue_files:
                        if len(inputs) >= limit:
                            break
                        if queue_file.is_file() and not queue_file.name.startswith("."):
                            data = queue_file.read_bytes()
                            if data not in self._drilled_inputs:
                                inputs.append(data)

        return inputs[:limit]

    def drill_input(
        self,
        input_data: bytes,
        timeout: int = None,
    ) -> DrillResult:
        """
        Use symbolic execution to find new paths from input.

        Args:
            input_data: Starting input
            timeout: Timeout in seconds

        Returns:
            DrillResult with new inputs
        """
        timeout = timeout or self.config.max_drill_time
        result = DrillResult()
        start_time = time.time()

        self._drilled_inputs.add(input_data)

        try:
            # Create state starting from crash input
            state = self.engine.create_entry_state(stdin=input_data)
            simgr = self.engine.create_simulation_manager(state)

            # Track seen states
            seen_addrs: Set[int] = set()

            # Step through execution
            steps = 0
            while steps < self.config.max_symbolic_steps:
                if time.time() - start_time > timeout:
                    break

                if not simgr.active:
                    break

                # Step forward
                simgr.step()
                steps += 1

                # Look for new paths (divergence points)
                for active_state in simgr.active:
                    addr = active_state.addr

                    if addr not in seen_addrs:
                        seen_addrs.add(addr)

                        # Check if this is a branch we haven't taken
                        if self._is_interesting_branch(active_state):
                            # Try to generate input for alternate path
                            new_input = self._solve_alternate_path(active_state)
                            if new_input and new_input not in self._drilled_inputs:
                                result.new_inputs.append(new_input)
                                result.paths_discovered += 1

            result.success = len(result.new_inputs) > 0
            result.time_elapsed = time.time() - start_time

        except Exception as e:
            logger.error(f"Drilling failed: {e}")

        return result

    def _is_interesting_branch(self, state: Any) -> bool:
        """
        Check if state represents an interesting branch point.

        Args:
            state: angr state

        Returns:
            True if branch is interesting
        """
        # Check if there's an unconstrained path
        try:
            # This is a heuristic - look for conditional branches
            # with constraints on symbolic input
            if state.solver.constraints:
                return True
        except Exception:
            pass

        return False

    def _solve_alternate_path(self, state: Any) -> Optional[bytes]:
        """
        Try to solve for input that takes alternate path.

        Args:
            state: angr state at branch

        Returns:
            New input bytes or None
        """
        try:
            # Copy state and negate last constraint
            new_state = state.copy()

            if new_state.solver.constraints:
                last_constraint = new_state.solver.constraints[-1]
                negated = self.engine.claripy.Not(last_constraint)

                # Check if negated path is satisfiable
                if new_state.solver.satisfiable(extra_constraints=[negated]):
                    new_state.solver.add(negated)

                    # Solve for stdin
                    stdin_content = new_state.posix.stdin.content
                    if stdin_content:
                        return new_state.solver.eval(
                            stdin_content[0],
                            cast_to=bytes,
                        )

        except Exception as e:
            logger.debug(f"Failed to solve alternate path: {e}")

        return None

    def feed_to_afl(
        self,
        inputs: List[bytes],
        afl_output: str,
    ) -> int:
        """
        Feed new inputs back to AFL queue.

        Args:
            inputs: New inputs to add
            afl_output: AFL output directory

        Returns:
            Number of inputs added
        """
        added = 0

        # Find queue directory
        output_path = Path(afl_output)
        queue_dir = None

        for fuzzer_dir in output_path.iterdir():
            if fuzzer_dir.is_dir():
                q = fuzzer_dir / "queue"
                if q.exists():
                    queue_dir = q
                    break

        if not queue_dir:
            logger.warning("Could not find AFL queue directory")
            return 0

        for i, input_data in enumerate(inputs):
            try:
                # Create file with AFL-style naming
                filename = f"driller_{int(time.time())}_{i:04d}"
                filepath = queue_dir / filename

                filepath.write_bytes(input_data)
                added += 1

                logger.debug(f"Added drilled input: {filename}")

            except Exception as e:
                logger.warning(f"Failed to add input: {e}")

        return added

    def run_hybrid_campaign(
        self,
        afl_output: str,
        duration: int = 3600,
        check_interval: int = 60,
    ) -> Dict[str, Any]:
        """
        Run hybrid fuzzing campaign.

        Args:
            afl_output: AFL output directory
            duration: Campaign duration in seconds
            check_interval: How often to check fuzzer status

        Returns:
            Campaign results
        """
        start_time = time.time()
        end_time = start_time + duration

        results = {
            "drill_attempts": 0,
            "new_inputs_found": 0,
            "inputs_fed_to_afl": 0,
        }

        while time.time() < end_time:
            # Wait before checking
            time.sleep(check_interval)

            # Check if fuzzer is stuck
            if self.is_fuzzer_stuck(afl_output):
                logger.info("Fuzzer appears stuck, initiating drilling...")

                # Get inputs to drill
                inputs = self.get_interesting_inputs(afl_output)

                for input_data in inputs:
                    results["drill_attempts"] += 1

                    # Drill input
                    drill_result = self.drill_input(input_data)

                    if drill_result.success:
                        results["new_inputs_found"] += len(drill_result.new_inputs)

                        # Feed back to AFL
                        added = self.feed_to_afl(
                            drill_result.new_inputs,
                            afl_output,
                        )
                        results["inputs_fed_to_afl"] += added

                        logger.info(
                            f"Driller found {len(drill_result.new_inputs)} new inputs"
                        )

                # Reset stuck timer
                self._stuck_since = 0.0

        return results

    def summary(self) -> str:
        """Get driller summary."""
        return f"""
Driller Integration
===================
Binary: {self.binary.path.name}
Drilled inputs: {len(self._drilled_inputs)}
Stuck threshold: {self.config.stuck_threshold}s
"""
