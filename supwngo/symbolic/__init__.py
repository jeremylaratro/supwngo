"""Symbolic execution modules using angr."""

from supwngo.symbolic.angr_engine import AngrEngine, SymbolicState, ExplorationResult
from supwngo.symbolic.path_finder import PathFinder
from supwngo.symbolic.constraint import ConstraintSolver
from supwngo.symbolic.driller import DrillerIntegration
from supwngo.symbolic.enhanced_engine import (
    EnhancedSymbolicEngine,
    VulnTarget,
    VulnPath,
    ExplorationStrategy,
    FunctionSummary,
    find_vulnerabilities,
)

__all__ = [
    # Core engine
    "AngrEngine",
    "SymbolicState",
    "ExplorationResult",
    # Path finding
    "PathFinder",
    # Constraint solving
    "ConstraintSolver",
    # Hybrid fuzzing
    "DrillerIntegration",
    # Enhanced engine
    "EnhancedSymbolicEngine",
    "VulnTarget",
    "VulnPath",
    "ExplorationStrategy",
    "FunctionSummary",
    "find_vulnerabilities",
]
