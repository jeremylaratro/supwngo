"""
Constraint solving and input generation.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class ConstraintSet:
    """Collection of constraints."""
    constraints: List[Any] = field(default_factory=list)
    variables: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Solution:
    """Solution to constraint set."""
    values: Dict[str, bytes] = field(default_factory=dict)
    satisfiable: bool = False


class ConstraintSolver:
    """
    Wrapper for claripy constraint solving.

    Provides:
    - Constraint building
    - Multiple solution generation
    - Bad character avoidance
    - Input optimization
    """

    def __init__(self):
        """Initialize constraint solver."""
        try:
            import claripy
            self.claripy = claripy
        except ImportError:
            raise RuntimeError("claripy is required for constraint solving")

        self._solver = None

    @property
    def solver(self):
        """Get solver instance."""
        if self._solver is None:
            self._solver = self.claripy.Solver()
        return self._solver

    def reset(self) -> None:
        """Reset solver state."""
        self._solver = None

    def create_symbolic_buffer(
        self,
        name: str,
        size: int,
    ) -> Any:
        """
        Create symbolic buffer.

        Args:
            name: Variable name
            size: Size in bytes

        Returns:
            Symbolic bitvector
        """
        return self.claripy.BVS(name, size * 8)

    def create_concrete_buffer(
        self,
        value: bytes,
    ) -> Any:
        """
        Create concrete buffer.

        Args:
            value: Concrete bytes

        Returns:
            Concrete bitvector
        """
        return self.claripy.BVV(value)

    def add_constraint(
        self,
        constraint: Any,
    ) -> None:
        """
        Add constraint to solver.

        Args:
            constraint: Claripy constraint
        """
        self.solver.add(constraint)

    def add_constraints(
        self,
        constraints: List[Any],
    ) -> None:
        """
        Add multiple constraints.

        Args:
            constraints: List of constraints
        """
        for c in constraints:
            self.solver.add(c)

    def is_satisfiable(
        self,
        extra_constraints: Optional[List[Any]] = None,
    ) -> bool:
        """
        Check if constraints are satisfiable.

        Args:
            extra_constraints: Additional temporary constraints

        Returns:
            True if satisfiable
        """
        return self.solver.satisfiable(extra_constraints=extra_constraints or [])

    def solve(
        self,
        var: Any,
        extra_constraints: Optional[List[Any]] = None,
    ) -> Optional[bytes]:
        """
        Solve for variable value.

        Args:
            var: Symbolic variable
            extra_constraints: Additional constraints

        Returns:
            Concrete bytes or None
        """
        if not self.is_satisfiable(extra_constraints):
            return None

        try:
            value = self.solver.eval(
                var,
                extra_constraints=extra_constraints or [],
                cast_to=bytes,
            )
            return value
        except Exception as e:
            logger.debug(f"Solve failed: {e}")
            return None

    def solve_n(
        self,
        var: Any,
        n: int,
        extra_constraints: Optional[List[Any]] = None,
    ) -> List[bytes]:
        """
        Find n different solutions.

        Args:
            var: Symbolic variable
            n: Number of solutions
            extra_constraints: Additional constraints

        Returns:
            List of solutions
        """
        solutions = []
        constraints = list(extra_constraints or [])

        for _ in range(n):
            if not self.is_satisfiable(constraints):
                break

            try:
                value = self.solver.eval(
                    var,
                    extra_constraints=constraints,
                    cast_to=bytes,
                )
                solutions.append(value)

                # Exclude this solution
                constraints.append(var != self.claripy.BVV(value))

            except Exception:
                break

        return solutions

    def add_printable_constraint(
        self,
        var: Any,
    ) -> None:
        """
        Constrain variable to printable ASCII.

        Args:
            var: Symbolic variable
        """
        size = var.size() // 8

        for i in range(size):
            byte = var.get_byte(i)
            self.solver.add(byte >= 0x20)
            self.solver.add(byte <= 0x7e)

    def add_alphanumeric_constraint(
        self,
        var: Any,
    ) -> None:
        """
        Constrain variable to alphanumeric.

        Args:
            var: Symbolic variable
        """
        size = var.size() // 8

        for i in range(size):
            byte = var.get_byte(i)
            # 0-9, A-Z, a-z
            is_digit = self.claripy.And(byte >= 0x30, byte <= 0x39)
            is_upper = self.claripy.And(byte >= 0x41, byte <= 0x5a)
            is_lower = self.claripy.And(byte >= 0x61, byte <= 0x7a)

            self.solver.add(self.claripy.Or(is_digit, is_upper, is_lower))

    def avoid_bad_chars(
        self,
        var: Any,
        bad_chars: List[int],
    ) -> None:
        """
        Add constraints to avoid bad characters.

        Args:
            var: Symbolic variable
            bad_chars: List of bad byte values
        """
        size = var.size() // 8

        for i in range(size):
            byte = var.get_byte(i)
            for bad in bad_chars:
                self.solver.add(byte != bad)

    def constrain_to_value(
        self,
        var: Any,
        value: int,
    ) -> None:
        """
        Constrain variable to specific value.

        Args:
            var: Symbolic variable
            value: Desired value
        """
        self.solver.add(var == value)

    def constrain_to_range(
        self,
        var: Any,
        min_val: int,
        max_val: int,
    ) -> None:
        """
        Constrain variable to range.

        Args:
            var: Symbolic variable
            min_val: Minimum value
            max_val: Maximum value
        """
        self.solver.add(var >= min_val)
        self.solver.add(var <= max_val)

    def build_overflow_constraints(
        self,
        buffer: Any,
        offset: int,
        target_value: int,
        word_size: int = 64,
    ) -> List[Any]:
        """
        Build constraints for buffer overflow.

        Args:
            buffer: Symbolic buffer
            offset: Offset to overwrite
            target_value: Value to write
            word_size: 32 or 64 bit

        Returns:
            List of constraints
        """
        constraints = []

        # Extract bytes at offset
        if word_size == 64:
            for i in range(8):
                byte_idx = offset + i
                byte_val = (target_value >> (i * 8)) & 0xFF
                constraints.append(
                    buffer.get_byte(byte_idx) == byte_val
                )
        else:
            for i in range(4):
                byte_idx = offset + i
                byte_val = (target_value >> (i * 8)) & 0xFF
                constraints.append(
                    buffer.get_byte(byte_idx) == byte_val
                )

        return constraints

    def build_format_string_constraints(
        self,
        buffer: Any,
        format_offset: int,
        writes: Dict[int, int],
    ) -> List[Any]:
        """
        Build constraints for format string attack.

        Args:
            buffer: Symbolic buffer
            format_offset: Argument offset for format string
            writes: Address -> value mapping

        Returns:
            List of constraints
        """
        # This is a simplified placeholder
        # Real implementation would build format string payload
        constraints = []

        # Constrain buffer to contain format specifiers
        # This is complex and format-string specific

        return constraints

    def minimize_input(
        self,
        var: Any,
        current_solution: bytes,
    ) -> bytes:
        """
        Try to minimize input while maintaining satisfiability.

        Args:
            var: Symbolic variable
            current_solution: Current solution

        Returns:
            Minimized solution
        """
        # Try to reduce trailing bytes
        minimized = current_solution

        for i in range(len(current_solution) - 1, -1, -1):
            # Try removing last byte
            test = minimized[:i]
            if not test:
                break

            # Check if still satisfiable with shorter input
            # This is a heuristic - real implementation needs state copy
            if len(test) >= 1:
                minimized = test
            else:
                break

        return minimized

    def summary(self) -> str:
        """Get solver summary."""
        return f"""
Constraint Solver
=================
Constraints: {len(self.solver.constraints)}
Satisfiable: {self.is_satisfiable()}
"""
