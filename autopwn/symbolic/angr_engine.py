"""
angr-based symbolic execution engine.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from autopwn.core.binary import Binary
from autopwn.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class SymbolicState:
    """Wrapper for angr symbolic state."""
    state: Any = None  # angr.SimState
    address: int = 0
    is_unconstrained: bool = False
    is_deadended: bool = False
    symbolic_variables: List[str] = field(default_factory=list)
    constraints_count: int = 0


@dataclass
class ExplorationResult:
    """Results from symbolic exploration."""
    found_states: List[SymbolicState] = field(default_factory=list)
    unconstrained_states: List[SymbolicState] = field(default_factory=list)
    deadended_states: List[SymbolicState] = field(default_factory=list)
    errored_states: List[SymbolicState] = field(default_factory=list)
    total_states_explored: int = 0
    time_elapsed: float = 0.0


class AngrEngine:
    """
    Core angr symbolic execution engine.

    Provides:
    - Project setup and configuration
    - State management
    - Symbolic memory and registers
    - Constraint solving
    """

    def __init__(self, binary: Binary, auto_load_libs: bool = False):
        """
        Initialize angr engine.

        Args:
            binary: Target binary
            auto_load_libs: Whether to load shared libraries
        """
        self.binary = binary
        self.auto_load_libs = auto_load_libs
        self._project = None
        self._cfg = None

        # Import angr
        try:
            import angr
            import claripy
            self.angr = angr
            self.claripy = claripy
        except ImportError:
            raise RuntimeError("angr is required for symbolic execution")

    @property
    def project(self):
        """Get or create angr project."""
        if self._project is None:
            self._project = self.angr.Project(
                str(self.binary.path),
                auto_load_libs=self.auto_load_libs,
            )
        return self._project

    @property
    def cfg(self):
        """Get or create CFG."""
        if self._cfg is None:
            self._cfg = self.project.analyses.CFGFast()
        return self._cfg

    def create_symbolic_input(
        self,
        name: str,
        size: int,
    ) -> Any:
        """
        Create symbolic bitvector for input.

        Args:
            name: Variable name
            size: Size in bits

        Returns:
            claripy BVS object
        """
        return self.claripy.BVS(name, size)

    def create_entry_state(
        self,
        stdin: Optional[bytes | Any] = None,
        args: Optional[List[bytes | Any]] = None,
        env: Optional[Dict[str, bytes]] = None,
        add_options: Optional[Set[str]] = None,
        remove_options: Optional[Set[str]] = None,
    ) -> Any:
        """
        Create symbolic entry state.

        Args:
            stdin: Symbolic or concrete stdin content
            args: Program arguments
            env: Environment variables
            add_options: Options to add
            remove_options: Options to remove

        Returns:
            angr SimState
        """
        add_opts = add_options or set()
        remove_opts = remove_options or set()

        # Common useful options
        add_opts.add(self.angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
        add_opts.add(self.angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)

        state_kwargs = {
            "add_options": add_opts,
            "remove_options": remove_opts,
        }

        if args:
            state_kwargs["args"] = args
        if env:
            state_kwargs["env"] = env

        state = self.project.factory.entry_state(**state_kwargs)

        # Setup stdin
        if stdin is not None:
            if isinstance(stdin, bytes):
                # Concrete stdin
                state.posix.stdin.write(stdin, len(stdin))
            else:
                # Symbolic stdin (claripy BVS)
                simfile = self.angr.SimFile(
                    name="stdin",
                    content=stdin,
                    size=stdin.size() // 8 if hasattr(stdin, 'size') else 0x1000,
                )
                state.posix.stdin = simfile

        return state

    def create_call_state(
        self,
        func_addr: int,
        args: List[Any] = None,
        ret_addr: int = 0,
    ) -> Any:
        """
        Create state at function entry.

        Args:
            func_addr: Function address
            args: Function arguments (concrete or symbolic)
            ret_addr: Return address

        Returns:
            angr SimState
        """
        args = args or []

        state = self.project.factory.call_state(
            func_addr,
            *args,
            ret_addr=ret_addr,
            add_options={
                self.angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            },
        )

        return state

    def create_simulation_manager(
        self,
        state: Any,
        save_unconstrained: bool = True,
    ) -> Any:
        """
        Create simulation manager.

        Args:
            state: Initial state
            save_unconstrained: Whether to save unconstrained states

        Returns:
            angr SimulationManager
        """
        return self.project.factory.simgr(
            state,
            save_unconstrained=save_unconstrained,
        )

    def explore(
        self,
        state: Any,
        find: Optional[int | List[int] | Callable] = None,
        avoid: Optional[int | List[int] | Callable] = None,
        timeout: int = 300,
        max_states: int = 10000,
    ) -> ExplorationResult:
        """
        Explore program paths.

        Args:
            state: Initial state
            find: Target address(es) or condition
            avoid: Address(es) to avoid
            timeout: Timeout in seconds
            max_states: Maximum states to explore

        Returns:
            ExplorationResult
        """
        import time

        result = ExplorationResult()
        start_time = time.time()

        simgr = self.create_simulation_manager(state)

        # Add exploration techniques
        if max_states:
            simgr.use_technique(
                self.angr.exploration_techniques.DFS()
            )

        # Configure exploration
        explore_kwargs = {}
        if find:
            explore_kwargs["find"] = find
        if avoid:
            explore_kwargs["avoid"] = avoid

        try:
            # Explore with timeout
            while time.time() - start_time < timeout:
                if not simgr.active:
                    break
                if len(simgr.found) > 0:
                    break
                if result.total_states_explored >= max_states:
                    break

                simgr.step()
                result.total_states_explored += len(simgr.active)

                # Check for unconstrained states
                if simgr.unconstrained:
                    for s in simgr.unconstrained:
                        result.unconstrained_states.append(
                            SymbolicState(
                                state=s,
                                address=s.addr if hasattr(s, 'addr') else 0,
                                is_unconstrained=True,
                            )
                        )
                    simgr.drop(stash="unconstrained")

        except Exception as e:
            logger.error(f"Exploration error: {e}")

        result.time_elapsed = time.time() - start_time

        # Collect results
        if hasattr(simgr, 'found'):
            for s in simgr.found:
                result.found_states.append(SymbolicState(
                    state=s,
                    address=s.addr,
                ))

        if hasattr(simgr, 'deadended'):
            for s in simgr.deadended:
                result.deadended_states.append(SymbolicState(
                    state=s,
                    address=s.addr if hasattr(s, 'addr') else 0,
                    is_deadended=True,
                ))

        return result

    def find_unconstrained_states(
        self,
        entry_state: Any = None,
        timeout: int = 300,
    ) -> List[Any]:
        """
        Find states with unconstrained (symbolic) program counter.

        Args:
            entry_state: Optional custom entry state
            timeout: Timeout in seconds

        Returns:
            List of unconstrained states
        """
        if entry_state is None:
            entry_state = self.create_entry_state()

        simgr = self.create_simulation_manager(entry_state)

        import time
        start = time.time()

        unconstrained = []

        while time.time() - start < timeout:
            if not simgr.active:
                break

            simgr.step()

            # Check for unconstrained PC
            for state in simgr.active:
                if state.solver.symbolic(state.regs.pc):
                    unconstrained.append(state)

            if simgr.unconstrained:
                unconstrained.extend(simgr.unconstrained)
                simgr.drop(stash="unconstrained")

        return unconstrained

    def solve_for_pc(
        self,
        state: Any,
        target_addr: int,
        max_solutions: int = 1,
    ) -> List[bytes]:
        """
        Solve constraints to make PC reach target address.

        Args:
            state: Symbolic state
            target_addr: Desired PC value
            max_solutions: Maximum solutions to find

        Returns:
            List of input bytes that reach target
        """
        solutions = []

        try:
            # Add constraint for target PC
            state = state.copy()
            state.solver.add(state.regs.pc == target_addr)

            if state.satisfiable():
                # Find symbolic stdin
                stdin_content = state.posix.stdin.content
                if stdin_content:
                    for _ in range(max_solutions):
                        solution = state.solver.eval(stdin_content[0], cast_to=bytes)
                        solutions.append(solution)

                        # Add constraint to find different solution
                        state.solver.add(stdin_content[0] != solution)
                        if not state.satisfiable():
                            break

        except Exception as e:
            logger.error(f"Failed to solve for PC: {e}")

        return solutions

    def concretize_state(
        self,
        state: Any,
        var_name: str = "stdin",
    ) -> bytes:
        """
        Concretize symbolic state to get input bytes.

        Args:
            state: Symbolic state
            var_name: Name of symbolic variable

        Returns:
            Concrete input bytes
        """
        try:
            # Try to get stdin content
            stdin = state.posix.stdin
            if hasattr(stdin, 'content') and stdin.content:
                content = stdin.content[0]
                return state.solver.eval(content, cast_to=bytes)

            # Try to get symbolic args
            for sym in state.solver._stored_solver._constraints:
                if var_name in str(sym):
                    return state.solver.eval(sym, cast_to=bytes)

        except Exception as e:
            logger.debug(f"Failed to concretize: {e}")

        return b""

    def hook_function(
        self,
        addr: int,
        handler: Callable,
        length: int = 0,
    ) -> None:
        """
        Hook function at address.

        Args:
            addr: Address to hook
            handler: Handler function (SimProcedure or callable)
            length: Instruction length to skip
        """
        self.project.hook(addr, handler, length=length)

    def hook_symbol(
        self,
        name: str,
        handler: Any,
    ) -> None:
        """
        Hook symbol by name.

        Args:
            name: Symbol name
            handler: SimProcedure class
        """
        self.project.hook_symbol(name, handler)

    def get_function(self, addr_or_name: int | str) -> Any:
        """
        Get function from CFG.

        Args:
            addr_or_name: Function address or name

        Returns:
            angr Function object
        """
        if isinstance(addr_or_name, str):
            # Find by name
            for addr, func in self.cfg.kb.functions.items():
                if func.name == addr_or_name:
                    return func
            return None
        else:
            return self.cfg.kb.functions.get(addr_or_name)

    def get_all_functions(self) -> Dict[int, Any]:
        """Get all functions from CFG."""
        return dict(self.cfg.kb.functions)

    def summary(self) -> str:
        """Get engine summary."""
        proj = self.project
        cfg = self.cfg

        return f"""
angr Engine Summary
===================
Binary: {self.binary.path.name}
Arch: {proj.arch.name}
Entry: 0x{proj.entry:x}
Functions: {len(cfg.kb.functions)}
"""
