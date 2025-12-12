"""
Vulnerability path discovery using symbolic execution.
"""

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from autopwn.core.binary import Binary
from autopwn.symbolic.angr_engine import AngrEngine, ExplorationResult
from autopwn.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class VulnerablePath:
    """Represents a path to a vulnerability."""
    vuln_type: str
    sink_address: int
    sink_function: str
    path_length: int
    constraints: List[str] = field(default_factory=list)
    input_bytes: bytes = b""
    state: Any = None


@dataclass
class UnconstrainedState:
    """Represents a state with unconstrained PC."""
    state: Any
    pc_value: Any  # Symbolic PC
    controlled_regs: List[str] = field(default_factory=list)
    constraints: List[str] = field(default_factory=list)


class PathFinder:
    """
    Find paths to vulnerabilities using symbolic execution.

    Discovers:
    - Unconstrained states (PC control)
    - Paths to dangerous functions
    - Format string vulnerabilities
    - Buffer overflows
    """

    # Dangerous sink functions
    DANGEROUS_SINKS = {
        "gets": "buffer_overflow",
        "strcpy": "buffer_overflow",
        "strcat": "buffer_overflow",
        "sprintf": "buffer_overflow",
        "scanf": "buffer_overflow",
        "printf": "format_string",
        "fprintf": "format_string",
        "sprintf": "format_string",
        "system": "command_injection",
        "execve": "command_injection",
        "popen": "command_injection",
    }

    def __init__(self, binary: Binary, engine: Optional[AngrEngine] = None):
        """
        Initialize path finder.

        Args:
            binary: Target binary
            engine: Optional pre-configured angr engine
        """
        self.binary = binary
        self.engine = engine or AngrEngine(binary)
        self._vulnerable_paths: List[VulnerablePath] = []

    def find_unconstrained_states(
        self,
        stdin_size: int = 200,
        timeout: int = 300,
    ) -> List[UnconstrainedState]:
        """
        Find states where PC is symbolic (controllable).

        Args:
            stdin_size: Size of symbolic stdin
            timeout: Exploration timeout

        Returns:
            List of unconstrained states
        """
        unconstrained = []

        # Create symbolic stdin
        sym_stdin = self.engine.create_symbolic_input("stdin", stdin_size * 8)

        # Create entry state
        state = self.engine.create_entry_state(stdin=sym_stdin)

        # Explore
        result = self.engine.explore(state, timeout=timeout)

        # Process unconstrained states
        for sym_state in result.unconstrained_states:
            angr_state = sym_state.state

            # Check which registers are controlled
            controlled = []
            for reg in ["rip", "rsp", "rbp", "rdi", "rsi", "rdx"]:
                try:
                    reg_val = getattr(angr_state.regs, reg)
                    if angr_state.solver.symbolic(reg_val):
                        controlled.append(reg)
                except Exception:
                    continue

            uncon = UnconstrainedState(
                state=angr_state,
                pc_value=angr_state.regs.pc,
                controlled_regs=controlled,
            )
            unconstrained.append(uncon)

        logger.info(f"Found {len(unconstrained)} unconstrained states")
        return unconstrained

    def find_path_to_function(
        self,
        func_name: str,
        stdin_size: int = 200,
        timeout: int = 300,
    ) -> Optional[VulnerablePath]:
        """
        Find path to reach a specific function.

        Args:
            func_name: Target function name
            stdin_size: Size of symbolic stdin
            timeout: Exploration timeout

        Returns:
            VulnerablePath if found
        """
        # Get function address
        func_addr = self.binary.plt.get(func_name)
        if not func_addr:
            func_addr = self.binary.symbols.get(func_name, {}).address
        if not func_addr:
            logger.warning(f"Function {func_name} not found")
            return None

        # Create symbolic input
        sym_stdin = self.engine.create_symbolic_input("stdin", stdin_size * 8)
        state = self.engine.create_entry_state(stdin=sym_stdin)

        # Explore to find function
        result = self.engine.explore(
            state,
            find=func_addr,
            timeout=timeout,
        )

        if result.found_states:
            found = result.found_states[0]
            angr_state = found.state

            # Get concrete input
            input_bytes = self.engine.concretize_state(angr_state)

            path = VulnerablePath(
                vuln_type=self.DANGEROUS_SINKS.get(func_name, "unknown"),
                sink_address=func_addr,
                sink_function=func_name,
                path_length=result.total_states_explored,
                input_bytes=input_bytes,
                state=angr_state,
            )

            self._vulnerable_paths.append(path)
            return path

        return None

    def find_all_dangerous_paths(
        self,
        timeout_per_func: int = 60,
    ) -> List[VulnerablePath]:
        """
        Find paths to all dangerous functions.

        Args:
            timeout_per_func: Timeout per function

        Returns:
            List of vulnerable paths
        """
        paths = []

        for func_name in self.DANGEROUS_SINKS.keys():
            if func_name in self.binary.plt:
                logger.debug(f"Searching for path to {func_name}")
                path = self.find_path_to_function(
                    func_name,
                    timeout=timeout_per_func,
                )
                if path:
                    paths.append(path)
                    logger.info(f"Found path to {func_name}")

        return paths

    def find_crash_path(
        self,
        crash_input: bytes,
        timeout: int = 300,
    ) -> Optional[Any]:
        """
        Reproduce crash symbolically.

        Args:
            crash_input: Input that caused crash
            timeout: Exploration timeout

        Returns:
            Symbolic state at crash or None
        """
        # Create state with crash input
        state = self.engine.create_entry_state(stdin=crash_input)

        # Explore until crash
        simgr = self.engine.create_simulation_manager(state)

        import time
        start = time.time()

        while time.time() - start < timeout:
            if not simgr.active:
                break

            simgr.step()

            # Check for error states
            if hasattr(simgr, 'errored') and simgr.errored:
                return simgr.errored[0].state

            # Check for unconstrained
            if simgr.unconstrained:
                return simgr.unconstrained[0]

        return None

    def analyze_vulnerability(
        self,
        state: Any,
        vuln_type: str,
    ) -> Dict[str, Any]:
        """
        Analyze vulnerability from symbolic state.

        Args:
            state: Symbolic state at vulnerability
            vuln_type: Type of vulnerability

        Returns:
            Dictionary with analysis results
        """
        analysis = {
            "type": vuln_type,
            "address": state.addr if hasattr(state, 'addr') else 0,
            "controllable_input": b"",
            "constraints": [],
            "registers": {},
        }

        try:
            # Get controllable input
            analysis["controllable_input"] = self.engine.concretize_state(state)

            # Get register values
            for reg in ["rip", "rsp", "rbp", "rdi", "rsi", "rdx", "rcx"]:
                try:
                    reg_val = getattr(state.regs, reg)
                    if state.solver.symbolic(reg_val):
                        analysis["registers"][reg] = "symbolic"
                    else:
                        analysis["registers"][reg] = hex(
                            state.solver.eval(reg_val)
                        )
                except Exception:
                    continue

            # Get constraint count
            analysis["constraints"] = len(state.solver.constraints)

        except Exception as e:
            logger.debug(f"Analysis error: {e}")

        return analysis

    def check_exploitability(
        self,
        state: Any,
    ) -> Dict[str, Any]:
        """
        Check exploitability of a symbolic state.

        Args:
            state: Symbolic state to analyze

        Returns:
            Exploitability analysis
        """
        result = {
            "pc_control": False,
            "stack_control": False,
            "arbitrary_write": False,
            "arbitrary_read": False,
            "controlled_data_size": 0,
        }

        try:
            # Check PC control
            if state.solver.symbolic(state.regs.pc):
                result["pc_control"] = True

                # Check if we can set PC to arbitrary value
                test_addr = 0x41414141
                if state.satisfiable(extra_constraints=[state.regs.pc == test_addr]):
                    result["arbitrary_pc"] = True

            # Check stack pointer control
            if state.solver.symbolic(state.regs.sp):
                result["stack_control"] = True

            # Try to determine controlled data size
            stdin = state.posix.stdin
            if hasattr(stdin, 'content') and stdin.content:
                result["controlled_data_size"] = len(stdin.content[0]) // 8

        except Exception as e:
            logger.debug(f"Exploitability check error: {e}")

        return result

    def generate_exploit_input(
        self,
        state: Any,
        target_pc: int,
    ) -> Optional[bytes]:
        """
        Generate input to reach target PC value.

        Args:
            state: Unconstrained state
            target_pc: Desired PC value

        Returns:
            Input bytes or None
        """
        solutions = self.engine.solve_for_pc(state, target_pc)
        return solutions[0] if solutions else None

    def summary(self) -> str:
        """Get path finder summary."""
        return f"""
Path Finder Summary
===================
Binary: {self.binary.path.name}
Vulnerable paths found: {len(self._vulnerable_paths)}

Paths:
""" + "\n".join(
            f"  - {p.sink_function} ({p.vuln_type}) at 0x{p.sink_address:x}"
            for p in self._vulnerable_paths
        )
