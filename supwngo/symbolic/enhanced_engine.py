"""
Enhanced Symbolic Execution Engine.

Improved symbolic execution with:
- Vulnerability-guided exploration
- Function summaries for common libc functions
- Checkpoint/resume for long analyses
- Path prioritization
"""

import hashlib
import json
import os
import pickle
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from supwngo.core.binary import Binary
from supwngo.utils.logging import get_logger

logger = get_logger(__name__)

# Try to import angr
try:
    import angr
    import claripy
    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False


class ExplorationStrategy(Enum):
    """Symbolic execution exploration strategies."""
    DFS = auto()           # Depth-first search
    BFS = auto()           # Breadth-first search
    VULN_GUIDED = auto()   # Prioritize paths to vulnerabilities
    COVERAGE = auto()      # Maximize code coverage
    LOOP_LIMIT = auto()    # Limit loop iterations


class VulnTarget(Enum):
    """Types of vulnerability targets to find."""
    UNCONSTRAINED_CALL = auto()    # Controllable function pointer
    UNCONSTRAINED_WRITE = auto()   # Controllable write address
    BUFFER_OVERFLOW = auto()       # Write past buffer bounds
    FORMAT_STRING = auto()         # Format string with user input
    COMMAND_INJECTION = auto()     # system() with user input


@dataclass
class PathState:
    """Represents a symbolic execution path state."""
    state: Any = None           # angr SimState
    address: int = 0
    depth: int = 0
    priority: float = 0.0
    history: List[int] = field(default_factory=list)
    symbolic_data: Dict[str, Any] = field(default_factory=dict)

    def __lt__(self, other):
        return self.priority > other.priority  # Higher priority first


@dataclass
class VulnPath:
    """A path leading to a vulnerability."""
    target_type: VulnTarget
    path_addresses: List[int]
    trigger_input: bytes
    constraints: List[str]
    exploitability: str = "unknown"
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Checkpoint:
    """Checkpoint for resuming exploration."""
    timestamp: float
    states_explored: int
    coverage: Set[int]
    pending_states: List[PathState]
    found_vulns: List[VulnPath]


class FunctionSummary:
    """
    Summaries for common libc functions.

    Instead of symbolically executing entire libc functions,
    we model their effects directly for efficiency.
    """

    @staticmethod
    def apply_strlen(state: Any, arg_ptr: Any) -> Any:
        """Model strlen: returns length until null byte."""
        # This is a simplified model
        # In practice, would need to handle symbolic strings properly
        claripy = state.solver._claripy
        max_len = 1024

        # Try to concretize if possible
        if state.solver.symbolic(arg_ptr):
            return claripy.BVS("strlen_result", 64)

        # Check for null terminator
        length = claripy.BVV(0, 64)
        for i in range(max_len):
            byte = state.memory.load(arg_ptr + i, 1)
            if state.solver.is_true(byte == 0):
                return claripy.BVV(i, 64)
            if state.solver.symbolic(byte):
                break

        return claripy.BVS("strlen_result", 64)

    @staticmethod
    def apply_strcpy(state: Any, dst: Any, src: Any) -> Any:
        """Model strcpy: copies string until null byte."""
        # Copy up to max length
        max_len = 1024
        for i in range(max_len):
            byte = state.memory.load(src + i, 1)
            state.memory.store(dst + i, byte)
            if state.solver.is_true(byte == 0):
                break
        return dst

    @staticmethod
    def apply_memcpy(state: Any, dst: Any, src: Any, n: Any) -> Any:
        """Model memcpy: copies n bytes."""
        # Try to concretize n
        try:
            n_concrete = state.solver.eval(n)
            if n_concrete > 4096:
                n_concrete = 4096  # Limit for performance
            data = state.memory.load(src, n_concrete)
            state.memory.store(dst, data)
        except:
            pass
        return dst

    @staticmethod
    def apply_malloc(state: Any, size: Any) -> Any:
        """Model malloc: returns symbolic heap pointer."""
        claripy = state.solver._claripy

        # Symbolic heap base (would be managed properly in full impl)
        heap_base = 0x20000000
        if hasattr(state, '_heap_offset'):
            state._heap_offset += 0x1000
        else:
            state._heap_offset = 0

        return claripy.BVV(heap_base + state._heap_offset, 64)


class EnhancedSymbolicEngine:
    """
    Enhanced symbolic execution engine.

    Features:
    - Vulnerability-guided path prioritization
    - Function summaries for common libc
    - Checkpointing for long-running analyses
    - Configurable exploration strategies

    Example:
        engine = EnhancedSymbolicEngine(binary)

        # Find paths to vulnerabilities
        vuln_paths = engine.find_vulnerability_paths(
            target=VulnTarget.BUFFER_OVERFLOW,
            timeout=300
        )

        for path in vuln_paths:
            print(f"Found: {path.target_type}")
            print(f"Input: {path.trigger_input.hex()}")
    """

    # Dangerous function addresses to watch
    DANGEROUS_FUNCS = {
        'gets', 'strcpy', 'strcat', 'sprintf', 'vsprintf',
        'scanf', 'fscanf', 'sscanf', 'printf', 'fprintf',
        'system', 'popen', 'execve', 'execl',
        'read', 'recv', 'memcpy', 'memmove',
    }

    def __init__(
        self,
        binary: Binary,
        auto_load_libs: bool = False,
        checkpoint_dir: Optional[str] = None
    ):
        """
        Initialize engine.

        Args:
            binary: Target binary
            auto_load_libs: Load shared libraries
            checkpoint_dir: Directory for checkpoints
        """
        if not ANGR_AVAILABLE:
            raise ImportError("angr required. Install with: pip install angr")

        self.binary = binary
        self.auto_load_libs = auto_load_libs
        self.checkpoint_dir = checkpoint_dir or str(
            Path.home() / ".supwngo" / "checkpoints"
        )

        # Create angr project
        self.project = angr.Project(
            str(binary.path),
            auto_load_libs=auto_load_libs,
            load_options={'main_opts': {'base_addr': 0x400000}}
        )

        # Exploration state
        self._coverage: Set[int] = set()
        self._found_vulns: List[VulnPath] = []
        self._states_explored = 0

        # Hook dangerous functions
        self._setup_hooks()

    def _setup_hooks(self):
        """Set up hooks for dangerous functions."""
        # Hook dangerous functions with summaries
        for func_name in self.DANGEROUS_FUNCS:
            if func_name in self.project.loader.main_object.plt:
                addr = self.project.loader.main_object.plt[func_name]
                self.project.hook(addr, self._create_func_hook(func_name))

    def _create_func_hook(self, func_name: str):
        """Create hook for a function."""
        class FuncHook(angr.SimProcedure):
            def __init__(self, name):
                super().__init__()
                self.func_name = name

            def run(self, *args):
                # Log dangerous function call
                logger.debug(f"Hooked call to {self.func_name}")

                # Apply summary if available
                if self.func_name == 'strlen' and args:
                    return FunctionSummary.apply_strlen(self.state, args[0])
                elif self.func_name == 'strcpy' and len(args) >= 2:
                    return FunctionSummary.apply_strcpy(self.state, args[0], args[1])
                elif self.func_name == 'memcpy' and len(args) >= 3:
                    return FunctionSummary.apply_memcpy(self.state, args[0], args[1], args[2])
                elif self.func_name == 'malloc' and args:
                    return FunctionSummary.apply_malloc(self.state, args[0])

                # Default: return symbolic value
                return claripy.BVS(f"{self.func_name}_ret", 64)

        return FuncHook(func_name)

    def create_entry_state(
        self,
        stdin_size: int = 256,
        argv: Optional[List[bytes]] = None
    ) -> Any:
        """
        Create initial symbolic state.

        Args:
            stdin_size: Size of symbolic stdin
            argv: Command line arguments

        Returns:
            angr SimState
        """
        # Create symbolic stdin
        stdin_content = claripy.BVS("stdin", stdin_size * 8)

        state = self.project.factory.entry_state(
            stdin=angr.SimFileStream(
                name='stdin',
                content=stdin_content,
                has_end=True
            ),
            args=argv or [self.binary.path.encode()],
        )

        # Store symbolic input reference
        state.globals['stdin_content'] = stdin_content

        return state

    def find_vulnerability_paths(
        self,
        target: VulnTarget = VulnTarget.UNCONSTRAINED_CALL,
        timeout: int = 300,
        max_states: int = 10000,
        strategy: ExplorationStrategy = ExplorationStrategy.VULN_GUIDED
    ) -> List[VulnPath]:
        """
        Find paths leading to vulnerabilities.

        Args:
            target: Type of vulnerability to find
            timeout: Maximum time in seconds
            max_states: Maximum states to explore
            strategy: Exploration strategy

        Returns:
            List of vulnerability paths found
        """
        start_time = time.time()
        self._found_vulns = []
        self._states_explored = 0

        # Create initial state
        state = self.create_entry_state()

        # Create simulation manager
        simgr = self.project.factory.simulation_manager(state)

        # Apply exploration technique
        if strategy == ExplorationStrategy.VULN_GUIDED:
            tech = self._vuln_guided_technique(target)
        elif strategy == ExplorationStrategy.COVERAGE:
            tech = angr.exploration_techniques.Coverage()
        elif strategy == ExplorationStrategy.DFS:
            tech = angr.exploration_techniques.DFS()
        else:
            tech = None

        if tech:
            simgr.use_technique(tech)

        # Exploration loop
        while simgr.active and self._states_explored < max_states:
            if time.time() - start_time > timeout:
                logger.info("Exploration timeout reached")
                break

            # Step simulation
            simgr.step()
            self._states_explored += len(simgr.active)

            # Check for unconstrained states (potential vulnerabilities)
            if hasattr(simgr, 'unconstrained') and simgr.unconstrained:
                for s in simgr.unconstrained:
                    vuln = self._analyze_unconstrained_state(s, target)
                    if vuln:
                        self._found_vulns.append(vuln)
                simgr.drop(stash='unconstrained')

            # Check active states for vulnerability patterns
            for s in simgr.active:
                vuln = self._check_state_for_vuln(s, target)
                if vuln:
                    self._found_vulns.append(vuln)

            # Update coverage
            for s in simgr.active:
                self._coverage.add(s.addr)

            # Checkpoint periodically
            if self._states_explored % 1000 == 0:
                self._save_checkpoint(simgr)

        elapsed = time.time() - start_time
        logger.info(f"Explored {self._states_explored} states in {elapsed:.1f}s, "
                   f"found {len(self._found_vulns)} vulnerabilities")

        return self._found_vulns

    def _vuln_guided_technique(self, target: VulnTarget):
        """Create vulnerability-guided exploration technique."""
        dangerous_addrs = set()

        # Get addresses of dangerous functions
        for func_name in self.DANGEROUS_FUNCS:
            if func_name in self.project.loader.main_object.plt:
                dangerous_addrs.add(self.project.loader.main_object.plt[func_name])

        class VulnGuidedExploration(angr.exploration_techniques.ExplorationTechnique):
            def __init__(self, dangerous_addrs):
                super().__init__()
                self.dangerous = dangerous_addrs

            def step(self, simgr, stash='active', **kwargs):
                simgr.step(stash=stash, **kwargs)

                # Prioritize states near dangerous functions
                if stash in simgr.stashes:
                    states = simgr.stashes[stash]
                    for s in states:
                        # Check if next instruction is call to dangerous func
                        if s.addr in self.dangerous:
                            s.globals['priority'] = 100
                        else:
                            s.globals['priority'] = s.globals.get('priority', 0)

                    # Sort by priority
                    simgr.stashes[stash] = sorted(
                        states,
                        key=lambda s: s.globals.get('priority', 0),
                        reverse=True
                    )

                return simgr

        return VulnGuidedExploration(dangerous_addrs)

    def _analyze_unconstrained_state(
        self,
        state: Any,
        target: VulnTarget
    ) -> Optional[VulnPath]:
        """
        Analyze unconstrained state for vulnerabilities.

        Args:
            state: Unconstrained angr state
            target: Target vulnerability type

        Returns:
            VulnPath if vulnerability found
        """
        # Check if IP is symbolic (controllable)
        if state.solver.symbolic(state.regs.rip if self.binary.bits == 64 else state.regs.eip):
            # Get concrete input that reaches this state
            stdin = state.globals.get('stdin_content')
            if stdin:
                try:
                    concrete_input = state.solver.eval(stdin, cast_to=bytes)

                    return VulnPath(
                        target_type=VulnTarget.UNCONSTRAINED_CALL,
                        path_addresses=list(state.history.bbl_addrs),
                        trigger_input=concrete_input,
                        constraints=[str(c) for c in state.solver.constraints[:10]],
                        exploitability="high",
                        details={
                            "controlled_ip": True,
                            "depth": len(list(state.history.bbl_addrs)),
                        }
                    )
                except:
                    pass

        return None

    def _check_state_for_vuln(
        self,
        state: Any,
        target: VulnTarget
    ) -> Optional[VulnPath]:
        """
        Check if current state represents a vulnerability.

        Args:
            state: Current state
            target: Target vulnerability type

        Returns:
            VulnPath if vulnerability found
        """
        # Check for specific vulnerability patterns
        # This is simplified - real implementation would be more thorough

        # Check for buffer overflow indicators
        if target == VulnTarget.BUFFER_OVERFLOW:
            # Check if stack pointer is corrupted
            sp = state.regs.rsp if self.binary.bits == 64 else state.regs.esp
            if state.solver.symbolic(sp):
                return self._create_vuln_path(state, VulnTarget.BUFFER_OVERFLOW)

        return None

    def _create_vuln_path(
        self,
        state: Any,
        vuln_type: VulnTarget
    ) -> VulnPath:
        """Create VulnPath from state."""
        stdin = state.globals.get('stdin_content')
        concrete_input = b''

        if stdin:
            try:
                concrete_input = state.solver.eval(stdin, cast_to=bytes)
            except:
                pass

        return VulnPath(
            target_type=vuln_type,
            path_addresses=list(state.history.bbl_addrs),
            trigger_input=concrete_input,
            constraints=[str(c) for c in state.solver.constraints[:10]],
            details={"addr": hex(state.addr)}
        )

    def _save_checkpoint(self, simgr: Any):
        """Save exploration checkpoint."""
        os.makedirs(self.checkpoint_dir, exist_ok=True)

        checkpoint = {
            'timestamp': time.time(),
            'states_explored': self._states_explored,
            'coverage': list(self._coverage),
            'num_vulns': len(self._found_vulns),
        }

        path = os.path.join(
            self.checkpoint_dir,
            f"checkpoint_{int(time.time())}.json"
        )

        with open(path, 'w') as f:
            json.dump(checkpoint, f)

        logger.debug(f"Saved checkpoint: {path}")

    def find_path_to_address(
        self,
        target_addr: int,
        timeout: int = 120
    ) -> Optional[bytes]:
        """
        Find input that reaches a specific address.

        Args:
            target_addr: Address to reach
            timeout: Maximum time

        Returns:
            Input bytes that reach target, or None
        """
        state = self.create_entry_state()
        simgr = self.project.factory.simulation_manager(state)

        def is_target(s):
            return s.addr == target_addr

        start = time.time()
        while simgr.active and time.time() - start < timeout:
            simgr.step()

            # Check for target
            found = [s for s in simgr.active if is_target(s)]
            if found:
                stdin = found[0].globals.get('stdin_content')
                if stdin:
                    try:
                        return found[0].solver.eval(stdin, cast_to=bytes)
                    except:
                        pass

        return None

    def get_coverage(self) -> Set[int]:
        """Get set of addresses covered during exploration."""
        return self._coverage.copy()

    def get_stats(self) -> Dict[str, Any]:
        """Get exploration statistics."""
        return {
            "states_explored": self._states_explored,
            "coverage": len(self._coverage),
            "vulnerabilities_found": len(self._found_vulns),
            "unique_blocks": len(self._coverage),
        }


# Convenience function
def find_vulnerabilities(
    binary: Binary,
    timeout: int = 300,
    target: VulnTarget = VulnTarget.UNCONSTRAINED_CALL
) -> List[VulnPath]:
    """
    Find vulnerabilities in a binary using symbolic execution.

    Args:
        binary: Target binary
        timeout: Maximum time in seconds
        target: Type of vulnerability to find

    Returns:
        List of vulnerability paths
    """
    engine = EnhancedSymbolicEngine(binary)
    return engine.find_vulnerability_paths(target=target, timeout=timeout)
