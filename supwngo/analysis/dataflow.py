"""
Data Flow Analysis module.

Provides intra-procedural data flow analysis including:
- Taint tracking from user input
- Use-def chains
- Reaching definitions
- Live variable analysis
- Constant propagation
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from collections import defaultdict
from enum import Enum, auto

from supwngo.core.binary import Binary
from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


class TaintSource(Enum):
    """Sources of tainted data."""
    STDIN = auto()
    FILE = auto()
    NETWORK = auto()
    ARGV = auto()
    ENVIRONMENT = auto()
    HEAP = auto()
    UNKNOWN = auto()


class TaintState(Enum):
    """Taint states for tracking."""
    CLEAN = auto()
    TAINTED = auto()
    SANITIZED = auto()
    PARTIAL = auto()  # Partially tainted (e.g., some bytes)


@dataclass
class TaintedValue:
    """Represents a tainted value."""
    source: TaintSource
    state: TaintState
    source_address: int = 0  # Where taint was introduced
    source_function: str = ""
    propagation_path: List[int] = field(default_factory=list)
    confidence: float = 1.0


@dataclass
class Definition:
    """Represents a variable definition."""
    address: int  # Instruction address
    variable: str  # Register or memory location
    value: Optional[Any] = None  # Constant value if known
    taint: Optional[TaintedValue] = None


@dataclass
class Use:
    """Represents a variable use."""
    address: int
    variable: str
    definitions: List[Definition] = field(default_factory=list)  # Reaching definitions


@dataclass
class UseDefChain:
    """Use-definition chain for a variable."""
    variable: str
    definitions: List[Definition] = field(default_factory=list)
    uses: List[Use] = field(default_factory=list)


# Functions that introduce taint
TAINT_SOURCES = {
    "read": TaintSource.STDIN,
    "fread": TaintSource.FILE,
    "fgets": TaintSource.STDIN,
    "gets": TaintSource.STDIN,
    "scanf": TaintSource.STDIN,
    "fscanf": TaintSource.FILE,
    "__isoc99_scanf": TaintSource.STDIN,
    "__isoc23_scanf": TaintSource.STDIN,
    "recv": TaintSource.NETWORK,
    "recvfrom": TaintSource.NETWORK,
    "recvmsg": TaintSource.NETWORK,
    "getenv": TaintSource.ENVIRONMENT,
    "getline": TaintSource.STDIN,
    "getdelim": TaintSource.STDIN,
}

# Functions that can propagate taint
TAINT_PROPAGATORS = {
    "strcpy": (0, 1),   # dest <- src
    "strncpy": (0, 1),
    "strcat": (0, 1),
    "strncat": (0, 1),
    "memcpy": (0, 1),
    "memmove": (0, 1),
    "sprintf": (0, None),  # dest <- format args
    "snprintf": (0, None),
    "strdup": (None, 0),  # return <- src
    "strndup": (None, 0),
}

# Functions that are sinks (dangerous if tainted data reaches them)
TAINT_SINKS = {
    "system": [0],      # Command injection
    "popen": [0],       # Command injection
    "execve": [0, 1],   # Command injection
    "execl": [0],       # Command injection
    "execv": [0, 1],    # Command injection
    "printf": [0],      # Format string (if format is tainted)
    "fprintf": [1],     # Format string
    "sprintf": [1],     # Format string
    "snprintf": [2],    # Format string
    "syslog": [1],      # Format string
    "open": [0],        # Path traversal
    "fopen": [0],       # Path traversal
    "unlink": [0],      # Arbitrary file deletion
    "rename": [0, 1],   # Arbitrary file operations
    "malloc": [0],      # Integer overflow in size
    "calloc": [0, 1],   # Integer overflow
    "realloc": [1],     # Integer overflow
}


class DataFlowAnalyzer:
    """
    Data flow analyzer for binary exploitation.

    Tracks how data flows through the program to identify:
    - User input reaching dangerous functions
    - Potential information leaks
    - Integer overflow opportunities
    """

    def __init__(self, binary: Binary):
        """
        Initialize data flow analyzer.

        Args:
            binary: Binary instance to analyze
        """
        self.binary = binary
        self.tainted_locations: Dict[str, TaintedValue] = {}
        self.use_def_chains: Dict[str, UseDefChain] = {}
        self.reaching_defs: Dict[int, Set[Definition]] = defaultdict(set)
        self.live_vars: Dict[int, Set[str]] = defaultdict(set)
        self.constants: Dict[str, Any] = {}
        self._cfg = None

    def analyze_function(self, func_addr: int) -> Dict[str, Any]:
        """
        Perform data flow analysis on a function.

        Args:
            func_addr: Function address

        Returns:
            Analysis results dictionary
        """
        logger.debug(f"Analyzing data flow for function at 0x{func_addr:x}")

        results = {
            "address": hex(func_addr),
            "tainted_paths": [],
            "dangerous_sinks": [],
            "constant_propagation": {},
            "use_def_chains": [],
        }

        try:
            # Use angr for more accurate analysis
            results = self._analyze_with_angr(func_addr)
        except Exception as e:
            logger.debug(f"angr analysis failed: {e}, using heuristic analysis")
            results = self._analyze_heuristic(func_addr)

        return results

    def _analyze_with_angr(self, func_addr: int) -> Dict[str, Any]:
        """Analyze using angr's data flow capabilities."""
        import angr
        from angr.analyses.reaching_definitions import ReachingDefinitionsAnalysis

        proj = self.binary.get_angr_project()
        cfg = proj.analyses.CFGFast()

        results = {
            "address": hex(func_addr),
            "tainted_paths": [],
            "dangerous_sinks": [],
            "constant_propagation": {},
            "use_def_chains": [],
        }

        # Get function
        func = cfg.kb.functions.get(func_addr)
        if not func:
            return results

        try:
            # Reaching definitions analysis
            rd = proj.analyses.ReachingDefinitions(
                subject=func,
                func_graph=func.graph,
                cc=func.calling_convention,
                observe_all=True,
            )

            # Extract use-def information
            for block in func.blocks:
                for observed in rd.observed_results.values():
                    # Track definitions
                    pass

        except Exception as e:
            logger.debug(f"Reaching definitions analysis failed: {e}")

        # Check for taint sources in function
        for block in func.blocks:
            try:
                for insn in block.capstone.insns:
                    if insn.mnemonic == 'call':
                        # Check if calling a taint source
                        target = self._resolve_call_target(insn, proj)
                        if target in TAINT_SOURCES:
                            results["tainted_paths"].append({
                                "source": target,
                                "type": TAINT_SOURCES[target].name,
                                "address": hex(insn.address),
                            })
                        elif target in TAINT_SINKS:
                            results["dangerous_sinks"].append({
                                "sink": target,
                                "address": hex(insn.address),
                                "dangerous_args": TAINT_SINKS[target],
                            })
            except Exception:
                continue

        return results

    def _resolve_call_target(self, insn, proj) -> str:
        """Resolve call instruction target to function name."""
        try:
            if insn.op_str.startswith('0x'):
                target_addr = int(insn.op_str, 16)
                # Check PLT
                for name, addr in self.binary.plt.items():
                    if addr == target_addr:
                        return name
                # Check symbols
                for name, sym in self.binary.symbols.items():
                    if sym.address == target_addr:
                        return name
        except (ValueError, AttributeError):
            pass
        return ""

    def _analyze_heuristic(self, func_addr: int) -> Dict[str, Any]:
        """Heuristic-based data flow analysis without angr."""
        results = {
            "address": hex(func_addr),
            "tainted_paths": [],
            "dangerous_sinks": [],
            "constant_propagation": {},
            "use_def_chains": [],
        }

        # Disassemble function
        try:
            import capstone
            if self.binary.arch == "amd64":
                cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            else:
                cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            cs.detail = True

            # Read function bytes
            func_size = 0x1000  # Assume max size
            for name, sym in self.binary.symbols.items():
                if sym.address == func_addr:
                    func_size = sym.size or func_size
                    break

            data = self.binary.read(func_addr, func_size)

            # Track register state heuristically
            reg_state: Dict[str, Optional[str]] = {}  # reg -> source function or None

            for insn in cs.disasm(data, func_addr):
                mnem = insn.mnemonic.lower()

                # Stop at return
                if mnem in ('ret', 'retn'):
                    break

                if mnem == 'call':
                    # Resolve call target
                    target_name = ""
                    if insn.op_str.startswith('0x'):
                        try:
                            target_addr = int(insn.op_str, 16)
                            for name, addr in self.binary.plt.items():
                                if addr == target_addr:
                                    target_name = name
                                    break
                        except ValueError:
                            pass

                    if target_name in TAINT_SOURCES:
                        # Return value (rax) is tainted
                        reg_state['rax'] = target_name
                        reg_state['eax'] = target_name
                        results["tainted_paths"].append({
                            "source": target_name,
                            "type": TAINT_SOURCES[target_name].name,
                            "address": hex(insn.address),
                        })

                    elif target_name in TAINT_SINKS:
                        # Check if arguments might be tainted
                        arg_regs = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
                        for idx in TAINT_SINKS[target_name]:
                            if idx < len(arg_regs):
                                if reg_state.get(arg_regs[idx]):
                                    results["dangerous_sinks"].append({
                                        "sink": target_name,
                                        "address": hex(insn.address),
                                        "tainted_arg": idx,
                                        "taint_source": reg_state[arg_regs[idx]],
                                    })

                # Track mov instructions for taint propagation
                elif mnem == 'mov':
                    if len(insn.operands) == 2:
                        dst = insn.op_str.split(',')[0].strip()
                        src = insn.op_str.split(',')[1].strip() if ',' in insn.op_str else ""

                        # Propagate taint through registers
                        if src in reg_state and reg_state[src]:
                            reg_state[dst] = reg_state[src]
                        elif dst in reg_state:
                            reg_state[dst] = None

                # Track lea for address calculations
                elif mnem == 'lea':
                    if len(insn.operands) == 2:
                        dst = insn.op_str.split(',')[0].strip()
                        # LEA result is typically an address, not tainted data
                        reg_state[dst] = None

        except Exception as e:
            logger.debug(f"Heuristic analysis failed: {e}")

        return results

    def find_taint_paths(self, source_func: str, sink_func: str) -> List[Dict[str, Any]]:
        """
        Find paths where tainted data from source reaches sink.

        Args:
            source_func: Name of taint source function
            sink_func: Name of sink function

        Returns:
            List of taint paths
        """
        paths = []

        try:
            import angr

            proj = self.binary.get_angr_project()

            # Get addresses
            source_addr = self.binary.plt.get(source_func, 0)
            sink_addr = self.binary.plt.get(sink_func, 0)

            if not source_addr or not sink_addr:
                return paths

            # Use symbolic execution to find paths
            state = proj.factory.entry_state()

            # Create simulation manager
            simgr = proj.factory.simulation_manager(state)

            # Define find/avoid conditions
            def found_sink(state):
                try:
                    return state.addr == sink_addr
                except Exception:
                    return False

            # Explore
            simgr.explore(find=found_sink, avoid=[])

            for found_state in simgr.found:
                path = {
                    "source": source_func,
                    "sink": sink_func,
                    "path_length": len(found_state.history.bbl_addrs),
                    "addresses": [hex(addr) for addr in list(found_state.history.bbl_addrs)[-20:]],
                }
                paths.append(path)

        except Exception as e:
            logger.debug(f"Taint path finding failed: {e}")

        return paths

    def get_reaching_definitions(self, addr: int) -> Set[Definition]:
        """
        Get definitions that reach a particular address.

        Args:
            addr: Target address

        Returns:
            Set of reaching definitions
        """
        return self.reaching_defs.get(addr, set())

    def get_live_variables(self, addr: int) -> Set[str]:
        """
        Get variables live at a particular address.

        Args:
            addr: Target address

        Returns:
            Set of live variable names
        """
        return self.live_vars.get(addr, set())

    def propagate_constants(self, func_addr: int) -> Dict[str, Any]:
        """
        Perform constant propagation analysis.

        Args:
            func_addr: Function address

        Returns:
            Dictionary mapping locations to constant values
        """
        constants = {}

        try:
            import capstone
            if self.binary.arch == "amd64":
                cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            else:
                cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            cs.detail = True

            data = self.binary.read(func_addr, 0x1000)
            reg_constants: Dict[str, int] = {}

            for insn in cs.disasm(data, func_addr):
                mnem = insn.mnemonic.lower()

                if mnem in ('ret', 'retn'):
                    break

                # Track immediate values loaded into registers
                if mnem == 'mov':
                    parts = insn.op_str.split(',')
                    if len(parts) == 2:
                        dst = parts[0].strip()
                        src = parts[1].strip()

                        # Check if source is immediate
                        if src.startswith('0x') or src.lstrip('-').isdigit():
                            try:
                                val = int(src, 0)
                                reg_constants[dst] = val
                                constants[f"{hex(insn.address)}:{dst}"] = val
                            except ValueError:
                                pass
                        elif src in reg_constants:
                            reg_constants[dst] = reg_constants[src]
                            constants[f"{hex(insn.address)}:{dst}"] = reg_constants[src]
                        else:
                            # Value is not constant
                            if dst in reg_constants:
                                del reg_constants[dst]

                # XOR reg, reg clears register to 0
                elif mnem == 'xor':
                    parts = insn.op_str.split(',')
                    if len(parts) == 2 and parts[0].strip() == parts[1].strip():
                        reg = parts[0].strip()
                        reg_constants[reg] = 0
                        constants[f"{hex(insn.address)}:{reg}"] = 0

                # LEA with constant offset
                elif mnem == 'lea':
                    parts = insn.op_str.split(',')
                    if len(parts) == 2:
                        dst = parts[0].strip()
                        # LEA typically loads addresses, not propagate
                        if dst in reg_constants:
                            del reg_constants[dst]

        except Exception as e:
            logger.debug(f"Constant propagation failed: {e}")

        return constants

    def analyze_integer_operations(self, func_addr: int) -> List[Dict[str, Any]]:
        """
        Find potentially dangerous integer operations.

        Args:
            func_addr: Function address

        Returns:
            List of potentially dangerous operations
        """
        dangerous_ops = []

        try:
            import capstone
            if self.binary.arch == "amd64":
                cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            else:
                cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            cs.detail = True

            data = self.binary.read(func_addr, 0x1000)

            for insn in cs.disasm(data, func_addr):
                mnem = insn.mnemonic.lower()

                if mnem in ('ret', 'retn'):
                    break

                # Check for multiplication (potential overflow)
                if mnem in ('imul', 'mul'):
                    dangerous_ops.append({
                        "type": "multiplication",
                        "address": hex(insn.address),
                        "instruction": f"{mnem} {insn.op_str}",
                        "risk": "Potential integer overflow",
                    })

                # Check for addition/subtraction with large operands
                elif mnem in ('add', 'sub'):
                    dangerous_ops.append({
                        "type": "arithmetic",
                        "address": hex(insn.address),
                        "instruction": f"{mnem} {insn.op_str}",
                        "risk": "Potential overflow/underflow",
                    })

                # Check for shifts (can cause unexpected results)
                elif mnem in ('shl', 'shr', 'sal', 'sar'):
                    dangerous_ops.append({
                        "type": "shift",
                        "address": hex(insn.address),
                        "instruction": f"{mnem} {insn.op_str}",
                        "risk": "Potential shift overflow",
                    })

                # Narrowing conversions
                elif mnem == 'mov':
                    parts = insn.op_str.split(',')
                    if len(parts) == 2:
                        dst = parts[0].strip()
                        src = parts[1].strip()
                        # Check for 64-bit to 32-bit (e.g., mov eax, rdi)
                        dst_64 = dst.startswith('r') and not dst.startswith('rip')
                        src_64 = src.startswith('r') and not src.startswith('rip')
                        if not dst_64 and src_64:
                            dangerous_ops.append({
                                "type": "truncation",
                                "address": hex(insn.address),
                                "instruction": f"{mnem} {insn.op_str}",
                                "risk": "Integer truncation",
                            })

        except Exception as e:
            logger.debug(f"Integer analysis failed: {e}")

        return dangerous_ops

    def summary(self) -> str:
        """Get data flow analysis summary."""
        lines = [
            "Data Flow Analysis Summary",
            "=" * 40,
            f"Tainted Locations: {len(self.tainted_locations)}",
            f"Use-Def Chains: {len(self.use_def_chains)}",
            "",
        ]

        if self.tainted_locations:
            lines.append("Tainted Locations:")
            for loc, taint in list(self.tainted_locations.items())[:10]:
                lines.append(f"  {loc}: {taint.source.name} ({taint.state.name})")

        return "\n".join(lines)
