"""
Control Flow Graph (CFG) analysis module.

Provides comprehensive CFG construction and analysis including:
- Basic block extraction
- Call graph generation
- Loop detection
- Dominator analysis
- Path finding to dangerous functions
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from collections import defaultdict
import struct

from supwngo.core.binary import Binary
from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class BasicBlock:
    """Represents a basic block in the CFG."""
    address: int
    size: int
    instructions: List[Tuple[int, str, str]] = field(default_factory=list)  # (addr, mnemonic, op_str)
    successors: List[int] = field(default_factory=list)
    predecessors: List[int] = field(default_factory=list)
    function: Optional[str] = None
    is_entry: bool = False
    is_exit: bool = False
    calls: List[int] = field(default_factory=list)  # Call targets from this block


@dataclass
class Function:
    """Represents a function in the binary."""
    name: str
    address: int
    size: int
    blocks: List[int] = field(default_factory=list)  # Block addresses
    entry_block: Optional[int] = None
    exit_blocks: List[int] = field(default_factory=list)
    calls: List[str] = field(default_factory=list)  # Functions called
    called_by: List[str] = field(default_factory=list)  # Functions that call this
    local_vars_size: int = 0
    is_recursive: bool = False
    has_indirect_calls: bool = False
    cyclomatic_complexity: int = 1


@dataclass
class Loop:
    """Represents a loop in the CFG."""
    header: int  # Loop header block address
    blocks: Set[int] = field(default_factory=set)  # All blocks in loop
    back_edges: List[Tuple[int, int]] = field(default_factory=list)  # (from, to) back edges
    exit_blocks: List[int] = field(default_factory=list)
    nesting_level: int = 0
    is_natural: bool = True  # Single entry point


class CFGAnalyzer:
    """
    Control Flow Graph analyzer.

    Builds and analyzes CFGs for binary exploitation:
    - Identifies basic blocks and their relationships
    - Finds loops that may indicate vulnerability patterns
    - Computes dominator trees for path analysis
    - Generates call graphs for inter-procedural analysis
    """

    def __init__(self, binary: Binary):
        """
        Initialize CFG analyzer.

        Args:
            binary: Binary instance to analyze
        """
        self.binary = binary
        self.blocks: Dict[int, BasicBlock] = {}
        self.functions: Dict[str, Function] = {}
        self.loops: List[Loop] = []
        self.call_graph: Dict[str, List[str]] = defaultdict(list)
        self.reverse_call_graph: Dict[str, List[str]] = defaultdict(list)
        self._dominators: Dict[int, Set[int]] = {}
        self._post_dominators: Dict[int, Set[int]] = {}
        self._capstone = None

    def _get_disassembler(self):
        """Get capstone disassembler for the binary's architecture."""
        if self._capstone is None:
            try:
                import capstone
                if self.binary.arch == "amd64":
                    self._capstone = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                elif self.binary.arch == "i386":
                    self._capstone = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
                elif self.binary.arch == "arm":
                    self._capstone = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
                elif self.binary.arch == "aarch64":
                    self._capstone = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
                else:
                    # Default to x86_64
                    self._capstone = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                self._capstone.detail = True
            except ImportError:
                logger.warning("capstone not available, CFG analysis limited")
                return None
        return self._capstone

    def build_cfg(self, start_addr: Optional[int] = None) -> Dict[int, BasicBlock]:
        """
        Build the control flow graph.

        Args:
            start_addr: Optional starting address (defaults to entry point)

        Returns:
            Dictionary mapping addresses to BasicBlock objects
        """
        logger.info("Building control flow graph...")

        # Try angr first for accurate CFG
        try:
            return self._build_cfg_angr()
        except Exception as e:
            logger.debug(f"angr CFG failed: {e}, falling back to linear disassembly")

        # Fallback to capstone-based analysis
        return self._build_cfg_capstone(start_addr)

    def _build_cfg_angr(self) -> Dict[int, BasicBlock]:
        """Build CFG using angr."""
        import angr

        proj = self.binary.get_angr_project()
        cfg = proj.analyses.CFGFast(normalize=True)

        # Convert angr CFG to our format
        for node in cfg.graph.nodes():
            if node.block is None:
                continue

            block = BasicBlock(
                address=node.addr,
                size=node.size,
                instructions=[],
                successors=[succ.addr for succ in cfg.graph.successors(node)],
                predecessors=[pred.addr for pred in cfg.graph.predecessors(node)],
            )

            # Extract instructions
            try:
                for insn in node.block.capstone.insns:
                    block.instructions.append((insn.address, insn.mnemonic, insn.op_str))
                    # Track calls
                    if insn.mnemonic in ('call', 'bl', 'blx'):
                        try:
                            target = int(insn.op_str, 16) if insn.op_str.startswith('0x') else 0
                            if target:
                                block.calls.append(target)
                        except ValueError:
                            block.calls.append(0)  # Indirect call
            except Exception:
                pass

            self.blocks[node.addr] = block

        # Map blocks to functions
        for func_addr, func in cfg.kb.functions.items():
            f = Function(
                name=func.name or f"sub_{func_addr:x}",
                address=func_addr,
                size=func.size,
                blocks=[b.addr for b in func.blocks if b.addr in self.blocks],
                entry_block=func_addr,
            )

            # Get function calls
            for callee in func.functions_called():
                f.calls.append(callee.name or f"sub_{callee.addr:x}")
                self.call_graph[f.name].append(callee.name or f"sub_{callee.addr:x}")
                self.reverse_call_graph[callee.name or f"sub_{callee.addr:x}"].append(f.name)

            # Check for recursion
            if f.name in f.calls:
                f.is_recursive = True

            # Compute cyclomatic complexity: E - N + 2P
            edges = sum(len(self.blocks[b].successors) for b in f.blocks if b in self.blocks)
            nodes = len(f.blocks)
            f.cyclomatic_complexity = edges - nodes + 2

            self.functions[f.name] = f

        logger.info(f"Built CFG: {len(self.blocks)} blocks, {len(self.functions)} functions")
        return self.blocks

    def _build_cfg_capstone(self, start_addr: Optional[int] = None) -> Dict[int, BasicBlock]:
        """Build CFG using capstone linear disassembly."""
        cs = self._get_disassembler()
        if cs is None:
            return {}

        # Get text section
        text_section = None
        for name, section in self.binary.sections.items():
            if name == '.text' or (section.flags & 0x4):  # Executable
                text_section = section
                break

        if text_section is None:
            logger.error("No executable section found")
            return {}

        # Read section data
        start = text_section.address
        size = text_section.size
        data = self.binary.read(start, size)

        # Disassemble and identify basic blocks
        current_block = None
        block_leaders = set()

        # First pass: identify block leaders
        block_leaders.add(start)
        if start_addr:
            block_leaders.add(start_addr)

        for symbol in self.binary.symbols.values():
            if start <= symbol.address < start + size:
                block_leaders.add(symbol.address)

        # Disassemble
        instructions = list(cs.disasm(data, start))

        for i, insn in enumerate(instructions):
            mnemonic = insn.mnemonic.lower()

            # Control flow instructions start new blocks after them
            if mnemonic in ('jmp', 'je', 'jne', 'jz', 'jnz', 'jg', 'jge', 'jl', 'jle',
                           'ja', 'jae', 'jb', 'jbe', 'jo', 'jno', 'js', 'jns',
                           'call', 'ret', 'retn', 'b', 'bl', 'bx', 'blx', 'beq', 'bne'):
                if i + 1 < len(instructions):
                    block_leaders.add(instructions[i + 1].address)

                # Branch targets are also leaders
                if insn.op_str and insn.op_str.startswith('0x'):
                    try:
                        target = int(insn.op_str, 16)
                        if start <= target < start + size:
                            block_leaders.add(target)
                    except ValueError:
                        pass

        # Second pass: create basic blocks
        sorted_leaders = sorted(block_leaders)

        for i, leader in enumerate(sorted_leaders):
            # Find instructions in this block
            block_insns = []
            block_size = 0

            for insn in instructions:
                if insn.address < leader:
                    continue
                if i + 1 < len(sorted_leaders) and insn.address >= sorted_leaders[i + 1]:
                    break
                block_insns.append((insn.address, insn.mnemonic, insn.op_str))
                block_size = insn.address + insn.size - leader

            if block_insns:
                block = BasicBlock(
                    address=leader,
                    size=block_size,
                    instructions=block_insns,
                )

                # Determine successors from last instruction
                if block_insns:
                    last_addr, last_mnem, last_op = block_insns[-1]
                    last_mnem = last_mnem.lower()

                    if last_mnem == 'ret' or last_mnem == 'retn':
                        block.is_exit = True
                    elif last_mnem == 'jmp':
                        # Unconditional jump
                        if last_op.startswith('0x'):
                            try:
                                block.successors.append(int(last_op, 16))
                            except ValueError:
                                pass
                    elif last_mnem.startswith('j') or last_mnem in ('b', 'beq', 'bne'):
                        # Conditional jump - two successors
                        if last_op.startswith('0x'):
                            try:
                                block.successors.append(int(last_op, 16))
                            except ValueError:
                                pass
                        # Fall through
                        if i + 1 < len(sorted_leaders):
                            block.successors.append(sorted_leaders[i + 1])
                    elif last_mnem == 'call':
                        # Call - continue to next block
                        if i + 1 < len(sorted_leaders):
                            block.successors.append(sorted_leaders[i + 1])
                        if last_op.startswith('0x'):
                            try:
                                block.calls.append(int(last_op, 16))
                            except ValueError:
                                pass
                    else:
                        # Fall through
                        if i + 1 < len(sorted_leaders):
                            block.successors.append(sorted_leaders[i + 1])

                self.blocks[leader] = block

        # Set predecessors
        for addr, block in self.blocks.items():
            for succ in block.successors:
                if succ in self.blocks:
                    self.blocks[succ].predecessors.append(addr)

        # Identify functions from symbols
        for name, symbol in self.binary.symbols.items():
            if symbol.address in self.blocks:
                func = Function(
                    name=name,
                    address=symbol.address,
                    size=symbol.size or 0,
                    entry_block=symbol.address,
                )
                self._collect_function_blocks(func)
                self.functions[name] = func

        logger.info(f"Built CFG: {len(self.blocks)} blocks, {len(self.functions)} functions")
        return self.blocks

    def _collect_function_blocks(self, func: Function) -> None:
        """Collect all blocks belonging to a function via reachability."""
        if func.entry_block is None or func.entry_block not in self.blocks:
            return

        visited = set()
        worklist = [func.entry_block]

        while worklist:
            addr = worklist.pop()
            if addr in visited or addr not in self.blocks:
                continue
            visited.add(addr)

            block = self.blocks[addr]
            block.function = func.name
            func.blocks.append(addr)

            # Track calls
            for call_target in block.calls:
                # Try to resolve call target to function name
                for name, f in self.functions.items():
                    if f.address == call_target:
                        if name not in func.calls:
                            func.calls.append(name)
                        break

            # Add successors to worklist (if they look like they're in this function)
            for succ in block.successors:
                if succ in self.blocks:
                    # Heuristic: don't follow jumps too far away
                    if abs(succ - func.address) < 0x10000:
                        worklist.append(succ)

            # Mark exit blocks
            if block.is_exit:
                func.exit_blocks.append(addr)

    def find_loops(self) -> List[Loop]:
        """
        Find all loops in the CFG using back edge detection.

        Returns:
            List of Loop objects
        """
        logger.debug("Finding loops in CFG...")

        # Compute dominators first
        self._compute_dominators()

        self.loops = []

        # Find back edges (edge where target dominates source)
        back_edges = []
        for addr, block in self.blocks.items():
            for succ in block.successors:
                if succ in self._dominators.get(addr, set()):
                    back_edges.append((addr, succ))

        # For each back edge, construct the natural loop
        for source, header in back_edges:
            loop = Loop(header=header)
            loop.back_edges.append((source, header))
            loop.blocks.add(header)

            # Find all blocks in loop via backward traversal from source
            worklist = [source]
            while worklist:
                node = worklist.pop()
                if node not in loop.blocks:
                    loop.blocks.add(node)
                    if node in self.blocks:
                        worklist.extend(self.blocks[node].predecessors)

            # Find exit blocks (have successors outside loop)
            for block_addr in loop.blocks:
                if block_addr in self.blocks:
                    for succ in self.blocks[block_addr].successors:
                        if succ not in loop.blocks:
                            if block_addr not in loop.exit_blocks:
                                loop.exit_blocks.append(block_addr)

            self.loops.append(loop)

        # Compute nesting levels
        for i, loop1 in enumerate(self.loops):
            for loop2 in self.loops:
                if loop1 is not loop2 and loop1.blocks < loop2.blocks:
                    loop1.nesting_level = max(loop1.nesting_level, loop2.nesting_level + 1)

        logger.debug(f"Found {len(self.loops)} loops")
        return self.loops

    def _compute_dominators(self) -> None:
        """Compute dominator sets for all blocks."""
        if not self.blocks:
            return

        # Find entry block
        entry = min(self.blocks.keys())

        # Initialize
        all_blocks = set(self.blocks.keys())
        self._dominators = {entry: {entry}}
        for addr in all_blocks - {entry}:
            self._dominators[addr] = all_blocks.copy()

        # Iterate until fixed point
        changed = True
        while changed:
            changed = False
            for addr in all_blocks - {entry}:
                if addr not in self.blocks:
                    continue
                block = self.blocks[addr]

                # Dom(n) = {n} U intersection(Dom(p) for p in predecessors)
                if block.predecessors:
                    new_dom = all_blocks.copy()
                    for pred in block.predecessors:
                        if pred in self._dominators:
                            new_dom &= self._dominators[pred]
                    new_dom.add(addr)

                    if new_dom != self._dominators[addr]:
                        self._dominators[addr] = new_dom
                        changed = True

    def find_paths_to_function(self, target_name: str, max_depth: int = 20) -> List[List[str]]:
        """
        Find all call paths from entry points to a target function.

        Args:
            target_name: Name of target function
            max_depth: Maximum path depth

        Returns:
            List of paths (each path is list of function names)
        """
        if target_name not in self.functions:
            # Check if it's a PLT function
            for name in self.binary.plt:
                if name == target_name:
                    break
            else:
                logger.warning(f"Function {target_name} not found")
                return []

        paths = []

        # Find entry points (functions not called by anything, or main)
        entry_points = []
        if "main" in self.functions:
            entry_points.append("main")
        if "_start" in self.functions:
            entry_points.append("_start")

        for name in self.functions:
            if not self.reverse_call_graph.get(name) and name not in entry_points:
                entry_points.append(name)

        # BFS from entry points
        for entry in entry_points:
            self._find_paths_dfs(entry, target_name, [], paths, max_depth, set())

        return paths

    def _find_paths_dfs(self, current: str, target: str, path: List[str],
                        all_paths: List[List[str]], max_depth: int, visited: Set[str]) -> None:
        """DFS helper for path finding."""
        if len(path) > max_depth:
            return
        if current in visited:
            return

        path = path + [current]

        if current == target:
            all_paths.append(path)
            return

        visited = visited | {current}

        # Follow call graph edges
        for callee in self.call_graph.get(current, []):
            self._find_paths_dfs(callee, target, path, all_paths, max_depth, visited)

    def get_function_complexity(self, func_name: str) -> Dict[str, Any]:
        """
        Compute complexity metrics for a function.

        Args:
            func_name: Function name

        Returns:
            Dictionary of complexity metrics
        """
        if func_name not in self.functions:
            return {}

        func = self.functions[func_name]

        # Count various metrics
        num_blocks = len(func.blocks)
        num_calls = len(func.calls)
        num_loops = len([l for l in self.loops if l.header in func.blocks])
        max_nesting = max([l.nesting_level for l in self.loops if l.header in func.blocks], default=0)

        # Count branches
        num_branches = 0
        for block_addr in func.blocks:
            if block_addr in self.blocks:
                if len(self.blocks[block_addr].successors) > 1:
                    num_branches += 1

        return {
            "name": func_name,
            "blocks": num_blocks,
            "calls": num_calls,
            "loops": num_loops,
            "max_loop_nesting": max_nesting,
            "branches": num_branches,
            "cyclomatic_complexity": func.cyclomatic_complexity,
            "is_recursive": func.is_recursive,
            "has_indirect_calls": func.has_indirect_calls,
        }

    def find_dangerous_patterns(self) -> List[Dict[str, Any]]:
        """
        Find potentially dangerous patterns in the CFG.

        Returns:
            List of pattern matches with details
        """
        patterns = []

        # Pattern 1: Loops with unbounded iteration (potential DoS or overflow)
        for loop in self.loops:
            if loop.nesting_level >= 2:
                patterns.append({
                    "type": "deeply_nested_loop",
                    "address": hex(loop.header),
                    "nesting": loop.nesting_level,
                    "risk": "Potential complexity/DoS issue",
                })

        # Pattern 2: Functions with many paths (complex error handling)
        for name, func in self.functions.items():
            if func.cyclomatic_complexity > 15:
                patterns.append({
                    "type": "high_complexity",
                    "function": name,
                    "complexity": func.cyclomatic_complexity,
                    "risk": "High complexity may hide vulnerabilities",
                })

        # Pattern 3: Recursive functions (potential stack overflow)
        for name, func in self.functions.items():
            if func.is_recursive:
                patterns.append({
                    "type": "recursive_function",
                    "function": name,
                    "address": hex(func.address),
                    "risk": "Unbounded recursion could cause stack overflow",
                })

        # Pattern 4: Indirect calls (potential control flow hijack targets)
        for addr, block in self.blocks.items():
            for inst_addr, mnem, op_str in block.instructions:
                if mnem in ('call', 'jmp') and not op_str.startswith('0x'):
                    if op_str and not op_str.isdigit():
                        patterns.append({
                            "type": "indirect_call",
                            "address": hex(inst_addr),
                            "target": op_str,
                            "risk": "Indirect call - potential hijack target",
                        })

        return patterns

    def summary(self) -> str:
        """Get CFG analysis summary."""
        lines = [
            "CFG Analysis Summary",
            "=" * 40,
            f"Basic Blocks: {len(self.blocks)}",
            f"Functions: {len(self.functions)}",
            f"Loops: {len(self.loops)}",
            "",
        ]

        # Top complex functions
        complex_funcs = sorted(
            self.functions.values(),
            key=lambda f: f.cyclomatic_complexity,
            reverse=True
        )[:5]

        if complex_funcs:
            lines.append("Most Complex Functions:")
            for f in complex_funcs:
                lines.append(f"  {f.name}: complexity={f.cyclomatic_complexity}, blocks={len(f.blocks)}")

        # Recursive functions
        recursive = [f for f in self.functions.values() if f.is_recursive]
        if recursive:
            lines.append("")
            lines.append(f"Recursive Functions: {len(recursive)}")
            for f in recursive[:5]:
                lines.append(f"  {f.name}")

        return "\n".join(lines)
