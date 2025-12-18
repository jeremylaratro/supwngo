"""
Advanced integer vulnerability detection module.

Provides comprehensive integer vulnerability detection including:
- Arithmetic chain analysis
- Truncation detection
- Signedness analysis
- Allocation size tracking
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from enum import Enum, auto

from supwngo.core.binary import Binary
from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


class IntVulnType(Enum):
    """Types of integer vulnerabilities."""
    OVERFLOW = auto()
    UNDERFLOW = auto()
    TRUNCATION = auto()
    SIGNEDNESS = auto()
    WRAP_AROUND = auto()
    DIVISION_BY_ZERO = auto()
    SHIFT_OVERFLOW = auto()


class IntContext(Enum):
    """Context where integer is used."""
    ALLOCATION_SIZE = auto()
    BUFFER_INDEX = auto()
    LOOP_BOUND = auto()
    MEMCPY_SIZE = auto()
    COMPARISON = auto()
    RETURN_VALUE = auto()
    UNKNOWN = auto()


@dataclass
class IntegerOperation:
    """Represents an integer operation that could overflow."""
    address: int
    instruction: str
    operation: str  # add, sub, mul, shl, etc.
    operands: List[str]
    result_reg: str
    source_width: int  # Bits
    dest_width: int  # Bits


@dataclass
class IntegerVulnerability:
    """Detailed integer vulnerability."""
    vuln_type: IntVulnType
    severity: str
    address: int
    function: str
    description: str
    context: IntContext
    operation: Optional[IntegerOperation] = None
    tainted_from_input: bool = False
    leads_to_memory_corruption: bool = False
    exploit_template: str = ""
    confidence: float = 0.5


@dataclass
class ArithmeticChain:
    """Chain of arithmetic operations on a value."""
    operations: List[IntegerOperation]
    source: str  # Where value originates
    sink: str  # Where value is used
    can_overflow: bool = False
    can_underflow: bool = False


class AdvancedIntegerAnalyzer:
    """
    Advanced integer vulnerability analyzer.

    Tracks integers through arithmetic operations to identify:
    - Overflow/underflow in calculations
    - Truncation when narrowing types
    - Signedness issues in comparisons
    - Integer issues leading to memory corruption
    """

    def __init__(self, binary: Binary):
        """
        Initialize integer analyzer.

        Args:
            binary: Binary instance to analyze
        """
        self.binary = binary
        self.operations: List[IntegerOperation] = []
        self.chains: List[ArithmeticChain] = []
        self.vulnerabilities: List[IntegerVulnerability] = []

    def analyze(self) -> List[IntegerVulnerability]:
        """
        Perform comprehensive integer analysis.

        Returns:
            List of detected integer vulnerabilities
        """
        logger.info("Starting advanced integer analysis...")

        # Find all arithmetic operations
        self._find_arithmetic_ops()

        # Build arithmetic chains
        self._build_chains()

        # Detect vulnerabilities
        self._detect_overflow()
        self._detect_truncation()
        self._detect_signedness()
        self._detect_allocation_issues()

        logger.info(f"Found {len(self.vulnerabilities)} integer vulnerabilities")
        return self.vulnerabilities

    def _find_arithmetic_ops(self) -> None:
        """Find all arithmetic operations in the binary."""
        arithmetic_insns = {
            'add': 'addition',
            'sub': 'subtraction',
            'imul': 'signed_multiply',
            'mul': 'unsigned_multiply',
            'idiv': 'signed_divide',
            'div': 'unsigned_divide',
            'shl': 'shift_left',
            'shr': 'shift_right',
            'sar': 'arithmetic_shift_right',
            'inc': 'increment',
            'dec': 'decrement',
            'neg': 'negate',
        }

        try:
            import capstone
            cs = capstone.Cs(capstone.CS_ARCH_X86,
                           capstone.CS_MODE_64 if self.binary.bits == 64 else capstone.CS_MODE_32)
            cs.detail = True

            for func_name, sym in self.binary.symbols.items():
                addr = sym.address if hasattr(sym, 'address') else sym
                if not addr:
                    continue

                try:
                    data = self.binary.read(addr, 0x500)
                    for insn in cs.disasm(data, addr):
                        mnem = insn.mnemonic.lower()
                        if mnem in arithmetic_insns:
                            op = IntegerOperation(
                                address=insn.address,
                                instruction=f"{mnem} {insn.op_str}",
                                operation=arithmetic_insns[mnem],
                                operands=insn.op_str.split(','),
                                result_reg=insn.op_str.split(',')[0].strip() if insn.op_str else "",
                                source_width=self._get_operand_width(insn),
                                dest_width=self._get_operand_width(insn),
                            )
                            self.operations.append(op)

                except Exception as e:
                    logger.debug(f"Error analyzing {func_name}: {e}")
                    continue

        except Exception as e:
            logger.warning(f"Arithmetic operation analysis failed: {e}")

    def _get_operand_width(self, insn) -> int:
        """Get operand width in bits."""
        op_str = insn.op_str.lower()
        if 'rax' in op_str or 'rbx' in op_str or 'rcx' in op_str or 'rdx' in op_str:
            return 64
        if 'eax' in op_str or 'ebx' in op_str or 'ecx' in op_str or 'edx' in op_str:
            return 32
        if 'ax' in op_str or 'bx' in op_str or 'cx' in op_str or 'dx' in op_str:
            return 16
        if 'al' in op_str or 'bl' in op_str or 'cl' in op_str or 'dl' in op_str:
            return 8
        return 64 if self.binary.bits == 64 else 32

    def _build_chains(self) -> None:
        """Build arithmetic operation chains."""
        # Group operations by function
        func_ops: Dict[str, List[IntegerOperation]] = {}
        for op in self.operations:
            # Determine function
            func = self._get_function_for_addr(op.address)
            if func not in func_ops:
                func_ops[func] = []
            func_ops[func].append(op)

        # Build chains within each function
        for func, ops in func_ops.items():
            if len(ops) >= 2:
                chain = ArithmeticChain(
                    operations=ops,
                    source=func,
                    sink="unknown",
                    can_overflow=any(op.operation in ('addition', 'signed_multiply', 'unsigned_multiply')
                                    for op in ops),
                    can_underflow=any(op.operation in ('subtraction', 'decrement')
                                     for op in ops),
                )
                self.chains.append(chain)

    def _get_function_for_addr(self, addr: int) -> str:
        """Get function name containing an address."""
        for name, sym in self.binary.symbols.items():
            sym_addr = sym.address if hasattr(sym, 'address') else sym
            if sym_addr and sym_addr <= addr < sym_addr + 0x1000:
                return name
        return "unknown"

    def _detect_overflow(self) -> None:
        """Detect integer overflow vulnerabilities."""
        # Check multiplication without overflow check
        for op in self.operations:
            if op.operation in ('signed_multiply', 'unsigned_multiply'):
                vuln = IntegerVulnerability(
                    vuln_type=IntVulnType.OVERFLOW,
                    severity="MEDIUM",
                    address=op.address,
                    function=self._get_function_for_addr(op.address),
                    description=f"Multiplication at {hex(op.address)} may overflow",
                    context=IntContext.UNKNOWN,
                    operation=op,
                    confidence=0.4,
                    exploit_template=self._gen_overflow_template(),
                )
                self.vulnerabilities.append(vuln)

        # Check chains that could overflow
        for chain in self.chains:
            if chain.can_overflow:
                vuln = IntegerVulnerability(
                    vuln_type=IntVulnType.OVERFLOW,
                    severity="MEDIUM",
                    address=chain.operations[0].address,
                    function=chain.source,
                    description=f"Arithmetic chain in {chain.source} may overflow",
                    context=IntContext.UNKNOWN,
                    confidence=0.5,
                )
                self.vulnerabilities.append(vuln)

    def _detect_truncation(self) -> None:
        """Detect integer truncation vulnerabilities."""
        try:
            import capstone
            cs = capstone.Cs(capstone.CS_ARCH_X86,
                           capstone.CS_MODE_64 if self.binary.bits == 64 else capstone.CS_MODE_32)

            for func_name, sym in self.binary.symbols.items():
                addr = sym.address if hasattr(sym, 'address') else sym
                if not addr:
                    continue

                try:
                    data = self.binary.read(addr, 0x300)
                    for insn in cs.disasm(data, addr):
                        # Look for narrowing moves (64-bit to 32-bit, etc.)
                        if insn.mnemonic == 'mov':
                            parts = insn.op_str.split(',')
                            if len(parts) == 2:
                                dst = parts[0].strip().lower()
                                src = parts[1].strip().lower()

                                # Check for truncation
                                dst_width = self._get_reg_width(dst)
                                src_width = self._get_reg_width(src)

                                if src_width > dst_width and dst_width > 0 and src_width > 0:
                                    vuln = IntegerVulnerability(
                                        vuln_type=IntVulnType.TRUNCATION,
                                        severity="LOW",
                                        address=insn.address,
                                        function=func_name,
                                        description=f"Truncation: {src_width}-bit to {dst_width}-bit",
                                        context=IntContext.UNKNOWN,
                                        confidence=0.3,
                                    )
                                    self.vulnerabilities.append(vuln)

                except Exception:
                    continue

        except Exception as e:
            logger.debug(f"Truncation detection failed: {e}")

    def _get_reg_width(self, reg: str) -> int:
        """Get register width in bits."""
        reg = reg.lower().strip()
        if reg.startswith('r') and len(reg) <= 3:
            return 64
        if reg.startswith('e'):
            return 32
        if reg in ('ax', 'bx', 'cx', 'dx', 'si', 'di', 'sp', 'bp'):
            return 16
        if reg in ('al', 'bl', 'cl', 'dl', 'ah', 'bh', 'ch', 'dh', 'sil', 'dil'):
            return 8
        if reg.startswith('r') and reg[-1] == 'd':
            return 32
        if reg.startswith('r') and reg[-1] == 'w':
            return 16
        if reg.startswith('r') and reg[-1] == 'b':
            return 8
        return 0

    def _detect_signedness(self) -> None:
        """Detect signedness vulnerabilities."""
        try:
            import capstone
            cs = capstone.Cs(capstone.CS_ARCH_X86,
                           capstone.CS_MODE_64 if self.binary.bits == 64 else capstone.CS_MODE_32)

            # Look for signed comparisons followed by unsigned operations
            for func_name, sym in self.binary.symbols.items():
                addr = sym.address if hasattr(sym, 'address') else sym
                if not addr:
                    continue

                try:
                    data = self.binary.read(addr, 0x300)
                    instructions = list(cs.disasm(data, addr))

                    for i, insn in enumerate(instructions):
                        # Signed comparison
                        if insn.mnemonic in ('jl', 'jle', 'jg', 'jge'):
                            # Look for nearby unsigned operation
                            for j in range(max(0, i-3), min(len(instructions), i+3)):
                                if instructions[j].mnemonic in ('ja', 'jae', 'jb', 'jbe'):
                                    vuln = IntegerVulnerability(
                                        vuln_type=IntVulnType.SIGNEDNESS,
                                        severity="MEDIUM",
                                        address=insn.address,
                                        function=func_name,
                                        description="Mixed signed/unsigned comparisons",
                                        context=IntContext.COMPARISON,
                                        confidence=0.5,
                                    )
                                    self.vulnerabilities.append(vuln)
                                    break

                except Exception:
                    continue

        except Exception as e:
            logger.debug(f"Signedness detection failed: {e}")

    def _detect_allocation_issues(self) -> None:
        """Detect integer issues in allocation sizes."""
        alloc_funcs = ['malloc', 'calloc', 'realloc', 'aligned_alloc']

        try:
            import capstone
            cs = capstone.Cs(capstone.CS_ARCH_X86,
                           capstone.CS_MODE_64 if self.binary.bits == 64 else capstone.CS_MODE_32)

            for func_name, sym in self.binary.symbols.items():
                addr = sym.address if hasattr(sym, 'address') else sym
                if not addr:
                    continue

                try:
                    data = self.binary.read(addr, 0x500)
                    instructions = list(cs.disasm(data, addr))

                    for i, insn in enumerate(instructions):
                        # Look for allocation call
                        if insn.mnemonic == 'call':
                            for alloc_func in alloc_funcs:
                                if alloc_func in self.binary.plt:
                                    if str(self.binary.plt[alloc_func]) in insn.op_str:
                                        # Check for arithmetic before allocation
                                        for j in range(max(0, i-10), i):
                                            prev = instructions[j]
                                            if prev.mnemonic in ('add', 'mul', 'imul', 'shl'):
                                                vuln = IntegerVulnerability(
                                                    vuln_type=IntVulnType.OVERFLOW,
                                                    severity="HIGH",
                                                    address=prev.address,
                                                    function=func_name,
                                                    description=f"Arithmetic before {alloc_func}() - potential size overflow",
                                                    context=IntContext.ALLOCATION_SIZE,
                                                    leads_to_memory_corruption=True,
                                                    confidence=0.7,
                                                    exploit_template=self._gen_alloc_overflow_template(),
                                                )
                                                self.vulnerabilities.append(vuln)
                                                break

                except Exception:
                    continue

        except Exception as e:
            logger.debug(f"Allocation issue detection failed: {e}")

    def _gen_overflow_template(self) -> str:
        """Generate integer overflow exploit template."""
        return '''
# Integer Overflow Exploit Template
from pwn import *

# Common overflow scenarios:
# 1. size * count overflow -> small allocation
# 2. size + header overflow -> negative or small allocation

# Example: size * 2 overflow
# If size = 0x80000001, size * 2 = 0x100000002 (truncated to 0x2 on 32-bit)

def trigger_overflow():
    # Send value that causes overflow
    # For 32-bit: 0x80000001 * 2 = 2
    # For 64-bit: 0x8000000000000001 * 2 = 2

    overflow_val = 0x80000001  # Adjust for target

    io.sendline(str(overflow_val))
'''

    def _gen_alloc_overflow_template(self) -> str:
        """Generate allocation overflow template."""
        return '''
# Allocation Size Overflow Template
from pwn import *

# Goal: Make allocation smaller than expected

# Example: malloc(user_size + 16)
# If user_size = 0xFFFFFFF0 (32-bit), result = 0x100000000 -> 0 (wraps)
# Allocates 0 bytes but program thinks it allocated user_size

def exploit_alloc_overflow():
    # Calculate overflow value
    # target_alloc_size + offset = wrap_to_small_value

    # For 32-bit with +16 header:
    overflow_size = 0xFFFFFFF0

    # For 64-bit with +16 header:
    # overflow_size = 0xFFFFFFFFFFFFFFF0

    io.sendline(str(overflow_size))

    # Now write more than allocated
    io.send(b"A" * 0x1000)  # Overflow into adjacent chunks
'''

    def get_critical_vulns(self) -> List[IntegerVulnerability]:
        """Get integer vulnerabilities that lead to memory corruption."""
        return [v for v in self.vulnerabilities
                if v.leads_to_memory_corruption or v.context == IntContext.ALLOCATION_SIZE]

    def summary(self) -> str:
        """Get integer analysis summary."""
        lines = [
            "Advanced Integer Analysis Summary",
            "=" * 40,
            f"Arithmetic Operations: {len(self.operations)}",
            f"Arithmetic Chains: {len(self.chains)}",
            f"Vulnerabilities: {len(self.vulnerabilities)}",
            "",
        ]

        if self.vulnerabilities:
            lines.append("Detected Vulnerabilities:")
            for vuln in self.vulnerabilities[:10]:
                lines.append(f"  [{vuln.severity}] {vuln.vuln_type.name}")
                lines.append(f"      {vuln.description}")

        critical = self.get_critical_vulns()
        if critical:
            lines.append("")
            lines.append(f"Critical (lead to memory corruption): {len(critical)}")

        return "\n".join(lines)
