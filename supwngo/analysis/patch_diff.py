"""
Patch diffing for 1-day exploit development.

Compares patched and unpatched binaries to identify security fixes,
enabling rapid exploit development for recently disclosed vulnerabilities.

Features:
- Function-level diffing
- Basic block comparison
- Semantic change detection
- Security-relevant change prioritization
- CVE correlation

Use cases:
- 1-day exploit development
- Patch gap analysis
- Security update prioritization
- Vulnerability research
"""

import hashlib
import subprocess
import tempfile
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


class ChangeType(Enum):
    """Types of changes detected in patches."""
    ADDED = auto()           # New code added
    REMOVED = auto()         # Code removed
    MODIFIED = auto()        # Code changed
    BOUNDS_CHECK = auto()    # Bounds check added
    NULL_CHECK = auto()      # Null pointer check added
    OVERFLOW_FIX = auto()    # Integer overflow fix
    FORMAT_STRING = auto()   # Format string fix
    MEMORY_ALLOC = auto()    # Memory allocation change
    SIZE_CHANGE = auto()     # Size/length change
    CONTROL_FLOW = auto()    # Control flow modification


class SecurityRelevance(Enum):
    """Security relevance of detected changes."""
    HIGH = auto()       # Likely security fix
    MEDIUM = auto()     # Possibly security related
    LOW = auto()        # Probably not security related
    UNKNOWN = auto()    # Cannot determine


@dataclass
class FunctionDiff:
    """Differences in a single function."""
    name: str
    address_old: int
    address_new: int
    size_old: int
    size_new: int
    changes: List['BasicBlockChange'] = field(default_factory=list)
    change_type: ChangeType = ChangeType.MODIFIED
    security_relevance: SecurityRelevance = SecurityRelevance.UNKNOWN
    similarity: float = 0.0  # 0-1, 1 = identical


@dataclass
class BasicBlockChange:
    """Change in a basic block."""
    address_old: int
    address_new: int
    instructions_added: List[str] = field(default_factory=list)
    instructions_removed: List[str] = field(default_factory=list)
    instructions_modified: List[Tuple[str, str]] = field(default_factory=list)


@dataclass
class PatchDiffResult:
    """Complete patch diff analysis result."""
    old_binary: str
    new_binary: str
    functions_added: List[str] = field(default_factory=list)
    functions_removed: List[str] = field(default_factory=list)
    functions_modified: List[FunctionDiff] = field(default_factory=list)
    security_fixes: List[FunctionDiff] = field(default_factory=list)
    timestamp: float = 0.0


class PatchDiffer:
    """
    Binary patch differ for security analysis.

    Compares two versions of a binary to identify security-relevant changes.
    """

    # Keywords suggesting security fixes
    SECURITY_KEYWORDS = [
        'strlen', 'strncpy', 'strncat', 'snprintf',
        'memcpy_s', 'memmove_s', 'strncmp',
        'bounds', 'check', 'limit', 'max', 'min',
        'overflow', 'underflow', 'null', 'nullptr',
        'size', 'length', 'count', 'sanitize', 'validate',
    ]

    # Dangerous functions that might be patched
    DANGEROUS_FUNCTIONS = [
        'strcpy', 'strcat', 'sprintf', 'gets',
        'scanf', 'vsprintf', 'memcpy', 'memmove',
    ]

    def __init__(self):
        self.results: Optional[PatchDiffResult] = None
        self._objdump_path = "objdump"
        self._radare2_path = "r2"

    def diff(
        self,
        old_binary: str,
        new_binary: str,
        use_symbols: bool = True,
    ) -> PatchDiffResult:
        """
        Perform patch diff between two binaries.

        Args:
            old_binary: Path to unpatched binary
            new_binary: Path to patched binary
            use_symbols: Use symbol information if available

        Returns:
            PatchDiffResult with all detected changes
        """
        import time

        result = PatchDiffResult(
            old_binary=old_binary,
            new_binary=new_binary,
            timestamp=time.time(),
        )

        # Get function lists
        old_funcs = self._get_functions(old_binary, use_symbols)
        new_funcs = self._get_functions(new_binary, use_symbols)

        old_names = set(old_funcs.keys())
        new_names = set(new_funcs.keys())

        # Find added/removed functions
        result.functions_added = list(new_names - old_names)
        result.functions_removed = list(old_names - new_names)

        # Compare common functions
        common = old_names & new_names
        for name in common:
            old_func = old_funcs[name]
            new_func = new_funcs[name]

            # Quick hash comparison
            if old_func['hash'] == new_func['hash']:
                continue

            # Detailed diff
            diff = self._diff_function(
                name, old_func, new_func,
                old_binary, new_binary
            )
            result.functions_modified.append(diff)

            # Check if security-relevant
            if diff.security_relevance in (SecurityRelevance.HIGH, SecurityRelevance.MEDIUM):
                result.security_fixes.append(diff)

        # Sort by security relevance
        result.security_fixes.sort(
            key=lambda x: (x.security_relevance.value, -x.similarity)
        )

        self.results = result
        logger.info(
            f"Diff complete: {len(result.functions_modified)} modified, "
            f"{len(result.security_fixes)} security-relevant"
        )

        return result

    def _get_functions(
        self,
        binary: str,
        use_symbols: bool,
    ) -> Dict[str, Dict[str, Any]]:
        """Extract functions from binary."""
        functions = {}

        try:
            # Use objdump to get function list
            cmd = [self._objdump_path, "-d", binary]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60
            )

            current_func = None
            current_bytes = []

            for line in result.stdout.split('\n'):
                # Function header
                if '<' in line and '>:' in line:
                    # Save previous function
                    if current_func:
                        func_hash = hashlib.md5(
                            b''.join(current_bytes)
                        ).hexdigest()
                        functions[current_func['name']]['hash'] = func_hash
                        functions[current_func['name']]['bytes'] = current_bytes

                    # Parse new function
                    parts = line.split()
                    addr = int(parts[0], 16)
                    name = line.split('<')[1].split('>')[0]

                    current_func = {
                        'name': name,
                        'address': addr,
                        'size': 0,
                    }
                    functions[name] = current_func
                    current_bytes = []

                elif current_func and '\t' in line:
                    # Instruction line
                    try:
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            bytes_hex = parts[1].strip()
                            current_bytes.append(bytes.fromhex(
                                bytes_hex.replace(' ', '')
                            ))
                    except (ValueError, IndexError):
                        pass

            # Handle last function
            if current_func:
                func_hash = hashlib.md5(
                    b''.join(current_bytes)
                ).hexdigest()
                functions[current_func['name']]['hash'] = func_hash
                functions[current_func['name']]['bytes'] = current_bytes

        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.error(f"Failed to extract functions: {e}")

        return functions

    def _diff_function(
        self,
        name: str,
        old_func: Dict,
        new_func: Dict,
        old_binary: str,
        new_binary: str,
    ) -> FunctionDiff:
        """Create detailed diff of a function."""
        diff = FunctionDiff(
            name=name,
            address_old=old_func.get('address', 0),
            address_new=new_func.get('address', 0),
            size_old=old_func.get('size', 0),
            size_new=new_func.get('size', 0),
        )

        # Get disassembly
        old_disasm = self._disassemble_function(old_binary, name)
        new_disasm = self._disassemble_function(new_binary, name)

        # Calculate similarity
        diff.similarity = self._calculate_similarity(old_disasm, new_disasm)

        # Detect change type and security relevance
        diff.change_type, diff.security_relevance = self._classify_changes(
            old_disasm, new_disasm
        )

        return diff

    def _disassemble_function(
        self,
        binary: str,
        func_name: str,
    ) -> List[str]:
        """Get disassembly of a specific function."""
        instructions = []

        try:
            cmd = [self._objdump_path, "-d", binary]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60
            )

            in_function = False
            for line in result.stdout.split('\n'):
                if f'<{func_name}>:' in line:
                    in_function = True
                    continue
                elif in_function:
                    if '<' in line and '>:' in line:
                        break  # Next function
                    if '\t' in line:
                        parts = line.split('\t')
                        if len(parts) >= 3:
                            instructions.append(parts[2].strip())

        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return instructions

    def _calculate_similarity(
        self,
        old_instrs: List[str],
        new_instrs: List[str],
    ) -> float:
        """Calculate similarity between two instruction lists."""
        if not old_instrs and not new_instrs:
            return 1.0
        if not old_instrs or not new_instrs:
            return 0.0

        # Jaccard similarity
        old_set = set(old_instrs)
        new_set = set(new_instrs)

        intersection = len(old_set & new_set)
        union = len(old_set | new_set)

        return intersection / union if union > 0 else 0.0

    def _classify_changes(
        self,
        old_instrs: List[str],
        new_instrs: List[str],
    ) -> Tuple[ChangeType, SecurityRelevance]:
        """Classify the type and security relevance of changes."""
        old_text = ' '.join(old_instrs).lower()
        new_text = ' '.join(new_instrs).lower()

        # Check for bounds check additions
        bounds_patterns = ['cmp', 'jbe', 'jae', 'jle', 'jge', 'test']
        old_checks = sum(1 for p in bounds_patterns if p in old_text)
        new_checks = sum(1 for p in bounds_patterns if p in new_text)

        if new_checks > old_checks + 2:
            return ChangeType.BOUNDS_CHECK, SecurityRelevance.HIGH

        # Check for null checks
        null_patterns = ['test', 'je', 'jne', 'cmp', '0x0']
        if any(p in new_text and p not in old_text for p in null_patterns):
            return ChangeType.NULL_CHECK, SecurityRelevance.HIGH

        # Check for size changes in memory operations
        size_patterns = ['mov', 'rep', 'stos', 'movs']
        if any(p in new_text for p in size_patterns):
            # Look for different immediate values
            return ChangeType.SIZE_CHANGE, SecurityRelevance.MEDIUM

        # Check for control flow changes
        cf_patterns = ['call', 'jmp', 'ret']
        old_cf = sum(1 for p in cf_patterns if p in old_text)
        new_cf = sum(1 for p in cf_patterns if p in new_text)

        if abs(new_cf - old_cf) > 2:
            return ChangeType.CONTROL_FLOW, SecurityRelevance.MEDIUM

        return ChangeType.MODIFIED, SecurityRelevance.LOW

    def get_security_summary(self) -> str:
        """Generate human-readable security summary."""
        if not self.results:
            return "No diff results available"

        lines = [
            f"# Patch Diff Security Summary",
            f"",
            f"Old: {self.results.old_binary}",
            f"New: {self.results.new_binary}",
            f"",
            f"## Statistics",
            f"- Functions added: {len(self.results.functions_added)}",
            f"- Functions removed: {len(self.results.functions_removed)}",
            f"- Functions modified: {len(self.results.functions_modified)}",
            f"- Security-relevant changes: {len(self.results.security_fixes)}",
            f"",
        ]

        if self.results.security_fixes:
            lines.append("## Security-Relevant Changes")
            lines.append("")

            for fix in self.results.security_fixes:
                lines.append(f"### {fix.name}")
                lines.append(f"- Change type: {fix.change_type.name}")
                lines.append(f"- Relevance: {fix.security_relevance.name}")
                lines.append(f"- Similarity: {fix.similarity:.2%}")
                lines.append(f"- Old address: 0x{fix.address_old:x}")
                lines.append(f"- New address: 0x{fix.address_new:x}")
                lines.append("")

        return '\n'.join(lines)


class BinDiffIntegration:
    """
    Integration with BinDiff for advanced analysis.

    BinDiff provides more accurate function matching and
    similarity analysis using graph isomorphism.
    """

    def __init__(self, bindiff_path: str = "bindiff"):
        self.bindiff_path = bindiff_path

    def export_ida_db(self, binary: str, output: str) -> bool:
        """Export binary to IDA database (requires IDA)."""
        # Placeholder - requires IDA installation
        logger.warning("BinDiff integration requires IDA Pro")
        return False

    def diff(
        self,
        old_db: str,
        new_db: str,
        output: str,
    ) -> Optional[str]:
        """Run BinDiff on two databases."""
        try:
            cmd = [
                self.bindiff_path,
                "--primary", old_db,
                "--secondary", new_db,
                "--output", output,
            ]
            result = subprocess.run(
                cmd, capture_output=True, timeout=300
            )
            return output if result.returncode == 0 else None
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            logger.error(f"BinDiff failed: {e}")
            return None


class Diaphora:
    """
    Diaphora integration for open-source binary diffing.

    Diaphora is an open-source alternative to BinDiff
    that works with IDA Pro.
    """

    def __init__(self):
        self.available = self._check_available()

    def _check_available(self) -> bool:
        """Check if Diaphora is available."""
        try:
            import sqlite3
            return True
        except ImportError:
            return False

    def parse_results(self, db_path: str) -> List[FunctionDiff]:
        """Parse Diaphora SQLite results."""
        diffs = []

        if not Path(db_path).exists():
            logger.error(f"Diaphora DB not found: {db_path}")
            return diffs

        try:
            import sqlite3
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            # Query modified functions
            cursor.execute("""
                SELECT name1, name2, address1, address2, ratio
                FROM results
                WHERE type = 'modified'
            """)

            for row in cursor.fetchall():
                name1, name2, addr1, addr2, ratio = row
                diffs.append(FunctionDiff(
                    name=name1,
                    address_old=addr1,
                    address_new=addr2,
                    size_old=0,
                    size_new=0,
                    similarity=ratio,
                ))

            conn.close()
        except Exception as e:
            logger.error(f"Failed to parse Diaphora results: {e}")

        return diffs


class CVECorrelator:
    """
    Correlate patch diffs with known CVEs.

    Uses function names, change patterns, and timing
    to suggest possible CVE associations.
    """

    # Common CVE patterns by vulnerability type
    CVE_PATTERNS = {
        'buffer_overflow': [
            'strcpy', 'strcat', 'memcpy', 'sprintf',
            'bounds', 'length', 'size',
        ],
        'format_string': [
            'printf', 'sprintf', 'fprintf', 'syslog',
            'format', 'fmt',
        ],
        'integer_overflow': [
            'add', 'mul', 'size_t', 'int', 'unsigned',
            'overflow', 'check',
        ],
        'use_after_free': [
            'free', 'delete', 'release', 'destroy',
            'use', 'reference',
        ],
        'null_deref': [
            'null', 'nullptr', 'check', 'valid',
            'assert', 'if',
        ],
    }

    def suggest_cve_type(self, diff: FunctionDiff) -> List[str]:
        """Suggest possible CVE types based on changes."""
        suggestions = []

        func_lower = diff.name.lower()

        for cve_type, patterns in self.CVE_PATTERNS.items():
            if any(p in func_lower for p in patterns):
                suggestions.append(cve_type)

        # Use change type as hint
        if diff.change_type == ChangeType.BOUNDS_CHECK:
            if 'buffer_overflow' not in suggestions:
                suggestions.append('buffer_overflow')
        elif diff.change_type == ChangeType.NULL_CHECK:
            if 'null_deref' not in suggestions:
                suggestions.append('null_deref')
        elif diff.change_type == ChangeType.OVERFLOW_FIX:
            if 'integer_overflow' not in suggestions:
                suggestions.append('integer_overflow')

        return suggestions


def diff_binaries(
    old_binary: str,
    new_binary: str,
    output_report: Optional[str] = None,
) -> PatchDiffResult:
    """
    High-level function to diff two binaries.

    Args:
        old_binary: Path to unpatched binary
        new_binary: Path to patched binary
        output_report: Optional path for security report

    Returns:
        PatchDiffResult with analysis
    """
    differ = PatchDiffer()
    result = differ.diff(old_binary, new_binary)

    if output_report:
        report = differ.get_security_summary()
        Path(output_report).write_text(report)
        logger.info(f"Security report written to {output_report}")

    return result


def generate_1day_template(
    diff_result: PatchDiffResult,
    target_function: str,
) -> str:
    """Generate 1-day exploit development template."""
    return f'''#!/usr/bin/env python3
"""
1-Day Exploit Development Template

Target: {diff_result.old_binary}
Patched: {diff_result.new_binary}
Vulnerable Function: {target_function}

Generated from patch diff analysis.
"""

from pwn import *

# Configuration
BINARY = "{diff_result.old_binary}"
TARGET_FUNC = "{target_function}"

# Analysis from patch diff
# {len(diff_result.security_fixes)} security-relevant changes found

def analyze_vulnerability():
    """Analyze the vulnerability based on patch diff."""
    # The patch added checks that suggest:
    # - Bounds checking
    # - Input validation
    # - Size limitations

    # TODO: Reverse engineer the exact vulnerability
    pass

def build_exploit():
    """Build exploit for the vulnerability."""
    # Based on patch analysis:
    # - Function: {target_function}
    # - Likely type: buffer overflow / format string / etc.

    # TODO: Implement exploit
    payload = b"A" * 100  # Placeholder
    return payload

def main():
    context.binary = BINARY

    # Local testing
    p = process(BINARY)

    payload = build_exploit()
    p.sendline(payload)

    p.interactive()

if __name__ == "__main__":
    main()
'''
