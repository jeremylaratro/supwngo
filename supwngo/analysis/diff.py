"""
Binary diffing module.

Provides binary comparison capabilities including:
- Function matching between binary versions
- Patch analysis for security fixes
- Similarity scoring (bindiff-like)
- Symbol recovery from similar binaries
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from collections import defaultdict
import hashlib

from supwngo.core.binary import Binary
from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class FunctionSignature:
    """Function signature for matching."""
    name: str
    address: int
    size: int
    hash_bytes: str  # Hash of function bytes
    hash_cfg: str  # Hash of CFG structure
    num_blocks: int
    num_calls: int
    num_strings: int
    called_functions: List[str] = field(default_factory=list)
    constants: List[int] = field(default_factory=list)


@dataclass
class FunctionMatch:
    """Matched function pair."""
    func1: FunctionSignature
    func2: FunctionSignature
    similarity: float
    match_type: str  # exact, cfg, heuristic
    differences: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class PatchInfo:
    """Information about a detected patch."""
    function: str
    old_address: int
    new_address: int
    patch_type: str  # added, removed, modified
    size_change: int
    description: str = ""
    security_relevant: bool = False


class BinaryDiffer:
    """
    Binary diffing and patch analysis.

    Compares two binaries to identify:
    - Function matches/differences
    - Security patches
    - Symbol recovery opportunities
    """

    def __init__(self, binary1: Binary, binary2: Binary):
        """
        Initialize differ with two binaries.

        Args:
            binary1: First (usually older) binary
            binary2: Second (usually newer) binary
        """
        self.binary1 = binary1
        self.binary2 = binary2
        self.signatures1: Dict[str, FunctionSignature] = {}
        self.signatures2: Dict[str, FunctionSignature] = {}
        self.matches: List[FunctionMatch] = []
        self.patches: List[PatchInfo] = []

    def diff(self) -> Dict[str, Any]:
        """
        Perform full binary diff.

        Returns:
            Diff results dictionary
        """
        logger.info(f"Diffing {self.binary1.path.name} vs {self.binary2.path.name}")

        # Build function signatures
        self._build_signatures(self.binary1, self.signatures1)
        self._build_signatures(self.binary2, self.signatures2)

        # Match functions
        self._match_functions()

        # Identify patches
        self._identify_patches()

        results = {
            "binary1": str(self.binary1.path),
            "binary2": str(self.binary2.path),
            "functions1": len(self.signatures1),
            "functions2": len(self.signatures2),
            "matched": len(self.matches),
            "unmatched1": len(self.signatures1) - len([m for m in self.matches]),
            "unmatched2": len(self.signatures2) - len([m for m in self.matches]),
            "patches": [
                {
                    "function": p.function,
                    "type": p.patch_type,
                    "size_change": p.size_change,
                    "security_relevant": p.security_relevant,
                    "description": p.description,
                }
                for p in self.patches
            ],
            "matches": [
                {
                    "func1": m.func1.name,
                    "func2": m.func2.name,
                    "similarity": m.similarity,
                    "type": m.match_type,
                }
                for m in self.matches[:100]  # Limit output
            ],
        }

        logger.info(f"Diff complete: {len(self.matches)} matches, {len(self.patches)} patches")
        return results

    def _build_signatures(self, binary: Binary, signatures: Dict[str, FunctionSignature]) -> None:
        """Build function signatures for a binary."""
        try:
            proj = binary.get_angr_project()
            cfg = proj.analyses.CFGFast()

            for func_addr, func in cfg.kb.functions.items():
                if func.name and not func.name.startswith("sub_"):
                    sig = self._create_signature(binary, func, cfg)
                    if sig:
                        signatures[func.name] = sig

            # Also add unnamed functions by address
            for func_addr, func in cfg.kb.functions.items():
                if func.name.startswith("sub_"):
                    sig = self._create_signature(binary, func, cfg)
                    if sig:
                        signatures[f"sub_{func_addr:x}"] = sig

        except Exception as e:
            logger.warning(f"Failed to build signatures with angr: {e}")
            # Fallback to symbol-based
            for name, symbol in binary.symbols.items():
                if symbol.size > 0:
                    sig = FunctionSignature(
                        name=name,
                        address=symbol.address,
                        size=symbol.size,
                        hash_bytes=self._hash_bytes(binary, symbol.address, symbol.size),
                        hash_cfg="",
                        num_blocks=0,
                        num_calls=0,
                        num_strings=0,
                    )
                    signatures[name] = sig

    def _create_signature(self, binary: Binary, func, cfg) -> Optional[FunctionSignature]:
        """Create signature for a function."""
        try:
            # Get function bytes
            func_bytes = binary.elf.read(func.addr, func.size) if func.size > 0 else b""

            # Build CFG hash
            cfg_structure = []
            for block in func.blocks:
                # Encode block: (num_instructions, num_successors)
                try:
                    n_insns = len(list(block.capstone.insns))
                except Exception:
                    n_insns = 0
                n_succs = len(list(cfg.graph.successors(block)))
                cfg_structure.append((n_insns, n_succs))

            cfg_hash = hashlib.md5(str(sorted(cfg_structure)).encode()).hexdigest()

            # Count calls
            called = []
            for block in func.blocks:
                try:
                    for insn in block.capstone.insns:
                        if insn.mnemonic == 'call':
                            called.append(insn.op_str)
                except Exception:
                    continue

            # Get constants
            constants = []
            for block in func.blocks:
                try:
                    for insn in block.capstone.insns:
                        # Look for immediate values
                        for op in insn.operands:
                            if hasattr(op, 'imm') and abs(op.imm) > 0x100:
                                constants.append(op.imm)
                except Exception:
                    continue

            return FunctionSignature(
                name=func.name,
                address=func.addr,
                size=func.size,
                hash_bytes=hashlib.md5(func_bytes).hexdigest() if func_bytes else "",
                hash_cfg=cfg_hash,
                num_blocks=len(list(func.blocks)),
                num_calls=len(called),
                num_strings=0,  # TODO: count string refs
                called_functions=called[:20],
                constants=constants[:20],
            )

        except Exception as e:
            logger.debug(f"Failed to create signature for {func.name}: {e}")
            return None

    def _hash_bytes(self, binary: Binary, addr: int, size: int) -> str:
        """Hash function bytes."""
        try:
            data = binary.elf.read(addr, min(size, 0x10000))
            return hashlib.md5(data).hexdigest()
        except Exception:
            return ""

    def _match_functions(self) -> None:
        """Match functions between binaries."""
        self.matches = []
        matched1 = set()
        matched2 = set()

        # Phase 1: Exact name matches
        for name, sig1 in self.signatures1.items():
            if name in self.signatures2:
                sig2 = self.signatures2[name]
                similarity = self._compute_similarity(sig1, sig2)
                self.matches.append(FunctionMatch(
                    func1=sig1,
                    func2=sig2,
                    similarity=similarity,
                    match_type="name",
                    differences=self._compute_differences(sig1, sig2),
                ))
                matched1.add(name)
                matched2.add(name)

        # Phase 2: Exact byte hash matches
        hash_to_func2 = {sig.hash_bytes: sig for sig in self.signatures2.values()
                        if sig.hash_bytes and sig.name not in matched2}

        for name, sig1 in self.signatures1.items():
            if name in matched1:
                continue
            if sig1.hash_bytes and sig1.hash_bytes in hash_to_func2:
                sig2 = hash_to_func2[sig1.hash_bytes]
                self.matches.append(FunctionMatch(
                    func1=sig1,
                    func2=sig2,
                    similarity=1.0,
                    match_type="exact",
                ))
                matched1.add(name)
                matched2.add(sig2.name)

        # Phase 3: CFG structure matches
        cfg_to_func2 = defaultdict(list)
        for sig in self.signatures2.values():
            if sig.hash_cfg and sig.name not in matched2:
                cfg_to_func2[sig.hash_cfg].append(sig)

        for name, sig1 in self.signatures1.items():
            if name in matched1:
                continue
            if sig1.hash_cfg and sig1.hash_cfg in cfg_to_func2:
                candidates = cfg_to_func2[sig1.hash_cfg]
                if len(candidates) == 1:
                    sig2 = candidates[0]
                    similarity = self._compute_similarity(sig1, sig2)
                    if similarity > 0.7:
                        self.matches.append(FunctionMatch(
                            func1=sig1,
                            func2=sig2,
                            similarity=similarity,
                            match_type="cfg",
                            differences=self._compute_differences(sig1, sig2),
                        ))
                        matched1.add(name)
                        matched2.add(sig2.name)

        # Phase 4: Heuristic matching (similar size, calls, constants)
        unmatched2 = [sig for name, sig in self.signatures2.items()
                     if name not in matched2]

        for name, sig1 in self.signatures1.items():
            if name in matched1:
                continue

            best_match = None
            best_similarity = 0.6  # Minimum threshold

            for sig2 in unmatched2:
                similarity = self._compute_similarity(sig1, sig2)
                if similarity > best_similarity:
                    best_similarity = similarity
                    best_match = sig2

            if best_match:
                self.matches.append(FunctionMatch(
                    func1=sig1,
                    func2=best_match,
                    similarity=best_similarity,
                    match_type="heuristic",
                    differences=self._compute_differences(sig1, best_match),
                ))
                matched1.add(name)
                matched2.add(best_match.name)
                unmatched2.remove(best_match)

    def _compute_similarity(self, sig1: FunctionSignature, sig2: FunctionSignature) -> float:
        """Compute similarity score between two signatures."""
        if sig1.hash_bytes and sig1.hash_bytes == sig2.hash_bytes:
            return 1.0

        score = 0.0
        factors = 0

        # Size similarity
        if sig1.size > 0 and sig2.size > 0:
            size_ratio = min(sig1.size, sig2.size) / max(sig1.size, sig2.size)
            score += size_ratio * 0.2
            factors += 0.2

        # Block count similarity
        if sig1.num_blocks > 0 and sig2.num_blocks > 0:
            block_ratio = min(sig1.num_blocks, sig2.num_blocks) / max(sig1.num_blocks, sig2.num_blocks)
            score += block_ratio * 0.2
            factors += 0.2

        # CFG hash match
        if sig1.hash_cfg and sig1.hash_cfg == sig2.hash_cfg:
            score += 0.3
        factors += 0.3

        # Call similarity
        if sig1.called_functions and sig2.called_functions:
            common_calls = set(sig1.called_functions) & set(sig2.called_functions)
            all_calls = set(sig1.called_functions) | set(sig2.called_functions)
            if all_calls:
                call_sim = len(common_calls) / len(all_calls)
                score += call_sim * 0.2
        factors += 0.2

        # Constant similarity
        if sig1.constants and sig2.constants:
            common_const = set(sig1.constants) & set(sig2.constants)
            all_const = set(sig1.constants) | set(sig2.constants)
            if all_const:
                const_sim = len(common_const) / len(all_const)
                score += const_sim * 0.1
        factors += 0.1

        return score / factors if factors > 0 else 0.0

    def _compute_differences(self, sig1: FunctionSignature, sig2: FunctionSignature) -> List[Dict[str, Any]]:
        """Compute detailed differences between matched functions."""
        diffs = []

        if sig1.size != sig2.size:
            diffs.append({
                "type": "size",
                "old": sig1.size,
                "new": sig2.size,
                "change": sig2.size - sig1.size,
            })

        if sig1.num_blocks != sig2.num_blocks:
            diffs.append({
                "type": "blocks",
                "old": sig1.num_blocks,
                "new": sig2.num_blocks,
            })

        # New calls
        old_calls = set(sig1.called_functions)
        new_calls = set(sig2.called_functions)

        added_calls = new_calls - old_calls
        removed_calls = old_calls - new_calls

        if added_calls:
            diffs.append({
                "type": "added_calls",
                "functions": list(added_calls),
            })

        if removed_calls:
            diffs.append({
                "type": "removed_calls",
                "functions": list(removed_calls),
            })

        return diffs

    def _identify_patches(self) -> None:
        """Identify security-relevant patches."""
        self.patches = []

        # Security-relevant function patterns
        security_functions = {
            'strcpy': 'strncpy',  # Buffer overflow fix
            'sprintf': 'snprintf',
            'gets': 'fgets',
            'strcat': 'strncat',
        }

        security_calls = {'malloc', 'free', 'memcpy', 'memmove', 'strlen', 'strcmp'}

        for match in self.matches:
            if match.similarity < 1.0:
                # Check for security-relevant changes
                is_security = False
                description = []

                for diff in match.differences:
                    if diff["type"] == "added_calls":
                        for call in diff["functions"]:
                            # Check if secure function added
                            for old, new in security_functions.items():
                                if new in call:
                                    is_security = True
                                    description.append(f"Added {new} (safer than {old})")
                            # Check for bounds checking
                            if any(s in call for s in ['check', 'valid', 'bound', 'len']):
                                is_security = True
                                description.append(f"Added bounds check: {call}")

                    if diff["type"] == "removed_calls":
                        for call in diff["functions"]:
                            # Check if dangerous function removed
                            for old, new in security_functions.items():
                                if old in call:
                                    is_security = True
                                    description.append(f"Removed unsafe {old}")

                    if diff["type"] == "size":
                        if diff["change"] > 0:
                            description.append(f"Function grew by {diff['change']} bytes")

                self.patches.append(PatchInfo(
                    function=match.func1.name,
                    old_address=match.func1.address,
                    new_address=match.func2.address,
                    patch_type="modified",
                    size_change=match.func2.size - match.func1.size,
                    description="; ".join(description) if description else "Minor changes",
                    security_relevant=is_security,
                ))

        # Find completely new functions
        matched_names2 = {m.func2.name for m in self.matches}
        for name, sig in self.signatures2.items():
            if name not in matched_names2 and not name.startswith("sub_"):
                self.patches.append(PatchInfo(
                    function=name,
                    old_address=0,
                    new_address=sig.address,
                    patch_type="added",
                    size_change=sig.size,
                    description="New function",
                    security_relevant=any(s in name.lower() for s in
                                        ['check', 'valid', 'secure', 'auth', 'verify']),
                ))

        # Find removed functions
        matched_names1 = {m.func1.name for m in self.matches}
        for name, sig in self.signatures1.items():
            if name not in matched_names1 and not name.startswith("sub_"):
                self.patches.append(PatchInfo(
                    function=name,
                    old_address=sig.address,
                    new_address=0,
                    patch_type="removed",
                    size_change=-sig.size,
                    description="Removed function",
                    security_relevant=False,
                ))

    def get_security_patches(self) -> List[PatchInfo]:
        """Get only security-relevant patches."""
        return [p for p in self.patches if p.security_relevant]

    def recover_symbols(self) -> Dict[int, str]:
        """
        Recover symbols in binary2 from binary1 matches.

        Returns:
            Dictionary mapping addresses in binary2 to recovered names
        """
        recovered = {}

        for match in self.matches:
            if match.similarity > 0.8:
                # High confidence match - can recover symbol
                if match.func1.name and not match.func1.name.startswith("sub_"):
                    if match.func2.name.startswith("sub_"):
                        recovered[match.func2.address] = match.func1.name

        return recovered

    def summary(self) -> str:
        """Get diff summary."""
        lines = [
            "Binary Diff Summary",
            "=" * 40,
            f"Binary 1: {self.binary1.path.name} ({len(self.signatures1)} functions)",
            f"Binary 2: {self.binary2.path.name} ({len(self.signatures2)} functions)",
            "",
            f"Matched Functions: {len(self.matches)}",
            f"Total Patches: {len(self.patches)}",
            f"Security Patches: {len(self.get_security_patches())}",
            "",
        ]

        # Show security patches
        sec_patches = self.get_security_patches()
        if sec_patches:
            lines.append("Security-Relevant Changes:")
            for p in sec_patches[:10]:
                lines.append(f"  [{p.patch_type}] {p.function}: {p.description}")

        return "\n".join(lines)
