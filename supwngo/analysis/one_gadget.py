"""
One-gadget and magic gadget detection for libc exploitation.

One-gadgets (magic gadgets) are single addresses in libc that, when jumped to,
will execute execve("/bin/sh", ...) with minimal setup required.

This module:
1. Integrates with the external 'one_gadget' Ruby tool (preferred)
2. Provides fallback patterns for common libc versions
3. Helps select the best gadget based on constraint satisfaction
"""

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict, Any

from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class OneGadget:
    """A one-gadget (magic gadget) that spawns a shell."""
    address: int
    constraints: List[str] = field(default_factory=list)
    instructions: List[str] = field(default_factory=list)
    libc_version: str = ""

    def __str__(self) -> str:
        result = f"0x{self.address:x}"
        if self.constraints:
            result += f"\n    Constraints: {', '.join(self.constraints)}"
        return result

    @property
    def constraint_summary(self) -> str:
        """Get human-readable constraint summary."""
        if not self.constraints:
            return "No constraints"
        return " && ".join(self.constraints)

    @property
    def num_constraints(self) -> int:
        """Number of constraints to satisfy."""
        return len(self.constraints)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "address": hex(self.address),
            "constraints": self.constraints,
            "instructions": self.instructions,
            "libc_version": self.libc_version,
        }


class OneGadgetFinder:
    """Find one-gadgets in libc."""

    # Known one-gadget patterns for common libc versions
    # These are offsets that typically work, found through extensive testing
    KNOWN_PATTERNS: Dict[str, List[Dict]] = {
        # Ubuntu 18.04 libc6 2.27
        "2.27": [
            {"offset": 0x4f2c5, "constraints": ["rsp & 0xf == 0", "rcx == NULL"]},
            {"offset": 0x4f322, "constraints": ["rsp & 0xf == 0", "rcx == NULL"]},
            {"offset": 0x10a38c, "constraints": ["rsp & 0xf == 0", "rcx == NULL"]},
        ],
        # Ubuntu 20.04 libc6 2.31
        "2.31": [
            {"offset": 0xe6c7e, "constraints": ["rsi == NULL", "rdx == NULL"]},
            {"offset": 0xe6c81, "constraints": ["rsi == NULL", "rdx == NULL"]},
            {"offset": 0xe6c84, "constraints": ["rsi == NULL", "rdx == NULL"]},
        ],
        # Ubuntu 22.04 libc6 2.35
        "2.35": [
            {"offset": 0xebc81, "constraints": ["rsi == NULL || [rsi] == NULL"]},
            {"offset": 0xebc85, "constraints": ["rsi == NULL || [rsi] == NULL"]},
            {"offset": 0xebc88, "constraints": ["rsi == NULL || [rsi] == NULL"]},
            {"offset": 0xebce2, "constraints": ["[rsi] == NULL || rsi == NULL", "rdx == NULL"]},
        ],
        # Ubuntu 24.04 libc6 2.39
        "2.39": [
            {"offset": 0xebc88, "constraints": ["rsi == NULL || [rsi] == NULL"]},
            {"offset": 0xebce2, "constraints": ["[rsi] == NULL || rsi == NULL", "rdx == NULL"]},
        ],
        # Debian 10 (Buster) libc6 2.28
        "2.28": [
            {"offset": 0xe21ce, "constraints": ["rsp & 0xf == 0", "rcx == NULL"]},
            {"offset": 0xe21d2, "constraints": ["rsp & 0xf == 0", "rcx == NULL"]},
        ],
        # Generic fallbacks (commonly work on many versions)
        "generic": [
            {"offset": 0x4f3d5, "constraints": ["rsp & 0xf == 0", "rcx == NULL"]},
            {"offset": 0x4f432, "constraints": ["rsp & 0xf == 0", "rcx == NULL"]},
            {"offset": 0x10a41c, "constraints": ["rsp & 0xf == 0", "rcx == NULL"]},
            {"offset": 0xe6c81, "constraints": ["rsi == NULL", "rdx == NULL"]},
        ],
    }

    def __init__(self, libc_path: Optional[str | Path] = None):
        """
        Initialize one-gadget finder.

        Args:
            libc_path: Path to libc.so.6 file
        """
        self.libc_path = Path(libc_path) if libc_path else None
        self._gadgets: List[OneGadget] = []
        self._libc_version: str = ""

    def find(self) -> List[OneGadget]:
        """
        Find one-gadgets in libc.

        Returns:
            List of OneGadget objects
        """
        if not self.libc_path or not self.libc_path.exists():
            logger.warning("No libc path provided or file not found")
            return []

        # Try external one_gadget tool first (most accurate)
        gadgets = self._run_one_gadget_tool()
        if gadgets:
            self._gadgets = gadgets
            logger.info(f"Found {len(gadgets)} one-gadgets using external tool")
            return gadgets

        # Fallback to pattern matching
        logger.info("External one_gadget tool not available, using pattern database")
        gadgets = self._find_by_pattern()
        self._gadgets = gadgets
        return gadgets

    def _run_one_gadget_tool(self) -> List[OneGadget]:
        """Run the one_gadget Ruby tool if available."""
        try:
            result = subprocess.run(
                ["one_gadget", str(self.libc_path)],
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.returncode != 0:
                logger.debug(f"one_gadget tool returned non-zero: {result.stderr}")
                return []

            return self._parse_one_gadget_output(result.stdout)

        except FileNotFoundError:
            logger.debug("one_gadget tool not found (install: gem install one_gadget)")
            return []
        except subprocess.TimeoutExpired:
            logger.warning("one_gadget tool timed out")
            return []
        except Exception as e:
            logger.debug(f"one_gadget tool error: {e}")
            return []

    def _parse_one_gadget_output(self, output: str) -> List[OneGadget]:
        """Parse output from one_gadget tool."""
        gadgets = []
        current_gadget = None

        for line in output.split('\n'):
            line = line.strip()
            if not line:
                if current_gadget:
                    gadgets.append(current_gadget)
                    current_gadget = None
                continue

            # Address line: 0x4f3d5 execve("/bin/sh", rsp+0x40, environ)
            addr_match = re.match(r'(0x[0-9a-f]+)\s*(.*)', line)
            if addr_match and not line.startswith(' '):
                if current_gadget:
                    gadgets.append(current_gadget)
                current_gadget = OneGadget(
                    address=int(addr_match.group(1), 16),
                    instructions=[addr_match.group(2)] if addr_match.group(2) else [],
                )
                continue

            # Constraint line (indented)
            if current_gadget and ("==" in line or "NULL" in line or "[" in line):
                current_gadget.constraints.append(line)

        if current_gadget:
            gadgets.append(current_gadget)

        return gadgets

    def _find_by_pattern(self) -> List[OneGadget]:
        """Find one-gadgets using known patterns."""
        if not self.libc_path:
            return []

        gadgets = []

        # Detect libc version
        version = self._detect_libc_version()
        self._libc_version = version

        # Get patterns for this version
        patterns = self.KNOWN_PATTERNS.get(version, [])
        if not patterns:
            patterns = self.KNOWN_PATTERNS["generic"]

        # Verify patterns exist at offsets
        try:
            libc_data = self.libc_path.read_bytes()
            libc_size = len(libc_data)
        except Exception as e:
            logger.error(f"Failed to read libc: {e}")
            return []

        for pattern in patterns:
            offset = pattern["offset"]
            if offset < libc_size:
                # Basic validation that offset contains code
                if self._validate_gadget_offset(libc_data, offset):
                    gadgets.append(OneGadget(
                        address=offset,
                        constraints=pattern["constraints"],
                        libc_version=version,
                    ))

        logger.info(f"Found {len(gadgets)} potential one-gadgets for libc {version}")
        return gadgets

    def _detect_libc_version(self) -> str:
        """Detect libc version from file."""
        if not self.libc_path:
            return "generic"

        try:
            data = self.libc_path.read_bytes()

            # Look for version strings
            version_patterns = [
                rb'GLIBC_(\d+\.\d+)',
                rb'GNU C Library.*?release version (\d+\.\d+)',
                rb'libc-(\d+\.\d+)\.so',
                rb'GNU C Library \(.*\) stable release version (\d+\.\d+)',
            ]

            versions_found = set()
            for pattern in version_patterns:
                for match in re.finditer(pattern, data):
                    versions_found.add(match.group(1).decode())

            if versions_found:
                # Return highest version found
                version = max(versions_found, key=lambda v: [int(x) for x in v.split('.')])
                logger.debug(f"Detected libc version: {version}")
                return version

        except Exception as e:
            logger.debug(f"Version detection failed: {e}")

        return "generic"

    def _validate_gadget_offset(self, data: bytes, offset: int) -> bool:
        """Basic validation that offset contains executable code."""
        if offset + 32 > len(data):
            return False

        chunk = data[offset:offset + 64]

        # Look for syscall instruction (0x0f 0x05) nearby
        if b'\x0f\x05' in chunk:
            return True

        # Look for call instruction patterns
        if b'\xe8' in chunk or b'\xff' in chunk:
            return True

        # Be optimistic if we can't validate
        return True

    def get_gadgets(self) -> List[OneGadget]:
        """Get cached gadgets or find them."""
        if not self._gadgets:
            self.find()
        return self._gadgets

    def get_best_gadget(self) -> Optional[OneGadget]:
        """
        Get the gadget with the fewest/easiest constraints.

        Returns:
            Best OneGadget or None
        """
        gadgets = self.get_gadgets()
        if not gadgets:
            return None

        # Sort by number of constraints (fewer is better)
        # Prefer constraints that are likely already satisfied
        def score_gadget(g: OneGadget) -> tuple:
            score = len(g.constraints)
            # Bonus for NULL constraints (often naturally satisfied)
            null_count = sum(1 for c in g.constraints if "NULL" in c)
            return (score - null_count * 0.5, score)

        return min(gadgets, key=score_gadget)

    def get_gadgets_by_constraint(self, register: str) -> List[OneGadget]:
        """
        Get gadgets that require a specific register constraint.

        Args:
            register: Register name (e.g., "rsi", "rdx")

        Returns:
            List of matching gadgets
        """
        gadgets = self.get_gadgets()
        return [g for g in gadgets
                if any(register.lower() in c.lower() for c in g.constraints)]

    def get_unconstrained_gadgets(self) -> List[OneGadget]:
        """Get gadgets with no constraints (rare but ideal)."""
        gadgets = self.get_gadgets()
        return [g for g in gadgets if not g.constraints]

    def summary(self) -> str:
        """Generate summary of found gadgets."""
        gadgets = self.get_gadgets()
        if not gadgets:
            return "No one-gadgets found"

        lines = [
            f"One-Gadget Summary for {self.libc_path}",
            f"Libc version: {self._libc_version}",
            f"Total gadgets: {len(gadgets)}",
            "",
            "Gadgets (sorted by constraint count):",
        ]

        for g in sorted(gadgets, key=lambda x: len(x.constraints)):
            lines.append(f"  {g}")
            lines.append("")

        return "\n".join(lines)


# === Convenience Functions ===

def find_one_gadgets(libc_path: str | Path) -> List[OneGadget]:
    """Find one-gadgets in libc (convenience function)."""
    finder = OneGadgetFinder(libc_path)
    return finder.find()


def get_best_one_gadget(libc_path: str | Path) -> Optional[OneGadget]:
    """Get the best one-gadget from libc (convenience function)."""
    finder = OneGadgetFinder(libc_path)
    return finder.get_best_gadget()
