"""
Kernel module (.ko) analysis.

Parses Linux kernel modules to identify:
- ioctl handlers and command codes
- kmalloc allocations and sizes
- copy_from_user/copy_to_user calls
- Potential vulnerabilities (OOB, UAF, etc.)
"""

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class IoctlCommand:
    """Represents an ioctl command handler."""
    code: int
    name: str = ""
    handler_addr: int = 0

    # Parsed command info
    type_char: str = ""  # _IOC type
    nr: int = 0          # Command number
    direction: str = ""  # R, W, RW, or none
    size: int = 0        # Argument size

    def __post_init__(self):
        """Parse ioctl code."""
        # Linux _IOC encoding:
        # bits 0-7: number
        # bits 8-15: type
        # bits 16-29: size
        # bits 30-31: direction
        self.nr = self.code & 0xff
        self.type_char = chr((self.code >> 8) & 0xff)
        self.size = (self.code >> 16) & 0x3fff
        dir_bits = (self.code >> 30) & 0x3
        self.direction = {0: "none", 1: "W", 2: "R", 3: "RW"}.get(dir_bits, "?")

    def __str__(self) -> str:
        return f"ioctl(0x{self.code:08x}) = _IO{self.direction}('{self.type_char}', {self.nr}, {self.size})"


@dataclass
class KmallocCall:
    """Represents a kmalloc/kmem_cache_alloc call."""
    address: int
    size: int
    flags: int = 0
    slab_name: str = ""  # e.g., "kmalloc-256"

    def __post_init__(self):
        """Determine slab cache name."""
        if not self.slab_name:
            self.slab_name = self._size_to_slab(self.size)

    @staticmethod
    def _size_to_slab(size: int) -> str:
        """Convert size to slab cache name."""
        slabs = [8, 16, 32, 64, 96, 128, 192, 256, 512, 1024, 2048, 4096, 8192]
        for s in slabs:
            if size <= s:
                return f"kmalloc-{s}"
        return f"kmalloc-{size}"


@dataclass
class CopyUserCall:
    """Represents a copy_from_user or copy_to_user call."""
    address: int
    direction: str  # "from" or "to"
    size: Optional[int] = None
    size_is_variable: bool = False


@dataclass
class KernelVulnerability:
    """Detected vulnerability in kernel module."""
    type: str  # OOB_READ, OOB_WRITE, UAF, DOUBLE_FREE, NULL_DEREF, etc.
    address: int
    description: str
    severity: str = "HIGH"  # LOW, MEDIUM, HIGH, CRITICAL

    # Related objects
    kmalloc_call: Optional[KmallocCall] = None
    copy_call: Optional[CopyUserCall] = None
    ioctl_cmd: Optional[IoctlCommand] = None


@dataclass
class KernelModule:
    """
    Linux kernel module (.ko) analysis.

    Parses and analyzes kernel modules for vulnerability research.
    """

    path: Path
    name: str = ""

    # Analysis results
    ioctl_handlers: List[IoctlCommand] = field(default_factory=list)
    kmalloc_calls: List[KmallocCall] = field(default_factory=list)
    copy_calls: List[CopyUserCall] = field(default_factory=list)
    vulnerabilities: List[KernelVulnerability] = field(default_factory=list)

    # Module info
    functions: Dict[str, int] = field(default_factory=dict)
    strings: List[Tuple[int, str]] = field(default_factory=list)

    # Raw ELF data
    _elf: Any = field(default=None, repr=False)

    def __post_init__(self):
        if isinstance(self.path, str):
            self.path = Path(self.path)
        if not self.name:
            self.name = self.path.stem

    @classmethod
    def load(cls, path: str) -> "KernelModule":
        """
        Load and analyze a kernel module.

        Args:
            path: Path to .ko file

        Returns:
            Analyzed KernelModule instance
        """
        module = cls(path=Path(path))
        module._load_elf()
        module._find_functions()
        module._find_ioctl_commands()
        module._find_kmalloc_calls()
        module._find_copy_calls()
        module._detect_vulnerabilities()
        return module

    def _load_elf(self) -> None:
        """Load module as ELF."""
        try:
            from pwn import ELF, context
            with context.local(log_level='error'):
                self._elf = ELF(str(self.path))
        except ImportError:
            logger.warning("pwntools not available for ELF parsing")
        except Exception as e:
            logger.error(f"Failed to load module: {e}")

    def _find_functions(self) -> None:
        """Find exported/internal functions."""
        if not self._elf:
            return

        for name, addr in self._elf.symbols.items():
            if addr != 0:
                self.functions[name] = addr

    def _find_ioctl_commands(self) -> None:
        """Find ioctl command codes from disassembly."""
        # Use objdump to find comparison values
        try:
            result = subprocess.run(
                ["objdump", "-d", str(self.path)],
                capture_output=True,
                text=True,
                timeout=60,
            )

            # Look for cmp with ioctl-like values
            # Pattern: cmp $0x40087401, %eax or similar
            ioctl_pattern = re.compile(
                r'cmp\s+\$0x([0-9a-f]{8}),\s*%[er]?[abcd]x',
                re.IGNORECASE
            )

            for line in result.stdout.split('\n'):
                match = ioctl_pattern.search(line)
                if match:
                    code = int(match.group(1), 16)
                    # Validate it looks like an ioctl code
                    if self._is_valid_ioctl(code):
                        cmd = IoctlCommand(code=code)
                        if cmd not in self.ioctl_handlers:
                            self.ioctl_handlers.append(cmd)

        except Exception as e:
            logger.debug(f"objdump analysis failed: {e}")

    def _is_valid_ioctl(self, code: int) -> bool:
        """Check if value looks like a valid ioctl code."""
        # Type should be printable ASCII
        type_char = (code >> 8) & 0xff
        if not (0x20 <= type_char <= 0x7e):
            return False
        # Size should be reasonable
        size = (code >> 16) & 0x3fff
        if size > 0x1000:
            return False
        return True

    def _find_kmalloc_calls(self) -> None:
        """Find kmalloc and related allocation calls."""
        if not self._elf:
            return

        # Check for relocation entries to allocation functions
        alloc_funcs = [
            "kmalloc", "kzalloc", "kmem_cache_alloc",
            "kmem_cache_alloc_trace", "__kmalloc",
        ]

        for func in alloc_funcs:
            if func in self._elf.plt:
                # Found allocation function, analyze callsites
                # This is simplified - full analysis would trace arguments
                self.kmalloc_calls.append(
                    KmallocCall(
                        address=self._elf.plt[func],
                        size=0,  # Would need CFG analysis
                    )
                )

        # Also scan disassembly for immediate size values near calls
        self._scan_kmalloc_sizes()

    def _scan_kmalloc_sizes(self) -> None:
        """Scan for kmalloc size arguments."""
        try:
            result = subprocess.run(
                ["objdump", "-d", str(self.path)],
                capture_output=True,
                text=True,
                timeout=60,
            )

            lines = result.stdout.split('\n')
            for i, line in enumerate(lines):
                # Look for mov $size, %edi (first arg) before call to kmalloc
                if 'kmalloc' in line.lower() or 'kmem_cache' in line.lower():
                    # Check previous lines for size argument
                    for j in range(max(0, i-5), i):
                        size_match = re.search(r'mov\s+\$0x([0-9a-f]+),\s*%[er]?di', lines[j])
                        if size_match:
                            size = int(size_match.group(1), 16)
                            if 0 < size < 0x10000:
                                # Extract address
                                addr_match = re.search(r'^([0-9a-f]+):', line)
                                addr = int(addr_match.group(1), 16) if addr_match else 0
                                self.kmalloc_calls.append(
                                    KmallocCall(address=addr, size=size)
                                )
                                break

        except Exception as e:
            logger.debug(f"kmalloc size scanning failed: {e}")

    def _find_copy_calls(self) -> None:
        """Find copy_from_user and copy_to_user calls."""
        if not self._elf:
            return

        for func_name, direction in [
            ("copy_from_user", "from"),
            ("_copy_from_user", "from"),
            ("copy_to_user", "to"),
            ("_copy_to_user", "to"),
        ]:
            if func_name in self._elf.plt:
                self.copy_calls.append(
                    CopyUserCall(
                        address=self._elf.plt[func_name],
                        direction=direction,
                    )
                )

    def _detect_vulnerabilities(self) -> None:
        """Detect potential vulnerabilities."""
        # Check for size mismatches in ioctl handlers
        for cmd in self.ioctl_handlers:
            if cmd.size > 0:
                # Look for corresponding kmalloc with different size
                for kmalloc in self.kmalloc_calls:
                    if kmalloc.size > 0 and kmalloc.size != cmd.size:
                        # Potential OOB if copy uses ioctl size
                        if cmd.size > kmalloc.size:
                            self.vulnerabilities.append(
                                KernelVulnerability(
                                    type="OOB_WRITE" if "W" in cmd.direction else "OOB_READ",
                                    address=kmalloc.address,
                                    description=(
                                        f"Potential OOB: ioctl copies {cmd.size} bytes "
                                        f"but buffer is {kmalloc.size} bytes"
                                    ),
                                    kmalloc_call=kmalloc,
                                    ioctl_cmd=cmd,
                                )
                            )

    def get_slab_targets(self) -> Dict[str, List[str]]:
        """
        Get useful kernel structures for each slab size.

        Returns:
            Dict mapping slab name to list of target structures
        """
        # Common targets per slab (from ptr-yudai's list)
        targets = {
            "kmalloc-32": [
                "seq_operations",
            ],
            "kmalloc-64": [
                "subprocess_info",
            ],
            "kmalloc-96": [
                "msg_msg (header)",
            ],
            "kmalloc-128": [
                "user_key_payload",
            ],
            "kmalloc-192": [
                "sk_buff (header)",
            ],
            "kmalloc-256": [
                "struct file",
                "timerfd_ctx",
                "sk_filter",
            ],
            "kmalloc-512": [
                "pipe_buffer",
            ],
            "kmalloc-1024": [
                "struct file (with large security context)",
            ],
            "kmalloc-4096": [
                "msg_msg (large data)",
            ],
        }

        return targets

    def summary(self) -> str:
        """Get analysis summary."""
        lines = [
            f"Kernel Module: {self.name}",
            f"Path: {self.path}",
            "",
            f"Functions: {len(self.functions)}",
            f"IOCTL commands: {len(self.ioctl_handlers)}",
            f"Kmalloc calls: {len(self.kmalloc_calls)}",
            f"Copy user calls: {len(self.copy_calls)}",
            f"Vulnerabilities: {len(self.vulnerabilities)}",
        ]

        if self.ioctl_handlers:
            lines.append("\nIOCTL Commands:")
            for cmd in self.ioctl_handlers:
                lines.append(f"  {cmd}")

        if self.kmalloc_calls:
            lines.append("\nKmalloc Calls:")
            for call in self.kmalloc_calls:
                if call.size > 0:
                    lines.append(f"  0x{call.address:x}: {call.slab_name} ({call.size} bytes)")

        if self.vulnerabilities:
            lines.append("\nPotential Vulnerabilities:")
            for vuln in self.vulnerabilities:
                lines.append(f"  [{vuln.severity}] {vuln.type}: {vuln.description}")

        return "\n".join(lines)

    def __str__(self) -> str:
        return f"KernelModule({self.name})"
