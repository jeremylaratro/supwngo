"""
Exploitation context management.

Tracks architecture, protections, libc version, and other context needed
for exploit generation.
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from supwngo.core.binary import Binary, Protections
from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


class ExploitGoal(Enum):
    """Target goal for exploitation."""
    SHELL = auto()          # Get interactive shell
    READ_FLAG = auto()      # Read flag file
    ARBITRARY_READ = auto() # Achieve arbitrary read
    ARBITRARY_WRITE = auto() # Achieve arbitrary write
    CODE_EXEC = auto()      # Execute arbitrary code
    ROP_CHAIN = auto()      # Build ROP chain


class ExploitType(Enum):
    """Type of exploitation technique."""
    STACK_BOF = auto()
    HEAP_EXPLOIT = auto()
    FORMAT_STRING = auto()
    ROP = auto()
    SROP = auto()
    RET2LIBC = auto()
    RET2SYSCALL = auto()
    RET2CSU = auto()
    RET2DLRESOLVE = auto()
    SHELLCODE = auto()
    ONE_GADGET = auto()


@dataclass
class LibcInfo:
    """Information about target libc."""
    path: Optional[Path] = None
    version: str = ""
    id: str = ""  # libc database ID

    # Key offsets
    system_offset: int = 0
    binsh_offset: int = 0
    execve_offset: int = 0

    # Hook addresses (for overwrites)
    malloc_hook: int = 0
    free_hook: int = 0

    # One gadgets
    one_gadgets: List[int] = field(default_factory=list)

    # Base address (runtime)
    base: int = 0

    def __post_init__(self):
        if self.path:
            self._analyze_libc()

    def _analyze_libc(self) -> None:
        """Analyze libc to extract offsets."""
        if not self.path or not self.path.exists():
            return

        try:
            from pwn import ELF, context
            with context.local(log_level='error'):
                libc = ELF(str(self.path))

            # Get key offsets
            self.system_offset = libc.symbols.get("system", 0)
            self.execve_offset = libc.symbols.get("execve", 0)

            # Find /bin/sh string
            binsh_results = list(libc.search(b"/bin/sh\x00"))
            if binsh_results:
                self.binsh_offset = binsh_results[0]

            # Get hooks
            self.malloc_hook = libc.symbols.get("__malloc_hook", 0)
            self.free_hook = libc.symbols.get("__free_hook", 0)

            logger.debug(f"Analyzed libc: system=0x{self.system_offset:x}")

        except Exception as e:
            logger.warning(f"Failed to analyze libc: {e}")

    def find_one_gadgets(self) -> List[int]:
        """Find one-gadget RCE gadgets in libc."""
        if not self.path or not self.path.exists():
            return []

        try:
            import subprocess
            result = subprocess.run(
                ["one_gadget", str(self.path)],
                capture_output=True,
                text=True,
                timeout=60,
            )

            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    if line.startswith("0x"):
                        addr = int(line.split()[0], 16)
                        self.one_gadgets.append(addr)

            logger.debug(f"Found {len(self.one_gadgets)} one-gadgets")
            return self.one_gadgets

        except (subprocess.SubprocessError, FileNotFoundError):
            logger.debug("one_gadget tool not available")
            return []

    def resolve(self, offset: int) -> int:
        """Resolve offset to runtime address."""
        return self.base + offset


@dataclass
class StackInfo:
    """Information about stack layout at vulnerability."""
    buffer_address: int = 0
    buffer_size: int = 0
    canary_offset: int = 0
    saved_rbp_offset: int = 0
    return_address_offset: int = 0
    controllable_bytes: int = 0

    # Canary value (if leaked)
    canary_value: Optional[int] = None

    # Saved RBP value (if leaked)
    saved_rbp: Optional[int] = None


@dataclass
class HeapInfo:
    """Information about heap state."""
    libc_version: str = ""
    has_tcache: bool = False
    has_safe_linking: bool = False  # glibc >= 2.32

    # Chunk tracking
    allocations: List[Tuple[int, int]] = field(default_factory=list)  # (addr, size)
    freed_chunks: List[int] = field(default_factory=list)

    # Exploitation info
    target_address: int = 0
    write_primitive: bool = False


@dataclass
class ExploitContext:
    """
    Complete exploitation context tracking all information needed
    for exploit generation.
    """

    # Target binary
    binary: Optional[Binary] = None

    # Target process info
    target_host: str = "localhost"
    target_port: int = 0
    is_remote: bool = False

    # Architecture context
    arch: str = "amd64"
    bits: int = 64
    endian: str = "little"

    # Protection status
    protections: Protections = field(default_factory=Protections)

    # Libc information
    libc: LibcInfo = field(default_factory=LibcInfo)

    # Stack information
    stack: StackInfo = field(default_factory=StackInfo)

    # Heap information
    heap: HeapInfo = field(default_factory=HeapInfo)

    # Exploitation parameters
    goal: ExploitGoal = ExploitGoal.SHELL
    exploit_type: Optional[ExploitType] = None

    # Bad characters to avoid
    bad_chars: List[int] = field(default_factory=lambda: [0x00])

    # Leaked addresses
    leaks: Dict[str, int] = field(default_factory=dict)

    # Generated payload
    payload: bytes = b""

    @classmethod
    def from_binary(cls, binary: Binary) -> "ExploitContext":
        """
        Create context from analyzed binary.

        Args:
            binary: Analyzed Binary instance

        Returns:
            ExploitContext with binary info populated
        """
        return cls(
            binary=binary,
            arch=binary.arch,
            bits=binary.bits,
            endian=binary.endian,
            protections=binary.protections,
        )

    def set_remote(self, host: str, port: int) -> None:
        """Configure for remote exploitation."""
        self.target_host = host
        self.target_port = port
        self.is_remote = True

    def set_libc(self, libc_path: str) -> None:
        """Set target libc."""
        self.libc = LibcInfo(path=Path(libc_path))

    def add_leak(self, name: str, address: int) -> None:
        """Record a leaked address."""
        self.leaks[name] = address
        logger.debug(f"Leak recorded: {name} = 0x{address:x}")

        # Auto-detect libc base from libc leaks
        if name.startswith("libc_") or name == "puts" or name == "printf":
            self._try_detect_libc_base(name, address)

    def _try_detect_libc_base(self, symbol: str, address: int) -> None:
        """Try to calculate libc base from leak."""
        if self.libc.path:
            try:
                from pwn import ELF, context
                with context.local(log_level='error'):
                    libc = ELF(str(self.libc.path))

                # Get symbol offset
                symbol_name = symbol.replace("libc_", "")
                if symbol_name in libc.symbols:
                    offset = libc.symbols[symbol_name]
                    self.libc.base = address - offset
                    logger.debug(f"Calculated libc base: 0x{self.libc.base:x}")

            except Exception:
                pass

    def needs_leak(self) -> bool:
        """Check if exploitation requires an information leak."""
        if self.protections.pie and "binary_base" not in self.leaks:
            return True
        if self.protections.aslr and self.libc.path and self.libc.base == 0:
            return True
        if self.protections.canary and self.stack.canary_value is None:
            return True
        return False

    def can_use_shellcode(self) -> bool:
        """Check if shellcode execution is possible."""
        return not self.protections.nx

    def requires_rop(self) -> bool:
        """Check if ROP is required."""
        return self.protections.nx

    def select_technique(self) -> ExploitType:
        """
        Select best exploitation technique based on context.

        Returns:
            Recommended ExploitType
        """
        # If NX is disabled, shellcode is simplest
        if not self.protections.nx:
            return ExploitType.SHELLCODE

        # If we have libc, ret2libc is reliable
        if self.libc.path and self.libc.system_offset:
            return ExploitType.RET2LIBC

        # If PIE is disabled, we can use binary gadgets
        if not self.protections.pie:
            # Try ret2csu for argument control
            if self.binary and "__libc_csu_init" in self.binary.symbols:
                return ExploitType.RET2CSU
            # Fall back to general ROP
            return ExploitType.ROP

        # PIE enabled without leaks - need ret2dlresolve
        if self.protections.pie and "binary_base" not in self.leaks:
            return ExploitType.RET2DLRESOLVE

        # Default to ROP
        return ExploitType.ROP

    def get_pwntools_context(self) -> Dict[str, Any]:
        """
        Get pwntools context settings.

        Returns:
            Dict for pwntools context
        """
        return {
            "arch": self.arch,
            "bits": self.bits,
            "endian": self.endian,
            "os": "linux",
        }

    def summary(self) -> str:
        """Get context summary string."""
        lines = [
            f"Target: {self.binary.path.name if self.binary else 'Unknown'}",
            f"Arch: {self.arch} ({self.bits}-bit)",
            f"Remote: {self.target_host}:{self.target_port}" if self.is_remote else "Local",
            "",
            "Protections:",
            str(self.protections),
            "",
            f"Goal: {self.goal.name}",
            f"Technique: {self.exploit_type.name if self.exploit_type else 'Auto'}",
        ]

        if self.leaks:
            lines.append("")
            lines.append("Leaks:")
            for name, addr in self.leaks.items():
                lines.append(f"  {name}: 0x{addr:x}")

        return "\n".join(lines)
