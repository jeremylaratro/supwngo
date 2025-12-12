"""
Common utility functions for AutoPwn.
"""

import struct
import subprocess
import hashlib
from pathlib import Path
from typing import List, Optional, Union, Tuple


def p64(value: int) -> bytes:
    """Pack 64-bit value as little-endian bytes."""
    return struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)


def u64(data: bytes) -> int:
    """Unpack 64-bit little-endian bytes to integer."""
    return struct.unpack("<Q", data.ljust(8, b"\x00")[:8])[0]


def p32(value: int) -> bytes:
    """Pack 32-bit value as little-endian bytes."""
    return struct.pack("<I", value & 0xFFFFFFFF)


def u32(data: bytes) -> int:
    """Unpack 32-bit little-endian bytes to integer."""
    return struct.unpack("<I", data.ljust(4, b"\x00")[:4])[0]


def p16(value: int) -> bytes:
    """Pack 16-bit value as little-endian bytes."""
    return struct.pack("<H", value & 0xFFFF)


def u16(data: bytes) -> int:
    """Unpack 16-bit little-endian bytes to integer."""
    return struct.unpack("<H", data.ljust(2, b"\x00")[:2])[0]


def hexdump(data: bytes, offset: int = 0, width: int = 16) -> str:
    """
    Generate hexdump of binary data.

    Args:
        data: Binary data to dump
        offset: Starting offset for display
        width: Bytes per line

    Returns:
        Formatted hexdump string
    """
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(
            chr(b) if 32 <= b < 127 else "." for b in chunk
        )
        lines.append(f"{offset + i:08x}  {hex_part:<{width * 3}}  |{ascii_part}|")
    return "\n".join(lines)


def cyclic(length: int, alphabet: bytes = None) -> bytes:
    """
    Generate de Bruijn sequence for offset finding.

    Args:
        length: Length of pattern to generate
        alphabet: Alphabet to use (default: lowercase letters)

    Returns:
        Cyclic pattern bytes
    """
    if alphabet is None:
        alphabet = b"abcdefghijklmnopqrstuvwxyz"

    # Simple cyclic pattern generation
    pattern = bytearray()
    for i in range(length):
        c1 = alphabet[(i // (len(alphabet) ** 2)) % len(alphabet)]
        c2 = alphabet[(i // len(alphabet)) % len(alphabet)]
        c3 = alphabet[i % len(alphabet)]
        pattern.append(c1)
        if len(pattern) >= length:
            break
        pattern.append(c2)
        if len(pattern) >= length:
            break
        pattern.append(c3)
        if len(pattern) >= length:
            break
        pattern.append(ord(b"a") + (i % 26))
        if len(pattern) >= length:
            break

    return bytes(pattern[:length])


def cyclic_find(value: Union[int, bytes], length: int = 10000) -> int:
    """
    Find offset of value in cyclic pattern.

    Args:
        value: Value to search for (int or bytes)
        length: Length of pattern to search

    Returns:
        Offset of value, or -1 if not found
    """
    if isinstance(value, int):
        # Convert to bytes (try both endiannesses)
        value_bytes = struct.pack("<I", value & 0xFFFFFFFF)
    else:
        value_bytes = value

    pattern = cyclic(length)
    pos = pattern.find(value_bytes)

    return pos


def align(value: int, alignment: int) -> int:
    """Align value up to alignment boundary."""
    return (value + alignment - 1) & ~(alignment - 1)


def align_down(value: int, alignment: int) -> int:
    """Align value down to alignment boundary."""
    return value & ~(alignment - 1)


def is_printable(data: bytes) -> bool:
    """Check if all bytes are printable ASCII."""
    return all(32 <= b < 127 for b in data)


def contains_bad_chars(data: bytes, bad_chars: List[int]) -> bool:
    """Check if data contains any bad characters."""
    bad_set = set(bad_chars)
    return any(b in bad_set for b in data)


def filter_bad_chars(data: bytes, bad_chars: List[int]) -> bytes:
    """Remove bad characters from data."""
    bad_set = set(bad_chars)
    return bytes(b for b in data if b not in bad_set)


def hash_crash(crash_data: bytes, registers: Optional[dict] = None) -> str:
    """
    Generate unique hash for crash deduplication.

    Args:
        crash_data: Input that caused crash
        registers: Optional register state at crash

    Returns:
        SHA256 hash string
    """
    hasher = hashlib.sha256()
    hasher.update(crash_data)
    if registers:
        for name, value in sorted(registers.items()):
            hasher.update(f"{name}:{value}".encode())
    return hasher.hexdigest()[:16]


def run_command(
    cmd: List[str],
    timeout: Optional[int] = None,
    input_data: Optional[bytes] = None,
    capture_output: bool = True,
) -> Tuple[int, bytes, bytes]:
    """
    Run shell command with optional timeout and input.

    Args:
        cmd: Command and arguments
        timeout: Timeout in seconds
        input_data: Data to send to stdin
        capture_output: Whether to capture stdout/stderr

    Returns:
        Tuple of (return_code, stdout, stderr)
    """
    try:
        result = subprocess.run(
            cmd,
            timeout=timeout,
            input=input_data,
            capture_output=capture_output,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, b"", b"Timeout expired"
    except FileNotFoundError:
        return -1, b"", f"Command not found: {cmd[0]}".encode()


def find_executable(name: str) -> Optional[Path]:
    """
    Find executable in PATH.

    Args:
        name: Executable name

    Returns:
        Path to executable or None
    """
    import shutil
    path = shutil.which(name)
    return Path(path) if path else None


def page_start(address: int, page_size: int = 0x1000) -> int:
    """Get page-aligned start address."""
    return address & ~(page_size - 1)


def page_end(address: int, page_size: int = 0x1000) -> int:
    """Get page-aligned end address."""
    return ((address + page_size - 1) & ~(page_size - 1))


def fit(data: dict, length: int, filler: bytes = b"A") -> bytes:
    """
    Create a buffer with data at specific offsets.

    Args:
        data: Dictionary mapping offset -> data
        length: Total buffer length
        filler: Byte to use for filling

    Returns:
        Constructed buffer
    """
    buf = bytearray(filler * length)
    for offset, value in data.items():
        if isinstance(value, int):
            value = p64(value)
        buf[offset:offset + len(value)] = value
    return bytes(buf)


def flat(*args, word_size: int = 64) -> bytes:
    """
    Flatten values into bytes.

    Args:
        *args: Values to flatten (int, bytes, str)
        word_size: Word size for integer packing (32 or 64)

    Returns:
        Flattened bytes
    """
    result = bytearray()
    pack_func = p64 if word_size == 64 else p32

    for arg in args:
        if isinstance(arg, int):
            result.extend(pack_func(arg))
        elif isinstance(arg, bytes):
            result.extend(arg)
        elif isinstance(arg, str):
            result.extend(arg.encode())
        elif isinstance(arg, (list, tuple)):
            result.extend(flat(*arg, word_size=word_size))
        else:
            raise TypeError(f"Unsupported type: {type(arg)}")

    return bytes(result)
