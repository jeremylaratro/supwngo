"""
Remote target interaction using pwntools tubes.
"""

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

from autopwn.core.binary import Binary
from autopwn.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class ConnectionConfig:
    """Remote connection configuration."""
    host: str = "localhost"
    port: int = 1337
    timeout: int = 30
    ssl: bool = False


class RemoteInteraction:
    """
    Remote target interaction abstraction.

    Wraps pwntools tubes for local/remote/SSH connections.
    """

    def __init__(
        self,
        binary: Binary,
        config: Optional[ConnectionConfig] = None,
    ):
        """
        Initialize remote interaction.

        Args:
            binary: Target binary
            config: Connection configuration
        """
        self.binary = binary
        self.config = config or ConnectionConfig()
        self._tube = None
        self._is_remote = False

    def connect_local(self, **kwargs) -> Any:
        """
        Connect to local process.

        Args:
            **kwargs: Additional process arguments

        Returns:
            pwntools tube
        """
        try:
            from pwn import process, context

            context.binary = self.binary._elf

            self._tube = process(str(self.binary.path), **kwargs)
            self._is_remote = False

            logger.info(f"Connected to local process: {self.binary.path}")
            return self._tube

        except ImportError:
            raise RuntimeError("pwntools required for remote interaction")

    def connect_remote(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        ssl: bool = False,
    ) -> Any:
        """
        Connect to remote target.

        Args:
            host: Remote host
            port: Remote port
            ssl: Use SSL

        Returns:
            pwntools tube
        """
        host = host or self.config.host
        port = port or self.config.port
        ssl = ssl or self.config.ssl

        try:
            from pwn import remote

            self._tube = remote(host, port, ssl=ssl)
            self._is_remote = True

            logger.info(f"Connected to {host}:{port}")
            return self._tube

        except ImportError:
            raise RuntimeError("pwntools required for remote interaction")

    def connect_ssh(
        self,
        host: str,
        user: str,
        password: Optional[str] = None,
        keyfile: Optional[str] = None,
    ) -> Any:
        """
        Connect via SSH.

        Args:
            host: SSH host
            user: Username
            password: Password
            keyfile: SSH key file

        Returns:
            pwntools SSH tube
        """
        try:
            from pwn import ssh

            shell = ssh(
                host=host,
                user=user,
                password=password,
                keyfile=keyfile,
            )

            self._tube = shell.process(str(self.binary.path))
            self._is_remote = True

            logger.info(f"Connected via SSH to {user}@{host}")
            return self._tube

        except ImportError:
            raise RuntimeError("pwntools required for SSH")

    def connect_gdb(
        self,
        gdbscript: str = "",
        **kwargs,
    ) -> Any:
        """
        Connect with GDB attached.

        Args:
            gdbscript: GDB commands to run
            **kwargs: Additional arguments

        Returns:
            pwntools tube with GDB
        """
        try:
            from pwn import gdb, context

            context.binary = self.binary._elf

            self._tube = gdb.debug(
                str(self.binary.path),
                gdbscript=gdbscript,
                **kwargs,
            )
            self._is_remote = False

            logger.info("Started process with GDB")
            return self._tube

        except ImportError:
            raise RuntimeError("pwntools required for GDB")

    @property
    def tube(self) -> Any:
        """Get current tube."""
        return self._tube

    def send(self, data: bytes) -> None:
        """Send data."""
        if self._tube:
            self._tube.send(data)

    def sendline(self, data: bytes) -> None:
        """Send data with newline."""
        if self._tube:
            self._tube.sendline(data)

    def recv(self, numb: int = 4096, timeout: int = None) -> bytes:
        """Receive data."""
        if self._tube:
            return self._tube.recv(numb, timeout=timeout or self.config.timeout)
        return b""

    def recvline(self, timeout: int = None) -> bytes:
        """Receive line."""
        if self._tube:
            return self._tube.recvline(timeout=timeout or self.config.timeout)
        return b""

    def recvuntil(self, delim: bytes, timeout: int = None) -> bytes:
        """Receive until delimiter."""
        if self._tube:
            return self._tube.recvuntil(delim, timeout=timeout or self.config.timeout)
        return b""

    def recvall(self, timeout: int = None) -> bytes:
        """Receive all data."""
        if self._tube:
            return self._tube.recvall(timeout=timeout or self.config.timeout)
        return b""

    def sendafter(self, delim: bytes, data: bytes) -> None:
        """Receive until delimiter then send."""
        if self._tube:
            self._tube.sendafter(delim, data)

    def sendlineafter(self, delim: bytes, data: bytes) -> None:
        """Receive until delimiter then sendline."""
        if self._tube:
            self._tube.sendlineafter(delim, data)

    def interactive(self) -> None:
        """Enter interactive mode."""
        if self._tube:
            self._tube.interactive()

    def close(self) -> None:
        """Close connection."""
        if self._tube:
            self._tube.close()
            self._tube = None

    def stage_payload(
        self,
        payload: bytes,
        method: str = "send",
        delimiter: bytes = b"",
    ) -> bool:
        """
        Stage exploit payload.

        Args:
            payload: Payload bytes
            method: send, sendline, sendafter
            delimiter: Delimiter for sendafter

        Returns:
            True if successful
        """
        try:
            if method == "send":
                self.send(payload)
            elif method == "sendline":
                self.sendline(payload)
            elif method == "sendafter":
                self.sendafter(delimiter, payload)
            elif method == "sendlineafter":
                self.sendlineafter(delimiter, payload)
            else:
                logger.error(f"Unknown method: {method}")
                return False

            return True

        except Exception as e:
            logger.error(f"Failed to stage payload: {e}")
            return False

    def get_shell(self) -> bool:
        """
        Check if we got a shell.

        Returns:
            True if shell obtained
        """
        if not self._tube:
            return False

        try:
            # Send command and check response
            self.sendline(b"id")
            response = self.recvline(timeout=2)

            if b"uid=" in response:
                logger.info("Shell obtained!")
                return True

            # Try echo test
            self.sendline(b"echo PWNED")
            response = self.recvline(timeout=2)

            if b"PWNED" in response:
                logger.info("Shell obtained!")
                return True

        except Exception:
            pass

        return False

    def leak_via_puts(
        self,
        got_entry: int,
        return_addr: int,
    ) -> Optional[int]:
        """
        Leak address using puts.

        Args:
            got_entry: GOT entry to leak
            return_addr: Address to return to after leak

        Returns:
            Leaked address or None
        """
        try:
            from pwn import ROP, p64, u64, context

            context.binary = self.binary._elf

            rop = ROP(self.binary._elf)
            rop.puts(got_entry)
            rop.raw(return_addr)

            # This is template - actual implementation depends on vuln
            # self.sendline(padding + rop.chain())

            # Parse response
            leaked = self.recvline().strip()
            if leaked:
                return u64(leaked.ljust(8, b"\x00"))

        except Exception as e:
            logger.error(f"Leak failed: {e}")

        return None

    def summary(self) -> str:
        """Get interaction summary."""
        status = "Connected" if self._tube else "Not connected"
        target = f"{self.config.host}:{self.config.port}" if self._is_remote else "local"

        return f"""
Remote Interaction
==================
Status: {status}
Target: {target}
Binary: {self.binary.path.name if self.binary else 'None'}
"""
