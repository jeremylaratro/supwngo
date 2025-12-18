"""
Linux kernel exploitation module.

Provides tools for:
- Kernel module (.ko) analysis
- KASLR bypass and kernel symbol resolution
- Slab allocator manipulation
- Kernel ROP chain building
- Exploit template generation
- ret2usr (return to userspace) exploitation
- modprobe_path / core_pattern overwrite
- Modern kernel exploitation (msg_msg, pipe_buffer, cross-cache)
"""

from supwngo.kernel.module import KernelModule
from supwngo.kernel.symbols import KernelSymbols
from supwngo.kernel.slab import SlabAllocator, SlabSpray
from supwngo.kernel.krop import KernelROPBuilder, KernelROPChain, KernelGadget
from supwngo.kernel.templates import KernelExploitTemplate
from supwngo.kernel.ret2usr import Ret2usr, Ret2usrPayload
from supwngo.kernel.modprobe import ModprobeExploit, ModprobePayload, CorePatternExploit

# Modern kernel exploitation techniques
from supwngo.kernel.msg_msg import (
    MsgMsgExploit,
    MsgMsgSpray,
    MsgMsgLeak,
    MsgMsgWrite,
    MsgMsgHeader,
)
from supwngo.kernel.pipe_buffer import (
    PipeBufferExploit,
    DirtyPipeExploit,
    DirtyPipeCheck,
    PipeSpray,
    PipeBuffer,
)
from supwngo.kernel.cross_cache import (
    CrossCacheExploit,
    CrossCacheAnalyzer,
    CrossCacheSpray,
    CommonVictimObjects,
    SlubCache,
)

__all__ = [
    # Module analysis
    "KernelModule",
    # Symbol resolution
    "KernelSymbols",
    # Slab exploitation
    "SlabAllocator",
    "SlabSpray",
    # Kernel ROP
    "KernelROPBuilder",
    "KernelROPChain",
    "KernelGadget",
    # Exploit templates
    "KernelExploitTemplate",
    # ret2usr
    "Ret2usr",
    "Ret2usrPayload",
    # modprobe/core_pattern
    "ModprobeExploit",
    "ModprobePayload",
    "CorePatternExploit",
    # msg_msg exploitation
    "MsgMsgExploit",
    "MsgMsgSpray",
    "MsgMsgLeak",
    "MsgMsgWrite",
    "MsgMsgHeader",
    # pipe_buffer exploitation
    "PipeBufferExploit",
    "DirtyPipeExploit",
    "DirtyPipeCheck",
    "PipeSpray",
    "PipeBuffer",
    # Cross-cache attacks
    "CrossCacheExploit",
    "CrossCacheAnalyzer",
    "CrossCacheSpray",
    "CommonVictimObjects",
    "SlubCache",
]
