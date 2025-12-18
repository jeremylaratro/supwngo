"""
Windows PE exploitation support for supwngo.

Provides Windows-specific binary analysis and exploitation:
- PE parsing and analysis
- SEH exploitation techniques
- Windows ROP chain building
- CFG/ACG bypass
- Windows-specific protections

Example:
    from supwngo.windows import PEBinary, SEHExploit, WindowsROP

    # Load PE binary
    pe = PEBinary("vulnerable.exe")
    print(pe.protections)  # SafeSEH, ASLR, DEP, CFG status

    # Build SEH exploit
    seh = SEHExploit(pe)
    chain = seh.build_seh_chain(shellcode_addr)

    # Windows ROP
    rop = WindowsROP(pe)
    chain = rop.virtualprotect_chain(shellcode_addr, size)
"""

from supwngo.windows.pe_binary import (
    PEBinary,
    PEProtections,
    PESection,
    ImportedFunction,
    ExportedFunction,
)
from supwngo.windows.seh_exploit import (
    SEHExploit,
    SEHChain,
    SEHRecord,
    SafeSEHBypass,
    find_seh_gadgets,
)
from supwngo.windows.rop_windows import (
    WindowsROP,
    WindowsGadget,
    VirtualProtectChain,
    VirtualAllocChain,
    NtProtectChain,
    build_windows_rop,
)
from supwngo.windows.cfg_bypass import (
    CFGAnalyzer,
    CFGBypass,
    CFGInfo,
    ValidCFGTarget,
    analyze_cfg,
)

__all__ = [
    # PE Binary
    "PEBinary",
    "PEProtections",
    "PESection",
    "ImportedFunction",
    "ExportedFunction",
    # SEH Exploitation
    "SEHExploit",
    "SEHChain",
    "SEHRecord",
    "SafeSEHBypass",
    "find_seh_gadgets",
    # Windows ROP
    "WindowsROP",
    "WindowsGadget",
    "VirtualProtectChain",
    "VirtualAllocChain",
    "NtProtectChain",
    "build_windows_rop",
    # CFG Bypass
    "CFGAnalyzer",
    "CFGBypass",
    "CFGInfo",
    "ValidCFGTarget",
    "analyze_cfg",
]
