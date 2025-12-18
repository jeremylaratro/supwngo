"""
macOS Mach-O exploitation support for supwngo.

Provides macOS-specific binary analysis and exploitation:
- Mach-O parsing and analysis
- macOS-specific protections (Hardened Runtime, Library Validation)
- ARM64e PAC support
- dyld exploitation techniques

Example:
    from supwngo.macos import MachOBinary, MacOSProtections

    # Load Mach-O binary
    macho = MachOBinary("vulnerable")
    print(macho.protections)

    # Check for PAC
    if macho.protections.arm64e_pac:
        print("ARM64e PAC enabled")
"""

from supwngo.macos.mach_binary import (
    MachOBinary,
    MacOSProtections,
    MachOSection,
    MachOSegment,
    DylibInfo,
    EntitlementInfo,
)

__all__ = [
    "MachOBinary",
    "MacOSProtections",
    "MachOSection",
    "MachOSegment",
    "DylibInfo",
    "EntitlementInfo",
]
