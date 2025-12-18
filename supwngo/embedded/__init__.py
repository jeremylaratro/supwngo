"""
Embedded systems and IoT exploitation support for supwngo.

Provides firmware analysis and exploitation for:
- ARM32 embedded systems
- MIPS routers and IoT devices
- Firmware extraction and analysis
- RTOS (FreeRTOS, VxWorks) analysis
- Serial console interaction

Example:
    from supwngo.embedded import FirmwareAnalyzer, ARMExploit, MIPSExploit

    # Analyze firmware
    fw = FirmwareAnalyzer("firmware.bin")
    fw.extract()  # Uses binwalk

    # Find ARM binaries
    for binary in fw.find_binaries(arch="arm"):
        arm = ARMExploit(binary)
        vulns = arm.analyze()

    # MIPS exploitation
    mips = MIPSExploit("target_binary")
    rop = mips.build_rop_chain()
"""

from supwngo.embedded.firmware import (
    FirmwareAnalyzer,
    FirmwareInfo,
    ExtractedFile,
    FilesystemInfo,
)
from supwngo.embedded.arm_exploit import (
    ARMExploit,
    ARMBinary,
    ARMProtections,
    ARMGadget,
    build_arm_rop,
)
from supwngo.embedded.mips_exploit import (
    MIPSExploit,
    MIPSBinary,
    MIPSProtections,
    MIPSGadget,
    build_mips_rop,
)

__all__ = [
    # Firmware
    "FirmwareAnalyzer",
    "FirmwareInfo",
    "ExtractedFile",
    "FilesystemInfo",
    # ARM
    "ARMExploit",
    "ARMBinary",
    "ARMProtections",
    "ARMGadget",
    "build_arm_rop",
    # MIPS
    "MIPSExploit",
    "MIPSBinary",
    "MIPSProtections",
    "MIPSGadget",
    "build_mips_rop",
]
