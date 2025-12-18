"""
Decompilation integration module.

Provides integration with decompilers including:
- Ghidra headless decompilation
- RetDec integration
- Output parsing for variables, types, control flow
- Pseudo-code generation
"""

import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from supwngo.core.binary import Binary
from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class DecompiledVariable:
    """Variable extracted from decompilation."""
    name: str
    type_str: str
    offset: Optional[int] = None  # Stack offset if local
    size: int = 0
    is_parameter: bool = False
    is_local: bool = False
    is_global: bool = False


@dataclass
class DecompiledFunction:
    """Decompiled function information."""
    name: str
    address: int
    return_type: str
    parameters: List[DecompiledVariable] = field(default_factory=list)
    locals: List[DecompiledVariable] = field(default_factory=list)
    code: str = ""
    calls: List[str] = field(default_factory=list)
    strings_used: List[str] = field(default_factory=list)
    complexity_hints: Dict[str, Any] = field(default_factory=dict)


class Decompiler:
    """
    Decompiler integration for binary analysis.

    Integrates with Ghidra and RetDec to provide:
    - Human-readable pseudo-code
    - Variable and type information
    - Control flow insights
    """

    def __init__(self, binary: Binary):
        """
        Initialize decompiler.

        Args:
            binary: Binary instance to decompile
        """
        self.binary = binary
        self.decompiled_functions: Dict[str, DecompiledFunction] = {}
        self._ghidra_path = self._find_ghidra()
        self._retdec_path = self._find_retdec()

    def _find_ghidra(self) -> Optional[Path]:
        """Find Ghidra installation."""
        # Check environment variable
        ghidra_home = os.environ.get("GHIDRA_HOME")
        if ghidra_home:
            path = Path(ghidra_home) / "support" / "analyzeHeadless"
            if path.exists():
                return path

        # Check common locations
        common_paths = [
            Path("/opt/ghidra/support/analyzeHeadless"),
            Path("/usr/share/ghidra/support/analyzeHeadless"),
            Path.home() / "ghidra" / "support" / "analyzeHeadless",
            Path.home() / ".local" / "share" / "ghidra" / "support" / "analyzeHeadless",
        ]

        for path in common_paths:
            if path.exists():
                return path

        # Try to find via which
        try:
            result = subprocess.run(["which", "analyzeHeadless"],
                                  capture_output=True, text=True)
            if result.returncode == 0:
                return Path(result.stdout.strip())
        except Exception:
            pass

        return None

    def _find_retdec(self) -> Optional[Path]:
        """Find RetDec installation."""
        # Check environment
        retdec_path = os.environ.get("RETDEC_PATH")
        if retdec_path:
            path = Path(retdec_path) / "bin" / "retdec-decompiler"
            if path.exists():
                return path

        # Check common locations
        common_paths = [
            Path("/usr/bin/retdec-decompiler"),
            Path("/usr/local/bin/retdec-decompiler"),
            Path.home() / ".local" / "bin" / "retdec-decompiler",
        ]

        for path in common_paths:
            if path.exists():
                return path

        # Try which
        try:
            result = subprocess.run(["which", "retdec-decompiler"],
                                  capture_output=True, text=True)
            if result.returncode == 0:
                return Path(result.stdout.strip())
        except Exception:
            pass

        return None

    def decompile(self, func_name: Optional[str] = None,
                  func_addr: Optional[int] = None,
                  use_ghidra: bool = True) -> Optional[DecompiledFunction]:
        """
        Decompile a function.

        Args:
            func_name: Function name to decompile
            func_addr: Function address to decompile
            use_ghidra: Prefer Ghidra over RetDec

        Returns:
            DecompiledFunction or None
        """
        if use_ghidra and self._ghidra_path:
            result = self._decompile_ghidra(func_name, func_addr)
            if result:
                return result

        if self._retdec_path:
            result = self._decompile_retdec(func_name, func_addr)
            if result:
                return result

        # Fallback to angr decompilation
        return self._decompile_angr(func_name, func_addr)

    def _decompile_ghidra(self, func_name: Optional[str],
                          func_addr: Optional[int]) -> Optional[DecompiledFunction]:
        """Decompile using Ghidra headless."""
        if not self._ghidra_path:
            return None

        logger.info("Decompiling with Ghidra...")

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                project_dir = Path(tmpdir) / "project"
                project_dir.mkdir()
                output_file = Path(tmpdir) / "output.json"

                # Create Ghidra script
                script_content = self._create_ghidra_script(func_name, func_addr, output_file)
                script_path = Path(tmpdir) / "decompile.py"
                script_path.write_text(script_content)

                # Run Ghidra headless
                cmd = [
                    str(self._ghidra_path),
                    str(project_dir),
                    "TempProject",
                    "-import", str(self.binary.path),
                    "-postScript", str(script_path),
                    "-deleteProject",
                ]

                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

                if output_file.exists():
                    data = json.loads(output_file.read_text())
                    return self._parse_ghidra_output(data)

        except subprocess.TimeoutExpired:
            logger.warning("Ghidra decompilation timed out")
        except Exception as e:
            logger.warning(f"Ghidra decompilation failed: {e}")

        return None

    def _create_ghidra_script(self, func_name: Optional[str],
                               func_addr: Optional[int],
                               output_path: Path) -> str:
        """Create Ghidra Python script for decompilation."""
        return f'''
# Ghidra decompilation script
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import json

def decompile_function(func):
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)

    result = decomp.decompileFunction(func, 60, ConsoleTaskMonitor())

    if result.decompileCompleted():
        return {{
            "name": func.getName(),
            "address": func.getEntryPoint().getOffset(),
            "code": result.getDecompiledFunction().getC(),
            "return_type": str(func.getReturnType()),
        }}
    return None

output = []

func_name = {repr(func_name) if func_name else 'None'}
func_addr = {hex(func_addr) if func_addr else 'None'}

if func_name:
    func = getGlobalFunctions(func_name)
    if func:
        result = decompile_function(func[0])
        if result:
            output.append(result)
elif func_addr:
    addr = currentProgram.getAddressFactory().getAddress(func_addr)
    func = getFunctionAt(addr)
    if func:
        result = decompile_function(func)
        if result:
            output.append(result)
else:
    # Decompile all functions
    fm = currentProgram.getFunctionManager()
    for func in fm.getFunctions(True):
        result = decompile_function(func)
        if result:
            output.append(result)
            if len(output) >= 100:  # Limit
                break

with open("{output_path}", "w") as f:
    json.dump(output, f)
'''

    def _parse_ghidra_output(self, data: List[Dict]) -> Optional[DecompiledFunction]:
        """Parse Ghidra JSON output."""
        if not data:
            return None

        func_data = data[0]

        # Parse code for variables and calls
        code = func_data.get("code", "")
        variables = self._parse_variables_from_code(code)
        calls = self._parse_calls_from_code(code)
        strings = self._parse_strings_from_code(code)

        return DecompiledFunction(
            name=func_data.get("name", "unknown"),
            address=func_data.get("address", 0),
            return_type=func_data.get("return_type", "void"),
            parameters=[v for v in variables if v.is_parameter],
            locals=[v for v in variables if v.is_local],
            code=code,
            calls=calls,
            strings_used=strings,
        )

    def _decompile_retdec(self, func_name: Optional[str],
                          func_addr: Optional[int]) -> Optional[DecompiledFunction]:
        """Decompile using RetDec."""
        if not self._retdec_path:
            return None

        logger.info("Decompiling with RetDec...")

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                output_c = Path(tmpdir) / "output.c"

                cmd = [
                    str(self._retdec_path),
                    str(self.binary.path),
                    "-o", str(output_c),
                ]

                if func_addr:
                    cmd.extend(["--select-ranges", f"{hex(func_addr)}-{hex(func_addr + 0x1000)}"])

                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

                if output_c.exists():
                    code = output_c.read_text()
                    return self._parse_retdec_output(code, func_name, func_addr)

        except subprocess.TimeoutExpired:
            logger.warning("RetDec decompilation timed out")
        except Exception as e:
            logger.warning(f"RetDec decompilation failed: {e}")

        return None

    def _parse_retdec_output(self, code: str, func_name: Optional[str],
                             func_addr: Optional[int]) -> Optional[DecompiledFunction]:
        """Parse RetDec C output."""
        # Extract specific function if requested
        if func_name:
            pattern = rf'{func_name}\s*\([^)]*\)\s*\{{[^}}]*\}}'
            match = re.search(pattern, code, re.DOTALL)
            if match:
                code = match.group()

        variables = self._parse_variables_from_code(code)
        calls = self._parse_calls_from_code(code)
        strings = self._parse_strings_from_code(code)

        return DecompiledFunction(
            name=func_name or "main",
            address=func_addr or 0,
            return_type="int",
            parameters=[v for v in variables if v.is_parameter],
            locals=[v for v in variables if v.is_local],
            code=code,
            calls=calls,
            strings_used=strings,
        )

    def _decompile_angr(self, func_name: Optional[str],
                        func_addr: Optional[int]) -> Optional[DecompiledFunction]:
        """Fallback decompilation using angr."""
        try:
            import angr
            from angr.analyses.decompiler.structured_codegen import DummyStructuredCodeGenerator

            proj = self.binary.get_angr_project()
            cfg = proj.analyses.CFGFast()

            # Find function
            func = None
            if func_addr:
                func = cfg.kb.functions.get(func_addr)
            elif func_name:
                for f in cfg.kb.functions.values():
                    if f.name == func_name:
                        func = f
                        break

            if not func:
                return None

            # Decompile
            try:
                dec = proj.analyses.Decompiler(func, cfg=cfg)
                if dec.codegen and hasattr(dec.codegen, 'text'):
                    code = dec.codegen.text
                else:
                    code = f"// Decompilation failed for {func.name}"
            except Exception as e:
                code = f"// Decompilation failed: {e}"

            return DecompiledFunction(
                name=func.name,
                address=func.addr,
                return_type="void",
                code=code,
                calls=[c.name for c in func.functions_called() if c.name],
            )

        except Exception as e:
            logger.warning(f"angr decompilation failed: {e}")
            return None

    def _parse_variables_from_code(self, code: str) -> List[DecompiledVariable]:
        """Parse variable declarations from C code."""
        variables = []

        # Pattern for local variable declarations
        # Matches: type name; or type name = value;
        local_pattern = r'^\s*(\w+(?:\s*\*)*)\s+(\w+)(?:\s*=\s*[^;]+)?;'

        # Pattern for parameters
        param_pattern = r'\(([^)]*)\)'

        # Extract parameters from function signature
        param_match = re.search(param_pattern, code)
        if param_match:
            params_str = param_match.group(1)
            for param in params_str.split(','):
                param = param.strip()
                if param and param != 'void':
                    parts = param.rsplit(None, 1)
                    if len(parts) == 2:
                        type_str, name = parts
                        variables.append(DecompiledVariable(
                            name=name.strip('*'),
                            type_str=type_str,
                            is_parameter=True,
                        ))

        # Extract local variables
        for line in code.split('\n'):
            if '=' in line or ';' in line:
                match = re.match(local_pattern, line)
                if match:
                    type_str = match.group(1)
                    name = match.group(2)
                    # Skip if it's a function call
                    if '(' not in line.split('=')[0] if '=' in line else '(' not in line:
                        variables.append(DecompiledVariable(
                            name=name,
                            type_str=type_str,
                            is_local=True,
                        ))

        return variables

    def _parse_calls_from_code(self, code: str) -> List[str]:
        """Parse function calls from C code."""
        calls = []

        # Pattern for function calls
        call_pattern = r'\b(\w+)\s*\('

        for match in re.finditer(call_pattern, code):
            func_name = match.group(1)
            # Skip C keywords
            if func_name not in ('if', 'while', 'for', 'switch', 'return', 'sizeof'):
                if func_name not in calls:
                    calls.append(func_name)

        return calls

    def _parse_strings_from_code(self, code: str) -> List[str]:
        """Parse string literals from C code."""
        strings = []

        # Pattern for string literals
        string_pattern = r'"([^"\\]*(?:\\.[^"\\]*)*)"'

        for match in re.finditer(string_pattern, code):
            string_value = match.group(1)
            if string_value and string_value not in strings:
                strings.append(string_value)

        return strings

    def decompile_all(self, max_functions: int = 100) -> Dict[str, DecompiledFunction]:
        """
        Decompile all functions in the binary.

        Args:
            max_functions: Maximum number of functions to decompile

        Returns:
            Dictionary mapping function names to decompiled functions
        """
        logger.info(f"Decompiling up to {max_functions} functions...")

        # Get function list
        functions = list(self.binary.symbols.items())[:max_functions]

        for name, symbol in functions:
            result = self.decompile(func_name=name, func_addr=symbol.address)
            if result:
                self.decompiled_functions[name] = result

        return self.decompiled_functions

    def find_vulnerabilities_in_decompiled(self) -> List[Dict[str, Any]]:
        """
        Find potential vulnerabilities in decompiled code.

        Returns:
            List of potential vulnerability findings
        """
        vulns = []

        dangerous_patterns = [
            (r'\bgets\s*\(', "gets() - Buffer overflow", "CRITICAL"),
            (r'\bstrcpy\s*\(', "strcpy() - Buffer overflow", "HIGH"),
            (r'\bsprintf\s*\(', "sprintf() - Buffer overflow", "HIGH"),
            (r'\bstrcat\s*\(', "strcat() - Buffer overflow", "HIGH"),
            (r'\bscanf\s*\([^,]*,\s*[^,]*\)', "scanf() without width", "MEDIUM"),
            (r'\bsystem\s*\(', "system() - Command injection", "HIGH"),
            (r'\bpopen\s*\(', "popen() - Command injection", "HIGH"),
            (r'\bprintf\s*\([^"]*\)', "printf() with non-literal format", "MEDIUM"),
            (r'\bfree\s*\([^)]+\).*\bfree\s*\(', "Double free pattern", "HIGH"),
        ]

        for name, func in self.decompiled_functions.items():
            for pattern, description, severity in dangerous_patterns:
                if re.search(pattern, func.code):
                    vulns.append({
                        "function": name,
                        "address": hex(func.address),
                        "pattern": pattern,
                        "description": description,
                        "severity": severity,
                    })

        return vulns

    def get_available_decompilers(self) -> List[str]:
        """Get list of available decompilers."""
        available = []

        if self._ghidra_path:
            available.append(f"ghidra ({self._ghidra_path})")
        if self._retdec_path:
            available.append(f"retdec ({self._retdec_path})")

        # angr is always available if installed
        try:
            import angr
            available.append("angr (builtin)")
        except ImportError:
            pass

        return available

    def summary(self) -> str:
        """Get decompilation summary."""
        lines = [
            "Decompilation Summary",
            "=" * 40,
            f"Available Decompilers: {', '.join(self.get_available_decompilers()) or 'None'}",
            f"Decompiled Functions: {len(self.decompiled_functions)}",
            "",
        ]

        if self.decompiled_functions:
            lines.append("Decompiled:")
            for name, func in list(self.decompiled_functions.items())[:10]:
                lines.append(f"  {name} @ 0x{func.address:x} ({len(func.code)} chars)")

        return "\n".join(lines)
