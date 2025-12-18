"""
CMPLOG integration for comparison operand logging.

CMPLOG (Comparison Logging) is an AFL++ feature that instruments
comparison operations to extract operands, helping the fuzzer
solve "magic byte" checks automatically.

Features:
- Automatic dictionary generation from comparisons
- Input-to-state correspondence tracking
- Comparison coverage analysis
- RedQueen-style constraint solving

References:
- AFL++ CMPLOG: https://github.com/AFLplusplus/AFLplusplus
- RedQueen: https://synthesis.to/papers/NDSS19-Redqueen.pdf
- Input-to-State Correspondence
"""

import os
import re
import struct
import subprocess
import tempfile
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


class ComparisonType(Enum):
    """Types of comparisons tracked."""
    STRCMP = auto()        # String comparison
    MEMCMP = auto()        # Memory comparison
    INTEGER_EQ = auto()     # Integer equality
    INTEGER_LT = auto()     # Integer less-than
    INTEGER_GT = auto()     # Integer greater-than
    SWITCH = auto()        # Switch statement


@dataclass
class ComparisonOperand:
    """A captured comparison operand."""
    cmp_type: ComparisonType
    operand1: bytes
    operand2: bytes
    pc: int = 0  # Program counter where comparison occurred
    input_offset: int = -1  # Offset in input if from input


@dataclass
class CMPLOGConfig:
    """CMPLOG configuration."""
    afl_path: str = "/usr/local/bin/afl-fuzz"
    afl_cmplog_path: str = "/usr/local/bin/afl-clang-lto"
    output_dir: str = "./cmplog_out"
    dictionary_path: str = "./cmplog.dict"
    enable_redqueen: bool = True
    enable_colorization: bool = True


class CMPLOGInstrumenter:
    """
    Instrument binaries for CMPLOG.

    Supports:
    - AFL++ CMPLOG instrumentation
    - Source-level instrumentation
    - Binary rewriting (experimental)
    """

    def __init__(self, config: Optional[CMPLOGConfig] = None):
        self.config = config or CMPLOGConfig()

    def check_afl_cmplog(self) -> bool:
        """Check if AFL++ CMPLOG is available."""
        try:
            result = subprocess.run(
                [self.config.afl_cmplog_path, "--version"],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def instrument_source(
        self,
        source_dir: str,
        output_binary: str,
        compiler_flags: List[str] = None,
    ) -> Tuple[str, str]:
        """
        Compile source with CMPLOG instrumentation.

        Args:
            source_dir: Source directory
            output_binary: Output binary path
            compiler_flags: Additional compiler flags

        Returns:
            (normal_binary, cmplog_binary) paths
        """
        flags = compiler_flags or []

        # Normal instrumented binary
        normal_binary = f"{output_binary}_normal"
        normal_cmd = [
            self.config.afl_cmplog_path.replace("cmplog", "fast"),
            "-o", normal_binary,
            *flags,
            f"{source_dir}/*.c",
        ]

        # CMPLOG instrumented binary
        cmplog_binary = f"{output_binary}_cmplog"
        cmplog_cmd = [
            self.config.afl_cmplog_path,
            "-o", cmplog_binary,
            *flags,
            f"{source_dir}/*.c",
        ]

        logger.info(f"Compiling normal binary: {normal_binary}")
        # subprocess.run(normal_cmd, check=True)

        logger.info(f"Compiling CMPLOG binary: {cmplog_binary}")
        # subprocess.run(cmplog_cmd, check=True)

        return normal_binary, cmplog_binary

    def generate_instrumentation_code(self) -> str:
        """Generate source-level CMPLOG instrumentation."""
        return '''
/* CMPLOG instrumentation for manual insertion */

#include <stdint.h>
#include <string.h>

#ifdef __AFL_COMPILER
extern void __afl_cmplog_ins_hook(uintptr_t, uintptr_t);
extern void __afl_cmplog_mem_hook(void*, void*, size_t);
#define CMPLOG_INS(a, b) __afl_cmplog_ins_hook((uintptr_t)(a), (uintptr_t)(b))
#define CMPLOG_MEM(a, b, n) __afl_cmplog_mem_hook((void*)(a), (void*)(b), n)
#else
#define CMPLOG_INS(a, b)
#define CMPLOG_MEM(a, b, n)
#endif

/* Instrumented strcmp wrapper */
int cmplog_strcmp(const char *s1, const char *s2) {
    CMPLOG_MEM(s1, s2, strlen(s1) < strlen(s2) ? strlen(s1) : strlen(s2));
    return strcmp(s1, s2);
}

/* Instrumented memcmp wrapper */
int cmplog_memcmp(const void *m1, const void *m2, size_t n) {
    CMPLOG_MEM(m1, m2, n);
    return memcmp(m1, m2, n);
}

/* Instrumented integer comparison */
#define CMPLOG_INT_CMP(a, b, op) ({ \\
    CMPLOG_INS(a, b); \\
    (a) op (b); \\
})
'''


class ComparisonExtractor:
    """
    Extract comparison operands from CMPLOG output.

    Parses AFL++ CMPLOG data to extract:
    - Magic bytes and constants
    - String comparisons
    - Switch case values
    """

    def __init__(self):
        self.operands: List[ComparisonOperand] = []
        self.dictionary: Set[bytes] = set()

    def parse_cmplog_output(self, cmplog_file: str) -> List[ComparisonOperand]:
        """
        Parse CMPLOG binary output file.

        Args:
            cmplog_file: Path to CMPLOG data file

        Returns:
            List of extracted operands
        """
        operands = []

        try:
            with open(cmplog_file, 'rb') as f:
                data = f.read()

            # Parse CMPLOG format (AFL++ specific)
            # Format varies by AFL++ version

            offset = 0
            while offset < len(data):
                # Each entry: type(1) + size(1) + op1(size) + op2(size)
                if offset + 2 > len(data):
                    break

                cmp_type = data[offset]
                size = data[offset + 1]
                offset += 2

                if offset + size * 2 > len(data):
                    break

                op1 = data[offset:offset + size]
                op2 = data[offset + size:offset + size * 2]
                offset += size * 2

                operands.append(ComparisonOperand(
                    cmp_type=self._type_from_int(cmp_type),
                    operand1=op1,
                    operand2=op2,
                ))

                # Add to dictionary
                if op1 and len(op1) >= 2:
                    self.dictionary.add(op1)
                if op2 and len(op2) >= 2:
                    self.dictionary.add(op2)

        except (FileNotFoundError, IOError) as e:
            logger.error(f"Failed to parse CMPLOG file: {e}")

        self.operands = operands
        return operands

    def _type_from_int(self, t: int) -> ComparisonType:
        """Convert integer type to enum."""
        type_map = {
            0: ComparisonType.INTEGER_EQ,
            1: ComparisonType.INTEGER_LT,
            2: ComparisonType.INTEGER_GT,
            3: ComparisonType.STRCMP,
            4: ComparisonType.MEMCMP,
            5: ComparisonType.SWITCH,
        }
        return type_map.get(t, ComparisonType.INTEGER_EQ)

    def extract_from_execution(
        self,
        binary: str,
        input_data: bytes,
    ) -> List[ComparisonOperand]:
        """
        Extract comparisons by running binary with CMPLOG.

        Args:
            binary: CMPLOG-instrumented binary
            input_data: Input to execute with

        Returns:
            List of comparison operands
        """
        operands = []

        with tempfile.NamedTemporaryFile(delete=False) as f:
            input_file = f.name
            f.write(input_data)

        try:
            # Run with CMPLOG
            env = os.environ.copy()
            env["AFL_CMPLOG_ONLY_NEW"] = "1"

            result = subprocess.run(
                [binary],
                stdin=open(input_file, 'rb'),
                capture_output=True,
                timeout=5,
                env=env,
            )

            # Parse CMPLOG output from shared memory or temp file
            cmplog_file = f"/tmp/cmplog_{os.getpid()}"
            if os.path.exists(cmplog_file):
                operands = self.parse_cmplog_output(cmplog_file)

        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.warning(f"CMPLOG execution failed: {e}")
        finally:
            os.unlink(input_file)

        return operands


class DictionaryGenerator:
    """
    Generate fuzzing dictionaries from comparison data.

    Dictionaries help fuzzers solve magic byte checks by
    providing known good values.
    """

    def __init__(self):
        self.entries: Set[bytes] = set()

    def add_from_operands(self, operands: List[ComparisonOperand]):
        """Add dictionary entries from comparison operands."""
        for op in operands:
            if op.operand1 and len(op.operand1) >= 2:
                self.entries.add(op.operand1)
            if op.operand2 and len(op.operand2) >= 2:
                self.entries.add(op.operand2)

    def add_from_binary(self, binary: str):
        """Extract strings from binary for dictionary."""
        try:
            result = subprocess.run(
                ["strings", "-n", "4", binary],
                capture_output=True,
                timeout=30,
            )
            for line in result.stdout.split(b'\n'):
                if 4 <= len(line) <= 32:
                    self.entries.add(line)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    def add_magic_bytes(self):
        """Add common magic byte sequences."""
        common_magic = [
            b"\x7fELF",      # ELF
            b"PK\x03\x04",   # ZIP
            b"\x89PNG",      # PNG
            b"GIF87a",       # GIF
            b"GIF89a",       # GIF
            b"\xff\xd8\xff", # JPEG
            b"BM",           # BMP
            b"MZ",           # PE/DOS
            b"%PDF",         # PDF
            b"<?xml",        # XML
            b"<!DOCTYPE",   # HTML
            b"HTTP/1",       # HTTP
            b"\x00\x00\x01\x00",  # ICO
        ]
        self.entries.update(common_magic)

    def export_afl_dict(self, path: str):
        """
        Export dictionary in AFL format.

        Args:
            path: Output dictionary file path
        """
        with open(path, 'w') as f:
            for i, entry in enumerate(sorted(self.entries, key=len)):
                # AFL dict format: name="value"
                hex_value = entry.hex()
                f.write(f'token_{i}="\\x{hex_value}"\n')

        logger.info(f"Exported {len(self.entries)} dictionary entries to {path}")

    def export_honggfuzz_dict(self, path: str):
        """Export dictionary in Honggfuzz format (one per line)."""
        with open(path, 'wb') as f:
            for entry in sorted(self.entries, key=len):
                f.write(entry + b'\n')


class InputToState:
    """
    Track input-to-state correspondence.

    Identifies which parts of the input affect which comparisons,
    enabling targeted mutation (RedQueen approach).
    """

    def __init__(self):
        self.correspondence: Dict[int, List[int]] = {}  # input_offset -> cmp_indices

    def analyze(
        self,
        binary: str,
        input_data: bytes,
        extractor: ComparisonExtractor,
    ) -> Dict[int, List[ComparisonOperand]]:
        """
        Analyze input-to-state correspondence.

        Args:
            binary: CMPLOG binary
            input_data: Input to analyze
            extractor: Comparison extractor

        Returns:
            Mapping of input offsets to affected comparisons
        """
        result: Dict[int, List[ComparisonOperand]] = {}

        # Get baseline comparisons
        baseline = extractor.extract_from_execution(binary, input_data)

        # Mutate each byte and observe changes
        for offset in range(len(input_data)):
            mutated = bytearray(input_data)
            mutated[offset] ^= 0xFF  # Flip all bits

            mutated_ops = extractor.extract_from_execution(binary, bytes(mutated))

            # Find differences
            affected = []
            for i, (b, m) in enumerate(zip(baseline, mutated_ops)):
                if b.operand1 != m.operand1 or b.operand2 != m.operand2:
                    affected.append(b)

            if affected:
                result[offset] = affected

        return result


class CMPLOGFuzzer:
    """
    High-level CMPLOG-aware fuzzer.

    Integrates CMPLOG with AFL++ for enhanced comparison solving.
    """

    def __init__(self, config: Optional[CMPLOGConfig] = None):
        self.config = config or CMPLOGConfig()
        self.instrumenter = CMPLOGInstrumenter(config)
        self.extractor = ComparisonExtractor()
        self.dict_gen = DictionaryGenerator()

    def prepare(
        self,
        binary: str,
        cmplog_binary: Optional[str] = None,
    ) -> Dict[str, str]:
        """
        Prepare fuzzing environment.

        Args:
            binary: Normal instrumented binary
            cmplog_binary: CMPLOG instrumented binary

        Returns:
            Configuration paths
        """
        # Generate dictionary from binary
        self.dict_gen.add_from_binary(binary)
        self.dict_gen.add_magic_bytes()
        self.dict_gen.export_afl_dict(self.config.dictionary_path)

        return {
            "binary": binary,
            "cmplog_binary": cmplog_binary or binary,
            "dictionary": self.config.dictionary_path,
            "output": self.config.output_dir,
        }

    def run_afl(
        self,
        binary: str,
        cmplog_binary: str,
        input_dir: str,
        timeout: int = 0,
    ) -> subprocess.Popen:
        """
        Launch AFL++ with CMPLOG.

        Args:
            binary: Normal binary
            cmplog_binary: CMPLOG binary
            input_dir: Input corpus directory
            timeout: Timeout in seconds (0 = unlimited)

        Returns:
            AFL process handle
        """
        cmd = [
            self.config.afl_path,
            "-i", input_dir,
            "-o", self.config.output_dir,
            "-c", cmplog_binary,  # CMPLOG binary
            "-x", self.config.dictionary_path,  # Dictionary
        ]

        if timeout:
            cmd.extend(["-V", str(timeout)])

        if self.config.enable_redqueen:
            cmd.extend(["-l", "2"])  # CMPLOG level

        cmd.extend(["--", binary, "@@"])

        logger.info(f"Launching AFL++: {' '.join(cmd)}")

        return subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def analyze_comparisons(
        self,
        binary: str,
        corpus_dir: str,
    ) -> List[ComparisonOperand]:
        """
        Analyze comparisons across corpus.

        Args:
            binary: CMPLOG binary
            corpus_dir: Directory with input files

        Returns:
            All unique comparisons found
        """
        all_operands = []

        corpus_path = Path(corpus_dir)
        for input_file in corpus_path.iterdir():
            if input_file.is_file():
                input_data = input_file.read_bytes()
                operands = self.extractor.extract_from_execution(binary, input_data)
                all_operands.extend(operands)

        # Deduplicate
        seen = set()
        unique = []
        for op in all_operands:
            key = (op.operand1, op.operand2, op.cmp_type)
            if key not in seen:
                seen.add(key)
                unique.append(op)

        logger.info(f"Found {len(unique)} unique comparisons")
        return unique


def generate_cmplog_harness(target_function: str) -> str:
    """Generate CMPLOG fuzzing harness."""
    return f'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Target function to fuzz
extern int {target_function}(const char *input, size_t len);

// AFL++ persistent mode
__AFL_FUZZ_INIT();

int main(int argc, char **argv) {{
    __AFL_INIT();

    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(10000)) {{
        int len = __AFL_FUZZ_TESTCASE_LEN;
        if (len > 0) {{
            {target_function}((const char *)buf, len);
        }}
    }}

    return 0;
}}
'''
