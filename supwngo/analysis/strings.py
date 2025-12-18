"""
Enhanced string analysis module.

Provides advanced string analysis including:
- Format string specifier detection
- Path and URL detection
- Command pattern detection
- Cryptographic constant detection
- Encoding detection (Base64, hex, XOR)
"""

import re
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from enum import Enum, auto

from supwngo.core.binary import Binary
from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


class StringCategory(Enum):
    """Categories of interesting strings."""
    FORMAT_STRING = auto()
    FILE_PATH = auto()
    URL = auto()
    SHELL_COMMAND = auto()
    CREDENTIAL = auto()
    CRYPTO_CONSTANT = auto()
    ERROR_MESSAGE = auto()
    DEBUG_INFO = auto()
    FLAG_PATTERN = auto()
    ENCODED_DATA = auto()
    FUNCTION_NAME = auto()
    SQL_QUERY = auto()
    NETWORK_PROTOCOL = auto()


@dataclass
class AnalyzedString:
    """Detailed string analysis result."""
    address: int
    value: str
    category: StringCategory
    section: str
    references: List[int] = field(default_factory=list)
    confidence: float = 1.0
    details: Dict[str, Any] = field(default_factory=dict)
    exploitable: bool = False
    exploit_type: str = ""


@dataclass
class FormatSpecifier:
    """Parsed format specifier."""
    position: int  # Position in string
    specifier: str  # Full specifier (e.g., "%08x")
    type_char: str  # Type character (e.g., 'x')
    width: Optional[int] = None
    precision: Optional[int] = None
    dollar_position: Optional[int] = None  # For %n$x style
    flags: str = ""
    is_write: bool = False  # %n can write


# Known cryptographic constants
CRYPTO_CONSTANTS = {
    # SHA-256 initial hash values
    0x6a09e667: "SHA-256 H0",
    0xbb67ae85: "SHA-256 H1",
    0x3c6ef372: "SHA-256 H2",
    0xa54ff53a: "SHA-256 H3",
    0x510e527f: "SHA-256 H4",
    0x9b05688c: "SHA-256 H5",
    0x1f83d9ab: "SHA-256 H6",
    0x5be0cd19: "SHA-256 H7",
    # MD5 constants
    0xd76aa478: "MD5 K0",
    0xe8c7b756: "MD5 K1",
    0x242070db: "MD5 K2",
    # AES S-box markers
    0x63: "Potential AES S-box",
    0x7c: "Potential AES S-box",
    # RC4/ChaCha
    0x61707865: "ChaCha/Salsa constant",
    0x3320646e: "ChaCha/Salsa constant",
    # RSA markers
    0x10001: "Common RSA public exponent",
}

# Format string patterns
FORMAT_PATTERN = re.compile(
    r'%'
    r'([0-9]+\$)?'  # Position specifier
    r'([-+ #0]*)?'   # Flags
    r'(\*|[0-9]+)?'  # Width
    r'(\.(\*|[0-9]+))?'  # Precision
    r'([hlLzjt]*)'   # Length modifier
    r'([diouxXeEfFgGaAcspn%])'  # Conversion specifier
)


class StringAnalyzer:
    """
    Advanced string analyzer for binary exploitation.

    Identifies interesting strings and their potential
    for exploitation, including format strings, paths,
    commands, and encoded data.
    """

    def __init__(self, binary: Binary):
        """
        Initialize string analyzer.

        Args:
            binary: Binary instance to analyze
        """
        self.binary = binary
        self.strings: List[AnalyzedString] = []
        self.format_strings: List[AnalyzedString] = []
        self.paths: List[AnalyzedString] = []
        self.commands: List[AnalyzedString] = []
        self.crypto_strings: List[AnalyzedString] = []

    def analyze(self, min_length: int = 4) -> List[AnalyzedString]:
        """
        Perform comprehensive string analysis.

        Args:
            min_length: Minimum string length to consider

        Returns:
            List of analyzed strings
        """
        logger.info("Starting string analysis...")

        raw_strings = self.binary.strings(min_length=min_length)

        for addr, value in raw_strings:
            analyzed = self._analyze_string(addr, value)
            if analyzed:
                self.strings.append(analyzed)

                # Categorize
                if analyzed.category == StringCategory.FORMAT_STRING:
                    self.format_strings.append(analyzed)
                elif analyzed.category == StringCategory.FILE_PATH:
                    self.paths.append(analyzed)
                elif analyzed.category == StringCategory.SHELL_COMMAND:
                    self.commands.append(analyzed)
                elif analyzed.category == StringCategory.CRYPTO_CONSTANT:
                    self.crypto_strings.append(analyzed)

        # Find cross-references
        self._find_string_xrefs()

        logger.info(f"Analyzed {len(self.strings)} strings")
        return self.strings

    def _analyze_string(self, addr: int, value: str) -> Optional[AnalyzedString]:
        """Analyze a single string."""
        section = self._get_section(addr)

        # Check format string
        format_result = self._check_format_string(value)
        if format_result:
            return AnalyzedString(
                address=addr,
                value=value[:200],
                category=StringCategory.FORMAT_STRING,
                section=section,
                confidence=format_result["confidence"],
                details=format_result,
                exploitable=format_result.get("has_write", False),
                exploit_type="format_string" if format_result.get("has_write") else "",
            )

        # Check file path
        if self._is_path(value):
            is_sensitive = self._is_sensitive_path(value)
            return AnalyzedString(
                address=addr,
                value=value[:200],
                category=StringCategory.FILE_PATH,
                section=section,
                confidence=0.9 if is_sensitive else 0.7,
                details={"sensitive": is_sensitive},
                exploitable=is_sensitive,
                exploit_type="path_traversal" if is_sensitive else "",
            )

        # Check URL
        if self._is_url(value):
            return AnalyzedString(
                address=addr,
                value=value[:200],
                category=StringCategory.URL,
                section=section,
                confidence=0.9,
                details={"protocol": value.split("://")[0] if "://" in value else "unknown"},
            )

        # Check shell command
        cmd_result = self._check_shell_command(value)
        if cmd_result:
            return AnalyzedString(
                address=addr,
                value=value[:200],
                category=StringCategory.SHELL_COMMAND,
                section=section,
                confidence=cmd_result["confidence"],
                details=cmd_result,
                exploitable=True,
                exploit_type="command_injection",
            )

        # Check credential patterns
        if self._is_credential(value):
            return AnalyzedString(
                address=addr,
                value=value[:200],
                category=StringCategory.CREDENTIAL,
                section=section,
                confidence=0.7,
            )

        # Check flag patterns (CTF)
        if self._is_flag_pattern(value):
            return AnalyzedString(
                address=addr,
                value=value[:200],
                category=StringCategory.FLAG_PATTERN,
                section=section,
                confidence=0.95,
            )

        # Check encoded data
        encoding_result = self._check_encoding(value)
        if encoding_result:
            return AnalyzedString(
                address=addr,
                value=value[:200],
                category=StringCategory.ENCODED_DATA,
                section=section,
                confidence=encoding_result["confidence"],
                details=encoding_result,
            )

        # Check SQL
        if self._is_sql(value):
            return AnalyzedString(
                address=addr,
                value=value[:200],
                category=StringCategory.SQL_QUERY,
                section=section,
                confidence=0.8,
                exploitable=True,
                exploit_type="sql_injection",
            )

        # Check error messages (may leak info)
        if self._is_error_message(value):
            return AnalyzedString(
                address=addr,
                value=value[:200],
                category=StringCategory.ERROR_MESSAGE,
                section=section,
                confidence=0.6,
            )

        return None

    def _check_format_string(self, value: str) -> Optional[Dict[str, Any]]:
        """Check if string is a format string."""
        specifiers = []
        has_write = False
        has_read = False
        has_positional = False

        for match in FORMAT_PATTERN.finditer(value):
            spec = FormatSpecifier(
                position=match.start(),
                specifier=match.group(0),
                type_char=match.group(7),
                dollar_position=int(match.group(1)[:-1]) if match.group(1) else None,
                flags=match.group(2) or "",
            )

            if match.group(3):
                try:
                    spec.width = int(match.group(3)) if match.group(3) != '*' else -1
                except ValueError:
                    pass

            if match.group(5):
                try:
                    spec.precision = int(match.group(5)) if match.group(5) != '*' else -1
                except ValueError:
                    pass

            if spec.type_char == 'n':
                has_write = True
                spec.is_write = True

            if spec.type_char in 'diouxXpxs':
                has_read = True

            if spec.dollar_position is not None:
                has_positional = True

            specifiers.append(spec)

        if not specifiers:
            return None

        # Calculate exploitation potential
        confidence = 0.5
        if has_write:
            confidence = 1.0
        elif has_positional:
            confidence = 0.9
        elif len(specifiers) > 3:
            confidence = 0.8
        elif has_read:
            confidence = 0.7

        return {
            "specifiers": [
                {
                    "position": s.position,
                    "specifier": s.specifier,
                    "type": s.type_char,
                    "dollar": s.dollar_position,
                    "is_write": s.is_write,
                }
                for s in specifiers
            ],
            "has_write": has_write,
            "has_read": has_read,
            "has_positional": has_positional,
            "specifier_count": len(specifiers),
            "confidence": confidence,
        }

    def _is_path(self, value: str) -> bool:
        """Check if string is a file path."""
        path_patterns = [
            r'^/[a-zA-Z0-9_\-./]+$',  # Unix absolute path
            r'^\./[a-zA-Z0-9_\-./]+$',  # Relative path
            r'^[a-zA-Z]:\\',  # Windows path
            r'/etc/',
            r'/proc/',
            r'/dev/',
            r'/tmp/',
            r'/var/',
            r'/home/',
            r'/root/',
        ]
        return any(re.search(p, value) for p in path_patterns)

    def _is_sensitive_path(self, value: str) -> bool:
        """Check if path is sensitive."""
        sensitive = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/hosts',
            '/proc/self/',
            '/dev/mem',
            '/dev/kmem',
            'id_rsa',
            '.ssh/',
            '.bash_history',
            '.gnupg/',
            '/flag',
            'flag.txt',
        ]
        return any(s in value.lower() for s in sensitive)

    def _is_url(self, value: str) -> bool:
        """Check if string is a URL."""
        return bool(re.match(r'^https?://|^ftp://|^file://', value, re.IGNORECASE))

    def _check_shell_command(self, value: str) -> Optional[Dict[str, Any]]:
        """Check if string is a shell command."""
        # Command patterns
        cmd_patterns = [
            (r'^/bin/(sh|bash|zsh|ksh|csh)', 0.95),
            (r'^sh\s+-[ci]', 0.9),
            (r'^\s*cat\s+', 0.7),
            (r'^\s*ls\s+', 0.6),
            (r'^\s*rm\s+', 0.8),
            (r';\s*(cat|ls|rm|chmod|chown|wget|curl)', 0.9),
            (r'\|\s*(sh|bash)', 0.95),
            (r'`[^`]+`', 0.85),
            (r'\$\([^)]+\)', 0.85),
            (r'&&\s*(cat|rm|wget)', 0.9),
        ]

        for pattern, confidence in cmd_patterns:
            if re.search(pattern, value):
                return {
                    "pattern": pattern,
                    "confidence": confidence,
                    "injectable": ';' in value or '|' in value or '`' in value,
                }

        return None

    def _is_credential(self, value: str) -> bool:
        """Check if string might be credential-related."""
        patterns = [
            r'password',
            r'passwd',
            r'secret',
            r'token',
            r'api[_-]?key',
            r'auth',
            r'credential',
            r'private[_-]?key',
        ]
        return any(re.search(p, value, re.IGNORECASE) for p in patterns)

    def _is_flag_pattern(self, value: str) -> bool:
        """Check if string matches CTF flag patterns."""
        patterns = [
            r'flag\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'HTB\{[^}]+\}',
            r'picoCTF\{[^}]+\}',
            r'CSAW\{[^}]+\}',
            r'ASIS\{[^}]+\}',
            r'FLAG_[A-Za-z0-9]+',
        ]
        return any(re.search(p, value, re.IGNORECASE) for p in patterns)

    def _check_encoding(self, value: str) -> Optional[Dict[str, Any]]:
        """Check if string is encoded data."""
        # Base64
        if len(value) >= 8:
            b64_pattern = r'^[A-Za-z0-9+/]+=*$'
            if re.match(b64_pattern, value) and len(value) % 4 == 0:
                try:
                    import base64
                    decoded = base64.b64decode(value)
                    if all(32 <= b < 127 or b in (9, 10, 13) for b in decoded[:20]):
                        return {
                            "encoding": "base64",
                            "confidence": 0.8,
                            "decoded_preview": decoded[:50].decode('utf-8', errors='replace'),
                        }
                except Exception:
                    pass

        # Hex string
        if len(value) >= 8 and len(value) % 2 == 0:
            hex_pattern = r'^[0-9a-fA-F]+$'
            if re.match(hex_pattern, value):
                try:
                    decoded = bytes.fromhex(value)
                    if all(32 <= b < 127 or b in (9, 10, 13) for b in decoded[:20]):
                        return {
                            "encoding": "hex",
                            "confidence": 0.7,
                            "decoded_preview": decoded[:50].decode('utf-8', errors='replace'),
                        }
                except Exception:
                    pass

        return None

    def _is_sql(self, value: str) -> bool:
        """Check if string is SQL query."""
        sql_keywords = [
            r'\bSELECT\b.*\bFROM\b',
            r'\bINSERT\b.*\bINTO\b',
            r'\bUPDATE\b.*\bSET\b',
            r'\bDELETE\b.*\bFROM\b',
            r'\bDROP\b.*\bTABLE\b',
            r'\bUNION\b.*\bSELECT\b',
        ]
        return any(re.search(p, value, re.IGNORECASE) for p in sql_keywords)

    def _is_error_message(self, value: str) -> bool:
        """Check if string is error message."""
        error_patterns = [
            r'\berror\b',
            r'\bfailed\b',
            r'\bexception\b',
            r'\binvalid\b',
            r'\bdenied\b',
            r'\bunauthorized\b',
            r'\btimeout\b',
            r'\bsegmentation fault\b',
            r'\baborted\b',
        ]
        return any(re.search(p, value, re.IGNORECASE) for p in error_patterns)

    def _get_section(self, addr: int) -> str:
        """Get section name for address."""
        for name, section in self.binary.sections.items():
            if section.address <= addr < section.address + section.size:
                return name
        return "unknown"

    def _find_string_xrefs(self) -> None:
        """Find cross-references to strings."""
        try:
            proj = self.binary.get_angr_project()
            cfg = proj.analyses.CFGFast()

            for analyzed in self.strings:
                # Find references to this string address
                for func in cfg.kb.functions.values():
                    for block in func.blocks:
                        try:
                            for insn in block.capstone.insns:
                                # Check if instruction references our string
                                if hex(analyzed.address)[2:] in insn.op_str:
                                    analyzed.references.append(insn.address)
                        except Exception:
                            continue
        except Exception as e:
            logger.debug(f"String xref analysis failed: {e}")

    def find_format_string_vulns(self) -> List[Dict[str, Any]]:
        """
        Find potential format string vulnerabilities.

        Returns:
            List of potential vulnerabilities
        """
        vulns = []

        for fs in self.format_strings:
            # Check if format string is in writable section
            writable = fs.section in ('.data', '.bss')

            # Check if it has dangerous specifiers
            has_n = fs.details.get("has_write", False)
            has_positional = fs.details.get("has_positional", False)

            if has_n:
                vulns.append({
                    "address": hex(fs.address),
                    "string": fs.value,
                    "type": "format_write",
                    "severity": "CRITICAL",
                    "details": "%n specifier allows arbitrary write",
                    "references": [hex(r) for r in fs.references],
                })
            elif has_positional and fs.references:
                vulns.append({
                    "address": hex(fs.address),
                    "string": fs.value,
                    "type": "format_read",
                    "severity": "HIGH",
                    "details": "Positional specifiers allow reading stack",
                    "references": [hex(r) for r in fs.references],
                })
            elif writable:
                vulns.append({
                    "address": hex(fs.address),
                    "string": fs.value,
                    "type": "writable_format",
                    "severity": "MEDIUM",
                    "details": "Format string in writable memory",
                    "references": [hex(r) for r in fs.references],
                })

        return vulns

    def find_crypto_constants(self) -> List[Dict[str, Any]]:
        """
        Find cryptographic constants in the binary.

        Returns:
            List of crypto constant findings
        """
        findings = []

        # Search binary data for known constants
        try:
            for section_name, section in self.binary.sections.items():
                if section.size > 0x100000:  # Skip very large sections
                    continue

                data = self.binary.read(section.address, section.size)

                for const, name in CRYPTO_CONSTANTS.items():
                    # Search as 32-bit little endian
                    pattern = struct.pack('<I', const)
                    offset = 0
                    while True:
                        idx = data.find(pattern, offset)
                        if idx == -1:
                            break
                        findings.append({
                            "constant": hex(const),
                            "name": name,
                            "address": hex(section.address + idx),
                            "section": section_name,
                        })
                        offset = idx + 1
        except Exception as e:
            logger.debug(f"Crypto constant search failed: {e}")

        return findings

    def summary(self) -> str:
        """Get string analysis summary."""
        lines = [
            "String Analysis Summary",
            "=" * 40,
            f"Total Analyzed: {len(self.strings)}",
            f"Format Strings: {len(self.format_strings)}",
            f"File Paths: {len(self.paths)}",
            f"Shell Commands: {len(self.commands)}",
            f"Crypto Constants: {len(self.crypto_strings)}",
            "",
        ]

        # Exploitable strings
        exploitable = [s for s in self.strings if s.exploitable]
        if exploitable:
            lines.append(f"Exploitable Strings: {len(exploitable)}")
            for s in exploitable[:5]:
                lines.append(f"  [{s.exploit_type}] 0x{s.address:x}: {s.value[:40]}")

        return "\n".join(lines)
