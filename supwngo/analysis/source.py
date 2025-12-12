#!/usr/bin/env python3
"""
Source Code Analysis Module

Provides static analysis of source code to detect vulnerabilities
using multiple SAST tools including Bearer CLI.
"""

import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any

from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


class SourceVulnType(Enum):
    """Source code vulnerability types."""
    BUFFER_OVERFLOW = "buffer_overflow"
    FORMAT_STRING = "format_string"
    COMMAND_INJECTION = "command_injection"
    SQL_INJECTION = "sql_injection"
    PATH_TRAVERSAL = "path_traversal"
    USE_AFTER_FREE = "use_after_free"
    INTEGER_OVERFLOW = "integer_overflow"
    NULL_DEREFERENCE = "null_dereference"
    MEMORY_LEAK = "memory_leak"
    RACE_CONDITION = "race_condition"
    HARDCODED_SECRET = "hardcoded_secret"
    INSECURE_FUNCTION = "insecure_function"
    UNINITIALIZED_VARIABLE = "uninitialized_variable"
    OTHER = "other"


class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class SourceVulnerability:
    """Represents a vulnerability found in source code."""
    vuln_type: SourceVulnType
    severity: Severity
    file_path: str
    line_number: int
    column: int = 0
    function: str = ""
    code_snippet: str = ""
    description: str = ""
    cwe_id: str = ""
    fix_suggestion: str = ""
    tool: str = ""
    confidence: str = ""

    def to_dict(self) -> Dict:
        return {
            "type": self.vuln_type.value,
            "severity": self.severity.value,
            "file": self.file_path,
            "line": self.line_number,
            "column": self.column,
            "function": self.function,
            "code": self.code_snippet,
            "description": self.description,
            "cwe": self.cwe_id,
            "fix": self.fix_suggestion,
            "tool": self.tool,
            "confidence": self.confidence,
        }


@dataclass
class SourceAnalysisReport:
    """Report from source code analysis."""
    files_analyzed: int = 0
    vulnerabilities: List[SourceVulnerability] = field(default_factory=list)
    dangerous_functions: List[Dict] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    tools_used: List[str] = field(default_factory=list)

    @property
    def total_vulns(self) -> int:
        return len(self.vulnerabilities)

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.HIGH)

    def get_by_type(self, vuln_type: SourceVulnType) -> List[SourceVulnerability]:
        return [v for v in self.vulnerabilities if v.vuln_type == vuln_type]

    def get_by_severity(self, severity: Severity) -> List[SourceVulnerability]:
        return [v for v in self.vulnerabilities if v.severity == severity]

    def to_dict(self) -> Dict:
        return {
            "files_analyzed": self.files_analyzed,
            "total_vulnerabilities": self.total_vulns,
            "critical": self.critical_count,
            "high": self.high_count,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "dangerous_functions": self.dangerous_functions,
            "warnings": self.warnings,
            "errors": self.errors,
            "tools_used": self.tools_used,
        }


class SourceAnalyzer:
    """
    Multi-tool source code analyzer for vulnerability detection.

    Integrates:
    - Bearer CLI (SAST)
    - Built-in C/C++ dangerous function detection
    - Pattern-based vulnerability detection
    """

    # Dangerous C/C++ functions
    DANGEROUS_FUNCTIONS = {
        # Buffer overflows
        "gets": ("CRITICAL", "buffer_overflow", "Use fgets() instead"),
        "strcpy": ("HIGH", "buffer_overflow", "Use strncpy() or strlcpy()"),
        "strcat": ("HIGH", "buffer_overflow", "Use strncat() or strlcat()"),
        "sprintf": ("HIGH", "buffer_overflow", "Use snprintf()"),
        "vsprintf": ("HIGH", "buffer_overflow", "Use vsnprintf()"),
        "scanf": ("MEDIUM", "buffer_overflow", "Use fgets() + sscanf() with length limits"),
        "fscanf": ("MEDIUM", "buffer_overflow", "Use fgets() + sscanf() with length limits"),
        "sscanf": ("LOW", "buffer_overflow", "Ensure buffer bounds are checked"),

        # Format strings
        "printf": ("MEDIUM", "format_string", "Ensure format string is not user-controlled"),
        "fprintf": ("MEDIUM", "format_string", "Ensure format string is not user-controlled"),
        "sprintf": ("HIGH", "format_string", "Ensure format string is not user-controlled"),
        "snprintf": ("LOW", "format_string", "Ensure format string is not user-controlled"),
        "syslog": ("MEDIUM", "format_string", "Ensure format string is not user-controlled"),

        # Command injection
        "system": ("HIGH", "command_injection", "Avoid system() with user input"),
        "popen": ("HIGH", "command_injection", "Avoid popen() with user input"),
        "exec": ("HIGH", "command_injection", "Validate input before exec*()"),
        "execl": ("HIGH", "command_injection", "Validate input before exec*()"),
        "execle": ("HIGH", "command_injection", "Validate input before exec*()"),
        "execlp": ("HIGH", "command_injection", "Validate input before exec*()"),
        "execv": ("HIGH", "command_injection", "Validate input before exec*()"),
        "execve": ("HIGH", "command_injection", "Validate input before exec*()"),
        "execvp": ("HIGH", "command_injection", "Validate input before exec*()"),

        # Memory operations
        "malloc": ("INFO", "memory_leak", "Ensure proper free()"),
        "calloc": ("INFO", "memory_leak", "Ensure proper free()"),
        "realloc": ("LOW", "memory_leak", "Check return value and ensure free()"),
        "free": ("LOW", "use_after_free", "Set pointer to NULL after free"),

        # Other dangerous functions
        "mktemp": ("HIGH", "race_condition", "Use mkstemp() instead"),
        "tmpnam": ("HIGH", "race_condition", "Use mkstemp() instead"),
        "tempnam": ("HIGH", "race_condition", "Use mkstemp() instead"),
        "getwd": ("MEDIUM", "buffer_overflow", "Use getcwd() with buffer size"),
        "realpath": ("MEDIUM", "buffer_overflow", "Use PATH_MAX buffer"),
        "strtok": ("LOW", "race_condition", "Not thread-safe, use strtok_r()"),
        "rand": ("LOW", "insecure_function", "Use random() or arc4random()"),
        "srand": ("LOW", "insecure_function", "Use better random seeding"),
        "atoi": ("LOW", "integer_overflow", "Use strtol() with error checking"),
        "atol": ("LOW", "integer_overflow", "Use strtol() with error checking"),
    }

    # Vulnerable patterns (regex)
    VULN_PATTERNS = [
        (r'char\s+\w+\[(\d+)\].*gets\s*\(', "buffer_overflow", "HIGH", "gets() with fixed buffer"),
        (r'strcpy\s*\(\s*\w+\s*,\s*\w+\s*\)', "buffer_overflow", "HIGH", "strcpy without bounds check"),
        (r'sprintf\s*\(\s*\w+\s*,\s*"[^"]*%s', "buffer_overflow", "HIGH", "sprintf with %s format"),
        (r'printf\s*\(\s*\w+\s*\)', "format_string", "HIGH", "printf with variable format string"),
        (r'system\s*\(\s*\w+\s*\)', "command_injection", "HIGH", "system() with variable argument"),
        (r'memcpy\s*\([^,]+,\s*[^,]+,\s*\w+\s*\)', "buffer_overflow", "MEDIUM", "memcpy with variable size"),
        (r'free\s*\([^)]+\).*free\s*\([^)]+\)', "use_after_free", "HIGH", "Double free potential"),
    ]

    def __init__(self, source_path: str):
        """
        Initialize source analyzer.

        Args:
            source_path: Path to source file or directory
        """
        self.source_path = Path(source_path)
        self.report = SourceAnalysisReport()

    def analyze(self, tools: List[str] = None) -> SourceAnalysisReport:
        """
        Run comprehensive source analysis.

        Args:
            tools: List of tools to use. Default: all available

        Returns:
            SourceAnalysisReport with all findings
        """
        if tools is None:
            tools = ["builtin", "bearer", "patterns"]

        # Count files
        if self.source_path.is_file():
            self.report.files_analyzed = 1
        else:
            self.report.files_analyzed = len(list(self._get_source_files()))

        # Run analysis with each tool
        if "builtin" in tools:
            self._analyze_dangerous_functions()
            self.report.tools_used.append("builtin")

        if "patterns" in tools:
            self._analyze_patterns()
            self.report.tools_used.append("patterns")

        if "bearer" in tools:
            if self._check_bearer_available():
                self._run_bearer_analysis()
                self.report.tools_used.append("bearer")
            else:
                self.report.warnings.append(
                    "Bearer CLI not installed. Install with: curl -sfL https://raw.githubusercontent.com/Bearer/bearer/main/contrib/install.sh | sh"
                )

        return self.report

    def _get_source_files(self) -> List[Path]:
        """Get all source files in path."""
        extensions = {'.c', '.cpp', '.cc', '.cxx', '.h', '.hpp', '.hxx'}

        if self.source_path.is_file():
            if self.source_path.suffix in extensions:
                return [self.source_path]
            return []

        files = []
        for ext in extensions:
            files.extend(self.source_path.rglob(f"*{ext}"))
        return files

    def _analyze_dangerous_functions(self):
        """Detect dangerous function calls."""
        source_files = self._get_source_files()

        for source_file in source_files:
            try:
                content = source_file.read_text(errors='ignore')
                lines = content.split('\n')

                for func_name, (severity, vuln_type, fix) in self.DANGEROUS_FUNCTIONS.items():
                    # Pattern to find function calls
                    pattern = rf'\b{func_name}\s*\('

                    for line_num, line in enumerate(lines, 1):
                        if re.search(pattern, line):
                            # Skip if in comment
                            stripped = line.strip()
                            if stripped.startswith('//') or stripped.startswith('/*'):
                                continue

                            # Get function context
                            func_context = self._get_function_context(lines, line_num)

                            vuln = SourceVulnerability(
                                vuln_type=SourceVulnType(vuln_type),
                                severity=Severity[severity],
                                file_path=str(source_file),
                                line_number=line_num,
                                function=func_context,
                                code_snippet=line.strip()[:100],
                                description=f"Use of dangerous function: {func_name}()",
                                fix_suggestion=fix,
                                tool="builtin",
                            )
                            self.report.vulnerabilities.append(vuln)

                            # Track dangerous function usage
                            self.report.dangerous_functions.append({
                                "function": func_name,
                                "file": str(source_file),
                                "line": line_num,
                                "severity": severity,
                            })

            except Exception as e:
                self.report.errors.append(f"Error analyzing {source_file}: {e}")

    def _analyze_patterns(self):
        """Analyze for vulnerable code patterns."""
        source_files = self._get_source_files()

        for source_file in source_files:
            try:
                content = source_file.read_text(errors='ignore')
                lines = content.split('\n')

                for pattern, vuln_type, severity, description in self.VULN_PATTERNS:
                    for match in re.finditer(pattern, content, re.MULTILINE):
                        # Calculate line number
                        line_num = content[:match.start()].count('\n') + 1
                        line = lines[line_num - 1] if line_num <= len(lines) else ""

                        vuln = SourceVulnerability(
                            vuln_type=SourceVulnType(vuln_type),
                            severity=Severity[severity],
                            file_path=str(source_file),
                            line_number=line_num,
                            code_snippet=line.strip()[:100],
                            description=description,
                            tool="patterns",
                            confidence="high",
                        )
                        self.report.vulnerabilities.append(vuln)

            except Exception as e:
                self.report.errors.append(f"Error pattern analysis {source_file}: {e}")

    def _get_function_context(self, lines: List[str], line_num: int) -> str:
        """Get the function name containing a line."""
        func_pattern = r'^\s*(?:static\s+)?(?:inline\s+)?(?:\w+\s+)+(\w+)\s*\([^)]*\)\s*{'

        # Search backwards for function definition
        for i in range(line_num - 1, max(0, line_num - 50), -1):
            match = re.match(func_pattern, lines[i])
            if match:
                return match.group(1)
        return ""

    def _check_bearer_available(self) -> bool:
        """Check if Bearer CLI is installed."""
        try:
            result = subprocess.run(
                ["bearer", "version"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def _run_bearer_analysis(self):
        """Run Bearer CLI SAST analysis."""
        try:
            # Create temp file for output
            with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmp:
                output_file = tmp.name

            cmd = [
                "bearer", "scan",
                str(self.source_path),
                "--format", "json",
                "--output", output_file,
                "--quiet"
            ]

            logger.info(f"Running Bearer: {' '.join(cmd)}")

            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=300,
                text=True
            )

            # Parse results
            if os.path.exists(output_file):
                try:
                    with open(output_file, 'r') as f:
                        bearer_results = json.load(f)

                    self._parse_bearer_results(bearer_results)
                finally:
                    os.unlink(output_file)
            else:
                if result.stderr:
                    self.report.errors.append(f"Bearer error: {result.stderr[:200]}")

        except subprocess.TimeoutExpired:
            self.report.errors.append("Bearer analysis timed out")
        except Exception as e:
            self.report.errors.append(f"Bearer error: {e}")

    def _parse_bearer_results(self, results: Dict):
        """Parse Bearer CLI JSON output."""
        findings = results.get("findings", [])

        for finding in findings:
            severity_map = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
                "warning": Severity.INFO,
            }

            # Map Bearer rule IDs to our vuln types
            vuln_type = self._map_bearer_rule_to_vuln_type(finding.get("rule_id", ""))

            vuln = SourceVulnerability(
                vuln_type=vuln_type,
                severity=severity_map.get(
                    finding.get("severity", "").lower(),
                    Severity.MEDIUM
                ),
                file_path=finding.get("filename", ""),
                line_number=finding.get("line_number", 0),
                code_snippet=finding.get("code_extract", ""),
                description=finding.get("title", ""),
                cwe_id=finding.get("cwe_ids", [""])[0] if finding.get("cwe_ids") else "",
                fix_suggestion=finding.get("remediation", ""),
                tool="bearer",
            )
            self.report.vulnerabilities.append(vuln)

    def _map_bearer_rule_to_vuln_type(self, rule_id: str) -> SourceVulnType:
        """Map Bearer rule ID to vulnerability type."""
        rule_id_lower = rule_id.lower()

        if "buffer" in rule_id_lower or "overflow" in rule_id_lower:
            return SourceVulnType.BUFFER_OVERFLOW
        elif "format" in rule_id_lower:
            return SourceVulnType.FORMAT_STRING
        elif "command" in rule_id_lower or "injection" in rule_id_lower:
            return SourceVulnType.COMMAND_INJECTION
        elif "sql" in rule_id_lower:
            return SourceVulnType.SQL_INJECTION
        elif "path" in rule_id_lower or "traversal" in rule_id_lower:
            return SourceVulnType.PATH_TRAVERSAL
        elif "secret" in rule_id_lower or "credential" in rule_id_lower:
            return SourceVulnType.HARDCODED_SECRET
        elif "memory" in rule_id_lower or "leak" in rule_id_lower:
            return SourceVulnType.MEMORY_LEAK
        elif "race" in rule_id_lower:
            return SourceVulnType.RACE_CONDITION
        elif "integer" in rule_id_lower:
            return SourceVulnType.INTEGER_OVERFLOW
        else:
            return SourceVulnType.OTHER


def analyze_source(source_path: str, tools: List[str] = None) -> SourceAnalysisReport:
    """
    Convenience function for source analysis.

    Args:
        source_path: Path to source file or directory
        tools: Tools to use (builtin, bearer, patterns)

    Returns:
        SourceAnalysisReport
    """
    analyzer = SourceAnalyzer(source_path)
    return analyzer.analyze(tools)
