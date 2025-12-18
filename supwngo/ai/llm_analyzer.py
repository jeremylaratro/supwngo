"""
LLM-powered vulnerability analysis.

Uses large language models (Claude, GPT) to analyze decompiled code
for security vulnerabilities that static analysis might miss.
"""

import json
import os
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Union

from supwngo.core.binary import Binary
from supwngo.utils.logging import get_logger

logger = get_logger(__name__)

# Try to import LLM libraries
try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False


class VulnSeverity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = auto()   # RCE, privilege escalation
    HIGH = auto()       # Memory corruption, info leak
    MEDIUM = auto()     # DoS, limited impact
    LOW = auto()        # Minor issues
    INFO = auto()       # Informational


class VulnCategory(Enum):
    """Vulnerability categories."""
    BUFFER_OVERFLOW = "Buffer Overflow"
    HEAP_OVERFLOW = "Heap Overflow"
    FORMAT_STRING = "Format String"
    USE_AFTER_FREE = "Use After Free"
    DOUBLE_FREE = "Double Free"
    INTEGER_OVERFLOW = "Integer Overflow"
    RACE_CONDITION = "Race Condition"
    COMMAND_INJECTION = "Command Injection"
    PATH_TRAVERSAL = "Path Traversal"
    NULL_DEREF = "Null Pointer Dereference"
    UNINITIALIZED = "Uninitialized Memory"
    LOGIC_BUG = "Logic Bug"
    TYPE_CONFUSION = "Type Confusion"
    OTHER = "Other"


@dataclass
class LLMFinding:
    """Represents a vulnerability found by LLM analysis."""
    category: VulnCategory
    severity: VulnSeverity
    confidence: float               # 0.0 - 1.0
    location: str                   # Function/line
    description: str
    exploit_hint: str = ""
    cwe_id: Optional[str] = None    # e.g., "CWE-121"
    affected_code: str = ""         # Relevant code snippet
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "category": self.category.value,
            "severity": self.severity.name,
            "confidence": self.confidence,
            "location": self.location,
            "description": self.description,
            "exploit_hint": self.exploit_hint,
            "cwe_id": self.cwe_id,
            "affected_code": self.affected_code,
            "remediation": self.remediation,
        }

    def __str__(self) -> str:
        return f"[{self.severity.name}] {self.category.value} in {self.location} ({self.confidence:.0%})"


@dataclass
class AnalysisConfig:
    """Configuration for LLM analysis."""
    model: str = "claude-sonnet-4-20250514"  # or "gpt-4-turbo"
    provider: str = "anthropic"              # or "openai"
    max_tokens: int = 4096
    temperature: float = 0.1                  # Low for consistent analysis
    analyze_all_functions: bool = False       # True = more thorough, slower
    focus_dangerous_funcs: bool = True        # Prioritize dangerous function calls
    include_context: bool = True              # Include surrounding code


class LLMVulnAnalyzer:
    """
    LLM-powered vulnerability analyzer.

    Uses Claude or GPT to analyze decompiled binary code for vulnerabilities.

    Example:
        analyzer = LLMVulnAnalyzer()

        # Analyze a single function
        findings = analyzer.analyze_function(decompiled_code)

        # Analyze entire binary
        all_findings = analyzer.analyze_binary(binary)

        # Get exploit strategy
        strategy = analyzer.suggest_exploit_strategy(binary, findings[0])
    """

    ANALYSIS_PROMPT = """You are an expert binary security researcher specializing in vulnerability discovery and exploitation.

Analyze the following decompiled C code for security vulnerabilities. Be thorough but precise - only report findings you are confident about.

Focus on:
1. **Buffer Overflows** - Stack and heap based
2. **Format String Vulnerabilities** - Uncontrolled format specifiers
3. **Integer Issues** - Overflows, underflows, truncation
4. **Memory Safety** - Use-after-free, double-free, uninitialized memory
5. **Race Conditions** - TOCTOU, signal handlers
6. **Injection** - Command injection, path traversal
7. **Logic Bugs** - Authentication bypass, incorrect validation

For EACH vulnerability found, provide a JSON object with:
- "category": One of [Buffer Overflow, Heap Overflow, Format String, Use After Free, Double Free, Integer Overflow, Race Condition, Command Injection, Path Traversal, Null Pointer Dereference, Uninitialized Memory, Logic Bug, Type Confusion, Other]
- "severity": One of [CRITICAL, HIGH, MEDIUM, LOW, INFO]
- "confidence": Float 0.0-1.0 (how certain you are)
- "location": Function name and approximate line/region
- "description": Brief technical description
- "exploit_hint": How this could be exploited
- "cwe_id": CWE identifier if known (e.g., "CWE-121")
- "affected_code": The vulnerable code snippet
- "remediation": How to fix it

Return a JSON array of findings. If no vulnerabilities found, return [].

CODE TO ANALYZE:
```c
{code}
```

RESPOND WITH ONLY THE JSON ARRAY, NO OTHER TEXT."""

    STRATEGY_PROMPT = """You are an expert exploit developer. Given the following binary and vulnerability information, provide a detailed exploitation strategy.

BINARY INFORMATION:
- Path: {binary_path}
- Architecture: {arch}
- Protections: {protections}

VULNERABILITY:
- Type: {vuln_type}
- Location: {location}
- Description: {description}

Provide a step-by-step exploitation strategy including:
1. Information gathering (what leaks are needed)
2. Protection bypass approach
3. Payload construction
4. Specific techniques (ROP gadgets, heap feng shui, etc.)
5. Expected challenges and mitigations

Be specific and technical. Include example code snippets where helpful."""

    def __init__(
        self,
        config: Optional[AnalysisConfig] = None,
        api_key: Optional[str] = None
    ):
        """
        Initialize LLM analyzer.

        Args:
            config: Analysis configuration
            api_key: API key (or use environment variable)
        """
        self.config = config or AnalysisConfig()
        self.api_key = api_key

        # Initialize client based on provider
        if self.config.provider == "anthropic":
            if not ANTHROPIC_AVAILABLE:
                raise ImportError("anthropic package required. Install with: pip install anthropic")
            self.client = anthropic.Anthropic(
                api_key=api_key or os.environ.get("ANTHROPIC_API_KEY")
            )
        elif self.config.provider == "openai":
            if not OPENAI_AVAILABLE:
                raise ImportError("openai package required. Install with: pip install openai")
            self.client = openai.OpenAI(
                api_key=api_key or os.environ.get("OPENAI_API_KEY")
            )
        else:
            raise ValueError(f"Unknown provider: {self.config.provider}")

        logger.debug(f"LLMVulnAnalyzer initialized with {self.config.provider}/{self.config.model}")

    def analyze_function(self, code: str) -> List[LLMFinding]:
        """
        Analyze a single decompiled function for vulnerabilities.

        Args:
            code: Decompiled C code

        Returns:
            List of findings
        """
        prompt = self.ANALYSIS_PROMPT.format(code=code)

        try:
            response = self._query_llm(prompt)
            return self._parse_findings(response)
        except Exception as e:
            logger.error(f"Error analyzing function: {e}")
            return []

    def analyze_binary(
        self,
        binary: Binary,
        decompiler: Optional[Any] = None
    ) -> List[LLMFinding]:
        """
        Analyze all functions in a binary.

        Args:
            binary: Target binary
            decompiler: Optional decompiler instance

        Returns:
            List of all findings
        """
        all_findings = []

        # Get decompiler
        if decompiler is None:
            try:
                from supwngo.analysis.decompile import GhidraDecompiler
                decompiler = GhidraDecompiler()
            except ImportError:
                logger.error("No decompiler available")
                return []

        # Determine which functions to analyze
        if self.config.focus_dangerous_funcs:
            # Prioritize functions that call dangerous functions
            functions = self._get_priority_functions(binary)
        else:
            functions = list(binary.functions.keys())

        logger.info(f"Analyzing {len(functions)} functions")

        for func_name in functions:
            func_addr = binary.functions.get(func_name)
            if func_addr is None:
                continue

            # Decompile function
            try:
                decompiled = decompiler.decompile_function(binary.path, func_addr)
                if decompiled:
                    findings = self.analyze_function(decompiled)
                    all_findings.extend(findings)
            except Exception as e:
                logger.debug(f"Error decompiling {func_name}: {e}")
                continue

        # Deduplicate findings
        all_findings = self._deduplicate(all_findings)

        return all_findings

    def suggest_exploit_strategy(
        self,
        binary: Binary,
        vulnerability: LLMFinding
    ) -> str:
        """
        Get natural language exploit strategy suggestion.

        Args:
            binary: Target binary
            vulnerability: Vulnerability to exploit

        Returns:
            Detailed exploitation strategy
        """
        prompt = self.STRATEGY_PROMPT.format(
            binary_path=binary.path,
            arch=binary.arch,
            protections=str(binary.protections),
            vuln_type=vulnerability.category.value,
            location=vulnerability.location,
            description=vulnerability.description
        )

        try:
            return self._query_llm(prompt)
        except Exception as e:
            logger.error(f"Error getting exploit strategy: {e}")
            return ""

    def analyze_crash(
        self,
        binary: Binary,
        crash_input: bytes,
        crash_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Analyze a crash to determine exploitability.

        Args:
            binary: Crashed binary
            crash_input: Input that caused crash
            crash_info: Crash information (registers, backtrace, etc.)

        Returns:
            Analysis results including exploitability assessment
        """
        prompt = f"""Analyze this crash for exploitability:

BINARY: {binary.path}
ARCHITECTURE: {binary.arch}
PROTECTIONS: {binary.protections}

CRASH INPUT (hex): {crash_input.hex()[:200]}...
CRASH INPUT (ascii): {crash_input[:100]}...

CRASH INFO:
{json.dumps(crash_info, indent=2)}

Determine:
1. Root cause of crash
2. Type of vulnerability (buffer overflow, use-after-free, etc.)
3. Exploitability rating (EXPLOITABLE, PROBABLY_EXPLOITABLE, UNKNOWN, NOT_EXPLOITABLE)
4. Exploitation difficulty (EASY, MEDIUM, HARD)
5. Suggested exploitation approach

Respond with JSON."""

        try:
            response = self._query_llm(prompt)
            return json.loads(response)
        except Exception as e:
            logger.error(f"Error analyzing crash: {e}")
            return {"error": str(e)}

    def _query_llm(self, prompt: str) -> str:
        """Query the LLM and return response."""
        if self.config.provider == "anthropic":
            response = self.client.messages.create(
                model=self.config.model,
                max_tokens=self.config.max_tokens,
                temperature=self.config.temperature,
                messages=[{"role": "user", "content": prompt}]
            )
            return response.content[0].text

        elif self.config.provider == "openai":
            response = self.client.chat.completions.create(
                model=self.config.model,
                max_tokens=self.config.max_tokens,
                temperature=self.config.temperature,
                messages=[{"role": "user", "content": prompt}]
            )
            return response.choices[0].message.content

        raise ValueError(f"Unknown provider: {self.config.provider}")

    def _parse_findings(self, response: str) -> List[LLMFinding]:
        """Parse LLM response into findings."""
        findings = []

        try:
            # Try to extract JSON from response
            # Handle case where response has extra text
            json_start = response.find('[')
            json_end = response.rfind(']') + 1

            if json_start != -1 and json_end > json_start:
                json_str = response[json_start:json_end]
                data = json.loads(json_str)

                for item in data:
                    try:
                        # Map category string to enum
                        category = VulnCategory.OTHER
                        for cat in VulnCategory:
                            if cat.value.lower() == item.get("category", "").lower():
                                category = cat
                                break

                        # Map severity string to enum
                        severity = VulnSeverity.MEDIUM
                        sev_str = item.get("severity", "MEDIUM").upper()
                        for sev in VulnSeverity:
                            if sev.name == sev_str:
                                severity = sev
                                break

                        finding = LLMFinding(
                            category=category,
                            severity=severity,
                            confidence=float(item.get("confidence", 0.5)),
                            location=item.get("location", "unknown"),
                            description=item.get("description", ""),
                            exploit_hint=item.get("exploit_hint", ""),
                            cwe_id=item.get("cwe_id"),
                            affected_code=item.get("affected_code", ""),
                            remediation=item.get("remediation", ""),
                        )
                        findings.append(finding)

                    except Exception as e:
                        logger.debug(f"Error parsing finding: {e}")
                        continue

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM response as JSON: {e}")

        return findings

    def _get_priority_functions(self, binary: Binary) -> List[str]:
        """Get list of functions to prioritize for analysis."""
        priority = []

        # Functions that call dangerous functions
        dangerous = {
            'gets', 'strcpy', 'strcat', 'sprintf', 'vsprintf',
            'printf', 'fprintf', 'scanf', 'fscanf', 'sscanf',
            'read', 'recv', 'recvfrom', 'memcpy', 'memmove',
            'system', 'popen', 'execve', 'execl', 'execlp',
            'malloc', 'free', 'realloc', 'calloc'
        }

        # Check which functions in binary call dangerous functions
        for func_name in binary.functions:
            # Would need proper analysis here - simplified
            priority.append(func_name)

        return priority[:20]  # Limit for performance

    def _deduplicate(self, findings: List[LLMFinding]) -> List[LLMFinding]:
        """Remove duplicate findings."""
        seen = set()
        unique = []

        for finding in findings:
            key = (finding.category, finding.location, finding.description[:50])
            if key not in seen:
                seen.add(key)
                unique.append(finding)

        return unique


# Convenience function
def analyze_with_llm(
    code_or_binary: Union[str, Binary],
    api_key: Optional[str] = None,
    provider: str = "anthropic"
) -> List[LLMFinding]:
    """
    Analyze code or binary using LLM.

    Args:
        code_or_binary: Decompiled code string or Binary object
        api_key: API key (or use environment variable)
        provider: "anthropic" or "openai"

    Returns:
        List of vulnerability findings
    """
    config = AnalysisConfig(provider=provider)
    analyzer = LLMVulnAnalyzer(config, api_key)

    if isinstance(code_or_binary, str):
        return analyzer.analyze_function(code_or_binary)
    elif isinstance(code_or_binary, Binary):
        return analyzer.analyze_binary(code_or_binary)
    else:
        raise TypeError("Expected str or Binary")
