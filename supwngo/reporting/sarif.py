"""
SARIF (Static Analysis Results Interchange Format) exporter.

Generates SARIF v2.1.0 reports for integration with security tools.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
import hashlib

from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class SARIFLocation:
    """Location information for SARIF."""
    file_path: str
    start_line: int = 0
    end_line: int = 0
    start_column: int = 0
    end_column: int = 0
    address: int = 0  # For binary analysis


@dataclass
class SARIFResult:
    """Single result/finding for SARIF."""
    rule_id: str
    message: str
    level: str = "warning"  # none, note, warning, error
    locations: List[SARIFLocation] = field(default_factory=list)
    fingerprint: str = ""
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SARIFRule:
    """Rule definition for SARIF."""
    id: str
    name: str
    short_description: str
    full_description: str = ""
    help_uri: str = ""
    default_level: str = "warning"
    properties: Dict[str, Any] = field(default_factory=dict)


class SARIFExporter:
    """
    Export analysis results in SARIF format.

    SARIF (Static Analysis Results Interchange Format) is an OASIS standard
    for representing static analysis results. It's supported by GitHub,
    Azure DevOps, and many security tools.

    Example:
        exporter = SARIFExporter(
            tool_name="supwngo",
            tool_version="1.0.0"
        )

        # Add rules
        exporter.add_rule(SARIFRule(
            id="SUPWNGO001",
            name="stack-buffer-overflow",
            short_description="Stack buffer overflow vulnerability",
        ))

        # Add results
        exporter.add_result(SARIFResult(
            rule_id="SUPWNGO001",
            message="Buffer overflow in vulnerable_function",
            level="error",
            locations=[SARIFLocation(
                file_path="target_binary",
                address=0x401234,
            )],
        ))

        # Export
        sarif_json = exporter.export()
    """

    # Rule definitions for common vulnerability types
    VULN_RULES = {
        "stack_buffer_overflow": SARIFRule(
            id="SUPWNGO001",
            name="stack-buffer-overflow",
            short_description="Stack buffer overflow detected",
            full_description="A stack-based buffer overflow vulnerability allows "
                           "an attacker to overwrite stack memory, potentially "
                           "leading to code execution.",
            default_level="error",
            properties={"security-severity": "9.8"},
        ),
        "heap_buffer_overflow": SARIFRule(
            id="SUPWNGO002",
            name="heap-buffer-overflow",
            short_description="Heap buffer overflow detected",
            full_description="A heap-based buffer overflow vulnerability allows "
                           "an attacker to corrupt heap metadata or adjacent data.",
            default_level="error",
            properties={"security-severity": "8.1"},
        ),
        "format_string": SARIFRule(
            id="SUPWNGO003",
            name="format-string-vulnerability",
            short_description="Format string vulnerability detected",
            full_description="A format string vulnerability allows an attacker to "
                           "read from or write to arbitrary memory locations.",
            default_level="error",
            properties={"security-severity": "7.5"},
        ),
        "use_after_free": SARIFRule(
            id="SUPWNGO004",
            name="use-after-free",
            short_description="Use-after-free vulnerability detected",
            full_description="A use-after-free vulnerability occurs when memory "
                           "is accessed after being freed.",
            default_level="error",
            properties={"security-severity": "8.1"},
        ),
        "double_free": SARIFRule(
            id="SUPWNGO005",
            name="double-free",
            short_description="Double-free vulnerability detected",
            full_description="A double-free vulnerability occurs when memory "
                           "is freed multiple times.",
            default_level="error",
            properties={"security-severity": "7.5"},
        ),
        "integer_overflow": SARIFRule(
            id="SUPWNGO006",
            name="integer-overflow",
            short_description="Integer overflow detected",
            full_description="An integer overflow can lead to incorrect calculations "
                           "and potentially exploitable conditions.",
            default_level="warning",
            properties={"security-severity": "5.3"},
        ),
        "dangerous_function": SARIFRule(
            id="SUPWNGO007",
            name="dangerous-function-usage",
            short_description="Dangerous function usage detected",
            full_description="The binary uses functions known to be unsafe "
                           "(e.g., gets, strcpy without bounds checking).",
            default_level="warning",
            properties={"security-severity": "6.5"},
        ),
        "missing_protection": SARIFRule(
            id="SUPWNGO008",
            name="missing-security-protection",
            short_description="Missing security protection",
            full_description="The binary is missing recommended security "
                           "protections (NX, Canary, PIE, RELRO).",
            default_level="note",
            properties={"security-severity": "3.0"},
        ),
        "race_condition": SARIFRule(
            id="SUPWNGO009",
            name="race-condition",
            short_description="Potential race condition detected",
            full_description="A race condition may allow an attacker to exploit "
                           "timing-dependent behavior.",
            default_level="warning",
            properties={"security-severity": "5.9"},
        ),
        "hardcoded_credential": SARIFRule(
            id="SUPWNGO010",
            name="hardcoded-credential",
            short_description="Hardcoded credential detected",
            full_description="Hardcoded credentials in binaries can be extracted "
                           "and used by attackers.",
            default_level="error",
            properties={"security-severity": "7.5"},
        ),
    }

    def __init__(
        self,
        tool_name: str = "supwngo",
        tool_version: str = "1.0.0",
        tool_uri: str = "https://github.com/supwngo/supwngo",
    ):
        """
        Initialize SARIF exporter.

        Args:
            tool_name: Name of the analysis tool
            tool_version: Tool version
            tool_uri: Tool information URI
        """
        self.tool_name = tool_name
        self.tool_version = tool_version
        self.tool_uri = tool_uri

        self.rules: Dict[str, SARIFRule] = {}
        self.results: List[SARIFResult] = []
        self.artifacts: List[Dict[str, Any]] = []

    def add_rule(self, rule: SARIFRule):
        """Add a rule definition."""
        self.rules[rule.id] = rule

    def add_result(self, result: SARIFResult):
        """Add a finding/result."""
        # Auto-add rule if using predefined vuln type
        if result.rule_id not in self.rules:
            for vuln_type, rule in self.VULN_RULES.items():
                if rule.id == result.rule_id:
                    self.add_rule(rule)
                    break

        # Generate fingerprint if not provided
        if not result.fingerprint:
            fp_data = f"{result.rule_id}:{result.message}"
            if result.locations:
                fp_data += f":{result.locations[0].file_path}"
                fp_data += f":{result.locations[0].address}"
            result.fingerprint = hashlib.sha256(fp_data.encode()).hexdigest()[:32]

        self.results.append(result)

    def add_artifact(self, file_path: str, mime_type: str = "application/octet-stream"):
        """Add an analyzed artifact (binary)."""
        artifact = {
            "location": {
                "uri": file_path,
            },
            "mimeType": mime_type,
        }

        # Try to get file hash
        try:
            path = Path(file_path)
            if path.exists():
                content = path.read_bytes()
                artifact["hashes"] = {
                    "sha-256": hashlib.sha256(content).hexdigest(),
                }
                artifact["length"] = len(content)
        except Exception:
            pass

        self.artifacts.append(artifact)

    def add_vulnerability(
        self,
        vuln_type: str,
        message: str,
        file_path: str,
        address: int = 0,
        line: int = 0,
        severity: str = "error",
        properties: Dict[str, Any] = None,
    ):
        """
        Convenience method to add a vulnerability finding.

        Args:
            vuln_type: Vulnerability type key
            message: Description message
            file_path: Path to affected file/binary
            address: Memory address (for binary analysis)
            line: Line number (for source analysis)
            severity: Severity level
            properties: Additional properties
        """
        # Get or create rule
        vuln_key = vuln_type.lower().replace("-", "_").replace(" ", "_")
        if vuln_key in self.VULN_RULES:
            rule = self.VULN_RULES[vuln_key]
            if rule.id not in self.rules:
                self.add_rule(rule)
            rule_id = rule.id
        else:
            # Create generic rule
            rule_id = f"SUPWNGO999"
            if rule_id not in self.rules:
                self.add_rule(SARIFRule(
                    id=rule_id,
                    name=vuln_type,
                    short_description=f"{vuln_type} vulnerability",
                ))

        location = SARIFLocation(
            file_path=file_path,
            start_line=line,
            address=address,
        )

        result = SARIFResult(
            rule_id=rule_id,
            message=message,
            level=severity,
            locations=[location],
            properties=properties or {},
        )

        self.add_result(result)

    def export(self) -> Dict[str, Any]:
        """
        Export to SARIF v2.1.0 format.

        Returns:
            SARIF JSON structure as dictionary
        """
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.tool_name,
                            "version": self.tool_version,
                            "informationUri": self.tool_uri,
                            "rules": self._export_rules(),
                        }
                    },
                    "results": self._export_results(),
                    "artifacts": self.artifacts if self.artifacts else None,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": datetime.utcnow().isoformat() + "Z",
                        }
                    ],
                }
            ],
        }

        # Remove None values
        if sarif["runs"][0]["artifacts"] is None:
            del sarif["runs"][0]["artifacts"]

        return sarif

    def _export_rules(self) -> List[Dict[str, Any]]:
        """Export rule definitions."""
        rules = []
        for rule in self.rules.values():
            rule_dict = {
                "id": rule.id,
                "name": rule.name,
                "shortDescription": {
                    "text": rule.short_description
                },
                "defaultConfiguration": {
                    "level": rule.default_level
                },
            }

            if rule.full_description:
                rule_dict["fullDescription"] = {
                    "text": rule.full_description
                }

            if rule.help_uri:
                rule_dict["helpUri"] = rule.help_uri

            if rule.properties:
                rule_dict["properties"] = rule.properties

            rules.append(rule_dict)

        return rules

    def _export_results(self) -> List[Dict[str, Any]]:
        """Export results/findings."""
        results = []
        for result in self.results:
            result_dict = {
                "ruleId": result.rule_id,
                "level": result.level,
                "message": {
                    "text": result.message
                },
            }

            if result.locations:
                result_dict["locations"] = []
                for loc in result.locations:
                    loc_dict = {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": loc.file_path
                            }
                        }
                    }

                    # Add region if we have line info
                    if loc.start_line > 0:
                        loc_dict["physicalLocation"]["region"] = {
                            "startLine": loc.start_line,
                        }
                        if loc.end_line > 0:
                            loc_dict["physicalLocation"]["region"]["endLine"] = loc.end_line
                        if loc.start_column > 0:
                            loc_dict["physicalLocation"]["region"]["startColumn"] = loc.start_column

                    # Add address for binary analysis
                    if loc.address > 0:
                        loc_dict["physicalLocation"]["address"] = {
                            "absoluteAddress": loc.address
                        }

                    result_dict["locations"].append(loc_dict)

            if result.fingerprint:
                result_dict["fingerprints"] = {
                    "primary": result.fingerprint
                }

            if result.properties:
                result_dict["properties"] = result.properties

            results.append(result_dict)

        return results

    def export_json(self, indent: int = 2) -> str:
        """Export to SARIF JSON string."""
        return json.dumps(self.export(), indent=indent)

    def save(self, output_path: str):
        """
        Save SARIF report to file.

        Args:
            output_path: Output file path
        """
        path = Path(output_path)
        path.write_text(self.export_json())
        logger.info(f"SARIF report saved to {output_path}")


def export_to_sarif(
    vulnerabilities: List[Dict[str, Any]],
    binary_path: str,
    output_path: Optional[str] = None,
) -> str:
    """
    Convenience function to export vulnerabilities to SARIF.

    Args:
        vulnerabilities: List of vulnerability dictionaries
        binary_path: Path to analyzed binary
        output_path: Optional output file path

    Returns:
        SARIF JSON string
    """
    exporter = SARIFExporter()
    exporter.add_artifact(binary_path)

    for vuln in vulnerabilities:
        exporter.add_vulnerability(
            vuln_type=vuln.get("type", "unknown"),
            message=vuln.get("description", "Vulnerability detected"),
            file_path=binary_path,
            address=vuln.get("address", 0),
            severity=vuln.get("severity", "warning"),
        )

    if output_path:
        exporter.save(output_path)

    return exporter.export_json()
