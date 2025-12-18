"""
Report templates for vulnerability and exploit documentation.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class VulnerabilityFinding:
    """Single vulnerability finding."""
    vuln_type: str
    severity: str
    description: str
    location: str = ""
    address: int = 0
    confidence: float = 0.0
    cvss_score: float = 0.0
    cvss_vector: str = ""
    recommendations: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    proof_of_concept: str = ""


@dataclass
class BinaryInfo:
    """Binary analysis information."""
    name: str
    path: str
    architecture: str = ""
    bits: int = 0
    endianness: str = "little"
    file_size: int = 0
    file_hash: str = ""
    protections: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VulnerabilityReport:
    """
    Vulnerability assessment report.

    Contains all findings from binary analysis with severity ratings
    and remediation recommendations.
    """
    title: str
    binary: BinaryInfo
    findings: List[VulnerabilityFinding] = field(default_factory=list)
    summary: str = ""
    analyst: str = ""
    date: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_finding(self, finding: VulnerabilityFinding):
        """Add a vulnerability finding."""
        self.findings.append(finding)

    def get_severity_counts(self) -> Dict[str, int]:
        """Get count of findings by severity."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in self.findings:
            sev = finding.severity.lower()
            if sev in counts:
                counts[sev] += 1
        return counts

    def get_overall_risk(self) -> str:
        """Calculate overall risk level."""
        counts = self.get_severity_counts()
        if counts["critical"] > 0:
            return "Critical"
        elif counts["high"] > 0:
            return "High"
        elif counts["medium"] > 0:
            return "Medium"
        elif counts["low"] > 0:
            return "Low"
        return "Informational"


@dataclass
class ExploitStep:
    """Single step in exploit chain."""
    step_number: int
    description: str
    code: str = ""
    notes: str = ""


@dataclass
class ExploitReport:
    """
    Exploit documentation report.

    Documents the exploitation process, techniques used,
    and provides proof-of-concept code.
    """
    title: str
    binary: BinaryInfo
    vulnerability: VulnerabilityFinding
    exploit_type: str = ""
    techniques: List[str] = field(default_factory=list)
    steps: List[ExploitStep] = field(default_factory=list)
    payload: str = ""
    payload_hex: str = ""
    script: str = ""
    success_rate: float = 0.0
    requirements: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    date: str = field(default_factory=lambda: datetime.now().isoformat())

    def add_step(self, description: str, code: str = "", notes: str = ""):
        """Add an exploitation step."""
        step = ExploitStep(
            step_number=len(self.steps) + 1,
            description=description,
            code=code,
            notes=notes,
        )
        self.steps.append(step)


@dataclass
class AssessmentReport:
    """
    Full security assessment report.

    Comprehensive report combining vulnerability findings,
    exploitation analysis, and recommendations.
    """
    title: str
    executive_summary: str = ""
    scope: str = ""
    methodology: str = ""
    binaries: List[BinaryInfo] = field(default_factory=list)
    vulnerability_reports: List[VulnerabilityReport] = field(default_factory=list)
    exploit_reports: List[ExploitReport] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    conclusion: str = ""
    analyst: str = ""
    organization: str = ""
    date: str = field(default_factory=lambda: datetime.now().isoformat())
    classification: str = "Confidential"

    def add_binary(self, binary: BinaryInfo):
        """Add analyzed binary."""
        self.binaries.append(binary)

    def add_vulnerability_report(self, report: VulnerabilityReport):
        """Add vulnerability report."""
        self.vulnerability_reports.append(report)

    def add_exploit_report(self, report: ExploitReport):
        """Add exploit report."""
        self.exploit_reports.append(report)

    def get_total_findings(self) -> int:
        """Get total number of findings."""
        return sum(len(r.findings) for r in self.vulnerability_reports)

    def get_severity_summary(self) -> Dict[str, int]:
        """Get combined severity counts across all reports."""
        totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for report in self.vulnerability_reports:
            counts = report.get_severity_counts()
            for sev, count in counts.items():
                totals[sev] += count
        return totals

    def generate_executive_summary(self) -> str:
        """Auto-generate executive summary."""
        total = self.get_total_findings()
        severity = self.get_severity_summary()
        binary_count = len(self.binaries)
        exploit_count = len(self.exploit_reports)

        summary = f"""This security assessment analyzed {binary_count} binary target(s) and identified {total} vulnerability finding(s).

Severity Distribution:
- Critical: {severity['critical']}
- High: {severity['high']}
- Medium: {severity['medium']}
- Low: {severity['low']}
- Informational: {severity['info']}

"""
        if exploit_count > 0:
            summary += f"Proof-of-concept exploits were developed for {exploit_count} vulnerabilities, demonstrating practical exploitability.\n\n"

        if severity['critical'] > 0 or severity['high'] > 0:
            summary += "IMMEDIATE ACTION REQUIRED: Critical and/or high severity vulnerabilities were identified that pose significant risk and should be remediated promptly.\n"
        elif severity['medium'] > 0:
            summary += "Several medium severity issues were identified that should be addressed in the near term to improve security posture.\n"
        else:
            summary += "No critical issues were identified. Minor improvements are recommended to enhance overall security.\n"

        return summary
