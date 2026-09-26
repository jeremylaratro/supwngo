"""Adapter from analysis output to the report data model.

The detectors in :mod:`supwngo.vulns` emit
:class:`~supwngo.vulns.detector.Vulnerability`; the report writers in this
package consume :class:`~supwngo.reporting.templates.VulnerabilityReport`.
Nothing connected the two, which is why ``reporting/`` shipped unreachable from
the CLI. This module is that connection.

Two honesty properties are load-bearing here, because a report is read as
evidence:

1. **A detector that raised is not a detector that found nothing.** ``detect_all``
   returns the failures alongside the findings, and :func:`build_report` records
   them in the report metadata. Without this, five crashed detectors and a clean
   binary produce the identical "0 findings" document.
2. **Unmeasured protections are not absent protections.** ``Binary`` tracks
   ``protections_measured`` precisely because "we never ran the check" must not
   render the same as "we checked and everything is off". :func:`binary_info`
   propagates that distinction instead of flattening it into a table of
   ``False``.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple, Type

from supwngo.core.binary import Binary
from supwngo.reporting.cvss import CVSSCalculator
from supwngo.reporting.templates import (
    BinaryInfo,
    VulnerabilityFinding,
    VulnerabilityReport,
)
from supwngo.utils.logging import get_logger
from supwngo.vulns.detector import Vulnerability, VulnerabilityDetector

logger = get_logger(__name__)


@dataclass(frozen=True)
class DetectorFailure:
    """A detector that could not complete.

    Kept as data rather than a log line so the report can state it. A failure
    silently logged is a failure the report's reader never learns about.
    """

    detector: str
    error: str


def static_detectors() -> List[Type[VulnerabilityDetector]]:
    """Detector classes that honour the ``detect(crash=None)`` base contract.

    ``UAFDetector`` and ``OffByOneDetector`` are deliberately excluded: their
    ``detect()`` takes no ``crash`` argument and they return their own vuln
    types (``UAFVuln``, ``OffByOneVuln``) rather than ``Vulnerability``, so they
    do not fit this adapter. Including them would raise ``TypeError`` at call
    time, which -- because failures are collected rather than raised -- would
    show up as a permanently failing detector rather than as a crash.
    """
    from supwngo.vulns.canary_bypass import CanaryBypassDetector
    from supwngo.vulns.format_string import FormatStringDetector
    from supwngo.vulns.heap import HeapVulnerabilityDetector
    from supwngo.vulns.integer import IntegerOverflowDetector
    from supwngo.vulns.stack_bof import StackBufferOverflowDetector

    return [
        StackBufferOverflowDetector,
        FormatStringDetector,
        IntegerOverflowDetector,
        HeapVulnerabilityDetector,
        CanaryBypassDetector,
    ]


def detect_all(
    binary: Binary,
    detectors: Optional[Sequence[Type[VulnerabilityDetector]]] = None,
) -> Tuple[List[Vulnerability], List[DetectorFailure]]:
    """Run each detector, returning findings **and** the ones that failed.

    A detector raising does not abort the run -- one broken detector should not
    cost the findings of the other four -- but it is never swallowed either.

    Returns:
        ``(vulnerabilities, failures)``. An empty ``vulnerabilities`` list means
        "nothing found" only when ``failures`` is also empty; callers must not
        report the former without the latter.
    """
    classes = list(detectors) if detectors is not None else static_detectors()
    found: List[Vulnerability] = []
    failures: List[DetectorFailure] = []

    for cls in classes:
        name = getattr(cls, "name", None) or cls.__name__
        try:
            found.extend(cls(binary).detect())
        except Exception as exc:  # noqa: BLE001 - recorded, not hidden
            failures.append(DetectorFailure(detector=name, error=f"{type(exc).__name__}: {exc}"))
            logger.warning("detector %s failed: %s", name, exc)

    return found, failures


def parse_failure_reason(binary: Binary) -> Optional[str]:
    """Why this binary could not be parsed, or ``None`` if it was.

    Neither loader setting ``arch`` means the file was never understood as an
    executable -- pwntools and pyelftools both rejected it. Detectors then run
    against an empty ``Binary`` and truthfully report nothing, which renders as
    a clean result for a file that was never read. ``PwntoolsLoadState``'s own
    docstring warns about exactly this: "a failed or skipped pwntools load must
    never be silently indistinguishable from 'this binary genuinely has no
    symbols'".

    ``protections_measured`` is deliberately *not* the test here: it requires
    the pwntools ELF specifically, so a host without pwntools would fail this
    check for binaries pyelftools parsed perfectly well.
    """
    if binary.arch:
        return None
    detail = binary.pwntools_load_error or "no loader identified an architecture"
    return (
        f"neither pwntools nor pyelftools could parse {binary.path.name} "
        f"({detail})"
    )


def binary_info(binary: Binary) -> BinaryInfo:
    """Describe the binary for the report header.

    ``protections`` carries a ``measured`` key. When protection detection never
    ran, the individual flags are omitted entirely rather than reported as
    ``False`` -- a reader who sees ``nx: false`` will conclude NX is off, which
    is a different claim from "we did not look".
    """
    if binary.protections_measured:
        protections: Dict[str, Any] = dict(binary.protections.to_dict())
        protections["measured"] = True
    else:
        protections = {
            "measured": False,
            "note": "protection detection did not run; absence of a flag here is "
                    "not evidence the protection is disabled",
        }

    try:
        file_size = binary.path.stat().st_size
    except OSError:
        file_size = 0

    return BinaryInfo(
        name=binary.path.name,
        path=str(binary.path),
        architecture=binary.arch,
        bits=binary.bits,
        endianness=binary.endian,
        file_size=file_size,
        file_hash=binary.sha256,
        protections=protections,
    )


def finding_from_vulnerability(
    vuln: Vulnerability,
    calculator: Optional[CVSSCalculator] = None,
    remote: bool = False,
) -> VulnerabilityFinding:
    """Convert one ``Vulnerability`` into a report finding, with a CVSS score.

    ``vuln_type`` is the lowercased enum name (``stack_buffer_overflow``), which
    is the key both :class:`CVSSCalculator` and :class:`SARIFExporter` look up.
    Types neither knows (``integer_underflow``, ``null_pointer_deref``,
    ``unknown``) fall back to a default CVSS vector and a generic SARIF rule
    rather than being dropped.
    """
    calc = calculator or CVSSCalculator()
    vuln_type = vuln.vuln_type.name.lower()
    severity = vuln.severity.name.lower()

    score = calc.score_vulnerability(vuln_type, remote=remote)

    location = vuln.function or (f"0x{vuln.address:x}" if vuln.address else "")
    description = vuln.description or f"{vuln_type.replace('_', ' ')} detected"

    return VulnerabilityFinding(
        vuln_type=vuln_type,
        severity=severity,
        description=description,
        location=location,
        address=vuln.address,
        confidence=vuln.confidence,
        cvss_score=score.base_score,
        cvss_vector=score.vector_string,
    )


def build_report(
    binary: Binary,
    vulnerabilities: Sequence[Vulnerability],
    failures: Sequence[DetectorFailure] = (),
    title: Optional[str] = None,
    analyst: str = "",
    remote: bool = False,
) -> VulnerabilityReport:
    """Assemble the report, recording detector failures in its metadata.

    The summary line states how many detectors failed. A report whose detectors
    all crashed says so on its face instead of presenting as a clean bill of
    health.
    """
    calc = CVSSCalculator()
    report = VulnerabilityReport(
        title=title or f"Vulnerability assessment: {binary.path.name}",
        binary=binary_info(binary),
        analyst=analyst,
    )

    for vuln in vulnerabilities:
        report.add_finding(finding_from_vulnerability(vuln, calculator=calc, remote=remote))

    counts = report.get_severity_counts()
    summary = (
        f"{len(report.findings)} finding(s): "
        + ", ".join(f"{n} {sev}" for sev, n in counts.items() if n)
        if report.findings
        else "No vulnerabilities were reported by the detectors that ran."
    )

    parse_failure = parse_failure_reason(binary)
    if parse_failure:
        summary += (
            f" The target was never parsed, so this is not a result: {parse_failure}."
        )
    if failures:
        summary += (
            f" {len(failures)} detector(s) failed to run, so this result is "
            f"incomplete: " + ", ".join(f.detector for f in failures) + "."
        )
    report.summary = summary

    report.metadata["detector_failures"] = [
        {"detector": f.detector, "error": f.error} for f in failures
    ]
    report.metadata["detectors_failed"] = len(failures)
    report.metadata["binary_parsed"] = parse_failure is None
    if parse_failure:
        report.metadata["parse_failure"] = parse_failure
    # An unparsed target makes the whole report incomplete, independently of
    # whether any detector raised: detectors that ran against an empty Binary
    # did not fail, they just had nothing to read.
    report.metadata["complete"] = not failures and parse_failure is None

    return report
