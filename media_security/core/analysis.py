from __future__ import annotations

from media_security.core.models import Finding, ScanReport, Severity

SEVERITY_PENALTY = {
    Severity.HIGH: 40,
    Severity.WARNING: 15,
    Severity.INFO: 0,
}


def choose_verdict(findings: list[Finding]) -> str:
    if any(finding.severity == Severity.HIGH for finding in findings):
        return "fail"
    if any(finding.severity == Severity.WARNING for finding in findings):
        return "warning"
    return "pass"


def calculate_trust_score(findings: list[Finding]) -> int:
    penalty = sum(SEVERITY_PENALTY[finding.severity] for finding in findings)
    return max(0, 100 - penalty)


def risk_level_from_score(score: int) -> str:
    if score >= 85:
        return "low"
    if score >= 60:
        return "medium"
    if score >= 30:
        return "high"
    return "critical"


def refresh_report_assessment(report: ScanReport) -> None:
    report.verdict = choose_verdict(report.findings)
    report.trust_score = calculate_trust_score(report.findings)
    report.risk_level = risk_level_from_score(report.trust_score)
