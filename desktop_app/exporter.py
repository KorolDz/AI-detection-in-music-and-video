from __future__ import annotations

from pathlib import Path

from .application.report_formatter import ReportFormatter
from .models import AnalysisResult


def export_result_to_txt(result: AnalysisResult, destination: str | Path) -> Path:
    if not result.export_payload:
        result.export_payload = ReportFormatter().build_export_payload(result)
    return ReportFormatter.export_result_to_txt(result, destination)
