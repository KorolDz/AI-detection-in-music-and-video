from __future__ import annotations

from pathlib import Path

from .application.report_formatter import ReportFormatter
from .models import AnalysisResult


def export_result(result: AnalysisResult, destination: str | Path, file_format: str) -> Path:
    formatter = ReportFormatter()
    normalized = file_format.lower()
    if normalized == "txt":
        if not result.export_payload:
            result.export_payload = formatter.build_export_payload(result)
        return formatter.export_result_to_txt(result, destination)
    if normalized == "html":
        return formatter.export_result_to_html(result, destination)
    if normalized == "pdf":
        return formatter.export_result_to_pdf(result, destination)
    raise ValueError(f"Неподдерживаемый формат экспорта: {file_format}")


def export_result_to_txt(result: AnalysisResult, destination: str | Path) -> Path:
    return export_result(result, destination, "txt")


def export_result_to_html(result: AnalysisResult, destination: str | Path) -> Path:
    return export_result(result, destination, "html")


def export_result_to_pdf(result: AnalysisResult, destination: str | Path) -> Path:
    return export_result(result, destination, "pdf")
