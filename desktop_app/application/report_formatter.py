from __future__ import annotations

from datetime import datetime
from pathlib import Path

from desktop_app.domain import AnalysisResult


class ReportFormatter:
    def build_export_payload(self, result: AnalysisResult) -> str:
        lines = [
            "Отчет о проверке медиафайла",
            f"Дата и время анализа: {self._format_datetime(result.analyzed_at)}",
            f"Имя файла: {result.file_name}",
            f"Тип медиа: {result.media_type}",
            f"Итоговый статус: {result.display_status}",
        ]

        if result.analysis_id is not None:
            lines.append(f"Идентификатор анализа: {result.analysis_id}")
        if result.probability is not None:
            lines.append(f"Вероятность подделки: {result.probability:.4f}")
        if result.threshold is not None:
            lines.append(f"Порог классификации: {result.threshold:.4f}")
        if result.file_sha256:
            lines.append(f"SHA-256 файла: {result.file_sha256}")
        if result.stored_at is not None:
            lines.append(f"Дата сохранения: {self._format_datetime(result.stored_at)}")

        lines.append(f"Сводка: {result.summary}")

        if result.indicators:
            lines.append("")
            lines.append("Выявленные признаки:")
            lines.extend(f"- {item}" for item in result.indicators)

        if result.technical_details:
            lines.append("")
            lines.append("Технические наблюдения:")
            lines.extend(f"- {item}" for item in result.technical_details)

        if result.error_message:
            lines.append("")
            lines.append(f"Сообщение об ошибке: {result.error_message}")

        if result.report_path:
            lines.append("")
            lines.append(f"Путь к отчету: {result.report_path}")

        return "\n".join(lines) + "\n"

    @staticmethod
    def export_result_to_txt(result: AnalysisResult, destination: str | Path) -> Path:
        destination_path = Path(destination)
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        destination_path.write_text(result.export_payload, encoding="utf-8")
        return destination_path

    @staticmethod
    def _format_datetime(value: datetime | None) -> str:
        if value is None:
            return "-"
        return value.strftime("%Y-%m-%d %H:%M:%S")
