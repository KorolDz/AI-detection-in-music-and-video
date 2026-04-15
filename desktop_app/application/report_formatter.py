from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field
from datetime import datetime
from html import escape
from pathlib import Path

from desktop_app.domain import AnalysisResult


@dataclass(slots=True)
class ReportMetric:
    label: str
    value: str


@dataclass(slots=True)
class ReportSection:
    title: str
    items: list[str] = field(default_factory=list)


@dataclass(slots=True)
class StructuredReportViewModel:
    title: str
    subtitle: str
    file_name: str
    media_type: str
    status_label: str
    status_tone: str
    summary: str
    probability_percent: int
    probability_text: str
    threshold_text: str
    probability_available: bool
    probability_alert: bool
    metrics: list[ReportMetric] = field(default_factory=list)
    sections: list[ReportSection] = field(default_factory=list)


class ReportFormatter:
    def build_view_model(self, result: AnalysisResult) -> StructuredReportViewModel:
        probability_percent = result.probability_percent or 0
        probability_available = result.probability is not None
        threshold_percent = self._percent_text(result.threshold)
        probability_text = self._percent_text(result.probability)

        if result.is_error:
            status_tone = "error"
        elif result.is_fake:
            status_tone = "danger"
        else:
            status_tone = "success"

        metrics = [
            ReportMetric("Файл", result.file_name),
            ReportMetric("Тип медиа", result.media_type),
            ReportMetric(
                "Идентификатор анализа",
                str(result.analysis_id) if result.analysis_id is not None else "-",
            ),
            ReportMetric("Контроль целостности", result.integrity_status),
            ReportMetric("Хеш SHA-256", result.file_sha256 or "-"),
            ReportMetric("Время загрузки", self._format_datetime(result.uploaded_at)),
            ReportMetric("Старт анализа", self._format_datetime(result.analysis_started_at)),
            ReportMetric("Завершение анализа", self._format_datetime(result.analyzed_at)),
            ReportMetric("Сохранено", self._format_datetime(result.stored_at)),
        ]

        sections = [
            ReportSection("Подозрительные признаки", list(result.indicators)),
            ReportSection("Технические детали", list(result.technical_details)),
        ]
        if result.error_message:
            sections.append(ReportSection("Сообщение об ошибке", [result.error_message]))

        return StructuredReportViewModel(
            title="Отчет о проверке медиафайла",
            subtitle="Структурированное представление результата локального анализа",
            file_name=result.file_name,
            media_type=result.media_type,
            status_label=result.display_status,
            status_tone=status_tone,
            summary=result.summary,
            probability_percent=probability_percent,
            probability_text=probability_text,
            threshold_text=threshold_percent,
            probability_available=probability_available,
            probability_alert=bool(
                result.probability is not None
                and result.threshold is not None
                and result.probability > result.threshold
            ),
            metrics=metrics,
            sections=sections,
        )

    def build_export_payload(self, result: AnalysisResult) -> str:
        return self.render_txt(result)

    def render_txt(
        self,
        result_or_view_model: AnalysisResult | StructuredReportViewModel,
    ) -> str:
        view_model = self._ensure_view_model(result_or_view_model)

        lines = [
            view_model.title,
            view_model.subtitle,
            f"Имя файла: {view_model.file_name}",
            f"Тип медиа: {view_model.media_type}",
            f"Итоговый статус: {view_model.status_label}",
            f"Вероятность подделки: {view_model.probability_text}",
            f"Порог срабатывания: {view_model.threshold_text}",
            f"Сводка: {view_model.summary}",
            "",
            "Метрики отчета:",
        ]
        lines.extend(f"- {metric.label}: {metric.value}" for metric in view_model.metrics)

        for section in view_model.sections:
            lines.append("")
            lines.append(f"{section.title}:")
            if section.items:
                lines.extend(f"- {item}" for item in section.items)
            else:
                lines.append("- Нет данных")

        return "\n".join(lines) + "\n"

    def render_html(
        self,
        result_or_view_model: AnalysisResult | StructuredReportViewModel,
        *,
        output_profile: str = "screen",
    ) -> str:
        view_model = self._ensure_view_model(result_or_view_model)
        tone = self._tone_palette(view_model.status_tone)
        fill_width = view_model.probability_percent if view_model.probability_available else 0
        is_pdf = output_profile.lower() == "pdf"

        body_padding = "0" if is_pdf else "32px"
        body_background = "#ffffff" if is_pdf else "#f4efe7"
        page_rule = "@page { size: A4; margin: 14mm; }" if is_pdf else ""
        sheet_max_width = "none" if is_pdf else "980px"
        sheet_width = "100%" if is_pdf else "auto"
        sheet_border = "0" if is_pdf else "1px solid #ddd5c9"
        sheet_border_radius = "0" if is_pdf else "24px"
        sheet_box_shadow = "none" if is_pdf else "0 10px 30px rgba(24, 41, 47, 0.08)"
        hero_background = "#edf2f3" if is_pdf else "linear-gradient(135deg, #14384d 0%, #1c4e5a 56%, #2d685d 100%)"
        hero_foreground = "#173447" if is_pdf else "#fff8ef"
        eyebrow_color = "#5a6b74" if is_pdf else "rgba(255, 245, 230, 0.82)"
        subtitle_color = "#48626e" if is_pdf else "rgba(255, 246, 234, 0.88)"
        hero_border_bottom = "1px solid #d8e0e2" if is_pdf else "0"
        hero_padding = "22px 24px" if is_pdf else "28px 32px"
        heading_font_size = "34px" if is_pdf else "28px"
        subtitle_font_size = "16px" if is_pdf else "15px"
        content_padding = "22px 24px 24px" if is_pdf else "28px 32px 32px"
        summary_font_size = "16px" if is_pdf else "15px"
        probability_title_size = "21px" if is_pdf else "19px"
        probability_meta_size = "15px" if is_pdf else "14px"
        probability_caption_size = "15px" if is_pdf else "14px"
        metrics_min_width = "180px" if is_pdf else "220px"
        metric_label_size = "14px" if is_pdf else "13px"
        metric_value_size = "17px" if is_pdf else "15px"
        section_heading_size = "20px" if is_pdf else "18px"
        section_item_size = "15px" if is_pdf else "inherit"

        metrics_html = "".join(
            f"""
            <div class="metric-card">
              <div class="metric-label">{escape(metric.label)}</div>
              <div class="metric-value">{escape(metric.value)}</div>
            </div>
            """
            for metric in view_model.metrics
        )

        sections_html = "".join(
            self._render_section_html(section)
            for section in view_model.sections
        )

        return f"""<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="utf-8" />
  <title>{escape(view_model.title)}</title>
  <style>
    {page_rule}
    body {{
      font-family: "Segoe UI", Arial, sans-serif;
      background: {body_background};
      color: #1f2f35;
      margin: 0;
      padding: {body_padding};
    }}
    .sheet {{
      width: {sheet_width};
      max-width: {sheet_max_width};
      margin: 0 auto;
      background: #fffdf9;
      border: {sheet_border};
      border-radius: {sheet_border_radius};
      overflow: hidden;
      box-shadow: {sheet_box_shadow};
    }}
    .hero {{
      background: {hero_background};
      color: {hero_foreground};
      padding: {hero_padding};
      border-bottom: {hero_border_bottom};
    }}
    .eyebrow {{
      font-size: 13px;
      font-weight: 700;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: {eyebrow_color};
      margin-bottom: 8px;
    }}
    h1 {{
      margin: 0 0 8px 0;
      font-size: {heading_font_size};
      line-height: 1.2;
    }}
    .subtitle {{
      font-size: {subtitle_font_size};
      color: {subtitle_color};
      margin: 0;
    }}
    .content {{
      padding: {content_padding};
    }}
    .status-row {{
      display: flex;
      gap: 16px;
      align-items: center;
      margin-bottom: 20px;
      flex-wrap: wrap;
    }}
    .status-badge {{
      display: inline-block;
      padding: 10px 16px;
      border-radius: 999px;
      background: {tone["badge_bg"]};
      color: {tone["badge_fg"]};
      border: 1px solid {tone["badge_border"]};
      font-weight: 700;
    }}
    .summary {{
      font-size: {summary_font_size};
      line-height: 1.6;
      margin: 0 0 24px 0;
      color: #35505b;
    }}
    .probability-panel {{
      background: #f8f4ed;
      border: 1px solid #e4ddd2;
      border-radius: 20px;
      padding: 20px;
      margin-bottom: 24px;
    }}
    .probability-header {{
      display: flex;
      justify-content: space-between;
      gap: 16px;
      align-items: center;
      flex-wrap: wrap;
      margin-bottom: 12px;
    }}
    .probability-title {{
      font-size: {probability_title_size};
      font-weight: 700;
      color: #173447;
    }}
    .probability-meta {{
      font-size: {probability_meta_size};
      color: #5f6f76;
    }}
    .track {{
      height: 18px;
      border-radius: 999px;
      background: #e3ddd2;
      overflow: hidden;
      margin-bottom: 10px;
    }}
    .fill {{
      height: 100%;
      width: {fill_width}%;
      background: {"#cf5a43" if view_model.probability_alert else "#2c6970"};
      border-radius: 999px;
    }}
    .probability-caption {{
      font-size: {probability_caption_size};
      color: #425a64;
    }}
    .metrics-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax({metrics_min_width}, 1fr));
      gap: 14px;
      margin-bottom: 26px;
    }}
    .metric-card {{
      background: #fcfaf6;
      border: 1px solid #ddd8cf;
      border-radius: 18px;
      padding: 16px;
    }}
    .metric-label {{
      font-size: {metric_label_size};
      color: #61737d;
      margin-bottom: 8px;
      font-weight: 600;
    }}
    .metric-value {{
      font-size: {metric_value_size};
      color: #173447;
      line-height: 1.45;
      word-break: break-word;
    }}
    .section {{
      margin-top: 18px;
      background: #f9f5ef;
      border: 1px solid #e3ddd1;
      border-radius: 18px;
      padding: 18px 20px;
    }}
    .section h2 {{
      margin: 0 0 12px 0;
      font-size: {section_heading_size};
      color: #173447;
    }}
    .section ul {{
      margin: 0;
      padding-left: 20px;
    }}
    .section li {{
      margin: 8px 0;
      line-height: 1.55;
      font-size: {section_item_size};
    }}
  </style>
</head>
<body>
  <div class="sheet">
    <div class="hero">
      <div class="eyebrow">Локальная проверка мультимедиа</div>
      <h1>{escape(view_model.title)}</h1>
      <p class="subtitle">{escape(view_model.subtitle)}</p>
    </div>
    <div class="content">
      <div class="status-row">
        <div class="status-badge">{escape(view_model.status_label)}</div>
        <div class="probability-meta">Файл: {escape(view_model.file_name)}</div>
      </div>

      <p class="summary">{escape(view_model.summary)}</p>

      <div class="probability-panel">
        <div class="probability-header">
          <div class="probability-title">Оценка вероятности</div>
          <div class="probability-meta">
            Вероятность: {escape(view_model.probability_text)} | Порог: {escape(view_model.threshold_text)}
          </div>
        </div>
        <div class="track">
          <div class="fill"></div>
        </div>
        <div class="probability-caption">
          {"Вероятность превышает порог и требует дополнительной проверки." if view_model.probability_alert else "Вероятность не превышает установленный порог."}
        </div>
      </div>

      <div class="metrics-grid">
        {metrics_html}
      </div>

      {sections_html}
    </div>
  </div>
</body>
</html>
"""

    def export_result_to_txt(
        self,
        result_or_view_model: AnalysisResult | StructuredReportViewModel,
        destination: str | Path,
    ) -> Path:
        destination_path = Path(destination)
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(result_or_view_model, AnalysisResult) and result_or_view_model.export_payload:
            payload = result_or_view_model.export_payload
        else:
            payload = self.render_txt(result_or_view_model)
        destination_path.write_text(payload, encoding="utf-8")
        return destination_path

    def export_result_to_html(
        self,
        result_or_view_model: AnalysisResult | StructuredReportViewModel,
        destination: str | Path,
    ) -> Path:
        destination_path = Path(destination)
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        destination_path.write_text(self.render_html(result_or_view_model), encoding="utf-8")
        return destination_path

    def export_result_to_pdf(
        self,
        result_or_view_model: AnalysisResult | StructuredReportViewModel,
        destination: str | Path,
    ) -> Path:
        try:
            from PySide6.QtGui import QPageSize
            from PySide6.QtGui import QTextDocument
            from PySide6.QtPrintSupport import QPrinter
            from PySide6.QtWidgets import QApplication
        except ImportError as exc:  # pragma: no cover - depends on local env
            raise ImportError("Для экспорта PDF необходимо установить PySide6.") from exc

        destination_path = Path(destination)
        destination_path.parent.mkdir(parents=True, exist_ok=True)

        app = QApplication.instance()
        owns_app = False
        if app is None:
            app = QApplication([])
            owns_app = True

        try:
            printer = QPrinter(QPrinter.PrinterMode.HighResolution)
            printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
            printer.setPageSize(QPageSize(QPageSize.PageSizeId.A4))
            printer.setOutputFileName(str(destination_path))

            document = QTextDocument()
            document.setDocumentMargin(0)
            document.setPageSize(printer.pageRect(QPrinter.Unit.Point).size())
            document.setHtml(self.render_html(result_or_view_model, output_profile="pdf"))
            document.print_(printer)
        finally:
            if owns_app:
                app.quit()

        return destination_path

    @staticmethod
    def _ensure_view_model(
        value: AnalysisResult | StructuredReportViewModel,
    ) -> StructuredReportViewModel:
        if isinstance(value, StructuredReportViewModel):
            return value
        return ReportFormatter().build_view_model(value)

    @staticmethod
    def _render_section_html(section: ReportSection) -> str:
        if section.items:
            items_html = "".join(f"<li>{escape(item)}</li>" for item in section.items)
        else:
            items_html = "<li>Нет данных</li>"
        return f"""
        <div class="section">
          <h2>{escape(section.title)}</h2>
          <ul>{items_html}</ul>
        </div>
        """

    @staticmethod
    def _format_datetime(value: datetime | None) -> str:
        if value is None:
            return "-"
        return value.strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def _percent_text(value: float | None) -> str:
        if value is None:
            return "-"
        return f"{value * 100:.2f}%"

    @staticmethod
    def _tone_palette(status_tone: str) -> dict[str, str]:
        if status_tone == "error":
            return {
                "badge_bg": "#fde8e4",
                "badge_fg": "#8e2a24",
                "badge_border": "#edc2ba",
            }
        if status_tone == "danger":
            return {
                "badge_bg": "#ffebd8",
                "badge_fg": "#8a4b16",
                "badge_border": "#edcaa7",
            }
        return {
            "badge_bg": "#e1f1e7",
            "badge_fg": "#1c5b37",
            "badge_border": "#bfdec9",
        }
