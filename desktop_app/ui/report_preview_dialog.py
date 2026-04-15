from __future__ import annotations

try:
    from PySide6.QtWidgets import QDialog
    from PySide6.QtWidgets import QHBoxLayout
    from PySide6.QtWidgets import QLabel
    from PySide6.QtWidgets import QPushButton
    from PySide6.QtWidgets import QTextBrowser
    from PySide6.QtWidgets import QVBoxLayout
except ImportError as exc:  # pragma: no cover - depends on local env
    raise ImportError("Для запуска desktop-интерфейса необходимо установить PySide6.") from exc

from desktop_app.application.report_formatter import ReportFormatter
from desktop_app.domain import AnalysisResult


class ReportPreviewDialog(QDialog):
    def __init__(self, result: AnalysisResult, parent=None) -> None:  # noqa: ANN001
        super().__init__(parent)
        self._result = result
        self._formatter = ReportFormatter()

        self.setWindowTitle("Предпросмотр отчета")
        self.resize(980, 720)
        self.setModal(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(14)

        title = QLabel("Структурированный отчет по результату анализа", self)
        title.setObjectName("cardTitle")

        self.browser = QTextBrowser(self)
        self.browser.setObjectName("reportPreviewBrowser")
        self.browser.setOpenExternalLinks(False)
        self.browser.setHtml(self._formatter.render_html(self._result))

        button_row = QHBoxLayout()
        button_row.addStretch(1)

        close_button = QPushButton("Закрыть", self)
        close_button.setObjectName("secondaryButton")
        close_button.clicked.connect(self.reject)
        button_row.addWidget(close_button)

        layout.addWidget(title)
        layout.addWidget(self.browser, 1)
        layout.addLayout(button_row)
