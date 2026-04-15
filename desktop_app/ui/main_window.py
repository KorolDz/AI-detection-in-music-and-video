from __future__ import annotations

from pathlib import Path

try:
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QFont
    from PySide6.QtWidgets import QFileDialog
    from PySide6.QtWidgets import QDialog
    from PySide6.QtWidgets import QFrame
    from PySide6.QtWidgets import QGridLayout
    from PySide6.QtWidgets import QHBoxLayout
    from PySide6.QtWidgets import QLabel
    from PySide6.QtWidgets import QLineEdit
    from PySide6.QtWidgets import QListWidget
    from PySide6.QtWidgets import QListWidgetItem
    from PySide6.QtWidgets import QMainWindow
    from PySide6.QtWidgets import QMessageBox
    from PySide6.QtWidgets import QPushButton
    from PySide6.QtWidgets import QProgressBar
    from PySide6.QtWidgets import QScrollArea
    from PySide6.QtWidgets import QSplitter
    from PySide6.QtWidgets import QTextEdit
    from PySide6.QtWidgets import QVBoxLayout
    from PySide6.QtWidgets import QWidget
except ImportError as exc:  # pragma: no cover
    raise ImportError("Для запуска desktop-интерфейса необходимо установить PySide6.") from exc

from desktop_app.app import create_app_context
from desktop_app.application.audit_log_service import AuditLogService
from desktop_app.application.audit_logger import AuditLogger
from desktop_app.application.coordinator import AnalysisCoordinator
from desktop_app.application.history_service import AnalysisHistoryService
from desktop_app.application.report_formatter import ReportFormatter
from desktop_app.config import AppConfig
from desktop_app.domain import AnalysisResult
from desktop_app.exporter import export_result

from .audit_log_dialog import AuditLogDialog
from .history_dialog import HistoryDialog
from .report_preview_dialog import ReportPreviewDialog
from .theme import MAIN_WINDOW_STYLESHEET
from .worker import AnalysisThread

VIDEO_FILE_FILTER = "Video Files (*.mp4 *.avi *.mov)"
EXPORT_FILE_FILTER = "PDF Files (*.pdf);;HTML Files (*.html);;Text Files (*.txt)"


class MainWindow(QMainWindow):
    def __init__(
        self,
        coordinator: AnalysisCoordinator | None = None,
        config: AppConfig | None = None,
        history_service: AnalysisHistoryService | None = None,
        audit_log_service: AuditLogService | None = None,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        super().__init__()
        context = None
        if coordinator is None or config is None:
            context = create_app_context(config)

        self._coordinator = coordinator or context.coordinator
        self._config = config or context.config
        self._history_service = history_service or (context.history_service if context else None)
        self._audit_log_service = audit_log_service or (context.audit_log_service if context else None)
        self._audit_logger = audit_logger or (context.audit_logger if context else None)
        self._report_formatter = ReportFormatter()

        self._selected_file = ""
        self._current_result: AnalysisResult | None = None
        self._analysis_thread: AnalysisThread | None = None

        self.setWindowTitle("AI Media Inspector")
        self.resize(1260, 840)
        self.setMinimumSize(1080, 720)
        self.setFont(QFont("Segoe UI", 11))
        self.setStyleSheet(MAIN_WINDOW_STYLESHEET)

        self._build_ui()
        self._reset_result_view()
        self._refresh_controls()

    def _build_ui(self) -> None:
        central = QWidget(self)
        central.setObjectName("windowSurface")
        self.setCentralWidget(central)
        outer = QVBoxLayout(central)
        outer.setContentsMargins(12, 12, 12, 12)

        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        content = QWidget(scroll)
        content.setObjectName("windowSurface")
        scroll.setWidget(content)
        layout = QVBoxLayout(content)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(14)
        layout.addWidget(self._build_hero_card())

        columns = QHBoxLayout()
        columns.setSpacing(14)

        left = QWidget(self)
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(14)
        left_layout.addWidget(self._build_file_card())
        left_layout.addWidget(self._build_control_card())
        left_layout.addWidget(self._build_status_card())
        left_layout.addStretch(1)

        right = QWidget(self)
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(14)
        right_layout.addWidget(self._build_summary_card())
        right_layout.addWidget(self._build_details_card(), stretch=1)

        columns.addWidget(left, 5)
        columns.addWidget(right, 7)
        layout.addLayout(columns, 1)
        outer.addWidget(scroll)

    def _build_hero_card(self) -> QFrame:
        card = QFrame(self)
        card.setObjectName("heroCard")
        card.setMinimumHeight(170)
        layout = QHBoxLayout(card)
        layout.setContentsMargins(24, 22, 24, 22)

        left = QVBoxLayout()
        eyebrow = QLabel("Локальная проверка мультимедиа", card)
        eyebrow.setObjectName("heroEyebrow")
        title = QLabel("Визуализация результата анализа видео", card)
        title.setObjectName("heroTitle")
        title.setWordWrap(True)
        left.addWidget(eyebrow)
        left.addWidget(title)
        left.addStretch(1)

        right = QVBoxLayout()
        self.hero_state_badge = QLabel("Режим готовности", card)
        self.hero_state_badge.setObjectName("heroBadge")
        self.hero_state_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.hero_formats_badge = QLabel("Экспорт: TXT / HTML / PDF", card)
        self.hero_formats_badge.setObjectName("heroBadge")
        self.hero_formats_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.hero_helper_label = QLabel("", card)
        self.hero_helper_label.setObjectName("heroMeta")
        self.hero_helper_label.setWordWrap(True)
        self.hero_helper_label.hide()
        right.addWidget(self.hero_state_badge)
        right.addWidget(self.hero_formats_badge)
        right.addWidget(self.hero_helper_label)
        right.addStretch(1)

        layout.addLayout(left, 3)
        layout.addLayout(right, 2)
        return card

    def _build_file_card(self) -> QFrame:
        card, layout = self._create_card("Источник данных", "")
        card.setMinimumHeight(0)
        self.file_path_edit = QLineEdit(card)
        self.file_path_edit.setObjectName("filePathEdit")
        self.file_path_edit.setReadOnly(True)
        self.file_path_edit.setPlaceholderText("Файл пока не выбран")
        self.file_path_edit.setMinimumHeight(46)
        self.browse_button = QPushButton("Выбрать файл", card)
        self.browse_button.setObjectName("secondaryButton")
        self.browse_button.setMinimumHeight(46)
        self.browse_button.clicked.connect(self._browse_file)
        row = QHBoxLayout()
        row.addWidget(self.file_path_edit, 1)
        row.addWidget(self.browse_button)
        self.file_meta_label = QLabel("", card)
        self.file_meta_label.setObjectName("mutedInfo")
        self.file_meta_label.setWordWrap(True)
        self.file_meta_label.hide()
        layout.addLayout(row)
        layout.addWidget(self.file_meta_label)
        return card

    def _build_control_card(self) -> QFrame:
        card, layout = self._create_card("Команды", "")
        card.setMinimumHeight(0)
        row1 = QHBoxLayout()
        row2 = QHBoxLayout()
        self.start_button = QPushButton("Запустить анализ", card)
        self.start_button.setObjectName("primaryButton")
        self.start_button.setMinimumHeight(46)
        self.start_button.clicked.connect(self._start_analysis)
        self.preview_button = QPushButton("Предпросмотр отчета", card)
        self.preview_button.setObjectName("secondaryButton")
        self.preview_button.setMinimumHeight(46)
        self.preview_button.clicked.connect(self._open_report_preview)
        self.export_button = QPushButton("Экспорт отчета", card)
        self.export_button.setObjectName("secondaryButton")
        self.export_button.setMinimumHeight(46)
        self.export_button.clicked.connect(self._export_report)
        self.history_button = QPushButton("История проверок", card)
        self.history_button.setObjectName("secondaryButton")
        self.history_button.setMinimumHeight(46)
        self.history_button.clicked.connect(self._open_history)
        self.audit_log_button = QPushButton("Журнал действий", card)
        self.audit_log_button.setObjectName("secondaryButton")
        self.audit_log_button.setMinimumHeight(46)
        self.audit_log_button.clicked.connect(self._open_audit_log)
        row1.addWidget(self.start_button)
        row1.addWidget(self.preview_button)
        row2.addWidget(self.export_button)
        row2.addWidget(self.history_button)
        row2.addWidget(self.audit_log_button)

        self.progress_bar = QProgressBar(card)
        self.progress_bar.setObjectName("busyProgress")
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.hide()
        self.busy_label = QLabel("Готово", card)
        self.busy_label.setObjectName("mutedInfo")
        self.busy_label.setWordWrap(True)
        self.report_hint_label = QLabel("", card)
        self.report_hint_label.setObjectName("mutedInfo")
        self.report_hint_label.setWordWrap(True)
        self.report_hint_label.hide()
        layout.addLayout(row1)
        layout.addLayout(row2)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.busy_label)
        layout.addWidget(self.report_hint_label)
        return card

    def _build_status_card(self) -> QFrame:
        card, layout = self._create_card("Вердикт", "")
        card.setMinimumHeight(0)
        self.status_value = QLabel("Ожидание анализа", card)
        self.status_value.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_value.setMinimumHeight(64)
        self.status_note_label = QLabel("", card)
        self.status_note_label.setObjectName("mutedInfo")
        self.status_note_label.setWordWrap(True)
        self.status_note_label.hide()

        probability_panel = QFrame(card)
        probability_panel.setObjectName("subCard")
        p_layout = QVBoxLayout(probability_panel)
        p_layout.setContentsMargins(18, 18, 18, 18)
        self.probability_headline = QLabel("Оценка вероятности", probability_panel)
        self.probability_headline.setObjectName("cardTitle")
        meta = QHBoxLayout()
        self.probability_percent_label = QLabel("-", probability_panel)
        self.probability_percent_label.setObjectName("probabilityValue")
        self.threshold_text_label = QLabel("Порог: -", probability_panel)
        self.threshold_text_label.setObjectName("mutedInfo")
        meta.addWidget(self.probability_percent_label)
        meta.addStretch(1)
        meta.addWidget(self.threshold_text_label)
        self.probability_gauge = QProgressBar(probability_panel)
        self.probability_gauge.setObjectName("probabilityGauge")
        self.probability_gauge.setRange(0, 100)
        self.probability_gauge.setTextVisible(False)
        self.probability_caption_label = QLabel("", probability_panel)
        self.probability_caption_label.setObjectName("mutedInfo")
        self.probability_caption_label.setWordWrap(True)
        self.probability_caption_label.hide()
        p_layout.addWidget(self.probability_headline)
        p_layout.addLayout(meta)
        p_layout.addWidget(self.probability_gauge)
        p_layout.addWidget(self.probability_caption_label)

        grid = QGridLayout()
        self._build_metric_widgets(grid)

        layout.addWidget(self.status_value)
        layout.addWidget(self.status_note_label)
        layout.addWidget(probability_panel)
        layout.addLayout(grid)
        return card

    def _build_metric_widgets(self, grid: QGridLayout) -> None:
        probability_tile, self.probability_value = self._build_metric_tile("Вероятность")
        threshold_tile, self.threshold_value = self._build_metric_tile("Порог")
        frames_tile, self.frames_value = self._build_metric_tile("Проанализировано кадров")
        record_tile, self.record_value = self._build_metric_tile("SQLite запись")
        integrity_tile, self.integrity_value = self._build_metric_tile("Целостность")
        model_tile, self.model_path_value = self._build_metric_tile("Путь к модели", compact=True)
        self.model_path_value.setWordWrap(True)
        grid.addWidget(probability_tile, 0, 0)
        grid.addWidget(threshold_tile, 0, 1)
        grid.addWidget(frames_tile, 1, 0)
        grid.addWidget(record_tile, 1, 1)
        grid.addWidget(integrity_tile, 2, 0)
        grid.addWidget(model_tile, 2, 1)

    def _build_summary_card(self) -> QFrame:
        card, layout = self._create_card("Краткая сводка", "")
        card.setMinimumHeight(0)
        self.summary_text = QTextEdit(card)
        self.summary_text.setObjectName("summaryText")
        self.summary_text.setReadOnly(True)
        self.summary_text.setMinimumHeight(210)
        layout.addWidget(self.summary_text)
        return card

    def _build_details_card(self) -> QFrame:
        card, layout = self._create_card("Детали расследования", "")
        card.setMinimumHeight(0)
        splitter = QSplitter(Qt.Orientation.Horizontal, card)
        indicators_panel = self._build_list_panel("Подозрительные признаки", "")
        technical_panel = self._build_list_panel("Технические детали", "")
        self.indicators_list = indicators_panel["list"]
        self.technical_list = technical_panel["list"]
        splitter.addWidget(indicators_panel["frame"])
        splitter.addWidget(technical_panel["frame"])
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 1)
        layout.addWidget(splitter, 1)
        return card

    def _browse_file(self) -> None:
        file_path, _ = QFileDialog.getOpenFileName(self, "Выберите видеофайл", "", VIDEO_FILE_FILTER)
        if file_path:
            self.set_selected_file(file_path)

    def set_selected_file(self, file_path: str) -> None:
        self._selected_file = file_path
        self.file_path_edit.setText(file_path)
        self.file_path_edit.setCursorPosition(0)
        path = Path(file_path)
        extension = path.suffix.lstrip(".").upper() or "UNKNOWN"
        self._set_optional_text(self.file_meta_label, f"Выбран локальный файл: {path.name} | Формат: {extension}")
        self.hero_state_badge.setText("Файл готов к проверке")
        self._set_optional_text(self.hero_helper_label, "")
        self._current_result = None
        self._reset_result_view()
        self._refresh_controls()
        self._log_event(
            "file_selected",
            "info",
            "Пользователь выбрал локальный файл для проверки.",
            details={"file_name": path.name, "extension": path.suffix.lower()},
        )

    def _start_analysis(self) -> None:
        if not self._selected_file or self._analysis_thread is not None:
            return
        self._current_result = None
        self._reset_result_view()
        self._set_busy_state(True, "Идет анализ видео. Повторный запуск временно заблокирован.")
        self._analysis_thread = AnalysisThread(self._coordinator, self._selected_file)
        self._analysis_thread.analysis_finished.connect(self._handle_analysis_result)
        self._analysis_thread.analysis_failed.connect(self._handle_analysis_failure)
        self._analysis_thread.finished.connect(self._cleanup_thread)
        self._analysis_thread.start()
        self._refresh_controls()

    def _handle_analysis_result(self, result: AnalysisResult) -> None:
        self._current_result = result
        self._render_result(result)
        self._set_busy_state(False, "Анализ завершен. Можно открыть отчет или экспортировать результат.")
        self._refresh_controls()

    def _handle_analysis_failure(self, message: str) -> None:
        fallback = AnalysisResult(
            status="error",
            media_type="video",
            file_path="",
            file_name=Path(self._selected_file).name,
            summary="Анализ завершился с критической ошибкой интерфейсного слоя.",
            technical_details=[f"Имя файла: {Path(self._selected_file).name}"],
            error_message=message,
        )
        self._current_result = fallback
        self._render_result(fallback)
        self._set_busy_state(False, "Анализ завершился с ошибкой.")
        self._refresh_controls()

    def _cleanup_thread(self) -> None:
        if self._analysis_thread is not None:
            self._analysis_thread.deleteLater()
            self._analysis_thread = None
        self._refresh_controls()

    def _open_report_preview(self) -> None:
        if self._current_result is None:
            QMessageBox.information(self, "Нет результата", "Сначала выполните анализ или загрузите запись из истории.")
            return
        ReportPreviewDialog(self._current_result, self).exec()

    def _export_report(self) -> None:
        if self._current_result is None:
            return
        suggested = self._config.reports_dir / f"report_{Path(self._current_result.file_name).stem}"
        destination, selected_filter = QFileDialog.getSaveFileName(
            self,
            "Сохранить отчет",
            str(suggested),
            EXPORT_FILE_FILTER,
        )
        if not destination:
            return
        file_format, normalized_destination = self._resolve_export_target(destination, selected_filter)
        try:
            saved_path = export_result(self._current_result, normalized_destination, file_format)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Ошибка экспорта", f"Не удалось сохранить отчет:\n{exc}")
            return
        self._current_result.report_path = str(saved_path)
        self._set_optional_text(self.report_hint_label, f"Отчет сохранен: {file_format.upper()}")
        self._set_optional_text(self.hero_helper_label, "")
        self._log_event(
            "report_exported",
            "info",
            "Отчет по анализу успешно экспортирован.",
            result_id=self._current_result.analysis_id,
            details={
                "file_name": self._current_result.file_name,
                "report_file": Path(saved_path).name,
                "report_format": file_format,
            },
        )
        QMessageBox.information(self, "Экспорт завершен", f"Отчет сохранен:\n{saved_path}")

    def _open_history(self) -> None:
        if self._history_service is None:
            QMessageBox.information(self, "История недоступна", "История проверок пока недоступна.")
            return
        dialog = HistoryDialog(self._history_service, self)
        if dialog.exec() != QDialog.DialogCode.Accepted or dialog.selected_analysis_id is None:
            return
        result = self._history_service.get_analysis(dialog.selected_analysis_id)
        if result is None:
            QMessageBox.warning(self, "Запись не найдена", "Не удалось загрузить выбранную запись из истории.")
            return
        self._current_result = result
        self._render_result(result)
        self._set_optional_text(self.file_meta_label, f"Загружена запись из истории: {result.file_name}")
        self._set_optional_text(self.report_hint_label, "Запись из истории загружена")
        self._set_optional_text(self.hero_helper_label, "")
        self._refresh_controls()

    def _open_audit_log(self) -> None:
        if self._audit_log_service is None:
            QMessageBox.information(self, "Журнал недоступен", "Журнал действий пока недоступен.")
            return
        AuditLogDialog(self._audit_log_service, self).exec()

    def _render_result(self, result: AnalysisResult) -> None:
        self.status_value.setText(result.display_status)
        self.status_value.setStyleSheet(self._status_style(result))
        self._set_optional_text(self.status_note_label, self._status_note(result))

        probability_text = self._format_probability(result.probability)
        threshold_text = self._format_probability(result.threshold)
        probability_percent = result.probability_percent or 0
        is_alert = bool(result.probability is not None and result.threshold is not None and result.probability > result.threshold)

        self.probability_percent_label.setText(probability_text)
        self.threshold_text_label.setText(f"Порог: {threshold_text}")
        self.probability_gauge.setValue(probability_percent)
        self.probability_gauge.setStyleSheet(self._probability_gauge_style(is_alert))
        self._set_optional_text(self.probability_caption_label, self._probability_caption(result, is_alert))

        self.probability_value.setText(probability_text)
        self.threshold_value.setText(threshold_text)
        self.frames_value.setText(self._extract_frames(result.technical_details))
        self.record_value.setText(str(result.analysis_id) if result.analysis_id is not None else "-")
        self.integrity_value.setText(result.integrity_status)
        self.model_path_value.setText(self._extract_model_path(result))

        self.summary_text.setPlainText(self._build_summary_block(result))
        self._fill_list(self.indicators_list, result.indicators, "Нет данных")

        technical_items = list(result.technical_details)
        if result.analysis_id is not None:
            technical_items.append(f"Идентификатор анализа: {result.analysis_id}")
        if result.uploaded_at is not None:
            technical_items.append(f"Время загрузки: {self._format_datetime(result.uploaded_at)}")
        if result.analysis_started_at is not None:
            technical_items.append(f"Время старта анализа: {self._format_datetime(result.analysis_started_at)}")
        if result.analyzed_at is not None:
            technical_items.append(f"Время завершения анализа: {self._format_datetime(result.analyzed_at)}")
        if result.stored_at is not None:
            technical_items.append(f"Дата сохранения: {self._format_datetime(result.stored_at)}")
        if result.file_sha256:
            technical_items.append(f"SHA-256 файла: {result.file_sha256}")
        technical_items.append(f"Контроль целостности: {result.integrity_status}")
        if result.error_message:
            technical_items.append(f"Сообщение об ошибке: {result.error_message}")
        self._fill_list(self.technical_list, technical_items, "Нет данных")

        self.hero_state_badge.setText(
            "Анализ завершен с ошибкой" if result.is_error else "Найдены подозрительные признаки" if result.is_fake else "Оригинальность подтверждена"
        )
        self._set_optional_text(self.hero_helper_label, "")
        self._set_optional_text(self.report_hint_label, "Результат готов")

    def _reset_result_view(self) -> None:
        self.status_value.setText("Ожидание анализа")
        self.status_value.setStyleSheet(self._neutral_status_style())
        self._set_optional_text(self.status_note_label, "")
        self.probability_percent_label.setText("-")
        self.threshold_text_label.setText("Порог: -")
        self.probability_gauge.setValue(0)
        self.probability_gauge.setStyleSheet(self._probability_gauge_style(False))
        self._set_optional_text(self.probability_caption_label, "")
        self.probability_value.setText("-")
        self.threshold_value.setText("-")
        self.frames_value.setText("-")
        self.record_value.setText("-")
        self.integrity_value.setText("-")
        self.model_path_value.setText("-")
        self.summary_text.clear()
        self._fill_list(self.indicators_list, [], "Нет данных")
        self._fill_list(self.technical_list, [], "Нет данных")
        self._set_optional_text(self.report_hint_label, "")

    def _refresh_controls(self) -> None:
        is_busy = self._analysis_thread is not None
        has_file = bool(self._selected_file)
        has_result = self._current_result is not None
        self.start_button.setEnabled(has_file and not is_busy)
        self.browse_button.setEnabled(not is_busy)
        self.preview_button.setEnabled(has_result and not is_busy)
        self.export_button.setEnabled(has_result and not is_busy)
        self.history_button.setEnabled(self._history_service is not None and not is_busy)
        self.audit_log_button.setEnabled(self._audit_log_service is not None and not is_busy)

    def _set_busy_state(self, is_busy: bool, text: str) -> None:
        if is_busy:
            self.progress_bar.setRange(0, 0)
            self.progress_bar.show()
            self.hero_state_badge.setText("Выполняется анализ")
        else:
            self.progress_bar.hide()
            self.progress_bar.setRange(0, 1)
            self.progress_bar.setValue(0)
        self.busy_label.setText(text)

    def closeEvent(self, event) -> None:  # type: ignore[override]
        if self._analysis_thread is not None:
            QMessageBox.information(self, "Анализ выполняется", "Дождитесь завершения анализа перед закрытием окна.")
            event.ignore()
            return
        super().closeEvent(event)

    def _create_card(self, title: str, subtitle: str) -> tuple[QFrame, QVBoxLayout]:
        card = QFrame(self)
        card.setObjectName("card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)
        title_label = QLabel(title, card)
        title_label.setObjectName("cardTitle")
        layout.addWidget(title_label)
        if subtitle:
            subtitle_label = QLabel(subtitle, card)
            subtitle_label.setObjectName("cardSubtitle")
            subtitle_label.setWordWrap(True)
            layout.addWidget(subtitle_label)
        return card, layout

    def _build_metric_tile(self, title: str, compact: bool = False) -> tuple[QFrame, QLabel]:
        tile = QFrame(self)
        tile.setObjectName("metricTile")
        tile.setMinimumHeight(92)
        layout = QVBoxLayout(tile)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(4)
        title_label = QLabel(title, tile)
        title_label.setObjectName("metricCaption")
        value_label = QLabel("-", tile)
        value_label.setObjectName("metricValueCompact" if compact else "metricValue")
        value_label.setWordWrap(compact)
        layout.addWidget(title_label)
        layout.addWidget(value_label)
        return tile, value_label

    def _build_list_panel(self, title: str, subtitle: str) -> dict[str, QWidget | QListWidget]:
        frame = QFrame(self)
        frame.setObjectName("subCard")
        frame.setMinimumHeight(250)
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)
        title_label = QLabel(title, frame)
        title_label.setObjectName("cardTitle")
        detail_list = QListWidget(frame)
        detail_list.setObjectName("detailList")
        detail_list.setWordWrap(True)
        detail_list.setTextElideMode(Qt.TextElideMode.ElideNone)
        detail_list.setMinimumHeight(180)
        layout.addWidget(title_label)
        if subtitle:
            subtitle_label = QLabel(subtitle, frame)
            subtitle_label.setObjectName("cardSubtitle")
            subtitle_label.setWordWrap(True)
            layout.addWidget(subtitle_label)
        layout.addWidget(detail_list, 1)
        return {"frame": frame, "list": detail_list}

    def _log_event(
        self,
        event_type: str,
        severity: str,
        message: str,
        *,
        result_id: int | None = None,
        details: dict[str, object] | None = None,
    ) -> None:
        if self._audit_logger is None:
            return
        self._audit_logger.log_event(event_type, severity, message, result_id=result_id, details=details)

    @staticmethod
    def _fill_list(widget: QListWidget, items: list[str], empty_message: str) -> None:
        widget.clear()
        if not items:
            if empty_message:
                widget.addItem(QListWidgetItem(empty_message))
            return
        for item in items:
            widget.addItem(QListWidgetItem(item))

    @staticmethod
    def _set_optional_text(label: QLabel, text: str) -> None:
        label.setText(text)
        label.setVisible(bool(text.strip()))

    @classmethod
    def _extract_frames(cls, technical_details: list[str]) -> str:
        return cls._match_after_colon(
            technical_details,
            ("Количество проанализированных кадров", "Обработано кадров с лицами", "Analyzed frames"),
        )

    @classmethod
    def _extract_model_path(cls, result: AnalysisResult) -> str:
        items = list(result.technical_details) + list(result.indicators)
        return cls._match_after_colon(items, ("Путь к модели", "Использована модель", "Model path", "Model"))

    @staticmethod
    def _match_after_colon(items: list[str], markers: tuple[str, ...]) -> str:
        for item in items:
            lowered = item.casefold()
            for marker in markers:
                marker_casefold = marker.casefold()
                if lowered.startswith(marker_casefold):
                    return item.split(":", 1)[1].strip() if ":" in item else item.strip()
                if marker_casefold in lowered and ":" in item:
                    return item.split(":", 1)[1].strip()
        return "-"

    @staticmethod
    def _format_datetime(value) -> str:  # noqa: ANN001
        if value is None:
            return "-"
        return value.strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def _format_probability(value: float | None) -> str:
        if value is None:
            return "-"
        return f"{value * 100:.2f}%"

    @staticmethod
    def _neutral_status_style() -> str:
        return (
            "QLabel {background-color: #dae6ea; color: #173447; border: 1px solid #c0d2d8; "
            "padding: 12px 16px; border-radius: 18px; font-size: 16px; font-weight: 700;}"
        )

    def _status_style(self, result: AnalysisResult) -> str:
        if result.status == "error":
            background, foreground, border = "#fde8e4", "#8e2a24", "#edc2ba"
        elif result.is_fake:
            background, foreground, border = "#ffebd8", "#8a4b16", "#edcaa7"
        else:
            background, foreground, border = "#e1f1e7", "#1c5b37", "#bfdec9"
        return (
            "QLabel {"
            f"background-color: {background}; color: {foreground}; border: 1px solid {border}; "
            "padding: 12px 16px; border-radius: 18px; font-size: 16px; font-weight: 700;}"
        )

    @staticmethod
    def _probability_gauge_style(is_alert: bool) -> str:
        chunk_color = "#cf5a43" if is_alert else "#2c6970"
        return (
            "QProgressBar {min-height: 18px; max-height: 18px; border: 0; border-radius: 9px; background-color: #e3ddd2;}"
            f"QProgressBar::chunk {{background-color: {chunk_color}; border-radius: 9px;}}"
        )

    @staticmethod
    def _status_note(result: AnalysisResult) -> str:
        if result.is_error:
            return result.error_message or "Проверка завершилась ошибкой. Изучите технические детали."
        if result.is_fake:
            return "Вероятность подделки превышает порог. Рекомендуется дополнительная ручная проверка."
        return "Явных признаков манипуляции не обнаружено. Результат сохранен и готов к экспорту."

    @staticmethod
    def _probability_caption(result: AnalysisResult, is_alert: bool) -> str:
        if result.probability is None:
            return "Модель не вернула числовую вероятность для этого результата."
        if result.threshold is None:
            return "Вероятность рассчитана, но порог классификации недоступен."
        if is_alert:
            return "Вероятность превышает порог. Индикатор окрашен в красный цвет."
        return "Вероятность не превышает порог. Индикатор остается нейтральным."

    def _build_summary_block(self, result: AnalysisResult) -> str:
        view_model = self._report_formatter.build_view_model(result)
        return "\n".join(
            [
                f"Статус: {view_model.status_label}",
                f"Вероятность: {view_model.probability_text}",
                f"Порог: {view_model.threshold_text}",
                "",
                view_model.summary,
            ]
        )

    @staticmethod
    def _resolve_export_target(destination: str, selected_filter: str) -> tuple[str, str]:
        destination_path = Path(destination)
        suffix = destination_path.suffix.lower()
        if suffix == ".pdf":
            return "pdf", str(destination_path)
        if suffix == ".html":
            return "html", str(destination_path)
        if suffix == ".txt":
            return "txt", str(destination_path)
        filter_lower = selected_filter.lower()
        if "pdf" in filter_lower:
            return "pdf", str(destination_path.with_suffix(".pdf"))
        if "html" in filter_lower:
            return "html", str(destination_path.with_suffix(".html"))
        return "txt", str(destination_path.with_suffix(".txt"))
