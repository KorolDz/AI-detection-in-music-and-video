from __future__ import annotations

from pathlib import Path

try:
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QFont
    from PySide6.QtWidgets import QFileDialog
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
except ImportError as exc:  # pragma: no cover - depends on local env
    raise ImportError("Для запуска desktop-интерфейса необходимо установить PySide6.") from exc

from desktop_app.app import create_app_context
from desktop_app.application.coordinator import AnalysisCoordinator
from desktop_app.config import AppConfig
from desktop_app.domain import AnalysisResult
from desktop_app.exporter import export_result_to_txt

from .theme import MAIN_WINDOW_STYLESHEET
from .worker import AnalysisThread

VIDEO_FILE_FILTER = "Video Files (*.mp4 *.avi *.mov)"


class MainWindow(QMainWindow):
    def __init__(
        self,
        coordinator: AnalysisCoordinator | None = None,
        config: AppConfig | None = None,
    ) -> None:
        super().__init__()

        if coordinator is None or config is None:
            context = create_app_context(config)
            self._coordinator = context.coordinator
            self._config = context.config
        else:
            self._coordinator = coordinator
            self._config = config

        self._selected_file: str = ""
        self._current_result: AnalysisResult | None = None
        self._analysis_thread: AnalysisThread | None = None

        self.setWindowTitle("AI Media Inspector")
        self.resize(1280, 860)
        self.setMinimumSize(1120, 760)
        self.setFont(QFont("Segoe UI", 11))
        self.setStyleSheet(MAIN_WINDOW_STYLESHEET)

        self._build_ui()
        self._reset_result_view()
        self._refresh_controls()

    def _build_ui(self) -> None:
        central_widget = QWidget(self)
        central_widget.setObjectName("windowSurface")
        self.setCentralWidget(central_widget)

        outer_layout = QVBoxLayout(central_widget)
        outer_layout.setContentsMargins(12, 12, 12, 12)
        outer_layout.setSpacing(0)

        scroll_area = QScrollArea(self)
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QFrame.Shape.NoFrame)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        scroll_content = QWidget(scroll_area)
        scroll_content.setObjectName("windowSurface")
        scroll_area.setWidget(scroll_content)

        layout = QVBoxLayout(scroll_content)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(18)
        layout.addWidget(self._build_hero_card())

        content_layout = QHBoxLayout()
        content_layout.setSpacing(18)

        left_column = QWidget(self)
        left_layout = QVBoxLayout(left_column)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(18)
        left_layout.addWidget(self._build_file_card())
        left_layout.addWidget(self._build_control_card())
        left_layout.addWidget(self._build_status_card())
        left_layout.addStretch(1)

        right_column = QWidget(self)
        right_layout = QVBoxLayout(right_column)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(18)
        right_layout.addWidget(self._build_summary_card())
        right_layout.addWidget(self._build_details_card(), stretch=1)

        content_layout.addWidget(left_column, 5)
        content_layout.addWidget(right_column, 7)
        layout.addLayout(content_layout, 1)
        outer_layout.addWidget(scroll_area)

    def _build_hero_card(self) -> QFrame:
        card = QFrame(self)
        card.setObjectName("heroCard")

        layout = QHBoxLayout(card)
        layout.setContentsMargins(28, 28, 28, 28)
        layout.setSpacing(20)

        left_column = QVBoxLayout()
        left_column.setSpacing(10)

        eyebrow = QLabel("Локальная проверка мультимедиа", card)
        eyebrow.setObjectName("heroEyebrow")

        title = QLabel("Видеоанализ на предмет манипуляций", card)
        title.setObjectName("heroTitle")
        title.setWordWrap(True)

        subtitle = QLabel(
            "Приложение запускает анализ в отдельном потоке, сохраняет результаты и аудит в SQLite "
            "и позволяет сразу сформировать текстовый отчет.",
            card,
        )
        subtitle.setObjectName("heroSubtitle")
        subtitle.setWordWrap(True)

        left_column.addWidget(eyebrow)
        left_column.addWidget(title)
        left_column.addWidget(subtitle)
        left_column.addStretch(1)

        right_column = QVBoxLayout()
        right_column.setSpacing(12)

        self.hero_state_badge = QLabel("Режим готовности", card)
        self.hero_state_badge.setObjectName("heroBadge")
        self.hero_state_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.hero_formats_badge = QLabel("Форматы: MP4 / AVI / MOV", card)
        self.hero_formats_badge.setObjectName("heroBadge")
        self.hero_formats_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.hero_helper_label = QLabel(
            "Выберите локальный видеофайл и запустите проверку. После завершения можно изучить детали и сохранить отчет.",
            card,
        )
        self.hero_helper_label.setObjectName("heroMeta")
        self.hero_helper_label.setWordWrap(True)

        right_column.addWidget(self.hero_state_badge)
        right_column.addWidget(self.hero_formats_badge)
        right_column.addWidget(self.hero_helper_label)
        right_column.addStretch(1)

        layout.addLayout(left_column, 3)
        layout.addLayout(right_column, 2)
        return card

    def _build_file_card(self) -> QFrame:
        card, layout = self._create_card(
            "Источник данных",
            "Выберите локальный видеофайл. Сейчас интерфейс поддерживает форматы MP4, AVI и MOV.",
        )

        self.file_path_edit = QLineEdit(card)
        self.file_path_edit.setObjectName("filePathEdit")
        self.file_path_edit.setReadOnly(True)
        self.file_path_edit.setPlaceholderText("Файл пока не выбран")
        self.file_path_edit.setMinimumHeight(50)

        self.browse_button = QPushButton("Выбрать файл", card)
        self.browse_button.setObjectName("secondaryButton")
        self.browse_button.setMinimumHeight(50)
        self.browse_button.setMinimumWidth(180)
        self.browse_button.clicked.connect(self._browse_file)

        controls_row = QHBoxLayout()
        controls_row.setSpacing(12)
        controls_row.addWidget(self.file_path_edit, 1)
        controls_row.addWidget(self.browse_button)

        self.file_meta_label = QLabel("После выбора файла здесь появится краткая информация о видео.", card)
        self.file_meta_label.setObjectName("mutedInfo")
        self.file_meta_label.setWordWrap(True)

        layout.addLayout(controls_row)
        layout.addWidget(self.file_meta_label)
        return card

    def _build_control_card(self) -> QFrame:
        card, layout = self._create_card(
            "Команды",
            "Анализ выполняется в отдельном потоке, поэтому интерфейс остается отзывчивым во время проверки.",
        )

        buttons_row = QHBoxLayout()
        buttons_row.setSpacing(12)

        self.start_button = QPushButton("Запустить анализ", card)
        self.start_button.setObjectName("primaryButton")
        self.start_button.setMinimumHeight(50)
        self.start_button.clicked.connect(self._start_analysis)

        self.export_button = QPushButton("Экспорт отчета", card)
        self.export_button.setObjectName("secondaryButton")
        self.export_button.setMinimumHeight(50)
        self.export_button.clicked.connect(self._export_report)

        buttons_row.addWidget(self.start_button)
        buttons_row.addWidget(self.export_button)

        self.progress_bar = QProgressBar(card)
        self.progress_bar.setObjectName("busyProgress")
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.hide()

        self.busy_label = QLabel("Ожидание запуска анализа.", card)
        self.busy_label.setObjectName("mutedInfo")
        self.busy_label.setWordWrap(True)

        self.report_hint_label = QLabel("После завершения анализа станет доступен экспорт текстового отчета.", card)
        self.report_hint_label.setObjectName("mutedInfo")
        self.report_hint_label.setWordWrap(True)

        layout.addLayout(buttons_row)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.busy_label)
        layout.addWidget(self.report_hint_label)
        return card

    def _build_status_card(self) -> QFrame:
        card, layout = self._create_card(
            "Вердикт",
            "После завершения проверки здесь появятся итоговый статус, ключевые метрики и идентификатор записи в SQLite.",
        )

        self.status_value = QLabel("Ожидание анализа", card)
        self.status_value.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_value.setMinimumHeight(72)

        self.status_note_label = QLabel("Выберите видео и запустите анализ, чтобы получить вердикт.", card)
        self.status_note_label.setObjectName("mutedInfo")
        self.status_note_label.setWordWrap(True)

        metric_grid = QGridLayout()
        metric_grid.setHorizontalSpacing(12)
        metric_grid.setVerticalSpacing(12)

        probability_tile, self.probability_value = self._build_metric_tile("Вероятность подделки")
        threshold_tile, self.threshold_value = self._build_metric_tile("Порог")
        frames_tile, self.frames_value = self._build_metric_tile("Проанализировано кадров")
        record_tile, self.record_value = self._build_metric_tile("SQLite запись")
        model_tile, self.model_path_value = self._build_metric_tile("Путь к модели", compact=True)
        self.model_path_value.setWordWrap(True)

        metric_grid.addWidget(probability_tile, 0, 0)
        metric_grid.addWidget(threshold_tile, 0, 1)
        metric_grid.addWidget(frames_tile, 1, 0)
        metric_grid.addWidget(record_tile, 1, 1)
        metric_grid.addWidget(model_tile, 2, 0, 1, 2)

        layout.addWidget(self.status_value)
        layout.addWidget(self.status_note_label)
        layout.addLayout(metric_grid)
        return card

    def _build_summary_card(self) -> QFrame:
        card, layout = self._create_card(
            "Краткая сводка",
            "Этот блок помогает быстро понять результат без просмотра всех технических деталей.",
        )

        self.summary_text = QTextEdit(card)
        self.summary_text.setObjectName("summaryText")
        self.summary_text.setReadOnly(True)
        self.summary_text.setMinimumHeight(240)
        self.summary_text.setPlaceholderText("Сводка по анализу появится после завершения проверки.")

        layout.addWidget(self.summary_text)
        return card

    def _build_details_card(self) -> QFrame:
        card, layout = self._create_card(
            "Детали расследования",
            "Слева показываются признаки и интерпретация результата, справа — технические наблюдения и служебные данные.",
        )

        splitter = QSplitter(Qt.Orientation.Horizontal, card)

        indicators_panel = self._build_list_panel(
            "Признаки",
            "Ключевые наблюдения по вероятности подделки и поведению модели.",
        )
        technical_panel = self._build_list_panel(
            "Технические детали",
            "Параметры запуска, путь к модели и сведения о сохранении результата.",
        )

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
        self.file_meta_label.setText(
            f"Выбран файл: {path.name} | Формат: {extension}"
        )
        self.hero_state_badge.setText("Файл готов к проверке")
        self.hero_helper_label.setText(
            "Файл выбран. Можно запускать анализ и затем сохранить результат в текстовый отчет."
        )

        self._current_result = None
        self._reset_result_view()
        self._refresh_controls()

    def _start_analysis(self) -> None:
        if not self._selected_file or self._analysis_thread is not None:
            return

        self._current_result = None
        self._reset_result_view()
        self._set_busy_state(True, "Идет анализ видео. Окно остается доступным, повторный запуск временно заблокирован.")

        self._analysis_thread = AnalysisThread(self._coordinator, self._selected_file)
        self._analysis_thread.analysis_finished.connect(self._handle_analysis_result)
        self._analysis_thread.analysis_failed.connect(self._handle_analysis_failure)
        self._analysis_thread.finished.connect(self._cleanup_thread)
        self._analysis_thread.start()
        self._refresh_controls()

    def _handle_analysis_result(self, result: AnalysisResult) -> None:
        self._current_result = result
        self._render_result(result)
        self._set_busy_state(False, "Анализ завершен. Можно изучить результат или экспортировать отчет.")
        self._refresh_controls()

    def _handle_analysis_failure(self, message: str) -> None:
        fallback_result = AnalysisResult(
            status="error",
            media_type="video",
            file_path="",
            file_name=Path(self._selected_file).name,
            summary="Анализ завершился с критической ошибкой интерфейсного слоя.",
            technical_details=[f"Идентификатор файла: {Path(self._selected_file).name}"],
            error_message=message,
        )
        self._current_result = fallback_result
        self._render_result(fallback_result)
        self._set_busy_state(False, "Анализ завершился с ошибкой.")
        self._refresh_controls()

    def _cleanup_thread(self) -> None:
        if self._analysis_thread is not None:
            self._analysis_thread.deleteLater()
            self._analysis_thread = None
        self._refresh_controls()

    def _export_report(self) -> None:
        if self._current_result is None:
            return

        suggested_name = f"report_{Path(self._current_result.file_name).stem}.txt"
        suggested_path = self._config.reports_dir / suggested_name
        destination, _ = QFileDialog.getSaveFileName(
            self,
            "Сохранить отчет",
            str(suggested_path),
            "Text Files (*.txt)",
        )
        if not destination:
            return

        try:
            saved_path = export_result_to_txt(self._current_result, destination)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Ошибка экспорта", f"Не удалось сохранить отчет:\n{exc}")
            return

        self._current_result.report_path = str(saved_path)
        self.report_hint_label.setText("Отчет успешно сохранен.")
        self.hero_helper_label.setText("Проверка завершена, отчет сформирован и сохранен.")
        QMessageBox.information(self, "Экспорт завершен", f"Отчет сохранен:\n{saved_path}")

    def _render_result(self, result: AnalysisResult) -> None:
        self.status_value.setText(result.display_status)
        self.status_value.setStyleSheet(self._status_style(result))
        self.status_note_label.setText(self._status_note(result))

        self.probability_value.setText(
            f"{result.probability:.4f}" if result.probability is not None else "-"
        )
        self.threshold_value.setText(
            f"{result.threshold:.4f}" if result.threshold is not None else "-"
        )
        self.frames_value.setText(self._extract_frames(result.technical_details))
        self.record_value.setText(str(result.analysis_id) if result.analysis_id is not None else "-")
        self.model_path_value.setText(self._extract_model_path(result))
        self.summary_text.setPlainText(result.summary)

        self._fill_list(
            self.indicators_list,
            result.indicators,
            "После анализа здесь появятся признаки и интерпретация результата.",
        )

        technical_items = list(result.technical_details)
        if result.analysis_id is not None:
            technical_items.append(f"Идентификатор анализа: {result.analysis_id}")
        if result.stored_at is not None:
            technical_items.append(f"Дата сохранения: {self._format_datetime(result.stored_at)}")
        if result.error_message:
            technical_items.append(f"Сообщение об ошибке: {result.error_message}")

        self._fill_list(
            self.technical_list,
            technical_items,
            "Технические наблюдения появятся после завершения проверки.",
        )

        if result.is_error:
            self.hero_state_badge.setText("Анализ завершен с ошибкой")
        elif result.is_fake:
            self.hero_state_badge.setText("Найдены подозрительные признаки")
        else:
            self.hero_state_badge.setText("Оригинальность подтверждена")

        self.hero_helper_label.setText(self._status_note(result))
        self.report_hint_label.setText("Результат готов к экспорту в текстовый отчет.")

    def _reset_result_view(self) -> None:
        self.status_value.setText("Ожидание анализа")
        self.status_value.setStyleSheet(self._neutral_status_style())
        self.status_note_label.setText("Итоговый статус появится после проверки выбранного файла.")
        self.probability_value.setText("-")
        self.threshold_value.setText("-")
        self.frames_value.setText("-")
        self.record_value.setText("-")
        self.model_path_value.setText("-")
        self.summary_text.setPlainText("Результат анализа появится после запуска проверки.")
        self._fill_list(
            self.indicators_list,
            [],
            "После анализа здесь появятся признаки и интерпретация результата.",
        )
        self._fill_list(
            self.technical_list,
            [],
            "После анализа здесь появятся технические детали и служебные наблюдения.",
        )
        self.report_hint_label.setText("После завершения анализа станет доступен экспорт текстового отчета.")

    def _refresh_controls(self) -> None:
        is_busy = self._analysis_thread is not None
        has_file = bool(self._selected_file)
        has_result = self._current_result is not None

        self.start_button.setEnabled(has_file and not is_busy)
        self.browse_button.setEnabled(not is_busy)
        self.export_button.setEnabled(has_result and not is_busy)

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
            QMessageBox.information(
                self,
                "Анализ выполняется",
                "Дождитесь завершения анализа перед закрытием окна.",
            )
            event.ignore()
            return
        super().closeEvent(event)

    def _create_card(self, title: str, subtitle: str) -> tuple[QFrame, QVBoxLayout]:
        card = QFrame(self)
        card.setObjectName("card")
        card.setMinimumHeight(220)

        layout = QVBoxLayout(card)
        layout.setContentsMargins(22, 22, 22, 22)
        layout.setSpacing(16)

        title_label = QLabel(title, card)
        title_label.setObjectName("cardTitle")

        subtitle_label = QLabel(subtitle, card)
        subtitle_label.setObjectName("cardSubtitle")
        subtitle_label.setWordWrap(True)

        layout.addWidget(title_label)
        layout.addWidget(subtitle_label)
        return card, layout

    def _build_metric_tile(self, title: str, compact: bool = False) -> tuple[QFrame, QLabel]:
        tile = QFrame(self)
        tile.setObjectName("metricTile")
        tile.setMinimumHeight(108)

        layout = QVBoxLayout(tile)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(6)

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
        frame.setMinimumHeight(320)

        layout = QVBoxLayout(frame)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)

        title_label = QLabel(title, frame)
        title_label.setObjectName("cardTitle")

        subtitle_label = QLabel(subtitle, frame)
        subtitle_label.setObjectName("cardSubtitle")
        subtitle_label.setWordWrap(True)

        detail_list = QListWidget(frame)
        detail_list.setObjectName("detailList")
        detail_list.setAlternatingRowColors(False)
        detail_list.setWordWrap(True)
        detail_list.setTextElideMode(Qt.TextElideMode.ElideNone)
        detail_list.setMinimumHeight(220)

        layout.addWidget(title_label)
        layout.addWidget(subtitle_label)
        layout.addWidget(detail_list, 1)
        return {"frame": frame, "list": detail_list}

    @staticmethod
    def _fill_list(widget: QListWidget, items: list[str], empty_message: str) -> None:
        widget.clear()
        if not items:
            widget.addItem(QListWidgetItem(empty_message))
            return
        for item in items:
            widget.addItem(QListWidgetItem(item))

    @classmethod
    def _extract_frames(cls, technical_details: list[str]) -> str:
        return cls._match_after_colon(
            technical_details,
            (
                "Количество проанализированных кадров",
                "Обработано кадров с лицами",
                "Analyzed frames",
            ),
        )

    @classmethod
    def _extract_model_path(cls, result: AnalysisResult) -> str:
        items = list(result.technical_details) + list(result.indicators)
        return cls._match_after_colon(
            items,
            (
                "Путь к модели",
                "Использована модель",
                "Model path",
                "Model",
            ),
        )

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
    def _neutral_status_style() -> str:
        return (
            "QLabel {"
            "background-color: #dae6ea;"
            "color: #173447;"
            "border: 1px solid #c0d2d8;"
            "padding: 12px 16px;"
            "border-radius: 18px;"
            "font-size: 16px;"
            "font-weight: 700;"
            "}"
        )

    def _status_style(self, result: AnalysisResult) -> str:
        if result.status == "error":
            background = "#fde8e4"
            foreground = "#8e2a24"
            border = "#edc2ba"
        elif result.is_fake:
            background = "#ffebd8"
            foreground = "#8a4b16"
            border = "#edcaa7"
        else:
            background = "#e1f1e7"
            foreground = "#1c5b37"
            border = "#bfdec9"
        return (
            "QLabel {"
            f"background-color: {background};"
            f"color: {foreground};"
            f"border: 1px solid {border};"
            "padding: 12px 16px;"
            "border-radius: 18px;"
            "font-size: 16px;"
            "font-weight: 700;"
            "}"
        )

    @staticmethod
    def _status_note(result: AnalysisResult) -> str:
        if result.is_error:
            return result.error_message or "Проверка завершилась ошибкой. Изучите технические детали."
        if result.is_fake:
            return "Вероятность подделки превышает допустимый порог. Рекомендуется дополнительная ручная проверка."
        return "Явных признаков манипуляции не обнаружено. Результат сохранен и готов к экспорту."
