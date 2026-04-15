from __future__ import annotations

import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

try:
    from PySide6.QtWidgets import QApplication
    from PySide6.QtWidgets import QDialog
except ImportError:  # pragma: no cover - depends on local env
    QApplication = None  # type: ignore[assignment]
    QDialog = None  # type: ignore[assignment]

from desktop_app.config import AppConfig

if QApplication is not None:
    from desktop_app.domain import AnalysisHistoryEntry
    from desktop_app.domain import AnalysisResult
    from desktop_app.domain import AuditLogEntry
    from desktop_app.ui.main_window import MainWindow


class FakeCoordinator:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def run(self, file_path: str) -> "AnalysisResult":  # pragma: no cover
        self.calls.append(file_path)
        return AnalysisResult(
            status="original",
            media_type="video",
            file_path=file_path,
            file_name=Path(file_path).name,
            probability=0.12,
            threshold=0.46,
            summary="Видео не превышает порог.",
        )


class FakeHistoryService:
    def __init__(self) -> None:
        self.list_calls = 0
        self.loaded_ids: list[int] = []
        self.result = AnalysisResult(
            status="fake",
            media_type="video",
            file_path="",
            file_name="history.mp4",
            is_fake=True,
            probability=0.82,
            threshold=0.46,
            summary="Загружено из истории.",
            file_sha256="abc123historyhash",
            integrity_verified=True,
            uploaded_at=datetime(2026, 4, 15, 11, 59, 50),
            analysis_started_at=datetime(2026, 4, 15, 11, 59, 58),
            analyzed_at=datetime(2026, 4, 15, 12, 0, 0),
            stored_at=datetime(2026, 4, 15, 12, 1, 0),
        )

    def list_recent(self, limit: int = 100) -> list["AnalysisHistoryEntry"]:  # pragma: no cover
        self.list_calls += 1
        return [
            AnalysisHistoryEntry(
                analysis_id=42,
                file_name="history.mp4",
                media_type="video",
                stored_at=datetime(2026, 4, 15, 12, 1, 0),
                status="fake",
                probability=0.82,
                file_sha256="abc123historyhash",
                integrity_verified=True,
            )
        ]

    def get_analysis(self, analysis_id: int) -> "AnalysisResult | None":  # pragma: no cover
        self.loaded_ids.append(analysis_id)
        return self.result


class FakeAuditLogService:
    def list_recent(self, limit: int = 200) -> list["AuditLogEntry"]:  # pragma: no cover
        return [
            AuditLogEntry(
                event_time=datetime(2026, 4, 15, 12, 2, 0),
                event_type="analysis_completed",
                severity="info",
                message="Анализ завершен.",
                result_id=42,
                details={"file_name": "history.mp4"},
            )
        ]


class FakeAuditLogger:
    def __init__(self) -> None:
        self.events: list[dict[str, object]] = []

    def log_event(
        self,
        event_type: str,
        severity: str,
        message: str,
        *,
        file_path: str | None = None,
        result_id: int | None = None,
        details: dict[str, object] | None = None,
    ) -> None:  # pragma: no cover
        self.events.append(
            {
                "event_type": event_type,
                "severity": severity,
                "message": message,
                "file_path": file_path,
                "result_id": result_id,
                "details": details or {},
            }
        )


@unittest.skipIf(QApplication is None, "PySide6 не установлена.")
class MainWindowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.base_dir = Path(self.temp_dir.name)
        self.config = AppConfig(
            base_dir=self.base_dir,
            db_path=self.base_dir / "app_data" / "app.db",
            reports_dir=self.base_dir / "reports",
            temp_dir=self.base_dir / "temp",
            temp_uploads_dir=self.base_dir / "temp" / "uploads",
            supported_video_extensions=(".mp4", ".avi", ".mov"),
            supported_audio_extensions=(".wav", ".mp3"),
            max_video_size_bytes=500 * 1024 * 1024,
            max_audio_size_bytes=100 * 1024 * 1024,
            model_threshold=0.46,
        )

    def test_start_and_preview_buttons_depend_on_state(self) -> None:
        window = MainWindow(coordinator=FakeCoordinator(), config=self.config, audit_logger=FakeAuditLogger())
        self.addCleanup(window.close)

        self.assertFalse(window.start_button.isEnabled())
        self.assertFalse(window.preview_button.isEnabled())
        self.assertFalse(window.history_button.isEnabled())
        self.assertFalse(window.audit_log_button.isEnabled())

        window.set_selected_file("C:/tmp/sample.mp4")

        self.assertTrue(window.start_button.isEnabled())
        self.assertFalse(window.export_button.isEnabled())
        self.assertFalse(window.preview_button.isEnabled())

    def test_main_window_uses_coordinator_in_analysis_thread(self) -> None:
        fake_coordinator = FakeCoordinator()
        captured: dict[str, object] = {}

        class StubThread:
            def __init__(self, coordinator, file_path) -> None:  # noqa: ANN001
                captured["coordinator"] = coordinator
                captured["file_path"] = file_path
                self.analysis_finished = self
                self.analysis_failed = self
                self.finished = self

            def connect(self, _callback) -> None:  # noqa: ANN001
                return None

            def start(self) -> None:
                return None

            def deleteLater(self) -> None:
                return None

        window = MainWindow(coordinator=fake_coordinator, config=self.config, audit_logger=FakeAuditLogger())
        self.addCleanup(window.close)
        window.set_selected_file("C:/tmp/sample.mov")

        with patch("desktop_app.ui.main_window.AnalysisThread", StubThread):
            window._start_analysis()

        self.assertIs(captured["coordinator"], fake_coordinator)
        self.assertEqual(captured["file_path"], "C:/tmp/sample.mov")
        window._analysis_thread = None

    def test_history_button_loads_selected_record_and_updates_probability_indicator(self) -> None:
        fake_history_service = FakeHistoryService()

        class StubDialog:
            def __init__(self, history_service, parent) -> None:  # noqa: ANN001
                self.selected_analysis_id = 42

            def exec(self) -> int:
                return QDialog.DialogCode.Accepted

        window = MainWindow(
            coordinator=FakeCoordinator(),
            config=self.config,
            history_service=fake_history_service,
            audit_log_service=FakeAuditLogService(),
            audit_logger=FakeAuditLogger(),
        )
        self.addCleanup(window.close)

        with patch("desktop_app.ui.main_window.HistoryDialog", StubDialog):
            window._open_history()

        self.assertEqual(fake_history_service.loaded_ids, [42])
        self.assertIsNotNone(window._current_result)
        assert window._current_result is not None
        self.assertEqual(window._current_result.file_name, "history.mp4")
        self.assertIn("Загружено из истории.", window.summary_text.toPlainText())
        self.assertEqual(window.probability_gauge.value(), 82)
        self.assertEqual(window.probability_percent_label.text(), "82.00%")
        technical_items = [window.technical_list.item(index).text() for index in range(window.technical_list.count())]
        self.assertTrue(any("Контроль целостности: Проверено" in item for item in technical_items))

    def test_report_preview_button_opens_dialog(self) -> None:
        captured: dict[str, object] = {}
        result = AnalysisResult(
            status="original",
            media_type="video",
            file_path="",
            file_name="demo.mp4",
            probability=0.21,
            threshold=0.46,
            summary="Нарушений не найдено.",
        )

        class StubPreviewDialog:
            def __init__(self, analysis_result, parent) -> None:  # noqa: ANN001
                captured["result"] = analysis_result
                captured["parent"] = parent

            def exec(self) -> int:
                return QDialog.DialogCode.Accepted

        window = MainWindow(coordinator=FakeCoordinator(), config=self.config, audit_logger=FakeAuditLogger())
        self.addCleanup(window.close)
        window._current_result = result
        window._refresh_controls()

        with patch("desktop_app.ui.main_window.ReportPreviewDialog", StubPreviewDialog):
            window._open_report_preview()

        self.assertIs(captured["result"], result)

    def test_export_report_uses_selected_format(self) -> None:
        fake_audit_logger = FakeAuditLogger()
        result = AnalysisResult(
            status="original",
            media_type="video",
            file_path="",
            file_name="demo.mp4",
            probability=0.21,
            threshold=0.46,
            summary="Нарушений не найдено.",
        )
        window = MainWindow(coordinator=FakeCoordinator(), config=self.config, audit_logger=fake_audit_logger)
        self.addCleanup(window.close)
        window._current_result = result
        window._refresh_controls()

        with patch("desktop_app.ui.main_window.QFileDialog.getSaveFileName", return_value=(str(self.base_dir / "demo"), "HTML Files (*.html)")), patch(
            "desktop_app.ui.main_window.export_result",
            return_value=self.base_dir / "demo.html",
        ) as export_mock, patch("desktop_app.ui.main_window.QMessageBox.information", return_value=None):
            window._export_report()

        export_mock.assert_called_once()
        self.assertEqual(export_mock.call_args.args[2], "html")
        self.assertEqual(fake_audit_logger.events[-1]["event_type"], "report_exported")

    def test_file_selection_is_logged_without_absolute_path(self) -> None:
        fake_audit_logger = FakeAuditLogger()
        window = MainWindow(coordinator=FakeCoordinator(), config=self.config, audit_logger=fake_audit_logger)
        self.addCleanup(window.close)

        window.set_selected_file("C:/tmp/sample.mp4")

        self.assertEqual(fake_audit_logger.events[-1]["event_type"], "file_selected")
        self.assertEqual(fake_audit_logger.events[-1]["details"], {"file_name": "sample.mp4", "extension": ".mp4"})
