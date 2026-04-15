from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

try:
    from PySide6.QtWidgets import QApplication
except ImportError:  # pragma: no cover - depends on local env
    QApplication = None  # type: ignore[assignment]

from desktop_app.config import AppConfig

if QApplication is not None:
    from desktop_app.domain import AnalysisResult
    from desktop_app.ui.main_window import MainWindow


class FakeCoordinator:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def run(self, file_path: str) -> "AnalysisResult":  # pragma: no cover - used only with PySide6
        self.calls.append(file_path)
        return AnalysisResult(
            status="original",
            media_type="video",
            file_path=file_path,
            file_name=Path(file_path).name,
            summary="Видео не превышает порог.",
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

    def test_start_button_state_depends_on_selected_file(self) -> None:
        window = MainWindow(coordinator=FakeCoordinator(), config=self.config)
        self.addCleanup(window.close)

        self.assertFalse(window.start_button.isEnabled())

        window.set_selected_file("C:/tmp/sample.mp4")
        self.assertTrue(window.start_button.isEnabled())
        self.assertFalse(window.export_button.isEnabled())

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

        window = MainWindow(coordinator=fake_coordinator, config=self.config)
        self.addCleanup(window.close)
        window.set_selected_file("C:/tmp/sample.mov")

        with patch("desktop_app.ui.main_window.AnalysisThread", StubThread):
            window._start_analysis()

        self.assertIs(captured["coordinator"], fake_coordinator)
        self.assertEqual(captured["file_path"], "C:/tmp/sample.mov")
