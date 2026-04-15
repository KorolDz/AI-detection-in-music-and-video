from __future__ import annotations

try:
    from PySide6.QtCore import QThread
    from PySide6.QtCore import Signal
except ImportError as exc:  # pragma: no cover - depends on local env
    raise ImportError("Для запуска desktop-интерфейса необходимо установить PySide6.") from exc

from desktop_app.application.coordinator import AnalysisCoordinator


class AnalysisThread(QThread):
    analysis_finished = Signal(object)
    analysis_failed = Signal(str)

    def __init__(self, coordinator: AnalysisCoordinator, file_path: str) -> None:
        super().__init__()
        self._coordinator = coordinator
        self._file_path = file_path

    def run(self) -> None:
        try:
            result = self._coordinator.run(self._file_path)
        except Exception as exc:  # noqa: BLE001
            self.analysis_failed.emit(str(exc))
            return
        self.analysis_finished.emit(result)
