from __future__ import annotations

from pathlib import Path

from .app import create_app_context
from .application.coordinator import AnalysisCoordinator
from .config import AppConfig
from .domain import AnalysisResult


class AnalysisService:
    def __init__(self, config: AppConfig | None = None) -> None:
        self._context = create_app_context(config)
        self._coordinator: AnalysisCoordinator = self._context.coordinator

    def analyze(self, file_path: str | Path) -> AnalysisResult:
        return self._coordinator.run(file_path)
