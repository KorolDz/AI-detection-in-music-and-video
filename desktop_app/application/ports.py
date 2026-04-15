from __future__ import annotations

from typing import Protocol

from desktop_app.domain import AnalysisHistoryEntry
from desktop_app.domain import AnalysisResult
from desktop_app.domain import AuditLogEntry
from desktop_app.domain import AuditEvent
from desktop_app.domain import MediaFileRef


class AnalyzerGateway(Protocol):
    def analyze(self, media_file: MediaFileRef) -> AnalysisResult:
        ...


class ResultRepository(Protocol):
    def save(self, result: AnalysisResult) -> int:
        ...

    def list_recent(self, limit: int = 100) -> list[AnalysisHistoryEntry]:
        ...

    def get_by_id(self, analysis_id: int) -> AnalysisResult | None:
        ...


class AuditLogRepository(Protocol):
    def write(self, event: AuditEvent) -> None:
        ...

    def list_recent(self, limit: int = 200) -> list[AuditLogEntry]:
        ...
