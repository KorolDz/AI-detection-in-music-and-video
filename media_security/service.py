from __future__ import annotations

from pathlib import Path
from typing import Protocol

from media_security.core.models import ScanReport
from media_security.core.scanner import MediaSecurityScanner
from media_security.storage.sqlite_history import SQLiteScanHistoryStore


class HistoryStore(Protocol):
    def enrich_and_store(self, report: ScanReport) -> None:
        ...


class SecurityAnalysisService:
    def __init__(
        self,
        scanner: MediaSecurityScanner | None = None,
        history_store: HistoryStore | None = None,
    ) -> None:
        self.scanner = scanner or MediaSecurityScanner()
        self.history_store = history_store

    @classmethod
    def with_sqlite(cls, sqlite_path: str | Path | None = None) -> "SecurityAnalysisService":
        return cls(history_store=SQLiteScanHistoryStore(sqlite_path))

    @classmethod
    def without_history(cls) -> "SecurityAnalysisService":
        return cls(history_store=None)

    def analyze_path(
        self, target: str | Path, recursive: bool = False, persist_history: bool = True
    ) -> list[ScanReport]:
        reports = self.scanner.scan_path(target=target, recursive=recursive)
        if persist_history and self.history_store is not None:
            for report in reports:
                self.history_store.enrich_and_store(report)
        return reports
