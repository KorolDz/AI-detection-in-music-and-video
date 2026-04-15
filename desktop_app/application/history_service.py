from __future__ import annotations

from desktop_app.application.audit_logger import AuditLogger
from desktop_app.application.ports import ResultRepository
from desktop_app.domain import AnalysisHistoryEntry
from desktop_app.domain import AnalysisResult


class AnalysisHistoryService:
    def __init__(self, repository: ResultRepository, audit_logger: AuditLogger | None = None) -> None:
        self._repository = repository
        self._audit_logger = audit_logger

    def list_recent(self, limit: int = 100) -> list[AnalysisHistoryEntry]:
        entries = self._repository.list_recent(limit=limit)
        if self._audit_logger is not None:
            self._audit_logger.log_event(
                "history_viewed",
                "info",
                "Открыта история проверок.",
                details={"entries_returned": len(entries)},
            )
        return entries

    def get_analysis(self, analysis_id: int) -> AnalysisResult | None:
        result = self._repository.get_by_id(analysis_id)
        if self._audit_logger is not None:
            self._audit_logger.log_event(
                "history_entry_opened",
                "info",
                "Открыта запись из истории проверок.",
                result_id=analysis_id,
                details={"analysis_id": analysis_id},
            )
            if result is not None and result.integrity_verified is not None:
                self._audit_logger.log_event(
                    "integrity_check_passed" if result.integrity_verified else "integrity_check_failed",
                    "info" if result.integrity_verified else "warning",
                    "Проверка целостности записи истории выполнена.",
                    result_id=result.analysis_id,
                    details={
                        "analysis_id": result.analysis_id,
                        "integrity_verified": result.integrity_verified,
                    },
                )
        return result
