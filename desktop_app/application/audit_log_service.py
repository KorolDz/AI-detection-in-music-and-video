from __future__ import annotations

from desktop_app.application.audit_logger import AuditLogger
from desktop_app.application.ports import AuditLogRepository
from desktop_app.domain import AuditLogEntry


class AuditLogService:
    def __init__(self, repository: AuditLogRepository, audit_logger: AuditLogger | None = None) -> None:
        self._repository = repository
        self._audit_logger = audit_logger

    def list_recent(self, limit: int = 200) -> list[AuditLogEntry]:
        entries = self._repository.list_recent(limit=limit)
        if self._audit_logger is not None:
            self._audit_logger.log_event(
                "audit_log_viewed",
                "info",
                "Открыт журнал действий.",
                details={"entries_returned": len(entries)},
            )
        return entries
