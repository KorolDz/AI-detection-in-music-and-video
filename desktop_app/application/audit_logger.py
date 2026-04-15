from __future__ import annotations

from desktop_app.application.ports import AuditLogRepository
from desktop_app.domain import AuditEvent


class AuditLogger:
    def __init__(self, repository: AuditLogRepository) -> None:
        self._repository = repository

    def log_event(
        self,
        event_type: str,
        severity: str,
        message: str,
        *,
        file_path: str | None = None,
        result_id: int | None = None,
        details: dict[str, object] | None = None,
    ) -> None:
        event = AuditEvent(
            event_type=event_type,
            severity=severity,
            message=message,
            file_path=file_path,
            result_id=result_id,
            details=dict(details or {}),
        )
        self._repository.write(event)
