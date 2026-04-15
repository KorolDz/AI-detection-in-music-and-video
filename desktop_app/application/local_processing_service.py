from __future__ import annotations

from datetime import datetime
from pathlib import Path

from desktop_app.application.file_loader import FileLoader
from desktop_app.application.secure_file_intake import SecureFileIntakeService
from desktop_app.domain import LocalProcessingSession
from desktop_app.domain import MediaFileRef


class LocalProcessingError(Exception):
    def __init__(
        self,
        reason: str,
        *,
        warnings: list[str] | None = None,
        stage: str = "local_processing",
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.warnings = list(warnings or [])
        self.stage = stage


class LocalProcessingService:
    def __init__(self, secure_file_intake: SecureFileIntakeService) -> None:
        self._secure_file_intake = secure_file_intake

    def start(self, media_file: MediaFileRef) -> LocalProcessingSession:
        try:
            FileLoader._ensure_local_source(media_file.source_path)
        except ValueError as exc:
            raise LocalProcessingError(str(exc), stage="local_source") from exc

        secure_load = self._secure_file_intake.prepare(media_file)
        if not secure_load.is_safe:
            raise LocalProcessingError(
                secure_load.reason or "Безопасная загрузка завершилась ошибкой.",
                warnings=secure_load.warnings,
                stage="secure_intake",
            )

        prepared_file = secure_load.prepared_file
        if prepared_file is None:
            raise LocalProcessingError(
                "Локальная обработка не получила временную копию файла.",
                warnings=secure_load.warnings,
                stage="local_processing",
            )

        return LocalProcessingSession(
            source_name=media_file.file_name,
            source_path=media_file.source_path,
            working_path=prepared_file.working_path,
            media_type=prepared_file.media_type,
            detected_format=prepared_file.detected_format,
            started_at=datetime.now(),
            cleanup_required=prepared_file.is_temporary,
            warnings=secure_load.warnings,
        )

    def finish(self, session: LocalProcessingSession) -> None:
        if not session.cleanup_required:
            return

        media_file = MediaFileRef(
            file_path=session.source_name,
            file_name=session.source_name,
            media_type=session.media_type,
            size_bytes=0,
            extension=Path(session.working_path).suffix.lower(),
            source_path=session.source_path,
            working_path=session.working_path,
            detected_format=session.detected_format,
            is_temporary=True,
        )
        self._secure_file_intake.cleanup(media_file)
