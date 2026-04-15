from __future__ import annotations

from datetime import datetime
from pathlib import Path

from desktop_app.application.audit_logger import AuditLogger
from desktop_app.application.file_hash_service import FileHashService
from desktop_app.application.file_loader import FileLoader
from desktop_app.application.local_processing_service import LocalProcessingError
from desktop_app.application.local_processing_service import LocalProcessingService
from desktop_app.application.ports import AnalyzerGateway
from desktop_app.application.ports import ResultRepository
from desktop_app.application.precheck_service import PrecheckService
from desktop_app.application.report_formatter import ReportFormatter
from desktop_app.domain import AnalysisRequest
from desktop_app.domain import AnalysisResult
from desktop_app.domain import LocalProcessingSession
from desktop_app.domain import MediaFileRef
from desktop_app.domain import PrecheckResult


class AnalysisCoordinator:
    def __init__(
        self,
        file_loader: FileLoader,
        file_hash_service: FileHashService,
        local_processing_service: LocalProcessingService,
        precheck_service: PrecheckService,
        analyzer_gateway: AnalyzerGateway,
        result_repository: ResultRepository,
        audit_logger: AuditLogger,
        report_formatter: ReportFormatter,
    ) -> None:
        self._file_loader = file_loader
        self._file_hash_service = file_hash_service
        self._local_processing_service = local_processing_service
        self._precheck_service = precheck_service
        self._analyzer_gateway = analyzer_gateway
        self._result_repository = result_repository
        self._audit_logger = audit_logger
        self._report_formatter = report_formatter

    def run(self, path: str | Path) -> AnalysisResult:
        requested_at = datetime.now()
        uploaded_at: datetime | None = None
        analysis_started_at: datetime | None = None
        result: AnalysisResult | None = None
        processing_session: LocalProcessingSession | None = None
        file_sha256: str | None = None

        try:
            try:
                media_file = self._file_loader.load(path)
                uploaded_at = datetime.now()
            except (FileNotFoundError, ValueError) as exc:
                result = self._finalize_error_result(
                    AnalysisResult(
                        status="error",
                        media_type="unknown",
                        file_path="",
                        file_name=Path(path).name,
                        summary="Анализ завершился с ошибкой.",
                        technical_details=[],
                        error_message=str(exc),
                        analyzed_at=requested_at,
                    ),
                    event_type="analysis_failed",
                    severity="error",
                    event_details={"stage": "file_loader", "file_name": Path(path).name},
                )
                return result

            self._audit_logger.log_event(
                "analysis_requested",
                "info",
                "Запрошен локальный анализ медиафайла.",
                details={
                    "file_name": media_file.file_name,
                    "media_type": media_file.media_type,
                    "extension": media_file.extension,
                    "size_bytes": media_file.size_bytes,
                    "uploaded_at": uploaded_at.isoformat(timespec="seconds") if uploaded_at else None,
                },
            )

            try:
                processing_session = self._local_processing_service.start(media_file)
            except LocalProcessingError as exc:
                result = self._handle_local_processing_failure(
                    media_file,
                    requested_at,
                    uploaded_at,
                    exc,
                )
                return result

            prepared_media = self._build_prepared_media(media_file, processing_session)

            try:
                file_sha256 = self._file_hash_service.calculate_sha256(prepared_media.working_path)
            except OSError as exc:
                result = self._handle_local_processing_failure(
                    media_file,
                    requested_at,
                    uploaded_at,
                    LocalProcessingError(
                        f"Не удалось вычислить SHA-256 для подготовленного файла: {exc}",
                        stage="hashing",
                    ),
                )
                return result

            self._audit_logger.log_event(
                "local_processing_started",
                "info",
                "Файл подготовлен к локальному анализу.",
                details={
                    "file_name": prepared_media.file_name,
                    "detected_format": prepared_media.detected_format,
                    "temporary_copy_created": processing_session.cleanup_required,
                    "file_sha256_calculated": file_sha256 is not None,
                },
            )

            request = AnalysisRequest(media_file=prepared_media, requested_at=requested_at)
            precheck = self._precheck_service.validate(prepared_media)
            if not precheck.is_valid:
                result = self._handle_precheck_failure(
                    request,
                    precheck,
                    uploaded_at,
                    file_sha256,
                )
                return result

            analysis_started_at = datetime.now()
            self._audit_logger.log_event(
                "analysis_started",
                "info",
                "Запущен модуль анализа.",
                details={
                    "file_name": prepared_media.file_name,
                    "analysis_started_at": analysis_started_at.isoformat(timespec="seconds"),
                },
            )

            result = self._analyzer_gateway.analyze(prepared_media)
            if result.analyzed_at is None:
                result.analyzed_at = datetime.now()
            result.uploaded_at = uploaded_at
            result.analysis_started_at = analysis_started_at
            result.file_sha256 = file_sha256

            result = self._store_and_log_result(result)
            return result
        finally:
            self._finish_local_processing(processing_session, result)

    def _build_prepared_media(
        self,
        source_media: MediaFileRef,
        session: LocalProcessingSession,
    ) -> MediaFileRef:
        return MediaFileRef(
            file_path=source_media.file_name,
            file_name=source_media.file_name,
            media_type=session.media_type,
            size_bytes=source_media.size_bytes,
            extension=source_media.extension,
            source_path=session.source_path,
            working_path=session.working_path,
            detected_format=session.detected_format,
            is_temporary=session.cleanup_required,
        )

    def _handle_local_processing_failure(
        self,
        media_file: MediaFileRef,
        requested_at: datetime,
        uploaded_at: datetime | None,
        exc: LocalProcessingError,
    ) -> AnalysisResult:
        technical_details = [
            f"Тип медиа: {media_file.media_type}",
            f"Размер файла (байт): {media_file.size_bytes}",
            f"Расширение: {media_file.extension}",
        ]
        technical_details.extend(exc.warnings)

        result = AnalysisResult(
            status="error",
            media_type=media_file.media_type,
            file_path="",
            file_name=media_file.file_name,
            summary="Локальная обработка файла завершилась ошибкой.",
            technical_details=technical_details,
            error_message=exc.reason,
            uploaded_at=uploaded_at,
            analyzed_at=requested_at,
        )
        event_type = "local_processing_failed"
        if exc.stage == "secure_intake":
            event_type = "secure_intake_failed"
        return self._finalize_error_result(
            result,
            event_type=event_type,
            severity="warning",
            event_details={
                "stage": exc.stage,
                "file_name": media_file.file_name,
                "warnings": exc.warnings,
            },
        )

    def _handle_precheck_failure(
        self,
        request: AnalysisRequest,
        precheck: PrecheckResult,
        uploaded_at: datetime | None,
        file_sha256: str | None,
    ) -> AnalysisResult:
        technical_details = [
            f"Тип медиа: {request.media_file.media_type}",
            f"Размер файла (байт): {request.media_file.size_bytes}",
            f"Расширение: {request.media_file.extension}",
        ]
        if request.media_file.detected_format != "unknown":
            technical_details.append(
                f"Определенный формат по сигнатуре: {request.media_file.detected_format}"
            )
        technical_details.extend(precheck.warnings)

        result = AnalysisResult(
            status="error",
            media_type=request.media_file.media_type,
            file_path="",
            file_name=request.media_file.file_name,
            summary="Предварительная проверка файла завершилась ошибкой.",
            technical_details=technical_details,
            error_message=precheck.reason,
            file_sha256=file_sha256,
            uploaded_at=uploaded_at,
            analyzed_at=request.requested_at,
        )
        return self._finalize_error_result(
            result,
            event_type="precheck_failed",
            severity="warning",
            event_details={"file_name": request.media_file.file_name, "warnings": precheck.warnings},
        )

    def _store_and_log_result(self, result: AnalysisResult) -> AnalysisResult:
        result.stored_at = datetime.now()
        result.analysis_id = self._result_repository.save(result)
        result.export_payload = self._report_formatter.build_export_payload(result)

        event_type = "analysis_completed"
        severity = "info"
        message = "Локальный анализ завершен успешно."
        if result.is_error:
            event_type = "analysis_failed"
            severity = "error"
            message = result.error_message or "Анализ завершился с ошибкой."

        self._audit_logger.log_event(
            event_type,
            severity,
            message,
            result_id=result.analysis_id,
            details={
                "file_name": result.file_name,
                "status": result.status,
                "is_fake": result.is_fake,
                "probability": result.probability,
                "file_sha256_calculated": result.file_sha256 is not None,
                "uploaded_at": self._serialize_datetime(result.uploaded_at),
                "analysis_started_at": self._serialize_datetime(result.analysis_started_at),
                "analyzed_at": self._serialize_datetime(result.analyzed_at),
                "stored_at": self._serialize_datetime(result.stored_at),
                "integrity_verified": result.integrity_verified,
            },
        )
        return result

    def _finalize_error_result(
        self,
        result: AnalysisResult,
        *,
        event_type: str,
        severity: str,
        event_details: dict[str, object] | None = None,
    ) -> AnalysisResult:
        result.stored_at = datetime.now()
        result.analysis_id = self._result_repository.save(result)
        result.export_payload = self._report_formatter.build_export_payload(result)
        details = dict(event_details or {})
        details["file_sha256_calculated"] = result.file_sha256 is not None
        details["uploaded_at"] = self._serialize_datetime(result.uploaded_at)
        details["analysis_started_at"] = self._serialize_datetime(result.analysis_started_at)
        details["analyzed_at"] = self._serialize_datetime(result.analyzed_at)
        details["stored_at"] = self._serialize_datetime(result.stored_at)
        details["integrity_verified"] = result.integrity_verified
        self._audit_logger.log_event(
            event_type,
            severity,
            result.error_message or result.summary,
            result_id=result.analysis_id,
            details=details,
        )
        return result

    def _finish_local_processing(
        self,
        session: LocalProcessingSession | None,
        result: AnalysisResult | None,
    ) -> None:
        if session is None or not session.cleanup_required:
            return

        try:
            self._local_processing_service.finish(session)
        except Exception as exc:  # noqa: BLE001
            self._audit_logger.log_event(
                "temporary_file_cleanup_failed",
                "warning",
                "Не удалось удалить временные данные локальной обработки.",
                result_id=result.analysis_id if result is not None else None,
                details={
                    "file_name": session.source_name,
                    "detected_format": session.detected_format,
                    "temporary_copy_deleted": False,
                    "error": str(exc),
                },
            )
            return

        self._audit_logger.log_event(
            "temporary_file_deleted",
            "info",
            "Временные данные локальной обработки удалены.",
            result_id=result.analysis_id if result is not None else None,
            details={
                "file_name": session.source_name,
                "detected_format": session.detected_format,
                "temporary_copy_deleted": True,
            },
        )

    @staticmethod
    def _serialize_datetime(value: datetime | None) -> str | None:
        if value is None:
            return None
        return value.isoformat(timespec="seconds")
