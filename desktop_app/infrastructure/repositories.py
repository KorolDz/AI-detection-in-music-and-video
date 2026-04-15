from __future__ import annotations

import json
from datetime import datetime

from desktop_app.application.result_integrity_service import ResultIntegrityService
from desktop_app.domain import AnalysisHistoryEntry
from desktop_app.domain import AnalysisResult
from desktop_app.domain import AuditEvent
from desktop_app.domain import AuditLogEntry

from .database import DatabaseManager


class SQLiteResultRepository:
    def __init__(self, db_manager: DatabaseManager, integrity_service: ResultIntegrityService) -> None:
        self._db_manager = db_manager
        self._integrity_service = integrity_service

    def save(self, result: AnalysisResult) -> int:
        uploaded_at = self._serialize_datetime(result.uploaded_at)
        analysis_started_at = self._serialize_datetime(result.analysis_started_at)
        analyzed_at = self._serialize_datetime(result.analyzed_at)
        stored_at = self._serialize_datetime(result.stored_at)
        is_fake = self._serialize_bool(result.is_fake)
        indicators_json = json.dumps(result.indicators, ensure_ascii=False)
        technical_details_json = json.dumps(result.technical_details, ensure_ascii=False)

        with self._db_manager.connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO analysis_results (
                    file_name,
                    file_path,
                    media_type,
                    uploaded_at,
                    analysis_started_at,
                    analyzed_at,
                    stored_at,
                    status,
                    is_fake,
                    probability,
                    threshold,
                    summary,
                    error_message,
                    indicators_json,
                    technical_details_json,
                    file_sha256,
                    integrity_signature,
                    integrity_version,
                    report_path
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.file_name,
                    None,
                    result.media_type,
                    uploaded_at,
                    analysis_started_at,
                    analyzed_at,
                    stored_at,
                    result.status,
                    is_fake,
                    result.probability,
                    result.threshold,
                    result.summary,
                    result.error_message,
                    indicators_json,
                    technical_details_json,
                    result.file_sha256,
                    None,
                    ResultIntegrityService.VERSION,
                    result.report_path,
                ),
            )
            analysis_id = int(cursor.lastrowid)
            integrity_signature = self._integrity_service.sign_result(
                analysis_id=analysis_id,
                file_name=result.file_name,
                media_type=result.media_type,
                uploaded_at=uploaded_at,
                analysis_started_at=analysis_started_at,
                analyzed_at=analyzed_at,
                stored_at=stored_at,
                status=result.status,
                is_fake=is_fake,
                probability=result.probability,
                threshold=result.threshold,
                summary=result.summary,
                error_message=result.error_message,
                indicators_json=indicators_json,
                technical_details_json=technical_details_json,
                file_sha256=result.file_sha256,
            )
            conn.execute(
                """
                UPDATE analysis_results
                SET integrity_signature = ?, integrity_version = ?
                WHERE id = ?
                """,
                (integrity_signature, ResultIntegrityService.VERSION, analysis_id),
            )

        result.analysis_id = analysis_id
        result.integrity_signature = integrity_signature
        result.integrity_verified = True
        return analysis_id

    def list_recent(self, limit: int = 100) -> list[AnalysisHistoryEntry]:
        safe_limit = max(1, int(limit))
        with self._db_manager.connection() as conn:
            rows = conn.execute(
                """
                SELECT
                    id,
                    file_name,
                    media_type,
                    uploaded_at,
                    analysis_started_at,
                    analyzed_at,
                    stored_at,
                    status,
                    is_fake,
                    probability,
                    threshold,
                    summary,
                    error_message,
                    indicators_json,
                    technical_details_json,
                    file_sha256,
                    integrity_signature,
                    integrity_version
                FROM analysis_results
                ORDER BY stored_at DESC, id DESC
                LIMIT ?
                """,
                (safe_limit,),
            ).fetchall()

        return [
            AnalysisHistoryEntry(
                analysis_id=row["id"],
                file_name=row["file_name"],
                media_type=row["media_type"],
                stored_at=self._deserialize_datetime(row["stored_at"]),
                status=row["status"],
                probability=row["probability"],
                file_sha256=row["file_sha256"],
                integrity_verified=self._verify_integrity(row),
            )
            for row in rows
        ]

    def get_by_id(self, analysis_id: int) -> AnalysisResult | None:
        with self._db_manager.connection() as conn:
            row = conn.execute(
                """
                SELECT
                    id,
                    file_name,
                    file_path,
                    media_type,
                    uploaded_at,
                    analysis_started_at,
                    analyzed_at,
                    stored_at,
                    status,
                    is_fake,
                    probability,
                    threshold,
                    summary,
                    error_message,
                    indicators_json,
                    technical_details_json,
                    file_sha256,
                    integrity_signature,
                    integrity_version,
                    report_path
                FROM analysis_results
                WHERE id = ?
                """,
                (analysis_id,),
            ).fetchone()

        if row is None:
            return None

        stored_file_path = row["file_path"] or ""
        return AnalysisResult(
            status=row["status"],
            media_type=row["media_type"],
            file_path=stored_file_path,
            file_name=row["file_name"],
            is_fake=self._deserialize_bool(row["is_fake"]),
            probability=row["probability"],
            threshold=row["threshold"],
            summary=row["summary"],
            error_message=row["error_message"],
            indicators=json.loads(row["indicators_json"]),
            technical_details=json.loads(row["technical_details_json"]),
            analysis_id=row["id"],
            file_sha256=row["file_sha256"],
            uploaded_at=self._deserialize_datetime(row["uploaded_at"]),
            analysis_started_at=self._deserialize_datetime(row["analysis_started_at"]),
            analyzed_at=self._deserialize_datetime(row["analyzed_at"]),
            stored_at=self._deserialize_datetime(row["stored_at"]),
            integrity_signature=row["integrity_signature"],
            integrity_verified=self._verify_integrity(row),
            report_path=row["report_path"],
        )

    def _verify_integrity(self, row) -> bool | None:  # noqa: ANN001
        return self._integrity_service.verify_result(
            analysis_id=row["id"],
            file_name=row["file_name"],
            media_type=row["media_type"],
            uploaded_at=row["uploaded_at"],
            analysis_started_at=row["analysis_started_at"],
            analyzed_at=row["analyzed_at"],
            stored_at=row["stored_at"],
            status=row["status"],
            is_fake=row["is_fake"],
            probability=row["probability"],
            threshold=row["threshold"],
            summary=row["summary"],
            error_message=row["error_message"],
            indicators_json=row["indicators_json"],
            technical_details_json=row["technical_details_json"],
            file_sha256=row["file_sha256"],
            integrity_signature=row["integrity_signature"],
            integrity_version=row["integrity_version"],
        )

    @staticmethod
    def _serialize_bool(value: bool | None) -> int | None:
        if value is None:
            return None
        return 1 if value else 0

    @staticmethod
    def _deserialize_bool(value: int | None) -> bool | None:
        if value is None:
            return None
        return bool(value)

    @staticmethod
    def _serialize_datetime(value: datetime | None) -> str | None:
        if value is None:
            return None
        return value.isoformat(timespec="seconds")

    @staticmethod
    def _deserialize_datetime(value: str | None) -> datetime | None:
        if value is None:
            return None
        return datetime.fromisoformat(value)


class SQLiteAuditLogRepository:
    def __init__(self, db_manager: DatabaseManager) -> None:
        self._db_manager = db_manager

    def write(self, event: AuditEvent) -> None:
        with self._db_manager.connection() as conn:
            conn.execute(
                """
                INSERT INTO audit_log (
                    event_time,
                    event_type,
                    file_path,
                    result_id,
                    severity,
                    message,
                    details_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_time.isoformat(timespec="seconds"),
                    event.event_type,
                    None,
                    event.result_id,
                    event.severity,
                    event.message,
                    json.dumps(event.details, ensure_ascii=False),
                ),
            )

    def list_recent(self, limit: int = 200) -> list[AuditLogEntry]:
        safe_limit = max(1, int(limit))
        with self._db_manager.connection() as conn:
            rows = conn.execute(
                """
                SELECT
                    event_time,
                    event_type,
                    severity,
                    message,
                    result_id,
                    details_json
                FROM audit_log
                ORDER BY event_time DESC, id DESC
                LIMIT ?
                """,
                (safe_limit,),
            ).fetchall()

        return [
            AuditLogEntry(
                event_time=datetime.fromisoformat(row["event_time"]),
                event_type=row["event_type"],
                severity=row["severity"],
                message=row["message"],
                result_id=row["result_id"],
                details=json.loads(row["details_json"]),
            )
            for row in rows
        ]
