from __future__ import annotations

import json
from datetime import datetime

from desktop_app.domain import AnalysisResult
from desktop_app.domain import AuditEvent

from .database import DatabaseManager


class SQLiteResultRepository:
    def __init__(self, db_manager: DatabaseManager) -> None:
        self._db_manager = db_manager

    def save(self, result: AnalysisResult) -> int:
        with self._db_manager.connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO analysis_results (
                    file_name,
                    file_path,
                    media_type,
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
                    report_path
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.file_name,
                    None,
                    result.media_type,
                    self._serialize_datetime(result.analyzed_at),
                    self._serialize_datetime(result.stored_at),
                    result.status,
                    self._serialize_bool(result.is_fake),
                    result.probability,
                    result.threshold,
                    result.summary,
                    result.error_message,
                    json.dumps(result.indicators, ensure_ascii=False),
                    json.dumps(result.technical_details, ensure_ascii=False),
                    result.file_sha256,
                    result.report_path,
                ),
            )
            return int(cursor.lastrowid)

    def get_by_id(self, analysis_id: int) -> AnalysisResult | None:
        with self._db_manager.connection() as conn:
            row = conn.execute(
                """
                SELECT
                    id,
                    file_name,
                    file_path,
                    media_type,
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
            analyzed_at=self._deserialize_datetime(row["analyzed_at"]),
            stored_at=self._deserialize_datetime(row["stored_at"]),
            report_path=row["report_path"],
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
