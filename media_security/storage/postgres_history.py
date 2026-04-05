from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from media_security.core.analysis import refresh_report_assessment
from media_security.core.models import Finding, ScanReport, Severity

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:  # pragma: no cover - handled at runtime.
    psycopg = None
    dict_row = None


class PostgresScanHistoryStore:
    def __init__(self, dsn: str) -> None:
        if not dsn:
            raise ValueError("PostgreSQL DSN is required for history storage.")
        if psycopg is None:
            raise RuntimeError(
                "Package 'psycopg' is not installed. Install dependencies with: "
                "python -m pip install -e .[dev]"
            )
        self.dsn = dsn
        self._init_schema()

    def enrich_and_store(self, report: ScanReport) -> None:
        if report.metadata is None:
            return

        absolute_path = report.metadata.path
        sha256_hash = report.metadata.hashes.get("sha256", "")
        previous_scan = self._fetch_last_scan_for_path(absolute_path)
        if previous_scan and previous_scan.get("sha256") and previous_scan["sha256"] != sha256_hash:
            report.findings.append(
                Finding(
                    code="FILE_CHANGED_SINCE_LAST_SCAN",
                    severity=Severity.WARNING,
                    message="File content has changed since previous scan.",
                    details={
                        "previous_sha256": previous_scan["sha256"],
                        "current_sha256": sha256_hash,
                        "previous_scanned_at_utc": previous_scan.get("scanned_at_utc"),
                    },
                )
            )
        elif previous_scan and previous_scan.get("sha256") == sha256_hash:
            report.findings.append(
                Finding(
                    code="KNOWN_FILE_HASH",
                    severity=Severity.INFO,
                    message="This file hash was already scanned for the same path.",
                    details={"previous_scanned_at_utc": previous_scan.get("scanned_at_utc")},
                )
            )

        duplicate_paths = self._fetch_other_paths_with_hash(sha256_hash, exclude_path=absolute_path, limit=3)
        if duplicate_paths:
            report.findings.append(
                Finding(
                    code="HASH_SEEN_ON_OTHER_PATHS",
                    severity=Severity.INFO,
                    message="Identical file hash was detected on other paths.",
                    details={"paths": duplicate_paths},
                )
            )

        refresh_report_assessment(report)
        report.scan_id = self._insert_scan(report)

    def _init_schema(self) -> None:
        query = """
            CREATE TABLE IF NOT EXISTS scan_history (
                id BIGSERIAL PRIMARY KEY,
                scanned_at_utc TIMESTAMPTZ NOT NULL,
                file_path TEXT NOT NULL,
                file_name TEXT NOT NULL,
                extension TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                md5 TEXT NOT NULL,
                size_bytes BIGINT NOT NULL,
                mime_type TEXT,
                detected_format TEXT,
                verdict TEXT NOT NULL,
                trust_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                findings_json JSONB NOT NULL,
                metadata_json JSONB NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_scan_history_file_path ON scan_history(file_path);
            CREATE INDEX IF NOT EXISTS idx_scan_history_sha256 ON scan_history(sha256);
        """
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(query)
            connection.commit()

    def _fetch_last_scan_for_path(self, file_path: str) -> dict[str, Any] | None:
        with self._connect(row_factory=dict_row) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT id, scanned_at_utc, sha256
                    FROM scan_history
                    WHERE file_path = %s
                    ORDER BY id DESC
                    LIMIT 1
                    """,
                    (file_path,),
                )
                row = cursor.fetchone()
        return dict(row) if row else None

    def _fetch_other_paths_with_hash(
        self, sha256_hash: str, exclude_path: str, limit: int = 3
    ) -> list[str]:
        if not sha256_hash:
            return []
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT DISTINCT file_path
                    FROM scan_history
                    WHERE sha256 = %s AND file_path <> %s
                    ORDER BY file_path
                    LIMIT %s
                    """,
                    (sha256_hash, exclude_path, limit),
                )
                rows = cursor.fetchall()
        return [row[0] for row in rows]

    def _insert_scan(self, report: ScanReport) -> int:
        if report.metadata is None:
            raise ValueError("Cannot persist report without metadata.")

        metadata = report.metadata
        payload = (
            datetime.now(tz=UTC),
            metadata.path,
            metadata.name,
            metadata.extension,
            metadata.hashes.get("sha256", ""),
            metadata.hashes.get("md5", ""),
            metadata.size_bytes,
            metadata.mime_type,
            metadata.detected_format,
            report.verdict,
            report.trust_score,
            report.risk_level,
            json.dumps([finding.to_dict() for finding in report.findings], ensure_ascii=False),
            json.dumps(metadata.to_dict(), ensure_ascii=False),
        )

        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO scan_history (
                        scanned_at_utc,
                        file_path,
                        file_name,
                        extension,
                        sha256,
                        md5,
                        size_bytes,
                        mime_type,
                        detected_format,
                        verdict,
                        trust_score,
                        risk_level,
                        findings_json,
                        metadata_json
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb)
                    RETURNING id
                    """,
                    payload,
                )
                row = cursor.fetchone()
            connection.commit()
        if row is None:
            raise RuntimeError("Failed to insert record into scan_history.")
        return int(row[0])

    def _connect(self, row_factory: Any | None = None) -> Any:
        connect_kwargs: dict[str, Any] = {}
        if row_factory is not None:
            connect_kwargs["row_factory"] = row_factory
        return psycopg.connect(self.dsn, **connect_kwargs)
