from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from media_security.core.analysis import refresh_report_assessment
from media_security.core.models import Finding, ScanReport, Severity
from media_security.storage.sqlite_config import harden_sqlite_file_permissions, resolve_sqlite_path


class SQLiteScanHistoryStore:
    def __init__(self, sqlite_path: str | Path | None = None) -> None:
        self.sqlite_path = resolve_sqlite_path(sqlite_path)
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
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scanned_at_utc TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_name TEXT NOT NULL,
                extension TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                md5 TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                mime_type TEXT,
                detected_format TEXT,
                verdict TEXT NOT NULL,
                trust_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                findings_json TEXT NOT NULL,
                metadata_json TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_scan_history_file_path ON scan_history(file_path);
            CREATE INDEX IF NOT EXISTS idx_scan_history_sha256 ON scan_history(sha256);
        """
        with self._connect() as connection:
            connection.executescript(query)

    def _fetch_last_scan_for_path(self, file_path: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT id, scanned_at_utc, sha256
                FROM scan_history
                WHERE file_path = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (file_path,),
            ).fetchone()
        return dict(row) if row else None

    def _fetch_other_paths_with_hash(
        self, sha256_hash: str, exclude_path: str, limit: int = 3
    ) -> list[str]:
        if not sha256_hash:
            return []
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT DISTINCT file_path
                FROM scan_history
                WHERE sha256 = ? AND file_path <> ?
                ORDER BY file_path
                LIMIT ?
                """,
                (sha256_hash, exclude_path, limit),
            ).fetchall()
        return [str(row["file_path"]) for row in rows]

    def _insert_scan(self, report: ScanReport) -> int:
        if report.metadata is None:
            raise ValueError("Cannot persist report without metadata.")

        metadata = report.metadata
        payload = (
            datetime.now(tz=UTC).isoformat(),
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
            cursor = connection.execute(
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
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                payload,
            )
            return int(cursor.lastrowid)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.sqlite_path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        self._apply_security_pragmas(connection)
        harden_sqlite_file_permissions(self.sqlite_path)
        return connection

    @staticmethod
    def _apply_security_pragmas(connection: sqlite3.Connection) -> None:
        pragmas = (
            "PRAGMA foreign_keys = ON",
            "PRAGMA journal_mode = WAL",
            "PRAGMA synchronous = FULL",
            "PRAGMA secure_delete = ON",
            "PRAGMA temp_store = MEMORY",
            "PRAGMA busy_timeout = 5000",
            "PRAGMA trusted_schema = OFF",
        )
        for pragma in pragmas:
            try:
                connection.execute(pragma)
            except sqlite3.DatabaseError:
                continue
