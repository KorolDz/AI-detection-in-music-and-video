from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


class DatabaseManager:
    def __init__(self, db_path: str | Path) -> None:
        self._db_path = Path(db_path)

    @property
    def db_path(self) -> Path:
        return self._db_path

    def initialize(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as conn:
            conn.execute("PRAGMA foreign_keys = OFF;")
            self._create_tables(conn)
            self._migrate_analysis_results_file_path(conn)
            self._ensure_analysis_results_columns(conn)
            self._create_indexes(conn)
            conn.execute("PRAGMA foreign_keys = ON;")

    def _create_tables(self, conn: sqlite3.Connection) -> None:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS analysis_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_name TEXT NOT NULL,
                file_path TEXT,
                media_type TEXT NOT NULL,
                uploaded_at TEXT,
                analysis_started_at TEXT,
                analyzed_at TEXT,
                stored_at TEXT,
                status TEXT NOT NULL,
                is_fake INTEGER,
                probability REAL,
                threshold REAL,
                summary TEXT NOT NULL,
                error_message TEXT,
                indicators_json TEXT NOT NULL,
                technical_details_json TEXT NOT NULL,
                file_sha256 TEXT,
                integrity_signature TEXT,
                integrity_version INTEGER,
                report_path TEXT
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_time TEXT NOT NULL,
                event_type TEXT NOT NULL,
                file_path TEXT,
                result_id INTEGER,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                details_json TEXT NOT NULL,
                FOREIGN KEY(result_id) REFERENCES analysis_results(id)
            );
            """
        )

    def _create_indexes(self, conn: sqlite3.Connection) -> None:
        conn.executescript(
            """
            CREATE INDEX IF NOT EXISTS idx_analysis_results_stored_at
            ON analysis_results (stored_at DESC, id DESC);

            CREATE INDEX IF NOT EXISTS idx_audit_log_event_time
            ON audit_log (event_time DESC, id DESC);
            """
        )

    def _migrate_analysis_results_file_path(self, conn: sqlite3.Connection) -> None:
        table_info = conn.execute("PRAGMA table_info(analysis_results)").fetchall()
        if not table_info:
            return

        file_path_row = next((row for row in table_info if row["name"] == "file_path"), None)
        if file_path_row is None or int(file_path_row["notnull"]) == 0:
            return

        conn.executescript(
            """
            CREATE TABLE analysis_results_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_name TEXT NOT NULL,
                file_path TEXT,
                media_type TEXT NOT NULL,
                uploaded_at TEXT,
                analysis_started_at TEXT,
                analyzed_at TEXT,
                stored_at TEXT,
                status TEXT NOT NULL,
                is_fake INTEGER,
                probability REAL,
                threshold REAL,
                summary TEXT NOT NULL,
                error_message TEXT,
                indicators_json TEXT NOT NULL,
                technical_details_json TEXT NOT NULL,
                file_sha256 TEXT,
                integrity_signature TEXT,
                integrity_version INTEGER,
                report_path TEXT
            );

            INSERT INTO analysis_results_new (
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
            )
            SELECT
                id,
                file_name,
                NULL,
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
            FROM analysis_results;

            DROP TABLE analysis_results;
            ALTER TABLE analysis_results_new RENAME TO analysis_results;
            """
        )

    def _ensure_analysis_results_columns(self, conn: sqlite3.Connection) -> None:
        table_info = conn.execute("PRAGMA table_info(analysis_results)").fetchall()
        existing_columns = {row["name"] for row in table_info}
        required_columns = {
            "uploaded_at": "TEXT",
            "analysis_started_at": "TEXT",
            "integrity_signature": "TEXT",
            "integrity_version": "INTEGER",
        }
        for column_name, column_type in required_columns.items():
            if column_name in existing_columns:
                continue
            conn.execute(
                f"ALTER TABLE analysis_results ADD COLUMN {column_name} {column_type}"
            )

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()
