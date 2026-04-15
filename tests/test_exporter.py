from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import datetime
from pathlib import Path

from desktop_app.application.report_formatter import ReportFormatter
from desktop_app.domain import AnalysisResult
from desktop_app.exporter import export_result_to_txt
from desktop_app.infrastructure.database import DatabaseManager
from desktop_app.infrastructure.repositories import SQLiteResultRepository


class ExporterAndRepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.base_dir = Path(self.temp_dir.name)

    def test_writes_export_payload_to_txt_file(self) -> None:
        result = AnalysisResult(
            status="original",
            media_type="video",
            file_path="C:/videos/sample.mp4",
            file_name="sample.mp4",
            summary="Видео не превышает порог.",
            export_payload="demo report\n",
        )
        destination = self.base_dir / "report.txt"

        saved_path = export_result_to_txt(result, destination)

        self.assertEqual(saved_path, destination)
        self.assertTrue(destination.is_file())
        self.assertEqual(destination.read_text(encoding="utf-8"), "demo report\n")

    def test_report_formatter_omits_absolute_source_path(self) -> None:
        result = AnalysisResult(
            status="fake",
            media_type="video",
            file_path="C:/videos/sample.mp4",
            file_name="sample.mp4",
            is_fake=True,
            probability=0.91,
            threshold=0.46,
            summary="Видео превышает порог.",
            indicators=["Вероятность выше порога."],
            technical_details=["Тип медиа: video"],
            analyzed_at=datetime(2026, 4, 15, 12, 0, 0),
        )

        payload = ReportFormatter().build_export_payload(result)

        self.assertIn("Имя файла: sample.mp4", payload)
        self.assertNotIn("Путь к файлу", payload)
        self.assertNotIn("C:/videos/sample.mp4", payload)

    def test_result_repository_round_trip_preserves_key_fields(self) -> None:
        db_path = self.base_dir / "app_data" / "app.db"
        db_manager = DatabaseManager(db_path)
        db_manager.initialize()
        repository = SQLiteResultRepository(db_manager)

        result = AnalysisResult(
            status="fake",
            media_type="video",
            file_path="sample.mp4",
            file_name="sample.mp4",
            is_fake=True,
            probability=0.91,
            threshold=0.46,
            summary="Видео превышает порог.",
            indicators=["Вероятность превышает порог."],
            technical_details=["Путь к модели: weights/model.keras"],
            error_message=None,
            file_sha256="abc123",
            analyzed_at=datetime(2026, 4, 15, 12, 0, 0),
            stored_at=datetime(2026, 4, 15, 12, 1, 0),
            report_path="reports/report_sample.txt",
        )

        analysis_id = repository.save(result)
        restored = repository.get_by_id(analysis_id)

        self.assertIsNotNone(restored)
        assert restored is not None
        self.assertEqual(restored.analysis_id, analysis_id)
        self.assertEqual(restored.file_name, "sample.mp4")
        self.assertEqual(restored.file_path, "")
        self.assertTrue(restored.is_fake)
        self.assertEqual(restored.file_sha256, "abc123")
        self.assertEqual(restored.report_path, "reports/report_sample.txt")
        self.assertEqual(restored.indicators, ["Вероятность превышает порог."])

        with closing(sqlite3.connect(db_path)) as conn:
            tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            ).fetchall()
            stored_file_path = conn.execute(
                "SELECT file_path FROM analysis_results WHERE id = ?",
                (analysis_id,),
            ).fetchone()[0]

        self.assertIn(("analysis_results",), tables)
        self.assertIn(("audit_log",), tables)
        self.assertIsNone(stored_file_path)

    def test_database_manager_migrates_file_path_to_nullable(self) -> None:
        db_path = self.base_dir / "app_data" / "app.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)

        with closing(sqlite3.connect(db_path)) as conn:
            conn.executescript(
                """
                CREATE TABLE analysis_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_name TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    media_type TEXT NOT NULL,
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
                    report_path TEXT
                );

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
                VALUES (
                    'sample.mp4',
                    'C:/videos/sample.mp4',
                    'video',
                    NULL,
                    NULL,
                    'original',
                    0,
                    0.12,
                    0.46,
                    'ok',
                    NULL,
                    '[]',
                    '[]',
                    NULL,
                    NULL
                );
                """
            )
            conn.commit()

        DatabaseManager(db_path).initialize()

        with closing(sqlite3.connect(db_path)) as conn:
            conn.row_factory = sqlite3.Row
            table_info = conn.execute("PRAGMA table_info(analysis_results)").fetchall()
            stored_value = conn.execute(
                "SELECT file_path FROM analysis_results WHERE file_name = 'sample.mp4'"
            ).fetchone()["file_path"]

        file_path_column = next(row for row in table_info if row["name"] == "file_path")
        self.assertEqual(int(file_path_column["notnull"]), 0)
        self.assertIsNone(stored_value)
