from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import datetime
from pathlib import Path

try:
    from PySide6.QtWidgets import QApplication
except ImportError:  # pragma: no cover - depends on local env
    QApplication = None  # type: ignore[assignment]

from desktop_app.application.report_formatter import ReportFormatter
from desktop_app.application.result_integrity_service import ResultIntegrityService
from desktop_app.domain import AnalysisResult
from desktop_app.domain import AuditEvent
from desktop_app.exporter import export_result_to_html
from desktop_app.exporter import export_result_to_pdf
from desktop_app.exporter import export_result_to_txt
from desktop_app.infrastructure.database import DatabaseManager
from desktop_app.infrastructure.repositories import SQLiteAuditLogRepository
from desktop_app.infrastructure.repositories import SQLiteResultRepository


class ExporterAndRepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.base_dir = Path(self.temp_dir.name)

    def _create_result_repository(self, db_path: Path) -> SQLiteResultRepository:
        db_manager = DatabaseManager(db_path)
        db_manager.initialize()
        integrity_service = ResultIntegrityService(db_path.parent / "integrity.key")
        return SQLiteResultRepository(db_manager, integrity_service)

    def test_writes_export_payload_to_txt_file(self) -> None:
        result = AnalysisResult(
            status="original",
            media_type="video",
            file_path="sample.mp4",
            file_name="sample.mp4",
            summary="Видео не превышает порог.",
            export_payload="demo report\n",
        )
        destination = self.base_dir / "report.txt"

        saved_path = export_result_to_txt(result, destination)

        self.assertEqual(saved_path, destination)
        self.assertTrue(destination.is_file())
        self.assertEqual(destination.read_text(encoding="utf-8"), "demo report\n")

    def test_report_formatter_builds_structured_text_and_html_without_absolute_path(self) -> None:
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
            file_sha256="abc123def456",
            analyzed_at=datetime(2026, 4, 15, 12, 0, 0),
            uploaded_at=datetime(2026, 4, 15, 11, 59, 50),
            analysis_started_at=datetime(2026, 4, 15, 11, 59, 58),
            integrity_verified=True,
        )

        formatter = ReportFormatter()
        txt_payload = formatter.render_txt(result)
        html_payload = formatter.render_html(result)

        self.assertIn("Имя файла: sample.mp4", txt_payload)
        self.assertIn("Вероятность подделки: 91.00%", txt_payload)
        self.assertIn("Контроль целостности: Проверено", txt_payload)
        self.assertIn("Оценка вероятности", html_payload)
        self.assertIn("sample.mp4", html_payload)
        self.assertIn("91.00%", html_payload)
        self.assertNotIn("C:/videos/sample.mp4", txt_payload)
        self.assertNotIn("C:/videos/sample.mp4", html_payload)

    def test_export_result_to_html_writes_html_file(self) -> None:
        result = AnalysisResult(
            status="original",
            media_type="video",
            file_path="sample.mp4",
            file_name="sample.mp4",
            probability=0.12,
            threshold=0.46,
            summary="Видео не превышает порог.",
        )
        destination = self.base_dir / "report.html"

        saved_path = export_result_to_html(result, destination)

        self.assertEqual(saved_path, destination)
        html = destination.read_text(encoding="utf-8")
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("Оценка вероятности", html)
        self.assertIn("sample.mp4", html)

    def test_report_formatter_builds_pdf_specific_html_with_print_friendly_header(self) -> None:
        result = AnalysisResult(
            status="fake",
            media_type="video",
            file_path="sample.mp4",
            file_name="sample.mp4",
            probability=0.77,
            threshold=0.46,
            is_fake=True,
            summary="Видео выглядит подозрительно.",
        )

        html = ReportFormatter().render_html(result, output_profile="pdf")

        self.assertIn("@page { size: A4; margin: 14mm; }", html)
        self.assertIn("max-width: none", html)
        self.assertIn("background: #edf2f3", html)
        self.assertIn("font-size: 34px", html)
        self.assertIn("color: #173447", html)

    @unittest.skipIf(QApplication is None, "PySide6 не установлена.")
    def test_export_result_to_pdf_writes_pdf_file(self) -> None:
        app = QApplication.instance() or QApplication([])
        self.addCleanup(lambda: app.quit() if QApplication.instance() is app else None)

        result = AnalysisResult(
            status="fake",
            media_type="video",
            file_path="sample.mp4",
            file_name="sample.mp4",
            probability=0.77,
            threshold=0.46,
            is_fake=True,
            summary="Видео выглядит подозрительно.",
        )
        destination = self.base_dir / "report.pdf"

        saved_path = export_result_to_pdf(result, destination)

        self.assertEqual(saved_path, destination)
        self.assertTrue(destination.exists())
        self.assertGreater(destination.stat().st_size, 0)

    def test_result_repository_round_trip_preserves_key_fields_and_integrity(self) -> None:
        db_path = self.base_dir / "app_data" / "app.db"
        repository = self._create_result_repository(db_path)

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
            file_sha256="abc123",
            uploaded_at=datetime(2026, 4, 15, 11, 59, 50),
            analysis_started_at=datetime(2026, 4, 15, 11, 59, 58),
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
        self.assertIsNotNone(restored.integrity_signature)
        self.assertTrue(restored.integrity_verified)

        with closing(sqlite3.connect(db_path)) as conn:
            row = conn.execute(
                "SELECT file_path, integrity_signature, integrity_version FROM analysis_results WHERE id = ?",
                (analysis_id,),
            ).fetchone()

        self.assertIsNone(row[0])
        self.assertTrue(row[1])
        self.assertEqual(row[2], ResultIntegrityService.VERSION)

    def test_tampering_saved_result_marks_integrity_as_broken(self) -> None:
        db_path = self.base_dir / "app_data" / "app.db"
        repository = self._create_result_repository(db_path)

        analysis_id = repository.save(
            AnalysisResult(
                status="original",
                media_type="video",
                file_path="sample.mp4",
                file_name="sample.mp4",
                summary="Видео не превышает порог.",
                file_sha256="hash-1",
                stored_at=datetime(2026, 4, 15, 12, 1, 0),
            )
        )

        with closing(sqlite3.connect(db_path)) as conn:
            conn.execute(
                "UPDATE analysis_results SET summary = ?, probability = ? WHERE id = ?",
                ("Подмена данных.", 0.99, analysis_id),
            )
            conn.commit()

        restored = repository.get_by_id(analysis_id)

        self.assertIsNotNone(restored)
        assert restored is not None
        self.assertFalse(restored.integrity_verified)

    def test_legacy_row_without_signature_is_loaded_as_not_available(self) -> None:
        db_path = self.base_dir / "app_data" / "app.db"
        db_manager = DatabaseManager(db_path)
        db_manager.initialize()

        with db_manager.connection() as conn:
            conn.execute(
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
                    "legacy.mp4",
                    None,
                    "video",
                    None,
                    None,
                    None,
                    "2026-04-15T12:00:00",
                    "original",
                    0,
                    0.11,
                    0.46,
                    "legacy row",
                    None,
                    "[]",
                    "[]",
                    None,
                    None,
                    None,
                    None,
                ),
            )

        repository = SQLiteResultRepository(
            db_manager,
            ResultIntegrityService(db_path.parent / "integrity.key"),
        )
        entries = repository.list_recent()
        restored = repository.get_by_id(entries[0].analysis_id)

        self.assertEqual(entries[0].integrity_verified, None)
        self.assertIsNotNone(restored)
        assert restored is not None
        self.assertEqual(restored.integrity_verified, None)

    def test_list_recent_returns_newest_first_without_path_and_with_integrity(self) -> None:
        db_path = self.base_dir / "app_data" / "app.db"
        repository = self._create_result_repository(db_path)

        old_id = repository.save(
            AnalysisResult(
                status="original",
                media_type="video",
                file_path="old.mp4",
                file_name="old.mp4",
                probability=0.10,
                summary="ok",
                file_sha256="oldhash",
                stored_at=datetime(2026, 4, 15, 10, 0, 0),
            )
        )
        new_id = repository.save(
            AnalysisResult(
                status="fake",
                media_type="video",
                file_path="new.mp4",
                file_name="new.mp4",
                probability=0.95,
                summary="fake",
                file_sha256="newhash",
                stored_at=datetime(2026, 4, 15, 11, 0, 0),
            )
        )

        entries = repository.list_recent()

        self.assertEqual([entry.analysis_id for entry in entries], [new_id, old_id])
        self.assertEqual(entries[0].file_name, "new.mp4")
        self.assertEqual(entries[0].file_sha256, "newhash")
        self.assertTrue(entries[0].integrity_verified)
        self.assertEqual(entries[1].file_name, "old.mp4")

    def test_audit_log_repository_returns_events_newest_first(self) -> None:
        db_path = self.base_dir / "app_data" / "app.db"
        db_manager = DatabaseManager(db_path)
        db_manager.initialize()
        repository = SQLiteAuditLogRepository(db_manager)

        repository.write(
            AuditEvent(
                event_type="older",
                severity="info",
                message="older message",
                details={},
                event_time=datetime(2026, 4, 15, 10, 0, 0),
            )
        )
        repository.write(
            AuditEvent(
                event_type="newer",
                severity="warning",
                message="newer message",
                details={"x": 1},
                event_time=datetime(2026, 4, 15, 11, 0, 0),
            )
        )

        entries = repository.list_recent()

        self.assertEqual(entries[0].event_type, "newer")
        self.assertEqual(entries[1].event_type, "older")
        self.assertEqual(entries[0].details, {"x": 1})

    def test_database_manager_creates_new_indexes_and_migrates_schema(self) -> None:
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

                CREATE TABLE audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_time TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    file_path TEXT,
                    result_id INTEGER,
                    severity TEXT NOT NULL,
                    message TEXT NOT NULL,
                    details_json TEXT NOT NULL
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
            index_rows = conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index' ORDER BY name"
            ).fetchall()

        column_names = {row["name"] for row in table_info}
        index_names = [row["name"] for row in index_rows]
        file_path_column = next(row for row in table_info if row["name"] == "file_path")

        self.assertEqual(int(file_path_column["notnull"]), 0)
        self.assertIsNone(stored_value)
        self.assertIn("uploaded_at", column_names)
        self.assertIn("analysis_started_at", column_names)
        self.assertIn("integrity_signature", column_names)
        self.assertIn("integrity_version", column_names)
        self.assertIn("idx_analysis_results_stored_at", index_names)
        self.assertIn("idx_audit_log_event_time", index_names)
