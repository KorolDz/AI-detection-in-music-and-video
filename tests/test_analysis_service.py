from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
import wave
from contextlib import closing
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from desktop_app.application.audit_logger import AuditLogger
from desktop_app.application.coordinator import AnalysisCoordinator
from desktop_app.application.file_hash_service import FileHashService
from desktop_app.application.file_loader import FileLoader
from desktop_app.application.local_processing_service import LocalProcessingError
from desktop_app.application.local_processing_service import LocalProcessingService
from desktop_app.application.precheck_service import PrecheckService
from desktop_app.application.report_formatter import ReportFormatter
from desktop_app.application.result_integrity_service import ResultIntegrityService
from desktop_app.application.secure_file_intake import SecureFileIntakeService
from desktop_app.config import AppConfig
from desktop_app.domain import AnalysisResult
from desktop_app.domain import LocalProcessingSession
from desktop_app.domain import MediaFileRef
from desktop_app.infrastructure.database import DatabaseManager
from desktop_app.infrastructure.repositories import SQLiteAuditLogRepository
from desktop_app.infrastructure.repositories import SQLiteResultRepository


class FakeAnalyzerGateway:
    def __init__(self, result: AnalysisResult) -> None:
        self._result = result
        self.called = False
        self.last_media_file: MediaFileRef | None = None

    def analyze(self, media_file: MediaFileRef) -> AnalysisResult:
        self.called = True
        self.last_media_file = media_file
        return AnalysisResult(
            status=self._result.status,
            media_type=media_file.media_type,
            file_path=media_file.file_path,
            file_name=media_file.file_name,
            is_fake=self._result.is_fake,
            probability=self._result.probability,
            threshold=self._result.threshold,
            summary=self._result.summary,
            indicators=list(self._result.indicators),
            technical_details=list(self._result.technical_details),
            error_message=self._result.error_message,
            analyzed_at=self._result.analyzed_at or datetime.now(),
        )


class CleanupFailingLocalProcessingService:
    def __init__(self, session: LocalProcessingSession) -> None:
        self._session = session

    def start(self, _media_file: MediaFileRef) -> LocalProcessingSession:
        return self._session

    def finish(self, _session: LocalProcessingSession) -> None:
        raise PermissionError("temporary file is locked")


class AnalysisCoordinatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.base_dir = Path(self.temp_dir.name)
        self.config = AppConfig(
            base_dir=self.base_dir,
            db_path=self.base_dir / "app_data" / "app.db",
            reports_dir=self.base_dir / "reports",
            temp_dir=self.base_dir / "temp",
            temp_uploads_dir=self.base_dir / "temp" / "uploads",
            supported_video_extensions=(".mp4", ".avi", ".mov"),
            supported_audio_extensions=(".wav", ".mp3"),
            max_video_size_bytes=500 * 1024 * 1024,
            max_audio_size_bytes=100 * 1024 * 1024,
            model_threshold=0.46,
        )
        self.db_manager = DatabaseManager(self.config.db_path)
        self.db_manager.initialize()
        self.result_repository = SQLiteResultRepository(
            self.db_manager,
            ResultIntegrityService(self.config.db_path.parent / "integrity.key"),
        )
        self.audit_repository = SQLiteAuditLogRepository(self.db_manager)
        self.audit_logger = AuditLogger(self.audit_repository)
        self.formatter = ReportFormatter()
        self.file_loader = FileLoader(self.config)
        self.file_hash_service = FileHashService()
        self.secure_intake = SecureFileIntakeService(self.config)

    def _create_mp4_file(self, suffix: str = ".mp4") -> Path:
        path = self.base_dir / f"sample{suffix}"
        path.write_bytes(b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isomiso2mp41")
        return path

    def _create_wav_file(self) -> Path:
        path = self.base_dir / "sample.wav"
        with wave.open(str(path), "wb") as wav_file:
            wav_file.setnchannels(1)
            wav_file.setsampwidth(2)
            wav_file.setframerate(8000)
            wav_file.writeframes(b"\x00\x00" * 64)
        return path

    def _build_coordinator(
        self,
        analyzer: FakeAnalyzerGateway,
        local_processing_service: object | None = None,
    ) -> AnalysisCoordinator:
        return AnalysisCoordinator(
            file_loader=self.file_loader,
            file_hash_service=self.file_hash_service,
            local_processing_service=local_processing_service
            or LocalProcessingService(self.secure_intake),
            precheck_service=PrecheckService(self.config),
            analyzer_gateway=analyzer,
            result_repository=self.result_repository,
            audit_logger=self.audit_logger,
            report_formatter=self.formatter,
        )

    def _expected_hash(self, path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def _fetch_event_types(self) -> list[str]:
        with closing(sqlite3.connect(self.config.db_path)) as conn:
            rows = conn.execute("SELECT event_type FROM audit_log ORDER BY id").fetchall()
        return [row[0] for row in rows]

    def _fetch_result_row(self) -> sqlite3.Row:
        with closing(sqlite3.connect(self.config.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                """
                SELECT
                    file_name,
                    file_path,
                    media_type,
                    status,
                    file_sha256,
                    uploaded_at,
                    analysis_started_at,
                    analyzed_at,
                    stored_at,
                    integrity_signature
                FROM analysis_results
                ORDER BY id DESC
                LIMIT 1
                """
            ).fetchone()
        assert row is not None
        return row

    def test_successful_chain_uses_temporary_copy_cleans_it_up_and_stores_hash(self) -> None:
        media_path = self._create_mp4_file()
        expected_hash = self._expected_hash(media_path)
        analyzer = FakeAnalyzerGateway(
            AnalysisResult(
                status="original",
                media_type="video",
                file_path="",
                file_name="",
                is_fake=False,
                probability=0.12,
                threshold=0.46,
                summary="Видео не превышает порог вероятности подделки.",
                indicators=["Вероятность ниже порога."],
                technical_details=["Проверка выполнена успешно."],
            )
        )
        coordinator = self._build_coordinator(analyzer)

        with patch.object(SecureFileIntakeService, "_probe_video_file", return_value=None):
            result = coordinator.run(media_path)

        self.assertFalse(result.is_error)
        self.assertTrue(analyzer.called)
        self.assertIsNotNone(analyzer.last_media_file)
        assert analyzer.last_media_file is not None
        self.assertEqual(analyzer.last_media_file.file_path, media_path.name)
        self.assertNotEqual(analyzer.last_media_file.working_path, str(media_path))
        self.assertFalse(Path(analyzer.last_media_file.working_path).exists())
        self.assertEqual(result.file_sha256, expected_hash)
        self.assertTrue(result.integrity_verified)
        self.assertIsNotNone(result.integrity_signature)
        self.assertIsNotNone(result.uploaded_at)
        self.assertIsNotNone(result.analysis_started_at)
        self.assertIsNotNone(result.analyzed_at)
        self.assertIsNotNone(result.stored_at)
        assert result.uploaded_at is not None
        assert result.analysis_started_at is not None
        assert result.analyzed_at is not None
        assert result.stored_at is not None
        self.assertLessEqual(result.uploaded_at, result.analysis_started_at)
        self.assertLessEqual(result.analysis_started_at, result.analyzed_at)
        self.assertLessEqual(result.analyzed_at, result.stored_at)
        self.assertIn(expected_hash, result.export_payload)

        result_row = self._fetch_result_row()
        self.assertEqual(result_row["file_name"], media_path.name)
        self.assertIsNone(result_row["file_path"])
        self.assertEqual(result_row["media_type"], "video")
        self.assertEqual(result_row["status"], "original")
        self.assertEqual(result_row["file_sha256"], expected_hash)
        self.assertIsNotNone(result_row["uploaded_at"])
        self.assertIsNotNone(result_row["analysis_started_at"])
        self.assertIsNotNone(result_row["analyzed_at"])
        self.assertIsNotNone(result_row["stored_at"])
        self.assertTrue(result_row["integrity_signature"])

        with closing(sqlite3.connect(self.config.db_path)) as conn:
            audit_row = conn.execute(
                "SELECT details_json FROM audit_log WHERE event_type = 'local_processing_started'"
            ).fetchone()
        self.assertIsNotNone(audit_row)
        details = json.loads(audit_row[0])
        self.assertTrue(details["file_sha256_calculated"])

        self.assertEqual(
            self._fetch_event_types(),
            [
                "analysis_requested",
                "local_processing_started",
                "analysis_started",
                "analysis_completed",
                "temporary_file_deleted",
            ],
        )

    def test_same_file_produces_same_hash_in_multiple_runs(self) -> None:
        media_path = self._create_mp4_file()
        analyzer = FakeAnalyzerGateway(
            AnalysisResult(
                status="original",
                media_type="video",
                file_path="",
                file_name="",
                summary="Видео не превышает порог.",
            )
        )
        coordinator = self._build_coordinator(analyzer)

        with patch.object(SecureFileIntakeService, "_probe_video_file", return_value=None):
            first = coordinator.run(media_path)
            second = coordinator.run(media_path)

        self.assertEqual(first.file_sha256, second.file_sha256)
        self.assertIsNotNone(first.file_sha256)

        with closing(sqlite3.connect(self.config.db_path)) as conn:
            hashes = conn.execute("SELECT file_sha256 FROM analysis_results ORDER BY id").fetchall()
        self.assertEqual(hashes[0][0], hashes[1][0])

    def test_error_analysis_is_logged_and_still_keeps_hash_and_times(self) -> None:
        media_path = self._create_mp4_file()
        expected_hash = self._expected_hash(media_path)
        analyzer = FakeAnalyzerGateway(
            AnalysisResult(
                status="error",
                media_type="video",
                file_path="",
                file_name="",
                summary="Анализ завершился с ошибкой.",
                technical_details=["Модель вернула ошибку."],
                error_message="Ошибка модели анализа.",
            )
        )
        coordinator = self._build_coordinator(analyzer)

        with patch.object(SecureFileIntakeService, "_probe_video_file", return_value=None):
            result = coordinator.run(media_path)

        self.assertTrue(result.is_error)
        self.assertEqual(result.error_message, "Ошибка модели анализа.")
        self.assertEqual(result.file_sha256, expected_hash)
        self.assertTrue(analyzer.called)
        self.assertIsNotNone(result.uploaded_at)
        self.assertIsNotNone(result.analysis_started_at)
        self.assertIsNotNone(result.analyzed_at)
        self.assertIsNotNone(result.stored_at)
        self.assertEqual(
            self._fetch_event_types(),
            [
                "analysis_requested",
                "local_processing_started",
                "analysis_started",
                "analysis_failed",
                "temporary_file_deleted",
            ],
        )

    def test_valid_audio_is_rejected_by_business_precheck_but_hash_is_saved(self) -> None:
        media_path = self._create_wav_file()
        expected_hash = self._expected_hash(media_path)
        analyzer = FakeAnalyzerGateway(
            AnalysisResult(
                status="original",
                media_type="audio",
                file_path="",
                file_name="",
                summary="unused",
            )
        )
        coordinator = self._build_coordinator(analyzer)

        result = coordinator.run(media_path)

        self.assertTrue(result.is_error)
        self.assertFalse(analyzer.called)
        self.assertIn("анализ аудио пока не реализован", (result.error_message or "").lower())
        self.assertEqual(result.file_sha256, expected_hash)
        self.assertIsNotNone(result.uploaded_at)
        self.assertIsNone(result.analysis_started_at)
        self.assertEqual(
            self._fetch_event_types(),
            [
                "analysis_requested",
                "local_processing_started",
                "precheck_failed",
                "temporary_file_deleted",
            ],
        )

    def test_unsupported_extension_stops_before_analyzer_and_has_no_hash(self) -> None:
        media_path = self.base_dir / "sample.txt"
        media_path.write_text("demo", encoding="utf-8")
        analyzer = FakeAnalyzerGateway(
            AnalysisResult(
                status="original",
                media_type="video",
                file_path="",
                file_name="",
                summary="unused",
            )
        )
        coordinator = self._build_coordinator(analyzer)

        result = coordinator.run(media_path)

        self.assertTrue(result.is_error)
        self.assertFalse(analyzer.called)
        self.assertIn("неподдерживаемое расширение", (result.error_message or "").lower())
        self.assertIsNone(result.file_sha256)
        self.assertIsNone(result.analysis_started_at)
        self.assertIsNone(self._fetch_result_row()["file_sha256"])
        self.assertEqual(self._fetch_event_types(), ["analysis_requested", "secure_intake_failed"])

    def test_cleanup_failure_is_logged_without_overwriting_result(self) -> None:
        source_path = self._create_mp4_file()
        expected_hash = self._expected_hash(source_path)
        prepared_dir = self.config.temp_uploads_dir / "locked-copy"
        prepared_dir.mkdir(parents=True, exist_ok=True)
        prepared_path = prepared_dir / "payload.mp4"
        prepared_path.write_bytes(source_path.read_bytes())

        session = LocalProcessingSession(
            source_name=source_path.name,
            source_path=str(source_path.absolute()),
            working_path=str(prepared_path),
            media_type="video",
            detected_format="iso-bmff",
            started_at=datetime.now(),
            cleanup_required=True,
        )
        analyzer = FakeAnalyzerGateway(
            AnalysisResult(
                status="original",
                media_type="video",
                file_path="",
                file_name="",
                is_fake=False,
                probability=0.14,
                threshold=0.46,
                summary="Видео не превышает порог вероятности подделки.",
                analyzed_at=datetime.now(),
            )
        )
        coordinator = self._build_coordinator(
            analyzer,
            local_processing_service=CleanupFailingLocalProcessingService(session),
        )

        result = coordinator.run(source_path)

        self.assertFalse(result.is_error)
        self.assertEqual(result.file_sha256, expected_hash)
        self.assertTrue(analyzer.called)
        self.assertEqual(
            self._fetch_event_types(),
            [
                "analysis_requested",
                "local_processing_started",
                "analysis_started",
                "analysis_completed",
                "temporary_file_cleanup_failed",
            ],
        )

    def test_url_like_source_is_rejected_before_analysis_request(self) -> None:
        analyzer = FakeAnalyzerGateway(
            AnalysisResult(
                status="original",
                media_type="video",
                file_path="",
                file_name="",
                summary="unused",
            )
        )
        coordinator = self._build_coordinator(analyzer)

        result = coordinator.run("https://example.com/sample.mp4")

        self.assertTrue(result.is_error)
        self.assertFalse(analyzer.called)
        self.assertIn("локальные файлы", (result.error_message or "").lower())
        self.assertEqual(self._fetch_event_types(), ["analysis_failed"])
        self.assertIsNone(self._fetch_result_row()["file_sha256"])

    def test_remote_drive_source_is_rejected_before_analysis_request(self) -> None:
        analyzer = FakeAnalyzerGateway(
            AnalysisResult(
                status="original",
                media_type="video",
                file_path="",
                file_name="",
                summary="unused",
            )
        )
        coordinator = self._build_coordinator(analyzer)

        with patch.object(FileLoader, "_is_remote_drive_path", return_value=True):
            result = coordinator.run(r"Z:\sample.mp4")

        self.assertTrue(result.is_error)
        self.assertFalse(analyzer.called)
        self.assertIn("сетевые диски запрещены", (result.error_message or "").lower())
        self.assertEqual(self._fetch_event_types(), ["analysis_failed"])

    def test_missing_local_file_does_not_leak_absolute_path(self) -> None:
        analyzer = FakeAnalyzerGateway(
            AnalysisResult(
                status="original",
                media_type="video",
                file_path="",
                file_name="",
                summary="unused",
            )
        )
        coordinator = self._build_coordinator(analyzer)
        missing_path = self.base_dir / "missing.mp4"

        result = coordinator.run(missing_path)

        self.assertTrue(result.is_error)
        self.assertFalse(analyzer.called)
        self.assertEqual(result.error_message, "Файл не найден или недоступен.")
        self.assertNotIn(str(missing_path.resolve()), result.export_payload)
        self.assertEqual(self._fetch_event_types(), ["analysis_failed"])

    def test_local_processing_error_before_analysis_preserves_uploaded_time(self) -> None:
        media_path = self._create_mp4_file()
        analyzer = FakeAnalyzerGateway(
            AnalysisResult(
                status="original",
                media_type="video",
                file_path="",
                file_name="",
                summary="unused",
            )
        )
        coordinator = self._build_coordinator(analyzer)

        with patch.object(
            LocalProcessingService,
            "start",
            side_effect=LocalProcessingError("Подозрительный файл.", stage="secure_intake"),
        ):
            result = coordinator.run(media_path)

        self.assertTrue(result.is_error)
        self.assertIsNotNone(result.uploaded_at)
        self.assertIsNone(result.analysis_started_at)
        self.assertEqual(self._fetch_event_types(), ["analysis_requested", "secure_intake_failed"])
