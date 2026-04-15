from __future__ import annotations

import tempfile
import unittest
import wave
from pathlib import Path
from unittest.mock import patch

from desktop_app.application.file_loader import FileLoader
from desktop_app.application.secure_file_intake import SecureFileIntakeService
from desktop_app.config import AppConfig


class SecureFileIntakeTests(unittest.TestCase):
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
        self.loader = FileLoader(self.config)
        self.service = SecureFileIntakeService(self.config)

    def _create_mp4_like_file(self, suffix: str = ".mp4") -> Path:
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

    def _create_mp3_like_file(self) -> Path:
        path = self.base_dir / "sample.mp3"
        path.write_bytes(b"ID3\x04\x00\x00\x00\x00\x00\x15TestTitleFrame")
        return path

    def test_prepare_creates_temporary_copy_for_valid_video(self) -> None:
        media_path = self._create_mp4_like_file()
        media_file = self.loader.load(media_path)

        with patch.object(self.service, "_probe_video_file", return_value=None):
            result = self.service.prepare(media_file)

        self.assertTrue(result.is_safe)
        self.assertIsNotNone(result.prepared_file)
        assert result.prepared_file is not None
        self.assertNotEqual(result.prepared_file.working_path, result.prepared_file.source_path)
        self.assertTrue(Path(result.prepared_file.working_path).exists())
        self.assertEqual(result.prepared_file.detected_format, "iso-bmff")

        self.service.cleanup(result.prepared_file)
        self.assertFalse(Path(result.prepared_file.working_path).parent.exists())

    def test_prepare_rejects_signature_mismatch_before_copy(self) -> None:
        media_path = self.base_dir / "sample.mp4"
        media_path.write_bytes(b"RIFF\x24\x00\x00\x00WAVEfmt ")
        media_file = self.loader.load(media_path)

        result = self.service.prepare(media_file)

        self.assertFalse(result.is_safe)
        self.assertIsNone(result.prepared_file)
        self.assertIn("не соответствует сигнатуре", (result.reason or "").lower())
        self.assertFalse(self.config.temp_uploads_dir.exists())

    def test_prepare_rejects_oversized_file(self) -> None:
        limited_config = AppConfig(
            base_dir=self.base_dir,
            db_path=self.base_dir / "app_data" / "app.db",
            reports_dir=self.base_dir / "reports",
            temp_dir=self.base_dir / "temp",
            temp_uploads_dir=self.base_dir / "temp" / "uploads",
            supported_video_extensions=(".mp4", ".avi", ".mov"),
            supported_audio_extensions=(".wav", ".mp3"),
            max_video_size_bytes=8,
            max_audio_size_bytes=8,
            model_threshold=0.46,
        )
        loader = FileLoader(limited_config)
        service = SecureFileIntakeService(limited_config)
        media_path = self._create_mp4_like_file()
        media_file = loader.load(media_path)

        result = service.prepare(media_file)

        self.assertFalse(result.is_safe)
        self.assertIn("превышает допустимый лимит", (result.reason or "").lower())

    def test_prepare_rejects_corrupted_video_when_probe_fails(self) -> None:
        media_path = self._create_mp4_like_file()
        media_file = self.loader.load(media_path)

        with patch.object(
            self.service,
            "_probe_video_file",
            return_value="Видеофайл поврежден или не может быть открыт.",
        ):
            result = self.service.prepare(media_file)

        self.assertFalse(result.is_safe)
        self.assertIsNone(result.prepared_file)
        self.assertIn("видеофайл поврежден", (result.reason or "").lower())

    def test_prepare_accepts_valid_wav_file(self) -> None:
        media_path = self._create_wav_file()
        media_file = self.loader.load(media_path)

        result = self.service.prepare(media_file)

        self.assertTrue(result.is_safe)
        self.assertIsNotNone(result.prepared_file)
        assert result.prepared_file is not None
        self.assertEqual(result.prepared_file.detected_format, "wav")
        self.service.cleanup(result.prepared_file)

    def test_prepare_rejects_corrupted_mp3_when_probe_fails(self) -> None:
        media_path = self._create_mp3_like_file()
        media_file = self.loader.load(media_path)

        with patch.object(
            self.service,
            "_probe_mp3_file",
            return_value="MP3-файл поврежден или не может быть открыт.",
        ):
            result = self.service.prepare(media_file)

        self.assertFalse(result.is_safe)
        self.assertIsNone(result.prepared_file)
        self.assertIn("mp3-файл поврежден", (result.reason or "").lower())
