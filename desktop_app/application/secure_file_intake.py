from __future__ import annotations

import shutil
import stat
import uuid
import wave
from pathlib import Path

try:
    import cv2
except ImportError:  # pragma: no cover - depends on local env
    cv2 = None  # type: ignore[assignment]

try:
    from mutagen import MutagenError
    from mutagen.mp3 import MP3
except ImportError:  # pragma: no cover - depends on local env
    MutagenError = Exception  # type: ignore[assignment]
    MP3 = None  # type: ignore[assignment]

from desktop_app.config import AppConfig
from desktop_app.domain import MediaFileRef
from desktop_app.domain import SecureLoadResult


class SecureFileIntakeService:
    _SIGNATURE_FAMILY_BY_EXTENSION = {
        ".avi": "avi",
        ".mov": "iso-bmff",
        ".mp3": "mp3",
        ".mp4": "iso-bmff",
        ".wav": "wav",
    }

    def __init__(self, config: AppConfig) -> None:
        self._config = config

    def prepare(self, media_file: MediaFileRef) -> SecureLoadResult:
        source_path = Path(media_file.source_path)
        working_dir: Path | None = None

        regular_file_error = self._ensure_regular_file(source_path)
        if regular_file_error is not None:
            return SecureLoadResult(is_safe=False, reason=regular_file_error)

        extension_error = self._ensure_supported_extension(media_file.extension)
        if extension_error is not None:
            return SecureLoadResult(is_safe=False, reason=extension_error)

        size_error = self._ensure_allowed_size(media_file)
        if size_error is not None:
            return SecureLoadResult(is_safe=False, reason=size_error)

        detected_format = self._detect_signature(source_path)
        if detected_format is None:
            return SecureLoadResult(
                is_safe=False,
                reason="Не удалось подтвердить формат файла по сигнатуре.",
            )

        if not self._signature_matches_extension(media_file.extension, detected_format):
            return SecureLoadResult(
                is_safe=False,
                reason=(
                    f"Расширение {media_file.extension} не соответствует сигнатуре файла "
                    f"({detected_format})."
                ),
                warnings=[f"Определенный формат по сигнатуре: {detected_format}"],
            )

        try:
            working_dir = self._config.temp_uploads_dir / uuid.uuid4().hex
            working_dir.mkdir(parents=True, exist_ok=False)
            working_path = working_dir / f"payload{media_file.extension}"
            shutil.copy2(source_path, working_path)
        except OSError as exc:
            self._cleanup_partial_directory(working_dir)
            return SecureLoadResult(
                is_safe=False,
                reason=f"Не удалось создать безопасную временную копию файла: {exc}",
                warnings=[f"Определенный формат по сигнатуре: {detected_format}"],
            )

        probe_error = self._probe_media(working_path, media_file.media_type, detected_format)
        if probe_error is not None:
            self._cleanup_partial_directory(working_dir)
            return SecureLoadResult(
                is_safe=False,
                reason=probe_error,
                warnings=[f"Определенный формат по сигнатуре: {detected_format}"],
            )

        prepared_file = MediaFileRef(
            file_path=media_file.file_path,
            file_name=media_file.file_name,
            media_type=media_file.media_type,
            size_bytes=media_file.size_bytes,
            extension=media_file.extension,
            source_path=media_file.source_path,
            working_path=str(working_path),
            detected_format=detected_format,
            is_temporary=True,
        )
        return SecureLoadResult(
            is_safe=True,
            warnings=[
                f"Определенный формат по сигнатуре: {detected_format}",
                "Для анализа подготовлена безопасная временная копия файла.",
            ],
            prepared_file=prepared_file,
        )

    def cleanup(self, media_file: MediaFileRef) -> None:
        if not media_file.is_temporary:
            return

        temp_root = self._config.temp_uploads_dir.resolve()
        working_path = Path(media_file.working_path)
        working_dir = working_path.parent

        candidate = working_dir.resolve() if working_dir.exists() else working_dir.absolute()
        if not self._is_within(temp_root, candidate):
            raise ValueError("Временная папка находится вне разрешенного каталога загрузок.")

        if working_dir.exists():
            shutil.rmtree(working_dir)

    def _ensure_regular_file(self, path: Path) -> str | None:
        if not path.exists():
            return "Файл не найден или недоступен."
        if path.is_symlink():
            return "Символические ссылки не поддерживаются для загрузки."

        try:
            file_stat = path.stat(follow_symlinks=False)
        except OSError as exc:
            return f"Не удалось получить информацию о файле: {exc}"

        if not stat.S_ISREG(file_stat.st_mode):
            return "Загружаемый объект не является обычным файлом."
        return None

    def _ensure_supported_extension(self, extension: str) -> str | None:
        if extension in self._SIGNATURE_FAMILY_BY_EXTENSION:
            return None

        supported = sorted(self._SIGNATURE_FAMILY_BY_EXTENSION)
        return f"Неподдерживаемое расширение файла. Допустимые расширения: {', '.join(supported)}"

    def _ensure_allowed_size(self, media_file: MediaFileRef) -> str | None:
        if media_file.size_bytes == 0:
            return "Файл пустой и не может быть отправлен на анализ."

        if media_file.media_type == "video":
            max_size = self._config.max_video_size_bytes
            label = "видео"
        elif media_file.media_type == "audio":
            max_size = self._config.max_audio_size_bytes
            label = "аудио"
        else:
            return "Тип файла не поддерживается."

        if media_file.size_bytes > max_size:
            max_size_mb = max_size // (1024 * 1024)
            return f"Размер {label} файла превышает допустимый лимит {max_size_mb} MB."
        return None

    def _detect_signature(self, path: Path) -> str | None:
        try:
            with path.open("rb") as file_obj:
                header = file_obj.read(32)
        except OSError:
            return None

        if len(header) >= 12 and header[:4] == b"RIFF" and header[8:12] == b"AVI ":
            return "avi"
        if len(header) >= 12 and header[:4] == b"RIFF" and header[8:12] == b"WAVE":
            return "wav"
        if len(header) >= 8 and header[4:8] == b"ftyp":
            return "iso-bmff"
        if self._looks_like_mp3(header):
            return "mp3"
        return None

    def _signature_matches_extension(self, extension: str, detected_format: str) -> bool:
        return self._SIGNATURE_FAMILY_BY_EXTENSION.get(extension) == detected_format

    def _probe_media(self, path: Path, media_type: str, detected_format: str) -> str | None:
        if media_type == "video":
            return self._probe_video_file(path)
        if detected_format == "wav":
            return self._probe_wav_file(path)
        if detected_format == "mp3":
            return self._probe_mp3_file(path)
        return "Не удалось проверить открываемость файла."

    def _probe_video_file(self, path: Path) -> str | None:
        if cv2 is None:
            return "Для проверки видеофайлов требуется opencv-python."

        capture = cv2.VideoCapture(str(path))
        try:
            if not capture.isOpened():
                return "Видеофайл поврежден или не может быть открыт."
            success, frame = capture.read()
            if not success or frame is None:
                return "Видеофайл не содержит корректно читаемых кадров."
        finally:
            capture.release()
        return None

    def _probe_wav_file(self, path: Path) -> str | None:
        try:
            with wave.open(str(path), "rb") as wav_file:
                wav_file.getparams()
        except (wave.Error, EOFError, OSError):
            return "WAV-файл поврежден или не может быть открыт."
        return None

    def _probe_mp3_file(self, path: Path) -> str | None:
        if MP3 is None:
            return "Для проверки MP3-файлов требуется библиотека mutagen."

        try:
            audio = MP3(str(path))
        except (MutagenError, OSError, EOFError):
            return "MP3-файл поврежден или не может быть открыт."

        if getattr(audio, "info", None) is None:
            return "MP3-файл поврежден или не может быть открыт."
        return None

    @staticmethod
    def _looks_like_mp3(header: bytes) -> bool:
        if len(header) < 4:
            return False
        if header.startswith(b"ID3"):
            return True

        if header[0] != 0xFF or (header[1] & 0xE0) != 0xE0:
            return False

        version_bits = (header[1] >> 3) & 0x03
        layer_bits = (header[1] >> 1) & 0x03
        bitrate_index = (header[2] >> 4) & 0x0F
        sample_rate_index = (header[2] >> 2) & 0x03

        return (
            version_bits != 0x01
            and layer_bits != 0x00
            and bitrate_index not in (0x00, 0x0F)
            and sample_rate_index != 0x03
        )

    @staticmethod
    def _is_within(root: Path, candidate: Path) -> bool:
        try:
            candidate.relative_to(root)
            return True
        except ValueError:
            return False

    @staticmethod
    def _cleanup_partial_directory(path: Path | None) -> None:
        if path is None or not path.exists():
            return
        shutil.rmtree(path, ignore_errors=True)
