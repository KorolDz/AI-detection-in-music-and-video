from __future__ import annotations

import ctypes
import os
import re
from pathlib import Path

from desktop_app.config import AppConfig
from desktop_app.domain import MediaFileRef

_WINDOWS_DRIVE_REMOTE = 4
_URL_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


class FileLoader:
    def __init__(self, config: AppConfig) -> None:
        self._config = config

    def load(self, path: str | Path) -> MediaFileRef:
        raw_path = str(path).strip()
        self._ensure_local_source(raw_path)

        absolute_path = Path(raw_path).expanduser().absolute()
        if not absolute_path.is_file():
            raise FileNotFoundError("Файл не найден или недоступен.")

        extension = absolute_path.suffix.lower()
        if extension in self._config.supported_video_extensions:
            media_type = "video"
        elif extension in self._config.supported_audio_extensions:
            media_type = "audio"
        else:
            media_type = "unknown"

        return MediaFileRef(
            file_path=str(absolute_path),
            file_name=absolute_path.name,
            media_type=media_type,
            size_bytes=absolute_path.stat().st_size,
            extension=extension,
            source_path=str(absolute_path),
            working_path=str(absolute_path),
        )

    @classmethod
    def _ensure_local_source(cls, raw_path: str) -> None:
        if not raw_path:
            raise ValueError("Путь к файлу не указан.")
        if cls._is_url_like(raw_path):
            raise ValueError("Поддерживаются только локальные файлы, URL-источники запрещены.")
        if cls._is_unc_path(raw_path):
            raise ValueError("Поддерживаются только локальные файлы, сетевые пути запрещены.")
        if cls._is_remote_drive_path(raw_path):
            raise ValueError("Поддерживаются только локальные файлы, сетевые диски запрещены.")

    @staticmethod
    def _is_url_like(raw_path: str) -> bool:
        return bool(_URL_PATTERN.match(raw_path))

    @staticmethod
    def _is_unc_path(raw_path: str) -> bool:
        return raw_path.startswith("\\\\") or raw_path.startswith("//")

    @staticmethod
    def _is_remote_drive_path(raw_path: str) -> bool:
        if os.name != "nt":
            return False

        drive = Path(raw_path).drive
        if not drive:
            return False

        root_path = f"{drive}\\"
        try:
            get_drive_type = ctypes.windll.kernel32.GetDriveTypeW
        except AttributeError:  # pragma: no cover - non-Windows envs
            return False
        return int(get_drive_type(root_path)) == _WINDOWS_DRIVE_REMOTE
