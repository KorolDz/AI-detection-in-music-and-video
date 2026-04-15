from __future__ import annotations

from desktop_app.config import AppConfig
from desktop_app.domain import MediaFileRef
from desktop_app.domain import PrecheckResult


class PrecheckService:
    def __init__(self, config: AppConfig) -> None:
        self._config = config

    def validate(self, media_file: MediaFileRef) -> PrecheckResult:
        warnings: list[str] = []

        if media_file.size_bytes == 0:
            return PrecheckResult(
                is_valid=False,
                reason="Файл пустой и не может быть отправлен на анализ.",
                warnings=warnings,
            )

        if media_file.media_type == "audio":
            supported = ", ".join(self._config.supported_audio_extensions)
            return PrecheckResult(
                is_valid=False,
                reason=(
                    "Аудиофайл успешно прошел безопасную загрузку, но анализ аудио "
                    f"пока не реализован. Поддержанные форматы загрузки: {supported}"
                ),
                warnings=warnings,
            )

        if media_file.media_type != "video":
            supported = ", ".join(self._config.supported_video_extensions)
            return PrecheckResult(
                is_valid=False,
                reason=f"Неподдерживаемый формат файла. Допустимые расширения: {supported}",
                warnings=warnings,
            )

        if media_file.extension not in self._config.supported_video_extensions:
            supported = ", ".join(self._config.supported_video_extensions)
            return PrecheckResult(
                is_valid=False,
                reason=f"Неподдерживаемый формат файла. Допустимые расширения: {supported}",
                warnings=warnings,
            )

        return PrecheckResult(is_valid=True, warnings=warnings)
