from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from desktop_app.domain import AnalysisResult
from desktop_app.domain import MediaFileRef
from video_detection import analyze_video as backend_analyze_video


class VideoAnalyzerAdapter:
    def __init__(self, default_threshold: float = 0.46) -> None:
        self._default_threshold = default_threshold

    def analyze(self, media_file: MediaFileRef) -> AnalysisResult:
        try:
            raw_result = backend_analyze_video(Path(media_file.working_path))
        except Exception as exc:  # noqa: BLE001
            return self._build_error_result(
                media_file,
                f"Внутренняя ошибка анализа: {exc}",
            )

        return self._map_backend_result(media_file, raw_result)

    def _map_backend_result(
        self,
        media_file: MediaFileRef,
        raw_result: dict[str, Any] | Any,
    ) -> AnalysisResult:
        if not isinstance(raw_result, dict):
            return self._build_error_result(
                media_file,
                "Модуль анализа вернул неподдерживаемый формат результата.",
            )

        analyzed_at = datetime.now()
        backend_status = str(raw_result.get("status", "Error"))
        if backend_status == "OK":
            probability = self._safe_float(raw_result.get("probability"))
            threshold = self._safe_float(raw_result.get("threshold")) or self._default_threshold
            analyzed_frames = raw_result.get("analyzed_frames")
            model_path = raw_result.get("model_path")
            is_fake = bool(raw_result.get("is_fake", False))

            indicators: list[str] = []
            if probability is not None:
                relation = "превышает" if probability > threshold else "ниже"
                indicators.append(
                    f"Вероятность подделки {probability:.4f} {relation} порога {threshold:.4f}."
                )
            if analyzed_frames is not None:
                indicators.append(f"Обработано кадров с лицами: {analyzed_frames}.")
            if model_path:
                indicators.append(f"Использована модель: {model_path}")

            technical_details = self._technical_details_for_media(media_file)
            if analyzed_frames is not None:
                technical_details.append(
                    f"Количество проанализированных кадров: {analyzed_frames}"
                )
            if model_path:
                technical_details.append(f"Путь к модели: {model_path}")

            summary = (
                "Видео превышает установленный порог вероятности подделки."
                if is_fake
                else "Видео не превышает установленный порог вероятности подделки."
            )
            return AnalysisResult(
                status="fake" if is_fake else "original",
                media_type=media_file.media_type,
                file_path=media_file.file_path,
                file_name=media_file.file_name,
                is_fake=is_fake,
                probability=probability,
                threshold=threshold,
                summary=summary,
                indicators=indicators,
                technical_details=technical_details,
                analyzed_at=analyzed_at,
            )

        message = str(raw_result.get("message", "Неизвестная ошибка анализа."))
        technical_details = self._technical_details_for_media(media_file)
        missing_dependencies = raw_result.get("missing_dependencies")
        if missing_dependencies:
            technical_details.append(
                "Отсутствуют зависимости: " + ", ".join(str(item) for item in missing_dependencies)
            )
        model_path = raw_result.get("model_path")
        if model_path:
            technical_details.append(f"Путь к модели: {model_path}")

        return AnalysisResult(
            status="error",
            media_type=media_file.media_type,
            file_path=media_file.file_path,
            file_name=media_file.file_name,
            summary="Анализ завершился с ошибкой.",
            technical_details=technical_details,
            error_message=message,
            analyzed_at=analyzed_at,
        )

    def _build_error_result(self, media_file: MediaFileRef, message: str) -> AnalysisResult:
        return AnalysisResult(
            status="error",
            media_type=media_file.media_type,
            file_path=media_file.file_path,
            file_name=media_file.file_name,
            summary="Анализ завершился с ошибкой.",
            technical_details=self._technical_details_for_media(media_file),
            error_message=message,
            analyzed_at=datetime.now(),
        )

    @staticmethod
    def _technical_details_for_media(media_file: MediaFileRef) -> list[str]:
        technical_details = [
            f"Тип медиа: {media_file.media_type}",
            f"Идентификатор файла: {media_file.file_name}",
            f"Размер файла (байт): {media_file.size_bytes}",
            f"Расширение: {media_file.extension}",
        ]
        if media_file.detected_format != "unknown":
            technical_details.append(
                f"Определенный формат по сигнатуре: {media_file.detected_format}"
            )
        if media_file.is_temporary:
            technical_details.append("Анализ выполнялся на безопасной временной копии файла.")
        return technical_details

    @staticmethod
    def _safe_float(value: Any) -> float | None:
        try:
            if value is None:
                return None
            return float(value)
        except (TypeError, ValueError):
            return None
