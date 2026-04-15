from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class AppConfig:
    base_dir: Path
    db_path: Path
    reports_dir: Path
    temp_dir: Path
    temp_uploads_dir: Path
    supported_video_extensions: tuple[str, ...]
    supported_audio_extensions: tuple[str, ...]
    max_video_size_bytes: int
    max_audio_size_bytes: int
    model_threshold: float

    @classmethod
    def default(cls) -> "AppConfig":
        base_dir = Path(__file__).resolve().parent.parent
        temp_dir = base_dir / "temp"
        return cls(
            base_dir=base_dir,
            db_path=base_dir / "app_data" / "app.db",
            reports_dir=base_dir / "reports",
            temp_dir=temp_dir,
            temp_uploads_dir=temp_dir / "uploads",
            supported_video_extensions=(".mp4", ".avi", ".mov"),
            supported_audio_extensions=(".wav", ".mp3"),
            max_video_size_bytes=500 * 1024 * 1024,
            max_audio_size_bytes=100 * 1024 * 1024,
            model_threshold=0.46,
        )
