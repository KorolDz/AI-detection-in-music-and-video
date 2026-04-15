from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field
from datetime import datetime
from typing import Any


@dataclass(slots=True)
class MediaFileRef:
    file_path: str
    file_name: str
    media_type: str
    size_bytes: int
    extension: str
    source_path: str = ""
    working_path: str = ""
    detected_format: str = "unknown"
    is_temporary: bool = False

    def __post_init__(self) -> None:
        if not self.source_path:
            self.source_path = self.file_path
        if not self.working_path:
            self.working_path = self.file_path


@dataclass(slots=True)
class PrecheckResult:
    is_valid: bool
    reason: str | None = None
    warnings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class AnalysisRequest:
    media_file: MediaFileRef
    requested_at: datetime


@dataclass(slots=True)
class SecureLoadResult:
    is_safe: bool
    reason: str | None = None
    warnings: list[str] = field(default_factory=list)
    prepared_file: MediaFileRef | None = None


@dataclass(slots=True)
class LocalProcessingSession:
    source_name: str
    source_path: str
    working_path: str
    media_type: str
    detected_format: str
    started_at: datetime
    cleanup_required: bool
    warnings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class AnalysisResult:
    status: str
    media_type: str
    file_path: str
    file_name: str
    is_fake: bool | None = None
    probability: float | None = None
    threshold: float | None = None
    summary: str = ""
    indicators: list[str] = field(default_factory=list)
    technical_details: list[str] = field(default_factory=list)
    error_message: str | None = None
    export_payload: str = ""
    analysis_id: int | None = None
    file_sha256: str | None = None
    analyzed_at: datetime | None = None
    stored_at: datetime | None = None
    report_path: str | None = None

    @property
    def is_error(self) -> bool:
        return self.status == "error"

    @property
    def display_status(self) -> str:
        if self.status == "error":
            return "Ошибка"
        if self.is_fake:
            return "Подозрение на подделку"
        return "Оригинал"


@dataclass(slots=True)
class AuditEvent:
    event_type: str
    severity: str
    message: str
    file_path: str | None = None
    result_id: int | None = None
    details: dict[str, Any] = field(default_factory=dict)
    event_time: datetime = field(default_factory=datetime.now)
