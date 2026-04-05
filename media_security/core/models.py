from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    HIGH = "high"


@dataclass(slots=True)
class Finding:
    code: str
    severity: Severity
    message: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity.value,
            "message": self.message,
            "details": self.details,
        }


@dataclass(slots=True)
class FileMetadata:
    path: str
    name: str
    extension: str
    media_type: str | None
    detected_format: str | None
    size_bytes: int
    mime_type: str | None
    hashes: dict[str, str]
    timestamps_utc: dict[str, str]
    signature: dict[str, Any]
    technical: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "name": self.name,
            "extension": self.extension,
            "media_type": self.media_type,
            "detected_format": self.detected_format,
            "size_bytes": self.size_bytes,
            "mime_type": self.mime_type,
            "hashes": self.hashes,
            "timestamps_utc": self.timestamps_utc,
            "signature": self.signature,
            "technical": self.technical,
        }


@dataclass(slots=True)
class ScanReport:
    file: str
    supported: bool
    verdict: str
    findings: list[Finding]
    trust_score: int = 100
    risk_level: str = "low"
    scan_id: int | None = None
    metadata: FileMetadata | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "supported": self.supported,
            "verdict": self.verdict,
            "trust_score": self.trust_score,
            "risk_level": self.risk_level,
            "scan_id": self.scan_id,
            "findings": [finding.to_dict() for finding in self.findings],
            "metadata": self.metadata.to_dict() if self.metadata else None,
        }
