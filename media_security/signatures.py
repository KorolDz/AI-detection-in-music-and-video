from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class SignatureResult:
    detected_format: str | None
    details: dict[str, Any]


def detect_format_from_signature(header: bytes) -> SignatureResult:
    if len(header) >= 12 and header[0:4] == b"RIFF":
        riff_kind = header[8:12]
        if riff_kind == b"WAVE":
            return SignatureResult("wav", {"container": "RIFF", "riff_kind": "WAVE"})
        if riff_kind == b"AVI ":
            return SignatureResult("avi", {"container": "RIFF", "riff_kind": "AVI"})

    if len(header) >= 12 and header[4:8] == b"ftyp":
        major_brand_raw = header[8:12]
        major_brand = major_brand_raw.decode("latin1", errors="replace")
        if major_brand_raw == b"qt  ":
            return SignatureResult(
                "mov", {"container": "ISO-BMFF", "major_brand": major_brand}
            )
        return SignatureResult(
            "mp4", {"container": "ISO-BMFF", "major_brand": major_brand}
        )

    if header.startswith(b"ID3"):
        return SignatureResult("mp3", {"container": "MPEG audio", "id3v2": True})

    frame_offset = _find_mp3_frame_sync(header)
    if frame_offset is not None:
        return SignatureResult(
            "mp3", {"container": "MPEG audio", "id3v2": False, "frame_offset": frame_offset}
        )

    return SignatureResult(None, {"container": "unknown"})


def is_signature_compatible(extension: str, detected_format: str | None) -> bool:
    extension = extension.lower().strip(".")
    if detected_format is None:
        return False
    compatibility_map = {
        "wav": {"wav"},
        "mp3": {"mp3"},
        "avi": {"avi"},
        "mp4": {"mp4"},
        "mov": {"mov"},
    }
    return detected_format in compatibility_map.get(extension, set())


def _find_mp3_frame_sync(data: bytes) -> int | None:
    if len(data) < 2:
        return None
    for offset in range(0, len(data) - 1):
        if data[offset] == 0xFF and (data[offset + 1] & 0xE0) == 0xE0:
            return offset
    return None
