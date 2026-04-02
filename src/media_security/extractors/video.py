from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .common import read_header


def extract_video_metadata(path: Path, expected_format: str) -> dict[str, Any]:
    metadata: dict[str, Any] = {}

    if expected_format in {"mp4", "mov"}:
        metadata.update(_extract_iso_bmff_metadata(path))
    elif expected_format == "avi":
        metadata.update(_extract_avi_metadata(path))

    ffprobe_summary = _extract_ffprobe_summary(path)
    if ffprobe_summary:
        metadata["ffprobe"] = ffprobe_summary
    return metadata


def _extract_iso_bmff_metadata(path: Path) -> dict[str, Any]:
    header = read_header(path, 128)
    if len(header) < 16 or header[4:8] != b"ftyp":
        return {}

    major_brand = header[8:12].decode("latin1", errors="replace")
    minor_version = int.from_bytes(header[12:16], byteorder="big")
    compatible_brands: list[str] = []

    for offset in range(16, len(header), 4):
        brand_bytes = header[offset : offset + 4]
        if len(brand_bytes) < 4:
            break
        brand = brand_bytes.decode("latin1", errors="replace").strip("\x00").strip()
        if brand:
            compatible_brands.append(brand)

    return {
        "major_brand": major_brand,
        "minor_version": minor_version,
        "compatible_brands": compatible_brands,
    }


def _extract_avi_metadata(path: Path) -> dict[str, Any]:
    header = read_header(path, 64)
    if len(header) < 12 or header[0:4] != b"RIFF" or header[8:12] != b"AVI ":
        return {}

    riff_declared_size = int.from_bytes(header[4:8], byteorder="little") + 8
    return {
        "container": "RIFF/AVI",
        "riff_declared_size_bytes": riff_declared_size,
    }


def _extract_ffprobe_summary(path: Path) -> dict[str, Any] | None:
    if shutil.which("ffprobe") is None:
        return {"available": False}

    command = [
        "ffprobe",
        "-v",
        "quiet",
        "-print_format",
        "json",
        "-show_format",
        "-show_streams",
        str(path),
    ]
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        payload = json.loads(result.stdout)
    except (subprocess.SubprocessError, json.JSONDecodeError):
        return {"available": True, "parse_error": True}

    format_block = payload.get("format", {})
    streams = payload.get("streams", [])
    video_streams = [item for item in streams if item.get("codec_type") == "video"]
    audio_streams = [item for item in streams if item.get("codec_type") == "audio"]

    return {
        "available": True,
        "format_name": format_block.get("format_name"),
        "duration_sec": _as_float(format_block.get("duration")),
        "bit_rate": _as_int(format_block.get("bit_rate")),
        "stream_count": len(streams),
        "video_stream_count": len(video_streams),
        "audio_stream_count": len(audio_streams),
        "video_codecs": sorted({stream.get("codec_name") for stream in video_streams if stream.get("codec_name")}),
        "audio_codecs": sorted({stream.get("codec_name") for stream in audio_streams if stream.get("codec_name")}),
    }


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
