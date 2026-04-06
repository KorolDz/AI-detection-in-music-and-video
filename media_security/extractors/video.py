from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any

from .common import read_header
from media_security.external_tools import resolve_external_tool

MAX_FTYP_BOX_BYTES = 4096
MAX_META_BOX_BYTES = 512 * 1024
MAX_TEXT_SAMPLE_BYTES = 4096

VIDEO_FFPROBE_TAG_KEYS = {
    "creation_time",
    "com.apple.quicktime.creationdate",
    "com.apple.quicktime.make",
    "com.apple.quicktime.model",
    "com.apple.quicktime.software",
    "com.apple.quicktime.location.iso6709",
    "com.apple.quicktime.location.accuracy.horizontal",
    "location",
    "location-eng",
    "make",
    "model",
    "software",
}

VIDEO_EXIFTOOL_TAG_KEYS = {
    "CreateDate",
    "ModifyDate",
    "TrackCreateDate",
    "TrackModifyDate",
    "MediaCreateDate",
    "MediaModifyDate",
    "CreationDate",
    "AndroidTimeZone",
    "AndroidVersion",
    "AndroidCaptureFPS",
    "Author",
    "Make",
    "Model",
    "SamsungModel",
    "Software",
    "GPSCoordinates",
    "GPSPosition",
    "GPSLatitude",
    "GPSLongitude",
    "GPSAltitude",
    "GPSAltitudeRef",
    "LocationAccuracyHorizontal",
    "Duration",
    "VideoFrameRate",
    "ImageWidth",
    "ImageHeight",
    "ImageSize",
    "Rotation",
    "AvgBitrate",
    "CompressorID",
    "AudioFormat",
    "AudioChannels",
    "AudioSampleRate",
    "ColorPrimaries",
    "TransferCharacteristics",
    "MatrixCoefficients",
    "VideoFullRangeFlag",
    "ZoneIdentifier",
    "Warning",
    "XMPToolkit",
    "CreatorTool",
    "HistorySoftwareAgent",
    "MetadataDate",
    "Comment",
}

VIDEO_STREAM_TAG_KEYS = {"creation_time", "language", "handler_name", "encoder"}


def extract_video_metadata(path: Path, expected_format: str) -> dict[str, Any]:
    metadata: dict[str, Any] = {}

    if expected_format in {"mp4", "mov"}:
        metadata.update(_extract_iso_bmff_metadata(path))
    elif expected_format == "avi":
        metadata.update(_extract_avi_metadata(path))

    embedded_tags = metadata.get("embedded_tags")
    if isinstance(embedded_tags, dict) and embedded_tags:
        _merge_hints(
            metadata,
            hints=_build_hints_from_generic_tags(embedded_tags),
            source="embedded",
        )

    ffprobe_summary = _extract_ffprobe_summary(path)
    if ffprobe_summary:
        metadata["ffprobe"] = ffprobe_summary
        _merge_hints(
            metadata,
            hints=_build_hints_from_ffprobe(ffprobe_summary),
            source="ffprobe",
        )

    exiftool_summary = _extract_exiftool_summary(path)
    if exiftool_summary:
        metadata["exiftool"] = exiftool_summary
        _merge_hints(
            metadata,
            hints=_build_hints_from_exiftool(exiftool_summary),
            source="exiftool",
        )

    return metadata


def _extract_iso_bmff_metadata(path: Path) -> dict[str, Any]:
    ftyp_box = _read_ftyp_box(path)
    if len(ftyp_box) < 16 or ftyp_box[4:8] != b"ftyp":
        return {}

    major_brand = ftyp_box[8:12].decode("latin1", errors="replace")
    minor_version = int.from_bytes(ftyp_box[12:16], byteorder="big")
    compatible_brands: list[str] = []

    for offset in range(16, len(ftyp_box), 4):
        brand_bytes = ftyp_box[offset : offset + 4]
        if len(brand_bytes) < 4:
            break
        brand = brand_bytes.decode("latin1", errors="replace").strip("\x00").strip()
        if brand:
            compatible_brands.append(brand)

    metadata: dict[str, Any] = {
        "major_brand": major_brand,
        "minor_version": minor_version,
        "compatible_brands": compatible_brands,
    }
    embedded_tags = _extract_iso_bmff_embedded_tags(path)
    if embedded_tags:
        metadata["embedded_tags"] = embedded_tags
    return metadata


def _read_ftyp_box(path: Path) -> bytes:
    header = read_header(path, 32)
    if len(header) < 8 or header[4:8] != b"ftyp":
        return b""

    box_size = int.from_bytes(header[0:4], byteorder="big")
    if box_size == 1:
        if len(header) < 16:
            return b""
        box_size = int.from_bytes(header[8:16], byteorder="big")
    if box_size < 16:
        return b""

    read_size = min(box_size, MAX_FTYP_BOX_BYTES)
    return read_header(path, read_size)


def _extract_avi_metadata(path: Path) -> dict[str, Any]:
    header = read_header(path, 64)
    if len(header) < 12 or header[0:4] != b"RIFF" or header[8:12] != b"AVI ":
        return {}

    riff_declared_size = int.from_bytes(header[4:8], byteorder="little") + 8
    return {
        "container": "RIFF/AVI",
        "riff_declared_size_bytes": riff_declared_size,
    }


def _extract_iso_bmff_embedded_tags(path: Path) -> dict[str, str]:
    tags: dict[str, str] = {}
    with path.open("rb") as file_obj:
        file_size = path.stat().st_size
        for box in _iter_boxes(file_obj, start=0, end=file_size):
            if box["type_bytes"] != b"moov":
                continue
            moov_start = box["payload_offset"]
            moov_end = box["payload_offset"] + box["payload_size"]
            for moov_child in _iter_boxes(file_obj, start=moov_start, end=moov_end):
                if moov_child["type_bytes"] == b"udta":
                    tags.update(_extract_udta_tags(file_obj, moov_child))
    return tags


def _extract_udta_tags(file_obj: Any, udta_box: dict[str, int | bytes | str]) -> dict[str, str]:
    tags: dict[str, str] = {}
    udta_start = int(udta_box["payload_offset"])
    udta_end = udta_start + int(udta_box["payload_size"])

    for child in _iter_boxes(file_obj, start=udta_start, end=udta_end):
        box_type_bytes = child["type_bytes"]
        box_type_text = _normalize_box_type(box_type_bytes)
        if box_type_bytes == b"meta":
            tags.update(_extract_meta_mdta_tags(file_obj, child))
            continue

        nested_tags = _extract_nested_udta_tags(file_obj, child)
        if nested_tags:
            for key, value in nested_tags.items():
                tags.setdefault(key, value)

        if child["payload_size"] <= 0:
            continue
        sample = _read_box_sample(file_obj, int(child["payload_offset"]), int(child["payload_size"]))
        text_value = _extract_best_text(sample)
        if not text_value:
            continue
        tags[f"udta.{box_type_text}"] = text_value

    return _postprocess_udta_tags(tags)


def _extract_nested_udta_tags(file_obj: Any, parent_box: dict[str, int | bytes | str]) -> dict[str, str]:
    tags: dict[str, str] = {}
    parent_payload_offset = int(parent_box["payload_offset"])
    parent_payload_size = int(parent_box["payload_size"])
    if parent_payload_size < 16:
        return tags

    nested_boxes = _iter_nested_boxes(file_obj, payload_offset=parent_payload_offset, payload_size=parent_payload_size)
    for child in nested_boxes:
        box_type_bytes = child["type_bytes"]
        box_type_text = _normalize_box_type(box_type_bytes)
        if box_type_bytes == b"meta":
            for key, value in _extract_meta_mdta_tags(file_obj, child).items():
                tags.setdefault(key, value)
            continue

        sample = _read_box_sample(file_obj, int(child["payload_offset"]), int(child["payload_size"]))
        text_value = _extract_best_text(sample)
        if not text_value:
            continue
        if _is_reasonable_box_name(box_type_text):
            tags.setdefault(f"udta.{box_type_text}", text_value)

    return tags


def _iter_nested_boxes(file_obj: Any, payload_offset: int, payload_size: int) -> list[dict[str, int | bytes | str]]:
    end = payload_offset + payload_size
    for shift in (0, 4, 8):
        start = payload_offset + shift
        if start + 8 > end:
            continue
        boxes = _iter_boxes(file_obj, start=start, end=end)
        if not boxes:
            continue
        total = sum(int(item["size"]) for item in boxes)
        if total >= 8 and total <= (end - start):
            return boxes
    return []


def _extract_meta_mdta_tags(file_obj: Any, meta_box: dict[str, int | bytes | str]) -> dict[str, str]:
    tags: dict[str, str] = {}
    meta_payload_offset = int(meta_box["payload_offset"])
    meta_payload_size = int(meta_box["payload_size"])
    if meta_payload_size <= 4:
        return tags

    meta_children_start = meta_payload_offset + 4  # skip version+flags
    meta_children_end = meta_payload_offset + meta_payload_size
    keys: list[str] = []

    for child in _iter_boxes(file_obj, start=meta_children_start, end=meta_children_end):
        if child["type_bytes"] == b"keys":
            keys = _parse_keys_box(file_obj, child)
        elif child["type_bytes"] == b"ilst":
            tags.update(_parse_ilst_box(file_obj, child, keys))

    return tags


def _parse_keys_box(file_obj: Any, keys_box: dict[str, int | bytes | str]) -> list[str]:
    payload = _read_box_payload(file_obj, int(keys_box["payload_offset"]), int(keys_box["payload_size"]), MAX_META_BOX_BYTES)
    if len(payload) < 8:
        return []

    entry_count = int.from_bytes(payload[4:8], byteorder="big")
    offset = 8
    keys: list[str] = []
    for _ in range(entry_count):
        if offset + 8 > len(payload):
            break
        entry_size = int.from_bytes(payload[offset : offset + 4], byteorder="big")
        if entry_size < 8 or offset + entry_size > len(payload):
            break
        namespace = payload[offset + 4 : offset + 8]
        value_bytes = payload[offset + 8 : offset + entry_size]
        value_text = _extract_best_text(value_bytes)
        if value_text:
            namespace_text = namespace.decode("latin1", errors="replace").strip().lower()
            if namespace_text == "mdta":
                keys.append(value_text)
            else:
                keys.append(f"{namespace_text}:{value_text}")
        else:
            keys.append("")
        offset += entry_size
    return keys


def _parse_ilst_box(file_obj: Any, ilst_box: dict[str, int | bytes | str], keys: list[str]) -> dict[str, str]:
    tags: dict[str, str] = {}
    ilst_start = int(ilst_box["payload_offset"])
    ilst_end = ilst_start + int(ilst_box["payload_size"])

    for entry in _iter_boxes(file_obj, start=ilst_start, end=ilst_end):
        key_name = _resolve_ilst_entry_key(entry, keys)
        if not key_name:
            continue

        entry_start = int(entry["payload_offset"])
        entry_end = entry_start + int(entry["payload_size"])
        for subbox in _iter_boxes(file_obj, start=entry_start, end=entry_end):
            if subbox["type_bytes"] != b"data":
                continue
            payload = _read_box_payload(
                file_obj,
                int(subbox["payload_offset"]),
                int(subbox["payload_size"]),
                MAX_TEXT_SAMPLE_BYTES,
            )
            if len(payload) <= 8:
                continue
            text_value = _extract_best_text(payload[8:])
            if text_value:
                tags.setdefault(key_name, text_value)
            break

    return tags


def _resolve_ilst_entry_key(entry: dict[str, int | bytes | str], keys: list[str]) -> str | None:
    type_bytes = entry["type_bytes"]
    if not isinstance(type_bytes, bytes):
        return None

    if type_bytes[0] == 0:
        index = int.from_bytes(type_bytes, byteorder="big")
        if 1 <= index <= len(keys):
            key_name = keys[index - 1].strip()
            if key_name:
                return key_name

    normalized = _normalize_box_type(type_bytes).strip()
    if normalized:
        return normalized
    return None


def _iter_boxes(file_obj: Any, start: int, end: int) -> list[dict[str, int | bytes | str]]:
    boxes: list[dict[str, int | bytes | str]] = []
    offset = start
    while offset + 8 <= end:
        file_obj.seek(offset)
        header = file_obj.read(8)
        if len(header) < 8:
            break

        size = int.from_bytes(header[0:4], byteorder="big")
        box_type = header[4:8]
        header_size = 8

        if size == 1:
            extended_size = file_obj.read(8)
            if len(extended_size) < 8:
                break
            size = int.from_bytes(extended_size, byteorder="big")
            header_size = 16
        elif size == 0:
            size = end - offset

        if size < header_size:
            break

        payload_offset = offset + header_size
        payload_size = size - header_size
        if payload_offset + payload_size > end:
            payload_size = max(0, end - payload_offset)
            size = header_size + payload_size

        boxes.append(
            {
                "offset": offset,
                "size": size,
                "type_bytes": box_type,
                "type_text": box_type.decode("latin1", errors="replace"),
                "payload_offset": payload_offset,
                "payload_size": payload_size,
            }
        )

        if size <= 0:
            break
        offset += size

    return boxes


def _read_box_sample(file_obj: Any, payload_offset: int, payload_size: int) -> bytes:
    to_read = min(payload_size, MAX_TEXT_SAMPLE_BYTES)
    if to_read <= 0:
        return b""
    file_obj.seek(payload_offset)
    return file_obj.read(to_read)


def _read_box_payload(file_obj: Any, payload_offset: int, payload_size: int, max_bytes: int) -> bytes:
    to_read = min(payload_size, max_bytes)
    if to_read <= 0:
        return b""
    file_obj.seek(payload_offset)
    return file_obj.read(to_read)


def _extract_best_text(payload: bytes) -> str | None:
    if not payload:
        return None

    cleaned = payload.replace(b"\x00", b" ").strip()
    if not cleaned:
        return None

    fragments = re.findall(rb"[ -~]{3,}", cleaned)
    if fragments:
        best = max(fragments, key=len)
        text = best.decode("utf-8", errors="replace").strip()
        if text:
            return text

    for encoding in ("utf-8", "utf-16-le", "utf-16-be", "latin1"):
        try:
            decoded = payload.decode(encoding, errors="ignore").replace("\x00", " ").strip()
        except LookupError:
            continue
        if len(decoded) >= 3:
            return decoded
    return None


def _normalize_box_type(type_bytes: bytes) -> str:
    try:
        return type_bytes.decode("latin1", errors="replace").strip("\x00").strip()
    except Exception:  # noqa: BLE001 - defensive conversion for malformed bytes
        return ""


def _is_reasonable_box_name(name: str) -> bool:
    if not name or len(name) > 16:
        return False
    return bool(re.match(r"^[A-Za-z©][A-Za-z0-9©._-]{0,15}$", name))


def _postprocess_udta_tags(tags: dict[str, str]) -> dict[str, str]:
    cleaned: dict[str, str] = {}
    for key, value in tags.items():
        if not value:
            continue
        if key.startswith("udta."):
            suffix = key[5:]
            if not _is_reasonable_box_name(suffix):
                continue
        cleaned[key] = value

    if "udta.mdln" not in cleaned:
        candidates = [cleaned.get("udta.smta", "")] + list(cleaned.values())
        for candidate in candidates:
            match = re.search(r"\bmdln([A-Za-z0-9_-]{3,})\b", candidate)
            if match:
                cleaned["udta.mdln"] = match.group(1)
                break

    return cleaned


def _extract_ffprobe_summary(path: Path) -> dict[str, Any] | None:
    ffprobe_path = resolve_external_tool("ffprobe")
    if ffprobe_path is None:
        return {"available": False}

    command = [
        str(ffprobe_path),
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
    primary_video = video_streams[0] if video_streams else {}
    format_tags = _select_video_ffprobe_tags(_to_string_dict(format_block.get("tags")))
    stream_tags = _collect_stream_tags(
        streams,
        include_keys=VIDEO_STREAM_TAG_KEYS,
        max_streams=3,
    )

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
        "width": _as_int(primary_video.get("width")),
        "height": _as_int(primary_video.get("height")),
        "avg_frame_rate": _parse_fraction(primary_video.get("avg_frame_rate")),
        "format_tags": format_tags,
        "stream_tags": stream_tags,
    }


def _extract_exiftool_summary(path: Path) -> dict[str, Any] | None:
    exiftool_path = resolve_external_tool("exiftool")
    if exiftool_path is None:
        return {"available": False}

    command = [str(exiftool_path), "-j", str(path)]
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        payload = json.loads(result.stdout)
        if not isinstance(payload, list) or not payload:
            return {"available": True, "parse_error": True}
        raw_tags = payload[0] if isinstance(payload[0], dict) else {}
    except (subprocess.SubprocessError, json.JSONDecodeError):
        return {"available": True, "parse_error": True}

    filtered = {
        key: value
        for key, value in raw_tags.items()
        if key
        not in {
            "SourceFile",
            "Directory",
            "FileName",
            "FilePermissions",
            "FileAccessDate",
            "FileModifyDate",
            "FileInodeChangeDate",
        }
    }
    normalized_tags = _to_string_dict(filtered)
    selected_tags = _select_video_exiftool_tags(normalized_tags)
    return {
        "available": True,
        "tags": selected_tags,
        "high_value": _build_video_exiftool_high_value(selected_tags),
    }


def _select_video_ffprobe_tags(tags: dict[str, str]) -> dict[str, str]:
    return _select_metadata_tags(tags, VIDEO_FFPROBE_TAG_KEYS)


def _select_video_exiftool_tags(tags: dict[str, str]) -> dict[str, str]:
    return _select_metadata_tags(tags, VIDEO_EXIFTOOL_TAG_KEYS)


def _build_hints_from_ffprobe(ffprobe_summary: dict[str, Any]) -> dict[str, str]:
    format_tags = ffprobe_summary.get("format_tags", {}) or {}
    stream_tags = ffprobe_summary.get("stream_tags", {}) or {}
    combined = dict(format_tags)
    for stream_tag in stream_tags.values():
        if isinstance(stream_tag, dict):
            combined.update(stream_tag)
    return _build_hints_from_generic_tags(combined)


def _build_hints_from_exiftool(exiftool_summary: dict[str, Any]) -> dict[str, str]:
    tags = exiftool_summary.get("tags", {}) or {}
    hints = _build_hints_from_generic_tags(tags)

    exif_make = _first_non_empty(tags, ["Make"])
    exif_model = _first_non_empty(tags, ["Model", "Samsung Model", "SamsungModel"])
    exif_author = _first_non_empty(tags, ["Author"])
    exif_software = _first_non_empty(tags, ["Software", "Encoder"])
    exif_datetime = _first_non_empty(
        tags,
        [
            "Create Date",
            "CreateDate",
            "Media Create Date",
            "MediaCreateDate",
            "Track Create Date",
            "TrackCreateDate",
        ],
    )
    exif_gps = _first_non_empty(tags, ["GPSCoordinates", "GPSPosition", "LocationInformation"])
    exif_android_version = _first_non_empty(tags, ["Android Version", "AndroidVersion"])

    if exif_make:
        hints.setdefault("device_make", exif_make)
    if exif_model:
        hints.setdefault("device_model", exif_model)
    if exif_author:
        if exif_model and exif_model not in exif_author:
            hints.setdefault("source_device", f"{exif_author} ({exif_model})")
        else:
            hints.setdefault("source_device", exif_author)
    if exif_software:
        hints.setdefault("editing_software", exif_software)
    if exif_datetime:
        hints.setdefault("recorded_at", exif_datetime)
    if exif_android_version:
        hints.setdefault("os_version", exif_android_version)
    if exif_gps:
        hints.setdefault("location", exif_gps)
    return hints


def _build_hints_from_generic_tags(tags: dict[str, str]) -> dict[str, str]:
    exact_map = {key.lower(): value for key, value in tags.items() if value}
    normalized_map = {_normalize_lookup_key(key): value for key, value in tags.items() if value}

    def by_candidates(candidates: list[str]) -> str | None:
        for candidate in candidates:
            candidate_lower = candidate.lower()
            if candidate_lower in exact_map:
                return exact_map[candidate_lower]
            normalized_candidate = _normalize_lookup_key(candidate)
            if normalized_candidate in normalized_map:
                return normalized_map[normalized_candidate]
        return None

    device_make = by_candidates(
        [
            "com.apple.quicktime.make",
            "make",
            "device_make",
            "\xa9mak",
        ]
    )
    device_model = by_candidates(
        [
            "com.apple.quicktime.model",
            "model",
            "samsung model",
            "device_model",
            "com.android.model",
            "udta.mdln",
            "mdln",
        ]
    )
    source_device_name = by_candidates(
        [
            "udta.auth",
            "author",
            "device_name",
            "title",
            "album",
        ]
    )
    editing_software = by_candidates(
        [
            "com.apple.quicktime.software",
            "software",
            "encoder",
            "encoding_tool",
            "\xa9swr",
        ]
    )
    os_version = by_candidates(
        [
            "com.android.version",
            "android version",
            "android_version",
            "os_version",
        ]
    )
    recorded_at = by_candidates(
        [
            "creation_time",
            "com.apple.quicktime.creationdate",
            "create date",
            "track create date",
            "media create date",
            "date",
            "\xa9day",
        ]
    )
    location = by_candidates(
        [
            "location",
            "location-eng",
            "com.apple.quicktime.location.iso6709",
            "com.apple.quicktime.location.ISO6709",
            "xyz",
        ]
    )

    hints: dict[str, str] = {}
    inferred_make = _infer_device_make(
        source_device_name=source_device_name,
        device_model=device_model,
    )
    if inferred_make and not device_make:
        device_make = inferred_make

    if device_make:
        hints["device_make"] = device_make
    if device_model:
        hints["device_model"] = device_model
    if source_device_name:
        if device_model and device_model not in source_device_name:
            hints["source_device"] = f"{source_device_name} ({device_model})"
        else:
            hints["source_device"] = source_device_name
    elif device_make or device_model:
        hints["source_device"] = " ".join(item for item in [device_make, device_model] if item)
    if editing_software:
        hints["editing_software"] = editing_software
    if os_version:
        hints["os_version"] = os_version
    if recorded_at:
        hints["recorded_at"] = recorded_at
    if location:
        hints["location"] = location
    return hints


def _infer_device_make(source_device_name: str | None, device_model: str | None) -> str | None:
    candidates = " ".join(item for item in [source_device_name or "", device_model or ""]).lower()
    if not candidates:
        return None
    if "galaxy" in candidates or "samsung" in candidates or "sm-" in candidates:
        return "Samsung"
    if "iphone" in candidates or "apple" in candidates:
        return "Apple"
    if "pixel" in candidates or "google" in candidates:
        return "Google"
    return None


def _merge_hints(metadata: dict[str, Any], hints: dict[str, str], source: str) -> None:
    if not hints:
        return
    existing = metadata.get("metadata_hints", {})
    if not isinstance(existing, dict):
        existing = {}
    for key, value in hints.items():
        existing.setdefault(key, value)
    metadata["metadata_hints"] = existing

    # Convenience aliases used in reports and security rules.
    if "source_device" in existing:
        metadata.setdefault("source_device_hint", existing["source_device"])
        metadata.setdefault("source_device_hint_source", source)
    if "editing_software" in existing:
        metadata.setdefault("editing_software_hint", existing["editing_software"])
        metadata.setdefault("editing_software_hint_source", source)


def _select_metadata_tags(tags: dict[str, str], allowed_keys: set[str]) -> dict[str, str]:
    if not tags:
        return {}
    allowed_normalized = {_normalize_lookup_key(key) for key in allowed_keys}
    selected: dict[str, str] = {}
    for key, value in tags.items():
        if _normalize_lookup_key(key) in allowed_normalized:
            selected[key] = value
    return selected


def _collect_stream_tags(
    streams: list[dict[str, Any]],
    include_keys: set[str] | None = None,
    max_streams: int | None = None,
) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    include_normalized = {_normalize_lookup_key(item) for item in include_keys} if include_keys else None

    for stream in streams:
        if max_streams is not None and len(result) >= max_streams:
            break

        index = stream.get("index")
        tags = _to_string_dict(stream.get("tags"))
        if include_normalized is not None:
            tags = {
                key: value
                for key, value in tags.items()
                if _normalize_lookup_key(key) in include_normalized
            }
        if tags and isinstance(index, int):
            result[str(index)] = tags
    return result


def _to_string_dict(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    normalized: dict[str, str] = {}
    for key, item in value.items():
        if key is None or item is None:
            continue
        key_text = str(key).strip()
        item_text = str(item).strip()
        if key_text and item_text:
            normalized[key_text] = item_text
    return normalized


def _build_video_exiftool_high_value(tags: dict[str, str]) -> dict[str, str | bool]:
    high_value: dict[str, str | bool] = {}

    source_author = _pick_case_insensitive(tags, ["Author"])
    device_make = _pick_case_insensitive(tags, ["Make"])
    device_model = _pick_case_insensitive(tags, ["Samsung Model", "SamsungModel", "Model"])
    os_version = _pick_case_insensitive(tags, ["Android Version", "AndroidVersion", "Software"])
    software_version = _pick_case_insensitive(tags, ["Software"])
    capture_fps = _pick_case_insensitive(tags, ["Android Capture FPS", "AndroidCaptureFPS", "Video Frame Rate"])
    android_timezone = _pick_case_insensitive(tags, ["Android Time Zone", "AndroidTimeZone"])
    create_date = _pick_case_insensitive(
        tags,
        ["CreationDate", "Create Date", "CreateDate", "Track Create Date", "TrackCreateDate", "Media Create Date"],
    )
    modify_date = _pick_case_insensitive(tags, ["Modify Date", "ModifyDate", "Track Modify Date", "Media Modify Date"])
    duration = _pick_case_insensitive(tags, ["Duration"])
    width = _pick_case_insensitive(tags, ["Image Width", "Source Image Width"])
    height = _pick_case_insensitive(tags, ["Image Height", "Source Image Height"])
    resolution = _pick_case_insensitive(tags, ["Image Size"])
    rotation = _pick_case_insensitive(tags, ["Rotation"])
    avg_bitrate = _pick_case_insensitive(tags, ["Avg Bitrate", "AvgBitrate"])
    video_codec = _pick_case_insensitive(tags, ["Compressor ID", "CompressorID"])
    audio_codec = _pick_case_insensitive(tags, ["Audio Format"])
    audio_channels = _pick_case_insensitive(tags, ["Audio Channels"])
    audio_sample_rate = _pick_case_insensitive(tags, ["Audio Sample Rate"])
    color_primaries = _pick_case_insensitive(tags, ["Color Primaries"])
    transfer = _pick_case_insensitive(tags, ["Transfer Characteristics"])
    matrix = _pick_case_insensitive(tags, ["Matrix Coefficients"])
    full_range = _pick_case_insensitive(tags, ["Video Full Range Flag"])
    gps_coordinates = _pick_case_insensitive(tags, ["GPSCoordinates", "GPSPosition"])
    gps_latitude = _pick_case_insensitive(tags, ["GPSLatitude"])
    gps_longitude = _pick_case_insensitive(tags, ["GPSLongitude"])
    gps_altitude = _pick_case_insensitive(tags, ["GPSAltitude"])
    location_accuracy = _pick_case_insensitive(tags, ["LocationAccuracyHorizontal"])
    zone_identifier = _pick_case_insensitive(tags, ["Zone Identifier", "ZoneIdentifier"])

    source_device = source_author or " ".join(item for item in [device_make, device_model] if item)
    if source_device:
        high_value["source_device"] = source_device
    if device_make:
        high_value["device_make"] = device_make
    if device_model:
        high_value["device_model"] = device_model
    if os_version:
        high_value["os_version"] = os_version
    if software_version:
        high_value["software_version"] = software_version
    if capture_fps:
        high_value["capture_fps"] = capture_fps
    if android_timezone:
        high_value["device_timezone"] = android_timezone
    if create_date:
        high_value["recorded_at"] = create_date
    if modify_date:
        high_value["modified_at"] = modify_date
    if gps_coordinates:
        high_value["gps_coordinates"] = gps_coordinates
    if gps_latitude:
        high_value["gps_latitude"] = gps_latitude
    if gps_longitude:
        high_value["gps_longitude"] = gps_longitude
    if gps_altitude:
        high_value["gps_altitude"] = gps_altitude
    if location_accuracy:
        high_value["gps_accuracy_horizontal"] = location_accuracy
    if duration:
        high_value["duration"] = duration
    if resolution:
        high_value["resolution"] = resolution
    elif width and height:
        high_value["resolution"] = f"{width}x{height}"
    if rotation:
        high_value["rotation"] = rotation
    if avg_bitrate:
        high_value["avg_bitrate"] = avg_bitrate
    if video_codec:
        high_value["video_codec"] = video_codec
    if audio_codec:
        high_value["audio_codec"] = audio_codec
    if audio_channels:
        high_value["audio_channels"] = audio_channels
    if audio_sample_rate:
        high_value["audio_sample_rate"] = audio_sample_rate
    if color_primaries:
        high_value["color_primaries"] = color_primaries
    if transfer:
        high_value["transfer_characteristics"] = transfer
    if matrix:
        high_value["matrix_coefficients"] = matrix
    if full_range:
        high_value["video_full_range_flag"] = full_range
    if zone_identifier:
        high_value["zone_identifier"] = zone_identifier
        high_value["downloaded_from_internet"] = zone_identifier.strip().lower() == "exists"

    warning = _pick_case_insensitive(tags, ["Warning"])
    if warning:
        high_value["exif_warning"] = warning
    return high_value


def _pick_case_insensitive(tags: dict[str, str], keys: list[str]) -> str | None:
    lowered = {key.lower(): value for key, value in tags.items()}
    normalized = {_normalize_lookup_key(key): value for key, value in tags.items()}
    for key in keys:
        value = lowered.get(key.lower())
        if value:
            return value
        value = normalized.get(_normalize_lookup_key(key))
        if value:
            return value
    return None


def _first_non_empty(tags: dict[str, str], keys: list[str]) -> str | None:
    normalized = {_normalize_lookup_key(key): value for key, value in tags.items() if value}
    for key in keys:
        value = tags.get(key)
        if value:
            return value
        normalized_value = normalized.get(_normalize_lookup_key(key))
        if normalized_value:
            return normalized_value
    return None


def _normalize_lookup_key(value: str) -> str:
    return "".join(char for char in value.lower() if char.isalnum())


def _parse_fraction(value: Any) -> float | None:
    if not value:
        return None
    text = str(value)
    if "/" in text:
        left, right = text.split("/", 1)
        try:
            denominator = float(right)
            if denominator == 0:
                return None
            return float(left) / denominator
        except ValueError:
            return None
    try:
        return float(text)
    except ValueError:
        return None


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
