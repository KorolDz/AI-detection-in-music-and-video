from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from media_security.core.models import Finding, Severity

EDITING_MARKERS = (
    "adobe",
    "premiere",
    "after effects",
    "photoshop",
    "final cut",
    "davinci",
    "resolve",
    "avidemux",
    "ffmpeg",
    "handbrake",
    "capcut",
    "clipchamp",
    "inshot",
    "canva",
    "audacity",
    "reaper",
    "logic pro",
    "ableton",
    "cubase",
    "fl studio",
    "spotidownloader",
    "yt-dlp",
    "converted by",
    "downloader",
    "youtube",
)


def analyze_metadata_forensics(file_format: str, technical: dict[str, object]) -> list[Finding]:
    if file_format not in {"wav", "mp3", "mp4", "mov", "avi"}:
        return []

    summary = build_metadata_forensics_summary(technical)
    if summary:
        technical["metadata_forensics"] = summary
    return _build_forensic_findings(summary)


def build_metadata_forensics_summary(technical: dict[str, object]) -> dict[str, object]:
    sources = _collect_metadata_sources(technical)
    source_names = sorted(sources)

    hardware_identity = _best_hardware_identity(sources, technical.get("metadata_hints"))
    hardware_markers_present = bool(hardware_identity)

    cross_checks = _build_cross_checks(sources)
    editing_markers = _collect_editing_markers(sources)
    xmp_summary = _build_xmp_summary(sources)
    metadata_edit_timeline = _build_metadata_edit_timeline(sources, editing_markers, xmp_summary)

    summary = {
        "sources_present": source_names,
        "hardware_markers_present": hardware_markers_present,
        "hardware_identity": hardware_identity,
        "cross_checks": cross_checks,
        "editing_markers": editing_markers,
        "xmp": xmp_summary,
        "metadata_edit_timeline": metadata_edit_timeline,
    }
    return _drop_empty(summary)


def _build_forensic_findings(summary: dict[str, object]) -> list[Finding]:
    findings: list[Finding] = []

    cross_checks = summary.get("cross_checks", {})
    if isinstance(cross_checks, dict):
        device_check = cross_checks.get("device")
        if isinstance(device_check, dict) and device_check.get("status") == "conflict":
            findings.append(
                Finding(
                    code="METADATA_DEVICE_CONFLICT",
                    severity=Severity.WARNING,
                    message="Device identifiers are inconsistent across metadata sources.",
                    details=device_check,
                )
            )

        recorded_check = cross_checks.get("recorded_at")
        if isinstance(recorded_check, dict) and recorded_check.get("status") == "conflict":
            findings.append(
                Finding(
                    code="METADATA_TIMESTAMP_CONFLICT",
                    severity=Severity.WARNING,
                    message="Recording timestamps differ across metadata sources.",
                    details=recorded_check,
                )
            )

        location_check = cross_checks.get("location")
        if isinstance(location_check, dict) and location_check.get("status") == "conflict":
            findings.append(
                Finding(
                    code="METADATA_LOCATION_CONFLICT",
                    severity=Severity.WARNING,
                    message="Location metadata differs across metadata sources.",
                    details=location_check,
                )
            )

    editing_markers = summary.get("editing_markers")
    if isinstance(editing_markers, list) and editing_markers:
        findings.append(
            Finding(
                code="EDITING_SOFTWARE_METADATA_MARKER",
                severity=Severity.WARNING,
                message="Metadata contains markers of editing, transcoding, or downloader software.",
                details={"markers": editing_markers},
            )
        )

    xmp_summary = summary.get("xmp")
    xmp_present = isinstance(xmp_summary, dict) and bool(xmp_summary.get("present"))
    if xmp_present:
        xmp_fields = {
            key: value
            for key, value in xmp_summary.items()
            if key != "present" and value not in ({}, [], "", None)
        }
        findings.append(
            Finding(
                code="XMP_METADATA_PRESENT",
                severity=Severity.INFO,
                message="XMP metadata is present and was included in forensic cross-checking.",
                details=xmp_fields,
            )
        )

    hardware_markers_present = bool(summary.get("hardware_markers_present"))
    if not hardware_markers_present:
        severity = Severity.WARNING if xmp_present or (isinstance(editing_markers, list) and editing_markers) else Severity.INFO
        findings.append(
            Finding(
                code="HARDWARE_TAGS_MISSING",
                severity=severity,
                message="No reliable hardware-origin metadata markers were found.",
            )
        )

    edit_timeline = summary.get("metadata_edit_timeline")
    if isinstance(edit_timeline, dict) and edit_timeline.get("status") == "modified_after_recording":
        findings.append(
            Finding(
                code="METADATA_MODIFIED_AFTER_RECORDING",
                severity=Severity.WARNING if editing_markers else Severity.INFO,
                message="Metadata modification time is later than the recorded creation time.",
                details=edit_timeline,
            )
        )

    return findings


def _collect_metadata_sources(technical: dict[str, object]) -> dict[str, dict[str, str]]:
    sources: dict[str, dict[str, str]] = {}

    embedded_tags = technical.get("embedded_tags")
    if isinstance(embedded_tags, dict):
        fields = _extract_fields_from_tags(embedded_tags)
        if fields:
            sources["embedded"] = fields

    ffprobe = technical.get("ffprobe")
    if isinstance(ffprobe, dict):
        combined_tags = {}
        format_tags = ffprobe.get("format_tags")
        if isinstance(format_tags, dict):
            combined_tags.update(format_tags)
        stream_tags = ffprobe.get("stream_tags")
        if isinstance(stream_tags, dict):
            for value in stream_tags.values():
                if isinstance(value, dict):
                    for key, item in value.items():
                        combined_tags.setdefault(key, item)
        fields = _extract_fields_from_tags(combined_tags)
        if fields:
            sources["ffprobe"] = fields

    exiftool = technical.get("exiftool")
    if isinstance(exiftool, dict):
        tags = exiftool.get("tags")
        if isinstance(tags, dict):
            fields = _extract_fields_from_tags(tags)
            if fields:
                sources["exiftool"] = fields

    return sources


def _extract_fields_from_tags(tags: dict[str, object]) -> dict[str, str]:
    string_tags = {str(key): str(value) for key, value in tags.items() if key and value not in (None, "")}
    exact_map = {key.lower(): value for key, value in string_tags.items()}
    normalized_map = {_normalize_key(key): value for key, value in string_tags.items()}

    def pick(*candidates: str) -> str | None:
        for candidate in candidates:
            exact_value = exact_map.get(candidate.lower())
            if exact_value:
                return exact_value
            normalized_value = normalized_map.get(_normalize_key(candidate))
            if normalized_value:
                return normalized_value
        return None

    gps_coordinates = pick("GPSCoordinates", "GPSPosition")
    if not gps_coordinates:
        latitude = pick("GPSLatitude")
        longitude = pick("GPSLongitude")
        altitude = pick("GPSAltitude")
        if latitude and longitude:
            gps_coordinates = f"{latitude}, {longitude}"
            if altitude:
                gps_coordinates = f"{gps_coordinates}, {altitude}"

    fields = {
        "device_make": pick("com.apple.quicktime.make", "Make", "device_make", "©mak"),
        "device_model": pick(
            "com.apple.quicktime.model",
            "Model",
            "Samsung Model",
            "SamsungModel",
            "device_model",
            "com.android.model",
            "udta.mdln",
            "mdln",
        ),
        "source_device": pick("udta.auth", "Author", "Artist", "device_name", "source_device"),
        "editing_software": pick(
            "com.apple.quicktime.software",
            "Software",
            "Encoder",
            "EncodedBy",
            "EncodingTool",
            "CreatorTool",
            "HistorySoftwareAgent",
            "©swr",
        ),
        "recorded_at": pick(
            "creation_time",
            "com.apple.quicktime.creationdate",
            "CreateDate",
            "Create Date",
            "TrackCreateDate",
            "MediaCreateDate",
            "DateTimeOriginal",
            "Date/Time Original",
            "CreationDate",
            "recording_time",
            "date",
            "©day",
        ),
        "modified_at": pick(
            "ModifyDate",
            "Modify Date",
            "TrackModifyDate",
            "MediaModifyDate",
            "MetadataDate",
        ),
        "location": pick(
            "location",
            "location-eng",
            "com.apple.quicktime.location.iso6709",
            "com.apple.quicktime.location.ISO6709",
            "LocationInformation",
            "xyz",
        )
        or gps_coordinates,
        "os_version": pick("AndroidVersion", "Android Version", "com.android.version", "os_version"),
        "xmp_toolkit": pick("XMPToolkit"),
        "xmp_creator_tool": pick("CreatorTool"),
        "xmp_history_software_agent": pick("HistorySoftwareAgent"),
        "xmp_metadata_date": pick("MetadataDate"),
        "comment": pick("Comment"),
        "zone_identifier": pick("ZoneIdentifier", "Zone Identifier"),
    }

    source_device = fields.get("source_device")
    device_make = fields.get("device_make")
    device_model = fields.get("device_model")
    if not source_device and (device_make or device_model):
        fields["source_device"] = " ".join(item for item in [device_make, device_model] if item)

    return {key: value for key, value in fields.items() if value}


def _best_hardware_identity(
    sources: dict[str, dict[str, str]],
    metadata_hints: object,
) -> str | None:
    candidates: list[str] = []
    for source in sources.values():
        device_identity = _device_identity(source)
        if device_identity:
            candidates.append(device_identity)

    if isinstance(metadata_hints, dict):
        source_device = metadata_hints.get("source_device")
        if isinstance(source_device, str) and source_device.strip():
            candidates.append(source_device.strip())

    return candidates[0] if candidates else None


def _build_cross_checks(sources: dict[str, dict[str, str]]) -> dict[str, object]:
    return _drop_empty(
        {
            "device": _check_device_consistency(sources),
            "recorded_at": _check_timestamp_consistency(sources, field_name="recorded_at"),
            "location": _check_location_consistency(sources),
        }
    )


def _check_device_consistency(sources: dict[str, dict[str, str]]) -> dict[str, object] | None:
    compared_values: dict[str, str] = {}
    make_values: dict[str, str] = {}
    model_values: dict[str, str] = {}

    for source_name, source_fields in sources.items():
        device_identity = _device_identity(source_fields)
        if device_identity:
            compared_values[source_name] = device_identity
        make_value = source_fields.get("device_make")
        if make_value:
            make_values[source_name] = make_value
        model_value = source_fields.get("device_model")
        if model_value:
            model_values[source_name] = model_value

    if len(compared_values) < 2:
        return None

    model_conflict = _normalized_distinct_count(model_values.values()) > 1
    make_conflict = _normalized_distinct_count(make_values.values()) > 1

    if model_conflict or make_conflict:
        return {
            "status": "conflict",
            "values": compared_values,
        }

    normalized_device_values = {_normalize_text(value) for value in compared_values.values() if value}
    if len(normalized_device_values) == 1:
        return {
            "status": "consistent",
            "value": next(iter(compared_values.values())),
            "sources": sorted(compared_values),
        }

    if model_values and not model_conflict:
        shared_model = next(iter(model_values.values()))
        return {
            "status": "consistent",
            "value": shared_model,
            "sources": sorted(compared_values),
        }

    return {
        "status": "conflict",
        "values": compared_values,
    }


def _check_timestamp_consistency(
    sources: dict[str, dict[str, str]],
    field_name: str,
) -> dict[str, object] | None:
    values = {
        source_name: source_fields[field_name]
        for source_name, source_fields in sources.items()
        if field_name in source_fields
    }
    if len(values) < 2:
        return None

    parsed_values = {source_name: _parse_metadata_timestamp(value) for source_name, value in values.items()}
    datetimes = [value for value in parsed_values.values() if value is not None]
    if len(datetimes) >= 2:
        earliest = min(datetimes)
        latest = max(datetimes)
        if (latest - earliest).total_seconds() <= 120:
            return {
                "status": "consistent",
                "value": values[next(iter(values))],
                "sources": sorted(values),
            }

    normalized_values = {_normalize_text(value) for value in values.values() if value}
    if len(normalized_values) == 1:
        return {
            "status": "consistent",
            "value": next(iter(values.values())),
            "sources": sorted(values),
        }

    return {
        "status": "conflict",
        "values": values,
    }


def _check_location_consistency(sources: dict[str, dict[str, str]]) -> dict[str, object] | None:
    values = {
        source_name: source_fields["location"]
        for source_name, source_fields in sources.items()
        if "location" in source_fields
    }
    if len(values) < 2:
        return None

    coordinates = {source_name: _parse_coordinates(value) for source_name, value in values.items()}
    comparable = [value for value in coordinates.values() if value is not None]
    if len(comparable) >= 2:
        latitudes = [item[0] for item in comparable]
        longitudes = [item[1] for item in comparable]
        if max(latitudes) - min(latitudes) <= 0.001 and max(longitudes) - min(longitudes) <= 0.001:
            return {
                "status": "consistent",
                "value": next(iter(values.values())),
                "sources": sorted(values),
            }

    normalized_values = {_normalize_text(value) for value in values.values() if value}
    if len(normalized_values) == 1:
        return {
            "status": "consistent",
            "value": next(iter(values.values())),
            "sources": sorted(values),
        }

    return {
        "status": "conflict",
        "values": values,
    }


def _collect_editing_markers(sources: dict[str, dict[str, str]]) -> list[str]:
    markers: list[str] = []
    seen: set[str] = set()

    for source_name, source_fields in sources.items():
        candidates = (
            ("editing_software", source_fields.get("editing_software")),
            ("xmp_creator_tool", source_fields.get("xmp_creator_tool")),
            ("xmp_history_software_agent", source_fields.get("xmp_history_software_agent")),
            ("xmp_toolkit", source_fields.get("xmp_toolkit")),
            ("comment", source_fields.get("comment")),
        )
        for field_name, value in candidates:
            if not value:
                continue
            lowered = value.lower()
            if any(marker in lowered for marker in EDITING_MARKERS):
                marker_value = f"{source_name}:{field_name}={value}"
                if marker_value not in seen:
                    seen.add(marker_value)
                    markers.append(marker_value)

    return markers


def _build_xmp_summary(sources: dict[str, dict[str, str]]) -> dict[str, object]:
    creator_tool: dict[str, str] = {}
    history_agent: dict[str, str] = {}
    metadata_date: dict[str, str] = {}
    toolkit: dict[str, str] = {}

    for source_name, source_fields in sources.items():
        if source_fields.get("xmp_creator_tool"):
            creator_tool[source_name] = source_fields["xmp_creator_tool"]
        if source_fields.get("xmp_history_software_agent"):
            history_agent[source_name] = source_fields["xmp_history_software_agent"]
        if source_fields.get("xmp_metadata_date"):
            metadata_date[source_name] = source_fields["xmp_metadata_date"]
        if source_fields.get("xmp_toolkit"):
            toolkit[source_name] = source_fields["xmp_toolkit"]

    present = bool(creator_tool or history_agent or metadata_date or toolkit)
    if not present:
        return {}

    return _drop_empty(
        {
            "present": True,
            "creator_tool": creator_tool,
            "history_software_agent": history_agent,
            "metadata_date": metadata_date,
            "toolkit": toolkit,
        }
    )


def _build_metadata_edit_timeline(
    sources: dict[str, dict[str, str]],
    editing_markers: list[str],
    xmp_summary: dict[str, object],
) -> dict[str, object] | None:
    recorded_values = {
        source_name: source_fields["recorded_at"]
        for source_name, source_fields in sources.items()
        if "recorded_at" in source_fields
    }
    modified_values = {
        source_name: source_fields["modified_at"]
        for source_name, source_fields in sources.items()
        if "modified_at" in source_fields
    }

    if not recorded_values or not modified_values:
        return None

    recorded_candidates = [_parse_metadata_timestamp(value) for value in recorded_values.values()]
    modified_candidates = [_parse_metadata_timestamp(value) for value in modified_values.values()]
    recorded_candidates = [value for value in recorded_candidates if value is not None]
    modified_candidates = [value for value in modified_candidates if value is not None]
    if not recorded_candidates or not modified_candidates:
        return None

    earliest_recorded = min(recorded_candidates)
    latest_modified = max(modified_candidates)
    if latest_modified <= earliest_recorded:
        return None

    if (latest_modified - earliest_recorded).total_seconds() <= 300:
        return None

    return {
        "status": "modified_after_recording",
        "recorded_at_utc": earliest_recorded.astimezone(UTC).isoformat(),
        "modified_at_utc": latest_modified.astimezone(UTC).isoformat(),
        "editing_markers_present": bool(editing_markers),
        "xmp_present": bool(isinstance(xmp_summary, dict) and xmp_summary.get("present")),
    }


def _device_identity(source_fields: dict[str, str]) -> str | None:
    source_device = source_fields.get("source_device")
    if source_device:
        return source_device
    device_make = source_fields.get("device_make")
    device_model = source_fields.get("device_model")
    if device_make or device_model:
        return " ".join(item for item in [device_make, device_model] if item)
    return None


def _normalize_key(value: str) -> str:
    return "".join(char for char in value.lower() if char.isalnum())


def _normalize_text(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().lower())


def _normalized_distinct_count(values: Any) -> int:
    normalized = {_normalize_text(value) for value in values if isinstance(value, str) and value.strip()}
    return len(normalized)


def _parse_metadata_timestamp(value: str) -> datetime | None:
    text = value.strip()
    if not text:
        return None

    normalized = text
    if len(text) >= 10 and text[4] == ":" and text[7] == ":":
        normalized = f"{text[0:4]}-{text[5:7]}-{text[8:]}"
    if len(normalized) >= 5 and normalized[-5] in {"+", "-"} and normalized[-3] != ":":
        normalized = f"{normalized[:-2]}:{normalized[-2:]}"
    normalized = normalized.replace("Z", "+00:00")

    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _parse_coordinates(value: str) -> tuple[float, float] | None:
    text = value.strip()
    if not text:
        return None

    iso6709_match = re.match(
        r"^(?P<lat>[+\-]\d{2}(?:\.\d+)?)(?P<lon>[+\-]\d{3}(?:\.\d+)?)(?P<alt>[+\-]\d+(?:\.\d+)?)?/?$",
        text,
    )
    if iso6709_match:
        try:
            return (
                float(iso6709_match.group("lat")),
                float(iso6709_match.group("lon")),
            )
        except ValueError:
            return None

    dms_match = re.match(
        r"^(?P<lat_deg>\d+)\s+deg\s+(?P<lat_min>\d+)'\s+(?P<lat_sec>[\d.]+)\"\s+(?P<lat_ref>[NS]),\s+"
        r"(?P<lon_deg>\d+)\s+deg\s+(?P<lon_min>\d+)'\s+(?P<lon_sec>[\d.]+)\"\s+(?P<lon_ref>[EW])",
        text,
    )
    if dms_match:
        lat = _dms_to_decimal(
            degrees=dms_match.group("lat_deg"),
            minutes=dms_match.group("lat_min"),
            seconds=dms_match.group("lat_sec"),
            hemisphere=dms_match.group("lat_ref"),
        )
        lon = _dms_to_decimal(
            degrees=dms_match.group("lon_deg"),
            minutes=dms_match.group("lon_min"),
            seconds=dms_match.group("lon_sec"),
            hemisphere=dms_match.group("lon_ref"),
        )
        if lat is not None and lon is not None:
            return lat, lon

    return None


def _dms_to_decimal(degrees: str, minutes: str, seconds: str, hemisphere: str) -> float | None:
    try:
        decimal = float(degrees) + float(minutes) / 60 + float(seconds) / 3600
    except ValueError:
        return None
    if hemisphere.upper() in {"S", "W"}:
        decimal *= -1
    return decimal


def _drop_empty(value: object) -> object:
    if isinstance(value, dict):
        cleaned: dict[str, object] = {}
        for key, item in value.items():
            compact_item = _drop_empty(item)
            if compact_item in ({}, [], "", None):
                continue
            cleaned[key] = compact_item
        return cleaned
    if isinstance(value, list):
        cleaned_list = [_drop_empty(item) for item in value]
        return [item for item in cleaned_list if item not in ({}, [], "", None)]
    return value
