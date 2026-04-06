from __future__ import annotations

import json
import subprocess
import wave
from pathlib import Path
from typing import Any

from media_security.core.constants import MAX_MP3_SCAN_BYTES
from media_security.external_tools import resolve_external_tool

BITRATE_TABLE = {
    ("1", "I"): [
        0,
        32,
        64,
        96,
        128,
        160,
        192,
        224,
        256,
        288,
        320,
        352,
        384,
        416,
        448,
    ],
    ("1", "II"): [
        0,
        32,
        48,
        56,
        64,
        80,
        96,
        112,
        128,
        160,
        192,
        224,
        256,
        320,
        384,
    ],
    ("1", "III"): [
        0,
        32,
        40,
        48,
        56,
        64,
        80,
        96,
        112,
        128,
        160,
        192,
        224,
        256,
        320,
    ],
    ("2", "I"): [
        0,
        32,
        48,
        56,
        64,
        80,
        96,
        112,
        128,
        144,
        160,
        176,
        192,
        224,
        256,
    ],
    ("2", "II"): [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160],
    ("2", "III"): [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160],
    ("2.5", "I"): [
        0,
        32,
        48,
        56,
        64,
        80,
        96,
        112,
        128,
        144,
        160,
        176,
        192,
        224,
        256,
    ],
    ("2.5", "II"): [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160],
    ("2.5", "III"): [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160],
}

SAMPLE_RATE_TABLE = {
    "1": [44100, 48000, 32000],
    "2": [22050, 24000, 16000],
    "2.5": [11025, 12000, 8000],
}

MPEG_VERSION_MAP = {0b00: "2.5", 0b01: None, 0b10: "2", 0b11: "1"}
LAYER_MAP = {0b01: "III", 0b10: "II", 0b11: "I"}
CHANNEL_MODE_MAP = {
    0b00: "stereo",
    0b01: "joint_stereo",
    0b10: "dual_channel",
    0b11: "single_channel",
}

ID3_TEXT_ENCODING_MAP = {
    0: "latin1",
    1: "utf-16",
    2: "utf-16-be",
    3: "utf-8",
}

ID3_TEXT_FRAME_MAP = {
    "TPE1": "artist",
    "TIT2": "title",
    "TALB": "album",
    "TENC": "encoded_by",
    "TSSE": "encoding_settings",
    "TDRC": "recording_time",
    "TCON": "genre",
}

AUDIO_FFPROBE_TAG_KEYS = {
    "creation_time",
    "artist",
    "title",
    "album",
    "album_artist",
    "genre",
    "date",
    "comment",
    "track",
    "encoder",
    "encoded_by",
    "encoding_tool",
    "software",
    "make",
    "model",
    "com.apple.quicktime.make",
    "com.apple.quicktime.model",
    "com.apple.quicktime.software",
    "com.apple.quicktime.creationdate",
}

AUDIO_EXIFTOOL_TAG_KEYS = {
    "Title",
    "Artist",
    "Album",
    "Genre",
    "Track",
    "Year",
    "DateTimeOriginal",
    "CreateDate",
    "ModifyDate",
    "Duration",
    "AudioBitrate",
    "SampleRate",
    "AudioSampleRate",
    "ChannelMode",
    "AudioChannels",
    "AudioBitsPerSample",
    "MPEGAudioVersion",
    "AudioLayer",
    "Comment",
    "Software",
    "Encoder",
    "EncodedBy",
    "EncodingTool",
    "Make",
    "Model",
    "AndroidVersion",
    "ZoneIdentifier",
    "ID3Size",
    "PictureMIMEType",
    "PictureType",
    "GPSCoordinates",
    "GPSPosition",
    "GPSLatitude",
    "GPSLongitude",
    "XMPToolkit",
    "CreatorTool",
    "HistorySoftwareAgent",
    "MetadataDate",
}

AUDIO_STREAM_TAG_KEYS = {"creation_time", "language", "handler_name", "encoder", "title", "artist", "album"}


def extract_wav_metadata(path: Path) -> dict[str, Any]:
    with wave.open(str(path), "rb") as wav_file:
        channels = wav_file.getnchannels()
        sample_rate = wav_file.getframerate()
        frame_count = wav_file.getnframes()
        sample_width_bytes = wav_file.getsampwidth()
        duration_seconds = frame_count / sample_rate if sample_rate else 0.0
        metadata = {
            "codec": "PCM" if wav_file.getcomptype() == "NONE" else wav_file.getcomptype(),
            "sample_rate_hz": sample_rate,
            "channels": channels,
            "sample_width_bytes": sample_width_bytes,
            "bits_per_sample": sample_width_bytes * 8,
            "frame_count": frame_count,
            "duration_sec": round(duration_seconds, 3),
            "compression_name": wav_file.getcompname(),
        }

    info_tags = _extract_riff_info_tags(path)
    if info_tags:
        metadata["info_tags"] = info_tags
        hints: dict[str, str] = {}
        if "ISFT" in info_tags:
            hints["editing_software"] = info_tags["ISFT"]
        if "IART" in info_tags:
            hints["source_device"] = info_tags["IART"]
        if "ICRD" in info_tags:
            hints["recorded_at"] = info_tags["ICRD"]
        _merge_hints(metadata, hints)

    ffprobe_summary = _extract_ffprobe_summary(path)
    if ffprobe_summary:
        metadata["ffprobe"] = ffprobe_summary
        _merge_hints(metadata, _build_hints_from_ffprobe(ffprobe_summary))

    exiftool_summary = _extract_exiftool_summary(path)
    if exiftool_summary:
        metadata["exiftool"] = exiftool_summary
        _merge_hints(metadata, _build_hints_from_exiftool(exiftool_summary))

    return metadata


def extract_mp3_metadata(path: Path) -> dict[str, Any]:
    file_size = path.stat().st_size
    with path.open("rb") as file_obj:
        data = file_obj.read(min(file_size, MAX_MP3_SCAN_BYTES))

    metadata: dict[str, Any] = {
        "id3v2_present": False,
        "id3v1_present": False,
    }

    id3_payload_start = 0
    if len(data) >= 10 and data.startswith(b"ID3"):
        version_major = data[3]
        id3_size = _synchsafe_to_int(data[6:10])
        metadata["id3v2_present"] = True
        metadata["id3v2_version"] = f"2.{data[3]}.{data[4]}"
        metadata["id3v2_size_bytes"] = id3_size
        id3_payload_start = 10 + id3_size

        tag_payload = data[10 : min(len(data), 10 + id3_size)]
        text_frames = _extract_id3_text_frames(tag_payload, version_major)
        if text_frames:
            metadata["id3v2_text_frames"] = text_frames
            hints: dict[str, str] = {}
            if "encoded_by" in text_frames:
                hints["editing_software"] = text_frames["encoded_by"]
            elif "encoding_settings" in text_frames:
                hints["editing_software"] = text_frames["encoding_settings"]
            if "artist" in text_frames:
                hints["source_device"] = text_frames["artist"]
            if "recording_time" in text_frames:
                hints["recorded_at"] = text_frames["recording_time"]
            _merge_hints(metadata, hints)

    if file_size >= 128:
        with path.open("rb") as file_obj:
            file_obj.seek(-128, 2)
            metadata["id3v1_present"] = file_obj.read(3) == b"TAG"

    frame_info = _find_first_mp3_frame(data, start_offset=id3_payload_start)
    if frame_info:
        metadata.update(frame_info)
        bitrate_kbps = frame_info.get("bitrate_kbps")
        if bitrate_kbps:
            data_bytes = max(file_size - id3_payload_start, 1)
            metadata["estimated_duration_sec"] = round((data_bytes * 8) / (bitrate_kbps * 1000), 3)

    ffprobe_summary = _extract_ffprobe_summary(path)
    if ffprobe_summary:
        metadata["ffprobe"] = ffprobe_summary
        _merge_hints(metadata, _build_hints_from_ffprobe(ffprobe_summary))

    exiftool_summary = _extract_exiftool_summary(path)
    if exiftool_summary:
        metadata["exiftool"] = exiftool_summary
        _merge_hints(metadata, _build_hints_from_exiftool(exiftool_summary))

    return metadata


def _find_first_mp3_frame(data: bytes, start_offset: int = 0) -> dict[str, Any] | None:
    if len(data) < 4:
        return None
    max_scan_end = min(len(data) - 4, start_offset + 32768)
    for offset in range(start_offset, max_scan_end):
        if data[offset] == 0xFF and (data[offset + 1] & 0xE0) == 0xE0:
            parsed = _parse_mp3_frame_header(data[offset : offset + 4])
            if parsed:
                parsed["frame_offset"] = offset
                return parsed
    return None


def _parse_mp3_frame_header(header: bytes) -> dict[str, Any] | None:
    if len(header) < 4:
        return None

    header_value = int.from_bytes(header, byteorder="big")
    sync = (header_value >> 21) & 0x7FF
    if sync != 0x7FF:
        return None

    version_bits = (header_value >> 19) & 0b11
    layer_bits = (header_value >> 17) & 0b11
    bitrate_index = (header_value >> 12) & 0b1111
    sample_rate_index = (header_value >> 10) & 0b11
    channel_mode_bits = (header_value >> 6) & 0b11

    version = MPEG_VERSION_MAP.get(version_bits)
    layer = LAYER_MAP.get(layer_bits)
    if version is None or layer is None:
        return None
    if bitrate_index in (0, 15) or sample_rate_index == 0b11:
        return None

    bitrate_list = BITRATE_TABLE.get((version, layer))
    sample_rate_list = SAMPLE_RATE_TABLE.get(version)
    if not bitrate_list or not sample_rate_list:
        return None

    bitrate_kbps = bitrate_list[bitrate_index]
    sample_rate_hz = sample_rate_list[sample_rate_index]
    if bitrate_kbps <= 0 or sample_rate_hz <= 0:
        return None

    return {
        "mpeg_version": version,
        "layer": layer,
        "bitrate_kbps": bitrate_kbps,
        "sample_rate_hz": sample_rate_hz,
        "channel_mode": CHANNEL_MODE_MAP[channel_mode_bits],
    }


def _extract_riff_info_tags(path: Path) -> dict[str, str]:
    tags: dict[str, str] = {}
    with path.open("rb") as file_obj:
        header = file_obj.read(12)
        if len(header) < 12 or header[0:4] != b"RIFF" or header[8:12] != b"WAVE":
            return tags

        while True:
            chunk_header = file_obj.read(8)
            if len(chunk_header) < 8:
                break
            chunk_id = chunk_header[0:4]
            chunk_size = int.from_bytes(chunk_header[4:8], byteorder="little")
            chunk_data = file_obj.read(chunk_size)
            if len(chunk_data) < chunk_size:
                break
            if chunk_size % 2 == 1:
                file_obj.read(1)

            if chunk_id != b"LIST" or len(chunk_data) < 4 or chunk_data[0:4] != b"INFO":
                continue

            info_data = chunk_data[4:]
            offset = 0
            while offset + 8 <= len(info_data):
                tag_id_bytes = info_data[offset : offset + 4]
                tag_size = int.from_bytes(info_data[offset + 4 : offset + 8], byteorder="little")
                offset += 8
                if tag_size < 0:
                    break
                if offset + tag_size > len(info_data):
                    break
                raw_value = info_data[offset : offset + tag_size]
                offset += tag_size
                if tag_size % 2 == 1:
                    offset += 1

                tag_id = tag_id_bytes.decode("ascii", errors="ignore").strip()
                value = raw_value.rstrip(b"\x00").decode("utf-8", errors="replace").strip()
                if tag_id and value:
                    tags[tag_id] = value

    return tags


def _extract_id3_text_frames(tag_payload: bytes, version_major: int) -> dict[str, str]:
    frames: dict[str, str] = {}
    offset = 0
    while offset + 10 <= len(tag_payload):
        frame_id_bytes = tag_payload[offset : offset + 4]
        if frame_id_bytes == b"\x00\x00\x00\x00":
            break

        frame_id = frame_id_bytes.decode("ascii", errors="ignore")
        if len(frame_id) != 4:
            break

        size_bytes = tag_payload[offset + 4 : offset + 8]
        if version_major == 4:
            frame_size = _synchsafe_to_int(size_bytes)
        else:
            frame_size = int.from_bytes(size_bytes, byteorder="big")
        if frame_size <= 0:
            break

        frame_content_start = offset + 10
        frame_content_end = frame_content_start + frame_size
        if frame_content_end > len(tag_payload):
            break

        frame_content = tag_payload[frame_content_start:frame_content_end]
        if frame_id.startswith("T") and frame_id != "TXXX":
            text = _decode_id3_text_content(frame_content)
            if text:
                key = ID3_TEXT_FRAME_MAP.get(frame_id, frame_id.lower())
                frames[key] = text

        offset = frame_content_end

    return frames


def _decode_id3_text_content(content: bytes) -> str:
    if not content:
        return ""
    encoding_byte = content[0]
    raw_text = content[1:]
    codec = ID3_TEXT_ENCODING_MAP.get(encoding_byte, "latin1")
    try:
        decoded = raw_text.decode(codec, errors="replace")
    except LookupError:
        decoded = raw_text.decode("latin1", errors="replace")
    return decoded.rstrip("\x00").strip()


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
    audio_streams = [item for item in streams if item.get("codec_type") == "audio"]
    format_tags = _select_audio_ffprobe_tags(_to_string_dict(format_block.get("tags")))
    stream_tags = _collect_stream_tags(
        streams,
        include_keys=AUDIO_STREAM_TAG_KEYS,
        max_streams=2,
    )

    return {
        "available": True,
        "format_name": format_block.get("format_name"),
        "duration_sec": _as_float(format_block.get("duration")),
        "bit_rate": _as_int(format_block.get("bit_rate")),
        "stream_count": len(streams),
        "audio_stream_count": len(audio_streams),
        "audio_codecs": sorted({stream.get("codec_name") for stream in audio_streams if stream.get("codec_name")}),
        "sample_rates_hz": sorted(
            {
                _as_int(stream.get("sample_rate"))
                for stream in audio_streams
                if _as_int(stream.get("sample_rate")) is not None
            }
        ),
        "channel_layouts": sorted(
            {str(stream.get("channel_layout")) for stream in audio_streams if stream.get("channel_layout")}
        ),
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
    selected_tags = _select_audio_exiftool_tags(normalized_tags)
    return {
        "available": True,
        "tags": selected_tags,
        "high_value": _build_audio_exiftool_high_value(selected_tags),
    }


def _select_audio_ffprobe_tags(tags: dict[str, str]) -> dict[str, str]:
    return _select_metadata_tags(tags, AUDIO_FFPROBE_TAG_KEYS)


def _select_audio_exiftool_tags(tags: dict[str, str]) -> dict[str, str]:
    return _select_metadata_tags(tags, AUDIO_EXIFTOOL_TAG_KEYS)


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
    exif_model = _first_non_empty(tags, ["Model"])
    exif_software = _first_non_empty(tags, ["Software", "Encoder", "EncodedBy"])
    exif_datetime = _first_non_empty(tags, ["CreateDate", "MediaCreateDate", "Date/Time Original", "DateTimeOriginal"])
    exif_artist = _first_non_empty(tags, ["Artist"])
    exif_os_version = _first_non_empty(tags, ["AndroidVersion"])

    if exif_make:
        hints.setdefault("device_make", exif_make)
    if exif_model:
        hints.setdefault("device_model", exif_model)
    if exif_software:
        hints.setdefault("editing_software", exif_software)
    if exif_datetime:
        hints.setdefault("recorded_at", exif_datetime)
    if exif_artist:
        hints.setdefault("content_author", exif_artist)
    if exif_os_version:
        hints.setdefault("os_version", exif_os_version)
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
        ]
    )
    device_model = by_candidates(
        [
            "com.apple.quicktime.model",
            "model",
            "device_model",
            "com.android.model",
        ]
    )
    editing_software = by_candidates(
        [
            "software",
            "encoder",
            "encoded_by",
            "encoding_tool",
            "tsse",
            "com.apple.quicktime.software",
        ]
    )
    recorded_at = by_candidates(
        [
            "creation_time",
            "create date",
            "date/time original",
            "date",
            "tdrc",
            "recording_time",
            "com.apple.quicktime.creationdate",
        ]
    )
    content_author = by_candidates(
        [
            "artist",
            "album_artist",
            "performer",
            "tpe1",
        ]
    )
    os_version = by_candidates(
        [
            "android version",
            "android_version",
            "androidversion",
            "os_version",
        ]
    )

    hints: dict[str, str] = {}
    if device_make:
        hints["device_make"] = device_make
    if device_model:
        hints["device_model"] = device_model
    if device_make or device_model:
        hints["source_device"] = " ".join(item for item in [device_make, device_model] if item)
    elif content_author:
        hints["source_device"] = content_author
    if editing_software:
        hints["editing_software"] = editing_software
    if recorded_at:
        hints["recorded_at"] = recorded_at
    if content_author:
        hints["content_author"] = content_author
    if os_version:
        hints["os_version"] = os_version
    return hints


def _merge_hints(metadata: dict[str, Any], hints: dict[str, str]) -> None:
    if not hints:
        return
    existing = metadata.get("metadata_hints", {})
    if not isinstance(existing, dict):
        existing = {}
    for key, value in hints.items():
        existing.setdefault(key, value)
    metadata["metadata_hints"] = existing

    if "source_device" in existing:
        metadata.setdefault("source_device_hint", existing["source_device"])
    if "editing_software" in existing:
        metadata.setdefault("editing_software_hint", existing["editing_software"])
    if "recorded_at" in existing:
        metadata.setdefault("recorded_at_hint", existing["recorded_at"])


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


def _build_audio_exiftool_high_value(tags: dict[str, str]) -> dict[str, str | bool]:
    high_value: dict[str, str | bool] = {}

    title = _pick_case_insensitive(tags, ["Title"])
    artist = _pick_case_insensitive(tags, ["Artist"])
    album = _pick_case_insensitive(tags, ["Album"])
    year = _pick_case_insensitive(tags, ["Year"])
    source_make = _pick_case_insensitive(tags, ["Make"])
    source_model = _pick_case_insensitive(tags, ["Model"])
    os_version = _pick_case_insensitive(tags, ["AndroidVersion"])
    software_version = _pick_case_insensitive(tags, ["Software"])
    duration = _pick_case_insensitive(tags, ["Duration"])
    bitrate = _pick_case_insensitive(tags, ["Audio Bitrate"])
    sample_rate = _pick_case_insensitive(tags, ["Sample Rate", "Audio Sample Rate"])
    channel_mode = _pick_case_insensitive(tags, ["Channel Mode", "AudioChannels"])
    comment = _pick_case_insensitive(tags, ["Comment"])
    date_original = _pick_case_insensitive(tags, ["Date/Time Original", "DateTimeOriginal", "CreateDate"])
    modify_date = _pick_case_insensitive(tags, ["ModifyDate"])
    track = _pick_case_insensitive(tags, ["Track"])
    id3_size = _pick_case_insensitive(tags, ["ID3 Size"])
    zone_identifier = _pick_case_insensitive(tags, ["Zone Identifier"])
    picture_mime = _pick_case_insensitive(tags, ["Picture MIME Type"])
    picture_type = _pick_case_insensitive(tags, ["Picture Type"])
    gps_coordinates = _pick_case_insensitive(tags, ["GPSCoordinates", "GPSPosition"])
    gps_latitude = _pick_case_insensitive(tags, ["GPSLatitude"])
    gps_longitude = _pick_case_insensitive(tags, ["GPSLongitude"])

    source_device = " ".join(item for item in [source_make, source_model] if item)

    if title:
        high_value["title"] = title
    if artist:
        high_value["artist"] = artist
    if album:
        high_value["album"] = album
    if year:
        high_value["year"] = year
    if track:
        high_value["track"] = track
    if source_device:
        high_value["source_device"] = source_device
    if source_make:
        high_value["device_make"] = source_make
    if source_model:
        high_value["device_model"] = source_model
    if os_version:
        high_value["os_version"] = os_version
    if software_version:
        high_value["software_version"] = software_version
    if date_original:
        high_value["recorded_at"] = date_original
    if modify_date:
        high_value["modified_at"] = modify_date
    if duration:
        high_value["duration"] = duration
    if bitrate:
        high_value["audio_bitrate"] = bitrate
    if sample_rate:
        high_value["sample_rate"] = sample_rate
    if channel_mode:
        high_value["channel_mode"] = channel_mode
    if id3_size:
        high_value["id3_size"] = id3_size
    if comment:
        high_value["comment"] = comment
    if gps_coordinates:
        high_value["gps_coordinates"] = gps_coordinates
    if gps_latitude:
        high_value["gps_latitude"] = gps_latitude
    if gps_longitude:
        high_value["gps_longitude"] = gps_longitude
    if picture_mime:
        high_value["cover_art_mime"] = picture_mime
    if picture_type:
        high_value["cover_art_type"] = picture_type
    if picture_mime or picture_type:
        high_value["has_cover_art"] = True
    if zone_identifier:
        high_value["zone_identifier"] = zone_identifier
        high_value["downloaded_from_internet"] = zone_identifier.strip().lower() == "exists"

    if _contains_downloader_marker(comment):
        high_value["download_source_marker"] = "possible_downloader_comment"
    return high_value


def _contains_downloader_marker(comment: str | None) -> bool:
    if not comment:
        return False
    normalized = comment.lower()
    markers = [
        "spotidownloader",
        "converted by",
        "youtube",
        "yt-dlp",
    ]
    return any(marker in normalized for marker in markers)


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


def _synchsafe_to_int(value: bytes) -> int:
    if len(value) != 4:
        return 0
    return (value[0] << 21) | (value[1] << 14) | (value[2] << 7) | value[3]
