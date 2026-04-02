from __future__ import annotations

import wave
from pathlib import Path
from typing import Any

from media_security.constants import MAX_MP3_SCAN_BYTES

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


def extract_wav_metadata(path: Path) -> dict[str, Any]:
    with wave.open(str(path), "rb") as wav_file:
        channels = wav_file.getnchannels()
        sample_rate = wav_file.getframerate()
        frame_count = wav_file.getnframes()
        sample_width_bytes = wav_file.getsampwidth()
        duration_seconds = frame_count / sample_rate if sample_rate else 0.0
        return {
            "codec": "PCM" if wav_file.getcomptype() == "NONE" else wav_file.getcomptype(),
            "sample_rate_hz": sample_rate,
            "channels": channels,
            "sample_width_bytes": sample_width_bytes,
            "bits_per_sample": sample_width_bytes * 8,
            "frame_count": frame_count,
            "duration_sec": round(duration_seconds, 3),
            "compression_name": wav_file.getcompname(),
        }


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
        id3_size = _synchsafe_to_int(data[6:10])
        metadata["id3v2_present"] = True
        metadata["id3v2_version"] = f"2.{data[3]}.{data[4]}"
        metadata["id3v2_size_bytes"] = id3_size
        id3_payload_start = 10 + id3_size

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


def _synchsafe_to_int(value: bytes) -> int:
    if len(value) != 4:
        return 0
    return (value[0] << 21) | (value[1] << 14) | (value[2] << 7) | value[3]
