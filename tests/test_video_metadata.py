from pathlib import Path

from media_security.extractors.video import (
    _build_video_exiftool_high_value,
    _build_hints_from_generic_tags,
    extract_video_metadata,
)


def test_extract_video_metadata_reads_ftyp_without_garbage(tmp_path: Path) -> None:
    video_file = tmp_path / "sample.mp4"
    # Valid ftyp box: size=24, type=ftyp, major=isom, minor=0x00000200, brands=isom+iso2
    video_file.write_bytes(b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isomiso2" + b"\x00" * 64)

    metadata = extract_video_metadata(video_file, expected_format="mp4")
    assert metadata["major_brand"] == "isom"
    assert metadata["compatible_brands"] == ["isom", "iso2"]


def test_build_hints_from_generic_tags() -> None:
    tags = {
        "com.apple.quicktime.make": "samsung",
        "com.apple.quicktime.model": "SM-S928B",
        "com.apple.quicktime.software": "One UI 6.1",
        "creation_time": "2026-04-01T10:00:00Z",
    }
    hints = _build_hints_from_generic_tags(tags)

    assert hints["device_make"] == "samsung"
    assert hints["device_model"] == "SM-S928B"
    assert hints["source_device"] == "samsung SM-S928B"
    assert hints["editing_software"] == "One UI 6.1"
    assert hints["recorded_at"] == "2026-04-01T10:00:00Z"


def test_extract_video_metadata_reads_embedded_udta_device_tags(tmp_path: Path) -> None:
    video_file = tmp_path / "samsung.mp4"

    def box(box_type: bytes, payload: bytes) -> bytes:
        return (len(payload) + 8).to_bytes(4, byteorder="big") + box_type + payload

    ftyp = box(b"ftyp", b"isom\x00\x00\x02\x00isomiso2")
    auth = box(b"auth", b"\x00\x00\x00\x00Galaxy S25 Ultra\x00")
    mdln = box(b"mdln", b"SM-S938B\x00")
    udta = box(b"udta", auth + mdln)
    moov = box(b"moov", udta)

    video_file.write_bytes(ftyp + moov)
    metadata = extract_video_metadata(video_file, expected_format="mp4")

    assert metadata["embedded_tags"]["udta.auth"] == "Galaxy S25 Ultra"
    assert metadata["embedded_tags"]["udta.mdln"] == "SM-S938B"
    assert metadata["source_device_hint"] == "Galaxy S25 Ultra (SM-S938B)"


def test_build_hints_for_android_version_not_as_editing_software() -> None:
    tags = {
        "udta.auth": "Galaxy S25 Ultra",
        "udta.mdln": "SM-S938B",
        "com.android.version": "16",
    }
    hints = _build_hints_from_generic_tags(tags)

    assert hints["device_make"] == "Samsung"
    assert hints["device_model"] == "SM-S938B"
    assert hints["source_device"] == "Galaxy S25 Ultra (SM-S938B)"
    assert hints["os_version"] == "16"
    assert "editing_software" not in hints


def test_build_video_exiftool_high_value_fields() -> None:
    tags = {
        "Author": "Galaxy S25 Ultra",
        "Samsung Model": "SM-S938B",
        "Android Version": "16",
        "Android Capture FPS": "120",
        "Android Time Zone": "+0300",
        "Create Date": "2026:04:01 10:52:28",
        "Duration": "10.65 s",
        "Image Width": "3840",
        "Image Height": "2160",
        "Video Frame Rate": "117.929",
        "Avg Bitrate": "96.1 Mbps",
        "Rotation": "90",
        "Compressor ID": "hvc1",
        "Audio Format": "mp4a",
        "Audio Channels": "2",
        "Audio Sample Rate": "48000",
        "Color Primaries": "BT.2020, BT.2100",
        "Transfer Characteristics": "BT.2100 HLG, ARIB STD-B67",
        "Matrix Coefficients": "BT.2020 non-constant luminance, BT.2100 YCbCr",
        "Video Full Range Flag": "Limited",
        "Zone Identifier": "Exists",
    }
    high_value = _build_video_exiftool_high_value(tags)

    assert high_value["source_device"] == "Galaxy S25 Ultra"
    assert high_value["device_model"] == "SM-S938B"
    assert high_value["os_version"] == "16"
    assert high_value["capture_fps"] == "120"
    assert high_value["device_timezone"] == "+0300"
    assert high_value["resolution"] == "3840x2160"
    assert high_value["rotation"] == "90"
    assert high_value["video_codec"] == "hvc1"
    assert high_value["audio_codec"] == "mp4a"
    assert high_value["downloaded_from_internet"] is True
