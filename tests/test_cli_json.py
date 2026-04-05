from media_security.cli import _compact_metadata_for_json, _report_to_json_dict
from media_security.core.models import FileMetadata, Finding, ScanReport, Severity


def test_report_to_json_dict_for_unsupported_format_is_minimal() -> None:
    report = ScanReport(
        file=r"H:\Detection\AI-detection-in-music-and-video\datasets\misc\note.txt",
        supported=False,
        verdict="fail",
        findings=[
            Finding(
                code="UNSUPPORTED_EXTENSION",
                severity=Severity.HIGH,
                message="Unsupported extension '.txt'.",
            )
        ],
    )

    payload = _report_to_json_dict(report)

    assert payload == {
        "path": r"H:\Detection\AI-detection-in-music-and-video\datasets\misc\note.txt",
        "supported": False,
        "message": "unsupported format",
    }


def test_compact_metadata_for_json_removes_repeated_values() -> None:
    metadata = FileMetadata(
        path=r"H:\Detection\AI-detection-in-music-and-video\datasets\external\FloreView\D02_L3S3C4_b.mov",
        name="D02_L3S3C4_b.mov",
        extension="mov",
        media_type="video",
        detected_format="mov",
        size_bytes=24510521,
        mime_type="video/quicktime",
        hashes={"sha256": "a", "md5": "b"},
        timestamps_utc={
            "created_at": "2026-04-05T16:41:02.666236+00:00",
            "modified_at": "2026-04-05T16:41:52.900321+00:00",
            "accessed_at": "2026-04-05T20:01:27.367598+00:00",
        },
        signature={"container": "ISO-BMFF", "major_brand": "qt  "},
        technical={
            "major_brand": "qt  ",
            "metadata_hints": {
                "device_make": "Apple",
                "device_model": "iPhone X",
                "source_device": "Apple iPhone X",
                "editing_software": "15.5",
                "recorded_at": "2022:05:20 08:41:04",
                "location": "+43.7694+011.2555+048.329/",
            },
            "source_device_hint": "Apple iPhone X",
            "source_device_hint_source": "ffprobe",
            "editing_software_hint": "15.5",
            "editing_software_hint_source": "ffprobe",
            "recorded_at_hint": "2022:05:20 08:41:04",
            "ffprobe": {
                "available": True,
                "duration_sec": 25.093333,
                "avg_frame_rate": 30.006,
                "width": 1920,
                "height": 1080,
                "video_codecs": ["hvc1"],
                "audio_codecs": ["mp4a"],
                "format_tags": {"creation_time": "2022-05-20T08:41:04.000000Z"},
                "stream_tags": {"0": {"creation_time": "2022-05-20T08:41:04.000000Z"}},
            },
            "exiftool": {
                "available": True,
                "tags": {"Make": "Apple"},
                "high_value": {
                    "source_device": "Apple iPhone X",
                    "device_make": "Apple",
                    "device_model": "iPhone X",
                    "software_version": "15.5",
                    "recorded_at": "2022:05:20 10:41:04+02:00",
                    "duration": "25.09 s",
                    "capture_fps": "30.006",
                    "resolution": "1920x1080",
                    "video_codec": "hvc1",
                    "audio_codec": "mp4a",
                    "gps_coordinates": "43 deg 46' 9.84\" N, 11 deg 15' 19.80\" E, 48.329 m Above Sea Level",
                    "gps_latitude": "43 deg 46' 9.84\" N",
                    "gps_longitude": "11 deg 15' 19.80\" E",
                    "gps_altitude": "48.329 m",
                    "zone_identifier": "Exists",
                    "downloaded_from_internet": True,
                },
            },
        },
    )

    compact = _compact_metadata_for_json(
        report_path=metadata.path,
        metadata_dict=metadata.to_dict(),
    )

    technical = compact["technical"]
    hints = technical["metadata_hints"]
    ffprobe = technical["ffprobe"]
    exiftool = technical["exiftool"]
    high_value = exiftool["high_value"]

    assert "name" not in compact
    assert "extension" not in compact
    assert "detected_format" not in compact
    assert "major_brand" not in technical
    assert "source_device_hint" not in technical
    assert "editing_software_hint" not in technical
    assert "recorded_at_hint" not in technical

    assert hints == {
        "source_device": "Apple iPhone X",
        "editing_software": "15.5",
        "recorded_at": "2022:05:20 08:41:04",
        "location": "+43.7694+011.2555+048.329/",
    }

    assert "format_tags" not in ffprobe
    assert "stream_tags" not in ffprobe

    assert "tags" not in exiftool
    assert "source_device" not in high_value
    assert "device_make" not in high_value
    assert "device_model" not in high_value
    assert "software_version" not in high_value
    assert "recorded_at" not in high_value
    assert "duration" not in high_value
    assert "capture_fps" not in high_value
    assert "resolution" not in high_value
    assert "video_codec" not in high_value
    assert "audio_codec" not in high_value
    assert "gps_latitude" not in high_value
    assert "gps_longitude" not in high_value
    assert "gps_altitude" not in high_value
    assert high_value["gps_coordinates"].startswith("43 deg 46'")
    assert high_value["zone_identifier"] == "Exists"
    assert high_value["downloaded_from_internet"] is True
