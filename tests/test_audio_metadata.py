from media_security.core.scanner import _advanced_metadata_tools_finding
from media_security.extractors.audio import (
    _build_audio_exiftool_high_value,
    _build_hints_from_generic_tags,
)


def test_build_hints_from_generic_audio_tags() -> None:
    tags = {
        "Make": "Samsung",
        "Model": "SM-S928B",
        "Software": "Voice Recorder 1.2",
        "Date": "2026-04-02T11:22:33Z",
        "Artist": "Field Mic",
    }
    hints = _build_hints_from_generic_tags(tags)

    assert hints["device_make"] == "Samsung"
    assert hints["device_model"] == "SM-S928B"
    assert hints["source_device"] == "Samsung SM-S928B"
    assert hints["editing_software"] == "Voice Recorder 1.2"
    assert hints["recorded_at"] == "2026-04-02T11:22:33Z"


def test_advanced_audio_metadata_unavailable_finding() -> None:
    finding = _advanced_metadata_tools_finding(
        file_format="mp3",
        technical={
            "ffprobe": {"available": False},
            "exiftool": {"available": False},
        },
    )

    assert finding is not None
    assert finding.code == "ADVANCED_AUDIO_METADATA_UNAVAILABLE"


def test_advanced_audio_metadata_finding_not_reported_when_tool_exists() -> None:
    finding = _advanced_metadata_tools_finding(
        file_format="wav",
        technical={
            "ffprobe": {"available": True},
            "exiftool": {"available": False},
        },
    )

    assert finding is None


def test_build_audio_exiftool_high_value_fields() -> None:
    tags = {
        "Title": "Ocean Drive",
        "Artist": "Duke Dumont",
        "Album": "Ocean Drive",
        "Year": "1970",
        "Comment": "(n) Converted by SpotiDownloader.com",
        "Track": "1/1",
        "Audio Bitrate": "320 kbps",
        "Sample Rate": "44100",
        "Channel Mode": "Stereo",
        "ID3 Size": "45862",
        "Date/Time Original": "1970",
        "Duration": "0:03:26 (approx)",
        "Picture MIME Type": "image/jpeg",
        "Picture Type": "Front Cover",
        "Zone Identifier": "Exists",
    }
    high_value = _build_audio_exiftool_high_value(tags)

    assert high_value["title"] == "Ocean Drive"
    assert high_value["artist"] == "Duke Dumont"
    assert high_value["audio_bitrate"] == "320 kbps"
    assert high_value["sample_rate"] == "44100"
    assert high_value["channel_mode"] == "Stereo"
    assert high_value["has_cover_art"] is True
    assert high_value["downloaded_from_internet"] is True
    assert high_value["download_source_marker"] == "possible_downloader_comment"
