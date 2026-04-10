from __future__ import annotations

import math
import subprocess
import wave
from pathlib import Path

import pytest

from media_security.core.scanner import MediaSecurityScanner
from media_security.core.splice_forensics import (
    _correlate_video_and_audio_track,
    _merge_candidates,
    _should_flag_modality,
    analyze_splice_forensics,
)
from media_security.external_tools import resolve_external_tool


def test_merge_candidates_combines_close_events() -> None:
    merged = _merge_candidates(
        [
            {
                "timestamp_sec": 1.00,
                "confidence": 0.68,
                "window_sec": 0.04,
                "signals": {"energy_jump": 0.7},
                "source": "audio",
            },
            {
                "timestamp_sec": 1.18,
                "confidence": 0.82,
                "window_sec": 0.04,
                "signals": {"noise_floor_shift": 0.9},
                "source": "audio",
            },
            {
                "timestamp_sec": 2.10,
                "confidence": 0.77,
                "window_sec": 0.04,
                "signals": {"silence_gap": 1.0},
                "source": "audio",
            },
        ],
        max_gap_sec=0.25,
    )

    assert len(merged) == 2
    assert merged[0]["timestamp_sec"] == 1.18
    assert merged[0]["confidence"] == 0.82
    assert merged[0]["signals"]["energy_jump"] == 0.7
    assert merged[0]["signals"]["noise_floor_shift"] == 0.9


def test_warning_threshold_requires_high_or_multiple_candidates() -> None:
    assert _should_flag_modality({"candidates": [{"confidence": 0.76}]})
    assert _should_flag_modality({"candidates": [{"confidence": 0.66}, {"confidence": 0.70}]})
    assert not _should_flag_modality({"candidates": [{"confidence": 0.66}]})


def test_correlation_boosts_video_candidate_and_records_match() -> None:
    video = {
        "status": "suspicious",
        "candidate_count": 1,
        "peak_confidence": 0.72,
        "candidates": [
            {
                "timestamp_sec": 1.00,
                "confidence": 0.72,
                "window_sec": 0.25,
                "signals": {"scene_score": 0.9},
                "source": "video",
            }
        ],
    }
    audio_track = {
        "status": "suspicious",
        "candidate_count": 1,
        "peak_confidence": 0.80,
        "candidates": [
            {
                "timestamp_sec": 1.12,
                "confidence": 0.80,
                "window_sec": 0.04,
                "signals": {"energy_jump": 0.9},
                "source": "video_audio_track",
            }
        ],
    }

    correlation = _correlate_video_and_audio_track(video, audio_track)

    assert correlation is not None
    assert correlation["status"] == "aligned"
    assert correlation["match_count"] == 1
    assert video["candidates"][0]["aligned_audio_track"] is True
    assert video["candidates"][0]["confidence"] == 0.82


def test_splice_analysis_reports_unavailable_without_ffmpeg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    audio_path = tmp_path / "sample.wav"
    _create_tone_wav(audio_path, segments=[(440.0, 0.5)])
    technical: dict[str, object] = {}

    monkeypatch.setattr("media_security.core.splice_forensics.get_external_tool_info", lambda _name: _DummyToolInfo())

    findings = analyze_splice_forensics(audio_path, "wav", "audio", technical)

    assert technical["splice_analysis"]["status"] == "unavailable"
    assert findings[0].code == "SPLICE_ANALYSIS_UNAVAILABLE"


@pytest.mark.skipif(resolve_external_tool("ffmpeg") is None, reason="ffmpeg is required for splice integration tests")
def test_scanner_detects_audio_splice_in_wav(tmp_path: Path) -> None:
    audio_path = tmp_path / "spliced.wav"
    _create_tone_wav(audio_path, segments=[(440.0, 0.8), (0.0, 0.06), (880.0, 0.8)])

    report = MediaSecurityScanner().scan_file(audio_path)
    codes = {finding.code for finding in report.findings}

    assert "AUDIO_SPLICE_SUSPECTED" in codes
    splice = report.metadata.technical["splice_analysis"]
    assert splice["audio"]["candidate_count"] >= 1


@pytest.mark.skipif(resolve_external_tool("ffmpeg") is None, reason="ffmpeg is required for splice integration tests")
def test_scanner_detects_audio_splice_in_mp3(tmp_path: Path) -> None:
    wav_path = tmp_path / "spliced_source.wav"
    mp3_path = tmp_path / "spliced.mp3"
    _create_tone_wav(wav_path, segments=[(440.0, 0.8), (0.0, 0.06), (880.0, 0.8)])
    _run_ffmpeg(["-y", "-v", "error", "-i", str(wav_path), str(mp3_path)])

    report = MediaSecurityScanner().scan_file(mp3_path)
    codes = {finding.code for finding in report.findings}

    assert "AUDIO_SPLICE_SUSPECTED" in codes
    assert report.metadata.technical["splice_analysis"]["audio"]["candidate_count"] >= 1


@pytest.mark.skipif(resolve_external_tool("ffmpeg") is None, reason="ffmpeg is required for splice integration tests")
def test_scanner_detects_video_seam_and_audio_alignment(tmp_path: Path) -> None:
    video_path = tmp_path / "video_seam.mp4"
    _run_ffmpeg(
        [
            "-y",
            "-v",
            "error",
            "-f",
            "lavfi",
            "-i",
            "color=c=red:s=320x240:d=0.7:r=24",
            "-f",
            "lavfi",
            "-i",
            "color=c=black:s=320x240:d=0.1:r=24",
            "-f",
            "lavfi",
            "-i",
            "color=c=blue:s=320x240:d=0.7:r=24",
            "-f",
            "lavfi",
            "-i",
            "sine=frequency=440:duration=0.7",
            "-f",
            "lavfi",
            "-i",
            "anullsrc=r=44100:cl=mono:d=0.1",
            "-f",
            "lavfi",
            "-i",
            "sine=frequency=880:duration=0.7",
            "-filter_complex",
            "[0:v][1:v][2:v]concat=n=3:v=1:a=0[v];[3:a][4:a][5:a]concat=n=3:v=0:a=1[a]",
            "-map",
            "[v]",
            "-map",
            "[a]",
            "-shortest",
            str(video_path),
        ]
    )

    report = MediaSecurityScanner().scan_file(video_path)
    codes = {finding.code for finding in report.findings}

    assert "VIDEO_SEAM_SUSPECTED" in codes
    assert "VIDEO_AUDIO_TRACK_SPLICE_SUSPECTED" in codes
    assert "VIDEO_AUDIO_SEAM_ALIGNMENT" in codes
    assert report.metadata.technical["splice_analysis"]["correlation"]["match_count"] >= 1


@pytest.mark.skipif(resolve_external_tool("ffmpeg") is None, reason="ffmpeg is required for splice integration tests")
def test_scanner_detects_splice_only_in_video_audio_track(tmp_path: Path) -> None:
    video_path = tmp_path / "audio_only_seam.mp4"
    _run_ffmpeg(
        [
            "-y",
            "-v",
            "error",
            "-f",
            "lavfi",
            "-i",
            "color=c=green:s=320x240:d=1.7:r=24",
            "-f",
            "lavfi",
            "-i",
            "sine=frequency=440:duration=0.8",
            "-f",
            "lavfi",
            "-i",
            "anullsrc=r=44100:cl=mono:d=0.08",
            "-f",
            "lavfi",
            "-i",
            "sine=frequency=880:duration=0.8",
            "-filter_complex",
            "[1:a][2:a][3:a]concat=n=3:v=0:a=1[a]",
            "-map",
            "0:v",
            "-map",
            "[a]",
            "-shortest",
            str(video_path),
        ]
    )

    report = MediaSecurityScanner().scan_file(video_path)
    codes = {finding.code for finding in report.findings}

    assert "VIDEO_AUDIO_TRACK_SPLICE_SUSPECTED" in codes
    assert "VIDEO_SEAM_SUSPECTED" not in codes
    splice = report.metadata.technical["splice_analysis"]
    assert splice["video"]["candidate_count"] == 0
    assert splice["video_audio_track"]["candidate_count"] >= 1


@pytest.mark.skipif(resolve_external_tool("ffmpeg") is None, reason="ffmpeg is required for splice integration tests")
def test_video_audio_track_reports_unavailable_when_stream_is_missing(tmp_path: Path) -> None:
    video_path = tmp_path / "silent_video.mp4"
    _run_ffmpeg(["-y", "-v", "error", "-f", "lavfi", "-i", "color=c=yellow:s=320x240:d=1.2:r=24", str(video_path)])

    report = MediaSecurityScanner().scan_file(video_path)
    splice = report.metadata.technical["splice_analysis"]

    assert splice["video_audio_track"]["status"] == "unavailable"
    assert splice["video_audio_track"]["reason"] == "no_audio_stream"


def _create_tone_wav(path: Path, segments: list[tuple[float, float]]) -> None:
    sample_rate = 16_000
    with wave.open(str(path), "wb") as wav_file:
        wav_file.setnchannels(1)
        wav_file.setsampwidth(2)
        wav_file.setframerate(sample_rate)

        frames = bytearray()
        for frequency, duration in segments:
            total_samples = int(sample_rate * duration)
            for sample_index in range(total_samples):
                if frequency <= 0:
                    sample_value = 0
                else:
                    phase = 2 * math.pi * frequency * (sample_index / sample_rate)
                    sample_value = int(12_000 * math.sin(phase))
                frames.extend(int(sample_value).to_bytes(2, byteorder="little", signed=True))
        wav_file.writeframes(bytes(frames))


def _run_ffmpeg(arguments: list[str]) -> None:
    ffmpeg_path = resolve_external_tool("ffmpeg")
    if ffmpeg_path is None:
        pytest.skip("ffmpeg is required")
    subprocess.run([str(ffmpeg_path), *arguments], check=True, capture_output=True)


class _DummyToolInfo:
    available = False
    path = None
    source = None
