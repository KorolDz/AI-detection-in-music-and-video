from __future__ import annotations

import array
import math
import statistics
import subprocess
import sys
from pathlib import Path
from typing import Any

from media_security.core.models import Finding, Severity
from media_security.external_tools import get_external_tool_info

AUDIO_SAMPLE_RATE_HZ = 16_000
AUDIO_WINDOW_SEC = 0.04
AUDIO_STEP_SEC = 0.02
AUDIO_WINDOW_SAMPLES = int(AUDIO_SAMPLE_RATE_HZ * AUDIO_WINDOW_SEC)
AUDIO_STEP_SAMPLES = int(AUDIO_SAMPLE_RATE_HZ * AUDIO_STEP_SEC)
AUDIO_MERGE_GAP_SEC = 0.25
VIDEO_ALIGNMENT_TOLERANCE_SEC = 0.2
VIDEO_SHORT_SHOT_GAP_SEC = 0.75
VIDEO_DEFAULT_ANALYSIS_WIDTH = 320
TOP_CANDIDATE_LIMIT = 10
WARNING_PRIMARY_THRESHOLD = 0.75
WARNING_SECONDARY_THRESHOLD = 0.65
VIDEO_SCENE_DIFF_REFERENCE = 0.18
VIDEO_DARK_FRAME_THRESHOLD = 0.15

AUDIO_FEATURE_WEIGHTS = {
    "energy_jump": 0.35,
    "noise_floor_shift": 0.25,
    "zero_crossing_jump": 0.20,
    "silence_gap": 0.10,
    "clipping_onset": 0.10,
}


def analyze_splice_forensics(
    path: Path,
    file_format: str,
    media_type: str | None,
    technical: dict[str, object],
) -> list[Finding]:
    if file_format not in {"wav", "mp3", "mp4", "avi", "mov"}:
        return []

    ffmpeg = get_external_tool_info("ffmpeg")
    if not ffmpeg.available or ffmpeg.path is None:
        technical["splice_analysis"] = _build_unavailable_analysis("ffmpeg_not_available", media_type)
        return [
            Finding(
                code="SPLICE_ANALYSIS_UNAVAILABLE",
                severity=Severity.INFO,
                message="Install ffmpeg to enable splice and seam detection.",
                details={"reason": "ffmpeg_not_available"},
            )
        ]

    try:
        analysis = _build_base_analysis()
        analysis["available"] = True
        analysis["tool"] = "ffmpeg"

        if media_type == "audio":
            analysis["audio"] = _analyze_audio_source(path, ffmpeg.path, "audio", False, technical)
        elif media_type == "video":
            analysis["video"] = _analyze_video_source(path, ffmpeg.path, technical)
            analysis["video_audio_track"] = _analyze_audio_source(
                path,
                ffmpeg.path,
                "video_audio_track",
                True,
                technical,
            )
            analysis["correlation"] = _correlate_video_and_audio_track(
                analysis["video"],
                analysis["video_audio_track"],
            )
        else:
            analysis["status"] = "unavailable"

        analysis["summary"] = _build_summary(analysis)
        analysis["status"] = _overall_status(analysis)
        technical["splice_analysis"] = analysis
        return _build_findings(analysis)
    except Exception as exc:  # noqa: BLE001
        technical["splice_analysis"] = _build_unavailable_analysis("analysis_error", media_type)
        return [
            Finding(
                code="SPLICE_ANALYSIS_UNAVAILABLE",
                severity=Severity.INFO,
                message="Splice analysis could not be completed.",
                details={"reason": "analysis_error", "error": str(exc)},
            )
        ]


def _build_base_analysis() -> dict[str, object]:
    return {
        "available": False,
        "tool": None,
        "status": "unavailable",
        "audio": None,
        "video": None,
        "video_audio_track": None,
        "correlation": None,
        "summary": {
            "candidate_count": 0,
            "peak_confidence": 0.0,
            "top_timestamps_sec": [],
            "modalities_flagged": [],
        },
    }


def _build_unavailable_analysis(reason: str, media_type: str | None) -> dict[str, object]:
    analysis = _build_base_analysis()
    if media_type == "audio":
        analysis["audio"] = _empty_modality_result("unavailable", "audio", reason)
    elif media_type == "video":
        analysis["video"] = _empty_modality_result("unavailable", "video", reason)
        analysis["video_audio_track"] = _empty_modality_result("unavailable", "video_audio_track", reason)
        analysis["correlation"] = {"status": "unavailable", "match_count": 0, "matches": [], "reason": reason}
    return analysis


def _analyze_audio_source(
    path: Path,
    ffmpeg_path: Path,
    source: str,
    video_audio_track: bool,
    technical: dict[str, object],
) -> dict[str, object]:
    if video_audio_track and not _video_has_audio_stream(technical):
        return _empty_modality_result("unavailable", source, "no_audio_stream")

    samples, reason = _decode_audio_pcm(path, ffmpeg_path, video_audio_track)
    if samples is None:
        return _empty_modality_result("unavailable", source, reason or "decode_failed")

    candidates = _detect_audio_candidates(samples, source)
    return {
        "status": "suspicious" if candidates else "clean",
        "source": source,
        "sample_rate_hz": AUDIO_SAMPLE_RATE_HZ,
        "window_sec": AUDIO_WINDOW_SEC,
        "step_sec": AUDIO_STEP_SEC,
        "candidate_count": len(candidates),
        "peak_confidence": round(max((item["confidence"] for item in candidates), default=0.0), 4),
        "candidates": candidates,
    }


def _decode_audio_pcm(
    path: Path,
    ffmpeg_path: Path,
    video_audio_track: bool,
) -> tuple[array.array | None, str | None]:
    command = [
        str(ffmpeg_path),
        "-v",
        "error",
        "-nostdin",
        "-i",
        str(path),
    ]
    if video_audio_track:
        command += ["-map", "0:a:0", "-vn"]
    command += ["-ac", "1", "-ar", str(AUDIO_SAMPLE_RATE_HZ), "-f", "s16le", "-"]

    result = subprocess.run(command, check=False, capture_output=True)
    stderr_text = result.stderr.decode("utf-8", errors="replace")
    if result.returncode != 0:
        if video_audio_track and _looks_like_missing_audio_stream(stderr_text):
            return None, "no_audio_stream"
        return None, "decode_failed"
    if not result.stdout:
        return None, "no_audio_stream" if video_audio_track else "decode_failed"

    samples = array.array("h")
    samples.frombytes(result.stdout)
    if sys.byteorder != "little":
        samples.byteswap()
    return samples, None


def _detect_audio_candidates(samples: array.array, source: str) -> list[dict[str, object]]:
    if len(samples) < AUDIO_WINDOW_SAMPLES * 2:
        return []

    windows = _compute_audio_windows(samples)
    if len(windows) < 2:
        return []

    energy_jumps: list[float] = []
    zcr_jumps: list[float] = []
    noise_shifts: list[float] = []
    silence_gaps: list[float] = []
    clipping_onsets: list[float] = []
    timestamps: list[float] = []

    for index in range(1, len(windows)):
        previous = windows[index - 1]
        current = windows[index]
        energy_jumps.append(abs(current["rms"] - previous["rms"]))
        zcr_jumps.append(abs(current["zero_crossing"] - previous["zero_crossing"]))
        noise_shifts.append(abs(current["noise_floor"] - previous["noise_floor"]))
        silence_gaps.append(_silence_gap_score(previous["rms"], current["rms"]))
        clipping_onsets.append(max(0.0, current["clipping"] - previous["clipping"]))
        timestamps.append(current["timestamp_sec"])

    normalized_energy = _robust_normalize(energy_jumps)
    normalized_zcr = _robust_normalize(zcr_jumps)
    normalized_noise = _robust_normalize(noise_shifts)
    normalized_clipping = _robust_normalize(clipping_onsets)

    candidates: list[dict[str, object]] = []
    for index, timestamp in enumerate(timestamps):
        signals = {
            "energy_jump": normalized_energy[index],
            "noise_floor_shift": normalized_noise[index],
            "zero_crossing_jump": normalized_zcr[index],
            "silence_gap": silence_gaps[index],
            "clipping_onset": normalized_clipping[index],
        }
        confidence = _combine_audio_signal_scores(signals)
        if confidence < WARNING_SECONDARY_THRESHOLD:
            continue
        candidates.append(
            {
                "timestamp_sec": round(timestamp, 3),
                "confidence": round(confidence, 4),
                "window_sec": AUDIO_WINDOW_SEC,
                "signals": _round_signal_values(signals),
                "source": source,
            }
        )

    merged = _merge_candidates(candidates, AUDIO_MERGE_GAP_SEC)
    return sorted(merged, key=lambda item: item["timestamp_sec"])


def _compute_audio_windows(samples: array.array) -> list[dict[str, float]]:
    windows: list[dict[str, float]] = []
    max_sample = 32768.0
    for start in range(0, len(samples) - AUDIO_WINDOW_SAMPLES + 1, AUDIO_STEP_SAMPLES):
        window = samples[start : start + AUDIO_WINDOW_SAMPLES]
        if not window:
            continue
        absolute_values: list[float] = []
        energy_sum = 0.0
        sign_changes = 0
        clipping_hits = 0
        previous_sign = 0

        for sample in window:
            normalized = sample / max_sample
            energy_sum += normalized * normalized
            absolute = abs(normalized)
            absolute_values.append(absolute)
            if absolute >= 0.98:
                clipping_hits += 1

            current_sign = 1 if sample > 0 else -1 if sample < 0 else 0
            if previous_sign and current_sign and previous_sign != current_sign:
                sign_changes += 1
            if current_sign:
                previous_sign = current_sign

        windows.append(
            {
                "timestamp_sec": start / AUDIO_SAMPLE_RATE_HZ,
                "rms": math.sqrt(energy_sum / len(window)),
                "zero_crossing": sign_changes / max(1, len(window) - 1),
                "noise_floor": statistics.median(absolute_values),
                "clipping": clipping_hits / len(window),
            }
        )
    return windows


def _combine_audio_signal_scores(signals: dict[str, float]) -> float:
    confidence = 0.0
    for signal_name, weight in AUDIO_FEATURE_WEIGHTS.items():
        confidence += weight * max(0.0, min(1.0, signals.get(signal_name, 0.0)))
    return min(1.0, confidence)


def _silence_gap_score(previous_rms: float, current_rms: float) -> float:
    quiet_threshold = 0.015
    active_threshold = 0.06
    if previous_rms <= quiet_threshold < current_rms and current_rms >= active_threshold:
        return 1.0
    if current_rms <= quiet_threshold < previous_rms and previous_rms >= active_threshold:
        return 1.0
    return 0.0


def _analyze_video_source(path: Path, ffmpeg_path: Path, technical: dict[str, object]) -> dict[str, object]:
    dimensions = _video_dimensions(technical)
    if dimensions is None:
        return _empty_modality_result("unavailable", "video", "dimensions_unavailable")

    duration_sec = _video_duration_sec(technical)
    analysis_fps = _video_analysis_fps(duration_sec)
    analysis_width = min(VIDEO_DEFAULT_ANALYSIS_WIDTH, dimensions[0]) if dimensions[0] > 0 else VIDEO_DEFAULT_ANALYSIS_WIDTH
    analysis_height = max(1, round(dimensions[1] * analysis_width / max(1, dimensions[0])))

    frame_bytes, reason = _decode_video_frames(path, ffmpeg_path, analysis_fps, analysis_width, analysis_height)
    if frame_bytes is None:
        return _empty_modality_result("unavailable", "video", reason or "decode_failed")

    candidates = _detect_video_candidates(frame_bytes, analysis_width, analysis_height, analysis_fps)
    return {
        "status": "suspicious" if candidates else "clean",
        "source": "video",
        "analysis_fps": analysis_fps,
        "analysis_width": analysis_width,
        "analysis_height": analysis_height,
        "candidate_count": len(candidates),
        "peak_confidence": round(max((item["confidence"] for item in candidates), default=0.0), 4),
        "candidates": candidates,
    }


def _decode_video_frames(
    path: Path,
    ffmpeg_path: Path,
    analysis_fps: float,
    analysis_width: int,
    analysis_height: int,
) -> tuple[bytes | None, str | None]:
    command = [
        str(ffmpeg_path),
        "-v",
        "error",
        "-nostdin",
        "-i",
        str(path),
        "-an",
        "-vf",
        f"fps={analysis_fps},scale={analysis_width}:{analysis_height},format=gray",
        "-f",
        "rawvideo",
        "-pix_fmt",
        "gray",
        "-",
    ]
    result = subprocess.run(command, check=False, capture_output=True)
    if result.returncode != 0 or not result.stdout:
        return None, "decode_failed"
    return result.stdout, None


def _detect_video_candidates(
    frame_bytes: bytes,
    analysis_width: int,
    analysis_height: int,
    analysis_fps: float,
) -> list[dict[str, object]]:
    frame_size = analysis_width * analysis_height
    if frame_size <= 0:
        return []

    frame_count = len(frame_bytes) // frame_size
    if frame_count < 2:
        return []

    raw_memory = memoryview(frame_bytes)
    frames = [raw_memory[index * frame_size : (index + 1) * frame_size] for index in range(frame_count)]
    brightness = [_frame_brightness(frame) for frame in frames]
    diffs = [_frame_difference(frames[index - 1], frames[index]) for index in range(1, len(frames))]

    candidates: list[dict[str, object]] = []
    candidate_indices: list[int] = []
    for index, diff in enumerate(diffs, start=1):
        scene_score = min(1.0, diff / VIDEO_SCENE_DIFF_REFERENCE)
        if scene_score < 0.55 and diff < 0.12:
            continue
        candidate_indices.append(index)
        candidates.append(
            {
                "timestamp_sec": round(index / analysis_fps, 3),
                "confidence": round(0.50 * scene_score, 4),
                "window_sec": round(1.0 / analysis_fps, 4),
                "signals": {"scene_score": round(scene_score, 4)},
                "scene_score": round(scene_score, 4),
                "source": "video",
            }
        )

    for position, candidate in enumerate(candidates):
        boundary_index = candidate_indices[position]
        black_or_dark = 1.0 if (
            brightness[boundary_index - 1] <= VIDEO_DARK_FRAME_THRESHOLD
            or brightness[boundary_index] <= VIDEO_DARK_FRAME_THRESHOLD
        ) else 0.0
        freeze_near_boundary = 1.0 if _has_freeze_near_boundary(diffs, boundary_index - 1) else 0.0
        short_shot_gap = 1.0 if _has_short_shot_gap(candidate_indices, boundary_index, analysis_fps) else 0.0
        candidate["signals"].update(
            _round_signal_values(
                {
                    "black_or_dark_transition": black_or_dark,
                    "freeze_near_boundary": freeze_near_boundary,
                    "short_shot_gap": short_shot_gap,
                }
            )
        )
        candidate["confidence"] = round(
            min(
                1.0,
                candidate["confidence"] + (0.15 * black_or_dark) + (0.10 * freeze_near_boundary) + (0.15 * short_shot_gap),
            ),
            4,
        )

    return candidates


def _frame_brightness(frame: memoryview) -> float:
    return (sum(frame) / max(1, len(frame))) / 255.0


def _frame_difference(left: memoryview, right: memoryview) -> float:
    if len(left) != len(right) or not left:
        return 0.0
    total = 0
    for left_pixel, right_pixel in zip(left, right):
        total += abs(left_pixel - right_pixel)
    return total / (len(left) * 255.0)


def _has_freeze_near_boundary(diffs: list[float], boundary_diff_index: int) -> bool:
    for index in range(max(0, boundary_diff_index - 2), min(len(diffs), boundary_diff_index + 3)):
        if index != boundary_diff_index and diffs[index] <= 0.01:
            return True
    return False


def _has_short_shot_gap(candidate_indices: list[int], boundary_index: int, analysis_fps: float) -> bool:
    sorted_indices = sorted(candidate_indices)
    if boundary_index not in sorted_indices:
        return False
    position = sorted_indices.index(boundary_index)
    distances: list[float] = []
    if position > 0:
        distances.append((boundary_index - sorted_indices[position - 1]) / analysis_fps)
    if position + 1 < len(sorted_indices):
        distances.append((sorted_indices[position + 1] - boundary_index) / analysis_fps)
    return any(distance <= VIDEO_SHORT_SHOT_GAP_SEC for distance in distances)


def _correlate_video_and_audio_track(video_result: object, audio_track_result: object) -> dict[str, object] | None:
    if not isinstance(video_result, dict) or not isinstance(audio_track_result, dict):
        return None
    if video_result.get("status") == "unavailable" or audio_track_result.get("status") == "unavailable":
        return {"status": "unavailable", "match_count": 0, "matches": []}

    video_candidates = video_result.get("candidates")
    audio_candidates = audio_track_result.get("candidates")
    if not isinstance(video_candidates, list) or not isinstance(audio_candidates, list):
        return {"status": "none", "match_count": 0, "matches": []}

    matches: list[dict[str, object]] = []
    for video_candidate in video_candidates:
        if not isinstance(video_candidate, dict):
            continue
        video_time = _as_float(video_candidate.get("timestamp_sec"))
        if video_time is None:
            continue

        nearest_match: dict[str, object] | None = None
        nearest_delta: float | None = None
        for audio_candidate in audio_candidates:
            if not isinstance(audio_candidate, dict):
                continue
            audio_time = _as_float(audio_candidate.get("timestamp_sec"))
            if audio_time is None:
                continue
            delta = abs(video_time - audio_time)
            if delta <= VIDEO_ALIGNMENT_TOLERANCE_SEC and (nearest_delta is None or delta < nearest_delta):
                nearest_match = audio_candidate
                nearest_delta = delta

        if nearest_match is None or nearest_delta is None:
            continue

        video_candidate["confidence"] = round(min(1.0, (_as_float(video_candidate.get("confidence")) or 0.0) + 0.10), 4)
        video_candidate["aligned_audio_track"] = True
        signals = video_candidate.get("signals")
        if isinstance(signals, dict):
            signals["audio_track_alignment"] = 1.0
        matches.append(
            {
                "video_timestamp_sec": round(video_time, 3),
                "audio_timestamp_sec": round(_as_float(nearest_match.get("timestamp_sec")) or 0.0, 3),
                "delta_sec": round(nearest_delta, 3),
            }
        )

    video_result["peak_confidence"] = round(
        max((_as_float(item.get("confidence")) or 0.0 for item in video_candidates if isinstance(item, dict)), default=0.0),
        4,
    )
    return {"status": "aligned" if matches else "none", "match_count": len(matches), "matches": matches[:TOP_CANDIDATE_LIMIT]}


def _build_summary(analysis: dict[str, object]) -> dict[str, object]:
    candidate_count = 0
    peak_confidence = 0.0
    top_entries: list[tuple[float, float]] = []
    modalities_flagged: list[str] = []

    for modality_name in ("audio", "video", "video_audio_track"):
        modality = analysis.get(modality_name)
        if not isinstance(modality, dict):
            continue
        candidate_count += int(modality.get("candidate_count", 0))
        peak_confidence = max(peak_confidence, _as_float(modality.get("peak_confidence")) or 0.0)
        if int(modality.get("candidate_count", 0)) > 0:
            modalities_flagged.append(modality_name)
        candidates = modality.get("candidates")
        if not isinstance(candidates, list):
            continue
        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            timestamp = _as_float(candidate.get("timestamp_sec"))
            confidence = _as_float(candidate.get("confidence"))
            if timestamp is not None and confidence is not None:
                top_entries.append((confidence, timestamp))

    return {
        "candidate_count": candidate_count,
        "peak_confidence": round(peak_confidence, 4),
        "top_timestamps_sec": [round(timestamp, 3) for _, timestamp in sorted(top_entries, reverse=True)[:TOP_CANDIDATE_LIMIT]],
        "modalities_flagged": modalities_flagged,
    }


def _overall_status(analysis: dict[str, object]) -> str:
    if not analysis.get("available"):
        return "unavailable"
    for modality_name in ("audio", "video", "video_audio_track"):
        modality = analysis.get(modality_name)
        if isinstance(modality, dict) and int(modality.get("candidate_count", 0)) > 0:
            return "suspicious"
    return "clean"


def _build_findings(analysis: dict[str, object]) -> list[Finding]:
    findings: list[Finding] = []
    audio = analysis.get("audio")
    if isinstance(audio, dict) and _should_flag_modality(audio):
        findings.append(
            Finding(
                code="AUDIO_SPLICE_SUSPECTED",
                severity=Severity.WARNING,
                message="Suspicious splice markers detected in the audio signal.",
                details=_finding_details(audio),
            )
        )
    video = analysis.get("video")
    if isinstance(video, dict) and _should_flag_modality(video):
        findings.append(
            Finding(
                code="VIDEO_SEAM_SUSPECTED",
                severity=Severity.WARNING,
                message="Suspicious seam markers detected in the video stream.",
                details=_finding_details(video),
            )
        )
    video_audio = analysis.get("video_audio_track")
    if isinstance(video_audio, dict) and _should_flag_modality(video_audio):
        findings.append(
            Finding(
                code="VIDEO_AUDIO_TRACK_SPLICE_SUSPECTED",
                severity=Severity.WARNING,
                message="Suspicious splice markers detected in the audio track of the video.",
                details=_finding_details(video_audio),
            )
        )
    correlation = analysis.get("correlation")
    if isinstance(correlation, dict) and int(correlation.get("match_count", 0)) > 0:
        findings.append(
            Finding(
                code="VIDEO_AUDIO_SEAM_ALIGNMENT",
                severity=Severity.INFO,
                message="Video seam candidates align with audio-track splice candidates.",
                details={"match_count": correlation["match_count"], "matches": correlation["matches"]},
            )
        )
    return findings


def _should_flag_modality(modality: dict[str, object]) -> bool:
    candidates = modality.get("candidates")
    if not isinstance(candidates, list):
        return False
    confidences = [_as_float(item.get("confidence")) or 0.0 for item in candidates if isinstance(item, dict)]
    if not confidences:
        return False
    return max(confidences) >= WARNING_PRIMARY_THRESHOLD or sum(item >= WARNING_SECONDARY_THRESHOLD for item in confidences) >= 2


def _finding_details(modality: dict[str, object]) -> dict[str, object]:
    candidates = modality.get("candidates")
    if not isinstance(candidates, list):
        candidates = []
    top_candidates = sorted(
        [item for item in candidates if isinstance(item, dict)],
        key=lambda item: _as_float(item.get("confidence")) or 0.0,
        reverse=True,
    )[:TOP_CANDIDATE_LIMIT]
    return {
        "candidate_count": int(modality.get("candidate_count", 0)),
        "peak_confidence": round(_as_float(modality.get("peak_confidence")) or 0.0, 4),
        "top_candidates": top_candidates,
    }


def _empty_modality_result(status: str, source: str, reason: str | None = None) -> dict[str, object]:
    result: dict[str, object] = {
        "status": status,
        "source": source,
        "candidate_count": 0,
        "peak_confidence": 0.0,
        "candidates": [],
    }
    if reason:
        result["reason"] = reason
    return result


def _merge_candidates(candidates: list[dict[str, object]], max_gap_sec: float) -> list[dict[str, object]]:
    if not candidates:
        return []
    ordered = sorted(candidates, key=lambda item: _as_float(item.get("timestamp_sec")) or 0.0)
    merged: list[dict[str, object]] = [dict(ordered[0])]
    for candidate in ordered[1:]:
        current = dict(candidate)
        previous = merged[-1]
        previous_time = _as_float(previous.get("timestamp_sec")) or 0.0
        current_time = _as_float(current.get("timestamp_sec")) or 0.0
        if current_time - previous_time > max_gap_sec:
            merged.append(current)
            continue

        previous_signals = previous.get("signals")
        current_signals = current.get("signals")
        if isinstance(previous_signals, dict) and isinstance(current_signals, dict):
            for signal_name, signal_value in current_signals.items():
                previous_signals[signal_name] = round(
                    max(_as_float(previous_signals.get(signal_name)) or 0.0, _as_float(signal_value) or 0.0),
                    4,
                )

        previous_confidence = _as_float(previous.get("confidence")) or 0.0
        current_confidence = _as_float(current.get("confidence")) or 0.0
        if current_confidence > previous_confidence:
            previous["timestamp_sec"] = current.get("timestamp_sec")
            previous["window_sec"] = current.get("window_sec")
            previous["source"] = current.get("source")
        previous["confidence"] = round(max(previous_confidence, current_confidence), 4)
    return merged


def _robust_normalize(values: list[float]) -> list[float]:
    if not values:
        return []
    if len(values) == 1:
        return [1.0 if values[0] > 0 else 0.0]
    median = statistics.median(values)
    deviations = [abs(value - median) for value in values]
    mad = statistics.median(deviations)
    if mad <= 1e-9:
        maximum = max(values)
        if maximum <= 1e-9:
            return [0.0 for _ in values]
        return [min(1.0, max(0.0, value / maximum)) for value in values]
    scale = mad * 1.4826
    normalized: list[float] = []
    for value in values:
        z_score = max(0.0, (value - median) / scale)
        normalized.append(min(1.0, z_score / 6.0))
    return normalized


def _round_signal_values(signals: dict[str, float]) -> dict[str, float]:
    return {key: round(value, 4) for key, value in signals.items() if value > 0}


def _looks_like_missing_audio_stream(stderr_text: str) -> bool:
    text = stderr_text.lower()
    return "stream map" in text and "matches no streams" in text


def _video_has_audio_stream(technical: dict[str, object]) -> bool:
    ffprobe = technical.get("ffprobe")
    if isinstance(ffprobe, dict) and isinstance(ffprobe.get("audio_stream_count"), int):
        return ffprobe["audio_stream_count"] > 0
    return True


def _video_dimensions(technical: dict[str, object]) -> tuple[int, int] | None:
    ffprobe = technical.get("ffprobe")
    if isinstance(ffprobe, dict):
        width = ffprobe.get("width")
        height = ffprobe.get("height")
        if isinstance(width, int) and width > 0 and isinstance(height, int) and height > 0:
            return width, height
    exiftool = technical.get("exiftool")
    if isinstance(exiftool, dict):
        high_value = exiftool.get("high_value")
        if isinstance(high_value, dict):
            resolution = _as_text(high_value.get("resolution"))
            if resolution and "x" in resolution:
                left, right = resolution.lower().split("x", 1)
                if left.isdigit() and right.isdigit():
                    return int(left), int(right)
    return None


def _video_duration_sec(technical: dict[str, object]) -> float | None:
    ffprobe = technical.get("ffprobe")
    if isinstance(ffprobe, dict):
        duration = _as_float(ffprobe.get("duration_sec"))
        if duration is not None and duration > 0:
            return duration
    exiftool = technical.get("exiftool")
    if isinstance(exiftool, dict):
        high_value = exiftool.get("high_value")
        if isinstance(high_value, dict):
            return _parse_duration_text(_as_text(high_value.get("duration")))
    return None


def _video_analysis_fps(duration_sec: float | None) -> float:
    if duration_sec is None:
        return 4.0
    if duration_sec > 30 * 60:
        return 1.0
    if duration_sec > 10 * 60:
        return 2.0
    return 4.0


def _parse_duration_text(value: str | None) -> float | None:
    if not value:
        return None
    text = value.strip().lower()
    if ":" in text:
        parts = text.split(":")
        try:
            numbers = [float(item) for item in parts]
        except ValueError:
            numbers = []
        if len(numbers) == 3:
            return (numbers[0] * 3600) + (numbers[1] * 60) + numbers[2]
        if len(numbers) == 2:
            return (numbers[0] * 60) + numbers[1]
    first_token = text.split()[0]
    parsed = _as_float(first_token)
    return parsed if parsed is not None and parsed > 0 else None


def _as_float(value: object) -> float | None:
    try:
        if value is None:
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_text(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
