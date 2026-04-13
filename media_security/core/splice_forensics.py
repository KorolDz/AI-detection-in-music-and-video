from __future__ import annotations

import math
import os
import subprocess
from pathlib import Path
from typing import Any

from media_security.core.models import Finding, Severity
from media_security.external_tools import get_external_tool_info, resolve_external_tool

_bundled_ffmpeg = resolve_external_tool("ffmpeg")
if _bundled_ffmpeg is not None:
    ffmpeg_dir = str(_bundled_ffmpeg.parent)
    current_path = os.environ.get("PATH", "")
    path_items = current_path.split(os.pathsep) if current_path else []
    if ffmpeg_dir not in path_items:
        os.environ["PATH"] = ffmpeg_dir if not current_path else f"{ffmpeg_dir}{os.pathsep}{current_path}"

try:
    import numpy as np
except ImportError:  # pragma: no cover - exercised via dependency checks
    np = None  # type: ignore[assignment]

try:
    import librosa
except ImportError:  # pragma: no cover - exercised via dependency checks
    librosa = None  # type: ignore[assignment]

try:
    from pydub import AudioSegment
    from pydub.silence import detect_silence
except ImportError:  # pragma: no cover - exercised via dependency checks
    AudioSegment = None  # type: ignore[assignment]
    detect_silence = None  # type: ignore[assignment]

try:
    from scenedetect import SceneManager, open_video
    from scenedetect.detectors import ContentDetector
except ImportError:  # pragma: no cover - exercised via dependency checks
    SceneManager = None  # type: ignore[assignment]
    ContentDetector = None  # type: ignore[assignment]
    open_video = None  # type: ignore[assignment]

AUDIO_SAMPLE_RATE_HZ = 16_000
AUDIO_WINDOW_SEC = 0.04
AUDIO_STEP_SEC = 0.02
AUDIO_WINDOW_SAMPLES = int(AUDIO_SAMPLE_RATE_HZ * AUDIO_WINDOW_SEC)
AUDIO_STEP_SAMPLES = int(AUDIO_SAMPLE_RATE_HZ * AUDIO_STEP_SEC)
AUDIO_MERGE_GAP_SEC = 0.25
AUDIO_SILENCE_WINDOW_SEC = 0.08
AUDIO_MIN_SIGNAL_THRESHOLD = 0.45
VIDEO_ALIGNMENT_TOLERANCE_SEC = 0.2
VIDEO_SHORT_SHOT_GAP_SEC = 0.75
VIDEO_DEFAULT_ANALYSIS_WIDTH = 320
VIDEO_SCENE_DIFF_REFERENCE = 0.18
VIDEO_DARK_FRAME_THRESHOLD = 0.15
TOP_CANDIDATE_LIMIT = 10
WARNING_PRIMARY_THRESHOLD = 0.75
WARNING_SECONDARY_THRESHOLD = 0.65
AUDIO_EDGE_MARGIN_SEC = 0.12

AUDIO_FEATURE_WEIGHTS = {
    "rms_jump": 0.20,
    "spectral_flux": 0.20,
    "onset_jump": 0.15,
    "mfcc_distance": 0.15,
    "spectral_centroid_shift": 0.10,
    "spectral_bandwidth_shift": 0.10,
    "silence_boundary": 0.10,
}

VIDEO_FEATURE_WEIGHTS = {
    "scene_score": 0.35,
    "freeze_near_boundary": 0.25,
    "black_or_dark_transition": 0.20,
    "short_shot_gap": 0.20,
}

SIGNAL_REASON_LABELS = {
    "rms_jump": "скачок громкости",
    "spectral_flux": "резкий спектральный переход",
    "onset_jump": "скачок onset-признака",
    "mfcc_distance": "смена тембра/источника",
    "spectral_centroid_shift": "сдвиг спектрального центра",
    "spectral_bandwidth_shift": "сдвиг ширины спектра",
    "silence_boundary": "граница паузы",
    "scene_score": "резкая смена сцены",
    "freeze_near_boundary": "freeze рядом с переходом",
    "black_or_dark_transition": "чёрный/тёмный кадр на границе",
    "short_shot_gap": "аномально короткий фрагмент",
    "audio_track_alignment": "совпадение с разрывом аудиодорожки",
}

PYTHON_DEPENDENCIES = {
    "audio": ("numpy", "pydub"),
    "video": ("numpy", "scenedetect"),
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
                message="Для forensic-анализа склеек требуется ffmpeg.",
                details={"reason": "ffmpeg_not_available"},
            )
        ]

    try:
        analysis = _build_base_analysis()
        analysis["available"] = True
        analysis["tool"] = "ffmpeg"

        if media_type == "audio":
            audio_missing = _missing_python_dependencies("audio")
            if audio_missing:
                analysis["audio"] = _empty_modality_result(
                    "unavailable",
                    "audio",
                    "missing_audio_dependencies",
                    missing_dependencies=audio_missing,
                )
            else:
                analysis["audio"] = _analyze_audio_source(path, ffmpeg.path, "audio", False, technical)
        elif media_type == "video":
            video_transition_pool: list[dict[str, object]] = []
            video_missing = _missing_python_dependencies("video")
            if video_missing:
                analysis["video"] = _empty_modality_result(
                    "unavailable",
                    "video",
                    "missing_video_dependencies",
                    missing_dependencies=video_missing,
                )
            else:
                analysis["video"], video_transition_pool = _analyze_video_source(path, ffmpeg.path, technical)

            audio_missing = _missing_python_dependencies("audio")
            if audio_missing:
                analysis["video_audio_track"] = _empty_modality_result(
                    "unavailable",
                    "video_audio_track",
                    "missing_audio_dependencies",
                    missing_dependencies=audio_missing,
                )
            else:
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
                transition_pool=video_transition_pool,
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
                message="Не удалось завершить forensic-анализ склеек.",
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

    decoded, reason = _decode_audio_pcm(path, ffmpeg_path, video_audio_track)
    if decoded is None:
        return _empty_modality_result("unavailable", source, reason or "decode_failed")

    samples = decoded["samples"]
    raw_bytes = decoded["raw_bytes"]
    duration_sec = decoded["duration_sec"]
    candidates, content_profile = _detect_audio_candidates(samples, raw_bytes, source, duration_sec)
    return {
        "status": "suspicious" if candidates else "clean",
        "source": source,
        "analysis_method": "ffmpeg+numpy+pydub",
        "content_profile": content_profile,
        "sample_rate_hz": AUDIO_SAMPLE_RATE_HZ,
        "window_sec": AUDIO_WINDOW_SEC,
        "step_sec": AUDIO_STEP_SEC,
        "duration_sec": round(duration_sec, 3),
        "candidate_count": len(candidates),
        "peak_confidence": round(max((_as_float(item.get("confidence")) or 0.0 for item in candidates), default=0.0), 4),
        "candidates": candidates,
    }


def _decode_audio_pcm(
    path: Path,
    ffmpeg_path: Path,
    video_audio_track: bool,
) -> tuple[dict[str, object] | None, str | None]:
    if np is None:
        return None, "missing_audio_dependencies"

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

    samples = np.frombuffer(result.stdout, dtype="<i2").astype(np.float32) / 32768.0
    if samples.size == 0:
        return None, "decode_failed"

    return {
        "samples": samples,
        "raw_bytes": bytes(result.stdout),
        "duration_sec": float(samples.size) / AUDIO_SAMPLE_RATE_HZ,
    }, None


def _detect_audio_candidates(
    samples: Any,
    raw_bytes: bytes,
    source: str,
    duration_sec: float,
) -> tuple[list[dict[str, object]], str]:
    if np is None or AudioSegment is None or detect_silence is None:
        return [], "speech_or_general"
    if len(samples) < AUDIO_WINDOW_SAMPLES * 3:
        return [], "speech_or_general"

    n_fft = max(1024, AUDIO_WINDOW_SAMPLES)
    frames = _frame_audio_samples(samples)
    frame_count = frames.shape[0]
    if frame_count < 3:
        return [], "speech_or_general"

    window = np.hanning(AUDIO_WINDOW_SAMPLES).astype(np.float32)
    windowed_frames = frames * window
    rms = np.sqrt(np.mean(frames * frames, axis=1))
    spectra = np.abs(np.fft.rfft(windowed_frames, n=n_fft, axis=1)).astype(np.float32, copy=False)
    freqs = np.fft.rfftfreq(n_fft, 1.0 / AUDIO_SAMPLE_RATE_HZ).astype(np.float32)
    spectral_energy = np.sum(spectra, axis=1) + 1e-6
    centroid = np.sum(spectra * freqs, axis=1) / spectral_energy
    bandwidth = np.sqrt(
        np.sum(((freqs - centroid[:, None]) ** 2) * spectra, axis=1) / spectral_energy
    )
    positive_stft_diff = np.maximum(0.0, np.diff(spectra, axis=0))
    spectral_flux_frames = np.zeros(frame_count, dtype=np.float32)
    spectral_flux_frames[1:] = np.sqrt(np.sum(positive_stft_diff * positive_stft_diff, axis=1))
    onset_envelope = spectral_flux_frames
    log_spectra = np.log(spectra + 1e-6)
    cepstrum = np.fft.irfft(log_spectra, axis=1)[:, :13].astype(np.float32, copy=False)

    timestamps = (np.arange(1, frame_count) * AUDIO_STEP_SAMPLES) / AUDIO_SAMPLE_RATE_HZ

    signals_by_name = {
        "rms_jump": _robust_normalize(np.abs(np.diff(rms))),
        "spectral_flux": _robust_normalize(spectral_flux_frames[1:]),
        "onset_jump": _robust_normalize(np.abs(np.diff(onset_envelope))),
        "mfcc_distance": _robust_normalize(np.linalg.norm(np.diff(cepstrum, axis=0), axis=1) / math.sqrt(cepstrum.shape[1])),
        "spectral_centroid_shift": _robust_normalize(np.abs(np.diff(centroid))),
        "spectral_bandwidth_shift": _robust_normalize(np.abs(np.diff(bandwidth))),
    }

    silence_boundaries, silence_ratio = _compute_silence_boundaries(raw_bytes, duration_sec)
    silence_boundary_scores = _silence_boundary_scores(timestamps, silence_boundaries)
    content_profile = _audio_content_profile(
        onset_envelope=onset_envelope,
        silence_ratio=silence_ratio,
        spectral_bandwidth=bandwidth,
        duration_sec=duration_sec,
    )

    candidate_threshold = 0.84 if content_profile == "music_like" else 0.68
    minimum_signal_count = 4 if content_profile == "music_like" else 2

    candidates: list[dict[str, object]] = []
    for index, timestamp in enumerate(timestamps):
        if float(timestamp) <= AUDIO_EDGE_MARGIN_SEC or (duration_sec - float(timestamp)) <= AUDIO_EDGE_MARGIN_SEC:
            continue
        signals = {
            "rms_jump": signals_by_name["rms_jump"][index],
            "spectral_flux": signals_by_name["spectral_flux"][index],
            "onset_jump": signals_by_name["onset_jump"][index],
            "mfcc_distance": signals_by_name["mfcc_distance"][index],
            "spectral_centroid_shift": signals_by_name["spectral_centroid_shift"][index],
            "spectral_bandwidth_shift": signals_by_name["spectral_bandwidth_shift"][index],
            "silence_boundary": silence_boundary_scores[index],
        }
        confidence = _combine_signal_scores(signals, AUDIO_FEATURE_WEIGHTS)
        strong_signals = sum(value >= AUDIO_MIN_SIGNAL_THRESHOLD for value in signals.values())
        pause_support = signals["silence_boundary"] >= 0.6
        if confidence < candidate_threshold:
            continue
        if strong_signals < minimum_signal_count and not (pause_support and strong_signals >= max(1, minimum_signal_count - 1)):
            continue
        if content_profile == "music_like":
            strong_timbre_break = signals["mfcc_distance"] >= 0.7 and signals["spectral_centroid_shift"] >= 0.45
            strong_energy_break = signals["rms_jump"] >= 0.75 and signals["spectral_flux"] >= 0.75
            if not ((pause_support and strong_timbre_break) or (strong_timbre_break and strong_energy_break)):
                continue

        candidates.append(
            {
                "timestamp_sec": round(float(timestamp), 3),
                "confidence": round(confidence, 4),
                "window_sec": AUDIO_WINDOW_SEC,
                "signals": _round_signal_values(signals),
                "reasons": _candidate_reasons(signals),
                "source": source,
            }
        )

    merged = _merge_candidates(candidates, AUDIO_MERGE_GAP_SEC)
    if content_profile == "music_like":
        merged = _suppress_dense_music_candidates(merged, duration_sec)
    return sorted(merged, key=lambda item: _as_float(item.get("timestamp_sec")) or 0.0), content_profile


def _compute_silence_boundaries(raw_bytes: bytes, duration_sec: float) -> tuple[list[float], float]:
    if AudioSegment is None or detect_silence is None:
        return [], 0.0

    segment = AudioSegment(
        data=raw_bytes,
        sample_width=2,
        frame_rate=AUDIO_SAMPLE_RATE_HZ,
        channels=1,
    )
    if len(segment) == 0:
        return [], 0.0

    silence_threshold = -55.0 if segment.dBFS == float("-inf") else segment.dBFS - 18.0
    silence_ranges = detect_silence(
        segment,
        min_silence_len=int(AUDIO_WINDOW_SEC * 1000),
        silence_thresh=silence_threshold,
        seek_step=10,
    )

    boundaries: list[float] = []
    total_silence_ms = 0
    for start_ms, end_ms in silence_ranges:
        total_silence_ms += max(0, end_ms - start_ms)
        boundaries.append(start_ms / 1000.0)
        boundaries.append(end_ms / 1000.0)

    silence_ratio = 0.0
    if duration_sec > 0:
        silence_ratio = min(1.0, (total_silence_ms / 1000.0) / duration_sec)
    return boundaries, silence_ratio


def _silence_boundary_scores(timestamps: Any, boundaries: list[float]) -> list[float]:
    if np is None or len(timestamps) == 0 or not boundaries:
        return [0.0 for _ in range(len(timestamps))]

    scores = np.zeros(len(timestamps), dtype=np.float32)
    max_distance = AUDIO_SILENCE_WINDOW_SEC
    half_distance = max_distance / 2.0
    for boundary in boundaries:
        deltas = np.abs(timestamps - boundary)
        full_mask = deltas <= half_distance
        taper_mask = (deltas > half_distance) & (deltas <= max_distance)
        scores[full_mask] = np.maximum(scores[full_mask], 1.0)
        taper_scores = 1.0 - ((deltas[taper_mask] - half_distance) / max(1e-6, half_distance))
        if taper_scores.size:
            scores[taper_mask] = np.maximum(scores[taper_mask], taper_scores.astype(np.float32))
    return [float(value) for value in np.clip(scores, 0.0, 1.0)]


def _audio_content_profile(
    onset_envelope: Any,
    silence_ratio: float,
    spectral_bandwidth: Any,
    duration_sec: float,
) -> str:
    if np is None or duration_sec <= 0:
        return "speech_or_general"

    median_onset = float(np.median(onset_envelope)) if len(onset_envelope) else 0.0
    prominence_floor = float(np.median(onset_envelope) + np.std(onset_envelope)) if len(onset_envelope) else 0.0
    onset_peaks = 0
    for index in range(1, max(0, len(onset_envelope) - 1)):
        value = float(onset_envelope[index])
        if value >= prominence_floor and value >= float(onset_envelope[index - 1]) and value >= float(onset_envelope[index + 1]):
            onset_peaks += 1
    onset_density = onset_peaks / duration_sec
    median_bandwidth = float(np.median(spectral_bandwidth)) if len(spectral_bandwidth) else 0.0

    if duration_sec >= 30.0 and onset_density >= 2.0 and median_onset >= 8.0 and median_bandwidth >= 1200.0:
        return "music_like"
    if duration_sec >= 12.0 and onset_density >= 3.5 and median_onset >= 10.0 and median_bandwidth >= 1500.0:
        return "music_like"
    if duration_sec >= 6.0 and silence_ratio < 0.02 and onset_density >= 3.0 and median_onset >= 3.0 and median_bandwidth >= 1500.0:
        return "music_like"
    return "speech_or_general"


def _suppress_dense_music_candidates(candidates: list[dict[str, object]], duration_sec: float) -> list[dict[str, object]]:
    if not candidates or duration_sec <= 0:
        return candidates

    candidate_rate_per_minute = len(candidates) / max(duration_sec / 60.0, 1e-6)
    if len(candidates) >= 12 and candidate_rate_per_minute >= 2.0:
        return []
    return candidates


def _frame_audio_samples(samples: Any) -> Any:
    if np is None:
        return []
    sample_array = np.ascontiguousarray(samples, dtype=np.float32)
    frame_count = 1 + max(0, (sample_array.shape[0] - AUDIO_WINDOW_SAMPLES) // AUDIO_STEP_SAMPLES)
    if frame_count <= 0:
        return np.empty((0, AUDIO_WINDOW_SAMPLES), dtype=np.float32)
    stride = sample_array.strides[0]
    return np.lib.stride_tricks.as_strided(
        sample_array,
        shape=(frame_count, AUDIO_WINDOW_SAMPLES),
        strides=(AUDIO_STEP_SAMPLES * stride, stride),
        writeable=False,
    )


def _analyze_video_source(
    path: Path,
    ffmpeg_path: Path,
    technical: dict[str, object],
) -> tuple[dict[str, object], list[dict[str, object]]]:
    dimensions = _video_dimensions(technical)
    if dimensions is None:
        return _empty_modality_result("unavailable", "video", "dimensions_unavailable"), []

    scene_timestamps, reason = _detect_scene_timestamps(path)
    if scene_timestamps is None:
        return _empty_modality_result("unavailable", "video", reason or "scene_detection_failed"), []

    duration_sec = _video_duration_sec(technical)
    analysis_fps = _video_analysis_fps(duration_sec)
    analysis_width = min(VIDEO_DEFAULT_ANALYSIS_WIDTH, dimensions[0]) if dimensions[0] > 0 else VIDEO_DEFAULT_ANALYSIS_WIDTH
    analysis_height = max(1, round(dimensions[1] * analysis_width / max(1, dimensions[0])))

    frame_bytes, reason = _decode_video_frames(path, ffmpeg_path, analysis_fps, analysis_width, analysis_height)
    if frame_bytes is None:
        return _empty_modality_result("unavailable", "video", reason or "decode_failed"), []

    candidates, transition_pool = _detect_video_candidates(
        frame_bytes=frame_bytes,
        analysis_width=analysis_width,
        analysis_height=analysis_height,
        analysis_fps=analysis_fps,
        scene_timestamps=scene_timestamps,
    )
    return (
        {
            "status": "suspicious" if candidates else "clean",
            "source": "video",
            "analysis_method": "PySceneDetect+ffmpeg",
            "analysis_fps": analysis_fps,
            "analysis_width": analysis_width,
            "analysis_height": analysis_height,
            "scene_transition_count": len(scene_timestamps),
            "candidate_count": len(candidates),
            "peak_confidence": round(max((_as_float(item.get("confidence")) or 0.0 for item in candidates), default=0.0), 4),
            "candidates": candidates,
        },
        transition_pool,
    )


def _detect_scene_timestamps(path: Path) -> tuple[list[float] | None, str | None]:
    if SceneManager is None or ContentDetector is None or open_video is None:
        return None, "missing_video_dependencies"

    try:
        video = open_video(str(path))
    except Exception:  # noqa: BLE001
        return None, "scene_detection_failed"

    close_video = getattr(video, "close", None)
    try:
        frame_rate = _scene_detect_frame_rate(video)
        min_scene_len = max(8, int(frame_rate * 0.5))
        manager = SceneManager()
        manager.add_detector(ContentDetector(threshold=27.0, min_scene_len=min_scene_len))
        manager.detect_scenes(video)
        scene_list = manager.get_scene_list()
    except Exception:  # noqa: BLE001
        return None, "scene_detection_failed"
    finally:
        if callable(close_video):
            close_video()

    timestamps: list[float] = []
    for start_time, _end_time in scene_list[1:]:
        seconds = _timecode_seconds(start_time)
        if seconds is not None:
            timestamps.append(round(seconds, 3))
    return timestamps, None


def _scene_detect_frame_rate(video: object) -> float:
    frame_rate = getattr(video, "frame_rate", None)
    try:
        numeric = float(frame_rate)
    except (TypeError, ValueError):
        numeric = 24.0
    return numeric if numeric > 0 else 24.0


def _timecode_seconds(value: object) -> float | None:
    getter = getattr(value, "get_seconds", None)
    if callable(getter):
        try:
            return float(getter())
        except (TypeError, ValueError):
            return None
    return _as_float(value)


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
    scene_timestamps: list[float],
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    if np is None:
        return [], []

    frame_size = analysis_width * analysis_height
    if frame_size <= 0:
        return [], []

    frame_array = np.frombuffer(frame_bytes, dtype=np.uint8)
    frame_count = frame_array.size // frame_size
    if frame_count < 2:
        return [], []

    frames = frame_array[: frame_count * frame_size].reshape(frame_count, frame_size).astype(np.float32)
    brightness = frames.mean(axis=1) / 255.0
    diffs = np.abs(np.diff(frames, axis=0)).mean(axis=1) / 255.0

    transition_pool: list[dict[str, object]] = []
    suspicious_candidates: list[dict[str, object]] = []
    for timestamp_sec in scene_timestamps:
        boundary_index = min(frame_count - 1, max(1, int(round(timestamp_sec * analysis_fps))))
        candidate = _build_video_transition(
            timestamp_sec=timestamp_sec,
            boundary_index=boundary_index,
            diffs=diffs,
            brightness=brightness,
            scene_timestamps=scene_timestamps,
            analysis_fps=analysis_fps,
        )
        transition_pool.append(candidate)
        if _is_video_transition_suspicious(candidate):
            suspicious_candidates.append(_public_video_candidate(candidate))

    merged = _merge_candidates(suspicious_candidates, max_gap_sec=max(0.2, 1.0 / analysis_fps))
    return merged, transition_pool


def _build_video_transition(
    timestamp_sec: float,
    boundary_index: int,
    diffs: Any,
    brightness: Any,
    scene_timestamps: list[float],
    analysis_fps: float,
) -> dict[str, object]:
    diff_index = max(0, min(len(diffs) - 1, boundary_index - 1))
    scene_score = min(1.0, float(diffs[diff_index]) / VIDEO_SCENE_DIFF_REFERENCE)
    black_or_dark = 1.0 if (
        float(brightness[max(0, boundary_index - 1)]) <= VIDEO_DARK_FRAME_THRESHOLD
        or float(brightness[boundary_index]) <= VIDEO_DARK_FRAME_THRESHOLD
    ) else 0.0
    freeze_near_boundary = 1.0 if _has_freeze_near_boundary(diffs, diff_index) else 0.0
    short_shot_gap = 1.0 if _has_short_shot_gap(scene_timestamps, timestamp_sec) else 0.0

    signals = {
        "scene_score": scene_score,
        "freeze_near_boundary": freeze_near_boundary,
        "black_or_dark_transition": black_or_dark,
        "short_shot_gap": short_shot_gap,
    }
    confidence = _combine_signal_scores(signals, VIDEO_FEATURE_WEIGHTS)
    return {
        "timestamp_sec": round(timestamp_sec, 3),
        "confidence": round(confidence, 4),
        "window_sec": round(1.0 / analysis_fps, 4),
        "signals": _round_signal_values(signals),
        "reasons": _candidate_reasons(signals),
        "scene_score": round(scene_score, 4),
        "source": "video",
    }


def _public_video_candidate(candidate: dict[str, object]) -> dict[str, object]:
    result = {
        "timestamp_sec": candidate["timestamp_sec"],
        "confidence": candidate["confidence"],
        "window_sec": candidate["window_sec"],
        "signals": candidate["signals"],
        "reasons": candidate.get("reasons", []),
        "scene_score": candidate.get("scene_score"),
        "source": candidate.get("source", "video"),
    }
    if candidate.get("aligned_audio_track"):
        result["aligned_audio_track"] = True
    return result


def _combine_signal_scores(signals: dict[str, float], weights: dict[str, float]) -> float:
    confidence = 0.0
    for signal_name, weight in weights.items():
        confidence += weight * max(0.0, min(1.0, signals.get(signal_name, 0.0)))
    return min(1.0, confidence)


def _has_freeze_near_boundary(diffs: Any, boundary_diff_index: int) -> bool:
    start = max(0, boundary_diff_index - 2)
    end = min(len(diffs), boundary_diff_index + 3)
    for index in range(start, end):
        if index == boundary_diff_index:
            continue
        if float(diffs[index]) <= 0.01:
            return True
    return False


def _has_short_shot_gap(scene_timestamps: list[float], timestamp_sec: float) -> bool:
    if not scene_timestamps:
        return False
    ordered = sorted(scene_timestamps)
    if timestamp_sec not in ordered:
        return False
    position = ordered.index(timestamp_sec)
    distances: list[float] = []
    if position > 0:
        distances.append(timestamp_sec - ordered[position - 1])
    if position + 1 < len(ordered):
        distances.append(ordered[position + 1] - timestamp_sec)
    return any(distance <= VIDEO_SHORT_SHOT_GAP_SEC for distance in distances)


def _is_video_transition_suspicious(candidate: dict[str, object], audio_aligned: bool = False) -> bool:
    signals = candidate.get("signals")
    if not isinstance(signals, dict):
        return False

    freeze = (_as_float(signals.get("freeze_near_boundary")) or 0.0) >= 0.9
    dark = (_as_float(signals.get("black_or_dark_transition")) or 0.0) >= 0.9
    short_gap = (_as_float(signals.get("short_shot_gap")) or 0.0) >= 0.9
    aligned = audio_aligned or ((_as_float(signals.get("audio_track_alignment")) or 0.0) >= 0.9)
    confidence = _as_float(candidate.get("confidence")) or 0.0
    scene_score = _as_float(candidate.get("scene_score")) or 0.0

    if freeze and confidence >= 0.60:
        return True
    weak_confirmers = int(dark) + int(short_gap) + int(aligned)
    return scene_score >= 0.55 and confidence >= WARNING_SECONDARY_THRESHOLD and weak_confirmers >= 2


def _correlate_video_and_audio_track(
    video_result: object,
    audio_track_result: object,
    transition_pool: list[dict[str, object]] | None = None,
) -> dict[str, object] | None:
    if not isinstance(video_result, dict) or not isinstance(audio_track_result, dict):
        return None
    if video_result.get("status") == "unavailable" or audio_track_result.get("status") == "unavailable":
        return {"status": "unavailable", "match_count": 0, "matches": []}

    video_candidates = video_result.get("candidates")
    audio_candidates = audio_track_result.get("candidates")
    if not isinstance(video_candidates, list) or not isinstance(audio_candidates, list):
        return {"status": "none", "match_count": 0, "matches": []}

    candidate_by_timestamp = {
        round(_as_float(candidate.get("timestamp_sec")) or -1.0, 3): candidate
        for candidate in video_candidates
        if isinstance(candidate, dict)
    }
    transition_pool = transition_pool or []

    matches: list[dict[str, object]] = []
    for audio_candidate in audio_candidates:
        if not isinstance(audio_candidate, dict):
            continue
        audio_time = _as_float(audio_candidate.get("timestamp_sec"))
        if audio_time is None:
            continue

        nearest_transition: dict[str, object] | None = None
        nearest_delta: float | None = None
        for transition in transition_pool:
            transition_time = _as_float(transition.get("timestamp_sec"))
            if transition_time is None:
                continue
            delta = abs(transition_time - audio_time)
            if delta <= VIDEO_ALIGNMENT_TOLERANCE_SEC and (nearest_delta is None or delta < nearest_delta):
                nearest_transition = transition
                nearest_delta = delta

        for video_candidate in video_candidates:
            if not isinstance(video_candidate, dict):
                continue
            video_time = _as_float(video_candidate.get("timestamp_sec"))
            if video_time is None:
                continue
            delta = abs(video_time - audio_time)
            if delta <= VIDEO_ALIGNMENT_TOLERANCE_SEC and (nearest_delta is None or delta < nearest_delta):
                nearest_transition = video_candidate
                nearest_delta = delta

        if nearest_transition is None or nearest_delta is None:
            continue

        _apply_audio_alignment(nearest_transition)
        transition_time = round(_as_float(nearest_transition.get("timestamp_sec")) or 0.0, 3)
        public_candidate = candidate_by_timestamp.get(transition_time)
        if public_candidate is None and _is_video_transition_suspicious(nearest_transition, audio_aligned=True):
            public_candidate = _public_video_candidate(nearest_transition)
            video_candidates.append(public_candidate)
            candidate_by_timestamp[transition_time] = public_candidate
        elif public_candidate is not None:
            _apply_audio_alignment(public_candidate)

        matches.append(
            {
                "video_timestamp_sec": transition_time,
                "audio_timestamp_sec": round(audio_time, 3),
                "delta_sec": round(nearest_delta, 3),
            }
        )

    video_candidates.sort(key=lambda item: _as_float(item.get("timestamp_sec")) or 0.0)
    video_result["candidate_count"] = len(video_candidates)
    video_result["peak_confidence"] = round(
        max((_as_float(item.get("confidence")) or 0.0 for item in video_candidates if isinstance(item, dict)), default=0.0),
        4,
    )
    if video_result["candidate_count"] > 0:
        video_result["status"] = "suspicious"

    deduplicated_matches = _deduplicate_matches(matches)
    return {
        "status": "aligned" if deduplicated_matches else "none",
        "match_count": len(deduplicated_matches),
        "matches": deduplicated_matches[:TOP_CANDIDATE_LIMIT],
    }


def _apply_audio_alignment(candidate: dict[str, object]) -> None:
    signals = candidate.get("signals")
    if not isinstance(signals, dict):
        signals = {}
        candidate["signals"] = signals

    current_alignment = _as_float(signals.get("audio_track_alignment")) or 0.0
    if current_alignment < 1.0:
        signals["audio_track_alignment"] = 1.0
        candidate["confidence"] = round(min(1.0, (_as_float(candidate.get("confidence")) or 0.0) + 0.15), 4)
        candidate["aligned_audio_track"] = True
        candidate["reasons"] = _merge_reasons(
            candidate.get("reasons"),
            [SIGNAL_REASON_LABELS["audio_track_alignment"]],
        )


def _deduplicate_matches(matches: list[dict[str, object]]) -> list[dict[str, object]]:
    seen: set[tuple[float, float]] = set()
    result: list[dict[str, object]] = []
    for match in sorted(matches, key=lambda item: (item["video_timestamp_sec"], item["audio_timestamp_sec"])):
        key = (match["video_timestamp_sec"], match["audio_timestamp_sec"])
        if key in seen:
            continue
        seen.add(key)
        result.append(match)
    return result


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
    for modality_name in ("audio", "video", "video_audio_track"):
        modality = analysis.get(modality_name)
        if isinstance(modality, dict) and modality.get("status") == "unavailable":
            return "unavailable"
    return "clean"


def _build_findings(analysis: dict[str, object]) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_build_unavailability_findings(analysis))

    audio = analysis.get("audio")
    if isinstance(audio, dict) and _should_flag_modality(audio):
        findings.append(
            Finding(
                code="AUDIO_SPLICE_SUSPECTED",
                severity=Severity.WARNING,
                message="В аудиосигнале обнаружены подозрительные признаки монтажа.",
                details=_finding_details(audio),
            )
        )
    video = analysis.get("video")
    if isinstance(video, dict) and _should_flag_modality(video):
        findings.append(
            Finding(
                code="VIDEO_SEAM_SUSPECTED",
                severity=Severity.WARNING,
                message="В видеоряде обнаружены подозрительные признаки монтажной склейки.",
                details=_finding_details(video),
            )
        )
    video_audio = analysis.get("video_audio_track")
    if isinstance(video_audio, dict) and _should_flag_modality(video_audio):
        findings.append(
            Finding(
                code="VIDEO_AUDIO_TRACK_SPLICE_SUSPECTED",
                severity=Severity.WARNING,
                message="В аудиодорожке видео обнаружены подозрительные признаки монтажа.",
                details=_finding_details(video_audio),
            )
        )
    correlation = analysis.get("correlation")
    if isinstance(correlation, dict) and int(correlation.get("match_count", 0)) > 0:
        findings.append(
            Finding(
                code="VIDEO_AUDIO_SEAM_ALIGNMENT",
                severity=Severity.INFO,
                message="Подозрительные точки в видеоряде совпадают с разрывами в аудиодорожке.",
                details={"match_count": correlation["match_count"], "matches": correlation["matches"]},
            )
        )
    return findings


def _build_unavailability_findings(analysis: dict[str, object]) -> list[Finding]:
    reason_groups: dict[str, dict[str, object]] = {}
    for modality_name in ("audio", "video", "video_audio_track"):
        modality = analysis.get(modality_name)
        if not isinstance(modality, dict) or modality.get("status") != "unavailable":
            continue
        reason = _as_text(modality.get("reason"))
        if reason in (None, "no_audio_stream", "ffmpeg_not_available", "analysis_error"):
            continue
        group = reason_groups.setdefault(reason, {"modalities": [], "missing_dependencies": []})
        group["modalities"].append(modality_name)
        if isinstance(modality.get("missing_dependencies"), list):
            for dependency in modality["missing_dependencies"]:
                if dependency not in group["missing_dependencies"]:
                    group["missing_dependencies"].append(dependency)

    findings: list[Finding] = []
    for reason, payload in reason_groups.items():
        findings.append(
            Finding(
                code="SPLICE_ANALYSIS_UNAVAILABLE",
                severity=Severity.INFO,
                message=_unavailability_message(reason),
                details={
                    "reason": reason,
                    "modalities": payload["modalities"],
                    **({"missing_dependencies": payload["missing_dependencies"]} if payload["missing_dependencies"] else {}),
                },
            )
        )
    return findings


def _unavailability_message(reason: str) -> str:
    mapping = {
        "missing_audio_dependencies": "Для аудиоанализа склеек требуются numpy и pydub.",
        "missing_video_dependencies": "Для видеоанализа склеек требуются numpy и PySceneDetect.",
        "scene_detection_failed": "Не удалось выделить кандидаты смен сцен в видеоряде.",
    }
    return mapping.get(reason, "Анализ склеек сейчас недоступен.")


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
    details = {
        "candidate_count": int(modality.get("candidate_count", 0)),
        "peak_confidence": round(_as_float(modality.get("peak_confidence")) or 0.0, 4),
        "top_candidates": top_candidates,
    }
    content_profile = _as_text(modality.get("content_profile"))
    if content_profile:
        details["content_profile"] = content_profile
    scene_transition_count = modality.get("scene_transition_count")
    if isinstance(scene_transition_count, int):
        details["scene_transition_count"] = scene_transition_count
    return details


def _empty_modality_result(
    status: str,
    source: str,
    reason: str | None = None,
    *,
    missing_dependencies: list[str] | None = None,
) -> dict[str, object]:
    result: dict[str, object] = {
        "status": status,
        "source": source,
        "candidate_count": 0,
        "peak_confidence": 0.0,
        "candidates": [],
    }
    if reason:
        result["reason"] = reason
    if missing_dependencies:
        result["missing_dependencies"] = missing_dependencies
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

        previous["reasons"] = _merge_reasons(previous.get("reasons"), current.get("reasons"))

        previous_confidence = _as_float(previous.get("confidence")) or 0.0
        current_confidence = _as_float(current.get("confidence")) or 0.0
        if current_confidence > previous_confidence:
            previous["timestamp_sec"] = current.get("timestamp_sec")
            previous["window_sec"] = current.get("window_sec")
            previous["source"] = current.get("source")
            if "scene_score" in current:
                previous["scene_score"] = current.get("scene_score")
            if current.get("aligned_audio_track"):
                previous["aligned_audio_track"] = True
        previous["confidence"] = round(max(previous_confidence, current_confidence), 4)
    return merged


def _merge_reasons(left: object, right: object) -> list[str]:
    ordered: list[str] = []
    for collection in (left, right):
        if not isinstance(collection, list):
            continue
        for item in collection:
            text = _as_text(item)
            if text and text not in ordered:
                ordered.append(text)
    return ordered[:TOP_CANDIDATE_LIMIT]


def _candidate_reasons(signals: dict[str, float], top_n: int = 3) -> list[str]:
    sorted_signals = sorted(
        ((name, value) for name, value in signals.items() if value >= 0.35),
        key=lambda item: item[1],
        reverse=True,
    )
    reasons: list[str] = []
    for signal_name, _value in sorted_signals[:top_n]:
        label = SIGNAL_REASON_LABELS.get(signal_name, signal_name)
        if label not in reasons:
            reasons.append(label)
    return reasons


def _robust_normalize(values: Any) -> list[float]:
    if np is None:
        return []
    array = np.asarray(values, dtype=np.float32)
    if array.size == 0:
        return []
    if array.size == 1:
        return [1.0 if float(array[0]) > 0 else 0.0]
    median = float(np.median(array))
    mad = float(np.median(np.abs(array - median)))
    if mad <= 1e-9:
        maximum = float(np.max(array))
        if maximum <= 1e-9:
            return [0.0 for _ in range(int(array.size))]
        return [float(min(1.0, max(0.0, value / maximum))) for value in array]
    scale = mad * 1.4826
    z_scores = np.maximum(0.0, (array - median) / scale)
    return [float(value) for value in np.clip(z_scores / 6.0, 0.0, 1.0)]


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


def _missing_python_dependencies(mode: str) -> list[str]:
    checks = {
        "numpy": np is not None,
        "pydub": AudioSegment is not None and detect_silence is not None,
        "scenedetect": SceneManager is not None and ContentDetector is not None and open_video is not None,
    }
    return [name for name in PYTHON_DEPENDENCIES.get(mode, ()) if not checks.get(name, False)]


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
