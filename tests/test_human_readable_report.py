from __future__ import annotations

from pathlib import Path

from media_security.cli import main
from media_security.core.models import FileMetadata, Finding, ScanReport, Severity
from media_security.reporting import render_markdown_report


def test_render_markdown_report_for_single_file_includes_key_sections() -> None:
    report = _build_sample_report()

    markdown = render_markdown_report(report.file, [report])

    assert "# Отчёт по анализу медиафайлов" in markdown
    assert "## Итог анализа" in markdown
    assert "### Ключевые проблемы" in markdown
    assert "### Основные метаданные" in markdown
    assert "### Криминалистические признаки" in markdown
    assert "### Склейки и швы" in markdown
    assert "### Рекомендация" in markdown
    assert "Apple iPhone X" in markdown
    assert "DaVinci Resolve" in markdown
    assert "43 deg 46' 9.84" in markdown
    assert "Аудиодорожка видео" in markdown
    assert "VIDEO_AUDIO_TRACK_SPLICE_SUSPECTED" in markdown
    assert "format_tags" not in markdown
    assert "stream_tags" not in markdown
    assert "\"available\"" not in markdown


def test_render_markdown_report_for_unsupported_format_is_minimal() -> None:
    report = ScanReport(
        file=r"H:\Detection\AI-detection-in-music-and-video\datasets\unsupported\note.txt",
        supported=False,
        verdict="fail",
        findings=[
            Finding(
                code="UNSUPPORTED_EXTENSION",
                severity=Severity.HIGH,
                message="Unsupported extension '.txt'.",
            )
        ],
        trust_score=0,
        risk_level="critical",
    )

    markdown = render_markdown_report(report.file, [report])

    assert "Файл не соответствует поддерживаемым форматам" in markdown
    assert "### Основные метаданные" not in markdown
    assert "### Склейки и швы" not in markdown


def test_render_markdown_report_for_directory_lists_suspicious_files_first() -> None:
    suspicious_report = _build_sample_report(
        file_path=r"H:\Detection\AI-detection-in-music-and-video\datasets\video\suspicious.mp4",
        verdict="fail",
        risk_level="high",
        trust_score=45,
        findings=[
            Finding(
                code="VIDEO_SEAM_SUSPECTED",
                severity=Severity.HIGH,
                message="Suspicious seam markers detected in the video stream.",
            )
        ],
    )
    warning_report = _build_sample_report(
        file_path=r"H:\Detection\AI-detection-in-music-and-video\datasets\audio\warning.wav",
        verdict="warning",
        risk_level="medium",
        trust_score=70,
        findings=[
            Finding(
                code="EDITING_SOFTWARE_METADATA_MARKER",
                severity=Severity.WARNING,
                message="Metadata contains markers of editing, transcoding, or downloader software.",
            )
        ],
    )
    pass_report = _build_sample_report(
        file_path=r"H:\Detection\AI-detection-in-music-and-video\datasets\audio\clean.wav",
        verdict="pass",
        risk_level="low",
        trust_score=100,
        findings=[],
    )

    markdown = render_markdown_report(
        r"H:\Detection\AI-detection-in-music-and-video\datasets",
        [pass_report, warning_report, suspicious_report],
    )

    suspicious_index = markdown.index("suspicious.mp4")
    warning_index = markdown.index("warning.wav")
    pass_index = markdown.index("clean.wav")

    assert "## Общая сводка" in markdown
    assert "## Подозрительные файлы" in markdown
    assert suspicious_index < warning_index < pass_index


def test_cli_can_request_markdown_and_json_outputs_together(monkeypatch, capsys) -> None:
    report = _build_sample_report(
        file_path=r"H:\Detection\AI-detection-in-music-and-video\datasets\audio\clean.wav",
        verdict="pass",
        risk_level="low",
        trust_score=100,
        findings=[],
    )

    class _DummyService:
        def analyze_path(self, target: str, recursive: bool, persist_history: bool) -> list[ScanReport]:
            assert recursive is False
            assert persist_history is False
            return [report]

    class _DummySecurityAnalysisService:
        @staticmethod
        def without_history() -> _DummyService:
            return _DummyService()

    written: dict[str, object] = {}

    def _capture_markdown(output_path: Path, target: str, reports: list[ScanReport]) -> None:
        written["report_out"] = str(output_path)
        written["report_target"] = target
        written["report_count"] = len(reports)

    def _capture_json(output_path: Path, target: str, reports: list[ScanReport]) -> None:
        written["json_out"] = str(output_path)
        written["json_target"] = target
        written["json_count"] = len(reports)

    monkeypatch.setattr("media_security.cli._setup_external_tools", lambda **_kwargs: None)
    monkeypatch.setattr("media_security.cli.SecurityAnalysisService", _DummySecurityAnalysisService)
    monkeypatch.setattr("media_security.cli.write_markdown_report", _capture_markdown)
    monkeypatch.setattr("media_security.cli._write_json_report", _capture_json)

    exit_code = main(
        [
            report.file,
            "--no-history",
            "--report-out",
            "reports/file_report.md",
            "--json-out",
            "reports/file_report.json",
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 0
    assert written["report_out"].endswith("reports\\file_report.md")
    assert written["json_out"].endswith("reports\\file_report.json")
    assert written["report_target"] == report.file
    assert written["json_target"] == report.file
    assert "# Отчёт по анализу медиафайлов" in captured.out
    assert "Markdown report written to:" in captured.out
    assert "JSON report written to:" in captured.out


def _build_sample_report(
    file_path: str = r"H:\Detection\AI-detection-in-music-and-video\datasets\video\sample.mp4",
    verdict: str = "warning",
    risk_level: str = "medium",
    trust_score: int = 70,
    findings: list[Finding] | None = None,
) -> ScanReport:
    metadata = FileMetadata(
        path=file_path,
        name=Path(file_path).name,
        extension=Path(file_path).suffix.lstrip("."),
        media_type="video",
        detected_format="mp4",
        size_bytes=128_000_000,
        mime_type="video/mp4",
        hashes={"sha256": "a" * 64, "md5": "b" * 32},
        timestamps_utc={
            "created_at": "2026-04-05T16:41:02+00:00",
            "modified_at": "2026-04-05T16:41:52+00:00",
            "accessed_at": "2026-04-05T20:01:27+00:00",
        },
        signature={"container": "ISO-BMFF", "major_brand": "isom"},
        technical={
            "metadata_hints": {
                "source_device": "Apple iPhone X",
                "device_model": "iPhone X",
                "editing_software": "DaVinci Resolve",
                "recorded_at": "2022-05-20T08:41:04Z",
                "location": "43 deg 46' 9.84\" N, 11 deg 15' 19.80\" E",
            },
            "metadata_forensics": {
                "sources_present": ["ffprobe", "exiftool"],
                "hardware_markers_present": True,
                "editing_markers": [
                    "exiftool:editing_software=DaVinci Resolve",
                    "xmp:creator_tool=DaVinci Resolve",
                ],
                "xmp": {"present": True},
                "metadata_edit_timeline": {
                    "status": "modified_after_recording",
                    "modified_at_utc": "2026-04-05T16:41:52+00:00",
                },
            },
            "exiftool": {
                "available": True,
                "high_value": {
                    "gps_coordinates": "43 deg 46' 9.84\" N, 11 deg 15' 19.80\" E, 48.329 m Above Sea Level",
                    "software_version": "DaVinci Resolve",
                },
            },
            "splice_analysis": {
                "status": "suspicious",
                "summary": {
                    "candidate_count": 2,
                    "peak_confidence": 0.85,
                    "top_timestamps_sec": [0.75, 0.70],
                },
                "audio": {
                    "status": "clean",
                    "candidate_count": 0,
                    "peak_confidence": 0.0,
                    "candidates": [],
                },
                "video": {
                    "status": "suspicious",
                    "candidate_count": 1,
                    "peak_confidence": 0.85,
                    "candidates": [
                        {"timestamp_sec": 0.75, "confidence": 0.85},
                    ],
                },
                "video_audio_track": {
                    "status": "suspicious",
                    "candidate_count": 1,
                    "peak_confidence": 0.79,
                    "candidates": [
                        {"timestamp_sec": 0.70, "confidence": 0.79},
                    ],
                },
                "correlation": {
                    "status": "aligned",
                    "match_count": 1,
                    "matches": [
                        {
                            "video_timestamp_sec": 0.75,
                            "audio_timestamp_sec": 0.70,
                            "delta_sec": 0.05,
                        }
                    ],
                },
            },
        },
    )

    resolved_findings = findings if findings is not None else [
        Finding(
            code="EDITING_SOFTWARE_METADATA_MARKER",
            severity=Severity.WARNING,
            message="Metadata contains markers of editing, transcoding, or downloader software.",
        ),
        Finding(
            code="VIDEO_AUDIO_TRACK_SPLICE_SUSPECTED",
            severity=Severity.WARNING,
            message="Suspicious splice markers detected in the audio track of the video.",
        ),
    ]

    return ScanReport(
        file=file_path,
        supported=True,
        verdict=verdict,
        trust_score=trust_score,
        risk_level=risk_level,
        scan_id=12,
        findings=resolved_findings,
        metadata=metadata,
    )
