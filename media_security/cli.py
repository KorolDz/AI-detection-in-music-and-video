from __future__ import annotations

import argparse
import copy
import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from media_security.core.models import ScanReport, Severity
from media_security.external_tools import missing_external_tools
from media_security.service import SecurityAnalysisService
from media_security.storage.sqlite_config import resolve_sqlite_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="media-security-scan",
        description="Scan media files for metadata integrity and anomalies.",
    )
    parser.add_argument("path", help="Target file or directory path.")
    parser.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        help="Recursively scan files in directory.",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        help="Write full report to JSON file.",
    )
    parser.add_argument(
        "--fail-on-warning",
        action="store_true",
        help="Return non-zero exit code when warning findings exist.",
    )
    parser.add_argument(
        "--sqlite-path",
        type=Path,
        help=(
            "SQLite history database path. If omitted, CLI uses MEDIA_SECURITY_SQLITE_PATH "
            "or a secure per-user local path."
        ),
    )
    parser.add_argument(
        "--no-history",
        action="store_true",
        help="Disable storing scan history in database.",
    )
    parser.add_argument(
        "--no-tool-setup",
        action="store_true",
        help="Skip ffprobe/exiftool pre-scan setup.",
    )
    parser.add_argument(
        "--no-auto-install-tools",
        action="store_true",
        help="Check external tools, but do not auto-install missing ones.",
    )
    parser.add_argument(
        "--require-external-tools",
        action="store_true",
        help="Fail startup when ffprobe/exiftool are unavailable.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        _setup_external_tools(
            skip_setup=args.no_tool_setup,
            no_auto_install=args.no_auto_install_tools,
            require_external=args.require_external_tools,
        )
        sqlite_path = None if args.no_history else resolve_sqlite_path(args.sqlite_path)
        service = (
            SecurityAnalysisService.without_history()
            if args.no_history
            else SecurityAnalysisService.with_sqlite(sqlite_path)
        )
        reports = service.analyze_path(
            target=args.path,
            recursive=args.recursive,
            persist_history=not args.no_history,
        )
    except Exception as exc:  # noqa: BLE001 - CLI should return readable error.
        print(f"Scan startup error: {exc}")
        return 2

    if not reports:
        print("No files found for scanning.")
        return 1

    _print_reports(reports)
    if not args.no_history:
        print(f"History DB: SQLite ({sqlite_path})")

    if args.json_out:
        _write_json_report(args.json_out, args.path, reports)
        print(f"JSON report written to: {args.json_out}")

    has_fail = any(report.verdict == "fail" for report in reports)
    has_warning = any(
        any(finding.severity == Severity.WARNING for finding in report.findings)
        for report in reports
    )
    if has_fail:
        return 1
    if args.fail_on_warning and has_warning:
        return 1
    return 0


def _print_reports(reports: list[ScanReport]) -> None:
    for report in reports:
        score = f"score={report.trust_score:3d}"
        risk = f"risk={report.risk_level}"
        scan_ref = f"scan_id={report.scan_id}" if report.scan_id is not None else "scan_id=-"
        print(f"{report.verdict.upper():7} {score} {risk:14} {scan_ref:12} {report.file}")
        for finding in report.findings:
            print(f"  - {finding.severity.value.upper():7} {finding.code}: {finding.message}")

    total = len(reports)
    passed = sum(1 for report in reports if report.verdict == "pass")
    warnings = sum(1 for report in reports if report.verdict == "warning")
    failed = sum(1 for report in reports if report.verdict == "fail")
    print("")
    print(f"Summary: total={total}, pass={passed}, warning={warnings}, fail={failed}")


def _write_json_report(output_path: Path, target: str, reports: list[ScanReport]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    resolved_target = str(Path(target).resolve())
    report_items = [_report_to_json_dict(report) for report in reports]
    if len(report_items) == 1 and report_items[0].get("path") == resolved_target:
        report_items[0].pop("path", None)

    payload = {
        "generated_at_utc": datetime.now(tz=UTC).isoformat(),
        "target": resolved_target,
        "reports": report_items,
    }
    output_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def _report_to_json_dict(report: ScanReport) -> dict[str, object]:
    report_path = str(Path(report.file).resolve())
    if _is_unsupported_format_report(report):
        return {
            "path": report_path,
            "supported": False,
            "message": "unsupported format",
        }

    metadata_dict = report.metadata.to_dict() if report.metadata else None
    if metadata_dict is not None:
        metadata_dict.pop("path", None)
        metadata_dict = _compact_metadata_for_json(
            report_path=report_path,
            metadata_dict=metadata_dict,
        )
    return {
        "path": report_path,
        "supported": report.supported,
        "verdict": report.verdict,
        "trust_score": report.trust_score,
        "risk_level": report.risk_level,
        "scan_id": report.scan_id,
        "findings": [finding.to_dict() for finding in report.findings],
        "metadata": metadata_dict,
    }


def _compact_metadata_for_json(report_path: str, metadata_dict: dict[str, object]) -> dict[str, object]:
    result = copy.deepcopy(metadata_dict)

    path_obj = Path(report_path)
    expected_name = path_obj.name
    expected_extension = path_obj.suffix.lower().lstrip(".")

    if result.get("name") == expected_name:
        result.pop("name", None)
    if result.get("extension") == expected_extension:
        result.pop("extension", None)

    extension_value = result.get("extension")
    detected_format = result.get("detected_format")
    if isinstance(extension_value, str) and isinstance(detected_format, str):
        if detected_format == extension_value:
            result.pop("detected_format", None)
    elif isinstance(detected_format, str) and detected_format == expected_extension:
        result.pop("detected_format", None)

    signature = result.get("signature")
    technical = result.get("technical")
    if isinstance(signature, dict) and isinstance(technical, dict):
        signature_major_brand = signature.get("major_brand")
        technical_major_brand = technical.get("major_brand")
        if signature_major_brand and technical_major_brand and signature_major_brand == technical_major_brand:
            technical.pop("major_brand", None)

        raw_hints = copy.deepcopy(technical.get("metadata_hints")) if isinstance(technical.get("metadata_hints"), dict) else {}
        hints = _compact_metadata_hints_for_json(technical.get("metadata_hints"))
        if hints:
            technical["metadata_hints"] = hints
        else:
            technical.pop("metadata_hints", None)

        if isinstance(hints, dict):
            if hints.get("source_device") == technical.get("source_device_hint"):
                technical.pop("source_device_hint", None)
                technical.pop("source_device_hint_source", None)
            if hints.get("editing_software") == technical.get("editing_software_hint"):
                technical.pop("editing_software_hint", None)
                technical.pop("editing_software_hint_source", None)
            if hints.get("recorded_at") == technical.get("recorded_at_hint"):
                technical.pop("recorded_at_hint", None)

        ffprobe = _compact_ffprobe_for_json(technical.get("ffprobe"))
        if ffprobe is not None:
            technical["ffprobe"] = ffprobe
        else:
            technical.pop("ffprobe", None)

        exiftool = _compact_exiftool_for_json(
            exiftool=technical.get("exiftool"),
            metadata_hints=raw_hints if isinstance(raw_hints, dict) else {},
            ffprobe=ffprobe if isinstance(ffprobe, dict) else {},
        )
        if exiftool is not None:
            technical["exiftool"] = exiftool
        else:
            technical.pop("exiftool", None)

    return _drop_empty_containers(result)


def _is_unsupported_format_report(report: ScanReport) -> bool:
    return (not report.supported) and any(finding.code == "UNSUPPORTED_EXTENSION" for finding in report.findings)


def _compact_metadata_hints_for_json(hints: object) -> dict[str, object] | None:
    if not isinstance(hints, dict):
        return None

    result = copy.deepcopy(hints)
    source_device = str(result.get("source_device", "")).lower()
    device_make = result.get("device_make")
    device_model = result.get("device_model")

    if source_device:
        if isinstance(device_make, str) and device_make.lower() in source_device:
            result.pop("device_make", None)
        if isinstance(device_model, str) and device_model.lower() in source_device:
            result.pop("device_model", None)

    if result.get("editing_software") == result.get("os_version"):
        result.pop("editing_software", None)

    cleaned = _drop_empty_containers(result)
    return cleaned if isinstance(cleaned, dict) and cleaned else None


def _compact_ffprobe_for_json(ffprobe: object) -> dict[str, object] | None:
    if not isinstance(ffprobe, dict):
        return None

    result = copy.deepcopy(ffprobe)
    result.pop("format_tags", None)
    result.pop("stream_tags", None)

    cleaned = _drop_empty_containers(result)
    return cleaned if isinstance(cleaned, dict) and cleaned else None


def _compact_exiftool_for_json(
    exiftool: object,
    metadata_hints: dict[str, object],
    ffprobe: dict[str, object],
) -> dict[str, object] | None:
    if not isinstance(exiftool, dict):
        return None

    result = copy.deepcopy(exiftool)
    result.pop("tags", None)

    high_value = result.get("high_value")
    if isinstance(high_value, dict):
        compact_high_value = _compact_exiftool_high_value_for_json(
            high_value=high_value,
            metadata_hints=metadata_hints,
            ffprobe=ffprobe,
        )
        if compact_high_value:
            result["high_value"] = compact_high_value
        else:
            result.pop("high_value", None)

    cleaned = _drop_empty_containers(result)
    return cleaned if isinstance(cleaned, dict) and cleaned else None


def _compact_exiftool_high_value_for_json(
    high_value: dict[str, object],
    metadata_hints: dict[str, object],
    ffprobe: dict[str, object],
) -> dict[str, object]:
    result = copy.deepcopy(high_value)

    if result.get("source_device") == metadata_hints.get("source_device"):
        result.pop("source_device", None)
    if result.get("device_make") == metadata_hints.get("device_make"):
        result.pop("device_make", None)
    if result.get("device_model") == metadata_hints.get("device_model"):
        result.pop("device_model", None)
    if result.get("os_version") == metadata_hints.get("os_version"):
        result.pop("os_version", None)
    if result.get("os_version") == metadata_hints.get("editing_software"):
        result.pop("os_version", None)
    if result.get("software_version") == metadata_hints.get("editing_software"):
        result.pop("software_version", None)
    if _timestamps_match(result.get("recorded_at"), metadata_hints.get("recorded_at")):
        result.pop("recorded_at", None)
    if result.get("gps_coordinates") == metadata_hints.get("location"):
        result.pop("gps_coordinates", None)

    if result.get("software_version") == result.get("os_version"):
        result.pop("software_version", None)

    source_device_text = str(metadata_hints.get("source_device", "")).lower()
    device_make = result.get("device_make")
    device_model = result.get("device_model")
    if source_device_text:
        if isinstance(device_make, str) and device_make.lower() in source_device_text:
            result.pop("device_make", None)
        if isinstance(device_model, str) and device_model.lower() in source_device_text:
            result.pop("device_model", None)

    resolution = result.get("resolution")
    ffprobe_width = ffprobe.get("width")
    ffprobe_height = ffprobe.get("height")
    if isinstance(resolution, str) and ffprobe_width and ffprobe_height:
        if resolution == f"{ffprobe_width}x{ffprobe_height}":
            result.pop("resolution", None)

    duration = _extract_numeric_prefix(result.get("duration"))
    ffprobe_duration = _extract_numeric_prefix(ffprobe.get("duration_sec"))
    if duration is not None and ffprobe_duration is not None and abs(duration - ffprobe_duration) < 0.05:
        result.pop("duration", None)

    capture_fps = _extract_numeric_prefix(result.get("capture_fps"))
    avg_frame_rate = _extract_numeric_prefix(ffprobe.get("avg_frame_rate"))
    if capture_fps is not None and avg_frame_rate is not None and abs(capture_fps - avg_frame_rate) < 0.05:
        result.pop("capture_fps", None)

    if _codec_matches(result.get("video_codec"), ffprobe.get("video_codecs")):
        result.pop("video_codec", None)
    if _codec_matches(result.get("audio_codec"), ffprobe.get("audio_codecs")):
        result.pop("audio_codec", None)

    if result.get("gps_coordinates"):
        result.pop("gps_latitude", None)
        result.pop("gps_longitude", None)
        result.pop("gps_altitude", None)

    return _drop_empty_containers(result)


def _codec_matches(codec_value: object, codec_list: object) -> bool:
    if not isinstance(codec_value, str) or not isinstance(codec_list, list) or len(codec_list) != 1:
        return False
    only_codec = codec_list[0]
    return isinstance(only_codec, str) and only_codec.lower() == codec_value.lower()


def _extract_numeric_prefix(value: object) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    if not isinstance(value, str):
        return None

    text = value.strip().replace(",", ".")
    numeric_chars: list[str] = []
    for char in text:
        if char.isdigit() or char == ".":
            numeric_chars.append(char)
            continue
        if numeric_chars:
            break
    if not numeric_chars:
        return None

    try:
        return float("".join(numeric_chars))
    except ValueError:
        return None


def _timestamps_match(left: object, right: object) -> bool:
    left_dt = _parse_metadata_timestamp(left)
    right_dt = _parse_metadata_timestamp(right)
    if left_dt is not None and right_dt is not None:
        if left_dt.tzinfo is None and right_dt.tzinfo is not None:
            return left_dt == right_dt.astimezone(UTC).replace(tzinfo=None)
        if left_dt.tzinfo is not None and right_dt.tzinfo is None:
            return left_dt.astimezone(UTC).replace(tzinfo=None) == right_dt
        return left_dt == right_dt
    return left == right


def _parse_metadata_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None

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
        return parsed
    return parsed.astimezone(UTC)


def _drop_empty_containers(value: object) -> object:
    if isinstance(value, dict):
        cleaned: dict[str, object] = {}
        for key, item in value.items():
            compact_item = _drop_empty_containers(item)
            if compact_item in ({}, []):
                continue
            cleaned[key] = compact_item
        return cleaned
    if isinstance(value, list):
        cleaned_list = [_drop_empty_containers(item) for item in value]
        return [item for item in cleaned_list if item not in ({}, [])]
    return value


def _setup_external_tools(skip_setup: bool, no_auto_install: bool, require_external: bool) -> None:
    if skip_setup:
        return

    tools = ("ffprobe", "exiftool")
    missing = missing_external_tools(tools)
    if not missing:
        return

    tools_script = Path(__file__).resolve().parents[1] / "scripts" / "check_external_tools.ps1"

    if os.name == "nt" and tools_script.exists():
        command = [
            "powershell",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(tools_script),
        ]
        if not no_auto_install:
            command.append("-InstallMissing")
        if require_external:
            command.append("-Strict")

        subprocess.run(command, check=False)
        missing = missing_external_tools(tools)
        if require_external and missing:
            raise RuntimeError(
                "External tools check failed. Install ffprobe/exiftool or run without --require-external-tools."
            )
        return

    if require_external and missing:
        raise RuntimeError(
            "Missing external tools: "
            + ", ".join(missing)
            + ". Install them or run without --require-external-tools."
        )


if __name__ == "__main__":
    raise SystemExit(main())
