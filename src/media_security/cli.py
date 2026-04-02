from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

from media_security.models import ScanReport, Severity
from media_security.scanner import MediaSecurityScanner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="media-security-scan",
        description="Scan media files for metadata integrity and security anomalies.",
    )
    parser.add_argument("path", help="Target file or directory path.")
    parser.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        help="Recursively scan files if the target is a directory.",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        help="Write full scan report to a JSON file.",
    )
    parser.add_argument(
        "--fail-on-warning",
        action="store_true",
        help="Return non-zero exit code when warning findings are present.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    scanner = MediaSecurityScanner()
    reports = scanner.scan_path(args.path, recursive=args.recursive)
    if not reports:
        print("No files found for scanning.")
        return 1

    _print_reports(reports)
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
        print(f"{report.verdict.upper():7} {report.file}")
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
    payload = {
        "generated_at_utc": datetime.now(tz=UTC).isoformat(),
        "target": str(Path(target).resolve()),
        "reports": [report.to_dict() for report in reports],
    }
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
