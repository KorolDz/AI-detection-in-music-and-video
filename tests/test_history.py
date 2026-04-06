from pathlib import Path

from media_security.service import SecurityAnalysisService


def test_history_detects_file_change(tmp_path: Path) -> None:
    media_file = tmp_path / "sample.mp3"
    sqlite_path = tmp_path / "history.sqlite3"
    media_file.write_bytes(bytes.fromhex("FFFB9064") + b"\x00" * 512)

    service = SecurityAnalysisService.with_sqlite(sqlite_path)
    first_report = service.analyze_path(media_file)[0]
    assert first_report.scan_id is not None

    media_file.write_bytes(bytes.fromhex("FFFB9064") + b"\x11" * 600)
    second_report = service.analyze_path(media_file)[0]
    codes = {finding.code for finding in second_report.findings}

    assert second_report.scan_id is not None
    assert "FILE_CHANGED_SINCE_LAST_SCAN" in codes
    assert second_report.verdict in {"warning", "fail"}
    assert second_report.trust_score < first_report.trust_score


def test_history_marks_known_hash_for_same_path(tmp_path: Path) -> None:
    media_file = tmp_path / "sample.mp3"
    sqlite_path = tmp_path / "history.sqlite3"
    media_file.write_bytes(bytes.fromhex("FFFB9064") + b"\x00" * 256)

    service = SecurityAnalysisService.with_sqlite(sqlite_path)
    service.analyze_path(media_file)
    second_report = service.analyze_path(media_file)[0]
    codes = {finding.code for finding in second_report.findings}

    assert "KNOWN_FILE_HASH" in codes
