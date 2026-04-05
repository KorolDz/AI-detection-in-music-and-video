from pathlib import Path
import wave

from media_security.core.scanner import MediaSecurityScanner


def test_scan_valid_wav_file(tmp_path: Path) -> None:
    sample = tmp_path / "sample.wav"
    _create_wav_file(sample)

    report = MediaSecurityScanner().scan_file(sample)
    assert report.supported is True
    assert report.verdict == "pass"
    assert report.trust_score == 100
    assert report.risk_level == "low"
    assert report.metadata is not None
    assert report.metadata.detected_format == "wav"
    assert report.metadata.technical["sample_rate_hz"] == 8000


def test_detect_extension_signature_mismatch(tmp_path: Path) -> None:
    fake = tmp_path / "fake.wav"
    fake.write_bytes(b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00")

    report = MediaSecurityScanner().scan_file(fake)
    codes = {finding.code for finding in report.findings}
    assert report.verdict == "fail"
    assert "EXTENSION_SIGNATURE_MISMATCH" in codes


def test_unsupported_extension(tmp_path: Path) -> None:
    unknown = tmp_path / "note.txt"
    unknown.write_text("example", encoding="utf-8")

    report = MediaSecurityScanner().scan_file(unknown)
    codes = {finding.code for finding in report.findings}
    assert report.supported is False
    assert "UNSUPPORTED_EXTENSION" in codes


def _create_wav_file(path: Path) -> None:
    with wave.open(str(path), "wb") as wav_file:
        wav_file.setnchannels(1)
        wav_file.setsampwidth(2)
        wav_file.setframerate(8000)
        wav_file.writeframes(b"\x00\x00" * 8000)
