from __future__ import annotations

from pathlib import Path
from typing import Iterable

from media_security.constants import (
    LARGE_FILE_WARNING_BYTES,
    MAX_SIGNATURE_BYTES,
    MIME_BY_EXTENSION,
    SUPPORTED_EXTENSIONS,
    SUPPORTED_MEDIA_EXTENSIONS,
)
from media_security.extractors import (
    compute_hashes,
    extract_file_timestamps,
    extract_mp3_metadata,
    extract_video_metadata,
    extract_wav_metadata,
    guess_mime_type,
    read_header,
)
from media_security.models import FileMetadata, Finding, ScanReport, Severity
from media_security.signatures import detect_format_from_signature, is_signature_compatible


class MediaSecurityScanner:
    def scan_path(self, target: str | Path, recursive: bool = False) -> list[ScanReport]:
        path = Path(target)
        if path.is_file():
            return [self.scan_file(path)]
        if not path.is_dir():
            return [
                ScanReport(
                    file=str(path),
                    supported=False,
                    verdict="fail",
                    findings=[
                        Finding(
                            code="PATH_NOT_FOUND",
                            severity=Severity.HIGH,
                            message="Target file or directory does not exist.",
                        )
                    ],
                )
            ]

        files = self._iter_files(path, recursive=recursive)
        return [self.scan_file(file_path) for file_path in files]

    def scan_file(self, file_path: str | Path) -> ScanReport:
        path = Path(file_path)
        if not path.exists() or not path.is_file():
            return ScanReport(
                file=str(path),
                supported=False,
                verdict="fail",
                findings=[
                    Finding(
                        code="FILE_NOT_FOUND",
                        severity=Severity.HIGH,
                        message="File does not exist or is not a regular file.",
                    )
                ],
            )

        extension = path.suffix.lower().strip(".")
        supported = extension in SUPPORTED_EXTENSIONS
        media_type = _media_type_for_extension(extension)
        findings: list[Finding] = []

        if not supported:
            findings.append(
                Finding(
                    code="UNSUPPORTED_EXTENSION",
                    severity=Severity.HIGH,
                    message=f"Unsupported extension '.{extension or 'none'}'.",
                    details={"supported_extensions": sorted(SUPPORTED_EXTENSIONS)},
                )
            )

        file_size = path.stat().st_size
        if file_size == 0:
            findings.append(
                Finding(
                    code="EMPTY_FILE",
                    severity=Severity.HIGH,
                    message="File is empty.",
                )
            )
        elif file_size >= LARGE_FILE_WARNING_BYTES:
            findings.append(
                Finding(
                    code="LARGE_FILE",
                    severity=Severity.WARNING,
                    message="File is very large and should be processed in a controlled environment.",
                    details={"size_bytes": file_size},
                )
            )

        header = read_header(path, MAX_SIGNATURE_BYTES)
        signature_result = detect_format_from_signature(header)
        detected_format = signature_result.detected_format

        if detected_format is None:
            findings.append(
                Finding(
                    code="UNKNOWN_SIGNATURE",
                    severity=Severity.HIGH,
                    message="File signature does not match known supported media containers.",
                )
            )
        elif supported and not is_signature_compatible(extension, detected_format):
            findings.append(
                Finding(
                    code="EXTENSION_SIGNATURE_MISMATCH",
                    severity=Severity.HIGH,
                    message="Extension and binary signature do not match.",
                    details={"extension": extension, "detected_format": detected_format},
                )
            )

        mime_type = guess_mime_type(path)
        expected_mime = MIME_BY_EXTENSION.get(extension, set())
        if supported and mime_type and expected_mime and mime_type not in expected_mime:
            findings.append(
                Finding(
                    code="MIME_MISMATCH",
                    severity=Severity.WARNING,
                    message="MIME type does not match expected values for this extension.",
                    details={"mime_type": mime_type, "expected_mime": sorted(expected_mime)},
                )
            )

        timestamps = extract_file_timestamps(path)
        if timestamps["created_at"] > timestamps["modified_at"]:
            findings.append(
                Finding(
                    code="TIMESTAMP_ANOMALY",
                    severity=Severity.WARNING,
                    message="Creation timestamp is newer than modification timestamp.",
                    details=timestamps,
                )
            )

        technical_metadata: dict[str, object] = {}
        extractor_format = detected_format or extension
        technical_metadata, extraction_finding = self._extract_technical_metadata(path, extractor_format)
        if extraction_finding:
            findings.append(extraction_finding)

        hashes = compute_hashes(path)
        metadata = FileMetadata(
            path=str(path.resolve()),
            name=path.name,
            extension=extension,
            media_type=media_type,
            detected_format=detected_format,
            size_bytes=file_size,
            mime_type=mime_type,
            hashes=hashes,
            timestamps_utc=timestamps,
            signature=signature_result.details,
            technical=technical_metadata,
        )
        verdict = _choose_verdict(findings)
        return ScanReport(
            file=str(path),
            supported=supported,
            verdict=verdict,
            findings=findings,
            metadata=metadata,
        )

    def _extract_technical_metadata(
        self, path: Path, file_format: str
    ) -> tuple[dict[str, object], Finding | None]:
        try:
            if file_format == "wav":
                technical = extract_wav_metadata(path)
            elif file_format == "mp3":
                technical = extract_mp3_metadata(path)
            elif file_format in {"mp4", "avi", "mov"}:
                technical = extract_video_metadata(path, expected_format=file_format)
            else:
                return {}, None
        except Exception as exc:  # noqa: BLE001 - we need robust scanner behavior.
            return {}, Finding(
                code="METADATA_PARSE_ERROR",
                severity=Severity.HIGH,
                message="Unable to extract technical metadata from file.",
                details={"error": str(exc), "format": file_format},
            )

        validation_finding = _validate_technical_metadata(file_format, technical)
        return technical, validation_finding

    @staticmethod
    def _iter_files(path: Path, recursive: bool) -> list[Path]:
        iterator: Iterable[Path] = path.rglob("*") if recursive else path.glob("*")
        files = [item for item in iterator if item.is_file()]
        return sorted(files, key=lambda item: str(item).lower())


def scan_path(target: str | Path, recursive: bool = False) -> list[ScanReport]:
    return MediaSecurityScanner().scan_path(target=target, recursive=recursive)


def _media_type_for_extension(extension: str) -> str | None:
    for media_type, extensions in SUPPORTED_MEDIA_EXTENSIONS.items():
        if extension in extensions:
            return media_type
    return None


def _choose_verdict(findings: list[Finding]) -> str:
    if any(finding.severity == Severity.HIGH for finding in findings):
        return "fail"
    if any(finding.severity == Severity.WARNING for finding in findings):
        return "warning"
    return "pass"


def _validate_technical_metadata(file_format: str, technical: dict[str, object]) -> Finding | None:
    if file_format == "wav":
        sample_rate = technical.get("sample_rate_hz")
        duration = technical.get("duration_sec")
        if not isinstance(sample_rate, int) or sample_rate <= 0:
            return Finding(
                code="INVALID_WAV_SAMPLE_RATE",
                severity=Severity.HIGH,
                message="WAV metadata contains invalid sample rate.",
            )
        if not isinstance(duration, (int, float)) or duration <= 0:
            return Finding(
                code="INVALID_WAV_DURATION",
                severity=Severity.HIGH,
                message="WAV metadata contains invalid duration.",
            )

    if file_format == "mp3":
        has_frame = "bitrate_kbps" in technical and "sample_rate_hz" in technical
        if not has_frame:
            return Finding(
                code="MP3_FRAME_NOT_FOUND",
                severity=Severity.HIGH,
                message="Could not detect a valid MPEG frame header.",
            )

    if file_format in {"mp4", "mov"}:
        major_brand = technical.get("major_brand")
        if not isinstance(major_brand, str) or not major_brand:
            return Finding(
                code="INVALID_ISO_BMFF_HEADER",
                severity=Severity.HIGH,
                message="Could not extract ISO-BMFF header metadata.",
            )

    if file_format == "avi":
        container = technical.get("container")
        if container != "RIFF/AVI":
            return Finding(
                code="INVALID_AVI_HEADER",
                severity=Severity.HIGH,
                message="Could not extract AVI RIFF metadata.",
            )

    return None
