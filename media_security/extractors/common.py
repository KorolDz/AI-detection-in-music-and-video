from __future__ import annotations

import hashlib
import mimetypes
from datetime import UTC, datetime
from pathlib import Path


def read_header(path: Path, size: int) -> bytes:
    with path.open("rb") as file_obj:
        return file_obj.read(size)


def compute_hashes(path: Path, chunk_size: int = 1024 * 1024) -> dict[str, str]:
    digesters = {
        "sha256": hashlib.sha256(),
        "md5": hashlib.md5(),  # noqa: S324 - md5 is included for compatibility reporting.
    }
    with path.open("rb") as file_obj:
        while chunk := file_obj.read(chunk_size):
            for hasher in digesters.values():
                hasher.update(chunk)
    return {name: hasher.hexdigest() for name, hasher in digesters.items()}


def extract_file_timestamps(path: Path) -> dict[str, str]:
    stat_info = path.stat()
    return {
        "created_at": _to_utc_iso(stat_info.st_ctime),
        "modified_at": _to_utc_iso(stat_info.st_mtime),
        "accessed_at": _to_utc_iso(stat_info.st_atime),
    }


def guess_mime_type(path: Path) -> str | None:
    mime_type, _ = mimetypes.guess_type(str(path))
    return mime_type


def _to_utc_iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=UTC).isoformat()
