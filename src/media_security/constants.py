from __future__ import annotations

from typing import Final

SUPPORTED_MEDIA_EXTENSIONS: Final[dict[str, set[str]]] = {
    "audio": {"wav", "mp3"},
    "video": {"mp4", "avi", "mov"},
}

SUPPORTED_EXTENSIONS: Final[set[str]] = {
    extension
    for extensions in SUPPORTED_MEDIA_EXTENSIONS.values()
    for extension in extensions
}

MIME_BY_EXTENSION: Final[dict[str, set[str]]] = {
    "wav": {"audio/wav", "audio/x-wav", "audio/wave"},
    "mp3": {"audio/mpeg", "audio/mp3"},
    "mp4": {"video/mp4", "application/mp4"},
    "avi": {"video/x-msvideo", "video/avi", "application/x-troff-msvideo"},
    "mov": {"video/quicktime"},
}

MAX_SIGNATURE_BYTES: Final[int] = 4096
MAX_MP3_SCAN_BYTES: Final[int] = 1024 * 1024
LARGE_FILE_WARNING_BYTES: Final[int] = 2 * 1024 * 1024 * 1024
