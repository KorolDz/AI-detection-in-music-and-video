from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ExternalToolInfo:
    name: str
    path: Path | None
    source: str | None

    @property
    def available(self) -> bool:
        return self.path is not None


_TOOL_ENV_VARS = {
    "ffmpeg": "MEDIA_SECURITY_FFMPEG_PATH",
    "ffprobe": "MEDIA_SECURITY_FFPROBE_PATH",
    "exiftool": "MEDIA_SECURITY_EXIFTOOL_PATH",
}

_TOOL_FILENAMES = {
    "ffmpeg": {
        "windows": ("ffmpeg/bin/ffmpeg.exe", "ffmpeg/ffmpeg.exe", "ffmpeg.exe"),
        "linux": ("ffmpeg/bin/ffmpeg", "ffmpeg/ffmpeg", "ffmpeg"),
        "darwin": ("ffmpeg/bin/ffmpeg", "ffmpeg/ffmpeg", "ffmpeg"),
    },
    "ffprobe": {
        "windows": ("ffmpeg/bin/ffprobe.exe", "ffprobe/ffprobe.exe", "ffprobe.exe"),
        "linux": ("ffmpeg/bin/ffprobe", "ffprobe/ffprobe", "ffprobe"),
        "darwin": ("ffmpeg/bin/ffprobe", "ffprobe/ffprobe", "ffprobe"),
    },
    "exiftool": {
        "windows": (
            "exiftool/exiftool.exe",
            "exiftool/exiftool(-k).exe",
            "exiftool.exe",
        ),
        "linux": ("exiftool/exiftool", "exiftool/exiftool.pl", "exiftool"),
        "darwin": ("exiftool/exiftool", "exiftool/exiftool.pl", "exiftool"),
    },
}


def resolve_external_tool(name: str) -> Path | None:
    return get_external_tool_info(name).path


def get_external_tool_info(name: str) -> ExternalToolInfo:
    normalized_name = name.strip().lower()
    if normalized_name not in _TOOL_ENV_VARS:
        raise ValueError(f"Unsupported external tool: {name}")

    env_override = _resolve_explicit_tool_env(normalized_name)
    if env_override is not None:
        return ExternalToolInfo(name=normalized_name, path=env_override, source="env")

    bundled_candidate = _resolve_bundled_tool(normalized_name)
    if bundled_candidate is not None:
        return ExternalToolInfo(name=normalized_name, path=bundled_candidate, source="bundled")

    system_candidate = shutil.which(normalized_name)
    if system_candidate:
        return ExternalToolInfo(
            name=normalized_name,
            path=Path(system_candidate).resolve(),
            source="path",
        )

    return ExternalToolInfo(name=normalized_name, path=None, source=None)


def missing_external_tools(names: tuple[str, ...] | list[str]) -> list[str]:
    return [name for name in names if not get_external_tool_info(name).available]


def _resolve_explicit_tool_env(name: str) -> Path | None:
    env_var = _TOOL_ENV_VARS[name]
    value = os.getenv(env_var, "").strip()
    if not value:
        return None
    candidate = Path(value).expanduser()
    return candidate.resolve() if candidate.is_file() else None


def _resolve_bundled_tool(name: str) -> Path | None:
    platform_key = _platform_key()
    for root in _iter_tool_roots():
        for relative_name in _TOOL_FILENAMES[name][platform_key]:
            for candidate in (
                root / platform_key / relative_name,
                root / relative_name,
            ):
                if candidate.is_file():
                    return candidate.resolve()
    return None


def _iter_tool_roots() -> list[Path]:
    candidates: list[Path] = []

    explicit_tools_dir = os.getenv("MEDIA_SECURITY_TOOLS_DIR", "").strip()
    if explicit_tools_dir:
        candidates.append(Path(explicit_tools_dir).expanduser())

    package_root = Path(__file__).resolve().parent
    candidates.append(package_root / "vendor" / "tools")
    candidates.append(package_root.parent / "vendor" / "tools")

    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        meipass_root = Path(meipass)
        candidates.append(meipass_root / "media_security" / "vendor" / "tools")
        candidates.append(meipass_root / "vendor" / "tools")

    unique_roots: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        normalized = str(candidate)
        if normalized in seen:
            continue
        seen.add(normalized)
        unique_roots.append(candidate)
    return unique_roots


def _platform_key() -> str:
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform == "darwin":
        return "darwin"
    return "linux"
