from pathlib import Path

from media_security.external_tools import get_external_tool_info, missing_external_tools, resolve_external_tool


def test_resolve_external_tool_prefers_explicit_env_path(monkeypatch, tmp_path: Path) -> None:
    tool_path = tmp_path / "ffprobe.exe"
    tool_path.write_bytes(b"test")

    monkeypatch.setenv("MEDIA_SECURITY_FFPROBE_PATH", str(tool_path))
    monkeypatch.delenv("MEDIA_SECURITY_TOOLS_DIR", raising=False)
    monkeypatch.setattr("media_security.external_tools.shutil.which", lambda _name: None)

    resolved = resolve_external_tool("ffprobe")

    assert resolved == tool_path.resolve()
    assert get_external_tool_info("ffprobe").source == "env"


def test_resolve_external_tool_from_shared_tools_dir(monkeypatch, tmp_path: Path) -> None:
    bundled_path = tmp_path / "windows" / "ffmpeg" / "bin" / "ffprobe.exe"
    bundled_path.parent.mkdir(parents=True, exist_ok=True)
    bundled_path.write_bytes(b"test")

    monkeypatch.delenv("MEDIA_SECURITY_FFPROBE_PATH", raising=False)
    monkeypatch.setenv("MEDIA_SECURITY_TOOLS_DIR", str(tmp_path))
    monkeypatch.setattr("media_security.external_tools.shutil.which", lambda _name: None)

    info = get_external_tool_info("ffprobe")

    assert info.path == bundled_path.resolve()
    assert info.source == "bundled"


def test_missing_external_tools_uses_path_fallback(monkeypatch, tmp_path: Path) -> None:
    system_tool = tmp_path / "ffprobe.exe"
    system_tool.write_bytes(b"test")

    monkeypatch.delenv("MEDIA_SECURITY_FFPROBE_PATH", raising=False)
    monkeypatch.delenv("MEDIA_SECURITY_TOOLS_DIR", raising=False)
    monkeypatch.setattr(
        "media_security.external_tools.shutil.which",
        lambda name: str(system_tool) if name == "ffprobe" else None,
    )

    assert resolve_external_tool("ffprobe") == system_tool.resolve()
    assert missing_external_tools(["ffprobe", "exiftool"]) == ["exiftool"]
