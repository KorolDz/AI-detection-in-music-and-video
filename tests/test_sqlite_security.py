from pathlib import Path

import pytest

from media_security.storage.sqlite_config import resolve_sqlite_path, validate_sqlite_path


def test_resolve_sqlite_path_uses_env_override(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    db_path = tmp_path / "history.sqlite3"

    monkeypatch.setenv("MEDIA_SECURITY_SKIP_DOTENV", "1")
    monkeypatch.setenv("MEDIA_SECURITY_SQLITE_PATH", str(db_path))

    resolved = resolve_sqlite_path()

    assert resolved == db_path.resolve()
    assert resolved.parent.exists()


def test_resolve_sqlite_path_defaults_to_user_local_appdata(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("MEDIA_SECURITY_SKIP_DOTENV", "1")
    monkeypatch.delenv("MEDIA_SECURITY_SQLITE_PATH", raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))

    resolved = resolve_sqlite_path()

    assert resolved == (tmp_path / "MediaSecurity" / "history" / "scan_history.sqlite3").resolve()
    assert resolved.parent.exists()


def test_validate_sqlite_path_rejects_symlink(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("MEDIA_SECURITY_SKIP_DOTENV", "1")
    target = tmp_path / "real.sqlite3"
    target.write_text("x", encoding="utf-8")
    link = tmp_path / "link.sqlite3"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("Symlinks are unavailable in current environment.")

    with pytest.raises(RuntimeError, match="must not be a symlink"):
        validate_sqlite_path(link)
