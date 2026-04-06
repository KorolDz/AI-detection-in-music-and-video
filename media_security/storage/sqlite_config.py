from __future__ import annotations

import os
import stat
from pathlib import Path


def load_local_env() -> None:
    if os.getenv("MEDIA_SECURITY_SKIP_DOTENV") == "1":
        return

    env_path = Path(__file__).resolve().parents[2] / ".env"
    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def resolve_sqlite_path(explicit_path: str | Path | None = None) -> Path:
    load_local_env()

    raw_path = str(explicit_path).strip() if explicit_path else ""
    if not raw_path:
        raw_path = os.getenv("MEDIA_SECURITY_SQLITE_PATH", "").strip()

    if raw_path:
        path = Path(raw_path).expanduser()
        if not path.is_absolute():
            path = path.resolve()
    else:
        path = _default_sqlite_path()

    validate_sqlite_path(path)
    prepare_sqlite_parent(path)
    return path


def validate_sqlite_path(path: Path) -> None:
    if path.exists() and path.is_symlink():
        raise RuntimeError(f"SQLite history path must not be a symlink: {path}")

    for parent in reversed(path.parents):
        if parent.exists() and parent.is_symlink():
            raise RuntimeError(f"SQLite history parent directory must not be a symlink: {parent}")


def prepare_sqlite_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _apply_private_permissions(path.parent, is_directory=True)


def harden_sqlite_file_permissions(path: Path) -> None:
    if path.exists():
        _apply_private_permissions(path, is_directory=False)


def _default_sqlite_path() -> Path:
    if os.name == "nt":
        base_dir = Path(os.getenv("LOCALAPPDATA") or (Path.home() / "AppData" / "Local"))
    else:
        base_dir = Path(os.getenv("XDG_DATA_HOME") or (Path.home() / ".local" / "share"))
    return (base_dir / "MediaSecurity" / "history" / "scan_history.sqlite3").resolve()


def _apply_private_permissions(path: Path, is_directory: bool) -> None:
    if os.name == "nt":
        try:
            os.chmod(path, stat.S_IREAD | stat.S_IWRITE)
        except OSError:
            return
        return

    mode = 0o700 if is_directory else 0o600
    try:
        os.chmod(path, mode)
    except OSError:
        return
