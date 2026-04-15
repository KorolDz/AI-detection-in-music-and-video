from __future__ import annotations

try:
    from .app import run_app
except ImportError as exc:  # pragma: no cover - depends on local env
    raise SystemExit(
        "Не удалось запустить desktop-интерфейс. Установите зависимость PySide6."
    ) from exc


if __name__ == "__main__":
    raise SystemExit(run_app())
