from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    import cv2
except ImportError:  # pragma: no cover - depends on local env
    cv2 = None  # type: ignore[assignment]

try:
    import face_recognition
except ImportError:  # pragma: no cover - depends on local env
    face_recognition = None  # type: ignore[assignment]

try:
    import numpy as np
except ImportError:  # pragma: no cover - depends on local env
    np = None  # type: ignore[assignment]

try:
    from tensorflow.keras.models import load_model
except ImportError:  # pragma: no cover - depends on local env
    load_model = None  # type: ignore[assignment]


PROJECT_ROOT = Path(__file__).resolve().parent.parent
WEIGHTS_DIR = PROJECT_ROOT / "weights"
LEGACY_MODEL_PATH = Path(__file__).resolve().parent / "deepfake_v5_final_85pc.keras"
DEFAULT_MODEL_PATH = WEIGHTS_DIR / "deepfake_v5_final_85pc.keras"
IMG_SIZE = (256, 256)
OPTIMAL_THRESHOLD = 0.46
FRAME_SAMPLE_SECONDS = 1.0

_MODEL: Any | None = None
_MODEL_LOAD_ERROR: str | None = None


def _missing_dependencies() -> list[str]:
    missing: list[str] = []
    if cv2 is None:
        missing.append("opencv-python")
    if np is None:
        missing.append("numpy")
    if load_model is None:
        missing.append("tensorflow")
    if face_recognition is None:
        missing.append("face-recognition")
    return missing


def _resolve_model_path() -> Path:
    if DEFAULT_MODEL_PATH.is_file():
        return DEFAULT_MODEL_PATH
    return LEGACY_MODEL_PATH


def _load_video_model() -> tuple[Any | None, str | None]:
    global _MODEL, _MODEL_LOAD_ERROR

    if _MODEL is not None:
        return _MODEL, None
    if _MODEL_LOAD_ERROR is not None:
        return None, _MODEL_LOAD_ERROR

    model_path = _resolve_model_path()
    if not model_path.is_file():
        _MODEL_LOAD_ERROR = f"Файл весов модели не найден: {model_path}"
        return None, _MODEL_LOAD_ERROR
    if load_model is None:
        _MODEL_LOAD_ERROR = "TensorFlow не установлен."
        return None, _MODEL_LOAD_ERROR

    try:
        _MODEL = load_model(model_path)
        return _MODEL, None
    except Exception as exc:  # noqa: BLE001
        _MODEL_LOAD_ERROR = f"Не удалось загрузить модель: {exc}"
        return None, _MODEL_LOAD_ERROR


def get_cropped_face(img_bgr: Any) -> Any | None:
    """Находит первое лицо на кадре и готовит crop для модели."""
    if cv2 is None or face_recognition is None:
        return None

    img_rgb = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2RGB)
    face_locations = face_recognition.face_locations(img_rgb, model="hog")
    if not face_locations:
        return None

    top, right, bottom, left = face_locations[0]
    height, width, _ = img_bgr.shape

    margin = 0.2
    delta_w = int((right - left) * margin)
    delta_h = int((bottom - top) * margin)

    top = max(0, top - delta_h)
    bottom = min(height, bottom + delta_h)
    left = max(0, left - delta_w)
    right = min(width, right + delta_w)

    crop_face = img_bgr[top:bottom, left:right]
    if crop_face.size == 0:
        return None
    return cv2.resize(cv2.cvtColor(crop_face, cv2.COLOR_BGR2RGB), IMG_SIZE)


def analyze_video(file_path: str | Path) -> dict[str, object]:
    """
    Анализирует видеофайл и возвращает словарь с результатом анализа.
    Формат результата пригоден для GUI-адаптера в desktop_app.
    """
    file_path = Path(file_path)
    if not file_path.is_file():
        return {"status": "Error", "message": f"Видео не найдено: {file_path}"}

    missing = _missing_dependencies()
    if missing:
        return {
            "status": "Error",
            "message": "Не установлены зависимости для анализа видео.",
            "missing_dependencies": missing,
        }

    model, model_error = _load_video_model()
    if model is None:
        return {
            "status": "Error",
            "message": model_error or "Не удалось загрузить модель.",
            "model_path": str(_resolve_model_path()),
        }

    cap = cv2.VideoCapture(str(file_path))
    if not cap.isOpened():
        return {"status": "Error", "message": "Не удалось открыть видеофайл."}

    fps = cap.get(cv2.CAP_PROP_FPS)
    sample_step = 30
    try:
        if fps and float(fps) > 0:
            sample_step = max(1, int(round(float(fps) * FRAME_SAMPLE_SECONDS)))
    except (TypeError, ValueError):
        sample_step = 30

    predictions: list[float] = []
    frame_index = 0
    try:
        while cap.isOpened():
            success, frame = cap.read()
            if not success:
                break

            if frame_index % sample_step == 0:
                face = get_cropped_face(frame)
                if face is not None and np is not None:
                    tensor = np.expand_dims(face.astype("float32") / 255.0, axis=0)
                    probability = model.predict(tensor, verbose=0)[0][0]
                    predictions.append(float(probability))
            frame_index += 1
    finally:
        cap.release()

    if not predictions:
        return {
            "status": "Error",
            "message": "Лица не обнаружены в видеопотоке.",
            "model_path": str(_resolve_model_path()),
        }

    final_probability = float(np.mean(predictions))
    return {
        "status": "OK",
        "is_fake": final_probability > OPTIMAL_THRESHOLD,
        "probability": round(final_probability, 4),
        "analyzed_frames": len(predictions),
        "model_path": str(_resolve_model_path()),
        "threshold": OPTIMAL_THRESHOLD,
    }


__all__ = ["OPTIMAL_THRESHOLD", "analyze_video", "get_cropped_face"]
