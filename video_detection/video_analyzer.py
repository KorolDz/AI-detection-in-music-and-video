!pip install face-recognition
import cv2
import numpy as np
import tensorflow as tf
import os
from tensorflow.keras.models import load_model

# Напарнику: pip install face-recognition opencv-python tensorflow
import face_recognition 

# ==========================================
# КОНСТАНТЫ
# ==========================================
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'deepfake_v5_final_85pc.keras') 
IMG_SIZE = (256, 256)
OPTIMAL_THRESHOLD = 0.46 

# Загружаем модель
try:
    model = load_model(MODEL_PATH)
    print("Модуль видео-аналитики готов к работе.")
except Exception as e:
    print(f"КРИТИЧЕСКАЯ ОШИБКА: Файл весов {MODEL_PATH} не найден!")

def get_cropped_face(img_bgr):
    """Находит лицо и делает правильный crop для нейросети."""
    img_rgb = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2RGB)
    face_locations = face_recognition.face_locations(img_rgb, model="hog")
    
    if not face_locations:
        return None
    
    top, right, bottom, left = face_locations[0]
    h, w, _ = img_bgr.shape
    
    # Отступ 20% (стандарт Celeb-DF)
    margin = 0.2
    dW, dH = int((right - left) * margin), int((bottom - top) * margin)
    
    t, b = max(0, top - dH), min(h, bottom + dH)
    l, r = max(0, left - dW), min(w, right + dW)
    
    crop_face = img_bgr[t:b, l:r]
    # Возвращаем RGB для модели
    return cv2.resize(cv2.cvtColor(crop_face, cv2.COLOR_BGR2RGB), IMG_SIZE)

def analyze_video(file_path):
    """
    Основная функция для ТЗ. Принимает путь к mp4/avi/mov.
    Возвращает вердикт и вероятность.
    """
    if not os.path.exists(file_path):
        return {'status': 'Error', 'message': 'Файл видео не найден'}

    cap = cv2.VideoCapture(file_path)
    predictions = []
    count = 0

    while cap.isOpened():
        success, frame = cap.read()
        if not success: break
        
        # Анализируем каждый 30-й кадр (примерно 1 кадр в секунду)
        if count % 30 == 0:
            face = get_cropped_face(frame)
            if face is not None:
                # Подготовка тензора (нормализация 0-1)
                tensor = np.expand_dims(face.astype('float32') / 255.0, axis=0)
                prob = model.predict(tensor, verbose=0)[0][0]
                predictions.append(prob)
        count += 1
    
    cap.release()

    if not predictions:
        return {'status': 'Error', 'message': 'Лица не обнаружены в видеопотоке'}

    # Усреднение результатов по всем кадрам (Temporal Pooling)
    final_prob = np.mean(predictions)
    
    return {
        'is_fake': final_prob > OPTIMAL_THRESHOLD,
        'probability': round(float(final_prob), 4),
        'analyzed_frames': len(predictions),
        'status': 'OK'
    }