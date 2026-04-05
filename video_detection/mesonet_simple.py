import numpy as np
import matplotlib.pyplot as plt
from classifiers import Meso4
from tensorflow.keras.preprocessing.image import load_img, img_to_array

def predict_media(file_path, model_path='Meso4_DF.h5'):
    # 1. Инициализируем модель и загружаем веса
    model = Meso4()
    model.load(model_path)
    
    # 2. Загружаем и обрабатываем картинку
    image = load_img(file_path, target_size=(256, 256))
    image_array = img_to_array(image) / 255.0
    image_array = np.expand_dims(image_array, axis=0)

    # 3. Делаем предсказание
    prediction = model.predict(image_array)[0][0]
    
    # Определяем статус
    status = "REAL" if prediction > 0.5 else "DEEPFAKE"
    return status, prediction, image

if __name__ == "__main__":
    # Пример использования
    test_file = 'real00772.jpg' # Убедись, что файл есть в папке
    try:
        status, score, img = predict_media(test_file)
        print(f"Файл: {test_file} | Вердикт: {status} (Уверенность: {score:.2f})")
        
        # Показываем результат (опционально для тестов)
        plt.imshow(img)
        plt.title(f"Verdict: {status} ({score:.2f})")
        plt.axis('off')
        plt.show()
    except Exception as e:
        print(f"Ошибка при анализе: {e}")
