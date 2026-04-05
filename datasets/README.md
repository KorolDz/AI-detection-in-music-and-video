# Датасеты и локальные файлы

Каталог `datasets` используется как единая рабочая папка для проверки медиафайлов.

## Структура

```text
datasets/
|-- audio/
|-- video/
|-- unsupported/
`-- README.md
```

- `audio/` — аудиофайлы `wav` и `mp3`.
- `video/` — видеофайлы `mp4`, `avi`, `mov`.
- `unsupported/` — файлы, которые не соответствуют формату из ТЗ и нужны для негативных проверок.

## Генерация тестовых файлов

Базовые локальные примеры:

```bash
python scripts/generate_test_media_fixtures.py
```

Примеры аудиофайлов с расширенными метаданными:

```bash
python scripts/generate_metadata_examples.py
```

После генерации файлы появляются сразу в `datasets/audio`, `datasets/video` и `datasets/unsupported`.
