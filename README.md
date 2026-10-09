# MultiAvaScanner

Веб-сканер подозрительных ссылок, APK, QR-кодов, паролей и скриншотов.

Использует **VirusTotal API**, **Have I Been Pwned** и **Google Gemini** для анализа.

> Это учебный / pet-проект. Не претендует на замену VirusTotal.

## Возможности

- Проверка **URL** через VirusTotal (70+ движков)
- Проверка **APK** (по SHA256 или загрузка файла)
- Распознавание **QR** → если внутри ссылка, сканируется через VT
- Проверка **пароля** через Have I Been Pwned (k-anonymity)
- **AI-анализ скриншотов** (фишинг / скам) через Google Gemini
- Кеширование результатов (24 часа)
- Rate-limit на эндпоинтах
- История сканов

## Стек

| Слой | Технологии |
|------|------------|
| Backend | Python 3.11+, Django 6 |
| БД | SQLite (для разработки) |
| Внешние API | VirusTotal, Have I Been Pwned, Google Gemini |
| Frontend | HTML + CSS + vanilla JS |
| Деплой | Gunicorn + WhiteNoise |

## Быстрый старт

```bash
git clone https://github.com/xshohjahon/MultiAvaScanner.git
cd MultiAvaScanner

python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

pip install -r requirements.txt

# Скопируй и заполни ключи
cp .env.example api.env

python manage.py migrate
python manage.py runserver
```

Открой http://127.0.0.1:8000/

## Переменные окружения

Создай файл `api.env` (или используй `.env`):

```env
VIRUSTOTAL_API_KEY=your_vt_api_key
GEMINI_API_KEY=your_gemini_api_key
HIBP_API_KEY=          # опционально, для HIBP
```

Ключи:
- VirusTotal: https://www.virustotal.com/gui/my-apikey
- Gemini: https://aistudio.google.com/apikey

## Структура проекта

```
main/
  views.py          # HTTP-слой (тонкий)
  services.py       # Бизнес-логика сканирования
  virustotal.py     # Клиент VirusTotal API
  exceptions.py     # Кастомные исключения
  helpers.py        # Утилиты для ответов
  rate_limit.py     # Простой IP rate-limit
  utils.py          # QR decode, HIBP
  ai_screenshot.py  # Gemini-анализ скриншотов
  models.py
```

## API (основные эндпоинты)

| Метод | Путь | Описание |
|-------|------|----------|
| POST | `/scan/url/` | Скан URL |
| POST | `/scan/file/` | Скан APK |
| POST | `/scan/qr/` | Скан QR-изображения |
| POST | `/scan/password/` | Проверка пароля |
| POST | `/scan/screenshot/` | AI-анализ скриншота |
| GET  | `/scan/<id>/` | Детали скана |
| GET  | `/history/` | История |

## Ограничения (важно)

- Бесплатный план VirusTotal: ~4 запроса в минуту
- Сканирование идёт **синхронно** (polling до ~50 сек) — при нагрузке лучше вынести в очередь
- SQLite не для продакшена
- `SECRET_KEY` в settings нужно сменить перед деплоем

## Roadmap (идеи)

- [ ] Фоновые задачи (Celery / django-q)
- [ ] Локальный ClamAV / YARA
- [ ] Docker Compose
- [ ] Нормальный rate-limit через Redis
- [ ] Экспорт отчётов в JSON/PDF

## Лицензия

Пока не указана. Можно добавить MIT.
