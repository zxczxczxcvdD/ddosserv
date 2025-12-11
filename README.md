# Owners Hack Util Server

Сервер для управления пользователями, подписками и аутентификацией.

## Установка на Railway

1. Создайте новый проект на Railway
2. Подключите PostgreSQL базу данных
3. Установите переменные окружения:
   - `DATABASE_URL` - URL PostgreSQL базы данных (Railway автоматически создаст)
   - `PORT` - порт (Railway автоматически установит)
4. Деплойте проект

## Локальный запуск

```bash
pip install -r requirements.txt
python app.py
```

## API Endpoints

- `POST /api/register` - Регистрация
- `POST /api/login` - Вход
- `POST /api/check_subscription` - Проверка подписки
- `GET /api/admin/users` - Список пользователей (требует админ права)
- `POST /api/admin/ban` - Бан/разбан пользователя
- `POST /api/admin/subscription` - Управление подпиской
- `GET /api/admin/password` - Получить хеш пароля пользователя

