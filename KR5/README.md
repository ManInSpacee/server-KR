# KR5 — FastAPI Tasks API

## Запуск локально

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

API доступно по адресу: http://localhost:8000  
Swagger UI: http://localhost:8000/docs

## Запуск в Docker

```bash
docker compose up --build
```

## Тесты

```bash
pytest
```

## Основные эндпоинты

### Tasks (требуется заголовок `X-User-Id: <int>`)

```bash
# Создать задачу
curl -X POST http://localhost:8000/tasks \
  -H "X-User-Id: 10" \
  -H "Content-Type: application/json" \
  -d '{"title": "My task", "priority": 3}'

# Список своих задач
curl http://localhost:8000/tasks -H "X-User-Id: 10"

# Изменить статус
curl -X PATCH http://localhost:8000/tasks/1/status \
  -H "X-User-Id: 10" \
  -H "Content-Type: application/json" \
  -d '{"status": "done"}'

# Удалить задачу
curl -X DELETE http://localhost:8000/tasks/1 -H "X-User-Id: 10"
```

### Admin (требуется `X-User-Role: admin`)

```bash
curl http://localhost:8000/admin/stats \
  -H "X-User-Id: 1" -H "X-User-Role: admin"
```

### Health check

```bash
curl http://localhost:8000/health
```

### WebSocket

```
ws://localhost:8000/ws/rooms/{room_id}?username=alice
```

Просмотр пользователей комнаты:

```bash
curl http://localhost:8000/rooms/python/users
```
