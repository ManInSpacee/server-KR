import os
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from app.routers import tasks, users, admin
from app.websocket import room_manager

app = FastAPI()

app.include_router(tasks.router)
app.include_router(users.router)
app.include_router(admin.router)


@app.get("/health")
def health():
    return {"status": "ok", "env": os.getenv("APP_ENV", "local")}


@app.websocket("/ws/rooms/{room_id}")
async def websocket_room(websocket: WebSocket, room_id: str, username: str | None = None):
    if not username or not username.strip():
        await websocket.close(code=1008)
        return

    await websocket.accept()
    room_manager.connect(room_id, username, websocket)
    await room_manager.broadcast(room_id, {"type": "join", "room_id": room_id, "username": username})

    try:
        while True:
            data = await websocket.receive_json()
            if data.get("type") == "message":
                text = data.get("text", "")
                if len(text) > 300:
                    await websocket.send_json({"type": "error", "detail": "Message is too long"})
                else:
                    await room_manager.broadcast(room_id, {
                        "type": "message",
                        "room_id": room_id,
                        "username": username,
                        "text": text,
                    })
    except WebSocketDisconnect:
        room_manager.disconnect(room_id, username)


@app.get("/rooms/{room_id}/users")
def get_room_users(room_id: str):
    return {"room_id": room_id, "users": room_manager.get_users(room_id)}
