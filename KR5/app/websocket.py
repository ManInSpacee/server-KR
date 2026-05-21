from fastapi import WebSocket, WebSocketDisconnect


class RoomManager:
    def __init__(self):
        self._rooms: dict[str, dict[str, WebSocket]] = {}

    def connect(self, room_id: str, username: str, websocket: WebSocket):
        if room_id not in self._rooms:
            self._rooms[room_id] = {}
        self._rooms[room_id][username] = websocket

    def disconnect(self, room_id: str, username: str):
        if room_id in self._rooms:
            self._rooms[room_id].pop(username, None)
            if not self._rooms[room_id]:
                del self._rooms[room_id]

    async def broadcast(self, room_id: str, payload: dict):
        for ws in list(self._rooms.get(room_id, {}).values()):
            await ws.send_json(payload)

    def get_users(self, room_id: str) -> list[str]:
        return list(self._rooms.get(room_id, {}).keys())


room_manager = RoomManager()
