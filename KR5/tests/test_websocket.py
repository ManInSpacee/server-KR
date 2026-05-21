import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.websocket import room_manager

client = TestClient(app)


@pytest.fixture(autouse=True)
def clear_rooms():
    room_manager._rooms.clear()
    yield
    room_manager._rooms.clear()


def test_connect_and_join_event():
    with client.websocket_connect("/ws/rooms/python?username=alice") as ws:
        msg = ws.receive_json()
        assert msg["type"] == "join"
        assert msg["username"] == "alice"


def test_send_message():
    with client.websocket_connect("/ws/rooms/python?username=alice") as ws:
        ws.receive_json()  # join event
        ws.send_json({"type": "message", "text": "Hello"})
        msg = ws.receive_json()
        assert msg["type"] == "message"
        assert msg["text"] == "Hello"
        assert msg["username"] == "alice"


def test_two_clients_same_room():
    with client.websocket_connect("/ws/rooms/python?username=alice") as ws1:
        ws1.receive_json()  # alice join
        with client.websocket_connect("/ws/rooms/python?username=bob") as ws2:
            ws2.receive_json()  # bob join
            ws1.receive_json()  # alice sees bob join
            ws1.send_json({"type": "message", "text": "Hi bob"})
            msg1 = ws1.receive_json()
            msg2 = ws2.receive_json()
            assert msg1["text"] == msg2["text"] == "Hi bob"


def test_different_rooms_isolation():
    with client.websocket_connect("/ws/rooms/python?username=alice") as ws1:
        ws1.receive_json()
        with client.websocket_connect("/ws/rooms/java?username=bob") as ws2:
            ws2.receive_json()
            ws2.send_json({"type": "message", "text": "Java msg"})
            msg2 = ws2.receive_json()
            assert msg2["text"] == "Java msg"
            # ws1 should not receive java room messages — no message in python room


def test_message_too_long():
    with client.websocket_connect("/ws/rooms/python?username=alice") as ws:
        ws.receive_json()
        ws.send_json({"type": "message", "text": "x" * 301})
        msg = ws.receive_json()
        assert msg["type"] == "error"
        assert "too long" in msg["detail"].lower()


def test_user_removed_after_disconnect():
    with client.websocket_connect("/ws/rooms/python?username=alice") as ws:
        ws.receive_json()
    res = client.get("/rooms/python/users")
    assert "alice" not in res.json()["users"]
