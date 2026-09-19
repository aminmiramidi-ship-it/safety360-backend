import hashlib

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from database import SessionLocal
from main import app
from realtime_models import RealtimeAccessTicket

client = TestClient(app)


def _register_login(email: str) -> dict[str, str]:
    response = client.post(
        "/auth/register",
        json={
            "email": email,
            "password": "Secret123!",
            "full_name": "Realtime Security Test",
            "language": "de",
        },
    )
    assert response.status_code in {201, 409}, response.text
    login = client.post("/auth/login", json={"email": email, "password": "Secret123!"})
    assert login.status_code == 200, login.text
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


def test_realtime_ticket_is_hashed_single_use_and_supports_ping():
    headers = _register_login("realtime-secure@example.com")
    issued = client.post("/realtime/tickets", headers=headers)
    assert issued.status_code == 201, issued.text
    payload = issued.json()
    ticket = payload["ticket"]
    assert payload["single_use"] is True
    assert payload["websocket_path"] == "/realtime/ws"

    db = SessionLocal()
    try:
        stored = db.query(RealtimeAccessTicket).filter(
            RealtimeAccessTicket.token_hash == hashlib.sha256(ticket.encode("utf-8")).hexdigest()
        ).first()
        assert stored is not None
        assert stored.token_hash != ticket
        assert stored.used_at is None
    finally:
        db.close()

    with client.websocket_connect(f"/realtime/ws?ticket={ticket}") as websocket:
        connected = websocket.receive_json()
        assert connected["type"] == "connected"
        assert connected["authenticated"] is True
        websocket.send_text("ping")
        assert websocket.receive_json()["type"] == "pong"

    db = SessionLocal()
    try:
        stored = db.query(RealtimeAccessTicket).filter(
            RealtimeAccessTicket.token_hash == hashlib.sha256(ticket.encode("utf-8")).hexdigest()
        ).first()
        assert stored is not None
        assert stored.used_at is not None
    finally:
        db.close()

    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/realtime/ws?ticket={ticket}") as websocket:
            websocket.receive_json()


def test_realtime_websocket_rejects_missing_ticket():
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/realtime/ws") as websocket:
            websocket.receive_json()
