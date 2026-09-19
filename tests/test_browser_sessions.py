import hashlib

from fastapi.testclient import TestClient

from database import SessionLocal
from main import app
from session_models import BrowserSession


def _register(client: TestClient, email: str) -> None:
    response = client.post(
        "/auth/register",
        json={
            "email": email,
            "password": "Secret123!",
            "full_name": "Browser Session Test",
            "language": "de",
        },
    )
    assert response.status_code in {201, 409}, response.text


def test_browser_session_uses_hashed_secrets_csrf_and_revocation():
    email = "browser-session@example.com"
    with TestClient(app) as client:
        _register(client, email)
        login = client.post(
            "/auth/session/login",
            json={"email": email, "password": "Secret123!"},
        )
        assert login.status_code == 200, login.text
        assert "access_token" not in login.json()

        raw_session = client.cookies.get("safety360_session")
        raw_csrf = client.cookies.get("safety360_csrf")
        assert raw_session
        assert raw_csrf

        db = SessionLocal()
        try:
            stored = db.query(BrowserSession).filter(
                BrowserSession.session_hash
                == hashlib.sha256(raw_session.encode("utf-8")).hexdigest()
            ).first()
            assert stored is not None
            assert stored.session_hash != raw_session
            assert stored.csrf_hash == hashlib.sha256(raw_csrf.encode("utf-8")).hexdigest()
            assert stored.revoked_at is None
        finally:
            db.close()

        me = client.get("/auth/me")
        assert me.status_code == 200, me.text
        assert me.json()["email"] == email

        blocked = client.post(
            "/tickets",
            json={"description": "CSRF must block this request", "status": "open"},
        )
        assert blocked.status_code == 403, blocked.text

        csrf_headers = {"X-Requested-With": raw_csrf}
        allowed = client.post(
            "/tickets",
            headers=csrf_headers,
            json={"description": "Session-authenticated request", "status": "open"},
        )
        assert allowed.status_code == 201, allowed.text

        logout = client.post("/auth/session/logout", headers=csrf_headers)
        assert logout.status_code == 200, logout.text
        assert logout.json()["status"] == "logged_out"

        denied = client.get("/auth/me")
        assert denied.status_code == 401, denied.text

        db = SessionLocal()
        try:
            stored = db.query(BrowserSession).filter(
                BrowserSession.session_hash
                == hashlib.sha256(raw_session.encode("utf-8")).hexdigest()
            ).first()
            assert stored is not None
            assert stored.revoked_at is not None
        finally:
            db.close()


def test_bearer_api_authentication_remains_supported():
    email = "browser-session-bearer@example.com"
    with TestClient(app) as client:
        _register(client, email)
        login = client.post(
            "/auth/login",
            json={"email": email, "password": "Secret123!"},
        )
        assert login.status_code == 200, login.text
        access_token = login.json()["access_token"]

        me = client.get(
            "/auth/me",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert me.status_code == 200, me.text
        assert me.json()["email"] == email
