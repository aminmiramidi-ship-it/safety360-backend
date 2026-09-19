import json
import uuid
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from audit_models import AuditEvent
from auth_security_models import LoginThrottle
from database import SessionLocal
from main import app

client = TestClient(app)


def _email(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}@example.com"


def _register(email: str) -> None:
    response = client.post(
        "/auth/register",
        json={
            "email": email,
            "password": "Secret123!",
            "full_name": "Login Protection Test",
            "language": "de",
        },
    )
    assert response.status_code == 201, response.text


def test_account_cooldown_blocks_bearer_and_cookie_login_paths():
    email = _email("cooldown")
    _register(email)

    for _ in range(7):
        response = client.post(
            "/auth/login",
            json={"email": email, "password": "WrongPassword!"},
        )
        assert response.status_code == 401, response.text

    threshold_response = client.post(
        "/auth/session/login",
        json={"email": email, "password": "WrongPassword!"},
    )
    assert threshold_response.status_code == 429, threshold_response.text
    assert int(threshold_response.headers["retry-after"]) > 0

    blocked_correct_password = client.post(
        "/auth/login",
        json={"email": email, "password": "Secret123!"},
    )
    assert blocked_correct_password.status_code == 429


def test_expired_cooldown_allows_valid_login_and_resets_state():
    email = _email("expiry")
    _register(email)

    for _ in range(8):
        response = client.post(
            "/auth/login",
            json={"email": email, "password": "WrongPassword!"},
        )
    assert response.status_code == 429

    db = SessionLocal()
    try:
        target_account = (
            db.query(LoginThrottle)
            .filter(
                LoginThrottle.key_type == "account",
                LoginThrottle.locked_until.is_not(None),
            )
            .order_by(LoginThrottle.id.desc())
            .first()
        )
        assert target_account is not None
        target_account_id = target_account.id

        past = datetime.now(timezone.utc) - timedelta(hours=2)
        throttles = db.query(LoginThrottle).all()
        for throttle in throttles:
            throttle.locked_until = past
            throttle.window_started_at = past
        db.commit()
    finally:
        db.close()

    success = client.post(
        "/auth/login",
        json={"email": email, "password": "Secret123!"},
    )
    assert success.status_code == 200, success.text

    db = SessionLocal()
    try:
        account_row = (
            db.query(LoginThrottle)
            .filter(LoginThrottle.id == target_account_id)
            .one()
        )
        assert account_row.failed_attempts == 0
        assert account_row.locked_until is None
    finally:
        db.close()


def test_unknown_account_failure_is_generic_and_audited_without_raw_identifier():
    unknown_email = _email("unknown")
    response = client.post(
        "/auth/login",
        json={"email": unknown_email, "password": "WrongPassword!"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "E-Mail-Adresse oder Passwort ist ungültig."

    db = SessionLocal()
    try:
        event = (
            db.query(AuditEvent)
            .filter(AuditEvent.action == "auth.login.failed")
            .order_by(AuditEvent.id.desc())
            .first()
        )
        assert event is not None
        details = json.loads(event.details_json or "{}")
        assert details["authentication_mode"] == "bearer"
        assert details["subject_fingerprint"]
        assert details["source_fingerprint"]
        assert unknown_email not in (event.details_json or "")
        assert unknown_email not in (event.object_id or "")
    finally:
        db.close()
