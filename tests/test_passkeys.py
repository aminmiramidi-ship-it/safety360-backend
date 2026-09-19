import base64
import uuid
from types import SimpleNamespace

from fastapi.testclient import TestClient

import passkey_api
from database import SessionLocal
from main import app
from passkey_models import PasskeyCredential, WebAuthnCeremony


def _email(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}@example.com"


def _register(client: TestClient, email: str) -> None:
    response = client.post(
        "/auth/register",
        json={
            "email": email,
            "password": "Secret123!",
            "full_name": "Passkey Test",
            "language": "de",
        },
    )
    assert response.status_code == 201, response.text


def _password_session(client: TestClient, email: str) -> str:
    response = client.post(
        "/auth/session/login",
        json={"email": email, "password": "Secret123!"},
    )
    assert response.status_code == 200, response.text
    csrf = client.cookies.get("safety360_csrf")
    assert csrf
    return csrf


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def test_registration_options_require_recent_browser_auth_and_strong_uv():
    email = _email("options")
    with TestClient(app) as client:
        _register(client, email)
        bearer = client.post(
            "/auth/login",
            json={"email": email, "password": "Secret123!"},
        )
        assert bearer.status_code == 200, bearer.text
        token = bearer.json()["access_token"]

        denied = client.post(
            "/auth/passkeys/registration/options",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert denied.status_code == 403, denied.text

        csrf = _password_session(client, email)
        response = client.post(
            "/auth/passkeys/registration/options",
            headers={"X-Requested-With": csrf},
        )
        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload["ceremony_id"]
        public_key = payload["public_key"]
        assert public_key["rp"]["id"] == passkey_api.WEBAUTHN_RP_ID
        assert public_key["authenticatorSelection"]["residentKey"] == "required"
        assert public_key["authenticatorSelection"]["userVerification"] == "required"
        assert public_key["attestation"] == "none"

        db = SessionLocal()
        try:
            ceremony = (
                db.query(WebAuthnCeremony)
                .filter(WebAuthnCeremony.ceremony_id == payload["ceremony_id"])
                .one()
            )
            assert ceremony.purpose == "registration"
            assert ceremony.user_id is not None
            assert ceremony.used_at is None
        finally:
            db.close()


def test_discoverable_authentication_options_do_not_require_account_identifier():
    with TestClient(app) as client:
        response = client.post("/auth/passkeys/authentication/options")
        assert response.status_code == 200, response.text
        payload = response.json()
        public_key = payload["public_key"]
        assert payload["ceremony_id"]
        assert public_key["rpId"] == passkey_api.WEBAUTHN_RP_ID
        assert public_key["userVerification"] == "required"
        assert public_key.get("allowCredentials") in (None, [])


def test_registration_and_passwordless_authentication_issue_cookie_session(monkeypatch):
    email = _email("passwordless")
    credential_id_bytes = f"credential-{uuid.uuid4().hex}".encode("ascii")
    credential_id = _encode(credential_id_bytes)

    with TestClient(app) as enrollment_client:
        _register(enrollment_client, email)
        csrf = _password_session(enrollment_client, email)
        options = enrollment_client.post(
            "/auth/passkeys/registration/options",
            headers={"X-Requested-With": csrf},
        )
        assert options.status_code == 200, options.text

        monkeypatch.setattr(
            passkey_api,
            "verify_registration_response",
            lambda **_kwargs: SimpleNamespace(
                credential_id=credential_id_bytes,
                credential_public_key=b"test-public-key",
                sign_count=0,
                aaguid="00000000-0000-0000-0000-000000000000",
                credential_device_type=SimpleNamespace(value="multi_device"),
                credential_backed_up=True,
            ),
        )

        registration = enrollment_client.post(
            "/auth/passkeys/registration/verify",
            headers={"X-Requested-With": csrf},
            json={
                "ceremony_id": options.json()["ceremony_id"],
                "credential": {
                    "id": credential_id,
                    "rawId": credential_id,
                    "type": "public-key",
                    "response": {"transports": ["internal", "hybrid"]},
                },
                "nickname": "Primary passkey",
            },
        )
        assert registration.status_code == 200, registration.text
        assert registration.json()["backed_up"] is True
        assert registration.json()["nickname"] == "Primary passkey"

    db = SessionLocal()
    try:
        stored = (
            db.query(PasskeyCredential)
            .filter(PasskeyCredential.credential_id == credential_id)
            .one()
        )
        assert stored.credential_public_key == _encode(b"test-public-key")
        assert stored.revoked_at is None
    finally:
        db.close()

    with TestClient(app) as passwordless_client:
        options = passwordless_client.post("/auth/passkeys/authentication/options")
        assert options.status_code == 200, options.text

        monkeypatch.setattr(
            passkey_api,
            "verify_authentication_response",
            lambda **_kwargs: SimpleNamespace(new_sign_count=1),
        )
        verify_payload = {
            "ceremony_id": options.json()["ceremony_id"],
            "credential": {
                "id": credential_id,
                "rawId": credential_id,
                "type": "public-key",
                "response": {},
            },
        }
        verified = passwordless_client.post(
            "/auth/passkeys/authentication/verify",
            json=verify_payload,
        )
        assert verified.status_code == 200, verified.text
        assert verified.json()["email"] == email
        assert passwordless_client.cookies.get("safety360_session")
        assert passwordless_client.cookies.get("safety360_csrf")

        replay = passwordless_client.post(
            "/auth/passkeys/authentication/verify",
            json=verify_payload,
        )
        assert replay.status_code == 400, replay.text

        me = passwordless_client.get("/auth/me")
        assert me.status_code == 200, me.text
        assert me.json()["email"] == email

    db = SessionLocal()
    try:
        stored = (
            db.query(PasskeyCredential)
            .filter(PasskeyCredential.credential_id == credential_id)
            .one()
        )
        assert stored.sign_count == 1
        assert stored.last_used_at is not None
    finally:
        db.close()
