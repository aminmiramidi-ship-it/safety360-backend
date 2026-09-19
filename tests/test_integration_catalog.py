from fastapi.testclient import TestClient

from database import SessionLocal
from main import app
from models import User

client = TestClient(app)


def _register_login(email: str) -> dict[str, str]:
    response = client.post(
        "/auth/register",
        json={"email": email, "password": "Secret123!", "full_name": "Integration Test", "language": "de"},
    )
    assert response.status_code in {201, 409}, response.text
    login = client.post("/auth/login", json={"email": email, "password": "Secret123!"})
    assert login.status_code == 200, login.text
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


def _promote(email: str, role: str) -> None:
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        assert user is not None
        user.role = role
        db.commit()
    finally:
        db.close()


def _tenant(headers: dict[str, str], name: str) -> None:
    response = client.post("/tenants", headers=headers, json={"name": name})
    assert response.status_code in {201, 409}, response.text


def test_catalog_contains_zoom_and_enterprise_connectors():
    email = "integration-admin@example.com"
    headers = _register_login(email)
    _tenant(headers, "Integration GmbH")
    _promote(email, "tenant_admin")
    headers = _register_login(email)

    response = client.get("/integrations/catalog", headers=headers)
    assert response.status_code == 200, response.text
    providers = {item["provider_key"] for item in response.json()["providers"]}
    assert {"zoom", "teams", "outlook-calendar", "sharepoint", "google-calendar", "box", "dropbox", "calendly", "generic-oidc", "generic-scim", "generic-webhook", "generic-rest"}.issubset(providers)


def test_connection_rejects_plaintext_secret_and_requires_purpose_before_enable():
    email = "integration-owner@example.com"
    headers = _register_login(email)
    _tenant(headers, "Connector AG")
    _promote(email, "tenant_admin")
    headers = _register_login(email)

    bad = client.post(
        "/integrations/connections",
        headers=headers,
        json={
            "provider_key": "zoom",
            "integration_type": "meeting",
            "secret_ref": "plaintext-secret",
            "capabilities": ["meeting.create"],
            "approved_purposes": ["training"],
        },
    )
    assert bad.status_code == 422, bad.text

    created = client.post(
        "/integrations/connections",
        headers=headers,
        json={
            "provider_key": "zoom",
            "integration_type": "meeting",
            "secret_ref": "vault:tenant/zoom",
            "capabilities": ["meeting.create", "meeting.join_link"],
            "approved_purposes": ["training", "remote_consultation"],
            "data_classes": ["meeting_metadata"],
            "external_processing_allowed": True,
        },
    )
    assert created.status_code == 201, created.text
    payload = created.json()
    assert payload["secret_ref_configured"] is True
    assert "secret_ref" not in payload

    enabled = client.post(f"/integrations/connections/{payload['id']}/enable", headers=headers)
    assert enabled.status_code == 200, enabled.text
    assert enabled.json()["enabled"] is True
