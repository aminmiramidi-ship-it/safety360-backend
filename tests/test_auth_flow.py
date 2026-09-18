import os
from pathlib import Path

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

TEST_DB = Path("test_safety360.db")
TEST_DB.unlink(missing_ok=True)

os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB.resolve().as_posix()}"
os.environ["SAFETY360_SECRET_KEY"] = "test-secret-key-for-ci-only-change-in-production-1234567890"
os.environ["ENCRYPTION_KEY"] = Fernet.generate_key().decode("utf-8")
os.environ["SAFETY360_ENV"] = "test"

from main import app  # noqa: E402

client = TestClient(app)


def test_complete_auth_and_ticket_flow():
    register_response = client.post(
        "/auth/register",
        json={
            "email": "ci-test@safety360.local",
            "password": "Secret123!",
            "full_name": "Safety360 CI",
            "language": "de",
        },
    )
    assert register_response.status_code == 201, register_response.text
    registered_user = register_response.json()
    assert registered_user["email"] == "ci-test@safety360.local"
    assert registered_user["role"] == "user"
    assert "password" not in registered_user
    assert "password_hash" not in registered_user

    duplicate_response = client.post(
        "/auth/register",
        json={
            "email": "ci-test@safety360.local",
            "password": "Secret123!",
            "full_name": "Duplicate",
            "language": "de",
        },
    )
    assert duplicate_response.status_code == 409

    bad_login_response = client.post(
        "/auth/login",
        json={
            "email": "ci-test@safety360.local",
            "password": "WrongPassword!",
        },
    )
    assert bad_login_response.status_code == 401

    login_response = client.post(
        "/auth/login",
        json={
            "email": "ci-test@safety360.local",
            "password": "Secret123!",
        },
    )
    assert login_response.status_code == 200, login_response.text
    token_data = login_response.json()
    assert token_data["token_type"] == "bearer"
    assert token_data["access_token"]
    assert token_data["expires_in"] > 0

    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    me_response = client.get("/auth/me", headers=headers)
    assert me_response.status_code == 200, me_response.text
    assert me_response.json()["email"] == "ci-test@safety360.local"

    dashboard_response = client.get("/dashboard", headers=headers)
    assert dashboard_response.status_code == 200, dashboard_response.text
    assert dashboard_response.json()["user"]["email"] == "ci-test@safety360.local"

    ticket_response = client.post(
        "/tickets",
        headers=headers,
        json={"description": "CI test ticket", "status": "open"},
    )
    assert ticket_response.status_code == 201, ticket_response.text
    assert ticket_response.json()["description"] == "CI test ticket"

    tickets_response = client.get("/tickets", headers=headers)
    assert tickets_response.status_code == 200, tickets_response.text
    tickets = tickets_response.json()["tickets"]
    assert len(tickets) == 1
    assert tickets[0]["description"] == "CI test ticket"

    unauthorized_response = client.get("/dashboard")
    assert unauthorized_response.status_code == 401
