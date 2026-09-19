import os
from pathlib import Path

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

TEST_DB = Path("test_safety360.db")
os.environ.setdefault("DATABASE_URL", f"sqlite:///{TEST_DB.resolve().as_posix()}")
os.environ.setdefault("SAFETY360_SECRET_KEY", "test-secret-key-for-ci-only-change-in-production-1234567890")
os.environ.setdefault("ENCRYPTION_KEY", Fernet.generate_key().decode("utf-8"))
os.environ.setdefault("SAFETY360_ENV", "test")

from main import app

client = TestClient(app)


def _auth_headers(email: str) -> dict[str, str]:
    register_response = client.post(
        "/auth/register",
        json={
            "email": email,
            "password": "Secret123!",
            "full_name": "Industry Intelligence Test",
            "language": "de",
        },
    )
    assert register_response.status_code in {201, 409}, register_response.text

    login_response = client.post(
        "/auth/login",
        json={"email": email, "password": "Secret123!"},
    )
    assert login_response.status_code == 200, login_response.text
    return {"Authorization": f"Bearer {login_response.json()['access_token']}"}


def test_industry_scheme_catalog_is_available_to_authenticated_users():
    headers = _auth_headers("industry-reader@example.com")
    response = client.get("/industry/schemes", headers=headers)
    assert response.status_code == 200, response.text

    schemes = {item["scheme"] for item in response.json()["schemes"]}
    assert "WZ2025" in schemes
    assert "NACE2.1" in schemes
    assert "ISIC5" in schemes


def test_industry_endpoints_require_authentication():
    response = client.get("/industry/schemes")
    assert response.status_code == 401
