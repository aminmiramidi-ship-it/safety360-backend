import os
from pathlib import Path

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

TEST_DB = Path("test_safety360.db")
os.environ.setdefault("DATABASE_URL", f"sqlite:///{TEST_DB.resolve().as_posix()}")
os.environ.setdefault(
    "SAFETY360_SECRET_KEY",
    "test-secret-key-for-ci-only-change-in-production-1234567890",
)
os.environ.setdefault("ENCRYPTION_KEY", Fernet.generate_key().decode("utf-8"))
os.environ.setdefault("SAFETY360_ENV", "test")

from main import app

client = TestClient(app)


def register_and_login(email: str, full_name: str) -> dict[str, str]:
    register_response = client.post(
        "/auth/register",
        json={
            "email": email,
            "password": "Secret123!",
            "full_name": full_name,
            "language": "de",
        },
    )
    assert register_response.status_code == 201, register_response.text

    login_response = client.post(
        "/auth/login",
        json={
            "email": email,
            "password": "Secret123!",
        },
    )
    assert login_response.status_code == 200, login_response.text
    return {
        "Authorization": f"Bearer {login_response.json()['access_token']}"
    }


def test_tenant_invitation_acceptance_and_permissions():
    admin_headers = register_and_login(
        "invite-admin@example.com",
        "Invite Admin",
    )
    tenant_response = client.post(
        "/tenants",
        headers=admin_headers,
        json={"name": "Invitation Test GmbH"},
    )
    assert tenant_response.status_code == 201, tenant_response.text
    tenant_id = tenant_response.json()["id"]

    invitee_headers = register_and_login(
        "invitee@example.com",
        "Invited HSE Manager",
    )
    wrong_user_headers = register_and_login(
        "wrong-invite-user@example.com",
        "Wrong Invite User",
    )

    invitation_response = client.post(
        "/tenants/invitations",
        headers=admin_headers,
        json={
            "email": "invitee@example.com",
            "role": "hse_manager",
            "expires_in_hours": 24,
        },
    )
    assert invitation_response.status_code == 201, invitation_response.text
    invitation = invitation_response.json()
    assert invitation["tenant_id"] == tenant_id
    assert invitation["role"] == "hse_manager"
    assert invitation["invitation_token"]

    pending_response = client.get(
        "/tenants/invitations",
        headers=admin_headers,
    )
    assert pending_response.status_code == 200, pending_response.text
    pending = pending_response.json()["invitations"]
    assert len(pending) == 1
    assert pending[0]["email"] == "invitee@example.com"
    assert "invitation_token" not in pending[0]
    assert "token_hash" not in pending[0]

    wrong_accept = client.post(
        "/tenants/invitations/accept",
        headers=wrong_user_headers,
        json={"invitation_token": invitation["invitation_token"]},
    )
    assert wrong_accept.status_code == 403

    accept_response = client.post(
        "/tenants/invitations/accept",
        headers=invitee_headers,
        json={"invitation_token": invitation["invitation_token"]},
    )
    assert accept_response.status_code == 200, accept_response.text
    accepted_user = accept_response.json()
    assert accepted_user["tenant_id"] == tenant_id
    assert accepted_user["role"] == "hse_manager"

    me_response = client.get("/auth/me", headers=invitee_headers)
    assert me_response.status_code == 200, me_response.text
    assert me_response.json()["tenant_id"] == tenant_id
    assert me_response.json()["role"] == "hse_manager"

    reused_response = client.post(
        "/tenants/invitations/accept",
        headers=invitee_headers,
        json={"invitation_token": invitation["invitation_token"]},
    )
    assert reused_response.status_code == 409

    closed_response = client.get(
        "/tenants/invitations?include_closed=true",
        headers=admin_headers,
    )
    assert closed_response.status_code == 200, closed_response.text
    closed = closed_response.json()["invitations"]
    assert len(closed) == 1
    assert closed[0]["accepted_at"] is not None

    non_admin_invite = client.post(
        "/tenants/invitations",
        headers=invitee_headers,
        json={
            "email": "should-not-work@example.com",
            "role": "user",
        },
    )
    assert non_admin_invite.status_code == 403
