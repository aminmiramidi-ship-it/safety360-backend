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
    token = login_response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_complete_auth_and_ticket_flow():
    test_email = "ci-test@example.com"

    register_response = client.post(
        "/auth/register",
        json={
            "email": test_email,
            "password": "Secret123!",
            "full_name": "Safety360 CI",
            "language": "de",
        },
    )
    assert register_response.status_code == 201, register_response.text
    registered_user = register_response.json()
    assert registered_user["email"] == test_email
    assert registered_user["role"] == "user"
    assert "password" not in registered_user
    assert "password_hash" not in registered_user

    duplicate_response = client.post(
        "/auth/register",
        json={
            "email": test_email,
            "password": "Secret123!",
            "full_name": "Duplicate",
            "language": "de",
        },
    )
    assert duplicate_response.status_code == 409

    bad_login_response = client.post(
        "/auth/login",
        json={
            "email": test_email,
            "password": "WrongPassword!",
        },
    )
    assert bad_login_response.status_code == 401

    login_response = client.post(
        "/auth/login",
        json={
            "email": test_email,
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
    assert me_response.json()["email"] == test_email

    dashboard_response = client.get("/dashboard", headers=headers)
    assert dashboard_response.status_code == 200, dashboard_response.text
    assert dashboard_response.json()["user"]["email"] == test_email

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


def test_tenant_onboarding_and_isolation():
    alpha_headers = register_and_login(
        "alpha-admin@example.com",
        "Alpha Admin",
    )

    alpha_create = client.post(
        "/tenants",
        headers=alpha_headers,
        json={"name": "Alpha GmbH"},
    )
    assert alpha_create.status_code == 201, alpha_create.text
    alpha_tenant = alpha_create.json()
    assert alpha_tenant["name"] == "Alpha GmbH"
    assert alpha_tenant["slug"] == "alpha-gmbh"

    alpha_current = client.get("/tenants/current", headers=alpha_headers)
    assert alpha_current.status_code == 200, alpha_current.text
    assert alpha_current.json()["id"] == alpha_tenant["id"]

    alpha_me = client.get("/auth/me", headers=alpha_headers)
    assert alpha_me.status_code == 200, alpha_me.text
    assert alpha_me.json()["tenant_id"] == alpha_tenant["id"]
    assert alpha_me.json()["role"] == "tenant_admin"

    alpha_ticket = client.post(
        "/tickets",
        headers=alpha_headers,
        json={"description": "Alpha confidential ticket", "status": "open"},
    )
    assert alpha_ticket.status_code == 201, alpha_ticket.text
    assert alpha_ticket.json()["tenant_id"] == alpha_tenant["id"]

    beta_headers = register_and_login(
        "beta-admin@example.com",
        "Beta Admin",
    )

    beta_before_tenant = client.get("/tickets", headers=beta_headers)
    assert beta_before_tenant.status_code == 200, beta_before_tenant.text
    assert beta_before_tenant.json()["tickets"] == []

    beta_create = client.post(
        "/tenants",
        headers=beta_headers,
        json={"name": "Beta AG"},
    )
    assert beta_create.status_code == 201, beta_create.text
    beta_tenant = beta_create.json()
    assert beta_tenant["id"] != alpha_tenant["id"]

    beta_ticket = client.post(
        "/tickets",
        headers=beta_headers,
        json={"description": "Beta confidential ticket", "status": "open"},
    )
    assert beta_ticket.status_code == 201, beta_ticket.text

    beta_list = client.get("/tickets", headers=beta_headers)
    assert beta_list.status_code == 200, beta_list.text
    beta_tickets = beta_list.json()["tickets"]
    assert len(beta_tickets) == 1
    assert beta_tickets[0]["description"] == "Beta confidential ticket"

    alpha_list = client.get("/tickets", headers=alpha_headers)
    assert alpha_list.status_code == 200, alpha_list.text
    alpha_tickets = alpha_list.json()["tickets"]
    assert len(alpha_tickets) == 1
    assert alpha_tickets[0]["description"] == "Alpha confidential ticket"

    second_tenant_attempt = client.post(
        "/tenants",
        headers=alpha_headers,
        json={"name": "Should Fail GmbH"},
    )
    assert second_tenant_attempt.status_code == 409


def test_document_control_workflow_and_tenant_isolation():
    owner_headers = register_and_login(
        "document-owner@example.com",
        "Document Owner",
    )

    tenant_response = client.post(
        "/tenants",
        headers=owner_headers,
        json={"name": "Document Control GmbH"},
    )
    assert tenant_response.status_code == 201, tenant_response.text

    create_response = client.post(
        "/documents",
        headers=owner_headers,
        json={
            "title": "Gefährdungsbeurteilung Arbeiten in der Höhe",
            "document_type": "risk_assessment",
            "content_summary": "Initiale kontrollierte Dokumentversion.",
        },
    )
    assert create_response.status_code == 201, create_response.text
    document = create_response.json()
    assert document["status"] == "draft"
    assert document["version"] == 1
    assert document["logical_id"]

    submit_response = client.post(
        f"/documents/{document['id']}/submit-review",
        headers=owner_headers,
    )
    assert submit_response.status_code == 200, submit_response.text
    assert submit_response.json()["status"] == "review"

    approve_response = client.post(
        f"/documents/{document['id']}/approve",
        headers=owner_headers,
    )
    assert approve_response.status_code == 200, approve_response.text
    approved = approve_response.json()
    assert approved["status"] == "approved"
    assert approved["approved_by_id"] is not None
    assert approved["approved_at"] is not None

    revision_response = client.post(
        f"/documents/{document['id']}/revisions",
        headers=owner_headers,
        json={
            "content_summary": "Überarbeitete Version nach Maßnahmenreview.",
        },
    )
    assert revision_response.status_code == 201, revision_response.text
    revision = revision_response.json()
    assert revision["version"] == 2
    assert revision["status"] == "draft"
    assert revision["logical_id"] == document["logical_id"]

    history_response = client.get(
        "/documents?latest_only=false",
        headers=owner_headers,
    )
    assert history_response.status_code == 200, history_response.text
    history = history_response.json()["documents"]
    assert len(history) == 2
    statuses = {item["version"]: item["status"] for item in history}
    assert statuses[1] == "obsolete"
    assert statuses[2] == "draft"

    latest_response = client.get("/documents", headers=owner_headers)
    assert latest_response.status_code == 200, latest_response.text
    latest_documents = latest_response.json()["documents"]
    assert len(latest_documents) == 1
    assert latest_documents[0]["version"] == 2

    other_headers = register_and_login(
        "other-document-admin@example.com",
        "Other Tenant Admin",
    )
    other_tenant = client.post(
        "/tenants",
        headers=other_headers,
        json={"name": "Other Tenant GmbH"},
    )
    assert other_tenant.status_code == 201, other_tenant.text

    cross_tenant_read = client.get(
        f"/documents/{revision['id']}",
        headers=other_headers,
    )
    assert cross_tenant_read.status_code == 404

    other_list = client.get("/documents", headers=other_headers)
    assert other_list.status_code == 200, other_list.text
    assert other_list.json()["documents"] == []
