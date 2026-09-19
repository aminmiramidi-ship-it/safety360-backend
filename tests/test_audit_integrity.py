import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from audit_integrity import append_audit_event
from audit_models import AuditEvent
from database import SessionLocal
from main import app
from models import User

client = TestClient(app)


def _unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def _register_login_and_create_tenant(prefix: str):
    unique = _unique(prefix)
    email = f"{unique}@example.com"
    password = "Secret123!"

    register = client.post(
        "/auth/register",
        json={
            "email": email,
            "password": password,
            "full_name": f"{prefix} Audit Admin",
            "language": "de",
        },
    )
    assert register.status_code == 201, register.text

    login = client.post(
        "/auth/login",
        json={"email": email, "password": password},
    )
    assert login.status_code == 200, login.text
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    tenant = client.post(
        "/tenants",
        headers=headers,
        json={"name": f"{unique} GmbH"},
    )
    assert tenant.status_code == 201, tenant.text

    me = client.get("/auth/me", headers=headers)
    assert me.status_code == 200, me.text
    assert me.json()["role"] == "tenant_admin"

    return headers, tenant.json(), me.json()


def test_ticket_event_is_structured_and_chain_verifies():
    headers, tenant, _user = _register_login_and_create_tenant("audit-ticket")

    created = client.post(
        "/tickets",
        headers=headers,
        json={"description": "Audit integrity ticket", "status": "open"},
    )
    assert created.status_code == 201, created.text

    events_response = client.get("/audit/events", headers=headers)
    assert events_response.status_code == 200, events_response.text
    events = events_response.json()["events"]
    ticket_events = [event for event in events if event["action"] == "ticket.created"]
    assert ticket_events
    event = ticket_events[0]
    assert event["tenant_id"] == tenant["id"]
    assert event["object_type"] == "ticket"
    assert event["object_id"] == str(created.json()["id"])
    assert event["details"] == {"status": "open"}
    assert len(event["record_hash"]) == 64

    verification = client.get("/audit/verify", headers=headers)
    assert verification.status_code == 200, verification.text
    result = verification.json()
    assert result["valid"] is True
    assert result["checked_events"] >= 1
    assert result["head_hash"] == event["record_hash"]


def test_sensitive_audit_metadata_is_redacted():
    headers, tenant, user = _register_login_and_create_tenant("audit-redact")

    db = SessionLocal()
    try:
        append_audit_event(
            db,
            tenant_id=tenant["id"],
            actor_user_id=user["id"],
            action="security.redaction_test",
            object_type="security_test",
            object_id="redaction-1",
            source="test",
            details={
                "password": "NeverStoreThisPassword",
                "api_token": "NeverStoreThisToken",
                "safe_field": "visible",
                "nested": {"client_secret": "NeverStoreThisSecret", "status": "ok"},
            },
        )
        db.commit()
    finally:
        db.close()

    response = client.get(
        "/audit/events?action=security.redaction_test",
        headers=headers,
    )
    assert response.status_code == 200, response.text
    events = response.json()["events"]
    assert len(events) == 1
    details = events[0]["details"]
    assert details["password"] == "[redacted]"
    assert details["api_token"] == "[redacted]"
    assert details["safe_field"] == "visible"
    assert details["nested"]["client_secret"] == "[redacted]"
    assert details["nested"]["status"] == "ok"

    serialized = response.text
    assert "NeverStoreThisPassword" not in serialized
    assert "NeverStoreThisToken" not in serialized
    assert "NeverStoreThisSecret" not in serialized


def test_audit_api_enforces_tenant_isolation():
    alpha_headers, alpha_tenant, _ = _register_login_and_create_tenant("audit-alpha")
    beta_headers, beta_tenant, _ = _register_login_and_create_tenant("audit-beta")

    alpha_ticket = client.post(
        "/tickets",
        headers=alpha_headers,
        json={"description": "Alpha audit event", "status": "open"},
    )
    assert alpha_ticket.status_code == 201, alpha_ticket.text

    beta_ticket = client.post(
        "/tickets",
        headers=beta_headers,
        json={"description": "Beta audit event", "status": "open"},
    )
    assert beta_ticket.status_code == 201, beta_ticket.text

    forbidden = client.get(
        f"/audit/events?tenant_id={beta_tenant['id']}",
        headers=alpha_headers,
    )
    assert forbidden.status_code == 403, forbidden.text

    alpha_events = client.get("/audit/events", headers=alpha_headers)
    assert alpha_events.status_code == 200, alpha_events.text
    assert alpha_events.json()["tenant_id"] == alpha_tenant["id"]
    assert all(
        event["tenant_id"] == alpha_tenant["id"]
        for event in alpha_events.json()["events"]
    )

    beta_events = client.get("/audit/events", headers=beta_headers)
    assert beta_events.status_code == 200, beta_events.text
    assert beta_events.json()["tenant_id"] == beta_tenant["id"]
    assert all(
        event["tenant_id"] == beta_tenant["id"]
        for event in beta_events.json()["events"]
    )


def test_raw_database_tampering_is_detected():
    headers, tenant, _ = _register_login_and_create_tenant("audit-tamper")

    created = client.post(
        "/tickets",
        headers=headers,
        json={"description": "Tamper detection ticket", "status": "open"},
    )
    assert created.status_code == 201, created.text

    before = client.get("/audit/verify", headers=headers)
    assert before.status_code == 200, before.text
    assert before.json()["valid"] is True

    db = SessionLocal()
    try:
        target = (
            db.query(AuditEvent)
            .filter(
                AuditEvent.tenant_id == tenant["id"],
                AuditEvent.action == "ticket.created",
            )
            .order_by(AuditEvent.sequence.desc())
            .first()
        )
        assert target is not None
        db.execute(
            text("UPDATE audit_events SET details_json = :details WHERE id = :event_id"),
            {"details": '{"status":"tampered"}', "event_id": target.id},
        )
        db.commit()
    finally:
        db.close()

    after = client.get("/audit/verify", headers=headers)
    assert after.status_code == 200, after.text
    result = after.json()
    assert result["valid"] is False
    assert result["error"].startswith("record_hash_mismatch_at:")


def test_orm_audit_event_mutation_is_rejected():
    _headers, tenant, user = _register_login_and_create_tenant("audit-append-only")

    db = SessionLocal()
    try:
        event = append_audit_event(
            db,
            tenant_id=tenant["id"],
            actor_user_id=user["id"],
            action="audit.append_only_test",
            object_type="audit_test",
            object_id="append-only-1",
            details={"status": "original"},
        )
        db.commit()
        event_id = event.id
    finally:
        db.close()

    db = SessionLocal()
    try:
        stored = db.query(AuditEvent).filter(AuditEvent.id == event_id).one()
        stored.outcome = "tampered"
        with pytest.raises(RuntimeError, match="append-only"):
            db.commit()
        db.rollback()
    finally:
        db.close()
