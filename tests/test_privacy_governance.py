from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def register_login_and_create_tenant(email: str, tenant_name: str) -> dict[str, str]:
    register_response = client.post(
        "/auth/register",
        json={
            "email": email,
            "password": "Secret123!",
            "full_name": "Privacy Admin",
            "language": "de",
        },
    )
    assert register_response.status_code == 201, register_response.text

    login_response = client.post(
        "/auth/login",
        json={"email": email, "password": "Secret123!"},
    )
    assert login_response.status_code == 200, login_response.text
    headers = {"Authorization": f"Bearer {login_response.json()['access_token']}"}

    tenant_response = client.post(
        "/tenants",
        headers=headers,
        json={"name": tenant_name},
    )
    assert tenant_response.status_code == 201, tenant_response.text
    return headers


def test_privacy_governance_flow_and_pseudonymized_dsar():
    headers = register_login_and_create_tenant(
        "privacy-admin@example.com",
        "Privacy Test GmbH",
    )

    initial_overview = client.get("/privacy/overview", headers=headers)
    assert initial_overview.status_code == 200, initial_overview.text
    assert initial_overview.json()["processing_activities"] == 0
    assert initial_overview.json()["raw_subject_identifiers_stored_in_dsar"] is False

    processing_response = client.post(
        "/privacy/processing-activities",
        headers=headers,
        json={
            "name": "Arbeitsmedizinische Vorsorgeverwaltung",
            "purpose": "Organisation und Nachweis arbeitsmedizinischer Vorsorgeprozesse.",
            "legal_basis": "tenant-configured legal basis",
            "data_subject_categories": ["employees"],
            "personal_data_categories": ["identity", "employment", "health-related metadata"],
            "recipients": ["authorized occupational health roles"],
            "third_country_transfers": [],
            "retention_summary": "According to approved tenant retention policy.",
            "security_measures_summary": "Role based access, tenant isolation, audit logging.",
            "owner_role": "privacy_officer",
            "high_risk": True,
            "special_categories": True,
            "status": "active",
        },
    )
    assert processing_response.status_code == 201, processing_response.text
    activity = processing_response.json()
    assert activity["high_risk"] is True
    assert activity["special_categories"] is True

    dpia_response = client.post(
        "/privacy/dpias",
        headers=headers,
        json={
            "processing_activity_id": activity["id"],
            "necessity_proportionality": "Processing scope must remain limited to the approved purpose.",
            "risk_summary": "Potential unauthorized access to sensitive employee information.",
            "safeguards_summary": "Least privilege, strong authentication, audit trail and data minimization.",
            "residual_risk_level": "medium",
            "dpo_consulted": True,
            "status": "in_review",
        },
    )
    assert dpia_response.status_code == 201, dpia_response.text
    assert dpia_response.json()["processing_activity_id"] == activity["id"]

    retention_response = client.post(
        "/privacy/retention-rules",
        headers=headers,
        json={
            "data_category": "occupational-health-process-metadata",
            "source_system": "safety360",
            "legal_basis": "tenant-configured retention requirement",
            "retention_days": 365,
            "trigger_event": "process_closed",
            "disposition": "review",
            "legal_hold_supported": True,
            "is_active": True,
        },
    )
    assert retention_response.status_code == 201, retention_response.text

    raw_subject_reference = "employee-privacy-test@example.com"
    dsar_response = client.post(
        "/privacy/data-subject-requests",
        headers=headers,
        json={
            "request_type": "access",
            "subject_reference": raw_subject_reference,
            "jurisdiction": "EU-GDPR",
        },
    )
    assert dsar_response.status_code == 201, dsar_response.text
    dsar = dsar_response.json()
    assert "subject_reference" not in dsar
    assert "subject_reference_hash" not in dsar
    assert raw_subject_reference not in dsar_response.text
    assert dsar["status"] == "open"
    assert dsar["verification_status"] == "pending"

    premature_completion = client.patch(
        f"/privacy/data-subject-requests/{dsar['request_id']}",
        headers=headers,
        json={"status": "completed"},
    )
    assert premature_completion.status_code == 409

    verify_response = client.patch(
        f"/privacy/data-subject-requests/{dsar['request_id']}",
        headers=headers,
        json={"verification_status": "verified", "status": "in_review"},
    )
    assert verify_response.status_code == 200, verify_response.text
    assert verify_response.json()["verification_status"] == "verified"

    complete_response = client.patch(
        f"/privacy/data-subject-requests/{dsar['request_id']}",
        headers=headers,
        json={"status": "completed"},
    )
    assert complete_response.status_code == 200, complete_response.text
    assert complete_response.json()["completed_at"] is not None

    final_overview = client.get("/privacy/overview", headers=headers)
    assert final_overview.status_code == 200, final_overview.text
    overview = final_overview.json()
    assert overview["processing_activities"] == 1
    assert overview["high_risk_processing_activities"] == 1
    assert overview["special_category_processing_activities"] == 1
    assert overview["dpias"] == 1
    assert overview["retention_rules"] == 1
    assert overview["open_data_subject_requests"] == 0


def test_privacy_records_are_tenant_isolated():
    first_headers = register_login_and_create_tenant(
        "privacy-alpha@example.com",
        "Privacy Alpha GmbH",
    )
    second_headers = register_login_and_create_tenant(
        "privacy-beta@example.com",
        "Privacy Beta GmbH",
    )

    create_response = client.post(
        "/privacy/processing-activities",
        headers=first_headers,
        json={
            "name": "Alpha only processing",
            "purpose": "Tenant isolation test",
            "legal_basis": "tenant-configured legal basis",
            "status": "active",
        },
    )
    assert create_response.status_code == 201, create_response.text

    first_list = client.get("/privacy/processing-activities", headers=first_headers)
    assert first_list.status_code == 200, first_list.text
    assert len(first_list.json()["activities"]) == 1

    second_list = client.get("/privacy/processing-activities", headers=second_headers)
    assert second_list.status_code == 200, second_list.text
    assert second_list.json()["activities"] == []
