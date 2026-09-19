from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from database import SessionLocal
from main import app
from models import User

client = TestClient(app)


def _register_login(email: str) -> dict[str, str]:
    response = client.post(
        "/auth/register",
        json={"email": email, "password": "Secret123!", "full_name": "Occupational Health Test", "language": "de"},
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


def test_occupational_health_autopilot_and_privacy_boundary():
    admin_email = "occ-health-admin@example.com"
    headers = _register_login(admin_email)
    _tenant(headers, "Occupational Health GmbH")
    _promote(admin_email, "tenant_admin")
    headers = _register_login(admin_email)

    requirement = client.post(
        "/occupational-health/requirements",
        headers=headers,
        json={
            "requirement_key": "forklift-health-gate-example",
            "title": "Arbeitsmedizinischer/Eignungsbezogener Prüfschritt für Flurförderzeug-Tätigkeit",
            "requirement_kind": "other",
            "trigger_type": "activity",
            "trigger_ref": "forklift_operation",
            "legal_basis_ref": "review_required:not hardcoded; determine from risk assessment and applicable law",
            "recurrence_days": 1095,
            "due_soon_days": 45,
        },
    )
    assert requirement.status_code == 201, requirement.text
    requirement_id = requirement.json()["id"]

    overdue = datetime.now(timezone.utc) - timedelta(days=3)
    case = client.put(
        "/occupational-health/cases",
        headers=headers,
        json={
            "requirement_id": requirement_id,
            "employee_ref": "employee:forklift-001",
            "manager_ref": "manager:warehouse",
            "provider_ref": "provider:occupational-physician",
            "due_at": overdue.isoformat(),
        },
    )
    assert case.status_code == 200, case.text
    case_id = case.json()["id"]

    evaluation = client.post("/occupational-health/autopilot/evaluate", headers=headers)
    assert evaluation.status_code == 200, evaluation.text
    assert evaluation.json()["evaluated"] >= 1

    cases = client.get("/occupational-health/cases", headers=headers)
    assert cases.status_code == 200, cases.text
    selected = next(item for item in cases.json()["cases"] if item["id"] == case_id)
    assert selected["status"] == "red"
    assert "Befund" not in (selected["employer_visible_summary"] or "")

    notifications = client.get("/occupational-health/notifications", headers=headers)
    assert notifications.status_code == 200, notifications.text
    recipients = {(item["recipient_type"], item["recipient_ref"]) for item in notifications.json()["notifications"]}
    assert ("employee", "employee:forklift-001") in recipients
    assert ("manager", "manager:warehouse") in recipients
    assert all(item["minimum_disclosure"] is True for item in notifications.json()["notifications"])

    boundary = client.get("/occupational-health/privacy-boundary", headers=headers)
    assert boundary.status_code == 200, boundary.text
    assert "Diagnosen" in boundary.json()["clinical_layer"]


def test_scheduling_and_clinical_evidence_are_role_separated():
    admin_email = "occ-schedule-admin@example.com"
    headers = _register_login(admin_email)
    _tenant(headers, "Schedule Health GmbH")
    _promote(admin_email, "tenant_admin")
    headers = _register_login(admin_email)

    requirement = client.post(
        "/occupational-health/requirements",
        headers=headers,
        json={
            "requirement_key": "scheduled-care-example",
            "title": "Terminpflichtiger arbeitsmedizinischer Prüfschritt",
            "requirement_kind": "preventive_care_offer",
            "trigger_type": "activity",
            "trigger_ref": "example_activity",
            "due_soon_days": 30,
        },
    )
    requirement_id = requirement.json()["id"]
    case = client.put(
        "/occupational-health/cases",
        headers=headers,
        json={
            "requirement_id": requirement_id,
            "employee_ref": "employee:schedule-001",
            "manager_ref": "manager:ops",
            "provider_ref": "provider:doctor-001",
            "due_at": (datetime.now(timezone.utc) + timedelta(days=7)).isoformat(),
        },
    )
    case_id = case.json()["id"]

    start = datetime.now(timezone.utc) + timedelta(days=2, hours=2)
    proposal = client.post(
        "/occupational-health/appointments/propose",
        headers=headers,
        json={
            "case_id": case_id,
            "employee_windows": [{"start": start.isoformat(), "end": (start + timedelta(hours=2)).isoformat()}],
            "provider_windows": [{"start": (start + timedelta(minutes=30)).isoformat(), "end": (start + timedelta(hours=3)).isoformat()}],
            "duration_minutes": 30,
            "employee_calendar_provider": "outlook-calendar",
            "provider_calendar_provider": "outlook-calendar",
            "consent_or_legal_basis_ref": "tenant-policy:occupational-health-scheduling",
        },
    )
    assert proposal.status_code == 201, proposal.text
    assert proposal.json()["minimum_disclosure_confirmed"] is True

    physician_email = "occupational-physician@example.com"
    physician_headers = _register_login(physician_email)
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.email == admin_email).first()
        physician = db.query(User).filter(User.email == physician_email).first()
        assert admin is not None and physician is not None
        physician.tenant_id = admin.tenant_id
        physician.role = "occupational_physician"
        db.commit()
    finally:
        db.close()
    physician_headers = _register_login(physician_email)

    evidence = client.post(
        "/occupational-health/evidence",
        headers=physician_headers,
        json={
            "case_id": case_id,
            "evidence_type": "clinical_report",
            "file_ref": "secure-clinical:report-001",
            "issued_at": datetime.now(timezone.utc).isoformat(),
            "contains_clinical_findings": True,
            "employer_access_allowed": True,
        },
    )
    assert evidence.status_code == 201, evidence.text
    assert evidence.json()["contains_clinical_findings"] is True
    assert evidence.json()["employer_access_allowed"] is False
    assert evidence.json()["clinician_only"] is True
