from database import SessionLocal
from main import app
from models import User
from fastapi.testclient import TestClient

client = TestClient(app)


def _register(email: str) -> None:
    response = client.post(
        "/auth/register",
        json={
            "email": email,
            "password": "Secret123!",
            "full_name": "Regulatory Test User",
            "language": "de",
        },
    )
    assert response.status_code in {201, 409}, response.text


def _login(email: str) -> dict[str, str]:
    response = client.post(
        "/auth/login",
        json={"email": email, "password": "Secret123!"},
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _promote_admin(email: str) -> None:
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        assert user is not None
        user.role = "admin"
        db.commit()
    finally:
        db.close()


def test_regulatory_source_change_and_review_flow():
    admin_email = "regulatory-admin@example.com"
    _register(admin_email)
    _promote_admin(admin_email)
    headers = _login(admin_email)

    seed_response = client.post("/regulatory/sources/seed", headers=headers)
    assert seed_response.status_code == 201, seed_response.text

    sources_response = client.get("/regulatory/sources", headers=headers)
    assert sources_response.status_code == 200, sources_response.text
    sources = sources_response.json()["sources"]
    assert sources

    legal_source = next(item for item in sources if item["source_key"] == "gesetze-im-internet")

    initial_payload = {
        "source_id": legal_source["id"],
        "external_key": "arbschg-5",
        "title": "Arbeitsschutzgesetz § 5 - Beurteilung der Arbeitsbedingungen",
        "citation": "ArbSchG § 5",
        "summary": "Tätigkeitsbezogene Beurteilung der mit der Arbeit verbundenen Gefährdungen.",
        "jurisdiction": "DE",
        "topic": "risk_assessment",
        "management_system": "ISO 45001",
        "status": "current",
        "source_version": "test-v1",
        "applicability": {
            "workflow": ["activity", "risk_assessment"],
            "evidence_required": True,
        },
        "human_review_required": True,
    }
    create_response = client.put(
        "/regulatory/requirements/upsert",
        headers=headers,
        json=initial_payload,
    )
    assert create_response.status_code == 200, create_response.text
    created = create_response.json()
    assert created["change"] == "created"
    requirement_id = created["requirement"]["id"]
    assert created["requirement"]["human_review_required"] is True

    unchanged_response = client.put(
        "/regulatory/requirements/upsert",
        headers=headers,
        json=initial_payload,
    )
    assert unchanged_response.status_code == 200, unchanged_response.text
    assert unchanged_response.json()["change"] == "unchanged"

    changed_payload = dict(initial_payload)
    changed_payload["summary"] = (
        "Aktualisierte Testzusammenfassung; fachliche Anwendbarkeit muss vor verbindlicher Nutzung geprüft werden."
    )
    changed_payload["source_version"] = "test-v2"
    update_response = client.put(
        "/regulatory/requirements/upsert",
        headers=headers,
        json=changed_payload,
    )
    assert update_response.status_code == 200, update_response.text
    assert update_response.json()["change"] == "updated"
    assert update_response.json()["requirement"]["verified_at"] is None

    changes_response = client.get(
        "/regulatory/changes?review_status=pending",
        headers=headers,
    )
    assert changes_response.status_code == 200, changes_response.text
    pending = [
        item
        for item in changes_response.json()["changes"]
        if item["requirement_id"] == requirement_id
    ]
    assert pending

    review_response = client.post(
        f"/regulatory/requirements/{requirement_id}/review",
        headers=headers,
        json={
            "verified": True,
            "review_status": "reviewed",
            "impact": {
                "affected_workflows": ["risk_assessment", "instruction"],
                "requires_follow_up": True,
            },
        },
    )
    assert review_response.status_code == 200, review_response.text
    reviewed = review_response.json()
    assert reviewed["human_review_required"] is False
    assert reviewed["verified_at"] is not None


def test_regulatory_write_is_admin_only_but_read_is_available():
    reader_email = "regulatory-reader@example.com"
    _register(reader_email)
    headers = _login(reader_email)

    read_response = client.get("/regulatory/sources", headers=headers)
    assert read_response.status_code == 200, read_response.text

    forbidden_response = client.post("/regulatory/sources/seed", headers=headers)
    assert forbidden_response.status_code == 403, forbidden_response.text
