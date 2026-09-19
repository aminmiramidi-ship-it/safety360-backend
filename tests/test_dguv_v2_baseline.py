from fastapi.testclient import TestClient

from database import SessionLocal
from main import app
from models import User

client = TestClient(app)


def _register_login_admin(email: str) -> dict[str, str]:
    register_response = client.post(
        "/auth/register",
        json={
            "email": email,
            "password": "Secret123!",
            "full_name": "DGUV V2 Test Admin",
            "language": "de",
        },
    )
    assert register_response.status_code in {201, 409}, register_response.text

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        assert user is not None
        user.role = "admin"
        db.commit()
    finally:
        db.close()

    login_response = client.post(
        "/auth/login",
        json={"email": email, "password": "Secret123!"},
    )
    assert login_response.status_code == 200, login_response.text
    return {"Authorization": f"Bearer {login_response.json()['access_token']}"}


def test_dguv_v2_german_baseline_is_structured_and_review_gated():
    headers = _register_login_admin("dguv-v2-admin@example.com")

    seed_response = client.post(
        "/regulatory/de/dguv-v2-2024/seed",
        headers=headers,
    )
    assert seed_response.status_code == 201, seed_response.text
    seed = seed_response.json()
    assert seed["requirements"] >= 15
    assert seed["status"] == "master_template_review_required"
    assert "Unfallversicherungsträger" in seed["binding_version_rule"]

    status_response = client.get(
        "/regulatory/de/dguv-v2-2024/status",
        headers=headers,
    )
    assert status_response.status_code == 200, status_response.text
    status_payload = status_response.json()
    assert status_payload["requirements"] >= 15
    assert status_payload["review_required"] == status_payload["requirements"]
    assert "Mustertext" in status_payload["important_notice"]

    requirements_response = client.get(
        "/regulatory/requirements?jurisdiction=DE&management_system=ISO%2045001",
        headers=headers,
    )
    assert requirements_response.status_code == 200, requirements_response.text
    requirements = requirements_response.json()["requirements"]

    dguv_items = [
        item
        for item in requirements
        if item["source_id"] == seed["source_id"]
    ]
    assert len(dguv_items) >= 15

    basic_time = next(
        item
        for item in dguv_items
        if item["external_key"] == "dguv-v2-2024-annex2-basic-care-hours"
    )
    assert basic_time["applicability"]["hours_per_employee_year"] == {
        "I": 2.5,
        "II": 1.5,
        "III": 0.5,
    }
    assert basic_time["applicability"]["minimum_share_per_profession"] == 0.2
    assert basic_time["human_review_required"] is True


def test_dguv_v2_seed_is_idempotent():
    headers = _register_login_admin("dguv-v2-idempotent@example.com")

    first = client.post("/regulatory/de/dguv-v2-2024/seed", headers=headers)
    assert first.status_code == 201, first.text

    second = client.post("/regulatory/de/dguv-v2-2024/seed", headers=headers)
    assert second.status_code == 201, second.text
    payload = second.json()
    assert payload["created"] == 0
    assert payload["updated"] == 0
    assert payload["unchanged"] == payload["requirements"]
