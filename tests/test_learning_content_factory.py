from fastapi.testclient import TestClient

from database import SessionLocal
from main import app
from models import User

client = TestClient(app)


def _register_login(email: str) -> dict[str, str]:
    response = client.post(
        "/auth/register",
        json={
            "email": email,
            "password": "Secret123!",
            "full_name": "Content Factory Test",
            "language": "de",
        },
    )
    assert response.status_code in {201, 409}, response.text
    login = client.post("/auth/login", json={"email": email, "password": "Secret123!"})
    assert login.status_code == 200, login.text
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


def _tenant(headers: dict[str, str], name: str) -> None:
    response = client.post("/tenants", headers=headers, json={"name": name})
    assert response.status_code in {201, 409}, response.text


def _promote(email: str, role: str) -> None:
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        assert user is not None
        user.role = role
        db.commit()
    finally:
        db.close()


def test_content_pack_generates_reviewable_linked_outlines():
    email = "content-factory-admin@example.com"
    headers = _register_login(email)
    _tenant(headers, "Content Factory GmbH")
    _promote(email, "tenant_admin")
    headers = _register_login(email)

    created = client.post(
        "/content-factory/packs",
        headers=headers,
        json={
            "pack_key": "forklift-warehouse-standard",
            "title": "Gabelstapler im Lager – integrierter HSE Content Pack",
            "activity_ref": "forklift_operation",
            "industry_scheme": "WZ2025",
            "industry_code": "52",
            "jurisdiction": "DE",
            "target_audience": "employees",
            "language": "de",
            "depth_profile": "standard",
            "source_refs": ["legal_graph:review_required"],
            "requirement_refs": ["risk_assessment:review_required"],
        },
    )
    assert created.status_code == 201, created.text
    pack = created.json()
    assert pack["version"] == 1
    assert pack["human_review_required"] is True

    generated = client.post(
        f"/content-factory/packs/{pack['id']}/generate-outlines",
        headers=headers,
    )
    assert generated.status_code == 200, generated.text
    artifacts = generated.json()["artifacts"]
    assert len(artifacts) == 9
    assert {item["artifact_type"] for item in artifacts} >= {
        "risk_assessment_outline",
        "operating_instruction_outline",
        "training_outline",
        "presentation_outline",
        "video_script_outline",
    }

    detail = client.get(f"/content-factory/packs/{pack['id']}", headers=headers)
    assert detail.status_code == 200, detail.text
    assert all(item["status"] == "draft" for item in detail.json()["artifacts"])
    assert all(item["human_review_required"] is True for item in detail.json()["artifacts"])

    artifact_id = detail.json()["artifacts"][0]["id"]
    approved = client.post(
        f"/content-factory/artifacts/{artifact_id}/review",
        headers=headers,
        json={"approved": True},
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "approved"
    assert approved.json()["human_review_required"] is False


def test_content_factory_is_role_protected():
    email = "content-factory-reader@example.com"
    headers = _register_login(email)
    response = client.get("/content-factory/packs", headers=headers)
    assert response.status_code == 403, response.text
    assert response.json()["detail"] == "Für diese Aktion fehlen die erforderlichen Berechtigungen."
