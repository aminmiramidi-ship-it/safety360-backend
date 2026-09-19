from fastapi.testclient import TestClient

from database import SessionLocal
from main import app
from models import User

client = TestClient(app)


def _register(email: str) -> None:
    response = client.post(
        "/auth/register",
        json={
            "email": email,
            "password": "Secret123!",
            "full_name": "Legal Graph Test User",
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


def _create_tenant(headers: dict[str, str], name: str) -> None:
    response = client.post("/tenants", headers=headers, json={"name": name})
    assert response.status_code in {201, 409}, response.text


def test_legal_graph_applicability_review_and_impact_flow():
    email = "legal-graph-admin@example.com"
    _register(email)
    headers = _login(email)
    _create_tenant(headers, "Legal Graph GmbH")
    _promote_admin(email)
    headers = _login(email)

    seed = client.post("/regulatory/de-eu/baseline/seed", headers=headers)
    assert seed.status_code == 201, seed.text

    requirements = client.get("/regulatory/requirements?jurisdiction=DE", headers=headers)
    assert requirements.status_code == 200, requirements.text
    arbschg = next(
        item
        for item in requirements.json()["requirements"]
        if item["external_key"] == "de-arbschg"
    )

    subject_response = client.post(
        "/regulatory/legal-graph/subjects",
        headers=headers,
        json={
            "subject_type": "activity",
            "subject_key": "dc-electrical-switching",
            "title": "Schalthandlungen an elektrischen Anlagen im Rechenzentrum",
            "jurisdiction": "DE",
            "metadata": {
                "industry": "data_center",
                "site": "test-site-de",
                "evidence_status": "partial",
            },
        },
    )
    assert subject_response.status_code == 201, subject_response.text
    subject_id = subject_response.json()["id"]

    assessment_response = client.put(
        "/regulatory/legal-graph/assessments",
        headers=headers,
        json={
            "requirement_id": arbschg["id"],
            "subject_id": subject_id,
            "applicability_status": "review_required",
            "origin": "agent",
            "confidence": 78,
            "priority": "high",
            "rationale": "Die Tätigkeit fällt in den betrieblichen Arbeitsschutzkontext; konkrete Evidenz ist noch zu prüfen.",
            "evidence": {"jurisdiction": "DE", "activity_confirmed": True},
            "missing_evidence": ["aktuelle tätigkeitsbezogene Gefährdungsbeurteilung"],
        },
    )
    assert assessment_response.status_code == 200, assessment_response.text
    assessment = assessment_response.json()
    assert assessment["human_review_required"] is True
    assert assessment["origin"] == "agent"

    matrix_response = client.get(
        f"/regulatory/legal-graph/matrix?requirement_id={arbschg['id']}",
        headers=headers,
    )
    assert matrix_response.status_code == 200, matrix_response.text
    assert matrix_response.json()["count"] >= 1
    assert matrix_response.json()["rows"][0]["subject"]["subject_key"] == "dc-electrical-switching"

    review_response = client.post(
        f"/regulatory/legal-graph/assessments/{assessment['id']}/review",
        headers=headers,
        json={
            "applicability_status": "applicable",
            "confidence": 100,
            "priority": "high",
            "rationale": "Fachlich bestätigt; Anforderungen müssen im Tätigkeits- und GBU-Workflow berücksichtigt werden.",
            "evidence": {"reviewed": True, "jurisdiction": "DE"},
            "missing_evidence": [],
        },
    )
    assert review_response.status_code == 200, review_response.text
    assert review_response.json()["human_review_required"] is False
    assert review_response.json()["applicability_status"] == "applicable"

    impact_response = client.get(
        f"/regulatory/legal-graph/requirements/{arbschg['id']}/impact-preview",
        headers=headers,
    )
    assert impact_response.status_code == 200, impact_response.text
    impact = impact_response.json()
    assert impact["impact_count"] >= 1
    assert impact["impacts"][0]["suggested_action_type"] == "review_risk_assessment"

    action_response = client.post(
        "/regulatory/legal-graph/actions",
        headers=headers,
        json={
            "requirement_id": arbschg["id"],
            "subject_id": subject_id,
            "action_type": "review_risk_assessment",
            "target_ref": "risk-assessment:dc-electrical-switching",
            "priority": "high",
            "rationale": "Rechtsanforderung wurde für die Tätigkeit bestätigt.",
            "evidence": {"assessment_id": assessment["id"]},
        },
    )
    assert action_response.status_code == 201, action_response.text
    action = action_response.json()
    assert action["status"] == "proposed"
    assert action["human_review_required"] is True

    approve_response = client.post(
        f"/regulatory/legal-graph/actions/{action['id']}/review",
        headers=headers,
        json={"approved": True},
    )
    assert approve_response.status_code == 200, approve_response.text
    assert approve_response.json()["status"] == "approved"
    assert approve_response.json()["human_review_required"] is False

    summary_response = client.get("/regulatory/legal-graph/summary", headers=headers)
    assert summary_response.status_code == 200, summary_response.text
    assert summary_response.json()["subjects"] >= 1
    assert summary_response.json()["applicable"] >= 1


def test_legal_graph_is_tenant_isolated_and_manage_is_restricted():
    reader_email = "legal-graph-reader@example.com"
    _register(reader_email)
    reader_headers = _login(reader_email)

    forbidden = client.post(
        "/regulatory/legal-graph/subjects",
        headers=reader_headers,
        json={
            "subject_type": "site",
            "subject_key": "forbidden-site",
            "title": "Nicht zulässiger Schreibversuch",
        },
    )
    assert forbidden.status_code == 403, forbidden.text

    tenant_email = "legal-graph-beta@example.com"
    _register(tenant_email)
    tenant_headers = _login(tenant_email)
    _create_tenant(tenant_headers, "Legal Graph Beta GmbH")

    own_subjects = client.get("/regulatory/legal-graph/subjects", headers=tenant_headers)
    assert own_subjects.status_code == 200, own_subjects.text
    assert all(item["subject_key"] != "dc-electrical-switching" for item in own_subjects.json()["subjects"])
