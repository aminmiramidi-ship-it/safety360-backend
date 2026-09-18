from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def _register_login_and_create_tenant(email: str) -> dict[str, str]:
    register = client.post(
        "/auth/register",
        json={
            "email": email,
            "password": "Secret123!",
            "full_name": "IMS Test Admin",
            "language": "de",
        },
    )
    assert register.status_code == 201, register.text

    login = client.post(
        "/auth/login",
        json={"email": email, "password": "Secret123!"},
    )
    assert login.status_code == 200, login.text
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    tenant = client.post(
        "/tenants",
        headers=headers,
        json={"name": "IMS Automation GmbH"},
    )
    assert tenant.status_code == 201, tenant.text
    return headers


def test_activity_to_controlled_ims_artifacts_flow():
    headers = _register_login_and_create_tenant("ims-autopilot@example.com")

    standards = client.get("/ims/standards", headers=headers)
    assert standards.status_code == 200, standards.text
    identifiers = {item["identifier"] for item in standards.json()["standards"]}
    assert "ISO 45001" in identifiers
    assert "ISO/IEC 27001" in identifiers
    assert "EN 50600" in identifiers

    activity_response = client.post(
        "/ims/activities",
        headers=headers,
        json={
            "title": "Generator-Testlauf im Rechenzentrum",
            "description": "Geplanter Funktionstest eines Notstromgenerators mit Kontrollgang im Technikbereich.",
            "industry": "data_center",
            "location": "Generatorbereich",
            "equipment": "Notstromgenerator, Schaltanlage, Prüfmittel",
            "substances": "Dieselkraftstoff und Betriebsstoffe",
            "environmental_context": "Emissionen, Leckage- und Abfallrisiken",
            "energy_context": "Lasttest und Energieverbrauch",
            "quality_context": "Prüfablauf, Freigabe und Nachweisführung",
            "information_security_context": "Zutrittskontrolle und Schutz betrieblicher Informationen",
        },
    )
    assert activity_response.status_code == 201, activity_response.text
    activity = activity_response.json()
    assert activity["status"] == "draft"

    generation = client.post(
        f"/ims/activities/{activity['id']}/generate",
        headers=headers,
        json={
            "standards": [
                "ISO 45001",
                "ISO 14001",
                "ISO 50001",
                "ISO 9001",
                "ISO/IEC 27001",
                "EN 50600",
            ],
            "artifact_types": [
                "risk_assessment",
                "operating_instruction",
                "training_plan",
                "ims_requirements_map",
            ],
        },
    )
    assert generation.status_code == 200, generation.text
    payload = generation.json()
    assert payload["activity"]["status"] == "generated"
    assert len(payload["artifacts"]) == 4
    assert len(payload["warnings"]) >= 1

    artifacts_by_type = {item["artifact_type"]: item for item in payload["artifacts"]}
    assert set(artifacts_by_type) == {
        "risk_assessment",
        "operating_instruction",
        "training_plan",
        "ims_requirements_map",
    }
    assert artifacts_by_type["risk_assessment"]["content"]["assessment_method"]["human_review_required"] is True
    assert artifacts_by_type["training_plan"]["content"]["delivery"]["competence_check_required"] is True

    approval = client.post(
        f"/ims/artifacts/{artifacts_by_type['risk_assessment']['id']}/approve",
        headers=headers,
    )
    assert approval.status_code == 200, approval.text
    assert approval.json()["status"] == "approved"
    assert approval.json()["approved_by_id"] is not None

    listing = client.get(
        f"/ims/activities/{activity['id']}/artifacts",
        headers=headers,
    )
    assert listing.status_code == 200, listing.text
    assert len(listing.json()["artifacts"]) == 4
