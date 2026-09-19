from fastapi.testclient import TestClient

from database import SessionLocal
from learning_content_models import LearningContentPack
from main import app
from models import User
from regulatory_models import RegulatoryRequirement, RegulatorySource

client = TestClient(app)


def _register_login(email: str) -> dict[str, str]:
    response = client.post(
        "/auth/register",
        json={
            "email": email,
            "password": "Secret123!",
            "full_name": "Content Impact Test",
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


def _create_pack(headers: dict[str, str], key: str) -> dict[str, object]:
    response = client.post(
        "/content-factory/packs",
        headers=headers,
        json={
            "pack_key": key,
            "title": f"Governed pack {key}",
            "activity_ref": "example_activity",
            "jurisdiction": "DE",
            "target_audience": "employees",
            "language": "de",
            "depth_profile": "standard",
            "source_refs": ["regulatory:source-backed"],
            "requirement_refs": ["requirement:source-backed"],
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _create_regulatory_requirement() -> int:
    db = SessionLocal()
    try:
        source = db.query(RegulatorySource).filter(
            RegulatorySource.authority == "Safety360 Impact Test Authority",
            RegulatorySource.source_key == "impact-test-source",
        ).first()
        if source is None:
            source = RegulatorySource(
                authority="Safety360 Impact Test Authority",
                source_key="impact-test-source",
                name="Impact Test Primary Source",
                jurisdiction="DE",
                source_type="official_test_fixture",
                base_url="https://example.invalid/official-test-source",
                is_primary=True,
                enabled=True,
            )
            db.add(source)
            db.flush()
        requirement = db.query(RegulatoryRequirement).filter(
            RegulatoryRequirement.source_id == source.id,
            RegulatoryRequirement.external_key == "impact-test-requirement",
        ).first()
        if requirement is None:
            requirement = RegulatoryRequirement(
                source_id=source.id,
                external_key="impact-test-requirement",
                title="Source-backed requirement used by the impact-engine test",
                citation="TEST § 1",
                summary="Test fixture only",
                jurisdiction="DE",
                topic="occupational_safety",
                management_system="ISO 45001",
                status="current",
                source_version="v1",
                content_hash="a" * 64,
                applicability_json="{}",
                human_review_required=True,
            )
            db.add(requirement)
            db.flush()
        else:
            requirement.source_version = "v1"
            requirement.content_hash = "a" * 64
        db.commit()
        return int(requirement.id)
    finally:
        db.close()


def _mutate_regulatory_requirement(requirement_id: int) -> None:
    db = SessionLocal()
    try:
        requirement = db.query(RegulatoryRequirement).filter(RegulatoryRequirement.id == requirement_id).first()
        assert requirement is not None
        requirement.source_version = "v2"
        requirement.content_hash = "b" * 64
        db.commit()
    finally:
        db.close()


def test_regulatory_change_creates_review_impact_and_governed_revision():
    email = "content-impact-admin@example.com"
    headers = _register_login(email)
    _tenant(headers, "Content Impact GmbH")
    _promote(email, "tenant_admin")
    headers = _register_login(email)

    pack = _create_pack(headers, "impact-regulatory-chain")
    requirement_id = _create_regulatory_requirement()

    dependency = client.post(
        "/content-impact/dependencies",
        headers=headers,
        json={
            "content_pack_id": pack["id"],
            "dependency_kind": "regulatory_requirement",
            "reference_id": requirement_id,
        },
    )
    assert dependency.status_code == 201, dependency.text
    assert dependency.json()["baseline_hash"] == "a" * 64

    _mutate_regulatory_requirement(requirement_id)

    scan = client.post("/content-impact/impact-scan", headers=headers)
    assert scan.status_code == 200, scan.text
    assert scan.json()["detected"] >= 1

    impacts = client.get("/content-impact/impacts?status_filter=pending", headers=headers)
    assert impacts.status_code == 200, impacts.text
    selected = next(
        item
        for item in impacts.json()["impacts"]
        if item["content_pack_id"] == pack["id"] and item["trigger_type"] == "regulatory_requirement"
    )
    assert selected["previous_hash"] == "a" * 64
    assert selected["current_hash"] == "b" * 64
    assert selected["human_review_required"] is True

    db = SessionLocal()
    try:
        stored_pack = db.query(LearningContentPack).filter(LearningContentPack.id == pack["id"]).first()
        assert stored_pack is not None
        assert stored_pack.currentness_status == "review_required"
    finally:
        db.close()

    revision = client.post(
        f"/content-impact/impacts/{selected['id']}/create-revision",
        headers=headers,
        json={"change_reason": "Regulatory source changed; create a reviewed replacement revision."},
    )
    assert revision.status_code == 201, revision.text
    assert revision.json()["new_version"] == 2
    assert revision.json()["dependencies_cloned"] == 1

    old_dependencies = client.get(
        f"/content-impact/packs/{pack['id']}/dependencies",
        headers=headers,
    )
    assert old_dependencies.status_code == 200, old_dependencies.text
    assert old_dependencies.json()["dependencies"][0]["active"] is False

    new_pack_id = revision.json()["new_pack_id"]
    new_dependencies = client.get(
        f"/content-impact/packs/{new_pack_id}/dependencies",
        headers=headers,
    )
    assert new_dependencies.status_code == 200, new_dependencies.text
    assert new_dependencies.json()["dependencies"][0]["active"] is True
    assert new_dependencies.json()["dependencies"][0]["baseline_hash"] == "b" * 64


def test_content_impact_is_tenant_scoped():
    owner_email = "content-impact-owner@example.com"
    owner_headers = _register_login(owner_email)
    _tenant(owner_headers, "Impact Owner GmbH")
    _promote(owner_email, "tenant_admin")
    owner_headers = _register_login(owner_email)
    pack = _create_pack(owner_headers, "impact-owner-only")

    other_email = "content-impact-other@example.com"
    other_headers = _register_login(other_email)
    _tenant(other_headers, "Impact Other GmbH")
    _promote(other_email, "tenant_admin")
    other_headers = _register_login(other_email)

    cross_tenant = client.post(
        "/content-impact/dependencies",
        headers=other_headers,
        json={
            "content_pack_id": pack["id"],
            "dependency_kind": "manual_reference",
            "reference_key": "manual:test",
            "baseline_hash": "c" * 64,
        },
    )
    assert cross_tenant.status_code == 404, cross_tenant.text

    other_impacts = client.get("/content-impact/impacts", headers=other_headers)
    assert other_impacts.status_code == 200, other_impacts.text
    assert all(item["content_pack_id"] != pack["id"] for item in other_impacts.json()["impacts"])
