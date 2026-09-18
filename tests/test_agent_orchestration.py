from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def _register_login_and_create_tenant(email: str) -> dict[str, str]:
    register = client.post(
        "/auth/register",
        json={
            "email": email,
            "password": "Secret123!",
            "full_name": "Agent Autopilot Admin",
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
        json={"name": "Agent Autopilot GmbH"},
    )
    assert tenant.status_code == 201, tenant.text
    return headers


def test_agent_catalog_and_cross_domain_plan():
    headers = _register_login_and_create_tenant("agent-catalog@example.com")

    catalog = client.get("/agents/catalog", headers=headers)
    assert catalog.status_code == 200, catalog.text
    payload = catalog.json()
    ids = {item["id"] for item in payload["agents"]}
    assert "hse_ims" in ids
    assert "security_privacy" in ids
    assert "market_marketing" in ids
    assert "sales_intelligence" in ids
    assert "governance_audit" in ids
    assert payload["learning_mode"] == "feedback_and_outcome_adaptation"

    plan = client.post(
        "/agents/plan",
        headers=headers,
        json={
            "objective": (
                "Safety360 für Rechenzentren positionieren, passende Firmen identifizieren, "
                "Marketing verbessern und Security sowie IMS-Anforderungen prüfen."
            ),
            "context": "Mehrsprachige Web-App und sichere B2B-Plattform.",
        },
    )
    assert plan.status_code == 200, plan.text
    data = plan.json()
    agent_ids = {task["agent_id"] for task in data["tasks"]}
    assert "security_privacy" in agent_ids
    assert "market_marketing" in agent_ids
    assert "sales_intelligence" in agent_ids
    assert "hse_ims" in agent_ids
    assert "governance_audit" in agent_ids
    assert data["learning_mode"] == "feedback_and_outcome_adaptation"

    marketing_task = next(task for task in data["tasks"] if task["agent_id"] == "market_marketing")
    assert marketing_task["human_review_required"] is True
    assert marketing_task["safe_to_auto_execute"] is False


def test_feedback_changes_tenant_local_agent_priority():
    headers = _register_login_and_create_tenant("agent-learning@example.com")

    initial = client.post(
        "/agents/plan",
        headers=headers,
        json={
            "objective": "Verbessere die Bedienbarkeit der Safety360 Web-App.",
            "requested_agents": ["ux_assistance"],
        },
    )
    assert initial.status_code == 200, initial.text
    initial_data = initial.json()
    run_id = initial_data["run_id"]
    initial_ux = next(task for task in initial_data["tasks"] if task["agent_id"] == "ux_assistance")
    assert initial_ux["adaptation_adjustment"] == 0

    feedback = client.post(
        "/agents/feedback",
        headers=headers,
        json={
            "run_id": run_id,
            "agent_id": "ux_assistance",
            "outcome": "completed",
            "rating": 5,
            "workflow": "web_app",
        },
    )
    assert feedback.status_code == 200, feedback.text
    assert feedback.json()["learned_adjustment"] > 0

    adaptation = client.get("/agents/adaptation", headers=headers)
    assert adaptation.status_code == 200, adaptation.text
    ux_status = next(
        item for item in adaptation.json()["agents"] if item["agent_id"] == "ux_assistance"
    )
    assert ux_status["feedback_count"] == 1
    assert ux_status["average_rating"] == 5.0
    assert ux_status["learned_adjustment"] > 0

    next_plan = client.post(
        "/agents/plan",
        headers=headers,
        json={
            "objective": "Verbessere die Bedienbarkeit der Safety360 Web-App.",
            "requested_agents": ["ux_assistance"],
        },
    )
    assert next_plan.status_code == 200, next_plan.text
    next_ux = next(
        task for task in next_plan.json()["tasks"] if task["agent_id"] == "ux_assistance"
    )
    assert next_ux["adaptation_adjustment"] > 0
    assert next_ux["priority"] > initial_ux["priority"]
