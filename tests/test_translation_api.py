from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def _register_login_and_create_tenant(email: str) -> dict[str, str]:
    register = client.post(
        "/auth/register",
        json={
            "email": email,
            "password": "Secret123!",
            "full_name": "Translation Test Admin",
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
        json={"name": "Translation Test GmbH"},
    )
    assert tenant.status_code == 201, tenant.text
    return headers


def test_translation_capabilities_and_critical_identity_translation():
    headers = _register_login_and_create_tenant("translation@example.com")

    capabilities = client.get("/translation/capabilities", headers=headers)
    assert capabilities.status_code == 200, capabilities.text
    payload = capabilities.json()
    assert payload["arbitrary_bcp47_languages"] is True
    assert payload["critical_content_human_review_required"] is True
    assert payload["external_processing_allowed"] is False

    response = client.post(
        "/translation",
        headers=headers,
        json={
            "text": "Gefährdungsbeurteilung freigeben",
            "source_language": "de",
            "target_language": "de",
            "content_class": "hse",
        },
    )
    assert response.status_code == 200, response.text
    translated = response.json()
    assert translated["translated_text"] == "Gefährdungsbeurteilung freigeben"
    assert translated["machine_translated"] is False
    assert translated["human_review_required"] is True
    assert translated["external_processing"] is False


def test_translation_rejects_invalid_language_tag_and_disabled_provider():
    headers = _register_login_and_create_tenant("translation-validation@example.com")

    invalid_tag = client.post(
        "/translation",
        headers=headers,
        json={
            "text": "Test",
            "source_language": "de",
            "target_language": "not a language",
            "content_class": "general",
        },
    )
    assert invalid_tag.status_code == 422

    disabled_provider = client.post(
        "/translation",
        headers=headers,
        json={
            "text": "Test",
            "source_language": "de",
            "target_language": "en",
            "content_class": "general",
        },
    )
    assert disabled_provider.status_code == 503
