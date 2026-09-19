from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def _auth_headers(email: str) -> dict[str, str]:
    register_response = client.post(
        "/auth/register",
        json={
            "email": email,
            "password": "Secret123!",
            "full_name": "Translation Test",
            "language": "de",
        },
    )
    assert register_response.status_code in {201, 409}, register_response.text

    login_response = client.post(
        "/auth/login",
        json={"email": email, "password": "Secret123!"},
    )
    assert login_response.status_code == 200, login_response.text
    return {"Authorization": f"Bearer {login_response.json()['access_token']}"}


def test_translation_same_language_needs_no_provider():
    headers = _auth_headers("translation-identity@example.com")
    response = client.post(
        "/platform/translation/translate",
        headers=headers,
        json={
            "text": "Sicher arbeiten",
            "source_language": "de",
            "target_language": "de",
            "criticality": "hse_critical",
        },
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["translated_text"] == "Sicher arbeiten"
    assert payload["provider"] == "identity"
    assert payload["machine_translated"] is False
    assert payload["requires_human_review"] is False


def test_translation_rejects_invalid_language_code():
    headers = _auth_headers("translation-language@example.com")
    response = client.post(
        "/platform/translation/translate",
        headers=headers,
        json={
            "text": "Safety first",
            "source_language": "en",
            "target_language": "not a language",
            "criticality": "normal",
        },
    )
    assert response.status_code == 422


def test_translation_requires_configured_provider_for_cross_language(monkeypatch):
    monkeypatch.setenv("TRANSLATION_PROVIDER", "disabled")
    headers = _auth_headers("translation-disabled@example.com")
    response = client.post(
        "/platform/translation/translate",
        headers=headers,
        json={
            "text": "Safety first",
            "source_language": "en",
            "target_language": "de",
            "criticality": "normal",
        },
    )
    assert response.status_code == 503
    assert "deaktiviert" in response.json()["detail"]


def test_translation_language_list_is_safe_when_disabled(monkeypatch):
    monkeypatch.setenv("TRANSLATION_PROVIDER", "disabled")
    headers = _auth_headers("translation-list@example.com")
    response = client.get(
        "/platform/translation/languages",
        headers=headers,
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["provider"] == "disabled"
    assert payload["languages"] == []
    assert payload["accepts_bcp47"] is True
