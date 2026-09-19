from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def _tenant_admin(email: str) -> dict[str, str]:
    register = client.post(
        "/auth/register",
        json={
            "email": email,
            "password": "Secret123!",
            "full_name": "Enterprise Admin",
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
        json={"name": f"Enterprise {email}"},
    )
    assert tenant.status_code == 201, tenant.text

    refreshed_login = client.post(
        "/auth/login",
        json={"email": email, "password": "Secret123!"},
    )
    assert refreshed_login.status_code == 200, refreshed_login.text
    return {"Authorization": f"Bearer {refreshed_login.json()['access_token']}"}


def test_secure_text_ingestion_processing_document_promotion_and_delete():
    headers = _tenant_admin("secure-ingestion@example.com")

    upload = client.post(
        "/files",
        headers=headers,
        data={"category": "existing-document", "folder": "/imports"},
        files={
            "file": (
                "existing-risk-assessment.txt",
                b"Existing risk assessment\nHazard: electrical energy\nMeasure: isolate before work.",
                "text/plain",
            )
        },
    )
    assert upload.status_code == 201, upload.text
    uploaded = upload.json()
    assert uploaded["sha256"]
    file_id = uploaded["id"]

    process = client.post(f"/files/{file_id}/process", headers=headers)
    assert process.status_code == 200, process.text
    processed = process.json()
    assert processed["detected_format"] == "text"
    assert processed["processing_status"] == "processed"
    assert processed["extracted_sha256"]
    assert "electrical energy" in processed["preview"]

    content = client.get(f"/files/{file_id}/content", headers=headers)
    assert content.status_code == 200, content.text
    assert "isolate before work" in content.json()["text"]

    promote = client.post(
        f"/files/{file_id}/to-document",
        headers=headers,
        json={
            "title": "Imported Electrical Risk Assessment",
            "document_type": "risk_assessment",
        },
    )
    assert promote.status_code == 201, promote.text
    promoted = promote.json()
    assert promoted["status"] == "draft"
    assert promoted["version"] == 1
    assert promoted["source_file_id"] == file_id
    assert promoted["source_sha256"] == uploaded["sha256"]

    archive = client.post(f"/files/{file_id}/archive", headers=headers)
    assert archive.status_code == 200, archive.text
    assert archive.json()["archived_at"] is not None

    delete = client.delete(f"/files/{file_id}", headers=headers)
    assert delete.status_code == 204, delete.text


def test_executable_upload_is_rejected_before_storage():
    headers = _tenant_admin("blocked-upload@example.com")

    upload = client.post(
        "/files",
        headers=headers,
        files={"file": ("malware.exe", b"MZnot-a-real-executable", "application/octet-stream")},
    )
    assert upload.status_code == 415, upload.text


def test_permanent_delete_requires_prior_archive():
    headers = _tenant_admin("delete-gate@example.com")

    upload = client.post(
        "/files",
        headers=headers,
        files={"file": ("note.txt", b"controlled content", "text/plain")},
    )
    assert upload.status_code == 201, upload.text
    file_id = upload.json()["id"]

    delete = client.delete(f"/files/{file_id}", headers=headers)
    assert delete.status_code == 409, delete.text


def test_tenant_admin_can_configure_oidc_without_storing_client_secret():
    headers = _tenant_admin("sso-config@example.com")

    invalid_secret_reference = client.put(
        "/auth/sso/config",
        headers=headers,
        json={
            "name": "Company SSO",
            "issuer_url": "https://login.example.com/tenant",
            "client_id": "safety360-client",
            "client_secret_env": "MY_RAW_SECRET_NAME",
            "allowed_domains": ["example.com"],
            "enabled": False,
        },
    )
    assert invalid_secret_reference.status_code == 422, invalid_secret_reference.text

    configured = client.put(
        "/auth/sso/config",
        headers=headers,
        json={
            "name": "Company SSO",
            "issuer_url": "https://login.example.com/tenant",
            "client_id": "safety360-public-client",
            "client_secret_env": None,
            "scopes": "openid profile email",
            "allowed_domains": ["example.com"],
            "enabled": True,
            "auto_provision": False,
            "auto_link_verified_email": False,
        },
    )
    assert configured.status_code == 200, configured.text
    payload = configured.json()
    assert payload["enabled"] is True
    assert payload["allowed_domains"] == ["example.com"]
    assert payload["client_secret_env"] is None
    assert payload["secret_configured"] is False

    tenant = client.get("/tenants/current", headers=headers)
    assert tenant.status_code == 200, tenant.text
    slug = tenant.json()["slug"]

    public_metadata = client.get(f"/auth/sso/tenant/{slug}")
    assert public_metadata.status_code == 200, public_metadata.text
    metadata = public_metadata.json()
    assert metadata["enabled"] is True
    assert metadata["provider_name"] == "Company SSO"
    assert metadata["login_url"].endswith(f"/tenant/{slug}/login")
