import json
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from auth import get_current_user
from database import get_db
from integration_models import TenantIntegration
from models import AuditLog, User
from permissions import require_permission

router = APIRouter()

DBSession = Annotated[Session, Depends(get_db)]
CurrentUser = Annotated[User, Depends(get_current_user)]

PROVIDER_CATALOG: dict[str, dict[str, object]] = {
    "microsoft-365": {
        "display_name": "Microsoft 365 / Microsoft Graph",
        "types": ["calendar", "email", "files", "directory", "collaboration"],
        "capabilities": ["calendar.read", "calendar.write", "mail.send", "files.read", "files.write", "directory.read", "webhooks"],
        "recommended_for": ["enterprise", "data_center", "bank", "authority"],
        "privacy_note": "Nur minimal notwendige Graph-Scopes; Mandantenfreigabe, Datenresidenz und Zweckbindung dokumentieren.",
    },
    "outlook-calendar": {
        "display_name": "Outlook Calendar",
        "types": ["calendar"],
        "capabilities": ["availability.read", "calendar.read", "calendar.write"],
        "recommended_for": ["scheduling", "occupational_health", "audits", "training"],
        "privacy_note": "Kalenderfreigaben auf Free/Busy und minimale Metadaten begrenzen, soweit ausreichend.",
    },
    "outlook-email": {
        "display_name": "Outlook Email",
        "types": ["email"],
        "capabilities": ["mail.read", "mail.send", "mail.draft"],
        "recommended_for": ["notifications", "approvals", "workflow"],
        "privacy_note": "Keine medizinischen Befunde oder unnötigen Gesundheitsdaten in E-Mail-Betreff/Body versenden.",
    },
    "teams": {
        "display_name": "Microsoft Teams",
        "types": ["messaging", "meeting", "collaboration"],
        "capabilities": ["message.send", "meeting.create", "meeting.join_link", "notifications"],
        "recommended_for": ["notifications", "approvals", "training", "remote_consultation"],
        "privacy_note": "Meeting-/Chat-Inhalte nur gemäß Mandantenrichtlinie speichern; klinische Inhalte getrennt halten.",
    },
    "sharepoint": {
        "display_name": "Microsoft SharePoint",
        "types": ["files", "document_management"],
        "capabilities": ["files.read", "files.write", "metadata.read", "metadata.write"],
        "recommended_for": ["document_ingestion", "controlled_documents", "evidence_import"],
        "privacy_note": "Importe durch Safety360-Quarantäne/Scan/Validierung führen; bestehende ACLs respektieren.",
    },
    "zoom": {
        "display_name": "Zoom",
        "types": ["meeting", "collaboration"],
        "capabilities": ["meeting.create", "meeting.join_link", "meeting.metadata", "meeting.insights"],
        "recommended_for": ["remote_consultation", "training", "audits", "interviews"],
        "privacy_note": "Aufzeichnungen/Transkripte standardmäßig deaktiviert bzw. nur mit klarer Rechtsgrundlage/Einwilligung und Retention nutzen.",
    },
    "google-calendar": {
        "display_name": "Google Calendar",
        "types": ["calendar"],
        "capabilities": ["availability.read", "calendar.read", "calendar.write"],
        "recommended_for": ["scheduling", "occupational_health", "audits", "training"],
        "privacy_note": "Minimale Kalenderberechtigungen und zweckgebundene Verarbeitung verwenden.",
    },
    "gmail": {
        "display_name": "Gmail",
        "types": ["email"],
        "capabilities": ["mail.read", "mail.send", "mail.draft"],
        "recommended_for": ["notifications", "approvals", "workflow"],
        "privacy_note": "Gesundheits-/klinische Informationen nicht unnötig per E-Mail übertragen.",
    },
    "google-drive": {
        "display_name": "Google Drive",
        "types": ["files", "document_management"],
        "capabilities": ["files.read", "files.write", "metadata.read"],
        "recommended_for": ["document_ingestion", "evidence_import"],
        "privacy_note": "Importierte Dateien immer durch sichere Ingestion-Pipeline führen.",
    },
    "box": {
        "display_name": "Box",
        "types": ["files", "document_management"],
        "capabilities": ["files.read", "metadata.read", "search"],
        "recommended_for": ["enterprise_documents", "evidence_import"],
        "privacy_note": "Box-Berechtigungen spiegeln; keine ACL-Ausweitung durch Safety360.",
    },
    "dropbox": {
        "display_name": "Dropbox",
        "types": ["files", "document_management"],
        "capabilities": ["files.read", "files.write", "sharing"],
        "recommended_for": ["document_ingestion", "small_business"],
        "privacy_note": "Mandanten- und Freigabegrenzen vor Synchronisation prüfen.",
    },
    "calendly": {
        "display_name": "Calendly",
        "types": ["scheduling"],
        "capabilities": ["availability.read", "booking.create", "booking.cancel"],
        "recommended_for": ["external_provider_scheduling", "occupational_health", "consulting"],
        "privacy_note": "Nur erforderliche Terminmetadaten übermitteln; Gesundheitsgründe nicht offenlegen.",
    },
    "slack": {
        "display_name": "Slack",
        "types": ["messaging", "collaboration"],
        "capabilities": ["message.send", "notifications", "workflow"],
        "recommended_for": ["notifications", "incident_workflow", "approvals"],
        "privacy_note": "Keine sensiblen Gesundheits-/Personaldaten in offene Channels senden.",
    },
    "fireflies": {
        "display_name": "Fireflies",
        "types": ["meeting_intelligence"],
        "capabilities": ["transcript.read", "summary.read", "action_items.read"],
        "recommended_for": ["meeting_follow_up", "audit_actions", "customer_interviews"],
        "privacy_note": "Nicht für klinische Gespräche ohne explizite Datenschutzfreigabe; Retention und Einwilligungen prüfen.",
    },
    "otter": {
        "display_name": "Otter.ai",
        "types": ["meeting_intelligence"],
        "capabilities": ["transcript.read", "summary.read", "action_items.read"],
        "recommended_for": ["meeting_follow_up", "training", "customer_interviews"],
        "privacy_note": "Keine Gesundheitsdaten/ärztlichen Gespräche standardmäßig transkribieren.",
    },
    "generic-oidc": {
        "display_name": "Generic OpenID Connect",
        "types": ["identity"],
        "capabilities": ["sso", "identity.login"],
        "recommended_for": ["enterprise_identity", "bank", "authority", "data_center"],
        "privacy_note": "Authorization Code + PKCE, State/Nonce, verifizierter Issuer/Audience/JWKS.",
    },
    "generic-scim": {
        "display_name": "SCIM 2.0",
        "types": ["identity", "provisioning"],
        "capabilities": ["user.provision", "user.deprovision", "group.sync"],
        "recommended_for": ["joiner_mover_leaver", "enterprise_identity"],
        "privacy_note": "Nur notwendige Identitätsattribute synchronisieren; Löschung/Sperrung revisionssicher verarbeiten.",
    },
    "generic-webhook": {
        "display_name": "Signed Webhook",
        "types": ["api", "eventing"],
        "capabilities": ["events.receive", "events.send"],
        "recommended_for": ["customer_systems", "workflow_automation"],
        "privacy_note": "HMAC/Signatur, Replay-Schutz, Idempotenz, Rate Limits und Payload-Minimierung verpflichtend.",
    },
    "generic-rest": {
        "display_name": "REST / OpenAPI",
        "types": ["api"],
        "capabilities": ["api.read", "api.write", "service_account"],
        "recommended_for": ["customer_systems", "hris", "erp", "cmms", "ehs"],
        "privacy_note": "OAuth2 Client Credentials oder rotierbare Secrets; minimale Scopes und vollständiger Audit-Trail.",
    },
    "sftp": {
        "display_name": "SFTP",
        "types": ["file_transfer"],
        "capabilities": ["files.import", "files.export"],
        "recommended_for": ["legacy_enterprise", "batch_import"],
        "privacy_note": "Host-Key-Pinning, getrennte Service-Accounts, verschlüsselte Übertragung und Quarantäne-Ingestion.",
    },
}


class IntegrationCreate(BaseModel):
    provider_key: str = Field(min_length=2, max_length=100)
    connection_key: str = Field(default="default", min_length=1, max_length=160)
    display_name: str | None = Field(default=None, max_length=240)
    integration_type: str = Field(min_length=2, max_length=80)
    base_url: str | None = Field(default=None, max_length=1000)
    auth_type: str = Field(default="oauth2", min_length=2, max_length=80)
    secret_ref: str | None = Field(default=None, max_length=240)
    scopes: list[str] = Field(default_factory=list)
    capabilities: list[str] = Field(default_factory=list)
    data_classes: list[str] = Field(default_factory=list)
    approved_purposes: list[str] = Field(default_factory=list)
    region: str | None = Field(default=None, max_length=80)
    external_processing_allowed: bool = False


def _require_tenant(user: User) -> int:
    if user.tenant_id is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Benutzer ist keinem Mandanten zugeordnet.")
    return int(user.tenant_id)


def _json_list(raw: str | None) -> list[object]:
    try:
        value = json.loads(raw or "[]")
        return value if isinstance(value, list) else []
    except (TypeError, ValueError):
        return []


def _serialize(item: TenantIntegration) -> dict[str, object]:
    return {
        "id": item.id,
        "provider_key": item.provider_key,
        "connection_key": item.connection_key,
        "display_name": item.display_name,
        "integration_type": item.integration_type,
        "base_url": item.base_url,
        "auth_type": item.auth_type,
        "secret_ref_configured": bool(item.secret_ref),
        "scopes": _json_list(item.scopes_json),
        "capabilities": _json_list(item.capabilities_json),
        "data_classes": _json_list(item.data_classes_json),
        "approved_purposes": _json_list(item.approved_purposes_json),
        "region": item.region,
        "enabled": item.enabled,
        "external_processing_allowed": item.external_processing_allowed,
        "minimum_disclosure": item.minimum_disclosure,
        "human_review_required": item.human_review_required,
    }


@router.get("/catalog")
def catalog(current_user: CurrentUser):
    require_permission(current_user, "integrations.read")
    return {
        "providers": [
            {"provider_key": key, **value}
            for key, value in sorted(PROVIDER_CATALOG.items())
        ],
        "principles": [
            "provider-neutral adapters",
            "least privilege",
            "tenant isolation",
            "secret references only",
            "purpose limitation",
            "minimum disclosure",
            "auditable events",
            "fail closed for sensitive data",
        ],
    }


@router.post("/connections", status_code=status.HTTP_201_CREATED)
def create_connection(data: IntegrationCreate, current_user: CurrentUser, db: DBSession):
    require_permission(current_user, "integrations.manage")
    tenant_id = _require_tenant(current_user)
    provider_key = data.provider_key.strip().lower()
    if provider_key not in PROVIDER_CATALOG:
        raise HTTPException(status_code=422, detail="Provider ist noch nicht im Safety360-Integrationskatalog freigegeben.")

    duplicate = db.query(TenantIntegration).filter(
        TenantIntegration.tenant_id == tenant_id,
        TenantIntegration.provider_key == provider_key,
        TenantIntegration.connection_key == data.connection_key.strip(),
    ).first()
    if duplicate:
        raise HTTPException(status_code=409, detail="Diese Integration ist bereits angelegt.")

    if data.secret_ref and not data.secret_ref.startswith(("env:", "vault:", "kms:", "secret:")):
        raise HTTPException(
            status_code=422,
            detail="Secrets dürfen nicht als Klartext gespeichert werden; nur Secret-Manager-/Environment-Referenzen sind zulässig.",
        )

    catalog_item = PROVIDER_CATALOG[provider_key]
    requested_capabilities = set(data.capabilities)
    supported = set(str(value) for value in catalog_item.get("capabilities", []))
    if requested_capabilities - supported:
        raise HTTPException(status_code=422, detail="Angeforderte Capability wird vom freigegebenen Providerprofil nicht unterstützt.")

    item = TenantIntegration(
        tenant_id=tenant_id,
        provider_key=provider_key,
        connection_key=data.connection_key.strip(),
        display_name=data.display_name.strip() if data.display_name else str(catalog_item["display_name"]),
        integration_type=data.integration_type.strip().lower(),
        base_url=data.base_url.strip() if data.base_url else None,
        auth_type=data.auth_type.strip().lower(),
        secret_ref=data.secret_ref.strip() if data.secret_ref else None,
        scopes_json=json.dumps(sorted(set(data.scopes)), ensure_ascii=False),
        capabilities_json=json.dumps(sorted(requested_capabilities), ensure_ascii=False),
        data_classes_json=json.dumps(sorted(set(data.data_classes)), ensure_ascii=False),
        approved_purposes_json=json.dumps(sorted(set(data.approved_purposes)), ensure_ascii=False),
        region=data.region.strip() if data.region else None,
        enabled=False,
        external_processing_allowed=data.external_processing_allowed,
        minimum_disclosure=True,
        human_review_required=True,
        created_by_id=current_user.id,
    )
    db.add(item)
    db.flush()
    db.add(AuditLog(event=f"integration_created:{item.id}:{provider_key}", user_id=current_user.id, tenant_id=tenant_id))
    db.commit()
    db.refresh(item)
    return _serialize(item)


@router.get("/connections")
def list_connections(current_user: CurrentUser, db: DBSession):
    require_permission(current_user, "integrations.read")
    tenant_id = _require_tenant(current_user)
    items = db.query(TenantIntegration).filter(TenantIntegration.tenant_id == tenant_id).order_by(TenantIntegration.provider_key).all()
    return {"connections": [_serialize(item) for item in items]}


@router.post("/connections/{integration_id}/enable")
def enable_connection(integration_id: int, current_user: CurrentUser, db: DBSession):
    require_permission(current_user, "integrations.manage")
    tenant_id = _require_tenant(current_user)
    item = db.query(TenantIntegration).filter(
        TenantIntegration.id == integration_id,
        TenantIntegration.tenant_id == tenant_id,
    ).first()
    if item is None:
        raise HTTPException(status_code=404, detail="Integration wurde nicht gefunden.")
    if item.auth_type not in {"none", "mtls"} and not item.secret_ref:
        raise HTTPException(status_code=409, detail="Integration kann ohne sichere Credential-Referenz nicht aktiviert werden.")
    if not _json_list(item.approved_purposes_json):
        raise HTTPException(status_code=409, detail="Vor Aktivierung muss mindestens ein zulässiger Verarbeitungszweck dokumentiert sein.")
    item.enabled = True
    item.human_review_required = False
    db.add(AuditLog(event=f"integration_enabled:{item.id}:{item.provider_key}", user_id=current_user.id, tenant_id=tenant_id))
    db.commit()
    db.refresh(item)
    return _serialize(item)
