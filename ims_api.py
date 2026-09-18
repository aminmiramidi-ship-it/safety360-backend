import json
from datetime import datetime, timezone
from typing import Annotated
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from auth import get_current_user
from database import get_db
from models import AuditLog, IMSActivity, IMSArtifact, User
from permissions import require_permission
from schemas import (
    IMSActivityCreate,
    IMSActivityListResponse,
    IMSActivityResponse,
    IMSArtifactListResponse,
    IMSArtifactResponse,
    IMSGenerationRequest,
    IMSGenerationResponse,
    StandardRegistryItem,
    StandardRegistryResponse,
)

router = APIRouter()

DBSession = Annotated[Session, Depends(get_db)]
CurrentUser = Annotated[User, Depends(get_current_user)]

APPROVER_ROLES = {"tenant_admin", "hse_manager", "document_controller", "admin"}
SUPPORTED_ARTIFACT_TYPES = {
    "risk_assessment",
    "operating_instruction",
    "training_plan",
    "ims_requirements_map",
}

STANDARD_REGISTRY = [
    StandardRegistryItem(
        identifier="ISO 45001",
        domain="occupational_health_safety",
        purpose="Managementsystem für Sicherheit und Gesundheit bei der Arbeit.",
        implementation_note="Safety360 verknüpft Tätigkeiten, Gefährdungen, Maßnahmen, Verantwortungen, Schulungen und Wirksamkeitsprüfung.",
    ),
    StandardRegistryItem(
        identifier="ISO 14001",
        domain="environment",
        purpose="Umweltmanagementsystem.",
        implementation_note="Umweltaspekte, Auswirkungen, bindende Verpflichtungen, Ziele und operative Steuerung werden als verknüpfte Objekte geführt.",
    ),
    StandardRegistryItem(
        identifier="ISO 50001",
        domain="energy",
        purpose="Energiemanagementsystem.",
        implementation_note="Energieeinsatz, wesentliche Energieverbräuche, Leistungskennzahlen, Ziele und Maßnahmen werden strukturiert angebunden.",
    ),
    StandardRegistryItem(
        identifier="ISO 9001",
        domain="quality",
        purpose="Qualitätsmanagementsystem.",
        implementation_note="Prozesse, Risiken, Anforderungen, Nachweise, Abweichungen, Korrekturmaßnahmen und Verbesserungen werden verknüpft.",
    ),
    StandardRegistryItem(
        identifier="ISO/IEC 27001",
        domain="information_security",
        purpose="Informationssicherheitsmanagementsystem.",
        implementation_note="Informationswerte, Risiken, Verantwortungen, Maßnahmen, Nachweise und Freigaben werden mandantenbezogen abgebildet.",
    ),
    StandardRegistryItem(
        identifier="EN 50600",
        domain="data_center",
        purpose="Rechenzentrumsinfrastruktur und Verfügbarkeit.",
        implementation_note="Standort-, Infrastruktur-, Betriebs-, Verfügbarkeits- und Sicherheitskontext kann Tätigkeiten und Nachweisen zugeordnet werden.",
    ),
]


def _require_tenant(current_user: User) -> int:
    if current_user.tenant_id is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Für IMS-Funktionen muss ein Mandant zugeordnet sein.",
        )
    return current_user.tenant_id


def _tenant_activity(db: Session, activity_id: int, tenant_id: int) -> IMSActivity:
    activity = (
        db.query(IMSActivity)
        .filter(IMSActivity.id == activity_id, IMSActivity.tenant_id == tenant_id)
        .first()
    )
    if activity is None:
        raise HTTPException(status_code=404, detail="Tätigkeit wurde nicht gefunden.")
    return activity


def _artifact_response(artifact: IMSArtifact) -> IMSArtifactResponse:
    try:
        content = json.loads(artifact.content_json)
        standards = json.loads(artifact.standards_json)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="IMS-Artefaktdaten sind beschädigt.",
        ) from exc

    return IMSArtifactResponse(
        id=artifact.id,
        tenant_id=artifact.tenant_id,
        activity_id=artifact.activity_id,
        logical_id=artifact.logical_id,
        artifact_type=artifact.artifact_type,
        title=artifact.title,
        version=artifact.version,
        status=artifact.status,
        content=content,
        standards=standards,
        generation_mode=artifact.generation_mode,
        created_by_id=artifact.created_by_id,
        approved_by_id=artifact.approved_by_id,
        approved_at=artifact.approved_at,
        created_at=artifact.created_at,
        updated_at=artifact.updated_at,
    )


def _risk_assessment(activity: IMSActivity) -> dict:
    hazard_prompts = [
        "Mechanische, elektrische, thermische und physikalische Gefährdungen prüfen.",
        "Arbeitsumgebung, Verkehrswege, Ergonomie und organisatorische Faktoren prüfen.",
        "Arbeitsmittel, Energiequellen, Gefahrstoffe und Wechselwirkungen prüfen.",
        "Personengruppen, Fremdfirmen, Alleinarbeit und Notfallsituationen berücksichtigen.",
    ]
    if activity.substances:
        hazard_prompts.append("Gefahrstoffexposition, Lagerung, Freisetzung und Entsorgung bewerten.")
    if activity.equipment:
        hazard_prompts.append("Arbeitsmittelbezogene Gefährdungen, Prüfstatus und sichere Verwendung bewerten.")
    if activity.information_security_context:
        hazard_prompts.append("Informationssicherheits- und Zugriffsrisiken der Tätigkeit berücksichtigen.")

    return {
        "activity": activity.title,
        "activity_description": activity.description,
        "hazard_assessment_prompts": hazard_prompts,
        "assessment_method": {
            "steps": [
                "Gefährdungen ermitteln",
                "bestehende Maßnahmen erfassen",
                "Risiko vor und nach Maßnahmen bewerten",
                "zusätzliche Maßnahmen nach STOP-Prinzip definieren",
                "Verantwortliche und Fristen festlegen",
                "Wirksamkeit prüfen und dokumentieren",
            ],
            "human_review_required": True,
        },
        "contexts": {
            "industry": activity.industry,
            "location": activity.location,
            "equipment": activity.equipment,
            "substances": activity.substances,
            "environment": activity.environmental_context,
            "energy": activity.energy_context,
            "quality": activity.quality_context,
            "information_security": activity.information_security_context,
        },
    }


def _operating_instruction(activity: IMSActivity) -> dict:
    return {
        "activity": activity.title,
        "purpose": "Sichere, umweltgerechte, qualitätsgerechte und kontrollierte Durchführung der Tätigkeit.",
        "sections": [
            "Anwendungsbereich und Tätigkeit",
            "Gefahren und relevante Auswirkungen",
            "Schutzmaßnahmen und Verhaltensregeln",
            "Persönliche Schutzausrüstung, soweit erforderlich",
            "Verhalten bei Störungen und Notfällen",
            "Erste Hilfe und Meldewege",
            "Instandhaltung, Prüfung, Freigabe und Dokumentation",
            "Umwelt-, Energie-, Qualitäts- und Informationssicherheitsanforderungen",
        ],
        "source_context": {
            "description": activity.description,
            "equipment": activity.equipment,
            "substances": activity.substances,
        },
        "human_review_required": True,
    }


def _training_plan(activity: IMSActivity) -> dict:
    topics = [
        f"Sichere Durchführung: {activity.title}",
        "Gefährdungen, Schutzmaßnahmen und STOP-Prinzip",
        "Notfall-, Melde- und Eskalationswege",
        "Verantwortungen, Freigaben und Dokumentationspflichten",
    ]
    if activity.environmental_context:
        topics.append("Umweltaspekte und operative Umweltkontrollen")
    if activity.energy_context:
        topics.append("Energierelevante Betriebsweise und Vermeidung unnötiger Verbräuche")
    if activity.quality_context:
        topics.append("Qualitätsanforderungen, Abweichungen und Nachweise")
    if activity.information_security_context:
        topics.append("Informationssicherheit, Zutritt/Zugriff und sichere Datenverarbeitung")

    return {
        "activity": activity.title,
        "training_topics": topics,
        "delivery": {
            "methods": ["Präsenz", "E-Learning", "Toolbox Talk", "praktische Einweisung"],
            "competence_check_required": True,
            "attendance_evidence_required": True,
            "refresh_due_date_required": True,
        },
        "human_review_required": True,
    }


def _requirements_map(activity: IMSActivity, standards: list[str]) -> dict:
    return {
        "activity": activity.title,
        "selected_standards": standards,
        "mapping_status": "draft_for_verification",
        "implementation_dimensions": [
            "Kontext und Anwendungsbereich",
            "Führung, Rollen und Verantwortungen",
            "Risiken, Chancen und relevante Aspekte",
            "Kompetenz, Bewusstsein und Kommunikation",
            "Dokumentierte Information und Nachweise",
            "Operative Planung und Steuerung",
            "Überwachung, Messung und Bewertung",
            "Abweichungen, Korrekturmaßnahmen und Verbesserung",
        ],
        "note": "Diese Struktur ist ein Managementsystem-Mapping und ersetzt keine lizenzierte Normausgabe oder fachliche Rechtsprüfung.",
        "human_review_required": True,
    }


def _build_content(artifact_type: str, activity: IMSActivity, standards: list[str]) -> dict:
    if artifact_type == "risk_assessment":
        return _risk_assessment(activity)
    if artifact_type == "operating_instruction":
        return _operating_instruction(activity)
    if artifact_type == "training_plan":
        return _training_plan(activity)
    if artifact_type == "ims_requirements_map":
        return _requirements_map(activity, standards)
    raise HTTPException(status_code=422, detail=f"Nicht unterstützter Artefakttyp: {artifact_type}")


@router.get("/standards", response_model=StandardRegistryResponse)
def list_standards(current_user: CurrentUser) -> StandardRegistryResponse:
    require_permission(current_user, "ims.read")
    return StandardRegistryResponse(standards=STANDARD_REGISTRY)


@router.post("/activities", response_model=IMSActivityResponse, status_code=status.HTTP_201_CREATED)
def create_activity(
    data: IMSActivityCreate,
    current_user: CurrentUser,
    db: DBSession,
) -> IMSActivity:
    require_permission(current_user, "ims.create")
    tenant_id = _require_tenant(current_user)
    activity = IMSActivity(
        tenant_id=tenant_id,
        title=data.title.strip(),
        description=data.description.strip(),
        industry=data.industry.strip() if data.industry else None,
        location=data.location.strip() if data.location else None,
        equipment=data.equipment.strip() if data.equipment else None,
        substances=data.substances.strip() if data.substances else None,
        environmental_context=data.environmental_context.strip() if data.environmental_context else None,
        energy_context=data.energy_context.strip() if data.energy_context else None,
        quality_context=data.quality_context.strip() if data.quality_context else None,
        information_security_context=(
            data.information_security_context.strip()
            if data.information_security_context
            else None
        ),
        status="draft",
        created_by_id=current_user.id,
    )
    db.add(activity)
    db.flush()
    db.add(
        AuditLog(
            event=f"ims_activity_created:{activity.id}",
            user_id=current_user.id,
            tenant_id=tenant_id,
        )
    )
    db.commit()
    db.refresh(activity)
    return activity


@router.get("/activities", response_model=IMSActivityListResponse)
def list_activities(current_user: CurrentUser, db: DBSession) -> IMSActivityListResponse:
    require_permission(current_user, "ims.read")
    tenant_id = _require_tenant(current_user)
    activities = (
        db.query(IMSActivity)
        .filter(IMSActivity.tenant_id == tenant_id)
        .order_by(IMSActivity.updated_at.desc())
        .all()
    )
    return IMSActivityListResponse(activities=activities)


@router.post("/activities/{activity_id}/generate", response_model=IMSGenerationResponse)
def generate_artifacts(
    activity_id: int,
    request: IMSGenerationRequest,
    current_user: CurrentUser,
    db: DBSession,
) -> IMSGenerationResponse:
    require_permission(current_user, "ims.generate")
    tenant_id = _require_tenant(current_user)
    activity = _tenant_activity(db, activity_id, tenant_id)

    requested_types = list(dict.fromkeys(item.strip().lower() for item in request.artifact_types))
    unsupported = sorted(set(requested_types) - SUPPORTED_ARTIFACT_TYPES)
    if unsupported:
        raise HTTPException(
            status_code=422,
            detail=f"Nicht unterstützte Artefakttypen: {', '.join(unsupported)}",
        )

    standards = list(dict.fromkeys(item.strip() for item in request.standards if item.strip()))
    artifacts: list[IMSArtifactResponse] = []
    for artifact_type in requested_types:
        artifact = IMSArtifact(
            tenant_id=tenant_id,
            activity_id=activity.id,
            logical_id=str(uuid4()),
            artifact_type=artifact_type,
            title=f"{activity.title} – {artifact_type.replace('_', ' ').title()}",
            version=1,
            status="draft",
            content_json=json.dumps(
                _build_content(artifact_type, activity, standards),
                ensure_ascii=False,
                separators=(",", ":"),
            ),
            standards_json=json.dumps(standards, ensure_ascii=False, separators=(",", ":")),
            generation_mode="rules",
            created_by_id=current_user.id,
        )
        db.add(artifact)
        db.flush()
        db.add(
            AuditLog(
                event=f"ims_artifact_generated:{artifact.id}:{artifact_type}",
                user_id=current_user.id,
                tenant_id=tenant_id,
            )
        )
        artifacts.append(_artifact_response(artifact))

    activity.status = "generated"
    db.commit()
    for item in artifacts:
        refreshed = db.query(IMSArtifact).filter(IMSArtifact.id == item.id).first()
        if refreshed is not None:
            item.updated_at = refreshed.updated_at

    warnings = [
        "Automatisch erzeugte Inhalte sind Entwürfe und müssen vor Freigabe fachlich geprüft werden.",
        "Normreferenzen sind Strukturhinweise; verbindliche Anforderungen sind anhand lizenzierter Normausgaben und aktueller Rechtsquellen zu verifizieren.",
    ]
    return IMSGenerationResponse(
        activity=IMSActivityResponse.model_validate(activity),
        artifacts=artifacts,
        warnings=warnings,
    )


@router.get("/activities/{activity_id}/artifacts", response_model=IMSArtifactListResponse)
def list_artifacts(
    activity_id: int,
    current_user: CurrentUser,
    db: DBSession,
) -> IMSArtifactListResponse:
    require_permission(current_user, "ims.read")
    tenant_id = _require_tenant(current_user)
    _tenant_activity(db, activity_id, tenant_id)
    artifacts = (
        db.query(IMSArtifact)
        .filter(
            IMSArtifact.tenant_id == tenant_id,
            IMSArtifact.activity_id == activity_id,
        )
        .order_by(IMSArtifact.created_at.desc())
        .all()
    )
    return IMSArtifactListResponse(artifacts=[_artifact_response(item) for item in artifacts])


@router.post("/artifacts/{artifact_id}/approve", response_model=IMSArtifactResponse)
def approve_artifact(
    artifact_id: int,
    current_user: CurrentUser,
    db: DBSession,
) -> IMSArtifactResponse:
    require_permission(current_user, "ims.approve")
    tenant_id = _require_tenant(current_user)
    if current_user.role not in APPROVER_ROLES:
        raise HTTPException(status_code=403, detail="Für die IMS-Freigabe fehlen die erforderlichen Rechte.")

    artifact = (
        db.query(IMSArtifact)
        .filter(IMSArtifact.id == artifact_id, IMSArtifact.tenant_id == tenant_id)
        .first()
    )
    if artifact is None:
        raise HTTPException(status_code=404, detail="IMS-Artefakt wurde nicht gefunden.")
    if artifact.status != "draft":
        raise HTTPException(status_code=409, detail="Nur IMS-Entwürfe können freigegeben werden.")

    artifact.status = "approved"
    artifact.approved_by_id = current_user.id
    artifact.approved_at = datetime.now(timezone.utc)
    db.add(
        AuditLog(
            event=f"ims_artifact_approved:{artifact.id}",
            user_id=current_user.id,
            tenant_id=tenant_id,
        )
    )
    db.commit()
    db.refresh(artifact)
    return _artifact_response(artifact)
