import hashlib
import json
from datetime import datetime, timezone
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, HttpUrl
from sqlalchemy.orm import Session

from auth import get_current_user
from database import get_db
from industry_models import (
    IndustryActivityTemplate,
    IndustryArtifactTemplate,
    IndustryClassification,
    IndustryKnowledgeChange,
    TenantIndustryProfile,
)
from models import AuditLog, User
from permissions import require_permission

router = APIRouter()

DBSession = Annotated[Session, Depends(get_db)]
CurrentUser = Annotated[User, Depends(get_current_user)]

SUPPORTED_ARTIFACT_TYPES = {
    "activity_description",
    "process_description",
    "risk_assessment",
    "operating_instruction",
    "training",
    "presentation",
    "checklist",
    "audit_question_set",
}

SCHEME_METADATA: tuple[dict[str, str], ...] = (
    {
        "scheme": "WZ2025",
        "version": "2025",
        "jurisdiction": "DE",
        "authority": "Statistisches Bundesamt",
        "source_url": "https://www.destatis.de/DE/Methoden/Klassifikationen/Gueter-Wirtschaftsklassifikationen/klassifikation-wz-2025.html",
        "purpose": "Primäre deutsche Branchenklassifikation; parallel zur Übergangsphase WZ 2008 berücksichtigen.",
    },
    {
        "scheme": "NACE2.1",
        "version": "2.1",
        "jurisdiction": "EU",
        "authority": "Eurostat / Europäische Kommission",
        "source_url": "https://ec.europa.eu/eurostat/web/nace/",
        "purpose": "Europäische Referenzklassifikation für Wirtschaftstätigkeiten ab 2025.",
    },
    {
        "scheme": "ISIC5",
        "version": "Rev.5",
        "jurisdiction": "GLOBAL",
        "authority": "United Nations Statistics Division",
        "source_url": "https://unstats.un.org/unsd/classifications/Econ/isic",
        "purpose": "Globale Referenzklassifikation zur späteren internationalen Zuordnung.",
    },
)


class ClassificationNode(BaseModel):
    scheme: str = Field(min_length=2, max_length=40)
    version: str = Field(min_length=1, max_length=40)
    code: str = Field(min_length=1, max_length=40)
    title: str = Field(min_length=2, max_length=500)
    parent_code: str | None = Field(default=None, max_length=40)
    level: str = Field(min_length=2, max_length=40)
    jurisdiction: str = Field(min_length=2, max_length=80)
    source_url: HttpUrl
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    is_active: bool = True


class ClassificationBulkUpsert(BaseModel):
    nodes: list[ClassificationNode] = Field(min_length=1, max_length=2000)


class TenantIndustryProfileCreate(BaseModel):
    scheme: str = Field(min_length=2, max_length=40)
    code: str = Field(min_length=1, max_length=40)
    is_primary: bool = False


class ActivityTemplateUpsert(BaseModel):
    scheme: str = Field(min_length=2, max_length=40)
    industry_code: str = Field(min_length=1, max_length=40)
    template_key: str = Field(min_length=2, max_length=160)
    title: str = Field(min_length=2, max_length=500)
    activity_description: str = Field(min_length=10)
    process_description: str | None = None
    process_steps: list[dict[str, object]] = Field(default_factory=list)
    equipment: list[str] = Field(default_factory=list)
    substances: list[str] = Field(default_factory=list)
    worker_groups: list[str] = Field(default_factory=list)
    hazard_factors: list[dict[str, object]] = Field(default_factory=list)
    controls: list[dict[str, object]] = Field(default_factory=list)
    training_topics: list[str] = Field(default_factory=list)
    operating_instruction_topics: list[str] = Field(default_factory=list)
    source_refs: list[dict[str, object]] = Field(default_factory=list)
    jurisdiction: str = Field(default="DE", min_length=2, max_length=80)
    valid_from: datetime | None = None
    valid_to: datetime | None = None


class ArtifactTemplateUpsert(BaseModel):
    artifact_type: str = Field(min_length=2, max_length=80)
    title: str = Field(min_length=2, max_length=500)
    content: dict[str, object] = Field(default_factory=dict)
    source_refs: list[dict[str, object]] = Field(default_factory=list)


class ReviewRequest(BaseModel):
    review_status: Literal["reviewed", "approved", "rejected", "needs_revision"] = "reviewed"
    impact: dict[str, object] = Field(default_factory=dict)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _canonical_json(payload: object) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _hash_payload(payload: object) -> str:
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _serialize_classification(item: IndustryClassification) -> dict[str, object]:
    return {
        "id": item.id,
        "scheme": item.scheme,
        "version": item.version,
        "code": item.code,
        "title": item.title,
        "parent_code": item.parent_code,
        "level": item.level,
        "jurisdiction": item.jurisdiction,
        "source_url": item.source_url,
        "source_hash": item.source_hash,
        "valid_from": item.valid_from,
        "valid_to": item.valid_to,
        "is_active": item.is_active,
        "review_status": item.review_status,
        "updated_at": item.updated_at,
    }


def _template_payload(data: ActivityTemplateUpsert) -> dict[str, object]:
    return {
        "scheme": data.scheme.strip().upper(),
        "industry_code": data.industry_code.strip(),
        "template_key": data.template_key.strip().lower(),
        "title": data.title.strip(),
        "activity_description": data.activity_description.strip(),
        "process_description": data.process_description.strip() if data.process_description else None,
        "process_steps": data.process_steps,
        "equipment": data.equipment,
        "substances": data.substances,
        "worker_groups": data.worker_groups,
        "hazard_factors": data.hazard_factors,
        "controls": data.controls,
        "training_topics": data.training_topics,
        "operating_instruction_topics": data.operating_instruction_topics,
        "source_refs": data.source_refs,
        "jurisdiction": data.jurisdiction.strip().upper(),
        "valid_from": data.valid_from,
        "valid_to": data.valid_to,
    }


def _serialize_activity(item: IndustryActivityTemplate) -> dict[str, object]:
    return {
        "id": item.id,
        "scheme": item.scheme,
        "industry_code": item.industry_code,
        "template_key": item.template_key,
        "version": item.version,
        "title": item.title,
        "activity_description": item.activity_description,
        "process_description": item.process_description,
        "process_steps": json.loads(item.process_steps_json or "[]"),
        "equipment": json.loads(item.equipment_json or "[]"),
        "substances": json.loads(item.substances_json or "[]"),
        "worker_groups": json.loads(item.worker_groups_json or "[]"),
        "hazard_factors": json.loads(item.hazard_factors_json or "[]"),
        "controls": json.loads(item.controls_json or "[]"),
        "training_topics": json.loads(item.training_topics_json or "[]"),
        "operating_instruction_topics": json.loads(item.operating_instruction_topics_json or "[]"),
        "source_refs": json.loads(item.source_refs_json or "[]"),
        "jurisdiction": item.jurisdiction,
        "review_status": item.review_status,
        "human_review_required": item.human_review_required,
        "content_hash": item.content_hash,
        "valid_from": item.valid_from,
        "valid_to": item.valid_to,
        "updated_at": item.updated_at,
    }


@router.get("/schemes")
def list_schemes(current_user: CurrentUser):
    require_permission(current_user, "industry.read")
    return {"schemes": list(SCHEME_METADATA)}


@router.put("/classifications/bulk-upsert")
def bulk_upsert_classifications(data: ClassificationBulkUpsert, current_user: CurrentUser, db: DBSession):
    require_permission(current_user, "industry.manage")
    created = 0
    updated = 0
    unchanged = 0

    for node in data.nodes:
        normalized = {
            "scheme": node.scheme.strip().upper(),
            "version": node.version.strip(),
            "code": node.code.strip(),
            "title": node.title.strip(),
            "parent_code": node.parent_code.strip() if node.parent_code else None,
            "level": node.level.strip().lower(),
            "jurisdiction": node.jurisdiction.strip().upper(),
            "source_url": str(node.source_url),
            "valid_from": node.valid_from,
            "valid_to": node.valid_to,
            "is_active": node.is_active,
        }
        new_hash = _hash_payload(normalized)
        item = db.query(IndustryClassification).filter(
            IndustryClassification.scheme == normalized["scheme"],
            IndustryClassification.code == normalized["code"],
            IndustryClassification.version == normalized["version"],
        ).first()

        if item is None:
            item = IndustryClassification(**normalized, source_hash=new_hash, review_status="verified_source")
            db.add(item)
            db.flush()
            db.add(
                IndustryKnowledgeChange(
                    object_type="classification",
                    object_key=f"{item.scheme}:{item.version}:{item.code}",
                    scheme=item.scheme,
                    industry_code=item.code,
                    change_type="created",
                    previous_hash=None,
                    new_hash=new_hash,
                    source_refs_json=_canonical_json([{"url": item.source_url}]),
                    impact_json="{}",
                    review_status="reviewed",
                    human_review_required=False,
                )
            )
            created += 1
            continue

        if item.source_hash == new_hash:
            unchanged += 1
            continue

        previous_hash = item.source_hash
        for key, value in normalized.items():
            setattr(item, key, value)
        item.source_hash = new_hash
        item.review_status = "review_required"
        db.add(
            IndustryKnowledgeChange(
                object_type="classification",
                object_key=f"{item.scheme}:{item.version}:{item.code}",
                scheme=item.scheme,
                industry_code=item.code,
                change_type="updated",
                previous_hash=previous_hash,
                new_hash=new_hash,
                source_refs_json=_canonical_json([{"url": item.source_url}]),
                impact_json="{}",
                review_status="pending",
                human_review_required=True,
            )
        )
        updated += 1

    db.add(AuditLog(event=f"industry_classifications_bulk_upsert:{created}:{updated}:{unchanged}", user_id=current_user.id, tenant_id=current_user.tenant_id))
    db.commit()
    return {"created": created, "updated": updated, "unchanged": unchanged}


@router.get("/classifications")
def list_classifications(
    current_user: CurrentUser,
    db: DBSession,
    scheme: str = "WZ2025",
    parent_code: str | None = None,
    level: str | None = None,
    query_text: str | None = Query(default=None, min_length=2, max_length=120),
    limit: int = Query(default=250, ge=1, le=1000),
):
    require_permission(current_user, "industry.read")
    query = db.query(IndustryClassification).filter(IndustryClassification.scheme == scheme.strip().upper())
    if parent_code is not None:
        query = query.filter(IndustryClassification.parent_code == parent_code.strip())
    if level:
        query = query.filter(IndustryClassification.level == level.strip().lower())
    if query_text:
        search = f"%{query_text.strip()}%"
        query = query.filter(IndustryClassification.title.ilike(search))
    items = query.order_by(IndustryClassification.code.asc()).limit(limit).all()
    return {"classifications": [_serialize_classification(item) for item in items]}


@router.post("/tenant-profile", status_code=status.HTTP_201_CREATED)
def assign_tenant_industry(data: TenantIndustryProfileCreate, current_user: CurrentUser, db: DBSession):
    require_permission(current_user, "industry.profile.manage")
    if current_user.tenant_id is None:
        raise HTTPException(status_code=409, detail="Der Benutzer gehört keinem Mandanten an.")

    scheme = data.scheme.strip().upper()
    code = data.code.strip()
    classification = db.query(IndustryClassification).filter(
        IndustryClassification.scheme == scheme,
        IndustryClassification.code == code,
        IndustryClassification.is_active.is_(True),
    ).order_by(IndustryClassification.valid_from.desc()).first()
    if classification is None:
        raise HTTPException(status_code=404, detail="Branchenklassifikation wurde nicht gefunden.")

    existing = db.query(TenantIndustryProfile).filter(
        TenantIndustryProfile.tenant_id == current_user.tenant_id,
        TenantIndustryProfile.scheme == scheme,
        TenantIndustryProfile.code == code,
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail="Branche ist dem Mandanten bereits zugeordnet.")

    if data.is_primary:
        db.query(TenantIndustryProfile).filter(
            TenantIndustryProfile.tenant_id == current_user.tenant_id,
            TenantIndustryProfile.scheme == scheme,
        ).update({TenantIndustryProfile.is_primary: False}, synchronize_session=False)

    profile = TenantIndustryProfile(
        tenant_id=current_user.tenant_id,
        scheme=scheme,
        code=code,
        is_primary=data.is_primary,
        verification_status="verified_against_catalog",
        verified_by_id=current_user.id,
        verified_at=_utc_now(),
    )
    db.add(profile)
    db.flush()
    db.add(AuditLog(event=f"tenant_industry_profile_created:{profile.id}", user_id=current_user.id, tenant_id=current_user.tenant_id))
    db.commit()
    db.refresh(profile)
    return {
        "id": profile.id,
        "tenant_id": profile.tenant_id,
        "scheme": profile.scheme,
        "code": profile.code,
        "is_primary": profile.is_primary,
        "verification_status": profile.verification_status,
    }


@router.put("/activities/upsert")
def upsert_activity_template(data: ActivityTemplateUpsert, current_user: CurrentUser, db: DBSession):
    require_permission(current_user, "industry.manage")
    payload = _template_payload(data)
    new_hash = _hash_payload(payload)
    scheme = payload["scheme"]
    code = payload["industry_code"]
    template_key = payload["template_key"]

    latest = db.query(IndustryActivityTemplate).filter(
        IndustryActivityTemplate.scheme == scheme,
        IndustryActivityTemplate.industry_code == code,
        IndustryActivityTemplate.template_key == template_key,
    ).order_by(IndustryActivityTemplate.version.desc()).first()

    if latest and latest.content_hash == new_hash:
        return {"change": "unchanged", "activity": _serialize_activity(latest)}

    version = 1 if latest is None else latest.version + 1
    item = IndustryActivityTemplate(
        scheme=scheme,
        industry_code=code,
        template_key=template_key,
        version=version,
        title=payload["title"],
        activity_description=payload["activity_description"],
        process_description=payload["process_description"],
        process_steps_json=_canonical_json(payload["process_steps"]),
        equipment_json=_canonical_json(payload["equipment"]),
        substances_json=_canonical_json(payload["substances"]),
        worker_groups_json=_canonical_json(payload["worker_groups"]),
        hazard_factors_json=_canonical_json(payload["hazard_factors"]),
        controls_json=_canonical_json(payload["controls"]),
        training_topics_json=_canonical_json(payload["training_topics"]),
        operating_instruction_topics_json=_canonical_json(payload["operating_instruction_topics"]),
        source_refs_json=_canonical_json(payload["source_refs"]),
        jurisdiction=payload["jurisdiction"],
        review_status="draft",
        human_review_required=True,
        content_hash=new_hash,
        valid_from=payload["valid_from"],
        valid_to=payload["valid_to"],
    )
    db.add(item)
    db.flush()
    db.add(
        IndustryKnowledgeChange(
            object_type="activity_template",
            object_key=f"{scheme}:{code}:{template_key}",
            scheme=scheme,
            industry_code=code,
            change_type="created" if latest is None else "updated",
            previous_hash=latest.content_hash if latest else None,
            new_hash=new_hash,
            source_refs_json=item.source_refs_json,
            impact_json=_canonical_json({"requires_tenant_relevance_check": True}),
            review_status="pending",
            human_review_required=True,
        )
    )
    db.add(AuditLog(event=f"industry_activity_template_created:{item.id}:v{item.version}", user_id=current_user.id, tenant_id=current_user.tenant_id))
    db.commit()
    db.refresh(item)
    return {"change": "created" if latest is None else "versioned", "activity": _serialize_activity(item)}


@router.get("/activities")
def list_activity_templates(
    current_user: CurrentUser,
    db: DBSession,
    scheme: str = "WZ2025",
    industry_code: str | None = None,
    review_status: str | None = None,
    limit: int = Query(default=250, ge=1, le=1000),
):
    require_permission(current_user, "industry.read")
    query = db.query(IndustryActivityTemplate).filter(IndustryActivityTemplate.scheme == scheme.strip().upper())
    if industry_code:
        query = query.filter(IndustryActivityTemplate.industry_code == industry_code.strip())
    if review_status:
        query = query.filter(IndustryActivityTemplate.review_status == review_status.strip().lower())
    items = query.order_by(IndustryActivityTemplate.industry_code.asc(), IndustryActivityTemplate.template_key.asc(), IndustryActivityTemplate.version.desc()).limit(limit).all()
    return {"activities": [_serialize_activity(item) for item in items]}


@router.put("/activities/{activity_id}/artifacts/upsert")
def upsert_artifact_template(activity_id: int, data: ArtifactTemplateUpsert, current_user: CurrentUser, db: DBSession):
    require_permission(current_user, "industry.manage")
    activity = db.query(IndustryActivityTemplate).filter(IndustryActivityTemplate.id == activity_id).first()
    if activity is None:
        raise HTTPException(status_code=404, detail="Tätigkeitsvorlage wurde nicht gefunden.")

    artifact_type = data.artifact_type.strip().lower()
    if artifact_type not in SUPPORTED_ARTIFACT_TYPES:
        raise HTTPException(status_code=422, detail="Dieser Artefakttyp ist nicht freigegeben.")

    payload = {
        "artifact_type": artifact_type,
        "title": data.title.strip(),
        "content": data.content,
        "source_refs": data.source_refs,
    }
    new_hash = _hash_payload(payload)
    latest = db.query(IndustryArtifactTemplate).filter(
        IndustryArtifactTemplate.activity_template_id == activity_id,
        IndustryArtifactTemplate.artifact_type == artifact_type,
    ).order_by(IndustryArtifactTemplate.version.desc()).first()
    if latest and latest.content_hash == new_hash:
        return {"change": "unchanged", "id": latest.id, "version": latest.version}

    version = 1 if latest is None else latest.version + 1
    item = IndustryArtifactTemplate(
        activity_template_id=activity_id,
        artifact_type=artifact_type,
        version=version,
        title=data.title.strip(),
        content_json=_canonical_json(data.content),
        source_refs_json=_canonical_json(data.source_refs),
        review_status="draft",
        human_review_required=True,
        content_hash=new_hash,
    )
    db.add(item)
    db.flush()
    db.add(
        IndustryKnowledgeChange(
            object_type="artifact_template",
            object_key=f"{activity.scheme}:{activity.industry_code}:{activity.template_key}:{artifact_type}",
            scheme=activity.scheme,
            industry_code=activity.industry_code,
            change_type="created" if latest is None else "updated",
            previous_hash=latest.content_hash if latest else None,
            new_hash=new_hash,
            source_refs_json=item.source_refs_json,
            impact_json=_canonical_json({"requires_controlled_document_revision_check": True}),
            review_status="pending",
            human_review_required=True,
        )
    )
    db.add(AuditLog(event=f"industry_artifact_template_created:{item.id}:v{version}", user_id=current_user.id, tenant_id=current_user.tenant_id))
    db.commit()
    return {"change": "created" if latest is None else "versioned", "id": item.id, "version": version}


@router.get("/activities/{activity_id}/generation-plan")
def generation_plan(activity_id: int, current_user: CurrentUser, db: DBSession):
    require_permission(current_user, "industry.read")
    activity = db.query(IndustryActivityTemplate).filter(IndustryActivityTemplate.id == activity_id).first()
    if activity is None:
        raise HTTPException(status_code=404, detail="Tätigkeitsvorlage wurde nicht gefunden.")

    artifacts = db.query(IndustryArtifactTemplate).filter(
        IndustryArtifactTemplate.activity_template_id == activity_id,
    ).order_by(IndustryArtifactTemplate.artifact_type.asc(), IndustryArtifactTemplate.version.desc()).all()
    latest_by_type: dict[str, IndustryArtifactTemplate] = {}
    for artifact in artifacts:
        latest_by_type.setdefault(artifact.artifact_type, artifact)

    sequence = [
        "activity_description",
        "process_description",
        "risk_assessment",
        "operating_instruction",
        "training",
        "presentation",
        "checklist",
        "audit_question_set",
    ]
    return {
        "activity": _serialize_activity(activity),
        "sequence": [
            {
                "artifact_type": artifact_type,
                "template_available": artifact_type in latest_by_type,
                "template_version": latest_by_type[artifact_type].version if artifact_type in latest_by_type else None,
                "review_status": latest_by_type[artifact_type].review_status if artifact_type in latest_by_type else "missing",
            }
            for artifact_type in sequence
        ],
        "required_customer_context": [
            "Standort und Arbeitsbereich",
            "konkrete Tätigkeit und Ablaufvarianten",
            "Arbeitsmittel/Maschinen",
            "Gefahrstoffe/Biostoffe",
            "betroffene Personengruppen",
            "Arbeitsumgebung und Arbeitszeit",
            "bestehende Schutzmaßnahmen",
            "Unfälle/Near Miss/Erfahrungswerte",
            "zuständiger Unfallversicherungsträger",
            "geltende Rechts- und Regelwerksquellen",
        ],
        "safety_gate": {
            "draft_only_until_review": True,
            "reason": "Branchentemplates sind eine Ausgangsbasis; betriebs- und situationsspezifische Gefährdungen müssen vor Freigabe fachlich geprüft werden.",
        },
    }


@router.post("/changes/{change_id}/review")
def review_change(change_id: int, data: ReviewRequest, current_user: CurrentUser, db: DBSession):
    require_permission(current_user, "industry.manage")
    change = db.query(IndustryKnowledgeChange).filter(IndustryKnowledgeChange.id == change_id).first()
    if change is None:
        raise HTTPException(status_code=404, detail="Branchenänderung wurde nicht gefunden.")
    change.review_status = data.review_status
    change.impact_json = _canonical_json(data.impact)
    change.reviewed_by_id = current_user.id
    change.reviewed_at = _utc_now()
    db.add(AuditLog(event=f"industry_change_reviewed:{change.id}:{data.review_status}", user_id=current_user.id, tenant_id=current_user.tenant_id))
    db.commit()
    return {"id": change.id, "review_status": change.review_status, "impact": data.impact}


@router.get("/changes")
def list_changes(current_user: CurrentUser, db: DBSession, review_status: str | None = None, limit: int = Query(default=250, ge=1, le=1000)):
    require_permission(current_user, "industry.read")
    query = db.query(IndustryKnowledgeChange)
    if review_status:
        query = query.filter(IndustryKnowledgeChange.review_status == review_status.strip().lower())
    items = query.order_by(IndustryKnowledgeChange.detected_at.desc()).limit(limit).all()
    return {
        "changes": [
            {
                "id": item.id,
                "object_type": item.object_type,
                "object_key": item.object_key,
                "scheme": item.scheme,
                "industry_code": item.industry_code,
                "change_type": item.change_type,
                "previous_hash": item.previous_hash,
                "new_hash": item.new_hash,
                "source_refs": json.loads(item.source_refs_json or "[]"),
                "impact": json.loads(item.impact_json or "{}"),
                "review_status": item.review_status,
                "human_review_required": item.human_review_required,
                "detected_at": item.detected_at,
            }
            for item in items
        ]
    }
