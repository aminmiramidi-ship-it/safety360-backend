import hashlib
import json
from datetime import datetime, timezone
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, model_validator
from sqlalchemy.orm import Session

from auth import get_current_user
from content_impact_models import ContentDependency, ContentImpactAssessment
from database import get_db
from industry_models import IndustryActivityTemplate, IndustryClassification
from learning_content_models import LearningContentPack
from legal_graph_models import ComplianceSubject
from models import AuditLog, User
from permissions import require_permission
from regulatory_models import RegulatoryRequirement

router = APIRouter()

DBSession = Annotated[Session, Depends(get_db)]
CurrentUser = Annotated[User, Depends(get_current_user)]

DEPENDENCY_KINDS = {
    "regulatory_requirement",
    "industry_activity_template",
    "industry_classification",
    "compliance_subject",
    "manual_reference",
}


class DependencyCreate(BaseModel):
    content_pack_id: int
    dependency_kind: str = Field(min_length=2, max_length=80)
    reference_id: int | None = None
    reference_key: str | None = Field(default=None, max_length=320)
    source_ref: str | None = Field(default=None, max_length=1000)
    baseline_hash: str | None = Field(default=None, min_length=16, max_length=64)
    baseline_version: str | None = Field(default=None, max_length=160)

    @model_validator(mode="after")
    def validate_reference(self):
        kind = self.dependency_kind.strip().lower()
        if kind == "manual_reference":
            if not self.reference_key:
                raise ValueError("manual_reference requires reference_key")
        elif self.reference_id is None:
            raise ValueError(f"{kind} requires reference_id")
        return self


class DependencySignal(BaseModel):
    current_hash: str = Field(min_length=16, max_length=64)
    current_version: str | None = Field(default=None, max_length=160)
    rationale: str = Field(min_length=3, max_length=3000)
    source_ref: str | None = Field(default=None, max_length=1000)
    priority: Literal["low", "normal", "high", "critical"] = "normal"


class ImpactResolution(BaseModel):
    resolution: Literal["accepted_no_change", "dismissed"]
    note: str = Field(min_length=3, max_length=3000)


class RevisionCreate(BaseModel):
    change_reason: str = Field(min_length=3, max_length=500)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _tenant_id(user: User) -> int:
    if user.tenant_id is None:
        raise HTTPException(status_code=409, detail="Benutzer ist keinem Mandanten zugeordnet.")
    return int(user.tenant_id)


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _hash(value: object) -> str:
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def _require_pack(db: Session, tenant_id: int, pack_id: int) -> LearningContentPack:
    pack = db.query(LearningContentPack).filter(
        LearningContentPack.id == pack_id,
        LearningContentPack.tenant_id == tenant_id,
    ).first()
    if pack is None:
        raise HTTPException(status_code=404, detail="Content Pack wurde nicht gefunden.")
    return pack


def _require_dependency(db: Session, tenant_id: int, dependency_id: int) -> ContentDependency:
    item = db.query(ContentDependency).filter(
        ContentDependency.id == dependency_id,
        ContentDependency.tenant_id == tenant_id,
    ).first()
    if item is None:
        raise HTTPException(status_code=404, detail="Content-Abhängigkeit wurde nicht gefunden.")
    return item


def _require_impact(db: Session, tenant_id: int, impact_id: int) -> ContentImpactAssessment:
    item = db.query(ContentImpactAssessment).filter(
        ContentImpactAssessment.id == impact_id,
        ContentImpactAssessment.tenant_id == tenant_id,
    ).first()
    if item is None:
        raise HTTPException(status_code=404, detail="Content-Impact wurde nicht gefunden.")
    return item


def _serialize_dependency(item: ContentDependency) -> dict[str, object]:
    return {
        "id": item.id,
        "content_pack_id": item.content_pack_id,
        "dependency_kind": item.dependency_kind,
        "dependency_key": item.dependency_key,
        "reference_id": item.reference_id,
        "source_ref": item.source_ref,
        "baseline_hash": item.baseline_hash,
        "baseline_version": item.baseline_version,
        "last_seen_hash": item.last_seen_hash,
        "last_seen_version": item.last_seen_version,
        "last_checked_at": item.last_checked_at,
        "active": item.active,
    }


def _serialize_impact(item: ContentImpactAssessment) -> dict[str, object]:
    try:
        evidence = json.loads(item.evidence_json or "{}")
    except (TypeError, ValueError):
        evidence = {}
    return {
        "id": item.id,
        "content_pack_id": item.content_pack_id,
        "dependency_id": item.dependency_id,
        "trigger_type": item.trigger_type,
        "trigger_ref": item.trigger_ref,
        "previous_hash": item.previous_hash,
        "current_hash": item.current_hash,
        "previous_version": item.previous_version,
        "current_version": item.current_version,
        "status": item.status,
        "priority": item.priority,
        "rationale": item.rationale,
        "evidence": evidence,
        "detected_at": item.detected_at,
        "human_review_required": item.human_review_required,
        "resolved_at": item.resolved_at,
        "resolution_note": item.resolution_note,
    }


def _dependency_state(
    db: Session,
    tenant_id: int,
    kind: str,
    reference_id: int | None,
    reference_key: str | None,
) -> tuple[str, str | None, str, str | None]:
    if kind == "regulatory_requirement":
        item = db.query(RegulatoryRequirement).filter(RegulatoryRequirement.id == reference_id).first()
        if item is None:
            raise HTTPException(status_code=404, detail="Regulatorische Anforderung wurde nicht gefunden.")
        return item.content_hash, item.source_version, f"regulatory_requirement:{item.id}", item.citation

    if kind == "industry_activity_template":
        item = db.query(IndustryActivityTemplate).filter(IndustryActivityTemplate.id == reference_id).first()
        if item is None:
            raise HTTPException(status_code=404, detail="Tätigkeitstemplate wurde nicht gefunden.")
        return item.content_hash, str(item.version), f"industry_activity_template:{item.id}", None

    if kind == "industry_classification":
        item = db.query(IndustryClassification).filter(IndustryClassification.id == reference_id).first()
        if item is None:
            raise HTTPException(status_code=404, detail="Branchenklassifikation wurde nicht gefunden.")
        fingerprint = item.source_hash or _hash(
            {
                "scheme": item.scheme,
                "version": item.version,
                "code": item.code,
                "title": item.title,
                "parent_code": item.parent_code,
                "active": item.is_active,
            }
        )
        return fingerprint, item.version, f"industry_classification:{item.id}", item.source_url

    if kind == "compliance_subject":
        item = db.query(ComplianceSubject).filter(
            ComplianceSubject.id == reference_id,
            ComplianceSubject.tenant_id == tenant_id,
        ).first()
        if item is None:
            raise HTTPException(status_code=404, detail="Compliance-Objekt wurde nicht gefunden.")
        fingerprint = _hash(
            {
                "subject_type": item.subject_type,
                "subject_key": item.subject_key,
                "title": item.title,
                "jurisdiction": item.jurisdiction,
                "parent_ref": item.parent_ref,
                "metadata_json": item.metadata_json,
                "active": item.active,
            }
        )
        return fingerprint, None, f"compliance_subject:{item.id}", None

    if kind == "manual_reference":
        return "", None, reference_key or "manual_reference", None

    raise HTTPException(status_code=422, detail="Unbekannte Content-Abhängigkeitsart.")


def _record_impact(
    db: Session,
    current_user: User,
    dependency: ContentDependency,
    current_hash: str,
    current_version: str | None,
    rationale: str,
    source_ref: str | None,
    priority: str = "normal",
) -> ContentImpactAssessment | None:
    dependency.last_seen_hash = current_hash
    dependency.last_seen_version = current_version
    dependency.last_checked_at = _now()
    if source_ref and not dependency.source_ref:
        dependency.source_ref = source_ref

    if dependency.baseline_hash is None:
        dependency.baseline_hash = current_hash
        dependency.baseline_version = current_version
        return None

    if dependency.baseline_hash == current_hash:
        return None

    existing = db.query(ContentImpactAssessment).filter(
        ContentImpactAssessment.tenant_id == dependency.tenant_id,
        ContentImpactAssessment.dependency_id == dependency.id,
        ContentImpactAssessment.current_hash == current_hash,
        ContentImpactAssessment.status == "pending",
    ).first()
    if existing is not None:
        return existing

    pack = _require_pack(db, dependency.tenant_id, dependency.content_pack_id)
    pack.currentness_status = "review_required"
    pack.human_review_required = True

    impact = ContentImpactAssessment(
        tenant_id=dependency.tenant_id,
        content_pack_id=dependency.content_pack_id,
        dependency_id=dependency.id,
        trigger_type=dependency.dependency_kind,
        trigger_ref=dependency.dependency_key,
        previous_hash=dependency.baseline_hash,
        current_hash=current_hash,
        previous_version=dependency.baseline_version,
        current_version=current_version,
        status="pending",
        priority=priority,
        rationale=rationale,
        evidence_json=_json(
            {
                "source_ref": source_ref or dependency.source_ref,
                "dependency_kind": dependency.dependency_kind,
                "automatic_release": False,
            }
        ),
        human_review_required=True,
    )
    db.add(impact)
    db.flush()
    db.add(
        AuditLog(
            event=f"content_impact_detected:{impact.id}:pack:{pack.id}",
            user_id=current_user.id,
            tenant_id=dependency.tenant_id,
        )
    )
    return impact


def _refresh_pack_currentness(db: Session, tenant_id: int, pack_id: int) -> None:
    pending = db.query(ContentImpactAssessment).filter(
        ContentImpactAssessment.tenant_id == tenant_id,
        ContentImpactAssessment.content_pack_id == pack_id,
        ContentImpactAssessment.status == "pending",
    ).count()
    if pending == 0:
        pack = _require_pack(db, tenant_id, pack_id)
        if pack.currentness_status != "superseded":
            pack.currentness_status = "current"


@router.post("/dependencies", status_code=status.HTTP_201_CREATED)
def create_dependency(data: DependencyCreate, current_user: CurrentUser, db: DBSession):
    require_permission(current_user, "content.manage_dependencies")
    tenant_id = _tenant_id(current_user)
    pack = _require_pack(db, tenant_id, data.content_pack_id)
    kind = data.dependency_kind.strip().lower()
    if kind not in DEPENDENCY_KINDS:
        raise HTTPException(status_code=422, detail="Unbekannte Content-Abhängigkeitsart.")

    state_hash, state_version, state_key, discovered_source = _dependency_state(
        db,
        tenant_id,
        kind,
        data.reference_id,
        data.reference_key.strip() if data.reference_key else None,
    )
    dependency_key = data.reference_key.strip() if kind == "manual_reference" and data.reference_key else state_key
    baseline_hash = data.baseline_hash or (state_hash if state_hash else None)
    baseline_version = data.baseline_version or state_version

    existing = db.query(ContentDependency).filter(
        ContentDependency.tenant_id == tenant_id,
        ContentDependency.content_pack_id == pack.id,
        ContentDependency.dependency_kind == kind,
        ContentDependency.dependency_key == dependency_key,
    ).first()
    if existing is not None:
        raise HTTPException(status_code=409, detail="Diese Content-Abhängigkeit existiert bereits.")

    item = ContentDependency(
        tenant_id=tenant_id,
        content_pack_id=pack.id,
        dependency_kind=kind,
        dependency_key=dependency_key,
        reference_id=data.reference_id,
        source_ref=data.source_ref.strip() if data.source_ref else discovered_source,
        baseline_hash=baseline_hash,
        baseline_version=baseline_version,
        last_seen_hash=baseline_hash,
        last_seen_version=baseline_version,
        last_checked_at=_now(),
        active=True,
        created_by_id=current_user.id,
    )
    db.add(item)
    db.flush()
    db.add(AuditLog(event=f"content_dependency_created:{item.id}:pack:{pack.id}", user_id=current_user.id, tenant_id=tenant_id))
    db.commit()
    db.refresh(item)
    return _serialize_dependency(item)


@router.get("/packs/{pack_id}/dependencies")
def list_dependencies(pack_id: int, current_user: CurrentUser, db: DBSession):
    require_permission(current_user, "content.read")
    tenant_id = _tenant_id(current_user)
    _require_pack(db, tenant_id, pack_id)
    items = db.query(ContentDependency).filter(
        ContentDependency.tenant_id == tenant_id,
        ContentDependency.content_pack_id == pack_id,
    ).order_by(ContentDependency.created_at.asc()).all()
    return {"dependencies": [_serialize_dependency(item) for item in items]}


@router.post("/impact-scan")
def impact_scan(current_user: CurrentUser, db: DBSession):
    require_permission(current_user, "content.scan_impacts")
    tenant_id = _tenant_id(current_user)
    dependencies = db.query(ContentDependency).filter(
        ContentDependency.tenant_id == tenant_id,
        ContentDependency.active.is_(True),
    ).all()
    checked = 0
    detected: list[int] = []
    for dependency in dependencies:
        if dependency.dependency_kind == "manual_reference":
            continue
        checked += 1
        state_hash, state_version, _key, source_ref = _dependency_state(
            db,
            tenant_id,
            dependency.dependency_kind,
            dependency.reference_id,
            dependency.dependency_key,
        )
        impact = _record_impact(
            db,
            current_user,
            dependency,
            state_hash,
            state_version,
            "Referenced governed source changed since the dependency baseline; qualified review is required.",
            source_ref,
        )
        if impact is not None and impact.id not in detected:
            detected.append(impact.id)
    db.add(AuditLog(event=f"content_impact_scan:{checked}:{len(detected)}", user_id=current_user.id, tenant_id=tenant_id))
    db.commit()
    return {
        "checked": checked,
        "detected": len(detected),
        "impact_ids": detected,
        "governance": "Impacts create review tasks only; approved operational content is never silently replaced.",
    }


@router.post("/dependencies/{dependency_id}/signal")
def signal_dependency_change(
    dependency_id: int,
    data: DependencySignal,
    current_user: CurrentUser,
    db: DBSession,
):
    require_permission(current_user, "content.scan_impacts")
    tenant_id = _tenant_id(current_user)
    dependency = _require_dependency(db, tenant_id, dependency_id)
    impact = _record_impact(
        db,
        current_user,
        dependency,
        data.current_hash,
        data.current_version,
        data.rationale.strip(),
        data.source_ref.strip() if data.source_ref else None,
        data.priority,
    )
    db.commit()
    return {
        "changed": impact is not None,
        "impact": _serialize_impact(impact) if impact is not None else None,
    }


@router.get("/impacts")
def list_impacts(
    current_user: CurrentUser,
    db: DBSession,
    status_filter: str | None = None,
):
    require_permission(current_user, "content.read")
    tenant_id = _tenant_id(current_user)
    query = db.query(ContentImpactAssessment).filter(ContentImpactAssessment.tenant_id == tenant_id)
    if status_filter:
        query = query.filter(ContentImpactAssessment.status == status_filter.strip().lower())
    items = query.order_by(ContentImpactAssessment.detected_at.desc()).all()
    return {"impacts": [_serialize_impact(item) for item in items]}


@router.post("/impacts/{impact_id}/resolve")
def resolve_impact(
    impact_id: int,
    data: ImpactResolution,
    current_user: CurrentUser,
    db: DBSession,
):
    require_permission(current_user, "content.approve")
    tenant_id = _tenant_id(current_user)
    impact = _require_impact(db, tenant_id, impact_id)
    if impact.status != "pending":
        raise HTTPException(status_code=409, detail="Dieser Impact wurde bereits bearbeitet.")
    dependency = _require_dependency(db, tenant_id, impact.dependency_id)
    impact.status = data.resolution
    impact.resolution_note = data.note.strip()
    impact.resolved_by_id = current_user.id
    impact.resolved_at = _now()
    impact.human_review_required = False
    if impact.current_hash:
        dependency.baseline_hash = impact.current_hash
        dependency.baseline_version = impact.current_version
    _refresh_pack_currentness(db, tenant_id, impact.content_pack_id)
    db.add(AuditLog(event=f"content_impact_resolved:{impact.id}:{impact.status}", user_id=current_user.id, tenant_id=tenant_id))
    db.commit()
    return _serialize_impact(impact)


@router.post("/impacts/{impact_id}/create-revision", status_code=status.HTTP_201_CREATED)
def create_revision(
    impact_id: int,
    data: RevisionCreate,
    current_user: CurrentUser,
    db: DBSession,
):
    require_permission(current_user, "content.create")
    tenant_id = _tenant_id(current_user)
    impact = _require_impact(db, tenant_id, impact_id)
    if impact.status != "pending":
        raise HTTPException(status_code=409, detail="Dieser Impact wurde bereits bearbeitet.")
    old_pack = _require_pack(db, tenant_id, impact.content_pack_id)
    latest = db.query(LearningContentPack).filter(
        LearningContentPack.tenant_id == tenant_id,
        LearningContentPack.pack_key == old_pack.pack_key,
    ).order_by(LearningContentPack.version.desc()).first()
    next_version = 1 if latest is None else latest.version + 1
    fingerprint = {
        "pack_key": old_pack.pack_key,
        "version": next_version,
        "supersedes_id": old_pack.id,
        "change_reason": data.change_reason.strip(),
        "source_refs_json": old_pack.source_refs_json,
        "requirement_refs_json": old_pack.requirement_refs_json,
    }
    new_pack = LearningContentPack(
        tenant_id=tenant_id,
        pack_key=old_pack.pack_key,
        version=next_version,
        title=old_pack.title,
        activity_template_id=old_pack.activity_template_id,
        activity_ref=old_pack.activity_ref,
        industry_scheme=old_pack.industry_scheme,
        industry_code=old_pack.industry_code,
        jurisdiction=old_pack.jurisdiction,
        target_audience=old_pack.target_audience,
        language=old_pack.language,
        depth_profile=old_pack.depth_profile,
        status="draft",
        currentness_status="current",
        source_refs_json=old_pack.source_refs_json,
        requirement_refs_json=old_pack.requirement_refs_json,
        content_hash=_hash(fingerprint),
        change_reason=data.change_reason.strip(),
        human_review_required=True,
        supersedes_id=old_pack.id,
        created_by_id=current_user.id,
    )
    db.add(new_pack)
    db.flush()

    old_dependencies = db.query(ContentDependency).filter(
        ContentDependency.tenant_id == tenant_id,
        ContentDependency.content_pack_id == old_pack.id,
        ContentDependency.active.is_(True),
    ).all()
    cloned = 0
    for dependency in old_dependencies:
        baseline_hash = dependency.last_seen_hash or dependency.baseline_hash
        baseline_version = dependency.last_seen_version or dependency.baseline_version
        db.add(
            ContentDependency(
                tenant_id=tenant_id,
                content_pack_id=new_pack.id,
                dependency_kind=dependency.dependency_kind,
                dependency_key=dependency.dependency_key,
                reference_id=dependency.reference_id,
                source_ref=dependency.source_ref,
                baseline_hash=baseline_hash,
                baseline_version=baseline_version,
                last_seen_hash=baseline_hash,
                last_seen_version=baseline_version,
                last_checked_at=_now(),
                active=True,
                created_by_id=current_user.id,
            )
        )
        dependency.active = False
        cloned += 1

    old_pack.currentness_status = "superseded"
    impact.status = "revision_created"
    impact.resolution_note = data.change_reason.strip()
    impact.resolved_by_id = current_user.id
    impact.resolved_at = _now()
    impact.human_review_required = False
    db.add(
        AuditLog(
            event=f"content_revision_created:{old_pack.id}:{new_pack.id}:impact:{impact.id}",
            user_id=current_user.id,
            tenant_id=tenant_id,
        )
    )
    db.commit()
    return {
        "impact_id": impact.id,
        "superseded_pack_id": old_pack.id,
        "new_pack_id": new_pack.id,
        "new_version": new_pack.version,
        "dependencies_cloned": cloned,
        "status": "draft_requires_human_review",
    }
