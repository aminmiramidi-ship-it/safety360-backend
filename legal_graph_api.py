import json
from datetime import datetime, timezone
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from auth import get_current_user
from database import get_db
from legal_graph_models import (
    ApplicabilityAssessment,
    ComplianceSubject,
    RegulatoryImpactAction,
    RequirementRelation,
)
from models import AuditLog, User
from permissions import require_permission
from regulatory_models import RegulatoryRequirement

router = APIRouter()

DBSession = Annotated[Session, Depends(get_db)]
CurrentUser = Annotated[User, Depends(get_current_user)]

SUBJECT_TYPES = {
    "organization",
    "site",
    "project",
    "process",
    "activity",
    "asset",
    "machine",
    "installation",
    "substance",
    "person_group",
    "role",
    "permit",
    "environment_aspect",
    "energy_aspect",
    "management_system",
    "document",
    "training",
}
APPLICABILITY_STATUSES = {"unknown", "review_required", "applicable", "not_applicable"}
ORIGINS = {"manual", "rule", "agent", "import"}
PRIORITIES = {"low", "normal", "high", "critical"}
RELATION_TYPES = {
    "implements",
    "concretizes",
    "depends_on",
    "related_to",
    "supersedes",
    "amends",
    "supports",
}
ACTION_TYPES = {
    "compliance_review",
    "review_risk_assessment",
    "create_controlled_revision",
    "review_operating_instruction",
    "review_training",
    "review_inspection_plan",
    "review_hazardous_substance_workflow",
    "review_environmental_aspect",
    "review_energy_action",
    "review_management_system_mapping",
    "review_audit_criteria",
    "create_capa",
}


class SubjectCreate(BaseModel):
    subject_type: str = Field(min_length=2, max_length=60)
    subject_key: str = Field(min_length=1, max_length=240)
    title: str = Field(min_length=2, max_length=500)
    jurisdiction: str | None = Field(default=None, max_length=80)
    parent_ref: str | None = Field(default=None, max_length=320)
    metadata: dict[str, object] = Field(default_factory=dict)


class AssessmentUpsert(BaseModel):
    requirement_id: int
    subject_id: int
    applicability_status: Literal["unknown", "review_required", "applicable", "not_applicable"] = "review_required"
    origin: Literal["manual", "rule", "agent", "import"] = "manual"
    confidence: int = Field(default=0, ge=0, le=100)
    priority: Literal["low", "normal", "high", "critical"] = "normal"
    rationale: str | None = None
    evidence: dict[str, object] = Field(default_factory=dict)
    missing_evidence: list[str] = Field(default_factory=list)


class AssessmentReview(BaseModel):
    applicability_status: Literal["applicable", "not_applicable", "review_required"]
    confidence: int = Field(default=100, ge=0, le=100)
    priority: Literal["low", "normal", "high", "critical"] = "normal"
    rationale: str | None = None
    evidence: dict[str, object] = Field(default_factory=dict)
    missing_evidence: list[str] = Field(default_factory=list)


class RelationCreate(BaseModel):
    from_requirement_id: int
    to_requirement_id: int
    relation_type: str = Field(min_length=2, max_length=60)
    rationale: str | None = None
    source_reference: str | None = Field(default=None, max_length=1000)


class ImpactActionCreate(BaseModel):
    requirement_id: int
    subject_id: int
    action_type: str = Field(min_length=2, max_length=80)
    target_ref: str = Field(min_length=1, max_length=320)
    priority: Literal["low", "normal", "high", "critical"] = "normal"
    rationale: str | None = None
    evidence: dict[str, object] = Field(default_factory=dict)


class ImpactActionReview(BaseModel):
    approved: bool


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _require_tenant(user: User) -> int:
    if user.tenant_id is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Für diese Funktion muss der Benutzer einem Mandanten zugeordnet sein.",
        )
    return int(user.tenant_id)


def _json_object(raw: str | None) -> dict[str, object]:
    try:
        value = json.loads(raw or "{}")
        return value if isinstance(value, dict) else {}
    except (TypeError, ValueError):
        return {}


def _json_list(raw: str | None) -> list[object]:
    try:
        value = json.loads(raw or "[]")
        return value if isinstance(value, list) else []
    except (TypeError, ValueError):
        return []


def _serialize_subject(item: ComplianceSubject) -> dict[str, object]:
    return {
        "id": item.id,
        "tenant_id": item.tenant_id,
        "subject_type": item.subject_type,
        "subject_key": item.subject_key,
        "title": item.title,
        "jurisdiction": item.jurisdiction,
        "parent_ref": item.parent_ref,
        "metadata": _json_object(item.metadata_json),
        "active": item.active,
        "created_at": item.created_at,
        "updated_at": item.updated_at,
    }


def _serialize_assessment(item: ApplicabilityAssessment) -> dict[str, object]:
    return {
        "id": item.id,
        "tenant_id": item.tenant_id,
        "requirement_id": item.requirement_id,
        "subject_id": item.subject_id,
        "applicability_status": item.applicability_status,
        "origin": item.origin,
        "confidence": item.confidence,
        "priority": item.priority,
        "rationale": item.rationale,
        "evidence": _json_object(item.evidence_json),
        "missing_evidence": _json_list(item.missing_evidence_json),
        "human_review_required": item.human_review_required,
        "reviewed_by_id": item.reviewed_by_id,
        "reviewed_at": item.reviewed_at,
        "last_evaluated_at": item.last_evaluated_at,
        "created_at": item.created_at,
        "updated_at": item.updated_at,
    }


def _serialize_action(item: RegulatoryImpactAction) -> dict[str, object]:
    return {
        "id": item.id,
        "tenant_id": item.tenant_id,
        "requirement_id": item.requirement_id,
        "subject_id": item.subject_id,
        "action_type": item.action_type,
        "target_ref": item.target_ref,
        "status": item.status,
        "priority": item.priority,
        "rationale": item.rationale,
        "evidence": _json_object(item.evidence_json),
        "human_review_required": item.human_review_required,
        "approved_by_id": item.approved_by_id,
        "approved_at": item.approved_at,
        "created_at": item.created_at,
        "updated_at": item.updated_at,
    }


def _require_requirement(db: Session, requirement_id: int) -> RegulatoryRequirement:
    requirement = db.query(RegulatoryRequirement).filter(RegulatoryRequirement.id == requirement_id).first()
    if requirement is None:
        raise HTTPException(status_code=404, detail="Regelwerksanforderung wurde nicht gefunden.")
    return requirement


def _require_subject(db: Session, tenant_id: int, subject_id: int) -> ComplianceSubject:
    subject = db.query(ComplianceSubject).filter(
        ComplianceSubject.id == subject_id,
        ComplianceSubject.tenant_id == tenant_id,
    ).first()
    if subject is None:
        raise HTTPException(status_code=404, detail="Compliance-Objekt wurde nicht gefunden.")
    return subject


def _suggested_action(subject_type: str) -> str:
    mapping = {
        "activity": "review_risk_assessment",
        "process": "review_risk_assessment",
        "document": "create_controlled_revision",
        "training": "review_training",
        "asset": "review_inspection_plan",
        "machine": "review_inspection_plan",
        "installation": "review_inspection_plan",
        "substance": "review_hazardous_substance_workflow",
        "environment_aspect": "review_environmental_aspect",
        "energy_aspect": "review_energy_action",
        "management_system": "review_management_system_mapping",
    }
    return mapping.get(subject_type, "compliance_review")


@router.post("/subjects", status_code=status.HTTP_201_CREATED)
def create_subject(data: SubjectCreate, current_user: CurrentUser, db: DBSession):
    require_permission(current_user, "legal_graph.manage")
    tenant_id = _require_tenant(current_user)
    subject_type = data.subject_type.strip().lower()
    if subject_type not in SUBJECT_TYPES:
        raise HTTPException(status_code=422, detail="Unbekannter Compliance-Objekttyp.")

    key = data.subject_key.strip()
    duplicate = db.query(ComplianceSubject).filter(
        ComplianceSubject.tenant_id == tenant_id,
        ComplianceSubject.subject_type == subject_type,
        ComplianceSubject.subject_key == key,
    ).first()
    if duplicate:
        raise HTTPException(status_code=409, detail="Compliance-Objekt existiert bereits.")

    item = ComplianceSubject(
        tenant_id=tenant_id,
        subject_type=subject_type,
        subject_key=key,
        title=data.title.strip(),
        jurisdiction=data.jurisdiction.strip().upper() if data.jurisdiction else None,
        parent_ref=data.parent_ref.strip() if data.parent_ref else None,
        metadata_json=json.dumps(data.metadata, ensure_ascii=False, sort_keys=True),
        created_by_id=current_user.id,
    )
    db.add(item)
    db.flush()
    db.add(AuditLog(event=f"legal_subject_created:{item.id}", user_id=current_user.id, tenant_id=tenant_id))
    db.commit()
    db.refresh(item)
    return _serialize_subject(item)


@router.get("/subjects")
def list_subjects(
    current_user: CurrentUser,
    db: DBSession,
    subject_type: str | None = None,
    active_only: bool = True,
):
    require_permission(current_user, "legal_graph.read")
    tenant_id = _require_tenant(current_user)
    query = db.query(ComplianceSubject).filter(ComplianceSubject.tenant_id == tenant_id)
    if subject_type:
        query = query.filter(ComplianceSubject.subject_type == subject_type.strip().lower())
    if active_only:
        query = query.filter(ComplianceSubject.active.is_(True))
    return {"subjects": [_serialize_subject(item) for item in query.order_by(ComplianceSubject.subject_type, ComplianceSubject.title).all()]}


@router.put("/assessments")
def upsert_assessment(data: AssessmentUpsert, current_user: CurrentUser, db: DBSession):
    require_permission(current_user, "legal_graph.manage")
    tenant_id = _require_tenant(current_user)
    _require_requirement(db, data.requirement_id)
    _require_subject(db, tenant_id, data.subject_id)

    item = db.query(ApplicabilityAssessment).filter(
        ApplicabilityAssessment.tenant_id == tenant_id,
        ApplicabilityAssessment.requirement_id == data.requirement_id,
        ApplicabilityAssessment.subject_id == data.subject_id,
    ).first()
    if item is None:
        item = ApplicabilityAssessment(
            tenant_id=tenant_id,
            requirement_id=data.requirement_id,
            subject_id=data.subject_id,
        )
        db.add(item)

    item.applicability_status = data.applicability_status
    item.origin = data.origin
    item.confidence = data.confidence
    item.priority = data.priority
    item.rationale = data.rationale.strip() if data.rationale else None
    item.evidence_json = json.dumps(data.evidence, ensure_ascii=False, sort_keys=True)
    item.missing_evidence_json = json.dumps(data.missing_evidence, ensure_ascii=False)
    item.human_review_required = True
    item.reviewed_by_id = None
    item.reviewed_at = None
    item.last_evaluated_at = _utc_now()

    db.flush()
    db.add(AuditLog(event=f"legal_applicability_upserted:{item.id}", user_id=current_user.id, tenant_id=tenant_id))
    db.commit()
    db.refresh(item)
    return _serialize_assessment(item)


@router.post("/assessments/{assessment_id}/review")
def review_assessment(
    assessment_id: int,
    data: AssessmentReview,
    current_user: CurrentUser,
    db: DBSession,
):
    require_permission(current_user, "legal_graph.review")
    tenant_id = _require_tenant(current_user)
    item = db.query(ApplicabilityAssessment).filter(
        ApplicabilityAssessment.id == assessment_id,
        ApplicabilityAssessment.tenant_id == tenant_id,
    ).first()
    if item is None:
        raise HTTPException(status_code=404, detail="Anwendbarkeitsbewertung wurde nicht gefunden.")

    item.applicability_status = data.applicability_status
    item.confidence = data.confidence
    item.priority = data.priority
    item.rationale = data.rationale.strip() if data.rationale else item.rationale
    item.evidence_json = json.dumps(data.evidence, ensure_ascii=False, sort_keys=True)
    item.missing_evidence_json = json.dumps(data.missing_evidence, ensure_ascii=False)
    item.human_review_required = data.applicability_status == "review_required"
    item.reviewed_by_id = current_user.id
    item.reviewed_at = _utc_now()

    db.add(AuditLog(event=f"legal_applicability_reviewed:{item.id}:{item.applicability_status}", user_id=current_user.id, tenant_id=tenant_id))
    db.commit()
    db.refresh(item)
    return _serialize_assessment(item)


@router.get("/matrix")
def applicability_matrix(
    current_user: CurrentUser,
    db: DBSession,
    applicability_status: str | None = None,
    subject_type: str | None = None,
    requirement_id: int | None = None,
    review_required: bool | None = Query(default=None),
):
    require_permission(current_user, "legal_graph.read")
    tenant_id = _require_tenant(current_user)
    query = db.query(ApplicabilityAssessment).filter(ApplicabilityAssessment.tenant_id == tenant_id)
    if applicability_status:
        normalized = applicability_status.strip().lower()
        if normalized not in APPLICABILITY_STATUSES:
            raise HTTPException(status_code=422, detail="Ungültiger Anwendbarkeitsstatus.")
        query = query.filter(ApplicabilityAssessment.applicability_status == normalized)
    if requirement_id is not None:
        query = query.filter(ApplicabilityAssessment.requirement_id == requirement_id)
    if review_required is not None:
        query = query.filter(ApplicabilityAssessment.human_review_required.is_(review_required))

    items = query.order_by(ApplicabilityAssessment.priority.desc(), ApplicabilityAssessment.updated_at.desc()).all()
    subject_ids = {item.subject_id for item in items}
    subjects = {
        item.id: item
        for item in db.query(ComplianceSubject).filter(
            ComplianceSubject.tenant_id == tenant_id,
            ComplianceSubject.id.in_(subject_ids) if subject_ids else False,
        ).all()
    } if subject_ids else {}

    rows = []
    for item in items:
        subject = subjects.get(item.subject_id)
        if subject_type and (subject is None or subject.subject_type != subject_type.strip().lower()):
            continue
        row = _serialize_assessment(item)
        row["subject"] = _serialize_subject(subject) if subject else None
        rows.append(row)
    return {"rows": rows, "count": len(rows)}


@router.post("/relations", status_code=status.HTTP_201_CREATED)
def create_requirement_relation(data: RelationCreate, current_user: CurrentUser, db: DBSession):
    require_permission(current_user, "*")
    relation_type = data.relation_type.strip().lower()
    if relation_type not in RELATION_TYPES:
        raise HTTPException(status_code=422, detail="Unbekannter Beziehungstyp.")
    if data.from_requirement_id == data.to_requirement_id:
        raise HTTPException(status_code=422, detail="Eine Anforderung kann nicht auf sich selbst verweisen.")
    _require_requirement(db, data.from_requirement_id)
    _require_requirement(db, data.to_requirement_id)

    duplicate = db.query(RequirementRelation).filter(
        RequirementRelation.from_requirement_id == data.from_requirement_id,
        RequirementRelation.to_requirement_id == data.to_requirement_id,
        RequirementRelation.relation_type == relation_type,
    ).first()
    if duplicate:
        raise HTTPException(status_code=409, detail="Regelwerksbeziehung existiert bereits.")

    item = RequirementRelation(
        from_requirement_id=data.from_requirement_id,
        to_requirement_id=data.to_requirement_id,
        relation_type=relation_type,
        rationale=data.rationale.strip() if data.rationale else None,
        source_reference=data.source_reference.strip() if data.source_reference else None,
    )
    db.add(item)
    db.flush()
    db.add(AuditLog(event=f"legal_relation_created:{item.id}", user_id=current_user.id, tenant_id=current_user.tenant_id))
    db.commit()
    return {"id": item.id, "relation_type": item.relation_type, "human_review_required": item.human_review_required}


@router.get("/relations")
def list_requirement_relations(current_user: CurrentUser, db: DBSession, requirement_id: int | None = None):
    require_permission(current_user, "legal_graph.read")
    query = db.query(RequirementRelation)
    if requirement_id is not None:
        query = query.filter(
            (RequirementRelation.from_requirement_id == requirement_id)
            | (RequirementRelation.to_requirement_id == requirement_id)
        )
    return {
        "relations": [
            {
                "id": item.id,
                "from_requirement_id": item.from_requirement_id,
                "to_requirement_id": item.to_requirement_id,
                "relation_type": item.relation_type,
                "rationale": item.rationale,
                "source_reference": item.source_reference,
                "human_review_required": item.human_review_required,
                "verified_at": item.verified_at,
            }
            for item in query.order_by(RequirementRelation.id.asc()).all()
        ]
    }


@router.get("/requirements/{requirement_id}/impact-preview")
def impact_preview(requirement_id: int, current_user: CurrentUser, db: DBSession):
    require_permission(current_user, "legal_graph.read")
    tenant_id = _require_tenant(current_user)
    requirement = _require_requirement(db, requirement_id)
    assessments = db.query(ApplicabilityAssessment).filter(
        ApplicabilityAssessment.tenant_id == tenant_id,
        ApplicabilityAssessment.requirement_id == requirement_id,
        ApplicabilityAssessment.applicability_status.in_(["applicable", "review_required", "unknown"]),
    ).all()

    subject_ids = {item.subject_id for item in assessments}
    subjects = {
        item.id: item
        for item in db.query(ComplianceSubject).filter(
            ComplianceSubject.tenant_id == tenant_id,
            ComplianceSubject.id.in_(subject_ids) if subject_ids else False,
        ).all()
    } if subject_ids else {}

    impacts = []
    for assessment in assessments:
        subject = subjects.get(assessment.subject_id)
        if subject is None:
            continue
        impacts.append(
            {
                "assessment_id": assessment.id,
                "applicability_status": assessment.applicability_status,
                "priority": assessment.priority,
                "subject": _serialize_subject(subject),
                "suggested_action_type": _suggested_action(subject.subject_type),
                "requires_human_review": True,
            }
        )

    return {
        "requirement": {
            "id": requirement.id,
            "title": requirement.title,
            "citation": requirement.citation,
            "jurisdiction": requirement.jurisdiction,
            "topic": requirement.topic,
            "source_version": requirement.source_version,
            "verified_at": requirement.verified_at,
        },
        "impact_count": len(impacts),
        "impacts": impacts,
        "note": "Impact-Vorschläge sind keine verbindliche Rechtsbewertung und müssen fachlich geprüft werden.",
    }


@router.post("/actions", status_code=status.HTTP_201_CREATED)
def create_impact_action(data: ImpactActionCreate, current_user: CurrentUser, db: DBSession):
    require_permission(current_user, "legal_graph.manage")
    tenant_id = _require_tenant(current_user)
    _require_requirement(db, data.requirement_id)
    _require_subject(db, tenant_id, data.subject_id)
    action_type = data.action_type.strip().lower()
    if action_type not in ACTION_TYPES:
        raise HTTPException(status_code=422, detail="Unbekannter Impact-Aktionstyp.")

    duplicate = db.query(RegulatoryImpactAction).filter(
        RegulatoryImpactAction.tenant_id == tenant_id,
        RegulatoryImpactAction.requirement_id == data.requirement_id,
        RegulatoryImpactAction.subject_id == data.subject_id,
        RegulatoryImpactAction.action_type == action_type,
        RegulatoryImpactAction.target_ref == data.target_ref.strip(),
    ).first()
    if duplicate:
        return _serialize_action(duplicate)

    item = RegulatoryImpactAction(
        tenant_id=tenant_id,
        requirement_id=data.requirement_id,
        subject_id=data.subject_id,
        action_type=action_type,
        target_ref=data.target_ref.strip(),
        priority=data.priority,
        rationale=data.rationale.strip() if data.rationale else None,
        evidence_json=json.dumps(data.evidence, ensure_ascii=False, sort_keys=True),
    )
    db.add(item)
    db.flush()
    db.add(AuditLog(event=f"regulatory_impact_action_created:{item.id}", user_id=current_user.id, tenant_id=tenant_id))
    db.commit()
    db.refresh(item)
    return _serialize_action(item)


@router.get("/actions")
def list_impact_actions(
    current_user: CurrentUser,
    db: DBSession,
    action_status: str | None = None,
    requirement_id: int | None = None,
):
    require_permission(current_user, "legal_graph.read")
    tenant_id = _require_tenant(current_user)
    query = db.query(RegulatoryImpactAction).filter(RegulatoryImpactAction.tenant_id == tenant_id)
    if action_status:
        query = query.filter(RegulatoryImpactAction.status == action_status.strip().lower())
    if requirement_id is not None:
        query = query.filter(RegulatoryImpactAction.requirement_id == requirement_id)
    return {"actions": [_serialize_action(item) for item in query.order_by(RegulatoryImpactAction.created_at.desc()).all()]}


@router.post("/actions/{action_id}/review")
def review_impact_action(
    action_id: int,
    data: ImpactActionReview,
    current_user: CurrentUser,
    db: DBSession,
):
    require_permission(current_user, "legal_graph.review")
    tenant_id = _require_tenant(current_user)
    item = db.query(RegulatoryImpactAction).filter(
        RegulatoryImpactAction.id == action_id,
        RegulatoryImpactAction.tenant_id == tenant_id,
    ).first()
    if item is None:
        raise HTTPException(status_code=404, detail="Impact-Aktion wurde nicht gefunden.")

    item.status = "approved" if data.approved else "rejected"
    item.human_review_required = False
    item.approved_by_id = current_user.id if data.approved else None
    item.approved_at = _utc_now()
    db.add(AuditLog(event=f"regulatory_impact_action_reviewed:{item.id}:{item.status}", user_id=current_user.id, tenant_id=tenant_id))
    db.commit()
    db.refresh(item)
    return _serialize_action(item)


@router.get("/summary")
def legal_graph_summary(current_user: CurrentUser, db: DBSession):
    require_permission(current_user, "legal_graph.read")
    tenant_id = _require_tenant(current_user)
    subjects = db.query(ComplianceSubject).filter(ComplianceSubject.tenant_id == tenant_id, ComplianceSubject.active.is_(True)).count()
    assessments = db.query(ApplicabilityAssessment).filter(ApplicabilityAssessment.tenant_id == tenant_id).all()
    pending_reviews = sum(1 for item in assessments if item.human_review_required)
    applicable = sum(1 for item in assessments if item.applicability_status == "applicable")
    actions = db.query(RegulatoryImpactAction).filter(RegulatoryImpactAction.tenant_id == tenant_id).all()
    proposed_actions = sum(1 for item in actions if item.status == "proposed")
    critical_actions = sum(1 for item in actions if item.status == "proposed" and item.priority == "critical")
    return {
        "subjects": subjects,
        "assessments": len(assessments),
        "applicable": applicable,
        "pending_reviews": pending_reviews,
        "proposed_actions": proposed_actions,
        "critical_proposed_actions": critical_actions,
    }
