import json
from datetime import datetime, timedelta, timezone
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from auth import get_current_user
from database import get_db
from models import AuditLog, User
from occupational_health_models import (
    OccupationalHealthAppointment,
    OccupationalHealthCase,
    OccupationalHealthEvidence,
    OccupationalHealthNotification,
    OccupationalHealthRequirement,
)
from permissions import require_permission

router = APIRouter()

DBSession = Annotated[Session, Depends(get_db)]
CurrentUser = Annotated[User, Depends(get_current_user)]

REQUIREMENT_KINDS = {
    "preventive_care_mandatory",
    "preventive_care_offer",
    "preventive_care_request",
    "fitness_assessment",
    "vaccination_offer",
    "other",
}


class RequirementCreate(BaseModel):
    requirement_key: str = Field(min_length=2, max_length=240)
    title: str = Field(min_length=2, max_length=500)
    requirement_kind: str = Field(min_length=2, max_length=60)
    trigger_type: str = Field(min_length=2, max_length=80)
    trigger_ref: str = Field(min_length=1, max_length=320)
    legal_basis_ref: str | None = Field(default=None, max_length=500)
    source_requirement_id: int | None = None
    recurrence_days: int | None = Field(default=None, ge=1, le=3650)
    due_soon_days: int = Field(default=30, ge=1, le=365)
    notes: str | None = None


class CaseUpsert(BaseModel):
    requirement_id: int
    employee_ref: str = Field(min_length=1, max_length=320)
    employee_user_id: int | None = None
    manager_ref: str | None = Field(default=None, max_length=320)
    provider_ref: str | None = Field(default=None, max_length=320)
    due_at: datetime | None = None


class AvailabilityWindow(BaseModel):
    start: datetime
    end: datetime


class AppointmentProposalRequest(BaseModel):
    case_id: int
    employee_windows: list[AvailabilityWindow] = Field(min_length=1, max_length=100)
    provider_windows: list[AvailabilityWindow] = Field(min_length=1, max_length=100)
    duration_minutes: int = Field(default=30, ge=15, le=240)
    timezone_name: str = Field(default="Europe/Berlin", min_length=2, max_length=80)
    employee_calendar_provider: str | None = Field(default=None, max_length=60)
    provider_calendar_provider: str | None = Field(default=None, max_length=60)
    consent_or_legal_basis_ref: str | None = Field(default=None, max_length=500)


class AppointmentReview(BaseModel):
    accepted: bool
    external_event_ref: str | None = Field(default=None, max_length=500)


class EvidenceCreate(BaseModel):
    case_id: int
    evidence_type: str = Field(min_length=2, max_length=80)
    file_ref: str | None = Field(default=None, max_length=500)
    issued_at: datetime | None = None
    next_due_at: datetime | None = None
    source: str = Field(default="provider_upload", min_length=2, max_length=80)
    contains_clinical_findings: bool = False
    employer_access_allowed: bool = False
    metadata: dict[str, object] = Field(default_factory=dict)


class EvidenceVerify(BaseModel):
    verified: bool = True


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _require_tenant(user: User) -> int:
    if user.tenant_id is None:
        raise HTTPException(status_code=409, detail="Benutzer ist keinem Mandanten zugeordnet.")
    return int(user.tenant_id)


def _require_requirement(db: Session, tenant_id: int, requirement_id: int) -> OccupationalHealthRequirement:
    item = db.query(OccupationalHealthRequirement).filter(
        OccupationalHealthRequirement.id == requirement_id,
        OccupationalHealthRequirement.tenant_id == tenant_id,
    ).first()
    if item is None:
        raise HTTPException(status_code=404, detail="Arbeitsmedizinische Anforderung wurde nicht gefunden.")
    return item


def _require_case(db: Session, tenant_id: int, case_id: int) -> OccupationalHealthCase:
    item = db.query(OccupationalHealthCase).filter(
        OccupationalHealthCase.id == case_id,
        OccupationalHealthCase.tenant_id == tenant_id,
    ).first()
    if item is None:
        raise HTTPException(status_code=404, detail="Arbeitsmedizinischer Vorgang wurde nicht gefunden.")
    return item


def _serialize_case(item: OccupationalHealthCase) -> dict[str, object]:
    return {
        "id": item.id,
        "requirement_id": item.requirement_id,
        "employee_ref": item.employee_ref,
        "manager_ref": item.manager_ref,
        "provider_ref": item.provider_ref,
        "status": item.status,
        "workflow_state": item.workflow_state,
        "due_at": item.due_at,
        "last_completed_at": item.last_completed_at,
        "next_due_at": item.next_due_at,
        "evidence_state": item.evidence_state,
        "privacy_classification": item.privacy_classification,
        "employer_visible_summary": item.employer_visible_summary,
        "human_review_required": item.human_review_required,
    }


def _status_for(case: OccupationalHealthCase, requirement: OccupationalHealthRequirement) -> tuple[str, str, str]:
    now = _now()
    next_due = case.next_due_at or case.due_at
    if case.evidence_state == "verified" and next_due is not None:
        if next_due > now + timedelta(days=requirement.due_soon_days):
            return "green", "compliant", "Administrativer Nachweis ist verifiziert; nächste Fälligkeit liegt außerhalb der Vorwarnfrist."
        if next_due >= now:
            return "yellow", "due_soon", "Administrativer Nachweis ist verifiziert; nächste Fälligkeit liegt innerhalb der Vorwarnfrist."
    if next_due is not None and next_due < now:
        return "red", "overdue", "Fälligkeit ist überschritten oder ein aktueller administrativer Nachweis fehlt."
    if case.workflow_state in {"appointment_proposed", "scheduled", "awaiting_evidence", "awaiting_evidence_verification"}:
        return "yellow", case.workflow_state, "Vorgang läuft, ist aber noch nicht vollständig abgeschlossen."
    if case.evidence_state in {"missing", "rejected"}:
        return "red", "needs_action", "Erforderlicher administrativer Nachweis ist nicht vollständig."
    return "yellow", "review_required", "Anwendbarkeit oder Evidenz muss fachlich geprüft werden."


def _queue_notification(
    db: Session,
    case: OccupationalHealthCase,
    recipient_type: str,
    recipient_ref: str | None,
    template_key: str,
) -> None:
    if not recipient_ref:
        return
    exists = db.query(OccupationalHealthNotification).filter(
        OccupationalHealthNotification.tenant_id == case.tenant_id,
        OccupationalHealthNotification.case_id == case.id,
        OccupationalHealthNotification.recipient_type == recipient_type,
        OccupationalHealthNotification.recipient_ref == recipient_ref,
        OccupationalHealthNotification.template_key == template_key,
        OccupationalHealthNotification.status.in_(["queued", "sent"]),
    ).first()
    if exists is None:
        db.add(
            OccupationalHealthNotification(
                tenant_id=case.tenant_id,
                case_id=case.id,
                recipient_type=recipient_type,
                recipient_ref=recipient_ref,
                channel="enterprise_messaging",
                template_key=template_key,
                status="queued",
                scheduled_for=_now(),
                minimum_disclosure=True,
            )
        )


def _find_overlap(
    employee_windows: list[AvailabilityWindow],
    provider_windows: list[AvailabilityWindow],
    duration_minutes: int,
) -> tuple[datetime, datetime] | None:
    duration = timedelta(minutes=duration_minutes)
    for employee in sorted(employee_windows, key=lambda item: item.start):
        for provider in sorted(provider_windows, key=lambda item: item.start):
            start = max(employee.start, provider.start)
            end = min(employee.end, provider.end)
            if employee.end > employee.start and provider.end > provider.start and end - start >= duration:
                return start, start + duration
    return None


@router.post("/requirements", status_code=status.HTTP_201_CREATED)
def create_requirement(data: RequirementCreate, current_user: CurrentUser, db: DBSession):
    require_permission(current_user, "occupational_health.manage")
    tenant_id = _require_tenant(current_user)
    kind = data.requirement_kind.strip().lower()
    if kind not in REQUIREMENT_KINDS:
        raise HTTPException(status_code=422, detail="Unbekannte arbeitsmedizinische Anforderungsart.")
    if db.query(OccupationalHealthRequirement).filter(
        OccupationalHealthRequirement.tenant_id == tenant_id,
        OccupationalHealthRequirement.requirement_key == data.requirement_key.strip(),
    ).first():
        raise HTTPException(status_code=409, detail="Anforderung existiert bereits.")
    item = OccupationalHealthRequirement(
        tenant_id=tenant_id,
        requirement_key=data.requirement_key.strip(),
        title=data.title.strip(),
        requirement_kind=kind,
        trigger_type=data.trigger_type.strip().lower(),
        trigger_ref=data.trigger_ref.strip(),
        legal_basis_ref=data.legal_basis_ref.strip() if data.legal_basis_ref else None,
        source_requirement_id=data.source_requirement_id,
        recurrence_days=data.recurrence_days,
        due_soon_days=data.due_soon_days,
        notes=data.notes.strip() if data.notes else None,
        created_by_id=current_user.id,
    )
    db.add(item)
    db.flush()
    db.add(AuditLog(event=f"occupational_health_requirement_created:{item.id}", user_id=current_user.id, tenant_id=tenant_id))
    db.commit()
    return {"id": item.id, "title": item.title, "requirement_kind": item.requirement_kind, "human_review_required": True}


@router.put("/cases")
def upsert_case(data: CaseUpsert, current_user: CurrentUser, db: DBSession):
    require_permission(current_user, "occupational_health.manage")
    tenant_id = _require_tenant(current_user)
    requirement = _require_requirement(db, tenant_id, data.requirement_id)
    item = db.query(OccupationalHealthCase).filter(
        OccupationalHealthCase.tenant_id == tenant_id,
        OccupationalHealthCase.requirement_id == requirement.id,
        OccupationalHealthCase.employee_ref == data.employee_ref.strip(),
    ).first()
    if item is None:
        item = OccupationalHealthCase(
            tenant_id=tenant_id,
            requirement_id=requirement.id,
            employee_ref=data.employee_ref.strip(),
        )
        db.add(item)
    item.employee_user_id = data.employee_user_id
    item.manager_ref = data.manager_ref.strip() if data.manager_ref else None
    item.provider_ref = data.provider_ref.strip() if data.provider_ref else None
    item.due_at = data.due_at
    item.last_evaluated_at = _now()
    item.human_review_required = True
    db.flush()
    db.add(AuditLog(event=f"occupational_health_case_upserted:{item.id}", user_id=current_user.id, tenant_id=tenant_id))
    db.commit()
    db.refresh(item)
    return _serialize_case(item)


@router.get("/cases")
def list_cases(current_user: CurrentUser, db: DBSession):
    require_permission(current_user, "occupational_health.read")
    tenant_id = _require_tenant(current_user)
    items = db.query(OccupationalHealthCase).filter(OccupationalHealthCase.tenant_id == tenant_id).order_by(OccupationalHealthCase.updated_at.desc()).all()
    return {"cases": [_serialize_case(item) for item in items]}


@router.post("/autopilot/evaluate")
def evaluate(current_user: CurrentUser, db: DBSession):
    require_permission(current_user, "occupational_health.manage")
    tenant_id = _require_tenant(current_user)
    requirements = {
        item.id: item
        for item in db.query(OccupationalHealthRequirement).filter(
            OccupationalHealthRequirement.tenant_id == tenant_id,
            OccupationalHealthRequirement.active.is_(True),
        ).all()
    }
    cases = db.query(OccupationalHealthCase).filter(OccupationalHealthCase.tenant_id == tenant_id).all()
    changed = 0
    for case in cases:
        requirement = requirements.get(case.requirement_id)
        if requirement is None:
            continue
        color, state, summary = _status_for(case, requirement)
        if (case.status, case.workflow_state, case.employer_visible_summary) != (color, state, summary):
            changed += 1
        case.status = color
        case.workflow_state = state
        case.employer_visible_summary = summary
        case.last_evaluated_at = _now()
        if color == "red":
            _queue_notification(db, case, "employee", case.employee_ref, "occupational_health_action_required")
            _queue_notification(db, case, "manager", case.manager_ref, "occupational_health_admin_attention")
        elif color == "yellow":
            _queue_notification(db, case, "employee", case.employee_ref, "occupational_health_due_soon")
    db.add(AuditLog(event=f"occupational_health_autopilot_evaluated:{len(cases)}:{changed}", user_id=current_user.id, tenant_id=tenant_id))
    db.commit()
    return {"evaluated": len(cases), "changed": changed, "privacy": "minimum necessary disclosure; no clinical findings in manager notifications"}


@router.post("/appointments/propose", status_code=status.HTTP_201_CREATED)
def propose_appointment(data: AppointmentProposalRequest, current_user: CurrentUser, db: DBSession):
    require_permission(current_user, "occupational_health.schedule")
    tenant_id = _require_tenant(current_user)
    case = _require_case(db, tenant_id, data.case_id)
    overlap = _find_overlap(data.employee_windows, data.provider_windows, data.duration_minutes)
    if overlap is None:
        raise HTTPException(status_code=409, detail="Kein gemeinsames freies Zeitfenster wurde gefunden.")
    start, end = overlap
    if start < _now() - timedelta(minutes=1):
        raise HTTPException(status_code=422, detail="Vorgeschlagener Termin liegt in der Vergangenheit.")
    item = OccupationalHealthAppointment(
        tenant_id=tenant_id,
        case_id=case.id,
        provider_ref=case.provider_ref,
        proposal_start=start,
        proposal_end=end,
        timezone_name=data.timezone_name,
        employee_calendar_provider=data.employee_calendar_provider,
        provider_calendar_provider=data.provider_calendar_provider,
        consent_or_legal_basis_ref=data.consent_or_legal_basis_ref,
        minimum_disclosure_confirmed=True,
        created_by="autopilot",
    )
    db.add(item)
    case.workflow_state = "appointment_proposed"
    case.status = "yellow"
    _queue_notification(db, case, "employee", case.employee_ref, "occupational_health_appointment_proposed")
    _queue_notification(db, case, "provider", case.provider_ref, "occupational_health_appointment_proposed")
    db.flush()
    db.add(AuditLog(event=f"occupational_health_appointment_proposed:{item.id}", user_id=current_user.id, tenant_id=tenant_id))
    db.commit()
    return {"id": item.id, "start": item.proposal_start, "end": item.proposal_end, "status": item.status, "minimum_disclosure_confirmed": True}


@router.post("/appointments/{appointment_id}/review")
def review_appointment(appointment_id: int, data: AppointmentReview, current_user: CurrentUser, db: DBSession):
    require_permission(current_user, "occupational_health.schedule")
    tenant_id = _require_tenant(current_user)
    item = db.query(OccupationalHealthAppointment).filter(
        OccupationalHealthAppointment.id == appointment_id,
        OccupationalHealthAppointment.tenant_id == tenant_id,
    ).first()
    if item is None:
        raise HTTPException(status_code=404, detail="Termin wurde nicht gefunden.")
    case = _require_case(db, tenant_id, item.case_id)
    item.status = "accepted" if data.accepted else "rejected"
    item.external_event_ref = data.external_event_ref.strip() if data.external_event_ref else None
    item.approved_by_id = current_user.id
    item.approved_at = _now()
    case.workflow_state = "scheduled" if data.accepted else "needs_reschedule"
    case.status = "yellow" if data.accepted else "red"
    db.add(AuditLog(event=f"occupational_health_appointment_reviewed:{item.id}:{item.status}", user_id=current_user.id, tenant_id=tenant_id))
    db.commit()
    return {"id": item.id, "status": item.status, "external_event_ref": item.external_event_ref}


@router.post("/evidence", status_code=status.HTTP_201_CREATED)
def add_evidence(data: EvidenceCreate, current_user: CurrentUser, db: DBSession):
    require_permission(current_user, "occupational_health.clinical")
    tenant_id = _require_tenant(current_user)
    case = _require_case(db, tenant_id, data.case_id)
    clinician_only = True
    employer_access = False
    normalized_type = data.evidence_type.strip().lower()
    if not data.contains_clinical_findings and normalized_type in {"vorsorgebescheinigung", "administrative_completion_certificate"}:
        clinician_only = False
        employer_access = data.employer_access_allowed
    item = OccupationalHealthEvidence(
        tenant_id=tenant_id,
        case_id=case.id,
        evidence_type=normalized_type,
        file_ref=data.file_ref.strip() if data.file_ref else None,
        issued_at=data.issued_at,
        next_due_at=data.next_due_at,
        source=data.source.strip().lower(),
        contains_clinical_findings=data.contains_clinical_findings,
        employer_access_allowed=employer_access,
        clinician_only=clinician_only,
        metadata_json=json.dumps(data.metadata, ensure_ascii=False, sort_keys=True),
    )
    db.add(item)
    case.evidence_state = "pending"
    case.workflow_state = "awaiting_evidence_verification"
    case.status = "yellow"
    db.flush()
    db.add(AuditLog(event=f"occupational_health_evidence_uploaded:{item.id}", user_id=current_user.id, tenant_id=tenant_id))
    db.commit()
    return {
        "id": item.id,
        "contains_clinical_findings": item.contains_clinical_findings,
        "employer_access_allowed": item.employer_access_allowed,
        "clinician_only": item.clinician_only,
        "verified": item.verified,
    }


@router.post("/evidence/{evidence_id}/verify")
def verify_evidence(evidence_id: int, data: EvidenceVerify, current_user: CurrentUser, db: DBSession):
    require_permission(current_user, "occupational_health.clinical")
    tenant_id = _require_tenant(current_user)
    item = db.query(OccupationalHealthEvidence).filter(
        OccupationalHealthEvidence.id == evidence_id,
        OccupationalHealthEvidence.tenant_id == tenant_id,
    ).first()
    if item is None:
        raise HTTPException(status_code=404, detail="Nachweis wurde nicht gefunden.")
    case = _require_case(db, tenant_id, item.case_id)
    requirement = _require_requirement(db, tenant_id, case.requirement_id)
    item.verified = data.verified
    item.verified_by_id = current_user.id
    item.verified_at = _now() if data.verified else None
    if data.verified:
        case.evidence_state = "verified"
        case.last_completed_at = item.issued_at or _now()
        if item.next_due_at:
            case.next_due_at = item.next_due_at
        elif requirement.recurrence_days:
            case.next_due_at = case.last_completed_at + timedelta(days=requirement.recurrence_days)
        color, state, summary = _status_for(case, requirement)
        case.status, case.workflow_state, case.employer_visible_summary = color, state, summary
        case.human_review_required = False
    else:
        case.evidence_state = "rejected"
        case.status = "red"
        case.workflow_state = "evidence_rejected"
        case.human_review_required = True
    db.add(AuditLog(event=f"occupational_health_evidence_verified:{item.id}:{str(data.verified).lower()}", user_id=current_user.id, tenant_id=tenant_id))
    db.commit()
    return {"evidence_id": item.id, "verified": item.verified, "case": _serialize_case(case)}


@router.get("/notifications")
def notifications(current_user: CurrentUser, db: DBSession):
    require_permission(current_user, "occupational_health.manage")
    tenant_id = _require_tenant(current_user)
    items = db.query(OccupationalHealthNotification).filter(
        OccupationalHealthNotification.tenant_id == tenant_id
    ).order_by(OccupationalHealthNotification.scheduled_for.asc()).all()
    return {
        "notifications": [
            {
                "id": item.id,
                "case_id": item.case_id,
                "recipient_type": item.recipient_type,
                "recipient_ref": item.recipient_ref,
                "channel": item.channel,
                "template_key": item.template_key,
                "status": item.status,
                "minimum_disclosure": item.minimum_disclosure,
            }
            for item in items
        ]
    }


@router.get("/privacy-boundary")
def privacy_boundary(current_user: CurrentUser):
    require_permission(current_user, "occupational_health.read")
    return {
        "employer_layer": [
            "Anforderung/Anlass im zulässigen Umfang",
            "Fälligkeit",
            "Termin-/Workflowstatus",
            "Vorsorgebescheinigung bzw. administrativer Nachweisstatus",
            "nächste Fälligkeit, soweit zulässig",
        ],
        "clinical_layer": [
            "medizinische Befunde",
            "Diagnosen",
            "Anamnese",
            "Labor-/Untersuchungsergebnisse",
            "ärztliche Detaildokumentation",
        ],
        "rule": "Klinische Daten bleiben standardmäßig ausschließlich für berechtigte ärztliche Rollen sichtbar; Führungskräfte erhalten nur das administrativ notwendige Minimum.",
    }
