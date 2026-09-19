import calendar
import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from typing import Annotated
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from auth import get_current_user
from database import get_db
from models import AuditLog, User
from permissions import require_permission
from privacy_models import (
    DataSubjectRequest,
    PrivacyImpactAssessment,
    ProcessingActivity,
    RetentionRule,
)

router = APIRouter()
DBSession = Annotated[Session, Depends(get_db)]
CurrentUser = Annotated[User, Depends(get_current_user)]

ENVIRONMENT = os.getenv("SAFETY360_ENV", "development").strip().lower()
PRIVACY_REFERENCE_SALT = os.getenv("PRIVACY_REFERENCE_SALT", "").strip()

REQUEST_TYPES = {
    "access",
    "rectification",
    "erasure",
    "restriction",
    "portability",
    "objection",
}
REQUEST_STATUSES = {"open", "in_review", "waiting_for_subject", "completed", "rejected"}
VERIFICATION_STATUSES = {"pending", "verified", "failed"}
DPIA_STATUSES = {"draft", "in_review", "approved", "rejected"}
RISK_LEVELS = {"unknown", "low", "medium", "high", "very_high"}
PROCESSING_STATUSES = {"draft", "active", "retired"}
RETENTION_DISPOSITIONS = {"review", "delete", "anonymize", "archive"}


class ProcessingActivityCreate(BaseModel):
    name: str = Field(min_length=2, max_length=250)
    purpose: str = Field(min_length=2, max_length=10000)
    legal_basis: str = Field(min_length=2, max_length=250)
    data_subject_categories: list[str] = Field(default_factory=list, max_length=100)
    personal_data_categories: list[str] = Field(default_factory=list, max_length=200)
    recipients: list[str] = Field(default_factory=list, max_length=100)
    third_country_transfers: list[str] = Field(default_factory=list, max_length=100)
    retention_summary: str | None = Field(default=None, max_length=500)
    security_measures_summary: str | None = Field(default=None, max_length=10000)
    owner_role: str | None = Field(default=None, max_length=120)
    high_risk: bool = False
    special_categories: bool = False
    status: str = Field(default="draft", min_length=2, max_length=30)


class ProcessingActivityResponse(BaseModel):
    id: int
    tenant_id: int
    name: str
    purpose: str
    legal_basis: str
    data_subject_categories: list[str]
    personal_data_categories: list[str]
    recipients: list[str]
    third_country_transfers: list[str]
    retention_summary: str | None = None
    security_measures_summary: str | None = None
    owner_role: str | None = None
    high_risk: bool
    special_categories: bool
    status: str
    created_by_id: int
    created_at: datetime
    updated_at: datetime


class ProcessingActivityListResponse(BaseModel):
    activities: list[ProcessingActivityResponse]


class PrivacyImpactAssessmentCreate(BaseModel):
    processing_activity_id: int
    necessity_proportionality: str = Field(min_length=2, max_length=20000)
    risk_summary: str = Field(min_length=2, max_length=20000)
    safeguards_summary: str = Field(min_length=2, max_length=20000)
    residual_risk_level: str = Field(default="unknown", min_length=2, max_length=20)
    dpo_consulted: bool = False
    status: str = Field(default="draft", min_length=2, max_length=30)
    review_due_at: datetime | None = None


class PrivacyImpactAssessmentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    tenant_id: int
    processing_activity_id: int
    necessity_proportionality: str
    risk_summary: str
    safeguards_summary: str
    residual_risk_level: str
    dpo_consulted: bool
    status: str
    created_by_id: int
    approved_by_id: int | None = None
    approved_at: datetime | None = None
    review_due_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class PrivacyImpactAssessmentListResponse(BaseModel):
    assessments: list[PrivacyImpactAssessmentResponse]


class RetentionRuleCreate(BaseModel):
    data_category: str = Field(min_length=2, max_length=200)
    source_system: str = Field(default="safety360", min_length=2, max_length=120)
    legal_basis: str | None = Field(default=None, max_length=300)
    retention_days: int | None = Field(default=None, ge=1, le=36500)
    trigger_event: str | None = Field(default=None, max_length=200)
    disposition: str = Field(default="review", min_length=2, max_length=40)
    legal_hold_supported: bool = True
    is_active: bool = True


class RetentionRuleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    tenant_id: int
    data_category: str
    source_system: str
    legal_basis: str | None = None
    retention_days: int | None = None
    trigger_event: str | None = None
    disposition: str
    legal_hold_supported: bool
    is_active: bool
    created_by_id: int
    created_at: datetime
    updated_at: datetime


class RetentionRuleListResponse(BaseModel):
    rules: list[RetentionRuleResponse]


class DataSubjectRequestCreate(BaseModel):
    request_type: str = Field(min_length=2, max_length=40)
    subject_reference: str = Field(min_length=3, max_length=500)
    jurisdiction: str = Field(default="EU-GDPR", min_length=2, max_length=40)


class DataSubjectRequestUpdate(BaseModel):
    verification_status: str | None = Field(default=None, min_length=2, max_length=30)
    status: str | None = Field(default=None, min_length=2, max_length=30)


class DataSubjectRequestResponse(BaseModel):
    id: int
    request_id: str
    tenant_id: int
    request_type: str
    verification_status: str
    status: str
    jurisdiction: str
    received_at: datetime
    due_at: datetime
    completed_at: datetime | None = None
    created_by_id: int
    created_at: datetime
    updated_at: datetime


class DataSubjectRequestListResponse(BaseModel):
    requests: list[DataSubjectRequestResponse]


class PrivacyOverviewResponse(BaseModel):
    processing_activities: int
    active_processing_activities: int
    high_risk_processing_activities: int
    special_category_processing_activities: int
    dpias: int
    open_data_subject_requests: int
    overdue_data_subject_requests: int
    retention_rules: int
    privacy_by_design: bool
    raw_subject_identifiers_stored_in_dsar: bool


def _require_tenant(current_user: User) -> int:
    if current_user.tenant_id is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Für Datenschutzfunktionen muss der Benutzer einem Mandanten zugeordnet sein.",
        )
    return current_user.tenant_id


def _json_list(raw: str) -> list[str]:
    try:
        value = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return []
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def _processing_response(activity: ProcessingActivity) -> ProcessingActivityResponse:
    return ProcessingActivityResponse(
        id=activity.id,
        tenant_id=activity.tenant_id,
        name=activity.name,
        purpose=activity.purpose,
        legal_basis=activity.legal_basis,
        data_subject_categories=_json_list(activity.data_subject_categories_json),
        personal_data_categories=_json_list(activity.personal_data_categories_json),
        recipients=_json_list(activity.recipients_json),
        third_country_transfers=_json_list(activity.third_country_transfers_json),
        retention_summary=activity.retention_summary,
        security_measures_summary=activity.security_measures_summary,
        owner_role=activity.owner_role,
        high_risk=activity.high_risk,
        special_categories=activity.special_categories,
        status=activity.status,
        created_by_id=activity.created_by_id,
        created_at=activity.created_at,
        updated_at=activity.updated_at,
    )


def _request_response(request: DataSubjectRequest) -> DataSubjectRequestResponse:
    return DataSubjectRequestResponse(
        id=request.id,
        request_id=request.request_id,
        tenant_id=request.tenant_id,
        request_type=request.request_type,
        verification_status=request.verification_status,
        status=request.status,
        jurisdiction=request.jurisdiction,
        received_at=request.received_at,
        due_at=request.due_at,
        completed_at=request.completed_at,
        created_by_id=request.created_by_id,
        created_at=request.created_at,
        updated_at=request.updated_at,
    )


def _privacy_salt() -> bytes:
    configured = PRIVACY_REFERENCE_SALT
    if not configured and ENVIRONMENT != "production":
        configured = os.getenv("SAFETY360_SECRET_KEY", "development-only-privacy-reference-salt")
    if not configured:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="PRIVACY_REFERENCE_SALT ist für Datenschutz-Referenzen nicht konfiguriert.",
        )
    return configured.encode("utf-8")


def _hash_subject_reference(value: str) -> str:
    normalized = value.strip().casefold().encode("utf-8")
    return hmac.new(_privacy_salt(), normalized, hashlib.sha256).hexdigest()


def _add_one_calendar_month(value: datetime) -> datetime:
    year = value.year + (1 if value.month == 12 else 0)
    month = 1 if value.month == 12 else value.month + 1
    day = min(value.day, calendar.monthrange(year, month)[1])
    return value.replace(year=year, month=month, day=day)


@router.get("/overview", response_model=PrivacyOverviewResponse)
def privacy_overview(current_user: CurrentUser, db: DBSession) -> PrivacyOverviewResponse:
    require_permission(current_user, "privacy.read")
    tenant_id = _require_tenant(current_user)
    now = datetime.now(timezone.utc)

    processing_query = db.query(ProcessingActivity).filter(ProcessingActivity.tenant_id == tenant_id)
    dsar_query = db.query(DataSubjectRequest).filter(DataSubjectRequest.tenant_id == tenant_id)

    return PrivacyOverviewResponse(
        processing_activities=processing_query.count(),
        active_processing_activities=processing_query.filter(ProcessingActivity.status == "active").count(),
        high_risk_processing_activities=processing_query.filter(ProcessingActivity.high_risk.is_(True)).count(),
        special_category_processing_activities=processing_query.filter(
            ProcessingActivity.special_categories.is_(True)
        ).count(),
        dpias=db.query(PrivacyImpactAssessment).filter(PrivacyImpactAssessment.tenant_id == tenant_id).count(),
        open_data_subject_requests=dsar_query.filter(
            DataSubjectRequest.status.notin_(["completed", "rejected"])
        ).count(),
        overdue_data_subject_requests=dsar_query.filter(
            DataSubjectRequest.status.notin_(["completed", "rejected"]),
            DataSubjectRequest.due_at < now,
        ).count(),
        retention_rules=db.query(RetentionRule).filter(RetentionRule.tenant_id == tenant_id).count(),
        privacy_by_design=True,
        raw_subject_identifiers_stored_in_dsar=False,
    )


@router.post(
    "/processing-activities",
    response_model=ProcessingActivityResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_processing_activity(
    payload: ProcessingActivityCreate,
    current_user: CurrentUser,
    db: DBSession,
) -> ProcessingActivityResponse:
    require_permission(current_user, "privacy.manage")
    tenant_id = _require_tenant(current_user)
    normalized_status = payload.status.strip().lower()
    if normalized_status not in PROCESSING_STATUSES:
        raise HTTPException(status_code=422, detail="Ungültiger Status für Verarbeitungstätigkeit.")

    existing = db.query(ProcessingActivity).filter(
        ProcessingActivity.tenant_id == tenant_id,
        ProcessingActivity.name == payload.name.strip(),
    ).first()
    if existing is not None:
        raise HTTPException(status_code=409, detail="Verarbeitungstätigkeit existiert bereits.")

    activity = ProcessingActivity(
        tenant_id=tenant_id,
        name=payload.name.strip(),
        purpose=payload.purpose.strip(),
        legal_basis=payload.legal_basis.strip(),
        data_subject_categories_json=json.dumps(payload.data_subject_categories, ensure_ascii=False),
        personal_data_categories_json=json.dumps(payload.personal_data_categories, ensure_ascii=False),
        recipients_json=json.dumps(payload.recipients, ensure_ascii=False),
        third_country_transfers_json=json.dumps(payload.third_country_transfers, ensure_ascii=False),
        retention_summary=payload.retention_summary,
        security_measures_summary=payload.security_measures_summary,
        owner_role=payload.owner_role,
        high_risk=payload.high_risk,
        special_categories=payload.special_categories,
        status=normalized_status,
        created_by_id=current_user.id,
    )
    db.add(activity)
    db.flush()
    db.add(
        AuditLog(
            event=f"privacy_processing_activity_created:{activity.id}",
            user_id=current_user.id,
            tenant_id=tenant_id,
        )
    )
    db.commit()
    db.refresh(activity)
    return _processing_response(activity)


@router.get("/processing-activities", response_model=ProcessingActivityListResponse)
def list_processing_activities(
    current_user: CurrentUser,
    db: DBSession,
) -> ProcessingActivityListResponse:
    require_permission(current_user, "privacy.read")
    tenant_id = _require_tenant(current_user)
    activities = db.query(ProcessingActivity).filter(
        ProcessingActivity.tenant_id == tenant_id
    ).order_by(ProcessingActivity.name.asc()).all()
    return ProcessingActivityListResponse(activities=[_processing_response(item) for item in activities])


@router.post(
    "/dpias",
    response_model=PrivacyImpactAssessmentResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_dpia(
    payload: PrivacyImpactAssessmentCreate,
    current_user: CurrentUser,
    db: DBSession,
) -> PrivacyImpactAssessmentResponse:
    require_permission(current_user, "privacy.manage")
    tenant_id = _require_tenant(current_user)
    risk_level = payload.residual_risk_level.strip().lower()
    dpia_status = payload.status.strip().lower()
    if risk_level not in RISK_LEVELS:
        raise HTTPException(status_code=422, detail="Ungültige Restrisiko-Einstufung.")
    if dpia_status not in DPIA_STATUSES:
        raise HTTPException(status_code=422, detail="Ungültiger DSFA-Status.")

    activity = db.query(ProcessingActivity).filter(
        ProcessingActivity.id == payload.processing_activity_id,
        ProcessingActivity.tenant_id == tenant_id,
    ).first()
    if activity is None:
        raise HTTPException(status_code=404, detail="Verarbeitungstätigkeit nicht gefunden.")

    assessment = PrivacyImpactAssessment(
        tenant_id=tenant_id,
        processing_activity_id=activity.id,
        necessity_proportionality=payload.necessity_proportionality.strip(),
        risk_summary=payload.risk_summary.strip(),
        safeguards_summary=payload.safeguards_summary.strip(),
        residual_risk_level=risk_level,
        dpo_consulted=payload.dpo_consulted,
        status=dpia_status,
        review_due_at=payload.review_due_at,
        created_by_id=current_user.id,
    )
    db.add(assessment)
    db.flush()
    db.add(
        AuditLog(
            event=f"privacy_dpia_created:{assessment.id}",
            user_id=current_user.id,
            tenant_id=tenant_id,
        )
    )
    db.commit()
    db.refresh(assessment)
    return PrivacyImpactAssessmentResponse.model_validate(assessment)


@router.get("/dpias", response_model=PrivacyImpactAssessmentListResponse)
def list_dpias(
    current_user: CurrentUser,
    db: DBSession,
) -> PrivacyImpactAssessmentListResponse:
    require_permission(current_user, "privacy.read")
    tenant_id = _require_tenant(current_user)
    assessments = db.query(PrivacyImpactAssessment).filter(
        PrivacyImpactAssessment.tenant_id == tenant_id
    ).order_by(PrivacyImpactAssessment.created_at.desc()).all()
    return PrivacyImpactAssessmentListResponse(
        assessments=[PrivacyImpactAssessmentResponse.model_validate(item) for item in assessments]
    )


@router.post(
    "/retention-rules",
    response_model=RetentionRuleResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_retention_rule(
    payload: RetentionRuleCreate,
    current_user: CurrentUser,
    db: DBSession,
) -> RetentionRuleResponse:
    require_permission(current_user, "privacy.manage")
    tenant_id = _require_tenant(current_user)
    disposition = payload.disposition.strip().lower()
    if disposition not in RETENTION_DISPOSITIONS:
        raise HTTPException(status_code=422, detail="Ungültige Retention-Aktion.")

    existing = db.query(RetentionRule).filter(
        RetentionRule.tenant_id == tenant_id,
        RetentionRule.data_category == payload.data_category.strip(),
        RetentionRule.source_system == payload.source_system.strip(),
    ).first()
    if existing is not None:
        raise HTTPException(status_code=409, detail="Retention-Regel existiert bereits.")

    rule = RetentionRule(
        tenant_id=tenant_id,
        data_category=payload.data_category.strip(),
        source_system=payload.source_system.strip(),
        legal_basis=payload.legal_basis,
        retention_days=payload.retention_days,
        trigger_event=payload.trigger_event,
        disposition=disposition,
        legal_hold_supported=payload.legal_hold_supported,
        is_active=payload.is_active,
        created_by_id=current_user.id,
    )
    db.add(rule)
    db.flush()
    db.add(
        AuditLog(
            event=f"privacy_retention_rule_created:{rule.id}",
            user_id=current_user.id,
            tenant_id=tenant_id,
        )
    )
    db.commit()
    db.refresh(rule)
    return RetentionRuleResponse.model_validate(rule)


@router.get("/retention-rules", response_model=RetentionRuleListResponse)
def list_retention_rules(
    current_user: CurrentUser,
    db: DBSession,
) -> RetentionRuleListResponse:
    require_permission(current_user, "privacy.read")
    tenant_id = _require_tenant(current_user)
    rules = db.query(RetentionRule).filter(
        RetentionRule.tenant_id == tenant_id
    ).order_by(RetentionRule.data_category.asc()).all()
    return RetentionRuleListResponse(rules=[RetentionRuleResponse.model_validate(item) for item in rules])


@router.post(
    "/data-subject-requests",
    response_model=DataSubjectRequestResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_data_subject_request(
    payload: DataSubjectRequestCreate,
    current_user: CurrentUser,
    db: DBSession,
) -> DataSubjectRequestResponse:
    require_permission(current_user, "privacy.dsar.manage")
    tenant_id = _require_tenant(current_user)
    request_type = payload.request_type.strip().lower()
    if request_type not in REQUEST_TYPES:
        raise HTTPException(status_code=422, detail="Ungültiger Betroffenenrechts-Anfragetyp.")

    received_at = datetime.now(timezone.utc)
    request = DataSubjectRequest(
        request_id=str(uuid4()),
        tenant_id=tenant_id,
        request_type=request_type,
        subject_reference_hash=_hash_subject_reference(payload.subject_reference),
        verification_status="pending",
        status="open",
        jurisdiction=payload.jurisdiction.strip(),
        received_at=received_at,
        due_at=_add_one_calendar_month(received_at),
        created_by_id=current_user.id,
    )
    db.add(request)
    db.flush()
    db.add(
        AuditLog(
            event=f"privacy_dsar_created:{request.request_id}:{request_type}",
            user_id=current_user.id,
            tenant_id=tenant_id,
        )
    )
    db.commit()
    db.refresh(request)
    return _request_response(request)


@router.get("/data-subject-requests", response_model=DataSubjectRequestListResponse)
def list_data_subject_requests(
    current_user: CurrentUser,
    db: DBSession,
) -> DataSubjectRequestListResponse:
    require_permission(current_user, "privacy.read")
    tenant_id = _require_tenant(current_user)
    requests = db.query(DataSubjectRequest).filter(
        DataSubjectRequest.tenant_id == tenant_id
    ).order_by(DataSubjectRequest.received_at.desc()).all()
    return DataSubjectRequestListResponse(requests=[_request_response(item) for item in requests])


@router.patch(
    "/data-subject-requests/{request_id}",
    response_model=DataSubjectRequestResponse,
)
def update_data_subject_request(
    request_id: str,
    payload: DataSubjectRequestUpdate,
    current_user: CurrentUser,
    db: DBSession,
) -> DataSubjectRequestResponse:
    require_permission(current_user, "privacy.dsar.manage")
    tenant_id = _require_tenant(current_user)
    request = db.query(DataSubjectRequest).filter(
        DataSubjectRequest.request_id == request_id,
        DataSubjectRequest.tenant_id == tenant_id,
    ).first()
    if request is None:
        raise HTTPException(status_code=404, detail="Betroffenenrechts-Anfrage nicht gefunden.")

    if payload.verification_status is not None:
        verification_status = payload.verification_status.strip().lower()
        if verification_status not in VERIFICATION_STATUSES:
            raise HTTPException(status_code=422, detail="Ungültiger Verifizierungsstatus.")
        request.verification_status = verification_status

    if payload.status is not None:
        request_status = payload.status.strip().lower()
        if request_status not in REQUEST_STATUSES:
            raise HTTPException(status_code=422, detail="Ungültiger Anfragestatus.")
        if request_status == "completed" and request.verification_status != "verified":
            raise HTTPException(
                status_code=409,
                detail="Eine Anfrage darf erst nach erfolgreicher Identitätsprüfung abgeschlossen werden.",
            )
        request.status = request_status
        request.completed_at = datetime.now(timezone.utc) if request_status == "completed" else None

    db.add(
        AuditLog(
            event=f"privacy_dsar_updated:{request.request_id}:{request.status}",
            user_id=current_user.id,
            tenant_id=tenant_id,
        )
    )
    db.commit()
    db.refresh(request)
    return _request_response(request)
