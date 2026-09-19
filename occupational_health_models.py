from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)

from database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class OccupationalHealthRequirement(Base):
    __tablename__ = "occupational_health_requirements"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "requirement_key",
            name="uq_occupational_health_requirement_tenant_key",
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    requirement_key = Column(String(240), nullable=False, index=True)
    title = Column(String(500), nullable=False)
    requirement_kind = Column(String(60), nullable=False, index=True)
    trigger_type = Column(String(80), nullable=False, index=True)
    trigger_ref = Column(String(320), nullable=False, index=True)
    legal_basis_ref = Column(String(500), nullable=True)
    source_requirement_id = Column(
        Integer,
        ForeignKey("regulatory_requirements.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    recurrence_days = Column(Integer, nullable=True)
    due_soon_days = Column(Integer, nullable=False, default=30)
    active = Column(Boolean, nullable=False, default=True, index=True)
    human_review_required = Column(Boolean, nullable=False, default=True)
    notes = Column(Text, nullable=True)
    created_by_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)


class OccupationalHealthCase(Base):
    __tablename__ = "occupational_health_cases"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "requirement_id",
            "employee_ref",
            name="uq_occupational_health_case_employee_requirement",
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    requirement_id = Column(
        Integer,
        ForeignKey("occupational_health_requirements.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    employee_ref = Column(String(320), nullable=False, index=True)
    employee_user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    manager_ref = Column(String(320), nullable=True, index=True)
    provider_ref = Column(String(320), nullable=True, index=True)
    status = Column(String(40), nullable=False, default="red", index=True)
    workflow_state = Column(String(60), nullable=False, default="needs_review", index=True)
    due_at = Column(DateTime(timezone=True), nullable=True, index=True)
    last_completed_at = Column(DateTime(timezone=True), nullable=True)
    next_due_at = Column(DateTime(timezone=True), nullable=True, index=True)
    evidence_state = Column(String(40), nullable=False, default="missing", index=True)
    privacy_classification = Column(String(60), nullable=False, default="special_category_health", index=True)
    employer_visible_summary = Column(String(500), nullable=True)
    last_evaluated_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    human_review_required = Column(Boolean, nullable=False, default=True, index=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)


class OccupationalHealthAppointment(Base):
    __tablename__ = "occupational_health_appointments"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    case_id = Column(Integer, ForeignKey("occupational_health_cases.id", ondelete="CASCADE"), nullable=False, index=True)
    provider_ref = Column(String(320), nullable=True, index=True)
    proposal_start = Column(DateTime(timezone=True), nullable=False, index=True)
    proposal_end = Column(DateTime(timezone=True), nullable=False, index=True)
    timezone_name = Column(String(80), nullable=False, default="Europe/Berlin")
    status = Column(String(40), nullable=False, default="proposed", index=True)
    employee_calendar_provider = Column(String(60), nullable=True)
    provider_calendar_provider = Column(String(60), nullable=True)
    external_event_ref = Column(String(500), nullable=True, index=True)
    consent_or_legal_basis_ref = Column(String(500), nullable=True)
    minimum_disclosure_confirmed = Column(Boolean, nullable=False, default=False)
    created_by = Column(String(40), nullable=False, default="autopilot", index=True)
    approved_by_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)


class OccupationalHealthEvidence(Base):
    __tablename__ = "occupational_health_evidence"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    case_id = Column(Integer, ForeignKey("occupational_health_cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_type = Column(String(80), nullable=False, index=True)
    file_ref = Column(String(500), nullable=True)
    issued_at = Column(DateTime(timezone=True), nullable=True)
    next_due_at = Column(DateTime(timezone=True), nullable=True)
    source = Column(String(80), nullable=False, default="provider_upload", index=True)
    contains_clinical_findings = Column(Boolean, nullable=False, default=False, index=True)
    employer_access_allowed = Column(Boolean, nullable=False, default=False, index=True)
    clinician_only = Column(Boolean, nullable=False, default=True, index=True)
    verified = Column(Boolean, nullable=False, default=False, index=True)
    verified_by_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    verified_at = Column(DateTime(timezone=True), nullable=True)
    metadata_json = Column(Text, nullable=False, default="{}")
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)


class OccupationalHealthNotification(Base):
    __tablename__ = "occupational_health_notifications"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    case_id = Column(Integer, ForeignKey("occupational_health_cases.id", ondelete="CASCADE"), nullable=False, index=True)
    recipient_type = Column(String(40), nullable=False, index=True)
    recipient_ref = Column(String(320), nullable=False, index=True)
    channel = Column(String(40), nullable=False, index=True)
    template_key = Column(String(160), nullable=False)
    status = Column(String(40), nullable=False, default="queued", index=True)
    scheduled_for = Column(DateTime(timezone=True), nullable=False, index=True)
    sent_at = Column(DateTime(timezone=True), nullable=True)
    minimum_disclosure = Column(Boolean, nullable=False, default=True)
    error_code = Column(String(120), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)
