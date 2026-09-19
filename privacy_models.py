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


class ProcessingActivity(Base):
    __tablename__ = "privacy_processing_activities"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "name",
            name="uq_privacy_processing_activity_tenant_name",
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(
        Integer,
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name = Column(String(250), nullable=False, index=True)
    purpose = Column(Text, nullable=False)
    legal_basis = Column(String(250), nullable=False)
    data_subject_categories_json = Column(Text, nullable=False, default="[]")
    personal_data_categories_json = Column(Text, nullable=False, default="[]")
    recipients_json = Column(Text, nullable=False, default="[]")
    third_country_transfers_json = Column(Text, nullable=False, default="[]")
    retention_summary = Column(String(500), nullable=True)
    security_measures_summary = Column(Text, nullable=True)
    owner_role = Column(String(120), nullable=True)
    high_risk = Column(Boolean, nullable=False, default=False, index=True)
    special_categories = Column(Boolean, nullable=False, default=False, index=True)
    status = Column(String(30), nullable=False, default="draft", index=True)
    created_by_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
    )


class PrivacyImpactAssessment(Base):
    __tablename__ = "privacy_impact_assessments"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(
        Integer,
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    processing_activity_id = Column(
        Integer,
        ForeignKey("privacy_processing_activities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    necessity_proportionality = Column(Text, nullable=False)
    risk_summary = Column(Text, nullable=False)
    safeguards_summary = Column(Text, nullable=False)
    residual_risk_level = Column(String(20), nullable=False, default="unknown", index=True)
    dpo_consulted = Column(Boolean, nullable=False, default=False)
    status = Column(String(30), nullable=False, default="draft", index=True)
    created_by_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    approved_by_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    approved_at = Column(DateTime(timezone=True), nullable=True)
    review_due_at = Column(DateTime(timezone=True), nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
    )


class RetentionRule(Base):
    __tablename__ = "privacy_retention_rules"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "data_category",
            "source_system",
            name="uq_privacy_retention_rule_tenant_category_source",
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(
        Integer,
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    data_category = Column(String(200), nullable=False, index=True)
    source_system = Column(String(120), nullable=False, default="safety360", index=True)
    legal_basis = Column(String(300), nullable=True)
    retention_days = Column(Integer, nullable=True)
    trigger_event = Column(String(200), nullable=True)
    disposition = Column(String(40), nullable=False, default="review", index=True)
    legal_hold_supported = Column(Boolean, nullable=False, default=True)
    is_active = Column(Boolean, nullable=False, default=True, index=True)
    created_by_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
    )


class DataSubjectRequest(Base):
    __tablename__ = "privacy_data_subject_requests"

    id = Column(Integer, primary_key=True, index=True)
    request_id = Column(String(36), nullable=False, unique=True, index=True)
    tenant_id = Column(
        Integer,
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    request_type = Column(String(40), nullable=False, index=True)
    subject_reference_hash = Column(String(64), nullable=False, index=True)
    verification_status = Column(String(30), nullable=False, default="pending", index=True)
    status = Column(String(30), nullable=False, default="open", index=True)
    jurisdiction = Column(String(40), nullable=False, default="EU-GDPR", index=True)
    received_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    due_at = Column(DateTime(timezone=True), nullable=False, index=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    created_by_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
    )
