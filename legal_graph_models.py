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


class ComplianceSubject(Base):
    __tablename__ = "compliance_subjects"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "subject_type",
            "subject_key",
            name="uq_compliance_subject_tenant_type_key",
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(
        Integer,
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    subject_type = Column(String(60), nullable=False, index=True)
    subject_key = Column(String(240), nullable=False, index=True)
    title = Column(String(500), nullable=False)
    jurisdiction = Column(String(80), nullable=True, index=True)
    parent_ref = Column(String(320), nullable=True, index=True)
    metadata_json = Column(Text, nullable=False, default="{}")
    active = Column(Boolean, nullable=False, default=True, index=True)
    created_by_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)


class RequirementRelation(Base):
    __tablename__ = "requirement_relations"
    __table_args__ = (
        UniqueConstraint(
            "from_requirement_id",
            "to_requirement_id",
            "relation_type",
            name="uq_requirement_relation_edge",
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    from_requirement_id = Column(
        Integer,
        ForeignKey("regulatory_requirements.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    to_requirement_id = Column(
        Integer,
        ForeignKey("regulatory_requirements.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    relation_type = Column(String(60), nullable=False, index=True)
    rationale = Column(Text, nullable=True)
    source_reference = Column(String(1000), nullable=True)
    human_review_required = Column(Boolean, nullable=False, default=True)
    verified_at = Column(DateTime(timezone=True), nullable=True)
    verified_by_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)


class ApplicabilityAssessment(Base):
    __tablename__ = "applicability_assessments"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "requirement_id",
            "subject_id",
            name="uq_applicability_tenant_requirement_subject",
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(
        Integer,
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    requirement_id = Column(
        Integer,
        ForeignKey("regulatory_requirements.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    subject_id = Column(
        Integer,
        ForeignKey("compliance_subjects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    applicability_status = Column(String(40), nullable=False, default="review_required", index=True)
    origin = Column(String(40), nullable=False, default="manual", index=True)
    confidence = Column(Integer, nullable=False, default=0)
    priority = Column(String(30), nullable=False, default="normal", index=True)
    rationale = Column(Text, nullable=True)
    evidence_json = Column(Text, nullable=False, default="{}")
    missing_evidence_json = Column(Text, nullable=False, default="[]")
    human_review_required = Column(Boolean, nullable=False, default=True, index=True)
    reviewed_by_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    reviewed_at = Column(DateTime(timezone=True), nullable=True)
    last_evaluated_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)


class RegulatoryImpactAction(Base):
    __tablename__ = "regulatory_impact_actions"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "requirement_id",
            "subject_id",
            "action_type",
            "target_ref",
            name="uq_regulatory_impact_action",
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(
        Integer,
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    requirement_id = Column(
        Integer,
        ForeignKey("regulatory_requirements.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    subject_id = Column(
        Integer,
        ForeignKey("compliance_subjects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    action_type = Column(String(80), nullable=False, index=True)
    target_ref = Column(String(320), nullable=False, index=True)
    status = Column(String(40), nullable=False, default="proposed", index=True)
    priority = Column(String(30), nullable=False, default="normal", index=True)
    rationale = Column(Text, nullable=True)
    evidence_json = Column(Text, nullable=False, default="{}")
    human_review_required = Column(Boolean, nullable=False, default=True)
    approved_by_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    approved_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)
