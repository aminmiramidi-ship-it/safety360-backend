from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint

from database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class IndustryClassification(Base):
    __tablename__ = "industry_classifications"
    __table_args__ = (
        UniqueConstraint(
            "scheme",
            "code",
            "version",
            name="uq_industry_classification_scheme_code_version",
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    scheme = Column(String(40), nullable=False, index=True)
    version = Column(String(40), nullable=False, index=True)
    code = Column(String(40), nullable=False, index=True)
    title = Column(String(500), nullable=False)
    parent_code = Column(String(40), nullable=True, index=True)
    level = Column(String(40), nullable=False, index=True)
    jurisdiction = Column(String(80), nullable=False, index=True)
    source_url = Column(String(1000), nullable=False)
    source_hash = Column(String(64), nullable=True, index=True)
    valid_from = Column(DateTime(timezone=True), nullable=True)
    valid_to = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, nullable=False, default=True, index=True)
    review_status = Column(String(40), nullable=False, default="verified_source", index=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)


class TenantIndustryProfile(Base):
    __tablename__ = "tenant_industry_profiles"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "scheme",
            "code",
            name="uq_tenant_industry_profile_tenant_scheme_code",
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    scheme = Column(String(40), nullable=False, index=True)
    code = Column(String(40), nullable=False, index=True)
    is_primary = Column(Boolean, nullable=False, default=False, index=True)
    verification_status = Column(String(40), nullable=False, default="unverified", index=True)
    verified_by_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    verified_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)


class IndustryActivityTemplate(Base):
    __tablename__ = "industry_activity_templates"
    __table_args__ = (
        UniqueConstraint(
            "scheme",
            "industry_code",
            "template_key",
            "version",
            name="uq_industry_activity_template_key_version",
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    scheme = Column(String(40), nullable=False, index=True)
    industry_code = Column(String(40), nullable=False, index=True)
    template_key = Column(String(160), nullable=False, index=True)
    version = Column(Integer, nullable=False, default=1)
    title = Column(String(500), nullable=False)
    activity_description = Column(Text, nullable=False)
    process_description = Column(Text, nullable=True)
    process_steps_json = Column(Text, nullable=False, default="[]")
    equipment_json = Column(Text, nullable=False, default="[]")
    substances_json = Column(Text, nullable=False, default="[]")
    worker_groups_json = Column(Text, nullable=False, default="[]")
    hazard_factors_json = Column(Text, nullable=False, default="[]")
    controls_json = Column(Text, nullable=False, default="[]")
    training_topics_json = Column(Text, nullable=False, default="[]")
    operating_instruction_topics_json = Column(Text, nullable=False, default="[]")
    source_refs_json = Column(Text, nullable=False, default="[]")
    jurisdiction = Column(String(80), nullable=False, default="DE", index=True)
    review_status = Column(String(40), nullable=False, default="draft", index=True)
    human_review_required = Column(Boolean, nullable=False, default=True)
    content_hash = Column(String(64), nullable=False, index=True)
    valid_from = Column(DateTime(timezone=True), nullable=True)
    valid_to = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)


class IndustryArtifactTemplate(Base):
    __tablename__ = "industry_artifact_templates"
    __table_args__ = (
        UniqueConstraint(
            "activity_template_id",
            "artifact_type",
            "version",
            name="uq_industry_artifact_template_type_version",
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    activity_template_id = Column(Integer, ForeignKey("industry_activity_templates.id", ondelete="CASCADE"), nullable=False, index=True)
    artifact_type = Column(String(80), nullable=False, index=True)
    version = Column(Integer, nullable=False, default=1)
    title = Column(String(500), nullable=False)
    content_json = Column(Text, nullable=False, default="{}")
    source_refs_json = Column(Text, nullable=False, default="[]")
    review_status = Column(String(40), nullable=False, default="draft", index=True)
    human_review_required = Column(Boolean, nullable=False, default=True)
    content_hash = Column(String(64), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)


class IndustryKnowledgeChange(Base):
    __tablename__ = "industry_knowledge_changes"

    id = Column(Integer, primary_key=True, index=True)
    object_type = Column(String(80), nullable=False, index=True)
    object_key = Column(String(250), nullable=False, index=True)
    scheme = Column(String(40), nullable=True, index=True)
    industry_code = Column(String(40), nullable=True, index=True)
    change_type = Column(String(60), nullable=False, index=True)
    previous_hash = Column(String(64), nullable=True)
    new_hash = Column(String(64), nullable=False)
    source_refs_json = Column(Text, nullable=False, default="[]")
    impact_json = Column(Text, nullable=False, default="{}")
    review_status = Column(String(40), nullable=False, default="pending", index=True)
    human_review_required = Column(Boolean, nullable=False, default=True)
    detected_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, index=True)
    reviewed_by_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    reviewed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
