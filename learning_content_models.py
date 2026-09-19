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


class LearningContentPack(Base):
    __tablename__ = "learning_content_packs"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "pack_key",
            "version",
            name="uq_learning_content_pack_tenant_key_version",
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    pack_key = Column(String(200), nullable=False, index=True)
    version = Column(Integer, nullable=False, default=1)
    title = Column(String(500), nullable=False)
    activity_template_id = Column(
        Integer,
        ForeignKey("industry_activity_templates.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    activity_ref = Column(String(320), nullable=True, index=True)
    industry_scheme = Column(String(40), nullable=True, index=True)
    industry_code = Column(String(40), nullable=True, index=True)
    jurisdiction = Column(String(80), nullable=False, default="DE", index=True)
    target_audience = Column(String(120), nullable=False, default="employees", index=True)
    language = Column(String(20), nullable=False, default="de", index=True)
    depth_profile = Column(String(40), nullable=False, default="standard", index=True)
    status = Column(String(40), nullable=False, default="draft", index=True)
    source_refs_json = Column(Text, nullable=False, default="[]")
    requirement_refs_json = Column(Text, nullable=False, default="[]")
    content_hash = Column(String(64), nullable=False, index=True)
    change_reason = Column(String(500), nullable=True)
    review_due_at = Column(DateTime(timezone=True), nullable=True, index=True)
    human_review_required = Column(Boolean, nullable=False, default=True, index=True)
    supersedes_id = Column(
        Integer,
        ForeignKey("learning_content_packs.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    created_by_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    approved_by_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)


class LearningArtifact(Base):
    __tablename__ = "learning_artifacts"
    __table_args__ = (
        UniqueConstraint(
            "content_pack_id",
            "artifact_type",
            "version",
            name="uq_learning_artifact_pack_type_version",
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    content_pack_id = Column(
        Integer,
        ForeignKey("learning_content_packs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    artifact_type = Column(String(80), nullable=False, index=True)
    title = Column(String(500), nullable=False)
    version = Column(Integer, nullable=False, default=1)
    language = Column(String(20), nullable=False, default="de", index=True)
    status = Column(String(40), nullable=False, default="draft", index=True)
    content_json = Column(Text, nullable=False, default="{}")
    source_refs_json = Column(Text, nullable=False, default="[]")
    content_hash = Column(String(64), nullable=False, index=True)
    human_review_required = Column(Boolean, nullable=False, default=True, index=True)
    approved_by_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)
