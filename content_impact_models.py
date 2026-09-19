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


class ContentDependency(Base):
    __tablename__ = "content_dependencies"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "content_pack_id",
            "dependency_kind",
            "dependency_key",
            name="uq_content_dependency_pack_kind_key",
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
    dependency_kind = Column(String(80), nullable=False, index=True)
    dependency_key = Column(String(320), nullable=False, index=True)
    reference_id = Column(Integer, nullable=True, index=True)
    source_ref = Column(String(1000), nullable=True)
    baseline_hash = Column(String(64), nullable=True, index=True)
    baseline_version = Column(String(160), nullable=True)
    last_seen_hash = Column(String(64), nullable=True, index=True)
    last_seen_version = Column(String(160), nullable=True)
    last_checked_at = Column(DateTime(timezone=True), nullable=True, index=True)
    active = Column(Boolean, nullable=False, default=True, index=True)
    human_review_required = Column(Boolean, nullable=False, default=False)
    created_by_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)


class ContentImpactAssessment(Base):
    __tablename__ = "content_impact_assessments"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    content_pack_id = Column(
        Integer,
        ForeignKey("learning_content_packs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    dependency_id = Column(
        Integer,
        ForeignKey("content_dependencies.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    trigger_type = Column(String(80), nullable=False, index=True)
    trigger_ref = Column(String(500), nullable=False, index=True)
    previous_hash = Column(String(64), nullable=True)
    current_hash = Column(String(64), nullable=True, index=True)
    previous_version = Column(String(160), nullable=True)
    current_version = Column(String(160), nullable=True)
    status = Column(String(40), nullable=False, default="pending", index=True)
    priority = Column(String(30), nullable=False, default="normal", index=True)
    rationale = Column(Text, nullable=False)
    evidence_json = Column(Text, nullable=False, default="{}")
    detected_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, index=True)
    human_review_required = Column(Boolean, nullable=False, default=True, index=True)
    resolved_by_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    resolution_note = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)
