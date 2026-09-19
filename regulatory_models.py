from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint

from database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class RegulatorySource(Base):
    __tablename__ = "regulatory_sources"
    __table_args__ = (
        UniqueConstraint("authority", "source_key", name="uq_regulatory_source_authority_key"),
    )

    id = Column(Integer, primary_key=True, index=True)
    authority = Column(String(160), nullable=False, index=True)
    source_key = Column(String(160), nullable=False, index=True)
    name = Column(String(250), nullable=False)
    jurisdiction = Column(String(80), nullable=False, index=True)
    source_type = Column(String(80), nullable=False, index=True)
    base_url = Column(String(1000), nullable=False)
    is_primary = Column(Boolean, nullable=False, default=True, index=True)
    enabled = Column(Boolean, nullable=False, default=True, index=True)
    terms_note = Column(String(1000), nullable=True)
    last_checked_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)


class RegulatoryRequirement(Base):
    __tablename__ = "regulatory_requirements"
    __table_args__ = (
        UniqueConstraint("source_id", "external_key", name="uq_regulatory_requirement_source_key"),
    )

    id = Column(Integer, primary_key=True, index=True)
    source_id = Column(
        Integer,
        ForeignKey("regulatory_sources.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    external_key = Column(String(240), nullable=False, index=True)
    title = Column(String(500), nullable=False)
    citation = Column(String(500), nullable=True)
    summary = Column(Text, nullable=True)
    jurisdiction = Column(String(80), nullable=False, index=True)
    topic = Column(String(120), nullable=False, index=True)
    management_system = Column(String(120), nullable=True, index=True)
    status = Column(String(40), nullable=False, default="current", index=True)
    source_version = Column(String(160), nullable=True)
    effective_from = Column(DateTime(timezone=True), nullable=True)
    effective_to = Column(DateTime(timezone=True), nullable=True)
    content_hash = Column(String(64), nullable=False, index=True)
    applicability_json = Column(Text, nullable=False, default="{}")
    human_review_required = Column(Boolean, nullable=False, default=True)
    verified_at = Column(DateTime(timezone=True), nullable=True)
    verified_by_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    last_seen_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)


class RegulatoryChange(Base):
    __tablename__ = "regulatory_changes"

    id = Column(Integer, primary_key=True, index=True)
    requirement_id = Column(
        Integer,
        ForeignKey("regulatory_requirements.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    change_type = Column(String(60), nullable=False, index=True)
    previous_hash = Column(String(64), nullable=True)
    new_hash = Column(String(64), nullable=False)
    source_version = Column(String(160), nullable=True)
    detected_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, index=True)
    review_status = Column(String(40), nullable=False, default="pending", index=True)
    impact_json = Column(Text, nullable=False, default="{}")
    human_review_required = Column(Boolean, nullable=False, default=True)
    reviewed_by_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    reviewed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
