from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text, UniqueConstraint

from database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class DguvPublication(Base):
    __tablename__ = "dguv_publications"
    __table_args__ = (
        UniqueConstraint(
            "publication_type",
            "publication_number",
            "edition",
            name="uq_dguv_publication_type_number_edition",
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    publication_type = Column(String(40), nullable=False, index=True)
    publication_number = Column(String(80), nullable=False, index=True)
    title = Column(String(500), nullable=False)
    edition = Column(String(40), nullable=False, default="unknown", index=True)
    language = Column(String(20), nullable=False, default="de", index=True)
    status = Column(String(40), nullable=False, default="current", index=True)
    article_id = Column(String(80), nullable=True, index=True)
    source_url = Column(String(1000), nullable=False)
    responsible_carrier = Column(String(250), nullable=True, index=True)
    topic = Column(String(160), nullable=True, index=True)
    industry_scope = Column(String(500), nullable=True)
    source_metadata_hash = Column(String(64), nullable=False, index=True)
    rights_basis = Column(String(80), nullable=False, default="manual_reference", index=True)
    rights_confirmed = Column(Boolean, nullable=False, default=False, index=True)
    human_review_required = Column(Boolean, nullable=False, default=True)
    last_seen_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    last_verified_at = Column(DateTime(timezone=True), nullable=True)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)


class DguvCatalogChange(Base):
    __tablename__ = "dguv_catalog_changes"

    id = Column(Integer, primary_key=True, index=True)
    publication_id = Column(Integer, nullable=False, index=True)
    change_type = Column(String(50), nullable=False, index=True)
    previous_hash = Column(String(64), nullable=True)
    new_hash = Column(String(64), nullable=False)
    detected_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, index=True)
    review_status = Column(String(40), nullable=False, default="pending", index=True)
    impact_json = Column(Text, nullable=False, default="{}")
    human_review_required = Column(Boolean, nullable=False, default=True)
    reviewed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
