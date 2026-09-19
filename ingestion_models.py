from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text

from database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class FileIngestionRecord(Base):
    __tablename__ = "file_ingestion_records"

    id = Column(Integer, primary_key=True, index=True)
    file_id = Column(
        Integer,
        ForeignKey("stored_files.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    tenant_id = Column(
        Integer,
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    detected_format = Column(String(50), nullable=False, index=True)
    scan_status = Column(String(30), nullable=False, default="pending", index=True)
    processing_status = Column(String(30), nullable=False, default="stored", index=True)
    parser = Column(String(80), nullable=True)
    source_sha256 = Column(String(64), nullable=False, index=True)
    extracted_text = Column(Text, nullable=True)
    extracted_sha256 = Column(String(64), nullable=True, index=True)
    error_message = Column(String(1000), nullable=True)
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
