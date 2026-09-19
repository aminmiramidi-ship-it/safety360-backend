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


class TenantIntegration(Base):
    __tablename__ = "tenant_integrations"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "provider_key",
            "connection_key",
            name="uq_tenant_integration_provider_connection",
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    provider_key = Column(String(100), nullable=False, index=True)
    connection_key = Column(String(160), nullable=False, default="default", index=True)
    display_name = Column(String(240), nullable=False)
    integration_type = Column(String(80), nullable=False, index=True)
    base_url = Column(String(1000), nullable=True)
    auth_type = Column(String(80), nullable=False, default="oauth2", index=True)
    secret_ref = Column(String(240), nullable=True)
    scopes_json = Column(Text, nullable=False, default="[]")
    capabilities_json = Column(Text, nullable=False, default="[]")
    data_classes_json = Column(Text, nullable=False, default="[]")
    approved_purposes_json = Column(Text, nullable=False, default="[]")
    region = Column(String(80), nullable=True)
    enabled = Column(Boolean, nullable=False, default=False, index=True)
    external_processing_allowed = Column(Boolean, nullable=False, default=False)
    minimum_disclosure = Column(Boolean, nullable=False, default=True)
    human_review_required = Column(Boolean, nullable=False, default=True)
    created_by_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)


class IntegrationEvent(Base):
    __tablename__ = "integration_events"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    integration_id = Column(Integer, ForeignKey("tenant_integrations.id", ondelete="CASCADE"), nullable=False, index=True)
    event_type = Column(String(100), nullable=False, index=True)
    direction = Column(String(20), nullable=False, index=True)
    status = Column(String(40), nullable=False, default="pending", index=True)
    subject_ref = Column(String(320), nullable=True, index=True)
    correlation_id = Column(String(120), nullable=True, index=True)
    payload_classification = Column(String(80), nullable=False, default="business_metadata", index=True)
    metadata_json = Column(Text, nullable=False, default="{}")
    error_code = Column(String(120), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, index=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
