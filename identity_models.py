from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint

from database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class TenantIdentityProvider(Base):
    __tablename__ = "tenant_identity_providers"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_tenant_identity_provider_name"),
    )

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(
        Integer,
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    name = Column(String(120), nullable=False, default="Corporate SSO")
    issuer_url = Column(String(500), nullable=False)
    client_id = Column(String(255), nullable=False)
    client_secret_env = Column(String(160), nullable=True)
    scopes = Column(String(500), nullable=False, default="openid profile email")
    allowed_domains_json = Column(Text, nullable=False, default="[]")
    enabled = Column(Boolean, nullable=False, default=False)
    auto_provision = Column(Boolean, nullable=False, default=False)
    auto_link_verified_email = Column(Boolean, nullable=False, default=False)
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


class FederatedIdentity(Base):
    __tablename__ = "federated_identities"
    __table_args__ = (
        UniqueConstraint("provider_id", "subject", name="uq_federated_identity_provider_subject"),
        UniqueConstraint("provider_id", "user_id", name="uq_federated_identity_provider_user"),
    )

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(
        Integer,
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    provider_id = Column(
        Integer,
        ForeignKey("tenant_identity_providers.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    issuer = Column(String(500), nullable=False)
    subject = Column(String(500), nullable=False)
    email_at_link = Column(String(320), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    last_login_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)


class SSOExchangeCode(Base):
    __tablename__ = "sso_exchange_codes"

    id = Column(Integer, primary_key=True, index=True)
    code_hash = Column(String(64), nullable=False, unique=True, index=True)
    tenant_id = Column(
        Integer,
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    consumed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
