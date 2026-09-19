from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text

from database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class WebAuthnUserHandle(Base):
    __tablename__ = "webauthn_user_handles"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    handle = Column(String(86), nullable=False, unique=True, index=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)


class PasskeyCredential(Base):
    __tablename__ = "passkey_credentials"

    id = Column(Integer, primary_key=True, index=True)
    credential_id = Column(String(1024), nullable=False, unique=True, index=True)
    credential_public_key = Column(Text, nullable=False)
    sign_count = Column(Integer, nullable=False, default=0)
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    tenant_id = Column(
        Integer,
        ForeignKey("tenants.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    nickname = Column(String(120), nullable=True)
    transports_json = Column(Text, nullable=True)
    device_type = Column(String(40), nullable=True)
    backed_up = Column(Boolean, nullable=False, default=False)
    aaguid = Column(String(36), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True, index=True)


class WebAuthnCeremony(Base):
    __tablename__ = "webauthn_ceremonies"

    id = Column(Integer, primary_key=True, index=True)
    ceremony_id = Column(String(36), nullable=False, unique=True, index=True)
    purpose = Column(String(24), nullable=False, index=True)
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    challenge = Column(String(256), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    used_at = Column(DateTime(timezone=True), nullable=True, index=True)
