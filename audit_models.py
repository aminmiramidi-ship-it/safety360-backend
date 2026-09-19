from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, event

from database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AuditChainHead(Base):
    __tablename__ = "audit_chain_heads"

    scope_key = Column(String(80), primary_key=True)
    tenant_id = Column(
        Integer,
        ForeignKey("tenants.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    last_sequence = Column(Integer, nullable=False, default=0)
    head_hash = Column(String(64), nullable=True)
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
    )


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        UniqueConstraint("scope_key", "sequence", name="uq_audit_events_scope_sequence"),
    )

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String(36), nullable=False, unique=True, index=True)
    scope_key = Column(String(80), nullable=False, index=True)
    sequence = Column(Integer, nullable=False)
    tenant_id = Column(
        Integer,
        ForeignKey("tenants.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    actor_user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    action = Column(String(120), nullable=False, index=True)
    object_type = Column(String(120), nullable=False, index=True)
    object_id = Column(String(160), nullable=True, index=True)
    outcome = Column(String(30), nullable=False, default="success", index=True)
    source = Column(String(80), nullable=False, default="application", index=True)
    request_id = Column(String(80), nullable=True, index=True)
    details_json = Column(Text, nullable=True)
    previous_hash = Column(String(64), nullable=True)
    record_hash = Column(String(64), nullable=False, unique=True, index=True)
    key_id = Column(String(50), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)


def _deny_audit_mutation(*_args, **_kwargs) -> None:
    raise RuntimeError("Audit events are append-only through the ORM.")


event.listen(AuditEvent, "before_update", _deny_audit_mutation)
event.listen(AuditEvent, "before_delete", _deny_audit_mutation)
