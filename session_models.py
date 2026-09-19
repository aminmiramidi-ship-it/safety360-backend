from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String

from database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class BrowserSession(Base):
    __tablename__ = "browser_sessions"

    id = Column(Integer, primary_key=True, index=True)
    session_hash = Column(String(64), unique=True, nullable=False, index=True)
    csrf_hash = Column(String(64), nullable=False)
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
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
