from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Integer, String, UniqueConstraint

from database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class LoginThrottle(Base):
    __tablename__ = "login_throttles"
    __table_args__ = (
        UniqueConstraint("key_type", "key_hash", name="uq_login_throttles_type_hash"),
    )

    id = Column(Integer, primary_key=True, index=True)
    key_type = Column(String(20), nullable=False, index=True)
    key_hash = Column(String(64), nullable=False, index=True)
    failed_attempts = Column(Integer, nullable=False, default=0)
    window_started_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    last_failed_at = Column(DateTime(timezone=True), nullable=True)
    locked_until = Column(DateTime(timezone=True), nullable=True, index=True)
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
    )
