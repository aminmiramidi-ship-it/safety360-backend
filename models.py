from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Integer, String

from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(320), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(200), nullable=True)
    role = Column(String(50), nullable=False, default="user")
    language = Column(String(10), nullable=False, default="de")
    tenant_id = Column(Integer, nullable=True, index=True)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
