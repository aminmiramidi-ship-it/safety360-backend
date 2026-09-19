"""Add hardened browser sessions.

Revision ID: 0018_browser_sessions
Revises: 0017_realtime_security
Create Date: 2026-09-19
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0018_browser_sessions"
down_revision: str | None = "0017_realtime_security"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "browser_sessions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("session_hash", sa.String(length=64), nullable=False),
        sa.Column("csrf_hash", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("session_hash"),
    )
    op.create_index(op.f("ix_browser_sessions_id"), "browser_sessions", ["id"], unique=False)
    op.create_index(
        op.f("ix_browser_sessions_session_hash"),
        "browser_sessions",
        ["session_hash"],
        unique=True,
    )
    op.create_index(op.f("ix_browser_sessions_user_id"), "browser_sessions", ["user_id"], unique=False)
    op.create_index(op.f("ix_browser_sessions_tenant_id"), "browser_sessions", ["tenant_id"], unique=False)
    op.create_index(op.f("ix_browser_sessions_expires_at"), "browser_sessions", ["expires_at"], unique=False)
    op.create_index(op.f("ix_browser_sessions_revoked_at"), "browser_sessions", ["revoked_at"], unique=False)


def downgrade() -> None:
    op.drop_table("browser_sessions")
