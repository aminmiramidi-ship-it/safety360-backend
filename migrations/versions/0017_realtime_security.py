"""Add one-time realtime access tickets.

Revision ID: 0017_realtime_security
Revises: 0016_content_impact_engine
Create Date: 2026-09-19
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0017_realtime_security"
down_revision: str | None = "0016_content_impact_engine"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "realtime_access_tickets",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=True),
        sa.Column("purpose", sa.String(length=80), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index(op.f("ix_realtime_access_tickets_id"), "realtime_access_tickets", ["id"], unique=False)
    op.create_index(
        op.f("ix_realtime_access_tickets_token_hash"),
        "realtime_access_tickets",
        ["token_hash"],
        unique=True,
    )
    op.create_index(op.f("ix_realtime_access_tickets_user_id"), "realtime_access_tickets", ["user_id"], unique=False)
    op.create_index(op.f("ix_realtime_access_tickets_tenant_id"), "realtime_access_tickets", ["tenant_id"], unique=False)
    op.create_index(op.f("ix_realtime_access_tickets_purpose"), "realtime_access_tickets", ["purpose"], unique=False)
    op.create_index(op.f("ix_realtime_access_tickets_expires_at"), "realtime_access_tickets", ["expires_at"], unique=False)
    op.create_index(op.f("ix_realtime_access_tickets_used_at"), "realtime_access_tickets", ["used_at"], unique=False)


def downgrade() -> None:
    op.drop_table("realtime_access_tickets")
