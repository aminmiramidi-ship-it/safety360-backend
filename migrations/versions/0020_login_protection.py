"""Add persistent login throttling state.

Revision ID: 0020_login_protection
Revises: 0019_audit_integrity
Create Date: 2026-09-19
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0020_login_protection"
down_revision: str | None = "0019_audit_integrity"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "login_throttles",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("key_type", sa.String(length=20), nullable=False),
        sa.Column("key_hash", sa.String(length=64), nullable=False),
        sa.Column("failed_attempts", sa.Integer(), nullable=False),
        sa.Column("window_started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_failed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("key_type", "key_hash", name="uq_login_throttles_type_hash"),
    )
    op.create_index(op.f("ix_login_throttles_id"), "login_throttles", ["id"], unique=False)
    op.create_index(
        op.f("ix_login_throttles_key_type"),
        "login_throttles",
        ["key_type"],
        unique=False,
    )
    op.create_index(
        op.f("ix_login_throttles_key_hash"),
        "login_throttles",
        ["key_hash"],
        unique=False,
    )
    op.create_index(
        op.f("ix_login_throttles_locked_until"),
        "login_throttles",
        ["locked_until"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_table("login_throttles")
