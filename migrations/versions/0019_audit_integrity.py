"""Add tamper-evident structured audit chain.

Revision ID: 0019_audit_integrity
Revises: 0018_browser_sessions
Create Date: 2026-09-19
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0019_audit_integrity"
down_revision: str | None = "0018_browser_sessions"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "audit_chain_heads",
        sa.Column("scope_key", sa.String(length=80), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=True),
        sa.Column("last_sequence", sa.Integer(), nullable=False),
        sa.Column("head_hash", sa.String(length=64), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("scope_key"),
    )
    op.create_index(
        op.f("ix_audit_chain_heads_tenant_id"),
        "audit_chain_heads",
        ["tenant_id"],
        unique=False,
    )

    op.create_table(
        "audit_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("event_id", sa.String(length=36), nullable=False),
        sa.Column("scope_key", sa.String(length=80), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=True),
        sa.Column("actor_user_id", sa.Integer(), nullable=True),
        sa.Column("action", sa.String(length=120), nullable=False),
        sa.Column("object_type", sa.String(length=120), nullable=False),
        sa.Column("object_id", sa.String(length=160), nullable=True),
        sa.Column("outcome", sa.String(length=30), nullable=False),
        sa.Column("source", sa.String(length=80), nullable=False),
        sa.Column("request_id", sa.String(length=80), nullable=True),
        sa.Column("details_json", sa.Text(), nullable=True),
        sa.Column("previous_hash", sa.String(length=64), nullable=True),
        sa.Column("record_hash", sa.String(length=64), nullable=False),
        sa.Column("key_id", sa.String(length=50), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["actor_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("event_id"),
        sa.UniqueConstraint("record_hash"),
        sa.UniqueConstraint("scope_key", "sequence", name="uq_audit_events_scope_sequence"),
    )
    for column in (
        "id",
        "event_id",
        "scope_key",
        "tenant_id",
        "actor_user_id",
        "action",
        "object_type",
        "object_id",
        "outcome",
        "source",
        "request_id",
        "record_hash",
    ):
        op.create_index(
            op.f(f"ix_audit_events_{column}"),
            "audit_events",
            [column],
            unique=column in {"event_id", "record_hash"},
        )


def downgrade() -> None:
    op.drop_table("audit_events")
    op.drop_table("audit_chain_heads")
