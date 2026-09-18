"""Add secure tenant invitations.

Revision ID: 0003_tenant_invitations
Revises: 0002_document_control
Create Date: 2026-09-18
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_tenant_invitations"
down_revision: str | None = "0002_document_control"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "tenant_invitations",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("role", sa.String(length=50), server_default="user", nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("created_by_id", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_tenant_invitations_id"),
        "tenant_invitations",
        ["id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_tenant_invitations_tenant_id"),
        "tenant_invitations",
        ["tenant_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_tenant_invitations_email"),
        "tenant_invitations",
        ["email"],
        unique=False,
    )
    op.create_index(
        op.f("ix_tenant_invitations_token_hash"),
        "tenant_invitations",
        ["token_hash"],
        unique=True,
    )
    op.create_index(
        op.f("ix_tenant_invitations_created_by_id"),
        "tenant_invitations",
        ["created_by_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_tenant_invitations_created_by_id"),
        table_name="tenant_invitations",
    )
    op.drop_index(
        op.f("ix_tenant_invitations_token_hash"),
        table_name="tenant_invitations",
    )
    op.drop_index(
        op.f("ix_tenant_invitations_email"),
        table_name="tenant_invitations",
    )
    op.drop_index(
        op.f("ix_tenant_invitations_tenant_id"),
        table_name="tenant_invitations",
    )
    op.drop_index(
        op.f("ix_tenant_invitations_id"),
        table_name="tenant_invitations",
    )
    op.drop_table("tenant_invitations")
