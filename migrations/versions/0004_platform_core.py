"""Add platform storage, assistant and subscription core.

Revision ID: 0004_platform_core
Revises: 0003_tenant_invitations
Create Date: 2026-09-18
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_platform_core"
down_revision: str | None = "0003_tenant_invitations"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "stored_files",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("logical_id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("original_name", sa.String(length=255), nullable=False),
        sa.Column("storage_key", sa.String(length=500), nullable=False),
        sa.Column("media_type", sa.String(length=160), nullable=True),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("category", sa.String(length=80), server_default="general", nullable=False),
        sa.Column("folder", sa.String(length=250), server_default="/", nullable=False),
        sa.Column("created_by_id", sa.Integer(), nullable=False),
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("storage_key"),
        sa.UniqueConstraint("tenant_id", "logical_id", name="uq_stored_files_tenant_logical_id"),
    )
    op.create_index(op.f("ix_stored_files_id"), "stored_files", ["id"], unique=False)
    op.create_index(op.f("ix_stored_files_logical_id"), "stored_files", ["logical_id"], unique=False)
    op.create_index(op.f("ix_stored_files_tenant_id"), "stored_files", ["tenant_id"], unique=False)
    op.create_index(op.f("ix_stored_files_sha256"), "stored_files", ["sha256"], unique=False)
    op.create_index(op.f("ix_stored_files_category"), "stored_files", ["category"], unique=False)
    op.create_index(op.f("ix_stored_files_created_by_id"), "stored_files", ["created_by_id"], unique=False)

    op.create_table(
        "assistant_threads",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(length=250), nullable=False),
        sa.Column("created_by_id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_assistant_threads_id"), "assistant_threads", ["id"], unique=False)
    op.create_index(op.f("ix_assistant_threads_tenant_id"), "assistant_threads", ["tenant_id"], unique=False)
    op.create_index(op.f("ix_assistant_threads_created_by_id"), "assistant_threads", ["created_by_id"], unique=False)

    op.create_table(
        "assistant_messages",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("thread_id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("role", sa.String(length=20), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("provider", sa.String(length=50), server_default="rules", nullable=False),
        sa.Column("model", sa.String(length=120), nullable=True),
        sa.Column("created_by_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["thread_id"], ["assistant_threads.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_assistant_messages_id"), "assistant_messages", ["id"], unique=False)
    op.create_index(op.f("ix_assistant_messages_thread_id"), "assistant_messages", ["thread_id"], unique=False)
    op.create_index(op.f("ix_assistant_messages_tenant_id"), "assistant_messages", ["tenant_id"], unique=False)
    op.create_index(op.f("ix_assistant_messages_created_by_id"), "assistant_messages", ["created_by_id"], unique=False)

    op.create_table(
        "tenant_subscriptions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("plan_code", sa.String(length=50), server_default="trial", nullable=False),
        sa.Column("status", sa.String(length=50), server_default="trialing", nullable=False),
        sa.Column("provider", sa.String(length=50), server_default="manual", nullable=False),
        sa.Column("external_customer_id", sa.String(length=255), nullable=True),
        sa.Column("external_subscription_id", sa.String(length=255), nullable=True),
        sa.Column("current_period_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_tenant_subscriptions_id"), "tenant_subscriptions", ["id"], unique=False)
    op.create_index(op.f("ix_tenant_subscriptions_tenant_id"), "tenant_subscriptions", ["tenant_id"], unique=True)


def downgrade() -> None:
    op.drop_index(op.f("ix_tenant_subscriptions_tenant_id"), table_name="tenant_subscriptions")
    op.drop_index(op.f("ix_tenant_subscriptions_id"), table_name="tenant_subscriptions")
    op.drop_table("tenant_subscriptions")

    op.drop_index(op.f("ix_assistant_messages_created_by_id"), table_name="assistant_messages")
    op.drop_index(op.f("ix_assistant_messages_tenant_id"), table_name="assistant_messages")
    op.drop_index(op.f("ix_assistant_messages_thread_id"), table_name="assistant_messages")
    op.drop_index(op.f("ix_assistant_messages_id"), table_name="assistant_messages")
    op.drop_table("assistant_messages")

    op.drop_index(op.f("ix_assistant_threads_created_by_id"), table_name="assistant_threads")
    op.drop_index(op.f("ix_assistant_threads_tenant_id"), table_name="assistant_threads")
    op.drop_index(op.f("ix_assistant_threads_id"), table_name="assistant_threads")
    op.drop_table("assistant_threads")

    op.drop_index(op.f("ix_stored_files_created_by_id"), table_name="stored_files")
    op.drop_index(op.f("ix_stored_files_category"), table_name="stored_files")
    op.drop_index(op.f("ix_stored_files_sha256"), table_name="stored_files")
    op.drop_index(op.f("ix_stored_files_tenant_id"), table_name="stored_files")
    op.drop_index(op.f("ix_stored_files_logical_id"), table_name="stored_files")
    op.drop_index(op.f("ix_stored_files_id"), table_name="stored_files")
    op.drop_table("stored_files")
