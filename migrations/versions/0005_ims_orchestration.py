"""Add IMS activity and generated artifact orchestration.

Revision ID: 0005_ims_orchestration
Revises: 0004_platform_core
Create Date: 2026-09-18
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005_ims_orchestration"
down_revision: str | None = "0004_platform_core"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ims_activities",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(length=250), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("industry", sa.String(length=120), nullable=True),
        sa.Column("location", sa.String(length=250), nullable=True),
        sa.Column("equipment", sa.Text(), nullable=True),
        sa.Column("substances", sa.Text(), nullable=True),
        sa.Column("environmental_context", sa.Text(), nullable=True),
        sa.Column("energy_context", sa.Text(), nullable=True),
        sa.Column("quality_context", sa.Text(), nullable=True),
        sa.Column("information_security_context", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=30), server_default="draft", nullable=False),
        sa.Column("created_by_id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_ims_activities_id"), "ims_activities", ["id"], unique=False)
    op.create_index(op.f("ix_ims_activities_tenant_id"), "ims_activities", ["tenant_id"], unique=False)
    op.create_index(op.f("ix_ims_activities_industry"), "ims_activities", ["industry"], unique=False)
    op.create_index(op.f("ix_ims_activities_status"), "ims_activities", ["status"], unique=False)
    op.create_index(op.f("ix_ims_activities_created_by_id"), "ims_activities", ["created_by_id"], unique=False)

    op.create_table(
        "ims_artifacts",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("activity_id", sa.Integer(), nullable=False),
        sa.Column("logical_id", sa.String(length=36), nullable=False),
        sa.Column("artifact_type", sa.String(length=80), nullable=False),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("version", sa.Integer(), server_default="1", nullable=False),
        sa.Column("status", sa.String(length=30), server_default="draft", nullable=False),
        sa.Column("content_json", sa.Text(), nullable=False),
        sa.Column("standards_json", sa.Text(), nullable=False),
        sa.Column("generation_mode", sa.String(length=50), server_default="rules", nullable=False),
        sa.Column("created_by_id", sa.Integer(), nullable=False),
        sa.Column("approved_by_id", sa.Integer(), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["activity_id"], ["ims_activities.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["approved_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "logical_id",
            "version",
            name="uq_ims_artifact_tenant_logical_version",
        ),
    )
    op.create_index(op.f("ix_ims_artifacts_id"), "ims_artifacts", ["id"], unique=False)
    op.create_index(op.f("ix_ims_artifacts_tenant_id"), "ims_artifacts", ["tenant_id"], unique=False)
    op.create_index(op.f("ix_ims_artifacts_activity_id"), "ims_artifacts", ["activity_id"], unique=False)
    op.create_index(op.f("ix_ims_artifacts_logical_id"), "ims_artifacts", ["logical_id"], unique=False)
    op.create_index(op.f("ix_ims_artifacts_artifact_type"), "ims_artifacts", ["artifact_type"], unique=False)
    op.create_index(op.f("ix_ims_artifacts_status"), "ims_artifacts", ["status"], unique=False)
    op.create_index(op.f("ix_ims_artifacts_created_by_id"), "ims_artifacts", ["created_by_id"], unique=False)
    op.create_index(op.f("ix_ims_artifacts_approved_by_id"), "ims_artifacts", ["approved_by_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_ims_artifacts_approved_by_id"), table_name="ims_artifacts")
    op.drop_index(op.f("ix_ims_artifacts_created_by_id"), table_name="ims_artifacts")
    op.drop_index(op.f("ix_ims_artifacts_status"), table_name="ims_artifacts")
    op.drop_index(op.f("ix_ims_artifacts_artifact_type"), table_name="ims_artifacts")
    op.drop_index(op.f("ix_ims_artifacts_logical_id"), table_name="ims_artifacts")
    op.drop_index(op.f("ix_ims_artifacts_activity_id"), table_name="ims_artifacts")
    op.drop_index(op.f("ix_ims_artifacts_tenant_id"), table_name="ims_artifacts")
    op.drop_index(op.f("ix_ims_artifacts_id"), table_name="ims_artifacts")
    op.drop_table("ims_artifacts")

    op.drop_index(op.f("ix_ims_activities_created_by_id"), table_name="ims_activities")
    op.drop_index(op.f("ix_ims_activities_status"), table_name="ims_activities")
    op.drop_index(op.f("ix_ims_activities_industry"), table_name="ims_activities")
    op.drop_index(op.f("ix_ims_activities_tenant_id"), table_name="ims_activities")
    op.drop_index(op.f("ix_ims_activities_id"), table_name="ims_activities")
    op.drop_table("ims_activities")
