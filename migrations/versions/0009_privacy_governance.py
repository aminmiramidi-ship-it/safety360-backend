"""Add privacy governance, ROPA, DPIA, retention and DSAR tables.

Revision ID: 0009_privacy_governance
Revises: 0008_secure_ingestion
Create Date: 2026-09-19
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009_privacy_governance"
down_revision: str | None = "0008_secure_ingestion"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "privacy_processing_activities",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=250), nullable=False),
        sa.Column("purpose", sa.Text(), nullable=False),
        sa.Column("legal_basis", sa.String(length=250), nullable=False),
        sa.Column("data_subject_categories_json", sa.Text(), nullable=False),
        sa.Column("personal_data_categories_json", sa.Text(), nullable=False),
        sa.Column("recipients_json", sa.Text(), nullable=False),
        sa.Column("third_country_transfers_json", sa.Text(), nullable=False),
        sa.Column("retention_summary", sa.String(length=500), nullable=True),
        sa.Column("security_measures_summary", sa.Text(), nullable=True),
        sa.Column("owner_role", sa.String(length=120), nullable=True),
        sa.Column("high_risk", sa.Boolean(), nullable=False),
        sa.Column("special_categories", sa.Boolean(), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("created_by_id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "name", name="uq_privacy_processing_activity_tenant_name"),
    )
    op.create_index(op.f("ix_privacy_processing_activities_id"), "privacy_processing_activities", ["id"], unique=False)
    op.create_index(op.f("ix_privacy_processing_activities_tenant_id"), "privacy_processing_activities", ["tenant_id"], unique=False)
    op.create_index(op.f("ix_privacy_processing_activities_name"), "privacy_processing_activities", ["name"], unique=False)
    op.create_index(op.f("ix_privacy_processing_activities_high_risk"), "privacy_processing_activities", ["high_risk"], unique=False)
    op.create_index(op.f("ix_privacy_processing_activities_special_categories"), "privacy_processing_activities", ["special_categories"], unique=False)
    op.create_index(op.f("ix_privacy_processing_activities_status"), "privacy_processing_activities", ["status"], unique=False)
    op.create_index(op.f("ix_privacy_processing_activities_created_by_id"), "privacy_processing_activities", ["created_by_id"], unique=False)

    op.create_table(
        "privacy_impact_assessments",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("processing_activity_id", sa.Integer(), nullable=False),
        sa.Column("necessity_proportionality", sa.Text(), nullable=False),
        sa.Column("risk_summary", sa.Text(), nullable=False),
        sa.Column("safeguards_summary", sa.Text(), nullable=False),
        sa.Column("residual_risk_level", sa.String(length=20), nullable=False),
        sa.Column("dpo_consulted", sa.Boolean(), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("created_by_id", sa.Integer(), nullable=False),
        sa.Column("approved_by_id", sa.Integer(), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("review_due_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["approved_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["processing_activity_id"], ["privacy_processing_activities.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in (
        "id",
        "tenant_id",
        "processing_activity_id",
        "residual_risk_level",
        "status",
        "created_by_id",
        "approved_by_id",
        "review_due_at",
    ):
        op.create_index(op.f(f"ix_privacy_impact_assessments_{column}"), "privacy_impact_assessments", [column], unique=False)

    op.create_table(
        "privacy_retention_rules",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("data_category", sa.String(length=200), nullable=False),
        sa.Column("source_system", sa.String(length=120), nullable=False),
        sa.Column("legal_basis", sa.String(length=300), nullable=True),
        sa.Column("retention_days", sa.Integer(), nullable=True),
        sa.Column("trigger_event", sa.String(length=200), nullable=True),
        sa.Column("disposition", sa.String(length=40), nullable=False),
        sa.Column("legal_hold_supported", sa.Boolean(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_by_id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "data_category",
            "source_system",
            name="uq_privacy_retention_rule_tenant_category_source",
        ),
    )
    for column in (
        "id",
        "tenant_id",
        "data_category",
        "source_system",
        "disposition",
        "is_active",
        "created_by_id",
    ):
        op.create_index(op.f(f"ix_privacy_retention_rules_{column}"), "privacy_retention_rules", [column], unique=False)

    op.create_table(
        "privacy_data_subject_requests",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("request_id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("request_type", sa.String(length=40), nullable=False),
        sa.Column("subject_reference_hash", sa.String(length=64), nullable=False),
        sa.Column("verification_status", sa.String(length=30), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("jurisdiction", sa.String(length=40), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by_id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("request_id"),
    )
    for column in (
        "id",
        "request_id",
        "tenant_id",
        "request_type",
        "subject_reference_hash",
        "verification_status",
        "status",
        "jurisdiction",
        "due_at",
        "created_by_id",
    ):
        op.create_index(op.f(f"ix_privacy_data_subject_requests_{column}"), "privacy_data_subject_requests", [column], unique=column == "request_id")


def downgrade() -> None:
    for column in (
        "created_by_id",
        "due_at",
        "jurisdiction",
        "status",
        "verification_status",
        "subject_reference_hash",
        "request_type",
        "tenant_id",
        "request_id",
        "id",
    ):
        op.drop_index(op.f(f"ix_privacy_data_subject_requests_{column}"), table_name="privacy_data_subject_requests")
    op.drop_table("privacy_data_subject_requests")

    for column in (
        "created_by_id",
        "is_active",
        "disposition",
        "source_system",
        "data_category",
        "tenant_id",
        "id",
    ):
        op.drop_index(op.f(f"ix_privacy_retention_rules_{column}"), table_name="privacy_retention_rules")
    op.drop_table("privacy_retention_rules")

    for column in (
        "review_due_at",
        "approved_by_id",
        "created_by_id",
        "status",
        "residual_risk_level",
        "processing_activity_id",
        "tenant_id",
        "id",
    ):
        op.drop_index(op.f(f"ix_privacy_impact_assessments_{column}"), table_name="privacy_impact_assessments")
    op.drop_table("privacy_impact_assessments")

    op.drop_index(op.f("ix_privacy_processing_activities_created_by_id"), table_name="privacy_processing_activities")
    op.drop_index(op.f("ix_privacy_processing_activities_status"), table_name="privacy_processing_activities")
    op.drop_index(op.f("ix_privacy_processing_activities_special_categories"), table_name="privacy_processing_activities")
    op.drop_index(op.f("ix_privacy_processing_activities_high_risk"), table_name="privacy_processing_activities")
    op.drop_index(op.f("ix_privacy_processing_activities_name"), table_name="privacy_processing_activities")
    op.drop_index(op.f("ix_privacy_processing_activities_tenant_id"), table_name="privacy_processing_activities")
    op.drop_index(op.f("ix_privacy_processing_activities_id"), table_name="privacy_processing_activities")
    op.drop_table("privacy_processing_activities")
