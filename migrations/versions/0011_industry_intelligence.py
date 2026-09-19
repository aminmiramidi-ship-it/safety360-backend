"""Add industry intelligence catalog and source-backed templates.

Revision ID: 0011_industry_intelligence
Revises: 0010_regulatory_intelligence
Create Date: 2026-09-19
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011_industry_intelligence"
down_revision: str | None = "0010_regulatory_intelligence"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "industry_classifications",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scheme", sa.String(length=40), nullable=False),
        sa.Column("version", sa.String(length=40), nullable=False),
        sa.Column("code", sa.String(length=40), nullable=False),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("parent_code", sa.String(length=40), nullable=True),
        sa.Column("level", sa.String(length=40), nullable=False),
        sa.Column("jurisdiction", sa.String(length=80), nullable=False),
        sa.Column("source_url", sa.String(length=1000), nullable=False),
        sa.Column("source_hash", sa.String(length=64), nullable=True),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=True),
        sa.Column("valid_to", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("review_status", sa.String(length=40), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scheme", "code", "version", name="uq_industry_classification_scheme_code_version"),
    )
    for column in ("id", "scheme", "version", "code", "parent_code", "level", "jurisdiction", "source_hash", "is_active", "review_status"):
        op.create_index(op.f(f"ix_industry_classifications_{column}"), "industry_classifications", [column], unique=False)

    op.create_table(
        "tenant_industry_profiles",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("scheme", sa.String(length=40), nullable=False),
        sa.Column("code", sa.String(length=40), nullable=False),
        sa.Column("is_primary", sa.Boolean(), nullable=False),
        sa.Column("verification_status", sa.String(length=40), nullable=False),
        sa.Column("verified_by_id", sa.Integer(), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["verified_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "scheme", "code", name="uq_tenant_industry_profile_tenant_scheme_code"),
    )
    for column in ("id", "tenant_id", "scheme", "code", "is_primary", "verification_status", "verified_by_id"):
        op.create_index(op.f(f"ix_tenant_industry_profiles_{column}"), "tenant_industry_profiles", [column], unique=False)

    op.create_table(
        "industry_activity_templates",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scheme", sa.String(length=40), nullable=False),
        sa.Column("industry_code", sa.String(length=40), nullable=False),
        sa.Column("template_key", sa.String(length=160), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("activity_description", sa.Text(), nullable=False),
        sa.Column("process_description", sa.Text(), nullable=True),
        sa.Column("process_steps_json", sa.Text(), nullable=False),
        sa.Column("equipment_json", sa.Text(), nullable=False),
        sa.Column("substances_json", sa.Text(), nullable=False),
        sa.Column("worker_groups_json", sa.Text(), nullable=False),
        sa.Column("hazard_factors_json", sa.Text(), nullable=False),
        sa.Column("controls_json", sa.Text(), nullable=False),
        sa.Column("training_topics_json", sa.Text(), nullable=False),
        sa.Column("operating_instruction_topics_json", sa.Text(), nullable=False),
        sa.Column("source_refs_json", sa.Text(), nullable=False),
        sa.Column("jurisdiction", sa.String(length=80), nullable=False),
        sa.Column("review_status", sa.String(length=40), nullable=False),
        sa.Column("human_review_required", sa.Boolean(), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=True),
        sa.Column("valid_to", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scheme", "industry_code", "template_key", "version", name="uq_industry_activity_template_key_version"),
    )
    for column in ("id", "scheme", "industry_code", "template_key", "jurisdiction", "review_status", "content_hash"):
        op.create_index(op.f(f"ix_industry_activity_templates_{column}"), "industry_activity_templates", [column], unique=False)

    op.create_table(
        "industry_artifact_templates",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("activity_template_id", sa.Integer(), nullable=False),
        sa.Column("artifact_type", sa.String(length=80), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("content_json", sa.Text(), nullable=False),
        sa.Column("source_refs_json", sa.Text(), nullable=False),
        sa.Column("review_status", sa.String(length=40), nullable=False),
        sa.Column("human_review_required", sa.Boolean(), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["activity_template_id"], ["industry_activity_templates.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("activity_template_id", "artifact_type", "version", name="uq_industry_artifact_template_type_version"),
    )
    for column in ("id", "activity_template_id", "artifact_type", "review_status", "content_hash"):
        op.create_index(op.f(f"ix_industry_artifact_templates_{column}"), "industry_artifact_templates", [column], unique=False)

    op.create_table(
        "industry_knowledge_changes",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("object_type", sa.String(length=80), nullable=False),
        sa.Column("object_key", sa.String(length=250), nullable=False),
        sa.Column("scheme", sa.String(length=40), nullable=True),
        sa.Column("industry_code", sa.String(length=40), nullable=True),
        sa.Column("change_type", sa.String(length=60), nullable=False),
        sa.Column("previous_hash", sa.String(length=64), nullable=True),
        sa.Column("new_hash", sa.String(length=64), nullable=False),
        sa.Column("source_refs_json", sa.Text(), nullable=False),
        sa.Column("impact_json", sa.Text(), nullable=False),
        sa.Column("review_status", sa.String(length=40), nullable=False),
        sa.Column("human_review_required", sa.Boolean(), nullable=False),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reviewed_by_id", sa.Integer(), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["reviewed_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in ("id", "object_type", "object_key", "scheme", "industry_code", "change_type", "review_status", "detected_at", "reviewed_by_id"):
        op.create_index(op.f(f"ix_industry_knowledge_changes_{column}"), "industry_knowledge_changes", [column], unique=False)


def downgrade() -> None:
    op.drop_table("industry_knowledge_changes")
    op.drop_table("industry_artifact_templates")
    op.drop_table("industry_activity_templates")
    op.drop_table("tenant_industry_profiles")
    op.drop_table("industry_classifications")
