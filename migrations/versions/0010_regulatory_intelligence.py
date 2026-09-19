"""Add regulatory intelligence source, requirement and change tracking.

Revision ID: 0010_regulatory_intelligence
Revises: 0009_privacy_governance
Create Date: 2026-09-19
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010_regulatory_intelligence"
down_revision: str | None = "0009_privacy_governance"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "regulatory_sources",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("authority", sa.String(length=160), nullable=False),
        sa.Column("source_key", sa.String(length=160), nullable=False),
        sa.Column("name", sa.String(length=250), nullable=False),
        sa.Column("jurisdiction", sa.String(length=80), nullable=False),
        sa.Column("source_type", sa.String(length=80), nullable=False),
        sa.Column("base_url", sa.String(length=1000), nullable=False),
        sa.Column("is_primary", sa.Boolean(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("terms_note", sa.String(length=1000), nullable=True),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("authority", "source_key", name="uq_regulatory_source_authority_key"),
    )
    op.create_index(op.f("ix_regulatory_sources_id"), "regulatory_sources", ["id"], unique=False)
    op.create_index(op.f("ix_regulatory_sources_authority"), "regulatory_sources", ["authority"], unique=False)
    op.create_index(op.f("ix_regulatory_sources_source_key"), "regulatory_sources", ["source_key"], unique=False)
    op.create_index(op.f("ix_regulatory_sources_jurisdiction"), "regulatory_sources", ["jurisdiction"], unique=False)
    op.create_index(op.f("ix_regulatory_sources_source_type"), "regulatory_sources", ["source_type"], unique=False)
    op.create_index(op.f("ix_regulatory_sources_is_primary"), "regulatory_sources", ["is_primary"], unique=False)
    op.create_index(op.f("ix_regulatory_sources_enabled"), "regulatory_sources", ["enabled"], unique=False)

    op.create_table(
        "regulatory_requirements",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("source_id", sa.Integer(), nullable=False),
        sa.Column("external_key", sa.String(length=240), nullable=False),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("citation", sa.String(length=500), nullable=True),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("jurisdiction", sa.String(length=80), nullable=False),
        sa.Column("topic", sa.String(length=120), nullable=False),
        sa.Column("management_system", sa.String(length=120), nullable=True),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("source_version", sa.String(length=160), nullable=True),
        sa.Column("effective_from", sa.DateTime(timezone=True), nullable=True),
        sa.Column("effective_to", sa.DateTime(timezone=True), nullable=True),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("applicability_json", sa.Text(), nullable=False),
        sa.Column("human_review_required", sa.Boolean(), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verified_by_id", sa.Integer(), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["source_id"], ["regulatory_sources.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["verified_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("source_id", "external_key", name="uq_regulatory_requirement_source_key"),
    )
    op.create_index(op.f("ix_regulatory_requirements_id"), "regulatory_requirements", ["id"], unique=False)
    op.create_index(op.f("ix_regulatory_requirements_source_id"), "regulatory_requirements", ["source_id"], unique=False)
    op.create_index(op.f("ix_regulatory_requirements_external_key"), "regulatory_requirements", ["external_key"], unique=False)
    op.create_index(op.f("ix_regulatory_requirements_jurisdiction"), "regulatory_requirements", ["jurisdiction"], unique=False)
    op.create_index(op.f("ix_regulatory_requirements_topic"), "regulatory_requirements", ["topic"], unique=False)
    op.create_index(op.f("ix_regulatory_requirements_management_system"), "regulatory_requirements", ["management_system"], unique=False)
    op.create_index(op.f("ix_regulatory_requirements_status"), "regulatory_requirements", ["status"], unique=False)
    op.create_index(op.f("ix_regulatory_requirements_content_hash"), "regulatory_requirements", ["content_hash"], unique=False)
    op.create_index(op.f("ix_regulatory_requirements_verified_by_id"), "regulatory_requirements", ["verified_by_id"], unique=False)

    op.create_table(
        "regulatory_changes",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("requirement_id", sa.Integer(), nullable=False),
        sa.Column("change_type", sa.String(length=60), nullable=False),
        sa.Column("previous_hash", sa.String(length=64), nullable=True),
        sa.Column("new_hash", sa.String(length=64), nullable=False),
        sa.Column("source_version", sa.String(length=160), nullable=True),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("review_status", sa.String(length=40), nullable=False),
        sa.Column("impact_json", sa.Text(), nullable=False),
        sa.Column("human_review_required", sa.Boolean(), nullable=False),
        sa.Column("reviewed_by_id", sa.Integer(), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["requirement_id"], ["regulatory_requirements.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["reviewed_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_regulatory_changes_id"), "regulatory_changes", ["id"], unique=False)
    op.create_index(op.f("ix_regulatory_changes_requirement_id"), "regulatory_changes", ["requirement_id"], unique=False)
    op.create_index(op.f("ix_regulatory_changes_change_type"), "regulatory_changes", ["change_type"], unique=False)
    op.create_index(op.f("ix_regulatory_changes_detected_at"), "regulatory_changes", ["detected_at"], unique=False)
    op.create_index(op.f("ix_regulatory_changes_review_status"), "regulatory_changes", ["review_status"], unique=False)
    op.create_index(op.f("ix_regulatory_changes_reviewed_by_id"), "regulatory_changes", ["reviewed_by_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_regulatory_changes_reviewed_by_id"), table_name="regulatory_changes")
    op.drop_index(op.f("ix_regulatory_changes_review_status"), table_name="regulatory_changes")
    op.drop_index(op.f("ix_regulatory_changes_detected_at"), table_name="regulatory_changes")
    op.drop_index(op.f("ix_regulatory_changes_change_type"), table_name="regulatory_changes")
    op.drop_index(op.f("ix_regulatory_changes_requirement_id"), table_name="regulatory_changes")
    op.drop_index(op.f("ix_regulatory_changes_id"), table_name="regulatory_changes")
    op.drop_table("regulatory_changes")

    op.drop_index(op.f("ix_regulatory_requirements_verified_by_id"), table_name="regulatory_requirements")
    op.drop_index(op.f("ix_regulatory_requirements_content_hash"), table_name="regulatory_requirements")
    op.drop_index(op.f("ix_regulatory_requirements_status"), table_name="regulatory_requirements")
    op.drop_index(op.f("ix_regulatory_requirements_management_system"), table_name="regulatory_requirements")
    op.drop_index(op.f("ix_regulatory_requirements_topic"), table_name="regulatory_requirements")
    op.drop_index(op.f("ix_regulatory_requirements_jurisdiction"), table_name="regulatory_requirements")
    op.drop_index(op.f("ix_regulatory_requirements_external_key"), table_name="regulatory_requirements")
    op.drop_index(op.f("ix_regulatory_requirements_source_id"), table_name="regulatory_requirements")
    op.drop_index(op.f("ix_regulatory_requirements_id"), table_name="regulatory_requirements")
    op.drop_table("regulatory_requirements")

    op.drop_index(op.f("ix_regulatory_sources_enabled"), table_name="regulatory_sources")
    op.drop_index(op.f("ix_regulatory_sources_is_primary"), table_name="regulatory_sources")
    op.drop_index(op.f("ix_regulatory_sources_source_type"), table_name="regulatory_sources")
    op.drop_index(op.f("ix_regulatory_sources_jurisdiction"), table_name="regulatory_sources")
    op.drop_index(op.f("ix_regulatory_sources_source_key"), table_name="regulatory_sources")
    op.drop_index(op.f("ix_regulatory_sources_authority"), table_name="regulatory_sources")
    op.drop_index(op.f("ix_regulatory_sources_id"), table_name="regulatory_sources")
    op.drop_table("regulatory_sources")
