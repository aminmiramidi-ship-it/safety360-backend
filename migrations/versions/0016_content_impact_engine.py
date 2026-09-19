"""Add governed content dependency and impact tracking.

Revision ID: 0016_content_impact_engine
Revises: 0015_learning_content_factory
Create Date: 2026-09-19
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0016_content_impact_engine"
down_revision: str | None = "0015_learning_content_factory"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _index(table: str, columns: tuple[str, ...]) -> None:
    for column in columns:
        op.create_index(op.f(f"ix_{table}_{column}"), table, [column], unique=False)


def upgrade() -> None:
    op.add_column(
        "learning_content_packs",
        sa.Column("currentness_status", sa.String(length=40), nullable=False, server_default="current"),
    )
    op.create_index(
        op.f("ix_learning_content_packs_currentness_status"),
        "learning_content_packs",
        ["currentness_status"],
        unique=False,
    )

    op.create_table(
        "content_dependencies",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("content_pack_id", sa.Integer(), nullable=False),
        sa.Column("dependency_kind", sa.String(length=80), nullable=False),
        sa.Column("dependency_key", sa.String(length=320), nullable=False),
        sa.Column("reference_id", sa.Integer(), nullable=True),
        sa.Column("source_ref", sa.String(length=1000), nullable=True),
        sa.Column("baseline_hash", sa.String(length=64), nullable=True),
        sa.Column("baseline_version", sa.String(length=160), nullable=True),
        sa.Column("last_seen_hash", sa.String(length=64), nullable=True),
        sa.Column("last_seen_version", sa.String(length=160), nullable=True),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("human_review_required", sa.Boolean(), nullable=False),
        sa.Column("created_by_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["content_pack_id"], ["learning_content_packs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "content_pack_id",
            "dependency_kind",
            "dependency_key",
            name="uq_content_dependency_pack_kind_key",
        ),
    )
    _index(
        "content_dependencies",
        (
            "id",
            "tenant_id",
            "content_pack_id",
            "dependency_kind",
            "dependency_key",
            "reference_id",
            "baseline_hash",
            "last_seen_hash",
            "last_checked_at",
            "active",
            "created_by_id",
        ),
    )

    op.create_table(
        "content_impact_assessments",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("content_pack_id", sa.Integer(), nullable=False),
        sa.Column("dependency_id", sa.Integer(), nullable=False),
        sa.Column("trigger_type", sa.String(length=80), nullable=False),
        sa.Column("trigger_ref", sa.String(length=500), nullable=False),
        sa.Column("previous_hash", sa.String(length=64), nullable=True),
        sa.Column("current_hash", sa.String(length=64), nullable=True),
        sa.Column("previous_version", sa.String(length=160), nullable=True),
        sa.Column("current_version", sa.String(length=160), nullable=True),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("priority", sa.String(length=30), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("evidence_json", sa.Text(), nullable=False),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("human_review_required", sa.Boolean(), nullable=False),
        sa.Column("resolved_by_id", sa.Integer(), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolution_note", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["content_pack_id"], ["learning_content_packs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["dependency_id"], ["content_dependencies.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["resolved_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    _index(
        "content_impact_assessments",
        (
            "id",
            "tenant_id",
            "content_pack_id",
            "dependency_id",
            "trigger_type",
            "trigger_ref",
            "current_hash",
            "status",
            "priority",
            "detected_at",
            "human_review_required",
            "resolved_by_id",
        ),
    )


def downgrade() -> None:
    op.drop_table("content_impact_assessments")
    op.drop_table("content_dependencies")
    op.drop_index(op.f("ix_learning_content_packs_currentness_status"), table_name="learning_content_packs")
    op.drop_column("learning_content_packs", "currentness_status")
