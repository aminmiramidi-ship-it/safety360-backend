"""Add governed learning content packs and artifacts.

Revision ID: 0015_learning_content_factory
Revises: 0014_occ_health_integrations
Create Date: 2026-09-19
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0015_learning_content_factory"
down_revision: str | None = "0014_occ_health_integrations"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _index(table: str, columns: tuple[str, ...]) -> None:
    for column in columns:
        op.create_index(op.f(f"ix_{table}_{column}"), table, [column], unique=False)


def upgrade() -> None:
    op.create_table(
        "learning_content_packs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("pack_key", sa.String(length=200), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("activity_template_id", sa.Integer(), nullable=True),
        sa.Column("activity_ref", sa.String(length=320), nullable=True),
        sa.Column("industry_scheme", sa.String(length=40), nullable=True),
        sa.Column("industry_code", sa.String(length=40), nullable=True),
        sa.Column("jurisdiction", sa.String(length=80), nullable=False),
        sa.Column("target_audience", sa.String(length=120), nullable=False),
        sa.Column("language", sa.String(length=20), nullable=False),
        sa.Column("depth_profile", sa.String(length=40), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("source_refs_json", sa.Text(), nullable=False),
        sa.Column("requirement_refs_json", sa.Text(), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("change_reason", sa.String(length=500), nullable=True),
        sa.Column("review_due_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("human_review_required", sa.Boolean(), nullable=False),
        sa.Column("supersedes_id", sa.Integer(), nullable=True),
        sa.Column("created_by_id", sa.Integer(), nullable=True),
        sa.Column("approved_by_id", sa.Integer(), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["activity_template_id"], ["industry_activity_templates.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["approved_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["supersedes_id"], ["learning_content_packs.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "pack_key", "version", name="uq_learning_content_pack_tenant_key_version"),
    )
    _index(
        "learning_content_packs",
        (
            "id",
            "tenant_id",
            "pack_key",
            "activity_template_id",
            "activity_ref",
            "industry_scheme",
            "industry_code",
            "jurisdiction",
            "target_audience",
            "language",
            "depth_profile",
            "status",
            "content_hash",
            "review_due_at",
            "human_review_required",
            "supersedes_id",
            "created_by_id",
            "approved_by_id",
        ),
    )

    op.create_table(
        "learning_artifacts",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("content_pack_id", sa.Integer(), nullable=False),
        sa.Column("artifact_type", sa.String(length=80), nullable=False),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("language", sa.String(length=20), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("content_json", sa.Text(), nullable=False),
        sa.Column("source_refs_json", sa.Text(), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("human_review_required", sa.Boolean(), nullable=False),
        sa.Column("approved_by_id", sa.Integer(), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["approved_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["content_pack_id"], ["learning_content_packs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("content_pack_id", "artifact_type", "version", name="uq_learning_artifact_pack_type_version"),
    )
    _index(
        "learning_artifacts",
        (
            "id",
            "tenant_id",
            "content_pack_id",
            "artifact_type",
            "language",
            "status",
            "content_hash",
            "human_review_required",
            "approved_by_id",
        ),
    )


def downgrade() -> None:
    op.drop_table("learning_artifacts")
    op.drop_table("learning_content_packs")
