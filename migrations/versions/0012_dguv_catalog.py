"""Add DGUV publication catalog governance tables.

Revision ID: 0012_dguv_catalog
Revises: 0011_industry_intelligence
Create Date: 2026-09-19
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0012_dguv_catalog"
down_revision: str | None = "0011_industry_intelligence"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "dguv_publications",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("publication_type", sa.String(length=40), nullable=False),
        sa.Column("publication_number", sa.String(length=80), nullable=False),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("edition", sa.String(length=40), nullable=False),
        sa.Column("language", sa.String(length=20), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("article_id", sa.String(length=80), nullable=True),
        sa.Column("source_url", sa.String(length=1000), nullable=False),
        sa.Column("responsible_carrier", sa.String(length=250), nullable=True),
        sa.Column("topic", sa.String(length=160), nullable=True),
        sa.Column("industry_scope", sa.String(length=500), nullable=True),
        sa.Column("source_metadata_hash", sa.String(length=64), nullable=False),
        sa.Column("rights_basis", sa.String(length=80), nullable=False),
        sa.Column("rights_confirmed", sa.Boolean(), nullable=False),
        sa.Column("human_review_required", sa.Boolean(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "publication_type",
            "publication_number",
            "edition",
            name="uq_dguv_publication_type_number_edition",
        ),
    )
    op.create_index(op.f("ix_dguv_publications_id"), "dguv_publications", ["id"], unique=False)
    op.create_index(op.f("ix_dguv_publications_publication_type"), "dguv_publications", ["publication_type"], unique=False)
    op.create_index(op.f("ix_dguv_publications_publication_number"), "dguv_publications", ["publication_number"], unique=False)
    op.create_index(op.f("ix_dguv_publications_edition"), "dguv_publications", ["edition"], unique=False)
    op.create_index(op.f("ix_dguv_publications_language"), "dguv_publications", ["language"], unique=False)
    op.create_index(op.f("ix_dguv_publications_status"), "dguv_publications", ["status"], unique=False)
    op.create_index(op.f("ix_dguv_publications_article_id"), "dguv_publications", ["article_id"], unique=False)
    op.create_index(op.f("ix_dguv_publications_responsible_carrier"), "dguv_publications", ["responsible_carrier"], unique=False)
    op.create_index(op.f("ix_dguv_publications_topic"), "dguv_publications", ["topic"], unique=False)
    op.create_index(op.f("ix_dguv_publications_source_metadata_hash"), "dguv_publications", ["source_metadata_hash"], unique=False)
    op.create_index(op.f("ix_dguv_publications_rights_basis"), "dguv_publications", ["rights_basis"], unique=False)
    op.create_index(op.f("ix_dguv_publications_rights_confirmed"), "dguv_publications", ["rights_confirmed"], unique=False)

    op.create_table(
        "dguv_catalog_changes",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("publication_id", sa.Integer(), nullable=False),
        sa.Column("change_type", sa.String(length=50), nullable=False),
        sa.Column("previous_hash", sa.String(length=64), nullable=True),
        sa.Column("new_hash", sa.String(length=64), nullable=False),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("review_status", sa.String(length=40), nullable=False),
        sa.Column("impact_json", sa.Text(), nullable=False),
        sa.Column("human_review_required", sa.Boolean(), nullable=False),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["publication_id"], ["dguv_publications.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_dguv_catalog_changes_id"), "dguv_catalog_changes", ["id"], unique=False)
    op.create_index(op.f("ix_dguv_catalog_changes_publication_id"), "dguv_catalog_changes", ["publication_id"], unique=False)
    op.create_index(op.f("ix_dguv_catalog_changes_change_type"), "dguv_catalog_changes", ["change_type"], unique=False)
    op.create_index(op.f("ix_dguv_catalog_changes_detected_at"), "dguv_catalog_changes", ["detected_at"], unique=False)
    op.create_index(op.f("ix_dguv_catalog_changes_review_status"), "dguv_catalog_changes", ["review_status"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_dguv_catalog_changes_review_status"), table_name="dguv_catalog_changes")
    op.drop_index(op.f("ix_dguv_catalog_changes_detected_at"), table_name="dguv_catalog_changes")
    op.drop_index(op.f("ix_dguv_catalog_changes_change_type"), table_name="dguv_catalog_changes")
    op.drop_index(op.f("ix_dguv_catalog_changes_publication_id"), table_name="dguv_catalog_changes")
    op.drop_index(op.f("ix_dguv_catalog_changes_id"), table_name="dguv_catalog_changes")
    op.drop_table("dguv_catalog_changes")

    op.drop_index(op.f("ix_dguv_publications_rights_confirmed"), table_name="dguv_publications")
    op.drop_index(op.f("ix_dguv_publications_rights_basis"), table_name="dguv_publications")
    op.drop_index(op.f("ix_dguv_publications_source_metadata_hash"), table_name="dguv_publications")
    op.drop_index(op.f("ix_dguv_publications_topic"), table_name="dguv_publications")
    op.drop_index(op.f("ix_dguv_publications_responsible_carrier"), table_name="dguv_publications")
    op.drop_index(op.f("ix_dguv_publications_article_id"), table_name="dguv_publications")
    op.drop_index(op.f("ix_dguv_publications_status"), table_name="dguv_publications")
    op.drop_index(op.f("ix_dguv_publications_language"), table_name="dguv_publications")
    op.drop_index(op.f("ix_dguv_publications_edition"), table_name="dguv_publications")
    op.drop_index(op.f("ix_dguv_publications_publication_number"), table_name="dguv_publications")
    op.drop_index(op.f("ix_dguv_publications_publication_type"), table_name="dguv_publications")
    op.drop_index(op.f("ix_dguv_publications_id"), table_name="dguv_publications")
    op.drop_table("dguv_publications")
