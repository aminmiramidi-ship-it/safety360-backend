"""Add secure document ingestion processing table.

Revision ID: 0008_secure_ingestion
Revises: 0007_federated_identity
Create Date: 2026-09-19
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008_secure_ingestion"
down_revision: str | None = "0007_federated_identity"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "file_ingestion_records",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("file_id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("detected_format", sa.String(length=50), nullable=False),
        sa.Column("scan_status", sa.String(length=30), nullable=False),
        sa.Column("processing_status", sa.String(length=30), nullable=False),
        sa.Column("parser", sa.String(length=80), nullable=True),
        sa.Column("source_sha256", sa.String(length=64), nullable=False),
        sa.Column("extracted_text", sa.Text(), nullable=True),
        sa.Column("extracted_sha256", sa.String(length=64), nullable=True),
        sa.Column("error_message", sa.String(length=1000), nullable=True),
        sa.Column("created_by_id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["file_id"], ["stored_files.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("file_id"),
    )
    op.create_index(op.f("ix_file_ingestion_records_id"), "file_ingestion_records", ["id"], unique=False)
    op.create_index(op.f("ix_file_ingestion_records_file_id"), "file_ingestion_records", ["file_id"], unique=True)
    op.create_index(op.f("ix_file_ingestion_records_tenant_id"), "file_ingestion_records", ["tenant_id"], unique=False)
    op.create_index(op.f("ix_file_ingestion_records_detected_format"), "file_ingestion_records", ["detected_format"], unique=False)
    op.create_index(op.f("ix_file_ingestion_records_scan_status"), "file_ingestion_records", ["scan_status"], unique=False)
    op.create_index(op.f("ix_file_ingestion_records_processing_status"), "file_ingestion_records", ["processing_status"], unique=False)
    op.create_index(op.f("ix_file_ingestion_records_source_sha256"), "file_ingestion_records", ["source_sha256"], unique=False)
    op.create_index(op.f("ix_file_ingestion_records_extracted_sha256"), "file_ingestion_records", ["extracted_sha256"], unique=False)
    op.create_index(op.f("ix_file_ingestion_records_created_by_id"), "file_ingestion_records", ["created_by_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_file_ingestion_records_created_by_id"), table_name="file_ingestion_records")
    op.drop_index(op.f("ix_file_ingestion_records_extracted_sha256"), table_name="file_ingestion_records")
    op.drop_index(op.f("ix_file_ingestion_records_source_sha256"), table_name="file_ingestion_records")
    op.drop_index(op.f("ix_file_ingestion_records_processing_status"), table_name="file_ingestion_records")
    op.drop_index(op.f("ix_file_ingestion_records_scan_status"), table_name="file_ingestion_records")
    op.drop_index(op.f("ix_file_ingestion_records_detected_format"), table_name="file_ingestion_records")
    op.drop_index(op.f("ix_file_ingestion_records_tenant_id"), table_name="file_ingestion_records")
    op.drop_index(op.f("ix_file_ingestion_records_file_id"), table_name="file_ingestion_records")
    op.drop_index(op.f("ix_file_ingestion_records_id"), table_name="file_ingestion_records")
    op.drop_table("file_ingestion_records")
