"""Add tenant legal knowledge graph and applicability tables.

Revision ID: 0013_legal_knowledge_graph
Revises: 0012_dguv_catalog
Create Date: 2026-09-19
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0013_legal_knowledge_graph"
down_revision: str | None = "0012_dguv_catalog"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "compliance_subjects",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("subject_type", sa.String(length=60), nullable=False),
        sa.Column("subject_key", sa.String(length=240), nullable=False),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("jurisdiction", sa.String(length=80), nullable=True),
        sa.Column("parent_ref", sa.String(length=320), nullable=True),
        sa.Column("metadata_json", sa.Text(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_by_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "subject_type", "subject_key", name="uq_compliance_subject_tenant_type_key"),
    )
    for column in ("id", "tenant_id", "subject_type", "subject_key", "jurisdiction", "parent_ref", "active", "created_by_id"):
        op.create_index(op.f(f"ix_compliance_subjects_{column}"), "compliance_subjects", [column], unique=False)

    op.create_table(
        "requirement_relations",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("from_requirement_id", sa.Integer(), nullable=False),
        sa.Column("to_requirement_id", sa.Integer(), nullable=False),
        sa.Column("relation_type", sa.String(length=60), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=True),
        sa.Column("source_reference", sa.String(length=1000), nullable=True),
        sa.Column("human_review_required", sa.Boolean(), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verified_by_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["from_requirement_id"], ["regulatory_requirements.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["to_requirement_id"], ["regulatory_requirements.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["verified_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("from_requirement_id", "to_requirement_id", "relation_type", name="uq_requirement_relation_edge"),
    )
    for column in ("id", "from_requirement_id", "to_requirement_id", "relation_type", "verified_by_id"):
        op.create_index(op.f(f"ix_requirement_relations_{column}"), "requirement_relations", [column], unique=False)

    op.create_table(
        "applicability_assessments",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("requirement_id", sa.Integer(), nullable=False),
        sa.Column("subject_id", sa.Integer(), nullable=False),
        sa.Column("applicability_status", sa.String(length=40), nullable=False),
        sa.Column("origin", sa.String(length=40), nullable=False),
        sa.Column("confidence", sa.Integer(), nullable=False),
        sa.Column("priority", sa.String(length=30), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=True),
        sa.Column("evidence_json", sa.Text(), nullable=False),
        sa.Column("missing_evidence_json", sa.Text(), nullable=False),
        sa.Column("human_review_required", sa.Boolean(), nullable=False),
        sa.Column("reviewed_by_id", sa.Integer(), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["requirement_id"], ["regulatory_requirements.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["reviewed_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["subject_id"], ["compliance_subjects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "requirement_id", "subject_id", name="uq_applicability_tenant_requirement_subject"),
    )
    for column in ("id", "tenant_id", "requirement_id", "subject_id", "applicability_status", "origin", "priority", "human_review_required", "reviewed_by_id"):
        op.create_index(op.f(f"ix_applicability_assessments_{column}"), "applicability_assessments", [column], unique=False)

    op.create_table(
        "regulatory_impact_actions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("requirement_id", sa.Integer(), nullable=False),
        sa.Column("subject_id", sa.Integer(), nullable=False),
        sa.Column("action_type", sa.String(length=80), nullable=False),
        sa.Column("target_ref", sa.String(length=320), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("priority", sa.String(length=30), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=True),
        sa.Column("evidence_json", sa.Text(), nullable=False),
        sa.Column("human_review_required", sa.Boolean(), nullable=False),
        sa.Column("approved_by_id", sa.Integer(), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["approved_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["requirement_id"], ["regulatory_requirements.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["subject_id"], ["compliance_subjects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "requirement_id", "subject_id", "action_type", "target_ref", name="uq_regulatory_impact_action"),
    )
    for column in ("id", "tenant_id", "requirement_id", "subject_id", "action_type", "target_ref", "status", "priority", "approved_by_id"):
        op.create_index(op.f(f"ix_regulatory_impact_actions_{column}"), "regulatory_impact_actions", [column], unique=False)


def downgrade() -> None:
    for table, columns in (
        ("regulatory_impact_actions", ("approved_by_id", "priority", "status", "target_ref", "action_type", "subject_id", "requirement_id", "tenant_id", "id")),
        ("applicability_assessments", ("reviewed_by_id", "human_review_required", "priority", "origin", "applicability_status", "subject_id", "requirement_id", "tenant_id", "id")),
        ("requirement_relations", ("verified_by_id", "relation_type", "to_requirement_id", "from_requirement_id", "id")),
        ("compliance_subjects", ("created_by_id", "active", "parent_ref", "jurisdiction", "subject_key", "subject_type", "tenant_id", "id")),
    ):
        for column in columns:
            op.drop_index(op.f(f"ix_{table}_{column}"), table_name=table)
        op.drop_table(table)
