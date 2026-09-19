"""Add occupational health orchestration and integration registry.

Revision ID: 0014_occ_health_integrations
Revises: 0013_legal_knowledge_graph
Create Date: 2026-09-19
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0014_occ_health_integrations"
down_revision: str | None = "0013_legal_knowledge_graph"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _index(table: str, columns: tuple[str, ...]) -> None:
    for column in columns:
        op.create_index(op.f(f"ix_{table}_{column}"), table, [column], unique=False)


def upgrade() -> None:
    op.create_table(
        "tenant_integrations",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("provider_key", sa.String(length=100), nullable=False),
        sa.Column("connection_key", sa.String(length=160), nullable=False),
        sa.Column("display_name", sa.String(length=240), nullable=False),
        sa.Column("integration_type", sa.String(length=80), nullable=False),
        sa.Column("base_url", sa.String(length=1000), nullable=True),
        sa.Column("auth_type", sa.String(length=80), nullable=False),
        sa.Column("secret_ref", sa.String(length=240), nullable=True),
        sa.Column("scopes_json", sa.Text(), nullable=False),
        sa.Column("capabilities_json", sa.Text(), nullable=False),
        sa.Column("data_classes_json", sa.Text(), nullable=False),
        sa.Column("approved_purposes_json", sa.Text(), nullable=False),
        sa.Column("region", sa.String(length=80), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("external_processing_allowed", sa.Boolean(), nullable=False),
        sa.Column("minimum_disclosure", sa.Boolean(), nullable=False),
        sa.Column("human_review_required", sa.Boolean(), nullable=False),
        sa.Column("created_by_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "provider_key", "connection_key", name="uq_tenant_integration_provider_connection"),
    )
    _index("tenant_integrations", ("id", "tenant_id", "provider_key", "connection_key", "integration_type", "auth_type", "enabled", "created_by_id"))

    op.create_table(
        "integration_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("integration_id", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(length=100), nullable=False),
        sa.Column("direction", sa.String(length=20), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("subject_ref", sa.String(length=320), nullable=True),
        sa.Column("correlation_id", sa.String(length=120), nullable=True),
        sa.Column("payload_classification", sa.String(length=80), nullable=False),
        sa.Column("metadata_json", sa.Text(), nullable=False),
        sa.Column("error_code", sa.String(length=120), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["integration_id"], ["tenant_integrations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    _index("integration_events", ("id", "tenant_id", "integration_id", "event_type", "direction", "status", "subject_ref", "correlation_id", "payload_classification", "created_at"))

    op.create_table(
        "occupational_health_requirements",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("requirement_key", sa.String(length=240), nullable=False),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("requirement_kind", sa.String(length=60), nullable=False),
        sa.Column("trigger_type", sa.String(length=80), nullable=False),
        sa.Column("trigger_ref", sa.String(length=320), nullable=False),
        sa.Column("legal_basis_ref", sa.String(length=500), nullable=True),
        sa.Column("source_requirement_id", sa.Integer(), nullable=True),
        sa.Column("recurrence_days", sa.Integer(), nullable=True),
        sa.Column("due_soon_days", sa.Integer(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("human_review_required", sa.Boolean(), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_by_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["source_requirement_id"], ["regulatory_requirements.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "requirement_key", name="uq_occupational_health_requirement_tenant_key"),
    )
    _index("occupational_health_requirements", ("id", "tenant_id", "requirement_key", "requirement_kind", "trigger_type", "trigger_ref", "source_requirement_id", "active", "created_by_id"))

    op.create_table(
        "occupational_health_cases",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("requirement_id", sa.Integer(), nullable=False),
        sa.Column("employee_ref", sa.String(length=320), nullable=False),
        sa.Column("employee_user_id", sa.Integer(), nullable=True),
        sa.Column("manager_ref", sa.String(length=320), nullable=True),
        sa.Column("provider_ref", sa.String(length=320), nullable=True),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("workflow_state", sa.String(length=60), nullable=False),
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_due_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("evidence_state", sa.String(length=40), nullable=False),
        sa.Column("privacy_classification", sa.String(length=60), nullable=False),
        sa.Column("employer_visible_summary", sa.String(length=500), nullable=True),
        sa.Column("last_evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("human_review_required", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["employee_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["requirement_id"], ["occupational_health_requirements.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "requirement_id", "employee_ref", name="uq_occupational_health_case_employee_requirement"),
    )
    _index("occupational_health_cases", ("id", "tenant_id", "requirement_id", "employee_ref", "employee_user_id", "manager_ref", "provider_ref", "status", "workflow_state", "due_at", "next_due_at", "evidence_state", "privacy_classification", "human_review_required"))

    op.create_table(
        "occupational_health_appointments",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("case_id", sa.Integer(), nullable=False),
        sa.Column("provider_ref", sa.String(length=320), nullable=True),
        sa.Column("proposal_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("proposal_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("timezone_name", sa.String(length=80), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("employee_calendar_provider", sa.String(length=60), nullable=True),
        sa.Column("provider_calendar_provider", sa.String(length=60), nullable=True),
        sa.Column("external_event_ref", sa.String(length=500), nullable=True),
        sa.Column("consent_or_legal_basis_ref", sa.String(length=500), nullable=True),
        sa.Column("minimum_disclosure_confirmed", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.String(length=40), nullable=False),
        sa.Column("approved_by_id", sa.Integer(), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["approved_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["case_id"], ["occupational_health_cases.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    _index("occupational_health_appointments", ("id", "tenant_id", "case_id", "provider_ref", "proposal_start", "proposal_end", "status", "external_event_ref", "created_by", "approved_by_id"))

    op.create_table(
        "occupational_health_evidence",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("case_id", sa.Integer(), nullable=False),
        sa.Column("evidence_type", sa.String(length=80), nullable=False),
        sa.Column("file_ref", sa.String(length=500), nullable=True),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_due_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("source", sa.String(length=80), nullable=False),
        sa.Column("contains_clinical_findings", sa.Boolean(), nullable=False),
        sa.Column("employer_access_allowed", sa.Boolean(), nullable=False),
        sa.Column("clinician_only", sa.Boolean(), nullable=False),
        sa.Column("verified", sa.Boolean(), nullable=False),
        sa.Column("verified_by_id", sa.Integer(), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("metadata_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["occupational_health_cases.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["verified_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    _index("occupational_health_evidence", ("id", "tenant_id", "case_id", "evidence_type", "source", "contains_clinical_findings", "employer_access_allowed", "clinician_only", "verified", "verified_by_id"))

    op.create_table(
        "occupational_health_notifications",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("case_id", sa.Integer(), nullable=False),
        sa.Column("recipient_type", sa.String(length=40), nullable=False),
        sa.Column("recipient_ref", sa.String(length=320), nullable=False),
        sa.Column("channel", sa.String(length=40), nullable=False),
        sa.Column("template_key", sa.String(length=160), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("scheduled_for", sa.DateTime(timezone=True), nullable=False),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("minimum_disclosure", sa.Boolean(), nullable=False),
        sa.Column("error_code", sa.String(length=120), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["occupational_health_cases.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    _index("occupational_health_notifications", ("id", "tenant_id", "case_id", "recipient_type", "recipient_ref", "channel", "status", "scheduled_for"))


def downgrade() -> None:
    for table in (
        "occupational_health_notifications",
        "occupational_health_evidence",
        "occupational_health_appointments",
        "occupational_health_cases",
        "occupational_health_requirements",
        "integration_events",
        "tenant_integrations",
    ):
        op.drop_table(table)
