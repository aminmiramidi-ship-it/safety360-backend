"""Add tenant-scoped OIDC SSO identity tables.

Revision ID: 0007_federated_identity
Revises: 0006_agent_memory
Create Date: 2026-09-19
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007_federated_identity"
down_revision: str | None = "0006_agent_memory"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "tenant_identity_providers",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("issuer_url", sa.String(length=500), nullable=False),
        sa.Column("client_id", sa.String(length=255), nullable=False),
        sa.Column("client_secret_env", sa.String(length=160), nullable=True),
        sa.Column("scopes", sa.String(length=500), nullable=False),
        sa.Column("allowed_domains_json", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("auto_provision", sa.Boolean(), nullable=False),
        sa.Column("auto_link_verified_email", sa.Boolean(), nullable=False),
        sa.Column("created_by_id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id"),
        sa.UniqueConstraint("tenant_id", "name", name="uq_tenant_identity_provider_name"),
    )
    op.create_index(op.f("ix_tenant_identity_providers_id"), "tenant_identity_providers", ["id"], unique=False)
    op.create_index(op.f("ix_tenant_identity_providers_tenant_id"), "tenant_identity_providers", ["tenant_id"], unique=True)
    op.create_index(op.f("ix_tenant_identity_providers_created_by_id"), "tenant_identity_providers", ["created_by_id"], unique=False)

    op.create_table(
        "federated_identities",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("provider_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("issuer", sa.String(length=500), nullable=False),
        sa.Column("subject", sa.String(length=500), nullable=False),
        sa.Column("email_at_link", sa.String(length=320), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["provider_id"], ["tenant_identity_providers.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("provider_id", "subject", name="uq_federated_identity_provider_subject"),
        sa.UniqueConstraint("provider_id", "user_id", name="uq_federated_identity_provider_user"),
    )
    op.create_index(op.f("ix_federated_identities_id"), "federated_identities", ["id"], unique=False)
    op.create_index(op.f("ix_federated_identities_tenant_id"), "federated_identities", ["tenant_id"], unique=False)
    op.create_index(op.f("ix_federated_identities_provider_id"), "federated_identities", ["provider_id"], unique=False)
    op.create_index(op.f("ix_federated_identities_user_id"), "federated_identities", ["user_id"], unique=False)

    op.create_table(
        "sso_exchange_codes",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("code_hash", sa.String(length=64), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("code_hash"),
    )
    op.create_index(op.f("ix_sso_exchange_codes_id"), "sso_exchange_codes", ["id"], unique=False)
    op.create_index(op.f("ix_sso_exchange_codes_code_hash"), "sso_exchange_codes", ["code_hash"], unique=True)
    op.create_index(op.f("ix_sso_exchange_codes_tenant_id"), "sso_exchange_codes", ["tenant_id"], unique=False)
    op.create_index(op.f("ix_sso_exchange_codes_user_id"), "sso_exchange_codes", ["user_id"], unique=False)
    op.create_index(op.f("ix_sso_exchange_codes_expires_at"), "sso_exchange_codes", ["expires_at"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_sso_exchange_codes_expires_at"), table_name="sso_exchange_codes")
    op.drop_index(op.f("ix_sso_exchange_codes_user_id"), table_name="sso_exchange_codes")
    op.drop_index(op.f("ix_sso_exchange_codes_tenant_id"), table_name="sso_exchange_codes")
    op.drop_index(op.f("ix_sso_exchange_codes_code_hash"), table_name="sso_exchange_codes")
    op.drop_index(op.f("ix_sso_exchange_codes_id"), table_name="sso_exchange_codes")
    op.drop_table("sso_exchange_codes")

    op.drop_index(op.f("ix_federated_identities_user_id"), table_name="federated_identities")
    op.drop_index(op.f("ix_federated_identities_provider_id"), table_name="federated_identities")
    op.drop_index(op.f("ix_federated_identities_tenant_id"), table_name="federated_identities")
    op.drop_index(op.f("ix_federated_identities_id"), table_name="federated_identities")
    op.drop_table("federated_identities")

    op.drop_index(op.f("ix_tenant_identity_providers_created_by_id"), table_name="tenant_identity_providers")
    op.drop_index(op.f("ix_tenant_identity_providers_tenant_id"), table_name="tenant_identity_providers")
    op.drop_index(op.f("ix_tenant_identity_providers_id"), table_name="tenant_identity_providers")
    op.drop_table("tenant_identity_providers")
