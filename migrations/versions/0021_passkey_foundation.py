"""Add passkey credentials and WebAuthn ceremonies.

Revision ID: 0021_passkey_foundation
Revises: 0020_login_protection
Create Date: 2026-09-19
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0021_passkey_foundation"
down_revision: str | None = "0020_login_protection"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "webauthn_user_handles",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("handle", sa.String(length=86), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("handle"),
        sa.UniqueConstraint("user_id"),
    )
    op.create_index(op.f("ix_webauthn_user_handles_id"), "webauthn_user_handles", ["id"], unique=False)
    op.create_index(
        op.f("ix_webauthn_user_handles_user_id"),
        "webauthn_user_handles",
        ["user_id"],
        unique=True,
    )
    op.create_index(
        op.f("ix_webauthn_user_handles_handle"),
        "webauthn_user_handles",
        ["handle"],
        unique=True,
    )

    op.create_table(
        "passkey_credentials",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("credential_id", sa.String(length=1024), nullable=False),
        sa.Column("credential_public_key", sa.Text(), nullable=False),
        sa.Column("sign_count", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=True),
        sa.Column("nickname", sa.String(length=120), nullable=True),
        sa.Column("transports_json", sa.Text(), nullable=True),
        sa.Column("device_type", sa.String(length=40), nullable=True),
        sa.Column("backed_up", sa.Boolean(), nullable=False),
        sa.Column("aaguid", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("credential_id"),
    )
    op.create_index(op.f("ix_passkey_credentials_id"), "passkey_credentials", ["id"], unique=False)
    op.create_index(
        op.f("ix_passkey_credentials_credential_id"),
        "passkey_credentials",
        ["credential_id"],
        unique=True,
    )
    op.create_index(
        op.f("ix_passkey_credentials_user_id"),
        "passkey_credentials",
        ["user_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_passkey_credentials_tenant_id"),
        "passkey_credentials",
        ["tenant_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_passkey_credentials_revoked_at"),
        "passkey_credentials",
        ["revoked_at"],
        unique=False,
    )

    op.create_table(
        "webauthn_ceremonies",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("ceremony_id", sa.String(length=36), nullable=False),
        sa.Column("purpose", sa.String(length=24), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("challenge", sa.String(length=256), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("ceremony_id"),
    )
    op.create_index(op.f("ix_webauthn_ceremonies_id"), "webauthn_ceremonies", ["id"], unique=False)
    op.create_index(
        op.f("ix_webauthn_ceremonies_ceremony_id"),
        "webauthn_ceremonies",
        ["ceremony_id"],
        unique=True,
    )
    op.create_index(
        op.f("ix_webauthn_ceremonies_purpose"),
        "webauthn_ceremonies",
        ["purpose"],
        unique=False,
    )
    op.create_index(
        op.f("ix_webauthn_ceremonies_user_id"),
        "webauthn_ceremonies",
        ["user_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_webauthn_ceremonies_expires_at"),
        "webauthn_ceremonies",
        ["expires_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_webauthn_ceremonies_used_at"),
        "webauthn_ceremonies",
        ["used_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_table("webauthn_ceremonies")
    op.drop_table("passkey_credentials")
    op.drop_table("webauthn_user_handles")
