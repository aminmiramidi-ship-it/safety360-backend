"""Add persistent adaptive agent memory.

Revision ID: 0006_agent_memory
Revises: 0005_ims_orchestration
Create Date: 2026-09-19
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006_agent_memory"
down_revision: str | None = "0005_ims_orchestration"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "agent_runs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("created_by_id", sa.Integer(), nullable=False),
        sa.Column("objective_hash", sa.String(length=64), nullable=False),
        sa.Column("selected_agents_json", sa.Text(), nullable=False),
        sa.Column(
            "learning_mode",
            sa.String(length=80),
            server_default="feedback_and_outcome_adaptation",
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("run_id"),
    )
    op.create_index(op.f("ix_agent_runs_id"), "agent_runs", ["id"], unique=False)
    op.create_index(op.f("ix_agent_runs_run_id"), "agent_runs", ["run_id"], unique=True)
    op.create_index(op.f("ix_agent_runs_tenant_id"), "agent_runs", ["tenant_id"], unique=False)
    op.create_index(op.f("ix_agent_runs_created_by_id"), "agent_runs", ["created_by_id"], unique=False)
    op.create_index(op.f("ix_agent_runs_objective_hash"), "agent_runs", ["objective_hash"], unique=False)

    op.create_table(
        "agent_feedback",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("agent_id", sa.String(length=50), nullable=False),
        sa.Column("outcome", sa.String(length=30), nullable=False),
        sa.Column("rating", sa.Integer(), nullable=False),
        sa.Column("workflow", sa.String(length=80), server_default="general", nullable=False),
        sa.Column("created_by_id", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["run_id"], ["agent_runs.run_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("run_id", "agent_id", name="uq_agent_feedback_run_agent"),
    )
    op.create_index(op.f("ix_agent_feedback_id"), "agent_feedback", ["id"], unique=False)
    op.create_index(op.f("ix_agent_feedback_tenant_id"), "agent_feedback", ["tenant_id"], unique=False)
    op.create_index(op.f("ix_agent_feedback_run_id"), "agent_feedback", ["run_id"], unique=False)
    op.create_index(op.f("ix_agent_feedback_agent_id"), "agent_feedback", ["agent_id"], unique=False)
    op.create_index(op.f("ix_agent_feedback_outcome"), "agent_feedback", ["outcome"], unique=False)
    op.create_index(op.f("ix_agent_feedback_workflow"), "agent_feedback", ["workflow"], unique=False)
    op.create_index(op.f("ix_agent_feedback_created_by_id"), "agent_feedback", ["created_by_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_agent_feedback_created_by_id"), table_name="agent_feedback")
    op.drop_index(op.f("ix_agent_feedback_workflow"), table_name="agent_feedback")
    op.drop_index(op.f("ix_agent_feedback_outcome"), table_name="agent_feedback")
    op.drop_index(op.f("ix_agent_feedback_agent_id"), table_name="agent_feedback")
    op.drop_index(op.f("ix_agent_feedback_run_id"), table_name="agent_feedback")
    op.drop_index(op.f("ix_agent_feedback_tenant_id"), table_name="agent_feedback")
    op.drop_index(op.f("ix_agent_feedback_id"), table_name="agent_feedback")
    op.drop_table("agent_feedback")

    op.drop_index(op.f("ix_agent_runs_objective_hash"), table_name="agent_runs")
    op.drop_index(op.f("ix_agent_runs_created_by_id"), table_name="agent_runs")
    op.drop_index(op.f("ix_agent_runs_tenant_id"), table_name="agent_runs")
    op.drop_index(op.f("ix_agent_runs_run_id"), table_name="agent_runs")
    op.drop_index(op.f("ix_agent_runs_id"), table_name="agent_runs")
    op.drop_table("agent_runs")
