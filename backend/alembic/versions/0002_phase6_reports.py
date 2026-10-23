"""Migração da Fase 6: Relatórios profissionais e ciclo de vida de correções.

Revision ID: 0002_phase6_reports
Revises: 0001_initial_foundation
Create Date: 2026-10-22
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0002_phase6_reports"
down_revision: str | None = "0001_initial_foundation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Colunas adicionais em findings para ciclo de vida e revalidação (Fase 6)
    op.add_column(
        "findings",
        sa.Column("priority", sa.String(length=24), nullable=False, server_default="MEDIUM"),
    )
    op.add_column(
        "findings",
        sa.Column("sla_deadline", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "findings",
        sa.Column(
            "revalidation_scan_id",
            sa.String(length=36),
            sa.ForeignKey("scans.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.add_column(
        "findings",
        sa.Column("risk_acceptance_reason", sa.Text(), nullable=True),
    )

    # 2. Tabela reports para relatórios profissionais (PDF, HTML, JSON, CSV)
    op.create_table(
        "reports",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "organization_id",
            sa.String(length=36),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "created_by_user_id",
            sa.String(length=36),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("report_type", sa.String(length=40), nullable=False),
        sa.Column("format", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="PENDING"),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column(
            "asset_id",
            sa.String(length=36),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column(
            "scan_id",
            sa.String(length=36),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column(
            "finding_id",
            sa.String(length=36),
            sa.ForeignKey("findings.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column(
            "comparison_scan_id_a",
            sa.String(length=36),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column(
            "comparison_scan_id_b",
            sa.String(length=36),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("filter_params", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("summary_data", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("file_path", sa.String(length=512), nullable=True),
        sa.Column("file_size_bytes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("download_token", sa.String(length=128), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_reports_organization_id", "reports", ["organization_id"])
    op.create_index("ix_reports_created_by_user_id", "reports", ["created_by_user_id"])
    op.create_index("ix_reports_report_type", "reports", ["report_type"])
    op.create_index("ix_reports_format", "reports", ["format"])
    op.create_index("ix_reports_status", "reports", ["status"])
    op.create_index("ix_reports_asset_id", "reports", ["asset_id"])
    op.create_index("ix_reports_scan_id", "reports", ["scan_id"])
    op.create_index("ix_reports_download_token", "reports", ["download_token"])


def downgrade() -> None:
    op.drop_table("reports")
    op.drop_column("findings", "risk_acceptance_reason")
    op.drop_column("findings", "revalidation_scan_id")
    op.drop_column("findings", "sla_deadline")
    op.drop_column("findings", "priority")
