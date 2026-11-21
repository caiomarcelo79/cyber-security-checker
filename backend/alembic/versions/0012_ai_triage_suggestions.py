"""Tabela de sugestões revisáveis de triagem assistida por IA."""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0012_ai_triage_suggestions"
down_revision: str | None = "0011_traffic_edr_signals"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ai_triage_suggestions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "organization_id",
            sa.String(36),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "asset_id",
            sa.String(36),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("target_type", sa.String(24), nullable=False),
        sa.Column(
            "traffic_alert_id",
            sa.String(36),
            sa.ForeignKey("suspicious_traffic_alerts.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column(
            "finding_id",
            sa.String(36),
            sa.ForeignKey("findings.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("generation_mode", sa.String(32), nullable=False),
        sa.Column("ai_status", sa.String(32), nullable=False),
        sa.Column("model_name", sa.String(120), nullable=False),
        sa.Column("summary", sa.Text, nullable=False),
        sa.Column("explanation", sa.Text, nullable=False),
        sa.Column("recommended_action", sa.String(32), nullable=False),
        sa.Column("remediation_steps", sa.JSON, nullable=False),
        sa.Column("evidence_citations", sa.JSON, nullable=False),
        sa.Column("sanitized_evidence_hash", sa.String(64), nullable=False),
        sa.Column("review_status", sa.String(24), nullable=False, server_default="PENDING_REVIEW"),
        sa.Column(
            "reviewer_user_id",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("reviewer_notes", sa.Text, nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_ai_triage_org", "ai_triage_suggestions", ["organization_id"])
    op.create_index("ix_ai_triage_asset", "ai_triage_suggestions", ["asset_id"])
    op.create_index(
        "ix_ai_triage_traffic_alert",
        "ai_triage_suggestions",
        ["traffic_alert_id", "created_at"],
    )
    op.create_index("ix_ai_triage_finding", "ai_triage_suggestions", ["finding_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_ai_triage_finding", table_name="ai_triage_suggestions")
    op.drop_index("ix_ai_triage_traffic_alert", table_name="ai_triage_suggestions")
    op.drop_index("ix_ai_triage_asset", table_name="ai_triage_suggestions")
    op.drop_index("ix_ai_triage_org", table_name="ai_triage_suggestions")
    op.drop_table("ai_triage_suggestions")
