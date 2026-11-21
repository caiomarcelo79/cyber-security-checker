"""Sinais opcionais de antivírus/EDR correlacionados à análise de tráfego suspeito."""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0011_traffic_edr_signals"
down_revision: str | None = "0010_suspicious_traffic"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "traffic_analysis_runs",
        sa.Column("edr_count", sa.Integer, nullable=False, server_default="0"),
    )
    op.create_table(
        "traffic_edr_signals",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "run_id",
            sa.String(36),
            sa.ForeignKey("traffic_analysis_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("uid", sa.String(64), nullable=False),
        sa.Column("host_ip", sa.String(45), nullable=False),
        sa.Column("source_type", sa.String(16), nullable=False),
        sa.Column("signal", sa.String(32), nullable=False),
        sa.Column("process_name", sa.String(120), nullable=False),
        sa.Column("detail", sa.String(255), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_traffic_edr_signals_run", "traffic_edr_signals", ["run_id"])


def downgrade() -> None:
    op.drop_index("ix_traffic_edr_signals_run", table_name="traffic_edr_signals")
    op.drop_table("traffic_edr_signals")
    op.drop_column("traffic_analysis_runs", "edr_count")
