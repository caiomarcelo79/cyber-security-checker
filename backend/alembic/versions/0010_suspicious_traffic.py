"""Tabelas de linha de base TLS e análises explicáveis de tráfego suspeito."""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0010_suspicious_traffic"
down_revision: str | None = "0009_availability_signals"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "telemetry_tls_baselines",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "source_id",
            sa.String(36),
            sa.ForeignKey("telemetry_sources.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("server_name", sa.String(255), nullable=False),
        sa.Column("responder_ip", sa.String(45), nullable=False),
        sa.Column("responder_port", sa.Integer, nullable=False),
        sa.Column("cert_sha256", sa.String(64), nullable=False),
        sa.Column("subject", sa.String(255), nullable=False),
        sa.Column("issuer", sa.String(255), nullable=False),
        sa.Column("not_before", sa.DateTime(timezone=True), nullable=False),
        sa.Column("not_after", sa.DateTime(timezone=True), nullable=False),
        sa.Column("rotation_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "source_id",
            "server_name",
            "responder_ip",
            "responder_port",
            name="uq_tls_baseline_target",
        ),
    )

    op.create_table(
        "traffic_analysis_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "asset_id",
            sa.String(36),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "source_id",
            sa.String(36),
            sa.ForeignKey("telemetry_sources.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("observed_layers", sa.JSON, nullable=False),
        sa.Column("missing_layers", sa.JSON, nullable=False),
        sa.Column("connection_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("dns_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("tls_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("alerts_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("benign_rotations_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_traffic_analysis_runs_asset_created",
        "traffic_analysis_runs",
        ["asset_id", "created_at"],
    )

    op.create_table(
        "suspicious_traffic_alerts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "run_id",
            sa.String(36),
            sa.ForeignKey("traffic_analysis_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("rule_id", sa.String(64), nullable=False),
        sa.Column("category", sa.String(24), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("confidence", sa.String(16), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("explanation", sa.Text, nullable=False),
        sa.Column("evidence", sa.JSON, nullable=False),
        sa.Column("observed_layers", sa.JSON, nullable=False),
        sa.Column("missing_layers", sa.JSON, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_suspicious_traffic_alerts_run", "suspicious_traffic_alerts", ["run_id"])

    op.create_table(
        "traffic_tls_decisions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "run_id",
            sa.String(36),
            sa.ForeignKey("traffic_analysis_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("uid", sa.String(64), nullable=False),
        sa.Column("server_name", sa.String(255), nullable=False),
        sa.Column("responder_ip", sa.String(45), nullable=False),
        sa.Column("responder_port", sa.Integer, nullable=False),
        sa.Column("outcome", sa.String(32), nullable=False),
        sa.Column("observed_cert_sha256", sa.String(64), nullable=False),
        sa.Column("previous_cert_sha256", sa.String(64), nullable=True),
        sa.Column("observed_issuer", sa.String(255), nullable=False),
        sa.Column("previous_issuer", sa.String(255), nullable=True),
        sa.Column("reason", sa.String(255), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_traffic_tls_decisions_run", "traffic_tls_decisions", ["run_id"])


def downgrade() -> None:
    op.drop_index("ix_traffic_tls_decisions_run", table_name="traffic_tls_decisions")
    op.drop_table("traffic_tls_decisions")
    op.drop_index("ix_suspicious_traffic_alerts_run", table_name="suspicious_traffic_alerts")
    op.drop_table("suspicious_traffic_alerts")
    op.drop_index("ix_traffic_analysis_runs_asset_created", table_name="traffic_analysis_runs")
    op.drop_table("traffic_analysis_runs")
    op.drop_table("telemetry_tls_baselines")
