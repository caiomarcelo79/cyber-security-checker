"""Fontes e observações limitadas de telemetria de rede."""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0007_network_telemetry"
down_revision: str | None = "0006_ssh_root_policy"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "telemetry_sources",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("asset_id", sa.String(36), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("network", sa.String(49), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_received_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_telemetry_sources_asset_id", "telemetry_sources", ["asset_id"])
    op.create_table(
        "telemetry_connections",
        sa.Column(
            "source_id",
            sa.String(36),
            sa.ForeignKey("telemetry_sources.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("uid", sa.String(64), primary_key=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("origin_ip", sa.String(45), nullable=False),
        sa.Column("origin_port", sa.Integer, nullable=False),
        sa.Column("responder_ip", sa.String(45), nullable=False),
        sa.Column("responder_port", sa.Integer, nullable=False),
        sa.Column("transport", sa.String(5), nullable=False),
        sa.Column("origin_bytes", sa.BigInteger, nullable=True),
        sa.Column("responder_bytes", sa.BigInteger, nullable=True),
    )
    op.create_index("ix_telemetry_connections_received_at", "telemetry_connections", ["received_at"])


def downgrade() -> None:
    op.drop_index("ix_telemetry_connections_received_at", table_name="telemetry_connections")
    op.drop_table("telemetry_connections")
    op.drop_index("ix_telemetry_sources_asset_id", table_name="telemetry_sources")
    op.drop_table("telemetry_sources")
