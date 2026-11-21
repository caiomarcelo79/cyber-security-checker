"""Estende ciclo de fontes de telemetria e cria tabelas de piloto e revisão de expansão."""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0013_pilot_rollout"
down_revision: str | None = "0012_ai_triage_suggestions"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "telemetry_sources",
        sa.Column("paused_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "telemetry_sources",
        sa.Column("collector_version", sa.String(32), nullable=True),
    )
    op.add_column(
        "telemetry_sources",
        sa.Column("desired_version", sa.String(32), nullable=True),
    )
    op.add_column(
        "telemetry_sources",
        sa.Column("poll_interval_seconds", sa.Integer, nullable=False, server_default="2"),
    )
    op.add_column(
        "telemetry_sources",
        sa.Column("config_version", sa.Integer, nullable=False, server_default="1"),
    )
    op.add_column(
        "telemetry_sources",
        sa.Column("applied_config_version", sa.Integer, nullable=True),
    )
    op.add_column(
        "telemetry_sources",
        sa.Column("token_generation", sa.Integer, nullable=False, server_default="1"),
    )
    op.add_column(
        "telemetry_sources",
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "telemetry_sources",
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_table(
        "pilot_enrollments",
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
        sa.Column("stage", sa.String(24), nullable=False),
        sa.Column("status", sa.String(24), nullable=False, server_default="ACTIVE"),
        sa.Column(
            "prerequisite_pilot_id",
            sa.String(36),
            sa.ForeignKey("pilot_enrollments.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("allowed_cidrs", sa.JSON, nullable=False),
        sa.Column("enabled_capabilities", sa.JSON, nullable=False),
        sa.Column("max_sources", sa.Integer, nullable=False, server_default="2"),
        sa.Column("scope_notes", sa.Text, nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("paused_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_by_user_id",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_pilot_enrollments_org", "pilot_enrollments", ["organization_id"])
    op.create_index("ix_pilot_enrollments_asset", "pilot_enrollments", ["asset_id"])
    op.create_index(
        "ix_pilot_enrollments_org_asset",
        "pilot_enrollments",
        ["organization_id", "asset_id"],
    )

    op.create_table(
        "pilot_reviews",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "pilot_id",
            sa.String(36),
            sa.ForeignKey("pilot_enrollments.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "organization_id",
            sa.String(36),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("decision", sa.String(32), nullable=False),
        sa.Column("coverage_ok", sa.Boolean, nullable=False),
        sa.Column("latency_ok", sa.Boolean, nullable=False),
        sa.Column("false_positives_ok", sa.Boolean, nullable=False),
        sa.Column(
            "reviewer_user_id",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("notes", sa.Text, nullable=True),
        sa.Column("metrics_snapshot", sa.JSON, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_pilot_reviews_pilot", "pilot_reviews", ["pilot_id"])
    op.create_index("ix_pilot_reviews_org", "pilot_reviews", ["organization_id"])
    op.create_index(
        "ix_pilot_reviews_pilot_created",
        "pilot_reviews",
        ["pilot_id", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_pilot_reviews_pilot_created", table_name="pilot_reviews")
    op.drop_index("ix_pilot_reviews_org", table_name="pilot_reviews")
    op.drop_index("ix_pilot_reviews_pilot", table_name="pilot_reviews")
    op.drop_table("pilot_reviews")

    op.drop_index("ix_pilot_enrollments_org_asset", table_name="pilot_enrollments")
    op.drop_index("ix_pilot_enrollments_asset", table_name="pilot_enrollments")
    op.drop_index("ix_pilot_enrollments_org", table_name="pilot_enrollments")
    op.drop_table("pilot_enrollments")

    op.drop_column("telemetry_sources", "updated_at")
    op.drop_column("telemetry_sources", "last_heartbeat_at")
    op.drop_column("telemetry_sources", "token_generation")
    op.drop_column("telemetry_sources", "applied_config_version")
    op.drop_column("telemetry_sources", "config_version")
    op.drop_column("telemetry_sources", "poll_interval_seconds")
    op.drop_column("telemetry_sources", "desired_version")
    op.drop_column("telemetry_sources", "collector_version")
    op.drop_column("telemetry_sources", "paused_at")
