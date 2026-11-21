"""Exercícios de disponibilidade e amostras de latência de laboratório."""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0008_availability_exercises"
down_revision: str | None = "0007_network_telemetry"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "availability_exercises",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("asset_id", sa.String(36), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("created_by_user_id", sa.String(36), nullable=False),
        sa.Column("status", sa.String(12), nullable=False),
        sa.Column("result", sa.String(16), nullable=True),
        sa.Column("threshold_ms", sa.Integer, nullable=False),
        sa.Column("consecutive_samples", sa.Integer, nullable=False),
        sa.Column("interval_ms", sa.Integer, nullable=False),
        sa.Column("normal_ms", sa.Integer, nullable=False),
        sa.Column("degraded_ms", sa.Integer, nullable=False),
        sa.Column("alert_notification_id", sa.String(36), nullable=True),
        sa.Column("recovery_notification_id", sa.String(36), nullable=True),
        sa.Column("alert_publication_ms", sa.Integer, nullable=True),
        sa.Column("recovery_publication_ms", sa.Integer, nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_availability_exercises_asset_started", "availability_exercises", ["asset_id", "started_at"]
    )
    op.create_table(
        "availability_samples",
        sa.Column(
            "exercise_id",
            sa.String(36),
            sa.ForeignKey("availability_exercises.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("seq", sa.Integer, primary_key=True),
        sa.Column("offset_ms", sa.Integer, nullable=False),
        sa.Column("latency_ms", sa.Float, nullable=True),
        sa.Column("outcome", sa.String(20), nullable=False),
        sa.Column("http_status", sa.Integer, nullable=True),
    )


def downgrade() -> None:
    op.drop_table("availability_samples")
    op.drop_index("ix_availability_exercises_asset_started", table_name="availability_exercises")
    op.drop_table("availability_exercises")
