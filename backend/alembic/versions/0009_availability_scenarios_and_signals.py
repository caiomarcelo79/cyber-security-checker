"""Cenários de disponibilidade (erros e saturação) e sinais externos de borda/provedor."""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0009_availability_signals"
down_revision: str | None = "0008_availability_exercises"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "availability_exercises",
        sa.Column("scenario", sa.String(16), nullable=False, server_default="LATENCY"),
    )
    op.create_table(
        "availability_signals",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "exercise_id",
            sa.String(36),
            sa.ForeignKey("availability_exercises.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("source_type", sa.String(16), nullable=False),
        sa.Column("signal", sa.String(24), nullable=False),
        sa.Column("offset_ms", sa.Integer, nullable=False),
        sa.Column("http_status", sa.Integer, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_availability_signals_exercise_offset",
        "availability_signals",
        ["exercise_id", "offset_ms"],
    )


def downgrade() -> None:
    op.drop_index("ix_availability_signals_exercise_offset", table_name="availability_signals")
    op.drop_table("availability_signals")
    op.drop_column("availability_exercises", "scenario")
