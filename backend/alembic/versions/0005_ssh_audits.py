"""Histórico de auditorias de configuração do OpenSSH."""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0005_ssh_audits"
down_revision: str | None = "0004_phase8_revoked_tokens"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ssh_audits",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "asset_id", sa.String(36), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("password_authentication", sa.String(24), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_ssh_audits_asset_created_at", "ssh_audits", ["asset_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_ssh_audits_asset_created_at", table_name="ssh_audits")
    op.drop_table("ssh_audits")
