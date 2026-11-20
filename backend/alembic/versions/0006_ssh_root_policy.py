"""Observação da política de acesso root no histórico de SSH."""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0006_ssh_root_policy"
down_revision: str | None = "0005_ssh_audits"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("ssh_audits", sa.Column("permit_root_login", sa.String(24), nullable=True))


def downgrade() -> None:
    op.drop_column("ssh_audits", "permit_root_login")
