"""Migração da Fase 7: Automação, Agendamentos, Notificações, Webhooks e API Tokens.

Revision ID: 0003_phase7_automations
Revises: 0002_phase6_reports
Create Date: 2026-10-22
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0003_phase7_automations"
down_revision: str | None = "0002_phase6_reports"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Atualizar scan_schedules com colunas da Fase 7
    op.add_column(
        "scan_schedules",
        sa.Column("frequency", sa.String(length=30), nullable=False, server_default="DAILY"),
    )
    op.add_column(
        "scan_schedules",
        sa.Column("timezone", sa.String(length=60), nullable=False, server_default="UTC"),
    )
    op.add_column(
        "scan_schedules",
        sa.Column("status", sa.String(length=30), nullable=False, server_default="ACTIVE"),
    )
    op.add_column(
        "scan_schedules",
        sa.Column("enabled_modules", sa.JSON(), nullable=False, server_default="[]"),
    )
    op.add_column(
        "scan_schedules",
        sa.Column("misfire_policy", sa.String(length=30), nullable=False, server_default="SKIP"),
    )
    op.add_column(
        "scan_schedules",
        sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "scan_schedules",
        sa.Column("last_scan_id", sa.String(length=36), nullable=True),
    )
    op.add_column(
        "scan_schedules",
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_scan_schedules_status", "scan_schedules", ["status"])
    op.create_index("ix_scan_schedules_next_run_at", "scan_schedules", ["next_run_at"])

    # 2. Adicionar schedule_id em scans
    op.add_column(
        "scans",
        sa.Column(
            "schedule_id",
            sa.String(length=36),
            sa.ForeignKey("scan_schedules.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index("ix_scans_schedule_id", "scans", ["schedule_id"])

    # 3. Tabela de notificações internas
    op.create_table(
        "notifications",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "organization_id",
            sa.String(length=36),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            sa.String(length=36),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("event_type", sa.String(length=60), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False, server_default="INFO"),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("link_url", sa.String(length=500), nullable=True),
        sa.Column("read_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_index("ix_notifications_organization_id", "notifications", ["organization_id"])
    op.create_index("ix_notifications_user_id", "notifications", ["user_id"])
    op.create_index("ix_notifications_event_type", "notifications", ["event_type"])
    op.create_index("ix_notifications_read_at", "notifications", ["read_at"])
    op.create_index("ix_notifications_created_at", "notifications", ["created_at"])

    # 4. Tabela de preferências de notificação
    op.create_table(
        "notification_preferences",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "organization_id",
            sa.String(length=36),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            sa.String(length=36),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("email_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("email_destination", sa.String(length=255), nullable=True),
        sa.Column("channels", sa.JSON(), nullable=False, server_default='["IN_APP"]'),
        sa.Column("min_severity", sa.String(length=20), nullable=False, server_default="MEDIUM"),
        sa.Column("subscribed_events", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_notification_preferences_organization_id", "notification_preferences", ["organization_id"]
    )
    op.create_index("ix_notification_preferences_user_id", "notification_preferences", ["user_id"])

    # 5. Tabela de webhook_endpoints
    op.create_table(
        "webhook_endpoints",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "organization_id",
            sa.String(length=36),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("url", sa.String(length=1000), nullable=False),
        sa.Column("description", sa.String(length=255), nullable=True),
        sa.Column("secret_token", sa.String(length=128), nullable=False),
        sa.Column("subscribed_events", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "created_by_user_id",
            sa.String(length=36),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_webhook_endpoints_organization_id", "webhook_endpoints", ["organization_id"])

    # 6. Tabela de webhook_deliveries
    op.create_table(
        "webhook_deliveries",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "webhook_id",
            sa.String(length=36),
            sa.ForeignKey("webhook_endpoints.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "organization_id",
            sa.String(length=36),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("event_type", sa.String(length=60), nullable=False),
        sa.Column("event_id", sa.String(length=64), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("response_body", sa.Text(), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("next_retry_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_index("ix_webhook_deliveries_webhook_id", "webhook_deliveries", ["webhook_id"])
    op.create_index("ix_webhook_deliveries_organization_id", "webhook_deliveries", ["organization_id"])
    op.create_index("ix_webhook_deliveries_event_type", "webhook_deliveries", ["event_type"])
    op.create_index("ix_webhook_deliveries_event_id", "webhook_deliveries", ["event_id"])
    op.create_index("ix_webhook_deliveries_status", "webhook_deliveries", ["status"])
    op.create_index("ix_webhook_deliveries_created_at", "webhook_deliveries", ["created_at"])

    # 7. Tabela de api_tokens
    op.create_table(
        "api_tokens",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "organization_id",
            sa.String(length=36),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            sa.String(length=36),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("token_prefix", sa.String(length=16), nullable=False),
        sa.Column("token_hash", sa.String(length=128), unique=True, nullable=False),
        sa.Column("scopes", sa.JSON(), nullable=False, server_default='["scans:read"]'),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_revoked", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_index("ix_api_tokens_organization_id", "api_tokens", ["organization_id"])
    op.create_index("ix_api_tokens_user_id", "api_tokens", ["user_id"])
    op.create_index("ix_api_tokens_token_hash", "api_tokens", ["token_hash"])
    op.create_index("ix_api_tokens_expires_at", "api_tokens", ["expires_at"])

    # 8. Tabela de scan_templates
    op.create_table(
        "scan_templates",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "organization_id",
            sa.String(length=36),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("profile_type", sa.String(length=40), nullable=False, server_default="QUICK"),
        sa.Column("enabled_modules", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("parameters", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("environment_type", sa.String(length=30), nullable=True),
        sa.Column(
            "created_by_user_id",
            sa.String(length=36),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_scan_templates_organization_id", "scan_templates", ["organization_id"])


def downgrade() -> None:
    op.drop_table("scan_templates")
    op.drop_table("api_tokens")
    op.drop_table("webhook_deliveries")
    op.drop_table("webhook_endpoints")
    op.drop_table("notification_preferences")
    op.drop_table("notifications")

    op.drop_index("ix_scans_schedule_id", table_name="scans")
    op.drop_column("scans", "schedule_id")

    op.drop_index("ix_scan_schedules_next_run_at", table_name="scan_schedules")
    op.drop_index("ix_scan_schedules_status", table_name="scan_schedules")
    op.drop_column("scan_schedules", "updated_at")
    op.drop_column("scan_schedules", "last_scan_id")
    op.drop_column("scan_schedules", "consecutive_failures")
    op.drop_column("scan_schedules", "misfire_policy")
    op.drop_column("scan_schedules", "enabled_modules")
    op.drop_column("scan_schedules", "status")
    op.drop_column("scan_schedules", "timezone")
    op.drop_column("scan_schedules", "frequency")
