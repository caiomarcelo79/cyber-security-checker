"""Migração inicial da fundação do cyber-security-checker (Fase 1).

Revision ID: 0001_initial_foundation
Revises: None
Create Date: 2026-10-21
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0001_initial_foundation"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "organizations",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("slug", sa.String(length=120), nullable=False, unique=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_organizations_slug", "organizations", ["slug"], unique=True)

    op.create_table(
        "users",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("email", sa.String(length=255), nullable=False, unique=True),
        sa.Column("hashed_password", sa.String(length=255), nullable=False),
        sa.Column("full_name", sa.String(length=160), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.create_table(
        "organization_memberships",
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
        sa.Column("role", sa.String(length=40), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_organization_memberships_organization_id",
        "organization_memberships",
        ["organization_id"],
    )
    op.create_index("ix_organization_memberships_user_id", "organization_memberships", ["user_id"])

    op.create_table(
        "assets",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "organization_id",
            sa.String(length=36),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(length=180), nullable=False),
        sa.Column("target_url", sa.String(length=512), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column("asset_type", sa.String(length=40), nullable=False),
        sa.Column("environment", sa.String(length=40), nullable=False),
        sa.Column("owner_name", sa.String(length=160), nullable=False),
        sa.Column("owner_email", sa.String(length=255), nullable=False),
        sa.Column("tags", sa.JSON(), nullable=False),
        sa.Column("excluded_paths", sa.JSON(), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("authorization_status", sa.String(length=40), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_assets_organization_id", "assets", ["organization_id"])
    op.create_index("ix_assets_hostname", "assets", ["hostname"])
    op.create_index("ix_assets_authorization_status", "assets", ["authorization_status"])

    op.create_table(
        "target_authorizations",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "asset_id",
            sa.String(length=36),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "organization_id",
            sa.String(length=36),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("method", sa.String(length=40), nullable=False),
        sa.Column("verification_token", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column(
            "verified_by_user_id",
            sa.String(length=36),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("scope_notes", sa.Text(), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_target_authorizations_asset_id", "target_authorizations", ["asset_id"])
    op.create_index(
        "ix_target_authorizations_organization_id", "target_authorizations", ["organization_id"]
    )

    op.create_table(
        "scans",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "organization_id",
            sa.String(length=36),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "asset_id",
            sa.String(length=36),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "initiated_by_user_id",
            sa.String(length=36),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("profile_type", sa.String(length=40), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("progress_percent", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("current_module", sa.String(length=80), nullable=True),
        sa.Column("enabled_modules", sa.JSON(), nullable=False),
        sa.Column("policy_snapshot", sa.JSON(), nullable=False),
        sa.Column("total_checks_run", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("findings_summary", sa.JSON(), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("celery_task_id", sa.String(length=120), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_scans_organization_id", "scans", ["organization_id"])
    op.create_index("ix_scans_asset_id", "scans", ["asset_id"])
    op.create_index("ix_scans_status", "scans", ["status"])

    op.create_table(
        "scan_check_results",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "scan_id",
            sa.String(length=36),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("module_id", sa.String(length=80), nullable=False),
        sa.Column("check_id", sa.String(length=80), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_scan_check_results_scan_id", "scan_check_results", ["scan_id"])
    op.create_index("ix_scan_check_results_status", "scan_check_results", ["status"])

    op.create_table(
        "findings",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "organization_id",
            sa.String(length=36),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "asset_id",
            sa.String(length=36),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "scan_id",
            sa.String(length=36),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("module_id", sa.String(length=80), nullable=False),
        sa.Column("check_id", sa.String(length=80), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("category", sa.String(length=120), nullable=False),
        sa.Column("result_classification", sa.String(length=40), nullable=False),
        sa.Column("severity", sa.String(length=24), nullable=False),
        sa.Column("confidence", sa.String(length=24), nullable=False),
        sa.Column("cvss_v4_vector", sa.String(length=160), nullable=True),
        sa.Column("cvss_v4_score", sa.Float(), nullable=True),
        sa.Column("cwe_ids", sa.JSON(), nullable=False),
        sa.Column("owasp_categories", sa.JSON(), nullable=False),
        sa.Column("affected_endpoint", sa.String(length=512), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("impact", sa.Text(), nullable=False),
        sa.Column("reproduction_steps", sa.JSON(), nullable=False),
        sa.Column("remediation_data", sa.JSON(), nullable=False),
        sa.Column("treatment_status", sa.String(length=40), nullable=False),
        sa.Column(
            "assigned_to_user_id",
            sa.String(length=36),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("first_detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_confirmed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_findings_organization_id", "findings", ["organization_id"])
    op.create_index("ix_findings_asset_id", "findings", ["asset_id"])
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"])
    op.create_index("ix_findings_fingerprint", "findings", ["fingerprint"])
    op.create_index("ix_findings_severity", "findings", ["severity"])
    op.create_index("ix_findings_treatment_status", "findings", ["treatment_status"])

    op.create_table(
        "scan_schedules",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "organization_id",
            sa.String(length=36),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "asset_id",
            sa.String(length=36),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("profile_type", sa.String(length=40), nullable=False),
        sa.Column("cron_expression", sa.String(length=80), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_by_user_id",
            sa.String(length=36),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_scan_schedules_organization_id", "scan_schedules", ["organization_id"])
    op.create_index("ix_scan_schedules_asset_id", "scan_schedules", ["asset_id"])

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "organization_id",
            sa.String(length=36),
            sa.ForeignKey("organizations.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "user_id",
            sa.String(length=36),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("action", sa.String(length=120), nullable=False),
        sa.Column("resource_type", sa.String(length=80), nullable=False),
        sa.Column("resource_id", sa.String(length=80), nullable=True),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_audit_logs_organization_id", "audit_logs", ["organization_id"])
    op.create_index("ix_audit_logs_user_id", "audit_logs", ["user_id"])
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"])


def downgrade() -> None:
    op.drop_table("audit_logs")
    op.drop_table("scan_schedules")
    op.drop_table("findings")
    op.drop_table("scan_check_results")
    op.drop_table("scans")
    op.drop_table("target_authorizations")
    op.drop_table("assets")
    op.drop_table("organization_memberships")
    op.drop_table("users")
    op.drop_table("organizations")
