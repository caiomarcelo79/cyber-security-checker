"""Modelos relacionais SQLAlchemy 2.0 do cyber-security-checker."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_uuid_str() -> str:
    return str(uuid4())


class Organization(Base):
    """Organização / Tenant com isolamento estrito de ativos, auditorias e vulnerabilidades."""

    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid_str)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    slug: Mapped[str] = mapped_column(String(120), unique=True, nullable=False, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    memberships: Mapped[list[OrganizationMembership]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )
    assets: Mapped[list[Asset]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )


class User(Base):
    """Usuário autenticado da plataforma."""

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid_str)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(160), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    memberships: Mapped[list[OrganizationMembership]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class OrganizationMembership(Base):
    """Vínculo RBAC entre usuário e organização (ADMIN, SECURITY_ANALYST, DEVELOPER, VIEWER)."""

    __tablename__ = "organization_memberships"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid_str)
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role: Mapped[str] = mapped_column(String(40), nullable=False, default="VIEWER")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    organization: Mapped[Organization] = relationship(back_populates="memberships")
    user: Mapped[User] = relationship(back_populates="memberships")


class Asset(Base):
    """Sistema, aplicação web, API ou domínio cadastrado para auditoria."""

    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid_str)
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(180), nullable=False)
    target_url: Mapped[str] = mapped_column(String(512), nullable=False)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    asset_type: Mapped[str] = mapped_column(String(40), nullable=False, default="WEB_APP")
    environment: Mapped[str] = mapped_column(String(40), nullable=False, default="STAGING")
    owner_name: Mapped[str] = mapped_column(String(160), nullable=False)
    owner_email: Mapped[str] = mapped_column(String(255), nullable=False)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    excluded_paths: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    authorization_status: Mapped[str] = mapped_column(
        String(40), default="PENDING", nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    organization: Mapped[Organization] = relationship(back_populates="assets")
    authorizations: Mapped[list[TargetAuthorization]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )
    scans: Mapped[list[Scan]] = relationship(back_populates="asset", cascade="all, delete-orphan")
    findings: Mapped[list[FindingRecord]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )


class TargetAuthorization(Base):
    """Comprovação formal de controle/autorização do alvo (DNS_TXT, HTTP_WELL_KNOWN, LAB_INTERNAL)."""

    __tablename__ = "target_authorizations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid_str)
    asset_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    method: Mapped[str] = mapped_column(String(40), nullable=False)
    verification_token: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(40), default="PENDING", nullable=False)
    verified_by_user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    scope_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    asset: Mapped[Asset] = relationship(back_populates="authorizations")


class Scan(Base):
    """Execução de auditoria de segurança sobre um ativo autorizado."""

    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid_str)
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    initiated_by_user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    profile_type: Mapped[str] = mapped_column(String(40), nullable=False, default="QUICK")
    status: Mapped[str] = mapped_column(String(40), nullable=False, default="PENDING", index=True)
    progress_percent: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    current_module: Mapped[str | None] = mapped_column(String(80), nullable=True)
    enabled_modules: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    policy_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    total_checks_run: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    findings_summary: Mapped[dict[str, int]] = mapped_column(JSON, default=dict, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    celery_task_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    schedule_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("scan_schedules.id", ondelete="SET NULL"), nullable=True, index=True
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    asset: Mapped[Asset] = relationship(back_populates="scans")
    check_results: Mapped[list[ScanCheckResultRecord]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    findings: Mapped[list[FindingRecord]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        foreign_keys="FindingRecord.scan_id",
    )


class ScanCheckResultRecord(Base):
    """Resultado individual de uma verificação executada (incluindo PASSED e EXECUTION_ERROR)."""

    __tablename__ = "scan_check_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid_str)
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    module_id: Mapped[str] = mapped_column(String(80), nullable=False)
    check_id: Mapped[str] = mapped_column(String(80), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    scan: Mapped[Scan] = relationship(back_populates="check_results")


class FindingRecord(Base):
    """Vulnerabilidade ou potencial vulnerabilidade persistida com evidências sanitizadas."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid_str)
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    fingerprint: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    module_id: Mapped[str] = mapped_column(String(80), nullable=False)
    check_id: Mapped[str] = mapped_column(String(80), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(String(120), nullable=False)
    result_classification: Mapped[str] = mapped_column(String(40), nullable=False)
    severity: Mapped[str] = mapped_column(String(24), nullable=False, index=True)
    confidence: Mapped[str] = mapped_column(String(24), nullable=False)
    cvss_v4_vector: Mapped[str | None] = mapped_column(String(160), nullable=True)
    cvss_v4_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cwe_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    owasp_categories: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    affected_endpoint: Mapped[str] = mapped_column(String(512), nullable=False)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    impact: Mapped[str] = mapped_column(Text, nullable=False)
    reproduction_steps: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    remediation_data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    treatment_status: Mapped[str] = mapped_column(String(40), default="OPEN", nullable=False, index=True)
    priority: Mapped[str] = mapped_column(String(24), default="MEDIUM", nullable=False)
    assigned_to_user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    sla_deadline: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revalidation_scan_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True
    )
    risk_acceptance_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    first_detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    last_confirmed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    asset: Mapped[Asset] = relationship(back_populates="findings")
    scan: Mapped[Scan] = relationship(back_populates="findings", foreign_keys=[scan_id])


class ReportRecord(Base):
    """Relatório gerado (Executivo, Técnico, Comparativo, etc.) em PDF, HTML, JSON ou CSV (Fase 6)."""

    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid_str)
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    created_by_user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    report_type: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    format: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), default="PENDING", nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    asset_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=True, index=True
    )
    scan_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=True, index=True
    )
    finding_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=True
    )
    comparison_scan_id_a: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=True
    )
    comparison_scan_id_b: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=True
    )
    filter_params: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    summary_data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    file_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    file_size_bytes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    download_token: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    organization: Mapped[Organization] = relationship()
    asset: Mapped[Asset | None] = relationship()
    scan: Mapped[Scan | None] = relationship(foreign_keys=[scan_id])


class ScanSchedule(Base):
    """Agendamento recorrente de auditorias autorizadas (Fase 7)."""

    __tablename__ = "scan_schedules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid_str)
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    profile_type: Mapped[str] = mapped_column(String(40), nullable=False, default="QUICK")
    enabled_modules: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    frequency: Mapped[str] = mapped_column(String(30), nullable=False, default="DAILY")
    cron_expression: Mapped[str] = mapped_column(String(80), nullable=False, default="0 2 * * *")
    timezone: Mapped[str] = mapped_column(String(60), nullable=False, default="UTC")
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="ACTIVE", index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    misfire_policy: Mapped[str] = mapped_column(String(30), nullable=False, default="SKIP")
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_run_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    last_scan_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_by_user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    organization: Mapped[Organization] = relationship()
    asset: Mapped[Asset] = relationship()
    created_by_user: Mapped[User | None] = relationship()


class NotificationRecord(Base):
    """Notificação interna gerada por eventos relevantes da plataforma (Fase 7)."""

    __tablename__ = "notifications"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid_str)
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True
    )
    event_type: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="INFO")
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    link_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )

    organization: Mapped[Organization] = relationship()
    user: Mapped[User | None] = relationship()


class NotificationPreferenceRecord(Base):
    """Preferências de recebimento de notificações por usuário e organização (Fase 7)."""

    __tablename__ = "notification_preferences"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid_str)
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    email_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    email_destination: Mapped[str | None] = mapped_column(String(255), nullable=True)
    channels: Mapped[list[str]] = mapped_column(JSON, default=lambda: ["IN_APP"], nullable=False)
    min_severity: Mapped[str] = mapped_column(String(20), default="MEDIUM", nullable=False)
    subscribed_events: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    organization: Mapped[Organization] = relationship()
    user: Mapped[User] = relationship()


class WebhookEndpointRecord(Base):
    """Endpoint de webhook para envio seguro de eventos para sistemas externos (Fase 7)."""

    __tablename__ = "webhook_endpoints"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid_str)
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    url: Mapped[str] = mapped_column(String(1000), nullable=False)
    description: Mapped[str | None] = mapped_column(String(255), nullable=True)
    secret_token: Mapped[str] = mapped_column(String(128), nullable=False)
    subscribed_events: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_by_user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    organization: Mapped[Organization] = relationship()
    created_by_user: Mapped[User | None] = relationship()


class WebhookDeliveryRecord(Base):
    """Registro e histórico de tentativa de entrega de evento via webhook (Fase 7)."""

    __tablename__ = "webhook_deliveries"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid_str)
    webhook_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("webhook_endpoints.id", ondelete="CASCADE"), nullable=False, index=True
    )
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_type: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    event_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    response_body: Mapped[str | None] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    attempt_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    next_retry_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )

    webhook: Mapped[WebhookEndpointRecord] = relationship()


class ApiTokenRecord(Base):
    """Chave de API autenticada com escopos e expiração para integrações de terceiros (Fase 7)."""

    __tablename__ = "api_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid_str)
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    token_prefix: Mapped[str] = mapped_column(String(16), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    scopes: Mapped[list[str]] = mapped_column(JSON, default=lambda: ["scans:read"], nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    organization: Mapped[Organization] = relationship()
    user: Mapped[User] = relationship()


class ScanTemplateRecord(Base):
    """Template reutilizável de auditoria com módulos e parâmetros pré-configurados (Fase 7)."""

    __tablename__ = "scan_templates"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid_str)
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    profile_type: Mapped[str] = mapped_column(String(40), nullable=False, default="QUICK")
    enabled_modules: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    parameters: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    environment_type: Mapped[str | None] = mapped_column(String(30), nullable=True)
    created_by_user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    organization: Mapped[Organization] = relationship()
    created_by_user: Mapped[User | None] = relationship()


class AuditLog(Base):
    """Registro de auditoria interna das ações executadas por usuários e componentes."""

    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid_str)
    organization_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True, index=True
    )
    user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    action: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(String(80), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class RevokedToken(Base):
    """JWTs revogados antes da expiração (logout). Linhas expiradas podem ser removidas."""

    __tablename__ = "revoked_tokens"

    jti: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    revoked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
