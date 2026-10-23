"""Pydantic schemas para a Fase 7: Automação, Agendamentos, Notificações, Webhooks e API Tokens."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

# ============================================================================
# Agendamentos de Auditorias (Schedules)
# ============================================================================


class ScanScheduleCreateRequest(BaseModel):
    """Payload para criação de agendamento de auditoria."""

    asset_id: str = Field(..., description="ID do ativo autorizado")
    profile_type: str = Field(default="QUICK", description="Perfil: QUICK, FULL, PASSIVE, API, etc.")
    enabled_modules: list[str] = Field(
        default_factory=list, description="Lista opcional de módulos específicos"
    )
    frequency: str = Field(
        default="DAILY",
        description="Frequência: ONCE, DAILY, WEEKLY, MONTHLY, CRON",
    )
    cron_expression: str = Field(
        default="0 2 * * *",
        description="Expressão cron de 5 campos (min hora dia mês dia-da-semana) ou padrão para a frequência",
    )
    timezone: str = Field(default="UTC", description="Fuso horário (ex: America/Sao_Paulo, UTC)")
    misfire_policy: str = Field(
        default="SKIP", description="Política para execuções perdidas: SKIP ou RUN_ONCE"
    )


class ScanScheduleUpdateRequest(BaseModel):
    """Payload para atualização de agendamento."""

    profile_type: str | None = None
    enabled_modules: list[str] | None = None
    frequency: str | None = None
    cron_expression: str | None = None
    timezone: str | None = None
    misfire_policy: str | None = None
    status: str | None = None  # ACTIVE, PAUSED


class ScanScheduleResponse(BaseModel):
    """Representação serializada de um agendamento de auditoria."""

    id: str
    organization_id: str
    asset_id: str
    asset_name: str | None = None
    profile_type: str
    enabled_modules: list[str] = Field(default_factory=list)
    frequency: str
    cron_expression: str
    timezone: str
    status: str
    is_active: bool
    misfire_policy: str
    consecutive_failures: int
    last_run_at: datetime | None = None
    next_run_at: datetime | None = None
    last_scan_id: str | None = None
    created_by_user_id: str | None = None
    created_at: datetime
    updated_at: datetime | None = None


class ScanSchedulePageResponse(BaseModel):
    items: list[ScanScheduleResponse]
    total: int
    limit: int
    offset: int


# ============================================================================
# Notificações e Preferências
# ============================================================================


class NotificationResponse(BaseModel):
    """Notificação gerada por eventos da plataforma."""

    id: str
    organization_id: str
    user_id: str | None = None
    event_type: str
    severity: str
    title: str
    message: str
    link_url: str | None = None
    read_at: datetime | None = None
    metadata_json: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class NotificationPageResponse(BaseModel):
    items: list[NotificationResponse]
    total: int
    unread_count: int
    limit: int
    offset: int


class NotificationPreferenceResponse(BaseModel):
    """Configurações e preferências de entrega de notificações."""

    id: str
    organization_id: str
    user_id: str
    email_enabled: bool
    email_destination: str | None = None
    channels: list[str] = Field(default_factory=list)
    min_severity: str
    subscribed_events: list[str] = Field(default_factory=list)
    updated_at: datetime | None = None


class NotificationPreferenceUpdateRequest(BaseModel):
    email_enabled: bool | None = None
    email_destination: str | None = None
    channels: list[str] | None = None
    min_severity: str | None = None
    subscribed_events: list[str] | None = None


# ============================================================================
# Webhooks
# ============================================================================


class WebhookEndpointCreateRequest(BaseModel):
    """Cadastro de endpoint receptor de webhooks."""

    url: str = Field(
        ..., description="URL HTTPS do receptor (ou HTTP para laboratório local autorizado)"
    )
    description: str | None = Field(default=None, max_length=255)
    subscribed_events: list[str] = Field(
        default_factory=lambda: [
            "scan.started",
            "scan.completed",
            "scan.failed",
            "finding.created",
            "finding.reopened",
            "remediation.verified",
            "report.generated",
        ],
        description="Lista de eventos para disparo",
    )


class WebhookEndpointUpdateRequest(BaseModel):
    url: str | None = None
    description: str | None = None
    subscribed_events: list[str] | None = None
    is_active: bool | None = None


class WebhookEndpointResponse(BaseModel):
    id: str
    organization_id: str
    url: str
    description: str | None = None
    secret_token_prefix: str
    subscribed_events: list[str] = Field(default_factory=list)
    is_active: bool
    consecutive_failures: int
    created_at: datetime
    updated_at: datetime | None = None


class WebhookEndpointSecretRotateResponse(BaseModel):
    id: str
    new_secret_token: str
    message: str


class WebhookDeliveryResponse(BaseModel):
    id: str
    webhook_id: str
    organization_id: str
    event_type: str
    event_id: str
    payload: dict[str, Any]
    status: str
    status_code: int | None = None
    response_body: str | None = None
    duration_ms: int | None = None
    attempt_count: int
    next_retry_at: datetime | None = None
    error_message: str | None = None
    created_at: datetime


class WebhookDeliveryPageResponse(BaseModel):
    items: list[WebhookDeliveryResponse]
    total: int
    limit: int
    offset: int


class WebhookTestResponse(BaseModel):
    status: str
    status_code: int | None = None
    response_summary: str | None = None
    duration_ms: int | None = None
    message: str


# ============================================================================
# API Tokens (Integrações Externas Autenticadas)
# ============================================================================


VALID_API_SCOPES = {
    "scans:read",
    "scans:write",
    "findings:read",
    "findings:write",
    "assets:read",
    "reports:read",
    "reports:write",
    "schedules:read",
    "schedules:write",
}


class ApiTokenCreateRequest(BaseModel):
    name: str = Field(
        ..., min_length=2, max_length=120, description="Nome identificador da chave de API"
    )
    scopes: list[str] = Field(
        default_factory=lambda: ["scans:read", "findings:read"],
        description="Escopos de autorização autorizados",
    )
    expires_in_days: int | None = Field(
        default=90, ge=1, le=365, description="Dias para expiração (None = sem expiração)"
    )


class ApiTokenCreatedResponse(BaseModel):
    """Retorna o segredo em texto puro UMA ÚNICA VEZ no momento da criação."""

    id: str
    name: str
    token_prefix: str
    raw_api_token: str = Field(
        ..., description="Chave completa. Salve agora, pois ela não será exibida novamente."
    )
    scopes: list[str]
    expires_at: datetime | None = None
    created_at: datetime


class ApiTokenResponse(BaseModel):
    id: str
    organization_id: str
    user_id: str
    name: str
    token_prefix: str
    scopes: list[str]
    expires_at: datetime | None = None
    last_used_at: datetime | None = None
    is_revoked: bool
    created_at: datetime


class ApiTokenPageResponse(BaseModel):
    items: list[ApiTokenResponse]
    total: int
    limit: int
    offset: int


# ============================================================================
# Templates de Auditoria
# ============================================================================


class ScanTemplateCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=120)
    description: str | None = Field(default=None, max_length=1000)
    profile_type: str = Field(default="QUICK")
    enabled_modules: list[str] = Field(default_factory=list)
    parameters: dict[str, Any] = Field(default_factory=dict)
    environment_type: str | None = Field(default=None, description="PRODUCTION, STAGING, LAB, etc.")


class ScanTemplateUpdateRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    profile_type: str | None = None
    enabled_modules: list[str] | None = None
    parameters: dict[str, Any] | None = None
    environment_type: str | None = None


class ScanTemplateResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    description: str | None = None
    profile_type: str
    enabled_modules: list[str] = Field(default_factory=list)
    parameters: dict[str, Any] = Field(default_factory=dict)
    environment_type: str | None = None
    created_by_user_id: str | None = None
    created_at: datetime
    updated_at: datetime | None = None


class ScanTemplatePageResponse(BaseModel):
    items: list[ScanTemplateResponse]
    total: int
    limit: int
    offset: int
