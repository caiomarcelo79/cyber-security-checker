"""Schemas Pydantic v2 para Orquestração de Auditorias (Scans), Progresso, Checks e Findings (Fase 3)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class ScanCreateRequest(BaseModel):
    """Payload para criação e enfileiramento de uma nova auditoria."""

    asset_id: str = Field(..., min_length=8, max_length=64)
    profile_type: str = Field(
        default="QUICK",
        description="Perfil de auditoria: QUICK, STANDARD, AUTHENTICATED, API, DEEP_ASSESSMENT, CUSTOM",
    )
    enabled_modules: list[str] | None = Field(
        default=None,
        description="Lista manual de IDs de módulos (opcional para perfis padrão, obrigatória para CUSTOM)",
    )
    max_requests_per_second: int | None = Field(default=None, ge=1, le=100)
    max_concurrency: int | None = Field(default=None, ge=1, le=50)
    request_timeout_seconds: int | None = Field(default=None, ge=2, le=120)
    max_redirects: int | None = Field(default=None, ge=0, le=20)
    idempotency_key: str | None = Field(
        default=None,
        max_length=120,
        description="Chave opcional de idempotência para evitar criação duplicada de auditorias ativas",
    )
    execute_synchronously: bool = Field(
        default=True,
        description=(
            "Se True, processa a auditoria imediatamente via worker/orquestrador garantindo persistência "
            "imediata; se False, apenas enfileira na fila Celery/Redis."
        ),
    )


class ScanProgressResponse(BaseModel):
    """Estado incremental e métricas em tempo real de uma auditoria."""

    scan_id: str
    asset_id: str
    status: str
    progress_percent: int
    current_module: str | None = None
    enabled_modules: list[str] = Field(default_factory=list)
    completed_modules: list[str] = Field(default_factory=list)
    failed_modules: list[str] = Field(default_factory=list)
    total_checks_run: int = 0
    findings_summary: dict[str, int] = Field(default_factory=dict)
    elapsed_seconds: float = 0.0
    error_message: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None


class ScanCheckResultResponse(BaseModel):
    """Resultado individual de uma verificação executada por um módulo."""

    id: str
    scan_id: str
    module_id: str
    check_id: str
    title: str
    status: str
    duration_ms: int
    summary: str
    details: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class FindingTriageUpdateRequest(BaseModel):
    """Payload para atualização de status de tratamento (triagem) de uma vulnerabilidade (Fase 4 e 6)."""

    treatment_status: str = Field(
        ...,
        description="Novo status: OPEN, IN_ANALYSIS, IN_PROGRESS, WAITING_VALIDATION, RESOLVED_VERIFIED, FALSE_POSITIVE, ACCEPTED_RISK, REOPENED",
    )
    triage_note: str | None = Field(
        default=None,
        max_length=1000,
        description="Justificativa técnica ou nota de tratamento registrada pelo analista/desenvolvedor",
    )
    assigned_to_user_id: str | None = Field(
        default=None,
        max_length=64,
        description="ID opcional do usuário responsável pela correção",
    )
    priority: str | None = Field(
        default=None,
        max_length=24,
        description="Prioridade de remediação: P1, P2, P3, P4 ou CRITICAL, HIGH, MEDIUM, LOW",
    )
    sla_deadline: datetime | None = Field(
        default=None,
        description="Data/hora limite de SLA para conclusão da remediação",
    )
    risk_acceptance_reason: str | None = Field(
        default=None,
        max_length=2000,
        description="Justificativa formal obrigatória caso o status seja ACCEPTED_RISK",
    )


class FindingResponse(BaseModel):
    """Vulnerabilidade ou potencial vulnerabilidade persistida com evidências sanitizadas."""

    id: str
    organization_id: str
    asset_id: str
    asset_name: str | None = None
    scan_id: str
    fingerprint: str
    module_id: str
    check_id: str
    title: str
    description: str
    category: str
    result_classification: str
    severity: str
    confidence: str
    cvss_v4_vector: str | None = None
    cvss_v4_score: float | None = None
    cwe_ids: list[str] = Field(default_factory=list)
    owasp_categories: list[str] = Field(default_factory=list)
    affected_endpoint: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    impact: str
    reproduction_steps: list[str] = Field(default_factory=list)
    remediation_data: dict[str, Any] = Field(default_factory=dict)
    treatment_status: str
    triage_note: str | None = None
    assigned_to_user_id: str | None = None
    priority: str = "MEDIUM"
    sla_deadline: datetime | None = None
    revalidation_scan_id: str | None = None
    risk_acceptance_reason: str | None = None
    first_detected_at: datetime
    last_confirmed_at: datetime
    resolved_at: datetime | None = None


class ScanResponse(BaseModel):
    """Representação completa de uma auditoria (Scan)."""

    id: str
    organization_id: str
    asset_id: str
    asset_name: str | None = None
    target_url: str | None = None
    initiated_by_user_id: str | None = None
    profile_type: str
    status: str
    progress_percent: int
    current_module: str | None = None
    enabled_modules: list[str] = Field(default_factory=list)
    completed_modules: list[str] = Field(default_factory=list)
    failed_modules: list[str] = Field(default_factory=list)
    policy_snapshot: dict[str, Any] = Field(default_factory=dict)
    total_checks_run: int = 0
    findings_summary: dict[str, int] = Field(default_factory=dict)
    elapsed_seconds: float = 0.0
    error_message: str | None = None
    celery_task_id: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime


class ScanDetailedResultsResponse(BaseModel):
    """Consolidação completa de uma auditoria com todos os seus checks e findings."""

    scan: ScanResponse
    checks: list[ScanCheckResultResponse] = Field(default_factory=list)
    findings: list[FindingResponse] = Field(default_factory=list)


class FindingPageResponse(BaseModel):
    """Página de vulnerabilidades com filtros, ordenação e paginação no servidor."""

    items: list[FindingResponse] = Field(default_factory=list)
    total: int = 0
    limit: int = 25
    offset: int = 0


class ScanPageResponse(BaseModel):
    """Página de auditorias com filtros e paginação no servidor."""

    items: list[ScanResponse] = Field(default_factory=list)
    total: int = 0
    limit: int = 25
    offset: int = 0


class FindingDetectionItem(BaseModel):
    """Detecção individual (por auditoria) da mesma vulnerabilidade (mesmo ativo + fingerprint)."""

    finding_id: str
    scan_id: str
    severity: str
    confidence: str
    treatment_status: str
    detected_at: datetime


class FindingTriageEvent(BaseModel):
    """Evento de triagem registrado na trilha de auditoria."""

    id: str
    user_id: str | None = None
    previous_status: str | None = None
    new_status: str | None = None
    triage_note: str | None = None
    created_at: datetime


class FindingHistoryResponse(BaseModel):
    finding_id: str
    detections: list[FindingDetectionItem] = Field(default_factory=list)
    triage_events: list[FindingTriageEvent] = Field(default_factory=list)


class ScanEventItem(BaseModel):
    """Evento administrativo da auditoria (criação, cancelamento etc.) da trilha de auditoria."""

    id: str
    action: str
    user_id: str | None = None
    created_at: datetime
    metadata: dict[str, Any] = Field(default_factory=dict)
