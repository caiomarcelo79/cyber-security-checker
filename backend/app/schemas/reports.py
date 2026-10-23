"""Schemas Pydantic v2 para o Sistema de Relatórios, Comparação de Auditorias e Revalidação (Fase 6)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.schemas.scans import FindingResponse, ScanCheckResultResponse, ScanResponse


class ReportCreateRequest(BaseModel):
    """Payload para criação e geração de relatórios (PDF, HTML, JSON, CSV)."""

    report_type: str = Field(
        default="EXECUTIVE",
        description="Tipo de relatório: EXECUTIVE, TECHNICAL, ASSET, SCAN, FINDING, COMPARISON, REMEDIATION_TRACKING",
    )
    format: str = Field(
        default="PDF",
        description="Formato de exportação: PDF, HTML, JSON, CSV",
    )
    title: str | None = Field(
        default=None,
        max_length=255,
        description="Título customizado opcional do relatório",
    )
    asset_id: str | None = Field(
        default=None,
        max_length=64,
        description="ID do ativo quando o relatório for por ativo ou executivo",
    )
    scan_id: str | None = Field(
        default=None,
        max_length=64,
        description="ID da auditoria quando o relatório for técnico de execução",
    )
    finding_id: str | None = Field(
        default=None,
        max_length=64,
        description="ID da vulnerabilidade quando o relatório for individual",
    )
    comparison_scan_id_a: str | None = Field(
        default=None,
        max_length=64,
        description="ID da auditoria base (A) para relatório comparativo",
    )
    comparison_scan_id_b: str | None = Field(
        default=None,
        max_length=64,
        description="ID da auditoria mais recente (B) para relatório comparativo",
    )
    filter_params: dict[str, Any] = Field(
        default_factory=dict,
        description="Filtros opcionais adicionais (severidade, período, categorias)",
    )
    execute_synchronously: bool = Field(
        default=True,
        description="Se True, gera o relatório imediatamente; se False, processa em segundo plano via Celery",
    )


class ReportResponse(BaseModel):
    """Metadados, status e URLs de download de um relatório gerado."""

    id: str
    organization_id: str
    created_by_user_id: str | None = None
    report_type: str
    format: str
    status: str
    title: str
    asset_id: str | None = None
    asset_name: str | None = None
    scan_id: str | None = None
    finding_id: str | None = None
    comparison_scan_id_a: str | None = None
    comparison_scan_id_b: str | None = None
    filter_params: dict[str, Any] = Field(default_factory=dict)
    summary_data: dict[str, Any] = Field(default_factory=dict)
    file_size_bytes: int = 0
    download_token: str | None = None
    download_url: str | None = None
    expires_at: datetime | None = None
    error_message: str | None = None
    created_at: datetime
    completed_at: datetime | None = None


class ReportPageResponse(BaseModel):
    """Página de relatórios com filtros e paginação no servidor."""

    items: list[ReportResponse] = Field(default_factory=list)
    total: int = 0
    limit: int = 25
    offset: int = 0


class CoverageDiff(BaseModel):
    """Diferenças objetivas de cobertura e metodologia entre duas auditorias comparadas."""

    modules_a: list[str] = Field(default_factory=list)
    modules_b: list[str] = Field(default_factory=list)
    common_modules: list[str] = Field(default_factory=list)
    modules_added_in_b: list[str] = Field(default_factory=list)
    modules_removed_in_b: list[str] = Field(default_factory=list)
    checks_count_a: int = 0
    checks_count_b: int = 0
    duration_ms_a: int = 0
    duration_ms_b: int = 0
    profile_a: str = "QUICK"
    profile_b: str = "QUICK"


class FindingSeverityChange(BaseModel):
    """Alteração de severidade ou confiança de uma vulnerabilidade persistente entre auditorias."""

    fingerprint: str
    title: str
    previous_severity: str
    current_severity: str
    previous_confidence: str
    current_confidence: str


class ScanComparisonResponse(BaseModel):
    """Resultado detalhado da correlação e comparação entre duas auditorias."""

    scan_a: ScanResponse
    scan_b: ScanResponse
    asset_id: str
    asset_name: str | None = None
    total_findings_a: int = 0
    total_findings_b: int = 0
    new_findings: list[FindingResponse] = Field(default_factory=list)
    persistent_findings: list[FindingResponse] = Field(default_factory=list)
    confirmed_remediated: list[FindingResponse] = Field(default_factory=list)
    not_detected_again: list[FindingResponse] = Field(default_factory=list)
    not_verified_coverage: list[FindingResponse] = Field(default_factory=list)
    reopened_findings: list[FindingResponse] = Field(default_factory=list)
    severity_changes: list[FindingSeverityChange] = Field(default_factory=list)
    coverage_diff: CoverageDiff
    comparison_summary: dict[str, Any] = Field(default_factory=dict)


class RevalidationRequest(BaseModel):
    """Solicitação de revalidação técnica de uma vulnerabilidade remediada."""

    triage_note: str | None = Field(
        default=None,
        max_length=1000,
        description="Nota técnica descrevendo a correção aplicada antes da revalidação",
    )


class RevalidationResponse(BaseModel):
    """Resultado da revalidação automatizada via Security Engine."""

    finding_id: str
    scan_id: str
    status: str
    message: str
    check_result: ScanCheckResultResponse | None = None
    previous_status: str
    new_status: str
    verified_at: datetime


class EvolutionPoint(BaseModel):
    """Métricas históricas agregadas por dia."""

    date: str
    open_count: int = 0
    in_progress_count: int = 0
    resolved_count: int = 0
    accepted_risk_count: int = 0
    reopened_count: int = 0
    new_detected_count: int = 0
    scans_executed: int = 0


class DashboardEvolutionResponse(BaseModel):
    """Série temporal de evolução do tratamento de vulnerabilidades e MTTR."""

    days: int
    points: list[EvolutionPoint] = Field(default_factory=list)
    mttr_average_days: float | None = None
    total_resolved: int = 0
    total_reopened: int = 0
    total_accepted_risk: int = 0
    total_active_unresolved: int = 0
