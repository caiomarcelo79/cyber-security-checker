"""Esquemas Pydantic v2 para diagnóstico do sistema, dashboard real, módulos e validação de escopo."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class ComponentHealth(BaseModel):
    """Estado operacional de um subsistema individual."""

    name: str
    status: str = Field(..., description="UP, DEGRADED ou DOWN")
    latency_ms: float | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class HealthResponse(BaseModel):
    """Resposta do endpoint /api/v1/health."""

    status: str
    service: str
    version: str
    environment: str
    timestamp: datetime


class TopRiskyAssetItem(BaseModel):
    """Ativo ranqueado por pontuação de risco real no Dashboard SOC."""

    id: str
    name: str
    target_url: str
    environment: str
    asset_type: str
    authorization_status: str
    risk_score: int
    open_findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    last_scan_at: datetime | None = None


class CategoryDistributionItem(BaseModel):
    """Distribuição de vulnerabilidades por categoria OWASP ou CWE."""

    category: str
    count: int


class RecentScanSummaryItem(BaseModel):
    """Resumo real de auditoria recente exibido no Dashboard SOC."""

    id: str
    asset_id: str
    asset_name: str
    profile_type: str
    status: str
    progress_percent: int
    total_checks_run: int
    findings_count: int
    created_at: datetime


class PlatformMetricsSummary(BaseModel):
    """Contadores e agregações reais extraídos diretamente do banco de dados PostgreSQL (Zero dados fictícios)."""

    total_organizations: int
    total_assets: int
    verified_assets: int
    total_scans_executed: int
    scans_in_progress: int
    open_vulnerabilities: int
    critical_vulnerabilities: int
    high_vulnerabilities: int
    medium_vulnerabilities: int
    low_vulnerabilities: int
    info_vulnerabilities: int
    treatment_status_counts: dict[str, int] = Field(
        default_factory=lambda: {
            "OPEN": 0,
            "IN_PROGRESS": 0,
            "MITIGATED": 0,
            "ACCEPTED_RISK": 0,
            "FALSE_POSITIVE": 0,
            "RESOLVED_VERIFIED": 0,
        }
    )
    top_risky_assets: list[TopRiskyAssetItem] = Field(default_factory=list)
    owasp_category_distribution: list[CategoryDistributionItem] = Field(default_factory=list)
    cwe_distribution: list[CategoryDistributionItem] = Field(default_factory=list)
    recent_scans: list[RecentScanSummaryItem] = Field(default_factory=list)
    average_scan_duration_seconds: float = 0.0
    scan_status_counts: dict[str, int] = Field(default_factory=dict)
    resolved_vulnerabilities: int = 0


class SystemStatusResponse(BaseModel):
    """Diagnóstico completo da plataforma, subsistemas, motor de segurança e contadores reais."""

    status: str
    app_name: str
    version: str
    environment: str
    current_phase: str
    timestamp: datetime
    components: dict[str, ComponentHealth]
    registered_modules_count: int
    available_profiles_count: int
    metrics: PlatformMetricsSummary


class ScopeValidationRequest(BaseModel):
    """Requisição para testar validação de escopo e bloqueio anti-SSRF."""

    target_url: str
    authorized_hosts: list[str]
    allow_subdomains: bool = False
    excluded_paths: list[str] = Field(default_factory=lambda: ["/logout", "/delete"])


class ScopeValidationResponse(BaseModel):
    """Resultado da avaliação do ScopePolicyValidator."""

    allowed: bool
    normalized_url: str | None = None
    hostname: str | None = None
    reason: str


class TrendPoint(BaseModel):
    """Ponto diário da série histórica (dados persistidos)."""

    date: str
    detected: int = 0
    resolved: int = 0
    scans: int = 0


class DashboardTrendsResponse(BaseModel):
    days: int
    points: list[TrendPoint] = Field(default_factory=list)
