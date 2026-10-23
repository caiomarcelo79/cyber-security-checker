"""Endpoints REST v1 da plataforma cyber-security-checker."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse
from security_engine.core.remediation import RemediationEngine
from security_engine.policies.scope_validator import ScopePolicyValidator, ScopeViolationError
from sqlalchemy.orm import Session

from app.api.deps import AuthenticatedPrincipal, get_optional_principal
from app.core.config import get_settings
from app.core.database import get_db
from app.repositories.metrics_repo import MetricsRepository
from app.schemas.system import (
    HealthResponse,
    PlatformMetricsSummary,
    ScopeValidationRequest,
    ScopeValidationResponse,
    SystemStatusResponse,
)
from app.services.system_service import SystemService

router = APIRouter(prefix="/api/v1", tags=["v1"])
DbSessionDep = Annotated[Session, Depends(get_db)]
OptionalPrincipalDep = Annotated[AuthenticatedPrincipal | None, Depends(get_optional_principal)]


@router.get("/health", response_model=HealthResponse, summary="Health check rápido da API")
def get_health() -> HealthResponse:
    """Retorna confirmação imediata de disponibilidade do serviço Backend."""
    settings = get_settings()
    return HealthResponse(
        status="UP",
        service=settings.app_name,
        version=settings.app_version,
        environment=settings.app_env,
        timestamp=datetime.now(UTC),
    )


@router.get(
    "/system/status",
    response_model=SystemStatusResponse,
    summary="Diagnóstico profundo dos subsistemas, motor de segurança e contadores reais",
)
def get_system_status(
    db: DbSessionDep,
    principal: OptionalPrincipalDep,
    skip_redis: bool = Query(default=False, description="Opcional para testes isolados sem broker"),
) -> SystemStatusResponse:
    """Consulta saúde do PostgreSQL, Redis, Security Engine e métricas reais do banco."""
    org_id = principal.organization.id if principal else None
    return SystemService.get_system_status(
        db=db,
        skip_external_redis=skip_redis,
        organization_id=org_id,
    )


@router.get(
    "/dashboard/summary",
    response_model=PlatformMetricsSummary,
    summary="Métricas reais do banco de dados para o Dashboard SOC",
)
def get_dashboard_summary(
    db: DbSessionDep,
    principal: OptionalPrincipalDep,
) -> PlatformMetricsSummary:
    """Retorna os contadores e agregações reais persistidos no PostgreSQL (zero dados fictícios)."""
    org_id = principal.organization.id if principal else None
    return MetricsRepository.get_platform_metrics(db=db, organization_id=org_id)


@router.get(
    "/modules",
    response_model=list[dict[str, Any]],
    summary="Catálogo dos módulos de auditoria registrados (Módulos A a H)",
)
def list_security_modules() -> list[dict[str, Any]]:
    """Lista todos os módulos registrados no PluginRegistry com metadados OWASP/WSTG/ASVS/CWE."""
    return SystemService.list_modules_catalog()


@router.get(
    "/profiles",
    response_model=list[dict[str, Any]],
    summary="Catálogo dos perfis de execução de auditoria",
)
def list_scan_profiles() -> list[dict[str, Any]]:
    """Lista os perfis de execução (Quick, Standard, Authenticated, API, Deep Assessment, Custom)."""
    return SystemService.list_profiles_catalog()


@router.get(
    "/remediation",
    response_model=list[dict[str, Any]],
    summary="Catálogo versionado de recomendações técnicas de correção",
)
def list_remediation_guidance() -> list[dict[str, Any]]:
    """Retorna a base de conhecimento de correções com exemplos seguros multi-stack."""
    return [item.model_dump() for item in RemediationEngine.list_all_guidance()]


@router.post(
    "/scope/validate",
    response_model=ScopeValidationResponse,
    summary="Valida se uma URL respeita o escopo autorizado e as regras Anti-SSRF",
)
def validate_target_scope(payload: ScopeValidationRequest) -> ScopeValidationResponse:
    """Valida URL contra a política de escopo, lista de exclusão e proteção Anti-SSRF."""
    settings = get_settings()
    validator = ScopePolicyValidator(
        authorized_hosts=payload.authorized_hosts,
        allow_subdomains=payload.allow_subdomains,
        excluded_paths=payload.excluded_paths,
        block_private_networks=settings.block_private_networks,
        allow_local_lab_targets=settings.allow_local_lab_targets,
        lab_allowed_hosts=settings.parsed_lab_allowed_hosts,
    )
    try:
        decision = validator.validate_url(payload.target_url, resolve_dns=False)
        return ScopeValidationResponse(
            allowed=decision.allowed,
            normalized_url=decision.normalized_url,
            hostname=decision.hostname,
            reason=decision.reason,
        )
    except ScopeViolationError as exc:
        return ScopeValidationResponse(
            allowed=False,
            normalized_url=None,
            hostname=None,
            reason=str(exc),
        )

@router.get("/ready", summary="Readiness check (banco de dados e Redis)")
def get_readiness() -> JSONResponse:
    """Retorna 200 apenas se PostgreSQL e Redis responderem; caso contrário 503."""
    import redis as redis_lib
    from sqlalchemy import text

    from app.core.database import SessionLocal

    checks: dict[str, str] = {}
    try:
        with SessionLocal() as session:
            session.execute(text("SELECT 1"))
        checks["database"] = "UP"
    except Exception:  # noqa: BLE001
        checks["database"] = "DOWN"
    try:
        redis_lib.from_url(get_settings().redis_url, socket_connect_timeout=2).ping()
        checks["redis"] = "UP"
    except Exception:  # noqa: BLE001
        checks["redis"] = "DOWN"
    ok = all(v == "UP" for v in checks.values())
    return JSONResponse(status_code=200 if ok else 503, content={"status": "READY" if ok else "NOT_READY", "checks": checks})
