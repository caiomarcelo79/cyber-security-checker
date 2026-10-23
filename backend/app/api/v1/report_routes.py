"""Rotas REST v1 para o Sistema de Relatórios, Comparação de Auditorias e Revalidação (Fase 6)."""

from __future__ import annotations

import os
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.api.deps import (
    AuthenticatedPrincipal,
    require_minimum_role,
)
from app.core.database import get_db
from app.core.security import UserRole
from app.schemas.reports import (
    DashboardEvolutionResponse,
    ReportCreateRequest,
    ReportPageResponse,
    ReportResponse,
    RevalidationRequest,
    RevalidationResponse,
    ScanComparisonResponse,
)
from app.services.audit_service import AuditLogService
from app.services.report_engine import ReportEngine
from app.services.revalidation_service import RevalidationService
from app.services.scan_comparison_service import ScanComparisonService
from app.services.vulnerability_service import VulnerabilityService

router = APIRouter(prefix="/api/v1", tags=["phase6-reports-comparison-revalidation"])

DbSessionDep = Annotated[Session, Depends(get_db)]
ViewerPrincipalDep = Annotated[AuthenticatedPrincipal, Depends(require_minimum_role(UserRole.VIEWER))]
DeveloperPrincipalDep = Annotated[
    AuthenticatedPrincipal, Depends(require_minimum_role(UserRole.DEVELOPER))
]
AnalystPrincipalDep = Annotated[
    AuthenticatedPrincipal, Depends(require_minimum_role(UserRole.SECURITY_ANALYST))
]


# =============================================================================
# RELATÓRIOS
# =============================================================================


@router.post(
    "/reports",
    response_model=ReportResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Cria e gera um relatório profissional (PDF, HTML, JSON, CSV) da organização ativa",
)
def create_report(
    payload: ReportCreateRequest,
    db: DbSessionDep,
    principal: DeveloperPrincipalDep,
) -> ReportResponse:
    return ReportEngine.create_report(
        db=db,
        organization_id=principal.organization.id,
        user_id=principal.user.id,
        payload=payload,
        ip_address=principal.client_ip,
    )


@router.get(
    "/reports",
    response_model=ReportPageResponse,
    summary="Lista relatórios gerados da organização ativa com filtros e paginação no servidor",
)
def list_reports(
    db: DbSessionDep,
    principal: ViewerPrincipalDep,
    asset_id: str | None = Query(default=None),
    scan_id: str | None = Query(default=None),
    report_type: str | None = Query(default=None),
    format: str | None = Query(default=None),
    status: str | None = Query(default=None),
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> ReportPageResponse:
    return ReportEngine.list_reports(
        db=db,
        organization_id=principal.organization.id,
        asset_id=asset_id,
        scan_id=scan_id,
        report_type=report_type,
        export_format=format,
        status_filter=status,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/reports/{report_id}",
    response_model=ReportResponse,
    summary="Consulta metadados, status e links de um relatório da organização",
)
def get_report(
    report_id: str,
    db: DbSessionDep,
    principal: ViewerPrincipalDep,
) -> ReportResponse:
    record = ReportEngine.get_report_or_404(db, principal.organization.id, report_id)
    return ReportEngine._to_response(record)


MIME_TYPES = {
    "PDF": "application/pdf",
    "HTML": "text/html; charset=utf-8",
    "JSON": "application/json; charset=utf-8",
    "CSV": "text/csv; charset=utf-8",
}


@router.get(
    "/reports/{report_id}/download",
    summary="Download autenticado do arquivo gerado do relatório",
)
def download_report(
    report_id: str,
    db: DbSessionDep,
    principal: ViewerPrincipalDep,
) -> FileResponse:
    report = ReportEngine.get_report_or_404(db, principal.organization.id, report_id)
    if report.status != "COMPLETED" or not report.file_path or not os.path.exists(report.file_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Arquivo do relatório não encontrado ou ainda em processamento.",
        )

    AuditLogService.record(
        db=db,
        action="REPORT_DOWNLOADED",
        resource_type="report",
        resource_id=report.id,
        organization_id=principal.organization.id,
        user_id=principal.user.id,
        ip_address=principal.client_ip,
        metadata={"format": report.format, "method": "authenticated"},
    )

    filename = os.path.basename(report.file_path)
    media_type = MIME_TYPES.get(report.format, "application/octet-stream")
    return FileResponse(
        path=report.file_path,
        media_type=media_type,
        filename=filename,
    )


@router.get(
    "/reports/download-by-token/{token}",
    summary="Download público autorizado via token temporário e de alta entropia",
)
def download_report_by_token(
    token: str,
    request: Request,
    db: DbSessionDep,
) -> FileResponse:
    report = ReportEngine.get_report_by_token(db, token)

    client_ip = request.client.host if request.client else None
    AuditLogService.record(
        db=db,
        action="REPORT_DOWNLOADED_BY_TOKEN",
        resource_type="report",
        resource_id=report.id,
        organization_id=report.organization_id,
        user_id=report.created_by_user_id,
        ip_address=client_ip,
        metadata={"format": report.format, "method": "token"},
    )

    filename = os.path.basename(report.file_path)
    media_type = MIME_TYPES.get(report.format, "application/octet-stream")
    return FileResponse(
        path=report.file_path,
        media_type=media_type,
        filename=filename,
    )


@router.delete(
    "/reports/{report_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Exclui um relatório gerado e seu arquivo associado do armazenamento (Requer ANALYST ou ADMIN)",
)
def delete_report(
    report_id: str,
    db: DbSessionDep,
    principal: AnalystPrincipalDep,
) -> None:
    ReportEngine.delete_report(db, principal.organization.id, report_id)


# =============================================================================
# COMPARAÇÃO ENTRE AUDITORIAS
# =============================================================================


@router.get(
    "/scans/{scan_id}/compare/{other_scan_id}",
    response_model=ScanComparisonResponse,
    summary="Compara duas auditorias do mesmo ativo, correlacionando novas, persistentes e correções validadas",
)
def compare_scans(
    scan_id: str,
    other_scan_id: str,
    db: DbSessionDep,
    principal: ViewerPrincipalDep,
) -> ScanComparisonResponse:
    return ScanComparisonService.compare_scans(
        db=db,
        organization_id=principal.organization.id,
        scan_id_a=scan_id,
        scan_id_b=other_scan_id,
    )


# =============================================================================
# REVALIDAÇÃO DE CORREÇÕES
# =============================================================================


@router.post(
    "/findings/{finding_id}/revalidate",
    response_model=RevalidationResponse,
    summary="Executa scanner direcionado contra alvo autorizado para revalidar correção de vulnerabilidade",
)
def revalidate_finding(
    finding_id: str,
    payload: RevalidationRequest,
    db: DbSessionDep,
    principal: DeveloperPrincipalDep,
) -> RevalidationResponse:
    return RevalidationService.revalidate_finding(
        db=db,
        organization_id=principal.organization.id,
        user_id=principal.user.id,
        finding_id=finding_id,
        payload=payload,
        ip_address=principal.client_ip,
    )


# =============================================================================
# EVOLUÇÃO E MÉTRICAS TEMPORAIS (FASE 6)
# =============================================================================


@router.get(
    "/dashboard/evolution",
    response_model=DashboardEvolutionResponse,
    summary="Série temporal avançada da evolução do ciclo de vida das vulnerabilidades e MTTR",
)
def get_dashboard_evolution(
    db: DbSessionDep,
    principal: ViewerPrincipalDep,
    days: int = Query(default=30, ge=7, le=90),
) -> DashboardEvolutionResponse:
    return VulnerabilityService.dashboard_evolution(
        db=db,
        organization_id=principal.organization.id,
        days=days,
    )
