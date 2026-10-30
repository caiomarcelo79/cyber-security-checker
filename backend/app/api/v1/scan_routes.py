"""Rotas REST v1 para criação, acompanhamento em tempo real, cancelamento e resultados de Auditorias (Fase 3)."""

from __future__ import annotations

import asyncio
import json
import os
import threading
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.api.deps import (
    AuthenticatedPrincipal,
    require_minimum_role,
)
from app.core.database import get_db, get_stream_session_factory
from app.core.security import UserRole
from app.models.entities import ReportRecord
from app.schemas.reports import ReportCreateRequest
from app.schemas.scans import (
    FindingHistoryResponse,
    FindingPageResponse,
    FindingResponse,
    FindingTriageUpdateRequest,
    ScanCheckResultResponse,
    ScanCreateRequest,
    ScanDetailedResultsResponse,
    ScanEventItem,
    ScanPageResponse,
    ScanProgressResponse,
    ScanResponse,
)
from app.schemas.system import DashboardTrendsResponse
from app.services.audit_service import AuditLogService
from app.services.report_engine import ReportEngine
from app.services.scan_orchestrator import ScanOrchestrator
from app.services.vulnerability_service import VulnerabilityService

router = APIRouter(prefix="/api/v1", tags=["phase3-4-scans-findings"])

DbSessionDep = Annotated[Session, Depends(get_db)]
ViewerPrincipalDep = Annotated[AuthenticatedPrincipal, Depends(require_minimum_role(UserRole.VIEWER))]
DeveloperPrincipalDep = Annotated[
    AuthenticatedPrincipal, Depends(require_minimum_role(UserRole.DEVELOPER))
]
AnalystPrincipalDep = Annotated[
    AuthenticatedPrincipal, Depends(require_minimum_role(UserRole.SECURITY_ANALYST))
]


@router.post(
    "/scans",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Cria e inicia uma auditoria de segurança sobre um ativo autorizado (Requer SECURITY_ANALYST ou ADMIN)",
)
def create_scan(
    payload: ScanCreateRequest,
    db: DbSessionDep,
    principal: AnalystPrincipalDep,
) -> ScanResponse:
    return ScanOrchestrator.create_and_dispatch_scan(
        db=db,
        organization_id=principal.organization.id,
        user_id=principal.user.id,
        payload=payload,
        ip_address=principal.client_ip,
    )


@router.get(
    "/scans",
    response_model=list[ScanResponse],
    summary="Lista as auditorias da organização ativa com filtro opcional por ativo",
)
def list_scans(
    db: DbSessionDep,
    principal: ViewerPrincipalDep,
    asset_id: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
) -> list[ScanResponse]:
    ScanOrchestrator.recover_interrupted_scans(db=db, organization_id=principal.organization.id)
    return ScanOrchestrator.list_scans(
        db=db,
        organization_id=principal.organization.id,
        asset_id=asset_id,
        limit=limit,
    )


SSE_POLL_INTERVAL_SECONDS = 1.0
SSE_HEARTBEAT_SECONDS = 15.0
SSE_MAX_DURATION_SECONDS = 900.0
SSE_MAX_STREAMS_PER_ORG = 5
TERMINAL_SCAN_STATUSES = {
    "COMPLETED",
    "PARTIALLY_COMPLETED",
    "FAILED",
    "CANCELLED",
    "ABORTED_TARGET_DEGRADED",
}
_sse_lock = threading.Lock()
_sse_active: dict[str, int] = {}


def _read_progress_json(
    factory: sessionmaker[Session], scan_id: str, organization_id: str
) -> tuple[str, bool]:
    """Lê o progresso persistido em uma sessão própria (sem cache) e indica se é terminal."""
    with factory() as session:
        progress = ScanOrchestrator.get_scan_progress(session, organization_id, scan_id)
    return progress.model_dump_json(), progress.status in TERMINAL_SCAN_STATUSES


@router.get(
    "/scans/page",
    response_model=ScanPageResponse,
    summary="Lista auditorias com busca, filtros (ativo, estado, período), ordenação e paginação no servidor",
)
def page_scans(
    db: DbSessionDep,
    principal: ViewerPrincipalDep,
    asset_id: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    search: str | None = Query(default=None, max_length=120),
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    sort_by: str = Query(default="created_at"),
    sort_desc: bool = Query(default=True),
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> ScanPageResponse:
    return VulnerabilityService.page_scans(
        db,
        principal.organization.id,
        asset_id=asset_id,
        status_filter=status_filter,
        search=search,
        date_from=date_from,
        date_to=date_to,
        sort_by=sort_by,
        sort_desc=sort_desc,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/scans/{scan_id}/stream",
    summary="Fluxo SSE do progresso real da auditoria (autenticado, isolado por organização)",
)
async def stream_scan_progress(
    scan_id: str,
    request: Request,
    db: DbSessionDep,
    principal: ViewerPrincipalDep,
    session_factory: Annotated[sessionmaker[Session], Depends(get_stream_session_factory)],
) -> StreamingResponse:
    organization_id = principal.organization.id
    ScanOrchestrator.get_scan_or_404(db, organization_id, scan_id)
    with _sse_lock:
        if _sse_active.get(organization_id, 0) >= SSE_MAX_STREAMS_PER_ORG:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Limite de conexões de acompanhamento em tempo real atingido.",
            )
        _sse_active[organization_id] = _sse_active.get(organization_id, 0) + 1

    async def event_stream():  # type: ignore[no-untyped-def]
        loop = asyncio.get_running_loop()
        started = loop.time()
        last_payload: str | None = None
        last_beat = started
        try:
            while True:
                payload, terminal = await asyncio.to_thread(
                    _read_progress_json, session_factory, scan_id, organization_id
                )
                if payload != last_payload:
                    last_payload = payload
                    yield f"event: progress\ndata: {payload}\n\n"
                if terminal:
                    yield f"event: end\ndata: {json.dumps({'scan_id': scan_id})}\n\n"
                    return
                now = loop.time()
                if now - started > SSE_MAX_DURATION_SECONDS:
                    yield "event: timeout\ndata: {}\n\n"
                    return
                if now - last_beat >= SSE_HEARTBEAT_SECONDS:
                    last_beat = now
                    yield ": heartbeat\n\n"
                if await request.is_disconnected():
                    return
                await asyncio.sleep(SSE_POLL_INTERVAL_SECONDS)
        finally:
            with _sse_lock:
                remaining = _sse_active.get(organization_id, 1) - 1
                if remaining <= 0:
                    _sse_active.pop(organization_id, None)
                else:
                    _sse_active[organization_id] = remaining

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get(
    "/scans/{scan_id}/events",
    response_model=list[ScanEventItem],
    summary="Histórico de eventos administrativos da auditoria (trilha de auditoria)",
)
def list_scan_events(
    scan_id: str, db: DbSessionDep, principal: ViewerPrincipalDep
) -> list[ScanEventItem]:
    return VulnerabilityService.scan_events(db, principal.organization.id, scan_id)


@router.get(
    "/dashboard/trends",
    response_model=DashboardTrendsResponse,
    summary="Série histórica diária persistida: detecções, correções e auditorias",
)
def dashboard_trends(
    db: DbSessionDep,
    principal: ViewerPrincipalDep,
    days: int = Query(default=30, ge=7, le=180),
) -> DashboardTrendsResponse:
    return VulnerabilityService.dashboard_trends(db, principal.organization.id, days)


@router.get(
    "/findings/page",
    response_model=FindingPageResponse,
    summary="Vulnerabilidades consolidadas (detecção mais recente) com filtros, busca, ordenação e paginação",
)
def page_findings(
    db: DbSessionDep,
    principal: ViewerPrincipalDep,
    asset_id: str | None = Query(default=None),
    scan_id: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    treatment_status: str | None = Query(default=None),
    confidence: str | None = Query(default=None),
    cwe_id: str | None = Query(default=None),
    owasp_category: str | None = Query(default=None),
    category: str | None = Query(default=None),
    module_id: str | None = Query(default=None),
    search: str | None = Query(default=None, max_length=120),
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    include_history: bool = Query(default=False),
    sort_by: str = Query(default="last_confirmed_at"),
    sort_desc: bool = Query(default=True),
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> FindingPageResponse:
    return VulnerabilityService.page_findings(
        db,
        principal.organization.id,
        asset_id=asset_id,
        scan_id=scan_id,
        severity=severity,
        treatment_status=treatment_status,
        confidence=confidence,
        cwe_id=cwe_id,
        owasp_category=owasp_category,
        category=category,
        module_id=module_id,
        search=search,
        date_from=date_from,
        date_to=date_to,
        include_history=include_history,
        sort_by=sort_by,
        sort_desc=sort_desc,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/findings/{finding_id}/history",
    response_model=FindingHistoryResponse,
    summary="Histórico de detecções e triagem de uma vulnerabilidade",
)
def finding_history(
    finding_id: str, db: DbSessionDep, principal: ViewerPrincipalDep
) -> FindingHistoryResponse:
    return VulnerabilityService.finding_history(db, principal.organization.id, finding_id)


@router.get(
    "/scans/{scan_id}",
    response_model=ScanResponse,
    summary="Consulta detalhes de uma auditoria da organização ativa",
)
def get_scan(
    scan_id: str,
    db: DbSessionDep,
    principal: ViewerPrincipalDep,
) -> ScanResponse:
    scan = ScanOrchestrator.get_scan_or_404(
        db=db,
        organization_id=principal.organization.id,
        scan_id=scan_id,
    )
    return ScanOrchestrator._to_scan_response(scan)


@router.get(
    "/scans/{scan_id}/progress",
    response_model=ScanProgressResponse,
    summary="Consulta o progresso em tempo real, módulos concluídos e estado da auditoria",
)
def get_scan_progress(
    scan_id: str,
    db: DbSessionDep,
    principal: ViewerPrincipalDep,
) -> ScanProgressResponse:
    return ScanOrchestrator.get_scan_progress(
        db=db,
        organization_id=principal.organization.id,
        scan_id=scan_id,
    )


@router.get(
    "/scans/{scan_id}/results",
    response_model=ScanDetailedResultsResponse,
    summary="Obtém resultados consolidados da auditoria incluindo todas as verificações e descobertas",
)
def get_scan_results(
    scan_id: str,
    db: DbSessionDep,
    principal: ViewerPrincipalDep,
) -> ScanDetailedResultsResponse:
    return ScanOrchestrator.get_scan_detailed_results(
        db=db,
        organization_id=principal.organization.id,
        scan_id=scan_id,
    )


@router.get(
    "/scans/{scan_id}/checks",
    response_model=list[ScanCheckResultResponse],
    summary="Lista os resultados individuais de cada verificação (PASSED, VULNERABILITY, EXECUTION_ERROR, etc.)",
)
def list_scan_checks(
    scan_id: str,
    db: DbSessionDep,
    principal: ViewerPrincipalDep,
) -> list[ScanCheckResultResponse]:
    detailed = ScanOrchestrator.get_scan_detailed_results(
        db=db,
        organization_id=principal.organization.id,
        scan_id=scan_id,
    )
    return detailed.checks


@router.get(
    "/scans/{scan_id}/export-pdf",
    summary="Exporta diretamente o relatório em PDF da auditoria com medidas protetivas e diagnósticos",
)
def export_scan_pdf(
    scan_id: str,
    db: DbSessionDep,
    principal: ViewerPrincipalDep,
) -> FileResponse:
    scan = ScanOrchestrator.get_scan_or_404(
        db=db,
        organization_id=principal.organization.id,
        scan_id=scan_id,
    )

    existing_report = db.scalar(
        select(ReportRecord)
        .where(
            ReportRecord.scan_id == scan_id,
            ReportRecord.organization_id == principal.organization.id,
            ReportRecord.format == "PDF",
            ReportRecord.status == "COMPLETED",
        )
        .order_by(ReportRecord.created_at.desc())
    )

    if existing_report and existing_report.file_path and os.path.exists(existing_report.file_path):
        report = existing_report
    else:
        create_req = ReportCreateRequest(
            title=f"Relatório de Segurança - Auditoria {scan.id[:8]}",
            report_type="TECHNICAL",
            format="PDF",
            scan_id=scan.id,
            asset_id=scan.asset_id,
            execute_synchronously=True,
        )
        rep_resp = ReportEngine.create_report(
            db=db,
            organization_id=principal.organization.id,
            user_id=principal.user.id,
            payload=create_req,
            ip_address=principal.client_ip,
        )
        report = ReportEngine.get_report_or_404(db, principal.organization.id, rep_resp.id)

    if not report.file_path or not os.path.exists(report.file_path):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Falha ao gerar o arquivo PDF do relatório.",
        )

    AuditLogService.record(
        db=db,
        action="SCAN_PDF_EXPORTED",
        resource_type="scan",
        resource_id=scan.id,
        organization_id=principal.organization.id,
        user_id=principal.user.id,
        ip_address=principal.client_ip,
        metadata={"scan_id": scan.id, "report_id": report.id},
    )

    filename = f"csc-auditoria-{scan.id[:8]}.pdf"
    return FileResponse(
        path=report.file_path,
        media_type="application/pdf",
        filename=filename,
    )


@router.post(
    "/scans/{scan_id}/cancel",
    response_model=ScanResponse,
    summary="Cancela cooperativamente uma auditoria pendente, na fila ou em execução (Requer SECURITY_ANALYST ou ADMIN)",
)
def cancel_scan(
    scan_id: str,
    db: DbSessionDep,
    principal: AnalystPrincipalDep,
) -> ScanResponse:
    return ScanOrchestrator.cancel_scan(
        db=db,
        organization_id=principal.organization.id,
        user_id=principal.user.id,
        scan_id=scan_id,
        ip_address=principal.client_ip,
    )


@router.get(
    "/findings",
    response_model=list[FindingResponse],
    summary="Lista vulnerabilidades e indícios técnicos da organização ativa com filtros avançados (Fase 4)",
)
def list_findings(
    db: DbSessionDep,
    principal: ViewerPrincipalDep,
    asset_id: str | None = Query(default=None),
    scan_id: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    treatment_status: str | None = Query(default=None),
    confidence: str | None = Query(default=None),
    cwe_id: str | None = Query(default=None),
    owasp_category: str | None = Query(default=None),
    search: str | None = Query(default=None),
) -> list[FindingResponse]:
    return ScanOrchestrator.list_organization_findings(
        db=db,
        organization_id=principal.organization.id,
        asset_id=asset_id,
        scan_id=scan_id,
        severity=severity,
        treatment_status=treatment_status,
        confidence=confidence,
        cwe_id=cwe_id,
        owasp_category=owasp_category,
        search=search,
    )


@router.get(
    "/findings/{finding_id}",
    response_model=FindingResponse,
    summary="Obtém os detalhes completos de uma vulnerabilidade específica da organização ativa",
)
def get_finding(
    finding_id: str,
    db: DbSessionDep,
    principal: ViewerPrincipalDep,
) -> FindingResponse:
    finding = ScanOrchestrator.get_finding_or_404(
        db=db,
        organization_id=principal.organization.id,
        finding_id=finding_id,
    )
    return ScanOrchestrator._to_finding_response(finding)


@router.patch(
    "/findings/{finding_id}/status",
    response_model=FindingResponse,
    summary="Atualiza o status de tratamento (triagem) de uma vulnerabilidade e recalcula o risco do ativo",
)
def update_finding_status(
    finding_id: str,
    payload: FindingTriageUpdateRequest,
    db: DbSessionDep,
    principal: DeveloperPrincipalDep,
) -> FindingResponse:
    return ScanOrchestrator.update_finding_status(
        db=db,
        organization_id=principal.organization.id,
        user_id=principal.user.id,
        finding_id=finding_id,
        payload=payload,
        ip_address=principal.client_ip,
    )
