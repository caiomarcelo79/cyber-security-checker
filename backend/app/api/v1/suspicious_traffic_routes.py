"""Rotas para ingestão e consulta de análises explicáveis de tráfego suspeito."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import ValidationError

from app.api.deps import AuthenticatedPrincipal, DbSessionDep, require_minimum_role
from app.api.v1.network_telemetry_routes import CollectorTokenDep
from app.core.security import UserRole
from app.schemas.suspicious_traffic import TrafficAnalysisBatch, TrafficAnalysisRunResponse
from app.services.suspicious_traffic_service import (
    analyze_traffic_batch,
    get_asset_traffic_analysis,
    list_asset_traffic_analyses,
)

router = APIRouter(prefix="/api/v1", tags=["Tráfego suspeito"])
ViewerDep = Annotated[AuthenticatedPrincipal, Depends(require_minimum_role(UserRole.VIEWER))]
MAX_ANALYSIS_BODY_BYTES = 256 * 1024


def _require_user_session(principal: AuthenticatedPrincipal) -> None:
    if principal.api_token_scopes is not None:
        raise HTTPException(403, "A consulta de análises de tráfego requer sessão de usuário.")


async def read_analysis_batch(
    request: Request, token: CollectorTokenDep
) -> tuple[str, TrafficAnalysisBatch]:
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > MAX_ANALYSIS_BODY_BYTES:
            raise HTTPException(413, "O lote ultrapassou o limite de 256 KiB.")
        body.extend(chunk)
    try:
        return token, TrafficAnalysisBatch.model_validate_json(body)
    except ValidationError as exc:
        raise HTTPException(
            422, "Lote de análise de tráfego inválido. Confira os campos e limites."
        ) from exc


@router.post(
    "/telemetry/sources/{source_id}/traffic-analyses",
    response_model=TrafficAnalysisRunResponse,
    status_code=201,
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {
                    "schema": TrafficAnalysisBatch.model_json_schema(),
                }
            },
        }
    },
)
def run_traffic_analysis(
    source_id: UUID,
    upload: Annotated[tuple[str, TrafficAnalysisBatch], Depends(read_analysis_batch)],
    db: DbSessionDep,
) -> TrafficAnalysisRunResponse:
    token, batch = upload
    return analyze_traffic_batch(db, str(source_id), token, batch)


@router.get("/assets/{asset_id}/traffic-analyses", response_model=list[TrafficAnalysisRunResponse])
def list_traffic_analyses(
    asset_id: UUID, db: DbSessionDep, principal: ViewerDep
) -> list[TrafficAnalysisRunResponse]:
    _require_user_session(principal)
    return list_asset_traffic_analyses(db, principal.organization.id, str(asset_id))


@router.get(
    "/assets/{asset_id}/traffic-analyses/{run_id}",
    response_model=TrafficAnalysisRunResponse,
)
def get_traffic_analysis(
    asset_id: UUID, run_id: UUID, db: DbSessionDep, principal: ViewerDep
) -> TrafficAnalysisRunResponse:
    _require_user_session(principal)
    return get_asset_traffic_analysis(db, principal.organization.id, str(asset_id), str(run_id))
