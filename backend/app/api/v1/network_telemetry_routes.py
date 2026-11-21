"""Gerencia fontes, ciclo operacional e lotes autenticados do coletor."""

import re
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import ValidationError

from app.api.deps import AuthenticatedPrincipal, DbSessionDep, require_minimum_role
from app.core.security import UserRole
from app.schemas.network_telemetry import (
    CollectorHeartbeatRequest,
    ConnectionBatch,
    ConnectionImportResult,
    ConnectionObservation,
    TelemetrySourceCreate,
    TelemetrySourceCreated,
    TelemetrySourceRecover,
    TelemetrySourceResponse,
    TelemetrySourceUpdate,
)
from app.services.network_telemetry import (
    COLLECTOR_TOKEN_PREFIX,
    get_collector_status,
    import_connections,
    list_sources,
    pause_source,
    record_collector_heartbeat,
    recover_source,
    register_source,
    resume_source,
    revoke_source,
    update_source,
)

router = APIRouter(prefix="/api/v1", tags=["Telemetria de rede"])
ViewerDep = Annotated[AuthenticatedPrincipal, Depends(require_minimum_role(UserRole.VIEWER))]
AnalystDep = Annotated[AuthenticatedPrincipal, Depends(require_minimum_role(UserRole.SECURITY_ANALYST))]
ASSET_SOURCES = "/assets/{asset_id}/telemetry-sources"
MAX_BATCH_BODY_BYTES = 128 * 1024
COLLECTOR_AUTHORIZATION = re.compile(rf"(?i:Bearer) ({COLLECTOR_TOKEN_PREFIX}[A-Za-z0-9_-]{{43}})")


def _require_user_session(principal: AuthenticatedPrincipal) -> None:
    if principal.api_token_scopes is not None:
        raise HTTPException(403, "A gestão de fontes requer uma sessão de usuário.")


@router.get(ASSET_SOURCES)
def get_sources(asset_id: UUID, db: DbSessionDep, principal: ViewerDep) -> list[TelemetrySourceResponse]:
    _require_user_session(principal)
    return list_sources(db, principal.organization.id, str(asset_id))


@router.post(ASSET_SOURCES, status_code=201)
def create_source(
    asset_id: UUID, payload: TelemetrySourceCreate, db: DbSessionDep, principal: AnalystDep
) -> TelemetrySourceCreated:
    _require_user_session(principal)
    return register_source(db, principal, str(asset_id), payload)


@router.post(f"{ASSET_SOURCES}/{{source_id}}/pause", response_model=TelemetrySourceResponse)
def pause_telemetry_source(
    asset_id: UUID, source_id: UUID, db: DbSessionDep, principal: AnalystDep
) -> TelemetrySourceResponse:
    _require_user_session(principal)
    return pause_source(db, principal, str(asset_id), str(source_id))


@router.post(f"{ASSET_SOURCES}/{{source_id}}/resume", response_model=TelemetrySourceResponse)
def resume_telemetry_source(
    asset_id: UUID, source_id: UUID, db: DbSessionDep, principal: AnalystDep
) -> TelemetrySourceResponse:
    _require_user_session(principal)
    return resume_source(db, principal, str(asset_id), str(source_id))


@router.patch(f"{ASSET_SOURCES}/{{source_id}}", response_model=TelemetrySourceResponse)
def patch_telemetry_source(
    asset_id: UUID,
    source_id: UUID,
    payload: TelemetrySourceUpdate,
    db: DbSessionDep,
    principal: AnalystDep,
) -> TelemetrySourceResponse:
    _require_user_session(principal)
    return update_source(db, principal, str(asset_id), str(source_id), payload)


@router.post(f"{ASSET_SOURCES}/{{source_id}}/recover", response_model=TelemetrySourceCreated)
def recover_telemetry_source(
    asset_id: UUID,
    source_id: UUID,
    db: DbSessionDep,
    principal: AnalystDep,
    payload: TelemetrySourceRecover | None = None,
) -> TelemetrySourceCreated:
    _require_user_session(principal)
    return recover_source(
        db,
        principal,
        str(asset_id),
        str(source_id),
        payload or TelemetrySourceRecover(),
    )


@router.delete(f"{ASSET_SOURCES}/{{source_id}}", status_code=204)
def deactivate_source(asset_id: UUID, source_id: UUID, db: DbSessionDep, principal: AnalystDep) -> Response:
    _require_user_session(principal)
    revoke_source(db, principal, str(asset_id), str(source_id))
    return Response(status_code=204)


def read_collector_token(request: Request) -> str:
    auth = COLLECTOR_AUTHORIZATION.fullmatch(request.headers.get("authorization", ""))
    if auth is None:
        raise HTTPException(401, "Forneça a credencial da instalação do coletor.")
    return auth[1]


CollectorTokenDep = Annotated[str, Depends(read_collector_token)]


@router.get("/telemetry/sources/{source_id}")
def collector_status(source_id: UUID, token: CollectorTokenDep, db: DbSessionDep) -> TelemetrySourceResponse:
    return get_collector_status(db, str(source_id), token)


@router.post("/telemetry/sources/{source_id}/heartbeat", response_model=TelemetrySourceResponse)
def collector_heartbeat(
    source_id: UUID,
    payload: CollectorHeartbeatRequest,
    token: CollectorTokenDep,
    db: DbSessionDep,
) -> TelemetrySourceResponse:
    return record_collector_heartbeat(db, str(source_id), token, payload)


async def read_collector_batch(request: Request, token: CollectorTokenDep) -> tuple[str, ConnectionBatch]:
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > MAX_BATCH_BODY_BYTES:
            raise HTTPException(413, "O lote ultrapassou o limite de 128 KiB.")
        body.extend(chunk)
    try:
        return token, ConnectionBatch.model_validate_json(body)
    except ValidationError as exc:
        raise HTTPException(422, "Lote de telemetria inválido. Confira o formato e o tamanho.") from exc


@router.post(
    "/telemetry/sources/{source_id}/connections",
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "events": {
                                "type": "array",
                                "items": ConnectionObservation.model_json_schema(),
                            },
                        },
                        "required": ["events"],
                    },
                }
            },
        },
    },
)
def ingest(
    source_id: UUID, upload: Annotated[tuple[str, ConnectionBatch], Depends(read_collector_batch)], db: DbSessionDep
) -> ConnectionImportResult:
    token, batch = upload
    return import_connections(db, str(source_id), token, batch)
