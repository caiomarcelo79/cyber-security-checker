"""Ciclo de vida de fontes e importação de telemetria passiva."""

from datetime import UTC, datetime, timedelta
from hashlib import sha256
from ipaddress import ip_network
from secrets import token_urlsafe
from typing import Literal

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import AuthenticatedPrincipal
from app.models.entities import TelemetryConnection, TelemetrySource, utcnow
from app.repositories.network_telemetry import (
    delete_received_before,
    existing_uids,
    find_collector_source,
    list_source_stats,
)
from app.schemas.network_telemetry import (
    ConnectionBatch,
    ConnectionImportResult,
    TelemetrySourceCreate,
    TelemetrySourceCreated,
    TelemetrySourceResponse,
)
from app.services.asset_service import AssetAuthorizationService
from app.services.audit_service import AuditLogService
from app.services.lab_authorization import require_authorized_lab_asset

COLLECTOR_TOKEN_PREFIX = "csc_sensor_"
TELEMETRY_RETENTION_DAYS = 7


def _as_utc(value: datetime) -> datetime:
    return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)


def _collector_status(
    source: TelemetrySource, now: datetime
) -> Literal["ACTIVE", "EXPIRED", "REVOKED"]:
    if source.revoked_at is not None:
        return "REVOKED"
    return "EXPIRED" if _as_utc(source.expires_at) <= now else "ACTIVE"


def _source_summary(
    source: TelemetrySource, count: int, newest: datetime | None
) -> TelemetrySourceResponse:
    return TelemetrySourceResponse(
        id=source.id,
        name=source.name,
        network=source.network,
        status=_collector_status(source, utcnow()),
        expires_at=_as_utc(source.expires_at),
        last_received_at=_as_utc(source.last_received_at) if source.last_received_at else None,
        latest_observed_at=_as_utc(newest) if newest else None,
        connection_count=count,
    )


def register_source(
    db: Session, principal: AuthenticatedPrincipal, asset_id: str, payload: TelemetrySourceCreate
) -> TelemetrySourceCreated:
    asset = require_authorized_lab_asset(db, principal.organization.id, asset_id, lock_authorization=True)
    token = f"{COLLECTOR_TOKEN_PREFIX}{token_urlsafe(32)}"
    source = TelemetrySource(
        asset_id=asset.id,
        name=payload.name,
        network=str(payload.network),
        token_hash=sha256(token.encode("ascii")).hexdigest(),
        expires_at=utcnow() + timedelta(days=payload.expires_in_days),
    )
    db.add(source)
    db.flush()
    AuditLogService.record(
        db,
        action="TELEMETRY_SOURCE_REGISTERED",
        resource_type="telemetry_source",
        resource_id=source.id,
        organization_id=principal.organization.id,
        user_id=principal.user.id,
        ip_address=principal.client_ip,
        metadata={"asset_id": asset.id, "network": source.network},
    )
    result = TelemetrySourceCreated(**_source_summary(source, 0, None).model_dump(), collector_token=token)
    db.commit()
    return result


def list_sources(db: Session, organization_id: str, asset_id: str) -> list[TelemetrySourceResponse]:
    asset = AssetAuthorizationService.get_asset_or_404(db, organization_id, asset_id)
    return [_source_summary(source, count, newest) for source, count, newest in list_source_stats(db, asset.id)]


def revoke_source(db: Session, principal: AuthenticatedPrincipal, asset_id: str, source_id: str) -> None:
    asset = AssetAuthorizationService.get_asset_or_404(db, principal.organization.id, asset_id)
    source = db.scalar(
        select(TelemetrySource)
        .where(TelemetrySource.id == source_id, TelemetrySource.asset_id == asset.id)
        .with_for_update()
    )
    if source is None:
        raise HTTPException(404, "Fonte de telemetria não encontrada.")
    if source.revoked_at is None:
        source.revoked_at = utcnow()
        AuditLogService.record(
            db,
            action="TELEMETRY_SOURCE_REVOKED",
            resource_type="telemetry_source",
            resource_id=source.id,
            organization_id=principal.organization.id,
            user_id=principal.user.id,
            ip_address=principal.client_ip,
            metadata={"asset_id": asset.id},
        )
    db.commit()


def require_collector_source(
    db: Session, source_id: str, token: str, *, lock: bool = False
) -> TelemetrySource:
    active_source = find_collector_source(db, source_id, sha256(token.encode("ascii")).hexdigest(), lock=lock)
    now = utcnow()
    if active_source is None or _collector_status(active_source[0], now) != "ACTIVE":
        raise HTTPException(401, "Credencial do coletor inválida, expirada ou revogada.")
    source, organization_id = active_source
    require_authorized_lab_asset(db, organization_id, source.asset_id, lock_authorization=lock)
    return source


def get_collector_status(db: Session, source_id: str, token: str) -> TelemetrySourceResponse:
    source = require_collector_source(db, source_id, token)
    rows = list_source_stats(db, source.asset_id, source.id)
    if not rows:
        raise HTTPException(401, "Fonte de telemetria indisponível.")
    return _source_summary(*rows[0])


def import_connections(
    db: Session, source_id: str, token: str, batch: ConnectionBatch
) -> ConnectionImportResult:
    source = require_collector_source(db, source_id, token, lock=True)
    now = utcnow()
    network = ip_network(source.network)
    if any(event.origin_ip not in network and event.responder_ip not in network for event in batch.events):
        raise HTTPException(422, "O lote contém conexão fora do segmento autorizado.")

    known_uids = existing_uids(db, source.id, [event.uid for event in batch.events])
    inserted = 0
    for event in batch.events:
        if event.uid in known_uids:
            continue
        known_uids.add(event.uid)
        db.add(
            TelemetryConnection(
                source_id=source.id,
                received_at=now,
                **event.model_dump(mode="json", exclude={"observed_at"}),
                observed_at=event.observed_at,
            )
        )
        inserted += 1
    source.last_received_at = now
    db.commit()
    return ConnectionImportResult(inserted=inserted, duplicates=len(batch.events) - inserted)


def purge_expired_connections(db: Session) -> int:
    return delete_received_before(db, utcnow() - timedelta(days=TELEMETRY_RETENTION_DAYS))
