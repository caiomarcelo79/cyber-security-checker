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
    CollectorHeartbeatRequest,
    ConnectionBatch,
    ConnectionImportResult,
    TelemetrySourceCreate,
    TelemetrySourceCreated,
    TelemetrySourceRecover,
    TelemetrySourceResponse,
    TelemetrySourceUpdate,
)
from app.services.asset_service import AssetAuthorizationService
from app.services.audit_service import AuditLogService
from app.services.lab_authorization import require_authorized_operational_asset
from app.services.pilot_logic import CollectorUpdateStatus, cidr_within_allowed

COLLECTOR_TOKEN_PREFIX = "csc_sensor_"
TELEMETRY_RETENTION_DAYS = 7


def _as_utc(value: datetime) -> datetime:
    return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)


def _collector_status(
    source: TelemetrySource, now: datetime
) -> Literal["ACTIVE", "PAUSED", "EXPIRED", "REVOKED"]:
    if source.revoked_at is not None:
        return "REVOKED"
    if _as_utc(source.expires_at) <= _as_utc(now):
        return "EXPIRED"
    if source.paused_at is not None:
        return "PAUSED"
    return "ACTIVE"


def _update_status(source: TelemetrySource) -> CollectorUpdateStatus:
    if source.desired_version is not None:
        if (
            source.collector_version == source.desired_version
            and source.applied_config_version == source.config_version
        ):
            return "UP_TO_DATE"
        return "UPDATE_AVAILABLE"
    if source.applied_config_version is None and source.collector_version is None:
        return "UNKNOWN"
    if source.applied_config_version == source.config_version:
        return "UP_TO_DATE"
    return "UPDATE_AVAILABLE"


def _source_summary(
    source: TelemetrySource, count: int, newest: datetime | None
) -> TelemetrySourceResponse:
    return TelemetrySourceResponse(
        id=source.id,
        name=source.name,
        network=source.network,
        status=_collector_status(source, utcnow()),
        expires_at=_as_utc(source.expires_at),
        paused_at=_as_utc(source.paused_at) if source.paused_at else None,
        collector_version=source.collector_version,
        desired_version=source.desired_version,
        poll_interval_seconds=source.poll_interval_seconds,
        config_version=source.config_version,
        applied_config_version=source.applied_config_version,
        token_generation=source.token_generation,
        update_status=_update_status(source),
        last_heartbeat_at=_as_utc(source.last_heartbeat_at) if source.last_heartbeat_at else None,
        last_received_at=_as_utc(source.last_received_at) if source.last_received_at else None,
        latest_observed_at=_as_utc(newest) if newest else None,
        connection_count=count,
    )


def _get_source_for_update(db: Session, asset_id: str, source_id: str) -> TelemetrySource:
    source = db.scalar(
        select(TelemetrySource)
        .where(TelemetrySource.id == source_id, TelemetrySource.asset_id == asset_id)
        .with_for_update()
    )
    if source is None:
        raise HTTPException(404, "Fonte de telemetria não encontrada.")
    return source


def _active_source_count(db: Session, asset_id: str, now: datetime) -> int:
    rows = db.scalars(select(TelemetrySource).where(TelemetrySource.asset_id == asset_id)).all()
    return sum(1 for row in rows if _collector_status(row, now) in {"ACTIVE", "PAUSED"})


def _stats_for_source(db: Session, source: TelemetrySource) -> tuple[int, datetime | None]:
    rows = list_source_stats(db, source.asset_id, source.id)
    if not rows:
        return 0, None
    _, count, newest = rows[0]
    return count, newest


def register_source(
    db: Session, principal: AuthenticatedPrincipal, asset_id: str, payload: TelemetrySourceCreate
) -> TelemetrySourceCreated:
    asset, enrollment = require_authorized_operational_asset(
        db,
        principal.organization.id,
        asset_id,
        capability="TELEMETRY",
        lock_authorization=True,
    )
    now = utcnow()
    network_str = str(payload.network)
    if enrollment is not None:
        if not cidr_within_allowed(network_str, enrollment.allowed_cidrs or []):
            raise HTTPException(
                422,
                "O segmento CIDR informado está fora do escopo autorizado para o piloto.",
            )
        if _active_source_count(db, asset.id, now) >= enrollment.max_sources:
            raise HTTPException(
                409,
                "Limite máximo de fontes ativas para este piloto atingido.",
            )

    token = f"{COLLECTOR_TOKEN_PREFIX}{token_urlsafe(32)}"
    source = TelemetrySource(
        asset_id=asset.id,
        name=payload.name,
        network=network_str,
        token_hash=sha256(token.encode("ascii")).hexdigest(),
        expires_at=now + timedelta(days=payload.expires_in_days),
        desired_version=payload.desired_version,
        poll_interval_seconds=payload.poll_interval_seconds,
        config_version=1,
        token_generation=1,
        updated_at=now,
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
        metadata={
            "asset_id": asset.id,
            "network": source.network,
            "desired_version": source.desired_version,
            "poll_interval_seconds": source.poll_interval_seconds,
        },
    )
    result = TelemetrySourceCreated(**_source_summary(source, 0, None).model_dump(), collector_token=token)
    db.commit()
    return result


def list_sources(db: Session, organization_id: str, asset_id: str) -> list[TelemetrySourceResponse]:
    asset = AssetAuthorizationService.get_asset_or_404(db, organization_id, asset_id)
    return [_source_summary(source, count, newest) for source, count, newest in list_source_stats(db, asset.id)]


def pause_source(
    db: Session, principal: AuthenticatedPrincipal, asset_id: str, source_id: str
) -> TelemetrySourceResponse:
    asset = AssetAuthorizationService.get_asset_or_404(db, principal.organization.id, asset_id)
    source = _get_source_for_update(db, asset.id, source_id)
    now = utcnow()
    current_status = _collector_status(source, now)
    if current_status in {"REVOKED", "EXPIRED"}:
        raise HTTPException(409, "Não é possível pausar uma fonte revogada ou expirada.")
    if current_status != "PAUSED":
        source.paused_at = now
        source.updated_at = now
        AuditLogService.record(
            db,
            action="TELEMETRY_SOURCE_PAUSED",
            resource_type="telemetry_source",
            resource_id=source.id,
            organization_id=principal.organization.id,
            user_id=principal.user.id,
            ip_address=principal.client_ip,
            metadata={"asset_id": asset.id},
        )
    count, newest = _stats_for_source(db, source)
    summary = _source_summary(source, count, newest)
    db.commit()
    return summary


def resume_source(
    db: Session, principal: AuthenticatedPrincipal, asset_id: str, source_id: str
) -> TelemetrySourceResponse:
    asset, _ = require_authorized_operational_asset(
        db,
        principal.organization.id,
        asset_id,
        capability="TELEMETRY",
        lock_authorization=True,
    )
    source = _get_source_for_update(db, asset.id, source_id)
    now = utcnow()
    current_status = _collector_status(source, now)
    if current_status in {"REVOKED", "EXPIRED"}:
        raise HTTPException(409, "Não é possível retomar uma fonte revogada ou expirada. Use recuperar credencial.")
    if current_status == "PAUSED":
        source.paused_at = None
        source.updated_at = now
        AuditLogService.record(
            db,
            action="TELEMETRY_SOURCE_RESUMED",
            resource_type="telemetry_source",
            resource_id=source.id,
            organization_id=principal.organization.id,
            user_id=principal.user.id,
            ip_address=principal.client_ip,
            metadata={"asset_id": asset.id},
        )
    count, newest = _stats_for_source(db, source)
    summary = _source_summary(source, count, newest)
    db.commit()
    return summary


def update_source(
    db: Session,
    principal: AuthenticatedPrincipal,
    asset_id: str,
    source_id: str,
    payload: TelemetrySourceUpdate,
) -> TelemetrySourceResponse:
    asset, enrollment = require_authorized_operational_asset(
        db,
        principal.organization.id,
        asset_id,
        capability="TELEMETRY",
        lock_authorization=True,
    )
    source = _get_source_for_update(db, asset.id, source_id)
    now = utcnow()
    if _collector_status(source, now) in {"REVOKED", "EXPIRED"}:
        raise HTTPException(409, "Não é possível atualizar uma fonte revogada ou expirada.")

    if payload.network is not None:
        network_str = str(payload.network)
        if enrollment is not None and not cidr_within_allowed(
            network_str, enrollment.allowed_cidrs or []
        ):
            raise HTTPException(
                422,
                "O segmento CIDR informado está fora do escopo autorizado para o piloto.",
            )
        source.network = network_str
    if payload.name is not None:
        source.name = payload.name
    if payload.desired_version is not None:
        source.desired_version = payload.desired_version
    if payload.poll_interval_seconds is not None:
        source.poll_interval_seconds = payload.poll_interval_seconds

    source.config_version += 1
    source.updated_at = now
    AuditLogService.record(
        db,
        action="TELEMETRY_SOURCE_UPDATED",
        resource_type="telemetry_source",
        resource_id=source.id,
        organization_id=principal.organization.id,
        user_id=principal.user.id,
        ip_address=principal.client_ip,
        metadata={
            "asset_id": asset.id,
            "network": source.network,
            "desired_version": source.desired_version,
            "poll_interval_seconds": source.poll_interval_seconds,
            "config_version": source.config_version,
        },
    )
    count, newest = _stats_for_source(db, source)
    summary = _source_summary(source, count, newest)
    db.commit()
    return summary


def recover_source(
    db: Session,
    principal: AuthenticatedPrincipal,
    asset_id: str,
    source_id: str,
    payload: TelemetrySourceRecover,
) -> TelemetrySourceCreated:
    asset, enrollment = require_authorized_operational_asset(
        db,
        principal.organization.id,
        asset_id,
        capability="TELEMETRY",
        lock_authorization=True,
    )
    source = _get_source_for_update(db, asset.id, source_id)
    now = utcnow()
    previous_status = _collector_status(source, now)
    if (
        previous_status in {"REVOKED", "EXPIRED"}
        and enrollment is not None
        and _active_source_count(db, asset.id, now) >= enrollment.max_sources
    ):
        raise HTTPException(
            409,
            "Limite máximo de fontes ativas para este piloto atingido.",
        )

    token = f"{COLLECTOR_TOKEN_PREFIX}{token_urlsafe(32)}"
    source.token_hash = sha256(token.encode("ascii")).hexdigest()
    source.revoked_at = None
    source.paused_at = None
    source.expires_at = now + timedelta(days=payload.expires_in_days)
    source.token_generation += 1
    source.config_version += 1
    source.updated_at = now

    AuditLogService.record(
        db,
        action="TELEMETRY_SOURCE_RECOVERED",
        resource_type="telemetry_source",
        resource_id=source.id,
        organization_id=principal.organization.id,
        user_id=principal.user.id,
        ip_address=principal.client_ip,
        metadata={
            "asset_id": asset.id,
            "previous_status": previous_status,
            "token_generation": source.token_generation,
            "config_version": source.config_version,
        },
    )
    count, newest = _stats_for_source(db, source)
    summary = _source_summary(source, count, newest)
    result = TelemetrySourceCreated(**summary.model_dump(), collector_token=token)
    db.commit()
    return result


def revoke_source(db: Session, principal: AuthenticatedPrincipal, asset_id: str, source_id: str) -> None:
    asset = AssetAuthorizationService.get_asset_or_404(db, principal.organization.id, asset_id)
    source = _get_source_for_update(db, asset.id, source_id)
    if source.revoked_at is None:
        now = utcnow()
        source.revoked_at = now
        source.updated_at = now
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
    db: Session,
    source_id: str,
    token: str,
    *,
    lock: bool = False,
    allow_paused: bool = False,
    capability: str = "TELEMETRY",
) -> TelemetrySource:
    active_source = find_collector_source(db, source_id, sha256(token.encode("ascii")).hexdigest(), lock=lock)
    now = utcnow()
    if active_source is None:
        raise HTTPException(401, "Credencial do coletor inválida, expirada ou revogada.")
    source, organization_id = active_source
    status = _collector_status(source, now)
    if status in {"REVOKED", "EXPIRED"}:
        raise HTTPException(401, "Credencial do coletor inválida, expirada ou revogada.")
    if status == "PAUSED" and not allow_paused:
        raise HTTPException(409, "A fonte de telemetria está pausada pelo operador.")
    require_authorized_operational_asset(
        db,
        organization_id,
        source.asset_id,
        capability=capability,
        lock_authorization=lock,
    )
    return source


def get_collector_status(db: Session, source_id: str, token: str) -> TelemetrySourceResponse:
    source = require_collector_source(db, source_id, token, allow_paused=True)
    rows = list_source_stats(db, source.asset_id, source.id)
    if not rows:
        raise HTTPException(401, "Fonte de telemetria indisponível.")
    return _source_summary(*rows[0])


def record_collector_heartbeat(
    db: Session, source_id: str, token: str, payload: CollectorHeartbeatRequest
) -> TelemetrySourceResponse:
    source = require_collector_source(db, source_id, token, lock=True, allow_paused=True)
    now = utcnow()
    source.collector_version = payload.collector_version
    if payload.applied_config_version is not None:
        source.applied_config_version = min(payload.applied_config_version, source.config_version)
    source.last_heartbeat_at = now
    source.updated_at = now
    count, newest = _stats_for_source(db, source)
    summary = _source_summary(source, count, newest)
    db.commit()
    return summary


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
