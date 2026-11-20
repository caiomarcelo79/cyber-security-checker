"""Persistência e agregações de telemetria de rede."""

from datetime import datetime

from sqlalchemy import delete, func, select
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session

from app.models.entities import Asset, Organization, TelemetryConnection, TelemetrySource


def list_source_stats(
    db: Session, asset_id: str, source_id: str | None = None
) -> list[tuple[TelemetrySource, int, datetime | None]]:
    statement = (
        select(TelemetrySource, func.count(TelemetryConnection.uid), func.max(TelemetryConnection.observed_at))
        .outerjoin(TelemetryConnection, TelemetryConnection.source_id == TelemetrySource.id)
        .where(TelemetrySource.asset_id == asset_id)
        .group_by(TelemetrySource.id)
        .order_by(TelemetrySource.created_at.desc(), TelemetrySource.id)
    )
    if source_id is not None:
        statement = statement.where(TelemetrySource.id == source_id)
    rows = db.execute(statement)
    return [(source, count, newest) for source, count, newest in rows]


def find_collector_source(
    db: Session, source_id: str, token_hash: str, *, lock: bool = False
) -> tuple[TelemetrySource, str] | None:
    statement = (
        select(TelemetrySource, Asset.organization_id)
        .join(Asset, Asset.id == TelemetrySource.asset_id)
        .join(Organization, Organization.id == Asset.organization_id)
        .where(
            TelemetrySource.id == source_id,
            TelemetrySource.token_hash == token_hash,
            Organization.is_active.is_(True),
        )
    )
    if lock:
        statement = statement.with_for_update(of=TelemetrySource)
    row = db.execute(statement).one_or_none()
    return (row[0], row[1]) if row is not None else None


def existing_uids(db: Session, source_id: str, uids: list[str]) -> set[str]:
    return set(
        db.scalars(
            select(TelemetryConnection.uid).where(
                TelemetryConnection.source_id == source_id, TelemetryConnection.uid.in_(uids)
            )
        )
    )


def delete_received_before(db: Session, cutoff: datetime) -> int:
    result = db.execute(delete(TelemetryConnection).where(TelemetryConnection.received_at < cutoff))
    db.commit()
    return result.rowcount if isinstance(result, CursorResult) else 0
