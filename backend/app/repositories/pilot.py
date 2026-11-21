"""Consultas e persistência para habilitações de piloto e revisões de expansão (Fase 6)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.entities import (
    AiTriageSuggestion,
    Asset,
    AuditLog,
    AvailabilityExercise,
    FindingRecord,
    OrganizationMembership,
    PilotEnrollment,
    PilotReview,
    SshAudit,
    TargetAuthorization,
    TelemetryConnection,
    TelemetrySource,
    TrafficAnalysisRun,
)
from app.repositories.finding_views import current_finding_ids_stmt

SOURCE_LIFECYCLE_AUDIT_ACTIONS = (
    "TELEMETRY_SOURCE_PAUSED",
    "TELEMETRY_SOURCE_RESUMED",
    "TELEMETRY_SOURCE_UPDATED",
    "TELEMETRY_SOURCE_REVOKED",
    "TELEMETRY_SOURCE_RECOVERED",
)


def list_pilots_with_assets(
    db: Session, organization_id: str
) -> list[tuple[PilotEnrollment, Asset]]:
    stmt = (
        select(PilotEnrollment, Asset)
        .join(Asset, Asset.id == PilotEnrollment.asset_id)
        .where(PilotEnrollment.organization_id == organization_id)
        .order_by(PilotEnrollment.created_at.desc(), PilotEnrollment.id.desc())
    )
    return [(row[0], row[1]) for row in db.execute(stmt)]


def list_asset_enrollments(
    db: Session, organization_id: str, asset_id: str
) -> list[PilotEnrollment]:
    return list(
        db.scalars(
            select(PilotEnrollment).where(
                PilotEnrollment.organization_id == organization_id,
                PilotEnrollment.asset_id == asset_id,
            )
        )
    )


def find_pilot_with_asset(
    db: Session, organization_id: str, pilot_id: str, *, lock: bool = False
) -> tuple[PilotEnrollment, Asset] | None:
    stmt = (
        select(PilotEnrollment, Asset)
        .join(Asset, Asset.id == PilotEnrollment.asset_id)
        .where(
            PilotEnrollment.id == pilot_id,
            PilotEnrollment.organization_id == organization_id,
        )
    )
    if lock:
        stmt = stmt.with_for_update(of=PilotEnrollment)
    row = db.execute(stmt).one_or_none()
    return (row[0], row[1]) if row is not None else None


def find_user_membership_in_org(
    db: Session, user_id: str, organization_id: str
) -> OrganizationMembership | None:
    return db.scalar(
        select(OrganizationMembership).where(
            OrganizationMembership.user_id == user_id,
            OrganizationMembership.organization_id == organization_id,
        )
    )


def list_reviews_for_pilots(
    db: Session, pilot_ids: list[str]
) -> dict[str, list[PilotReview]]:
    if not pilot_ids:
        return {}
    rows = list(
        db.scalars(
            select(PilotReview)
            .where(PilotReview.pilot_id.in_(pilot_ids))
            .order_by(PilotReview.created_at.desc(), PilotReview.id.desc())
        )
    )
    grouped: dict[str, list[PilotReview]] = {}
    for row in rows:
        grouped.setdefault(row.pilot_id, []).append(row)
    return grouped


def has_valid_authorization_for_method(
    db: Session,
    organization_id: str,
    asset_id: str,
    methods: tuple[str, ...],
    now: datetime,
) -> bool:
    auth_id = db.scalar(
        select(TargetAuthorization.id)
        .where(
            TargetAuthorization.asset_id == asset_id,
            TargetAuthorization.organization_id == organization_id,
            TargetAuthorization.method.in_(methods),
            TargetAuthorization.status == "VERIFIED",
            TargetAuthorization.verified_at.is_not(None),
            TargetAuthorization.expires_at > now,
        )
        .order_by(TargetAuthorization.expires_at.desc(), TargetAuthorization.id)
        .limit(1)
    )
    return auth_id is not None


def list_asset_telemetry_sources(db: Session, asset_id: str) -> list[TelemetrySource]:
    return list(
        db.scalars(
            select(TelemetrySource)
            .where(TelemetrySource.asset_id == asset_id)
            .order_by(TelemetrySource.created_at.desc(), TelemetrySource.id)
        )
    )


def list_source_connection_timestamps(
    db: Session, source_ids: list[str]
) -> list[tuple[datetime, datetime]]:
    if not source_ids:
        return []
    rows = db.execute(
        select(TelemetryConnection.observed_at, TelemetryConnection.received_at).where(
            TelemetryConnection.source_id.in_(source_ids)
        )
    )
    return [(row[0], row[1]) for row in rows]


def list_source_lifecycle_audit_actions(
    db: Session, organization_id: str, source_ids: list[str]
) -> set[str]:
    if not source_ids:
        return set()
    rows = db.scalars(
        select(AuditLog.action).where(
            AuditLog.organization_id == organization_id,
            AuditLog.resource_type == "telemetry_source",
            AuditLog.resource_id.in_(source_ids),
            AuditLog.action.in_(SOURCE_LIFECYCLE_AUDIT_ACTIONS),
        )
    )
    return set(rows)


def list_asset_traffic_runs(db: Session, asset_id: str) -> list[TrafficAnalysisRun]:
    return list(
        db.scalars(
            select(TrafficAnalysisRun).where(TrafficAnalysisRun.asset_id == asset_id)
        )
    )


def list_asset_availability_exercises(
    db: Session, asset_id: str
) -> list[AvailabilityExercise]:
    return list(
        db.scalars(
            select(AvailabilityExercise).where(AvailabilityExercise.asset_id == asset_id)
        )
    )


def count_asset_ssh_audits(db: Session, asset_id: str) -> int:
    total = db.scalar(select(func.count(SshAudit.id)).where(SshAudit.asset_id == asset_id))
    return int(total or 0)


def list_asset_triage_statuses(
    db: Session, organization_id: str, asset_id: str
) -> list[str]:
    return list(
        db.scalars(
            select(AiTriageSuggestion.review_status).where(
                AiTriageSuggestion.organization_id == organization_id,
                AiTriageSuggestion.asset_id == asset_id,
            )
        )
    )


def count_asset_current_findings(
    db: Session, organization_id: str, asset_id: str
) -> tuple[int, int]:
    current_ids = current_finding_ids_stmt(organization_id)
    statuses = list(
        db.scalars(
            select(FindingRecord.treatment_status).where(
                FindingRecord.asset_id == asset_id,
                FindingRecord.id.in_(current_ids),
            )
        )
    )
    false_positives = sum(1 for st in statuses if st == "FALSE_POSITIVE")
    return len(statuses), false_positives
