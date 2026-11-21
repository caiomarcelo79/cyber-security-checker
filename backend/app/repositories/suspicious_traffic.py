"""Consultas de persistência para linha de base TLS e análises de tráfego suspeito."""

from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.entities import (
    SuspiciousTrafficAlert,
    TelemetrySource,
    TelemetryTlsBaseline,
    TrafficAnalysisRun,
    TrafficEdrSignal,
    TrafficTlsDecision,
)


def load_tls_baselines(db: Session, source_id: str) -> dict[tuple[str, str, int], TelemetryTlsBaseline]:
    rows = db.scalars(
        select(TelemetryTlsBaseline).where(TelemetryTlsBaseline.source_id == source_id)
    ).all()
    return {
        (row.server_name.lower(), row.responder_ip, row.responder_port): row
        for row in rows
    }


def list_analysis_runs(db: Session, asset_id: str, limit: int = 25) -> list[tuple[TrafficAnalysisRun, str]]:
    statement = (
        select(TrafficAnalysisRun, TelemetrySource.name)
        .join(TelemetrySource, TelemetrySource.id == TrafficAnalysisRun.source_id)
        .where(TrafficAnalysisRun.asset_id == asset_id)
        .order_by(TrafficAnalysisRun.created_at.desc(), TrafficAnalysisRun.id.desc())
        .limit(limit)
    )
    return [(run, source_name) for run, source_name in db.execute(statement)]


def find_analysis_run(db: Session, asset_id: str, run_id: str) -> tuple[TrafficAnalysisRun, str] | None:
    statement = (
        select(TrafficAnalysisRun, TelemetrySource.name)
        .join(TelemetrySource, TelemetrySource.id == TrafficAnalysisRun.source_id)
        .where(TrafficAnalysisRun.asset_id == asset_id, TrafficAnalysisRun.id == run_id)
    )
    row = db.execute(statement).one_or_none()
    return (row[0], row[1]) if row is not None else None


def list_run_alerts(db: Session, run_ids: list[str]) -> dict[str, list[SuspiciousTrafficAlert]]:
    if not run_ids:
        return {}
    rows = db.scalars(
        select(SuspiciousTrafficAlert)
        .where(SuspiciousTrafficAlert.run_id.in_(run_ids))
        .order_by(SuspiciousTrafficAlert.created_at.asc(), SuspiciousTrafficAlert.id.asc())
    ).all()
    grouped: dict[str, list[SuspiciousTrafficAlert]] = defaultdict(list)
    for row in rows:
        grouped[row.run_id].append(row)
    return grouped


def list_run_tls_decisions(db: Session, run_ids: list[str]) -> dict[str, list[TrafficTlsDecision]]:
    if not run_ids:
        return {}
    rows = db.scalars(
        select(TrafficTlsDecision)
        .where(TrafficTlsDecision.run_id.in_(run_ids))
        .order_by(TrafficTlsDecision.observed_at.asc(), TrafficTlsDecision.id.asc())
    ).all()
    grouped: dict[str, list[TrafficTlsDecision]] = defaultdict(list)
    for row in rows:
        grouped[row.run_id].append(row)
    return grouped


def list_run_edr_signals(db: Session, run_ids: list[str]) -> dict[str, list[TrafficEdrSignal]]:
    if not run_ids:
        return {}
    rows = db.scalars(
        select(TrafficEdrSignal)
        .where(TrafficEdrSignal.run_id.in_(run_ids))
        .order_by(TrafficEdrSignal.observed_at.asc(), TrafficEdrSignal.id.asc())
    ).all()
    grouped: dict[str, list[TrafficEdrSignal]] = defaultdict(list)
    for row in rows:
        grouped[row.run_id].append(row)
    return grouped
