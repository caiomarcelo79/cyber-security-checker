"""Consultas de persistência para sugestões de triagem assistida."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.entities import (
    AiTriageSuggestion,
    Asset,
    FindingRecord,
    SuspiciousTrafficAlert,
    TrafficAnalysisRun,
)


def find_scoped_traffic_alert(
    db: Session,
    organization_id: str,
    asset_id: str,
    run_id: str,
    alert_id: str,
) -> tuple[SuspiciousTrafficAlert, TrafficAnalysisRun] | None:
    statement = (
        select(SuspiciousTrafficAlert, TrafficAnalysisRun)
        .join(TrafficAnalysisRun, TrafficAnalysisRun.id == SuspiciousTrafficAlert.run_id)
        .join(Asset, Asset.id == TrafficAnalysisRun.asset_id)
        .where(
            Asset.organization_id == organization_id,
            TrafficAnalysisRun.asset_id == asset_id,
            TrafficAnalysisRun.id == run_id,
            SuspiciousTrafficAlert.id == alert_id,
        )
    )
    row = db.execute(statement).one_or_none()
    return (row[0], row[1]) if row is not None else None


def find_scoped_finding(
    db: Session,
    organization_id: str,
    finding_id: str,
) -> FindingRecord | None:
    return db.scalar(
        select(FindingRecord).where(
            FindingRecord.organization_id == organization_id,
            FindingRecord.id == finding_id,
        )
    )


def get_latest_suggestion_for_alert(
    db: Session,
    organization_id: str,
    alert_id: str,
) -> AiTriageSuggestion | None:
    return db.scalar(
        select(AiTriageSuggestion)
        .where(
            AiTriageSuggestion.organization_id == organization_id,
            AiTriageSuggestion.traffic_alert_id == alert_id,
        )
        .order_by(AiTriageSuggestion.created_at.desc(), AiTriageSuggestion.id.desc())
        .limit(1)
    )


def get_latest_suggestion_for_finding(
    db: Session,
    organization_id: str,
    finding_id: str,
) -> AiTriageSuggestion | None:
    return db.scalar(
        select(AiTriageSuggestion)
        .where(
            AiTriageSuggestion.organization_id == organization_id,
            AiTriageSuggestion.finding_id == finding_id,
        )
        .order_by(AiTriageSuggestion.created_at.desc(), AiTriageSuggestion.id.desc())
        .limit(1)
    )


def find_scoped_suggestion(
    db: Session,
    organization_id: str,
    suggestion_id: str,
) -> AiTriageSuggestion | None:
    return db.scalar(
        select(AiTriageSuggestion).where(
            AiTriageSuggestion.organization_id == organization_id,
            AiTriageSuggestion.id == suggestion_id,
        )
    )
