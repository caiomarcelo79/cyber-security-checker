"""Visões consolidadas de vulnerabilidades: a detecção mais recente por (ativo, fingerprint).

Cada auditoria persiste seus próprios `FindingRecord`; para que a mesma vulnerabilidade
não seja contada várias vezes entre auditorias, indicadores e listagens usam apenas o
registro mais recente de cada (ativo, fingerprint).
"""

from __future__ import annotations

from sqlalchemy import Select, and_, func, select

from app.models.entities import FindingRecord

OPEN_TREATMENT_STATUSES = ("OPEN", "IN_PROGRESS")
RESOLVED_TREATMENT_STATUSES = ("MITIGATED", "RESOLVED_VERIFIED")


def current_finding_ids_stmt(organization_id: str | None = None) -> Select[tuple[str]]:
    """IDs dos registros mais recentes por (ativo, fingerprint), opcionalmente de uma organização."""
    latest = select(
        FindingRecord.asset_id.label("asset_id"),
        FindingRecord.fingerprint.label("fingerprint"),
        func.max(FindingRecord.last_confirmed_at).label("max_confirmed"),
    ).group_by(FindingRecord.asset_id, FindingRecord.fingerprint)
    if organization_id:
        latest = latest.where(FindingRecord.organization_id == organization_id)
    sub = latest.subquery()
    return select(FindingRecord.id).join(
        sub,
        and_(
            FindingRecord.asset_id == sub.c.asset_id,
            FindingRecord.fingerprint == sub.c.fingerprint,
            FindingRecord.last_confirmed_at == sub.c.max_confirmed,
        ),
    )
