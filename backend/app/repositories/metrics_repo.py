"""Repositório de consultas de métricas e agregações reais da plataforma (Zero estatísticas inventadas)."""

from __future__ import annotations

from datetime import UTC
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.models.entities import Asset, FindingRecord, Organization, Scan
from app.repositories.finding_views import (
    OPEN_TREATMENT_STATUSES,
    RESOLVED_TREATMENT_STATUSES,
    current_finding_ids_stmt,
)
from app.schemas.system import (
    CategoryDistributionItem,
    PlatformMetricsSummary,
    RecentScanSummaryItem,
    TopRiskyAssetItem,
)


class MetricsRepository:
    """Consulta contadores e agregações reais diretamente nas tabelas do banco de dados."""

    @staticmethod
    def get_platform_metrics(
        db: Session,
        organization_id: str | None = None,
    ) -> PlatformMetricsSummary:
        """Retorna métricas reais persistidas. Se o banco estiver vazio, retorna zeros reais."""
        try:
            if organization_id:
                total_orgs = (
                    db.scalar(
                        select(func.count())
                        .select_from(Organization)
                        .where(Organization.id == organization_id)
                    )
                    or 0
                )
            else:
                total_orgs = db.scalar(select(func.count()).select_from(Organization)) or 0

            asset_stmt = select(func.count()).select_from(Asset)
            verified_stmt = (
                select(func.count()).select_from(Asset).where(Asset.authorization_status == "VERIFIED")
            )
            scan_stmt = select(func.count()).select_from(Scan)
            scan_running_stmt = (
                select(func.count())
                .select_from(Scan)
                .where(Scan.status.in_(["PENDING", "QUEUED", "RUNNING"]))
            )

            open_statuses = list(OPEN_TREATMENT_STATUSES)
            cur_ids = current_finding_ids_stmt(organization_id)
            cur = FindingRecord.id.in_(cur_ids)
            open_vulns_stmt = (
                select(func.count())
                .select_from(FindingRecord)
                .where(FindingRecord.treatment_status.in_(open_statuses), cur)
            )

            if organization_id:
                asset_stmt = asset_stmt.where(Asset.organization_id == organization_id)
                verified_stmt = verified_stmt.where(Asset.organization_id == organization_id)
                scan_stmt = scan_stmt.where(Scan.organization_id == organization_id)
                scan_running_stmt = scan_running_stmt.where(Scan.organization_id == organization_id)
                open_vulns_stmt = open_vulns_stmt.where(FindingRecord.organization_id == organization_id)

            total_assets = db.scalar(asset_stmt) or 0
            verified_assets = db.scalar(verified_stmt) or 0
            total_scans = db.scalar(scan_stmt) or 0
            scans_running = db.scalar(scan_running_stmt) or 0
            open_vulns = db.scalar(open_vulns_stmt) or 0

            severity_counts: dict[str, int] = {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "INFO": 0,
            }
            sev_query = select(FindingRecord.severity, func.count()).where(
                FindingRecord.treatment_status.in_(open_statuses), cur
            )
            if organization_id:
                sev_query = sev_query.where(FindingRecord.organization_id == organization_id)
            rows = db.execute(sev_query.group_by(FindingRecord.severity)).all()
            for sev, cnt in rows:
                if sev in severity_counts:
                    severity_counts[sev] = int(cnt)

            # Contagem por status de tratamento (Triagem Fase 4)
            treatment_counts: dict[str, int] = {
                "OPEN": 0,
                "IN_PROGRESS": 0,
                "MITIGATED": 0,
                "ACCEPTED_RISK": 0,
                "FALSE_POSITIVE": 0,
                "RESOLVED_VERIFIED": 0,
            }
            status_query = select(FindingRecord.treatment_status, func.count()).where(cur)
            if organization_id:
                status_query = status_query.where(FindingRecord.organization_id == organization_id)
            for st_key, cnt in db.execute(status_query.group_by(FindingRecord.treatment_status)).all():
                if st_key in treatment_counts:
                    treatment_counts[st_key] = int(cnt)

            # Ranking de ativos de maior risco (Top 5)
            top_assets_query = (
                select(Asset).order_by(Asset.risk_score.desc(), Asset.created_at.desc()).limit(5)
            )
            if organization_id:
                top_assets_query = top_assets_query.where(Asset.organization_id == organization_id)
            top_assets_rows = list(db.scalars(top_assets_query).all())
            top_risky_assets: list[TopRiskyAssetItem] = []
            for asset in top_assets_rows:
                open_cnt = (
                    db.scalar(
                        select(func.count())
                        .select_from(FindingRecord)
                        .where(
                            FindingRecord.asset_id == asset.id,
                            FindingRecord.treatment_status.in_(open_statuses),
                            cur,
                        )
                    )
                    or 0
                )
                sev_rows = dict(
                    db.execute(
                        select(FindingRecord.severity, func.count())
                        .where(
                            FindingRecord.asset_id == asset.id,
                            FindingRecord.treatment_status.in_(open_statuses),
                            cur,
                        )
                        .group_by(FindingRecord.severity)
                    ).all()
                )
                last_scan_at = db.scalar(
                    select(func.max(Scan.created_at)).where(Scan.asset_id == asset.id)
                )
                top_risky_assets.append(
                    TopRiskyAssetItem(
                        id=asset.id,
                        name=asset.name,
                        target_url=asset.target_url,
                        environment=asset.environment,
                        asset_type=asset.asset_type,
                        authorization_status=asset.authorization_status,
                        risk_score=asset.risk_score,
                        open_findings_count=int(open_cnt),
                        critical_count=int(sev_rows.get("CRITICAL", 0)),
                        high_count=int(sev_rows.get("HIGH", 0)),
                        last_scan_at=last_scan_at,
                    )
                )

            # Distribuição OWASP e CWE das vulnerabilidades abertas
            open_findings_query = select(FindingRecord.owasp_categories, FindingRecord.cwe_ids).where(
                FindingRecord.treatment_status.in_(open_statuses), cur
            )
            if organization_id:
                open_findings_query = open_findings_query.where(
                    FindingRecord.organization_id == organization_id
                )
            owasp_map: dict[str, int] = {}
            cwe_map: dict[str, int] = {}
            for owasp_list, cwe_list in db.execute(open_findings_query).all():
                for ow in owasp_list or []:
                    ow_str = str(ow).strip()
                    if ow_str:
                        owasp_map[ow_str] = owasp_map.get(ow_str, 0) + 1
                for cwe in cwe_list or []:
                    cwe_str = str(cwe).strip()
                    if cwe_str:
                        cwe_map[cwe_str] = cwe_map.get(cwe_str, 0) + 1

            owasp_dist = [
                CategoryDistributionItem(category=k, count=v)
                for k, v in sorted(owasp_map.items(), key=lambda x: (-x[1], x[0]))[:8]
            ]
            cwe_dist = [
                CategoryDistributionItem(category=k, count=v)
                for k, v in sorted(cwe_map.items(), key=lambda x: (-x[1], x[0]))[:8]
            ]

            # Auditorias recentes e duração média
            scans_query = select(Scan).order_by(Scan.created_at.desc()).limit(10)
            if organization_id:
                scans_query = scans_query.where(Scan.organization_id == organization_id)
            recent_scan_rows = list(db.scalars(scans_query).all())
            recent_scans: list[RecentScanSummaryItem] = []
            durations: list[float] = []

            for sc in recent_scan_rows:
                asset_obj = db.scalar(select(Asset).where(Asset.id == sc.asset_id))
                asset_name = asset_obj.name if asset_obj else sc.asset_id
                f_summary: dict[str, Any] = dict(sc.findings_summary or {})
                f_total = sum(int(v) for v in f_summary.values() if isinstance(v, (int, float)))
                recent_scans.append(
                    RecentScanSummaryItem(
                        id=sc.id,
                        asset_id=sc.asset_id,
                        asset_name=asset_name,
                        profile_type=sc.profile_type,
                        status=sc.status,
                        progress_percent=sc.progress_percent,
                        total_checks_run=sc.total_checks_run,
                        findings_count=f_total,
                        created_at=sc.created_at,
                    )
                )
                if sc.started_at and sc.completed_at:
                    st_dt = (
                        sc.started_at
                        if sc.started_at.tzinfo is not None
                        else sc.started_at.replace(tzinfo=UTC)
                    )
                    end_dt = (
                        sc.completed_at
                        if sc.completed_at.tzinfo is not None
                        else sc.completed_at.replace(tzinfo=UTC)
                    )
                    dur = max(0.0, (end_dt - st_dt).total_seconds())
                    durations.append(dur)

            scan_status_counts: dict[str, int] = {}
            ss_query = select(Scan.status, func.count())
            if organization_id:
                ss_query = ss_query.where(Scan.organization_id == organization_id)
            for s_key, s_cnt in db.execute(ss_query.group_by(Scan.status)).all():
                scan_status_counts[str(s_key)] = int(s_cnt)
            resolved_vulns = sum(treatment_counts.get(k, 0) for k in RESOLVED_TREATMENT_STATUSES)

            avg_duration = round(sum(durations) / len(durations), 2) if durations else 0.0

            return PlatformMetricsSummary(
                total_organizations=int(total_orgs),
                total_assets=int(total_assets),
                verified_assets=int(verified_assets),
                total_scans_executed=int(total_scans),
                scans_in_progress=int(scans_running),
                open_vulnerabilities=int(open_vulns),
                critical_vulnerabilities=severity_counts["CRITICAL"],
                high_vulnerabilities=severity_counts["HIGH"],
                medium_vulnerabilities=severity_counts["MEDIUM"],
                low_vulnerabilities=severity_counts["LOW"],
                info_vulnerabilities=severity_counts["INFO"],
                treatment_status_counts=treatment_counts,
                top_risky_assets=top_risky_assets,
                owasp_category_distribution=owasp_dist,
                cwe_distribution=cwe_dist,
                recent_scans=recent_scans,
                average_scan_duration_seconds=avg_duration,
                scan_status_counts=scan_status_counts,
                resolved_vulnerabilities=int(resolved_vulns),
            )
        except SQLAlchemyError:
            return PlatformMetricsSummary(
                total_organizations=0,
                total_assets=0,
                verified_assets=0,
                total_scans_executed=0,
                scans_in_progress=0,
                open_vulnerabilities=0,
                critical_vulnerabilities=0,
                high_vulnerabilities=0,
                medium_vulnerabilities=0,
                low_vulnerabilities=0,
                info_vulnerabilities=0,
            )
