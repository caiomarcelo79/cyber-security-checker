"""Serviço de Correlação e Comparação Técnica entre Auditorias (Fase 6)."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.entities import Asset, FindingRecord, ScanCheckResultRecord
from app.schemas.reports import (
    CoverageDiff,
    FindingSeverityChange,
    ScanComparisonResponse,
)
from app.services.scan_orchestrator import ScanOrchestrator

logger = logging.getLogger(__name__)


class ScanComparisonService:
    """Motor de correlação e análise diferencial entre execuções de auditorias."""

    @classmethod
    def compare_scans(
        cls,
        db: Session,
        organization_id: str,
        scan_id_a: str,
        scan_id_b: str,
    ) -> ScanComparisonResponse:
        """Compara duas auditorias da mesma organização e ativo, identificando novas, persistentes e correções reais."""
        scan_a = ScanOrchestrator.get_scan_or_404(db, organization_id, scan_id_a)
        scan_b = ScanOrchestrator.get_scan_or_404(db, organization_id, scan_id_b)

        if scan_a.asset_id != scan_b.asset_id:
            asset_a = db.scalar(select(Asset).where(Asset.id == scan_a.asset_id))
            asset_b = db.scalar(select(Asset).where(Asset.id == scan_b.asset_id))
            if not (asset_a and asset_b and asset_a.target_url == asset_b.target_url):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        f"Não é possível comparar auditorias de ativos diferentes "
                        f"('{scan_a.asset_id}' vs '{scan_b.asset_id}')."
                    ),
                )

        asset = db.scalar(select(Asset).where(Asset.id == scan_a.asset_id))
        asset_name = asset.name if asset else None

        # Carrega todas as descobertas e checks de cada auditoria
        findings_a = list(
            db.scalars(
                select(FindingRecord)
                .where(FindingRecord.scan_id == scan_a.id)
                .order_by(FindingRecord.severity.desc())
            ).all()
        )
        findings_b = list(
            db.scalars(
                select(FindingRecord)
                .where(FindingRecord.scan_id == scan_b.id)
                .order_by(FindingRecord.severity.desc())
            ).all()
        )

        checks_a = list(
            db.scalars(
                select(ScanCheckResultRecord).where(ScanCheckResultRecord.scan_id == scan_a.id)
            ).all()
        )
        checks_b = list(
            db.scalars(
                select(ScanCheckResultRecord).where(ScanCheckResultRecord.scan_id == scan_b.id)
            ).all()
        )

        checks_b_by_id = {c.check_id: c for c in checks_b}
        modules_b_set = set(scan_b.enabled_modules or [])

        findings_a_by_fp = {f.fingerprint: f for f in findings_a}
        findings_b_by_fp = {f.fingerprint: f for f in findings_b}

        # 1. Novas vulnerabilidades em B
        raw_new = [f for fp, f in findings_b_by_fp.items() if fp not in findings_a_by_fp]
        new_findings: list[FindingRecord] = []
        reopened_findings: list[FindingRecord] = []

        # Verifica se alguma vulnerabilidade "nova" em relação a A é na verdade reincidente de histórico anterior
        for fnd in raw_new:
            prior_resolved = db.scalar(
                select(FindingRecord).where(
                    FindingRecord.asset_id == fnd.asset_id,
                    FindingRecord.organization_id == organization_id,
                    FindingRecord.fingerprint == fnd.fingerprint,
                    FindingRecord.scan_id != scan_b.id,
                    FindingRecord.treatment_status.in_(["RESOLVED_VERIFIED", "MITIGATED"]),
                )
            )
            if prior_resolved is not None:
                reopened_findings.append(fnd)
            else:
                new_findings.append(fnd)

        # 2. Vulnerabilidades persistentes em ambos
        persistent_findings = [f for fp, f in findings_b_by_fp.items() if fp in findings_a_by_fp]

        # 3. Alterações de severidade ou confiança
        severity_changes: list[FindingSeverityChange] = []
        for f_b in persistent_findings:
            f_a = findings_a_by_fp[f_b.fingerprint]
            if f_b.severity != f_a.severity or f_b.confidence != f_a.confidence:
                severity_changes.append(
                    FindingSeverityChange(
                        fingerprint=f_b.fingerprint,
                        title=f_b.title,
                        previous_severity=f_a.severity,
                        current_severity=f_b.severity,
                        previous_confidence=f_a.confidence,
                        current_confidence=f_b.confidence,
                    )
                )

        # 4. Descobertas de A que não reapareceram em B (análise estrita de cobertura)
        not_in_b = [f for fp, f in findings_a_by_fp.items() if fp not in findings_b_by_fp]
        confirmed_remediated: list[FindingRecord] = []
        not_verified_coverage: list[FindingRecord] = []
        not_detected_again: list[FindingRecord] = []

        for f_a in not_in_b:
            if f_a.module_id not in modules_b_set:
                # O módulo inteiro não fez parte do escopo de Scan B!
                not_verified_coverage.append(f_a)
            elif f_a.check_id in checks_b_by_id:
                chk_b = checks_b_by_id[f_a.check_id]
                if chk_b.status == "PASSED":
                    # O scanner rodou em B e comprovou resolução técnica
                    confirmed_remediated.append(f_a)
                elif chk_b.status in {"EXECUTION_ERROR", "INCONCLUSIVE"}:
                    # Ocorreu erro técnico ou inconclusão — NÃO considerar remediada
                    not_verified_coverage.append(f_a)
                else:
                    not_detected_again.append(f_a)
            else:
                # Módulo rodou sem erro mas check específico não foi acionado
                not_detected_again.append(f_a)

        # 5. Diferencial de Cobertura
        mods_a = list(scan_a.enabled_modules or [])
        mods_b = list(scan_b.enabled_modules or [])
        common_mods = [m for m in mods_a if m in mods_b]
        added_mods = [m for m in mods_b if m not in mods_a]
        removed_mods = [m for m in mods_a if m not in mods_b]

        dur_a = int((scan_a.policy_snapshot or {}).get("total_duration_ms", 0))
        dur_b = int((scan_b.policy_snapshot or {}).get("total_duration_ms", 0))

        coverage_diff = CoverageDiff(
            modules_a=mods_a,
            modules_b=mods_b,
            common_modules=common_mods,
            modules_added_in_b=added_mods,
            modules_removed_in_b=removed_mods,
            checks_count_a=len(checks_a),
            checks_count_b=len(checks_b),
            duration_ms_a=dur_a,
            duration_ms_b=dur_b,
            profile_a=scan_a.profile_type,
            profile_b=scan_b.profile_type,
        )

        comparison_summary: dict[str, Any] = {
            "findings_count_a": len(findings_a),
            "findings_count_b": len(findings_b),
            "delta_total": len(findings_b) - len(findings_a),
            "new_count": len(new_findings),
            "persistent_count": len(persistent_findings),
            "confirmed_remediated_count": len(confirmed_remediated),
            "not_detected_again_count": len(not_detected_again),
            "not_verified_coverage_count": len(not_verified_coverage),
            "reopened_count": len(reopened_findings),
            "severity_changes_count": len(severity_changes),
            "coverage_parity_percent": int((len(common_mods) / max(1, len(set(mods_a + mods_b)))) * 100),
        }

        return ScanComparisonResponse(
            scan_a=ScanOrchestrator._to_scan_response(scan_a, asset),
            scan_b=ScanOrchestrator._to_scan_response(scan_b, asset),
            asset_id=scan_a.asset_id,
            asset_name=asset_name,
            total_findings_a=len(findings_a),
            total_findings_b=len(findings_b),
            new_findings=[ScanOrchestrator._to_finding_response(f, asset) for f in new_findings],
            persistent_findings=[
                ScanOrchestrator._to_finding_response(f, asset) for f in persistent_findings
            ],
            confirmed_remediated=[
                ScanOrchestrator._to_finding_response(f, asset) for f in confirmed_remediated
            ],
            not_detected_again=[
                ScanOrchestrator._to_finding_response(f, asset) for f in not_detected_again
            ],
            not_verified_coverage=[
                ScanOrchestrator._to_finding_response(f, asset) for f in not_verified_coverage
            ],
            reopened_findings=[
                ScanOrchestrator._to_finding_response(f, asset) for f in reopened_findings
            ],
            severity_changes=severity_changes,
            coverage_diff=coverage_diff,
            comparison_summary=comparison_summary,
        )
