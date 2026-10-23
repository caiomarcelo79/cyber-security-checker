"""Serviço de Revalidação Automatizada de Vulnerabilidades Remediadas (Fase 6)."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.entities import (
    Asset,
    FindingRecord,
    Scan,
    ScanCheckResultRecord,
    utcnow,
)
from app.schemas.reports import RevalidationRequest, RevalidationResponse
from app.services.audit_service import AuditLogService
from app.services.scan_orchestrator import ScanOrchestrator

logger = logging.getLogger(__name__)


class RevalidationService:
    """Orquestra revalidações técnicas pontuais e seguras contra alvos autorizados."""

    @classmethod
    def revalidate_finding(
        cls,
        db: Session,
        organization_id: str,
        user_id: str,
        finding_id: str,
        payload: RevalidationRequest,
        ip_address: str | None = None,
    ) -> RevalidationResponse:
        """Executa scanner direcionado para revalidar se a vulnerabilidade foi tecnicamente corrigida."""
        finding = ScanOrchestrator.get_finding_or_404(db, organization_id, finding_id)
        asset = db.scalar(select(Asset).where(Asset.id == finding.asset_id))
        if not asset:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Ativo associado à vulnerabilidade não encontrado.",
            )

        # 1. Gate inviolável de autorização
        ScanOrchestrator._verify_asset_authorization_gate(
            db=db,
            asset=asset,
            user_id=user_id,
            ip_address=ip_address,
        )

        previous_status = finding.treatment_status

        # 2. Registra nota técnica de tentativa de revalidação
        rem_data = dict(finding.remediation_data or {})
        if payload.triage_note:
            rem_data["revalidation_note"] = payload.triage_note.strip()
        rem_data["revalidation_requested_at"] = utcnow().isoformat()
        rem_data["revalidation_requested_by"] = user_id
        finding.remediation_data = rem_data

        # 3. Cria auditoria direcionada exclusiva para o módulo da vulnerabilidade
        target_module = finding.module_id
        scan = Scan(
            organization_id=organization_id,
            asset_id=asset.id,
            initiated_by_user_id=user_id,
            profile_type="CUSTOM",
            status="PENDING",
            progress_percent=0,
            enabled_modules=[target_module],
            policy_snapshot={
                "revalidation_for_finding_id": finding.id,
                "revalidation_check_id": finding.check_id,
                "environment": asset.environment,
                "asset_type": asset.asset_type,
            },
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        # 4. Executa a auditoria direcionada imediatamente
        ScanOrchestrator.execute_scan_by_id(db=db, scan_id=scan.id)
        db.refresh(scan)

        # 5. Avalia resultado da revalidação
        # Verifica se o fingerprint ainda apareceu na nova auditoria
        re_detected = db.scalar(
            select(FindingRecord).where(
                FindingRecord.scan_id == scan.id,
                FindingRecord.fingerprint == finding.fingerprint,
            )
        )

        # Obtém o resultado do check específico
        chk_record = db.scalar(
            select(ScanCheckResultRecord).where(
                ScanCheckResultRecord.scan_id == scan.id,
                ScanCheckResultRecord.check_id == finding.check_id,
            )
        )

        check_resp = ScanOrchestrator._to_check_response(chk_record) if chk_record is not None else None
        now_dt = utcnow()

        if re_detected is not None:
            # Vulnerabilidade ainda persiste
            new_status = "REOPENED" if previous_status in {"RESOLVED_VERIFIED", "MITIGATED"} else "OPEN"
            finding.treatment_status = new_status
            finding.last_confirmed_at = now_dt
            finding.resolved_at = None
            finding.revalidation_scan_id = scan.id
            result_code = "REOPENED" if new_status == "REOPENED" else "INCONCLUSIVE_OR_STILL_OPEN"
            msg = (
                f"Vulnerabilidade revalidada: a falha continua presente no alvo ({finding.check_id}). "
                f"Status atualizado para '{new_status}'."
            )
        elif chk_record is not None and chk_record.status == "PASSED":
            # Resolução comprovada com check aprovado!
            new_status = "RESOLVED_VERIFIED"
            finding.treatment_status = new_status
            finding.resolved_at = now_dt
            finding.revalidation_scan_id = scan.id
            result_code = "RESOLVED_VERIFIED"
            msg = (
                f"Vulnerabilidade revalidada com sucesso: o teste '{finding.check_id}' foi executado "
                f"e aprovado (PASSED). Correção validada e confirmada."
            )
        else:
            # Check inconclusivo ou erro de execução — NÃO marcar como resolvida
            new_status = previous_status
            finding.revalidation_scan_id = scan.id
            result_code = "INCONCLUSIVE_OR_STILL_OPEN"
            err_detail = (
                chk_record.summary if chk_record else "Verificação não produziu resultado definitivo"
            )
            msg = (
                f"A revalidação técnica foi inconclusiva ou apresentou erro operacional ({err_detail}). "
                f"A vulnerabilidade permanece com o status anterior '{previous_status}'."
            )

        db.flush()
        ScanOrchestrator.recalculate_asset_risk_score(db, asset)

        audit_meta: dict[str, Any] = {
            "finding_id": finding.id,
            "check_id": finding.check_id,
            "revalidation_scan_id": scan.id,
            "previous_status": previous_status,
            "new_status": new_status,
            "result_code": result_code,
        }
        AuditLogService.record(
            db=db,
            action="FINDING_REVALIDATED",
            resource_type="finding",
            resource_id=finding.id,
            organization_id=organization_id,
            user_id=user_id,
            ip_address=ip_address,
            metadata=audit_meta,
        )
        db.commit()

        return RevalidationResponse(
            finding_id=finding.id,
            scan_id=scan.id,
            status=result_code,
            message=msg,
            check_result=check_resp,
            previous_status=previous_status,
            new_status=new_status,
            verified_at=now_dt,
        )
