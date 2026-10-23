"""Mecanismo Profissional de Geração e Exportação de Relatórios de Segurança (Fase 6).

Formatos: PDF (ReportLab), HTML sanitizado, JSON estruturado e CSV com proteção anti-Formula Injection.
Tipos: EXECUTIVE, TECHNICAL, COMPARISON, REMEDIATION_TRACKING, ASSET, SCAN.
"""

from __future__ import annotations

import csv
import html
import json
import logging
import os
import secrets
from datetime import UTC, timedelta
from pathlib import Path
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.entities import (
    Asset,
    FindingRecord,
    Organization,
    ReportRecord,
    Scan,
    ScanCheckResultRecord,
    TargetAuthorization,
    utcnow,
)
from app.schemas.reports import (
    ReportCreateRequest,
    ReportPageResponse,
    ReportResponse,
)
from app.services.audit_service import AuditLogService
from app.services.scan_comparison_service import ScanComparisonService

logger = logging.getLogger(__name__)

# Paleta SOC para relatórios
COLOR_BG_DARK = "#0F172A"
COLOR_TEXT_PRIMARY = "#0F172A"
COLOR_CRITICAL = "#EF4444"
COLOR_HIGH = "#F97316"
COLOR_MEDIUM = "#F59E0B"
COLOR_LOW = "#3B82F6"
COLOR_INFO = "#64748B"
COLOR_PASSED = "#10B981"


def sanitize_csv_cell(value: Any) -> str:
    """Protege contra CSV Formula Injection (DDE) segundo diretrizes OWASP e RFC 4180.

    Se uma célula iniciar com '=', '+', '-', '@', '\\t' ou '\\r', prefixa com apóstrofo (').
    """
    if value is None:
        return ""
    text = str(value)
    if not text:
        return ""
    if text[0] in ("=", "+", "-", "@", "\t", "\r"):
        return f"'{text}"
    trimmed = text.lstrip()
    if trimmed and trimmed[0] in ("=", "+", "-", "@"):
        return f"'{text}"
    return text


class ReportEngine:
    """Motor de geração de relatórios de segurança determinísticos e protegidos."""

    @classmethod
    def _ensure_storage_dir(cls) -> Path:
        settings = get_settings()
        base_dir = Path(settings.reports_dir)
        if not base_dir.is_absolute():
            base_dir = Path(__file__).resolve().parent.parent.parent / base_dir
        base_dir.mkdir(parents=True, exist_ok=True)
        return base_dir

    @classmethod
    def create_report(
        cls,
        db: Session,
        organization_id: str,
        user_id: str | None,
        payload: ReportCreateRequest,
        ip_address: str | None = None,
    ) -> ReportResponse:
        """Registra e processa a geração de um novo relatório de segurança."""
        report_type = payload.report_type.upper().strip()
        export_format = payload.format.upper().strip()

        valid_types = {
            "EXECUTIVE",
            "TECHNICAL",
            "COMPARISON",
            "REMEDIATION_TRACKING",
            "ASSET",
            "SCAN",
            "FINDING",
        }
        valid_formats = {"PDF", "HTML", "JSON", "CSV"}

        if report_type not in valid_types:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Tipo de relatório inválido: '{report_type}'. Tipos suportados: {sorted(valid_types)}",
            )
        if export_format not in valid_formats:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Formato inválido: '{export_format}'. Formatos suportados: {sorted(valid_formats)}",
            )

        # Validação de escopo e pertencimento
        asset: Asset | None = None
        if payload.asset_id:
            asset = db.scalar(
                select(Asset).where(
                    Asset.id == payload.asset_id, Asset.organization_id == organization_id
                )
            )
            if not asset:
                raise HTTPException(status_code=404, detail="Ativo não encontrado na organização ativa.")

        scan: Scan | None = None
        if payload.scan_id:
            scan = db.scalar(
                select(Scan).where(Scan.id == payload.scan_id, Scan.organization_id == organization_id)
            )
            if not scan:
                raise HTTPException(
                    status_code=404, detail="Auditoria não encontrada na organização ativa."
                )

        comparison_a: Scan | None = None
        comparison_b: Scan | None = None
        if report_type == "COMPARISON":
            if not (payload.comparison_scan_id_a and payload.comparison_scan_id_b):
                raise HTTPException(
                    status_code=422,
                    detail="Relatório comparativo requer 'comparison_scan_id_a' e 'comparison_scan_id_b'.",
                )
            comparison_a = db.scalar(
                select(Scan).where(
                    Scan.id == payload.comparison_scan_id_a, Scan.organization_id == organization_id
                )
            )
            comparison_b = db.scalar(
                select(Scan).where(
                    Scan.id == payload.comparison_scan_id_b, Scan.organization_id == organization_id
                )
            )
            if not (comparison_a and comparison_b):
                raise HTTPException(
                    status_code=404,
                    detail="Uma ou ambas as auditorias comparadas não foram encontradas na organização.",
                )

        org = db.scalar(select(Organization).where(Organization.id == organization_id))
        org_name = org.name if org else "Organização"
        default_title = f"Relatório {report_type.title()} — {org_name}"
        if asset:
            default_title += f" ({asset.name})"
        elif scan:
            default_title += f" [Scan {scan.id[:8]}]"

        title = payload.title.strip() if payload.title else default_title
        download_token = secrets.token_urlsafe(32)
        settings = get_settings()
        expires_at = utcnow() + timedelta(minutes=settings.reports_download_expire_minutes)

        record = ReportRecord(
            organization_id=organization_id,
            created_by_user_id=user_id,
            report_type=report_type,
            format=export_format,
            status="PENDING",
            title=title,
            asset_id=payload.asset_id,
            scan_id=payload.scan_id,
            finding_id=payload.finding_id,
            comparison_scan_id_a=payload.comparison_scan_id_a,
            comparison_scan_id_b=payload.comparison_scan_id_b,
            filter_params=dict(payload.filter_params or {}),
            summary_data={},
            download_token=download_token,
            expires_at=expires_at,
        )
        db.add(record)
        db.commit()
        db.refresh(record)

        AuditLogService.record(
            db=db,
            action="REPORT_CREATED",
            resource_type="report",
            resource_id=record.id,
            organization_id=organization_id,
            user_id=user_id,
            ip_address=ip_address,
            metadata={"report_type": report_type, "format": export_format, "title": title},
        )

        if payload.execute_synchronously:
            cls._generate_report_content(db=db, report=record)

        return cls._to_response(record, asset)

    @classmethod
    def _generate_report_content(cls, db: Session, report: ReportRecord) -> None:
        """Processa a extração dos dados reais do banco e renderiza o arquivo no formato solicitado."""
        report.status = "GENERATING"
        db.commit()

        storage_dir = cls._ensure_storage_dir()
        file_ext = report.format.lower()
        file_name = f"report_{report.id}_{report.report_type.lower()}.{file_ext}"
        dest_path = storage_dir / file_name

        try:
            # Coleta dados reais consolidados
            context = cls._build_report_context(db=db, report=report)
            report.summary_data = context["summary"]

            # Renderiza no formato alvo
            if report.format == "JSON":
                cls._render_json(context, dest_path)
            elif report.format == "CSV":
                cls._render_csv(context, dest_path)
            elif report.format == "HTML":
                cls._render_html(context, dest_path)
            elif report.format == "PDF":
                cls._render_pdf(context, dest_path)
            else:
                raise ValueError(f"Formato não suportado: {report.format}")

            report.file_path = str(dest_path)
            report.file_size_bytes = dest_path.stat().st_size if dest_path.exists() else 0
            report.status = "COMPLETED"
            report.completed_at = utcnow()
            report.error_message = None

            AuditLogService.record(
                db=db,
                action="REPORT_GENERATED",
                resource_type="report",
                resource_id=report.id,
                organization_id=report.organization_id,
                user_id=report.created_by_user_id,
                metadata={
                    "format": report.format,
                    "file_size_bytes": report.file_size_bytes,
                    "findings_included": context["summary"].get("total_findings", 0),
                },
            )
        except Exception as exc:
            logger.exception("Falha na geração do relatório %s", report.id)
            report.status = "FAILED"
            report.error_message = f"Erro na geração do relatório: {exc}"
        finally:
            db.commit()

    @classmethod
    def _build_report_context(cls, db: Session, report: ReportRecord) -> dict[str, Any]:
        """Extrai todos os dados necessários para o relatório a partir do banco de dados relacional."""
        org = db.scalar(select(Organization).where(Organization.id == report.organization_id))
        org_name = org.name if org else "Organização"

        # Coleta ativos do escopo
        asset_stmt = select(Asset).where(Asset.organization_id == report.organization_id)
        if report.asset_id:
            asset_stmt = asset_stmt.where(Asset.id == report.asset_id)
        assets = list(db.scalars(asset_stmt).all())
        assets_map = {a.id: a for a in assets}

        # Coleta autorização correspondente
        auth_records = list(
            db.scalars(
                select(TargetAuthorization).where(
                    TargetAuthorization.organization_id == report.organization_id
                )
            ).all()
        )
        auth_by_asset = {ar.asset_id: ar for ar in auth_records}

        # Coleta auditorias
        scans: list[Scan] = []
        if report.scan_id:
            sc = db.scalar(
                select(Scan).where(
                    Scan.id == report.scan_id, Scan.organization_id == report.organization_id
                )
            )
            if sc:
                scans.append(sc)
        elif report.asset_id:
            scans = list(
                db.scalars(
                    select(Scan)
                    .where(
                        Scan.asset_id == report.asset_id,
                        Scan.organization_id == report.organization_id,
                    )
                    .order_by(Scan.created_at.desc())
                ).all()
            )
        else:
            scans = list(
                db.scalars(
                    select(Scan)
                    .where(Scan.organization_id == report.organization_id)
                    .order_by(Scan.created_at.desc())
                    .limit(20)
                ).all()
            )

        # Coleta descobertas
        findings_stmt = select(FindingRecord).where(
            FindingRecord.organization_id == report.organization_id
        )
        if report.scan_id:
            findings_stmt = findings_stmt.where(FindingRecord.scan_id == report.scan_id)
        elif report.asset_id:
            findings_stmt = findings_stmt.where(FindingRecord.asset_id == report.asset_id)
        elif report.finding_id:
            findings_stmt = findings_stmt.where(FindingRecord.id == report.finding_id)

        findings = list(db.scalars(findings_stmt.order_by(FindingRecord.last_confirmed_at.desc())).all())

        # Coleta checks se scan_id estiver presente
        checks: list[ScanCheckResultRecord] = []
        if report.scan_id:
            checks = list(
                db.scalars(
                    select(ScanCheckResultRecord).where(ScanCheckResultRecord.scan_id == report.scan_id)
                ).all()
            )

        # Trata caso de comparação
        comparison_data: dict[str, Any] | None = None
        if (
            report.report_type == "COMPARISON"
            and report.comparison_scan_id_a
            and report.comparison_scan_id_b
        ):
            comparison_res = ScanComparisonService.compare_scans(
                db=db,
                organization_id=report.organization_id,
                scan_id_a=report.comparison_scan_id_a,
                scan_id_b=report.comparison_scan_id_b,
            )
            comparison_data = comparison_res.model_dump(mode="json")

        # Métricas consolidadas
        sev_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        status_counts: dict[str, int] = {}
        for f in findings:
            sev = f.severity.upper()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            st = f.treatment_status.upper()
            status_counts[st] = status_counts.get(st, 0) + 1

        top_risks = [f for f in findings if f.severity in {"CRITICAL", "HIGH"}][:10]

        summary = {
            "organization_name": org_name,
            "generated_at": utcnow().isoformat(),
            "report_type": report.report_type,
            "format": report.format,
            "total_assets": len(assets),
            "total_scans": len(scans),
            "total_findings": len(findings),
            "severity_counts": sev_counts,
            "treatment_status_counts": status_counts,
            "total_checks_run": sum(s.total_checks_run for s in scans) or len(checks),
            "average_risk_score": (
                int(sum(a.risk_score for a in assets) / max(1, len(assets))) if assets else 0
            ),
        }

        return {
            "report_id": report.id,
            "title": report.title,
            "report_type": report.report_type,
            "format": report.format,
            "organization_id": report.organization_id,
            "organization_name": org_name,
            "created_at": report.created_at.isoformat(),
            "expires_at": report.expires_at.isoformat() if report.expires_at else None,
            "summary": summary,
            "assets": [
                {
                    "id": a.id,
                    "name": a.name,
                    "target_url": a.target_url,
                    "asset_type": a.asset_type,
                    "environment": a.environment,
                    "risk_score": a.risk_score,
                    "authorization_status": a.authorization_status,
                    "authorization_token": (
                        auth_by_asset[a.id].verification_token if a.id in auth_by_asset else None
                    ),
                }
                for a in assets
            ],
            "scans": [
                {
                    "id": s.id,
                    "asset_id": s.asset_id,
                    "profile_type": s.profile_type,
                    "status": s.status,
                    "started_at": s.started_at.isoformat() if s.started_at else None,
                    "completed_at": s.completed_at.isoformat() if s.completed_at else None,
                    "total_checks": s.total_checks_run,
                    "enabled_modules": s.enabled_modules,
                }
                for s in scans
            ],
            "findings": [
                {
                    "id": f.id,
                    "fingerprint": f.fingerprint,
                    "asset_id": f.asset_id,
                    "asset_name": assets_map[f.asset_id].name if f.asset_id in assets_map else None,
                    "scan_id": f.scan_id,
                    "title": f.title,
                    "description": f.description,
                    "category": f.category,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "treatment_status": f.treatment_status,
                    "priority": getattr(f, "priority", "MEDIUM"),
                    "sla_deadline": f.sla_deadline.isoformat() if f.sla_deadline else None,
                    "affected_endpoint": f.affected_endpoint,
                    "impact": f.impact,
                    "evidence": f.evidence,
                    "reproduction_steps": f.reproduction_steps,
                    "remediation": f.remediation_data,
                    "first_detected_at": f.first_detected_at.isoformat(),
                    "last_confirmed_at": f.last_confirmed_at.isoformat(),
                    "resolved_at": f.resolved_at.isoformat() if f.resolved_at else None,
                }
                for f in findings
            ],
            "checks": [
                {
                    "check_id": c.check_id,
                    "module_id": c.module_id,
                    "title": c.title,
                    "status": c.status,
                    "summary": c.summary,
                    "duration_ms": c.duration_ms,
                }
                for c in checks
            ],
            "top_risks": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity,
                    "endpoint": f.affected_endpoint,
                    "category": f.category,
                }
                for f in top_risks
            ],
            "comparison": comparison_data,
            "methodology": {
                "frameworks": ["OWASP Top 10 (2021)", "OWASP API Top 10 (2023)", "OWASP ASVS 5.0"],
                "engine": "Cyber-Security-Checker Scoped Security Engine",
                "non_destructive_guarantee": True,
            },
        }

    # =========================================================================
    # RENDERIZADORES DE FORMATO
    # =========================================================================

    @classmethod
    def _render_json(cls, context: dict[str, Any], dest: Path) -> None:
        """Gera exportação JSON estruturada completa."""
        with open(dest, "w", encoding="utf-8") as f:
            json.dump(context, f, indent=2, ensure_ascii=False)

    @classmethod
    def _render_csv(cls, context: dict[str, Any], dest: Path) -> None:
        """Gera CSV com sanitização estrita de células para prevenir CSV Formula Injection."""
        findings = context.get("findings", [])
        fieldnames = [
            "ID",
            "Fingerprint",
            "Ativo",
            "Auditoria_ID",
            "Título",
            "Severidade",
            "Confiança",
            "Status_Tratamento",
            "Prioridade",
            "Prazo_SLA",
            "Endpoint_Afetado",
            "Categoria",
            "Primeira_Detecção",
            "Última_Confirmação",
            "Data_Resolução",
            "Impacto",
            "Passos_Reprodução",
            "Diretriz_Remediação",
        ]

        with open(dest, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
            writer.writerow(fieldnames)
            for item in findings:
                rem_data = item.get("remediation") or {}
                rem_title = rem_data.get("title") or rem_data.get("remediation_id") or ""
                repro_str = " | ".join(item.get("reproduction_steps") or [])
                row = [
                    sanitize_csv_cell(item.get("id")),
                    sanitize_csv_cell(item.get("fingerprint")),
                    sanitize_csv_cell(item.get("asset_name")),
                    sanitize_csv_cell(item.get("scan_id")),
                    sanitize_csv_cell(item.get("title")),
                    sanitize_csv_cell(item.get("severity")),
                    sanitize_csv_cell(item.get("confidence")),
                    sanitize_csv_cell(item.get("treatment_status")),
                    sanitize_csv_cell(item.get("priority")),
                    sanitize_csv_cell(item.get("sla_deadline")),
                    sanitize_csv_cell(item.get("affected_endpoint")),
                    sanitize_csv_cell(item.get("category")),
                    sanitize_csv_cell(item.get("first_detected_at")),
                    sanitize_csv_cell(item.get("last_confirmed_at")),
                    sanitize_csv_cell(item.get("resolved_at")),
                    sanitize_csv_cell(item.get("impact")),
                    sanitize_csv_cell(repro_str),
                    sanitize_csv_cell(rem_title),
                ]
                writer.writerow(row)

    @classmethod
    def _render_html(cls, context: dict[str, Any], dest: Path) -> None:
        """Gera relatório HTML responsivo, estilizado no tema SOC e totalmente sanitizado contra XSS."""
        summary = context.get("summary", {})
        findings = context.get("findings", [])
        comparison = context.get("comparison")
        sev_counts = summary.get("severity_counts", {})

        def _esc(val: Any) -> str:
            return html.escape(str(val) if val is not None else "")

        # Cards de severidade
        sev_cards_html = f"""
        <div class="metrics-grid">
            <div class="card card-critical"><span class="card-num">{sev_counts.get("CRITICAL", 0)}</span><span class="card-label">Crítica</span></div>
            <div class="card card-high"><span class="card-num">{sev_counts.get("HIGH", 0)}</span><span class="card-label">Alta</span></div>
            <div class="card card-medium"><span class="card-num">{sev_counts.get("MEDIUM", 0)}</span><span class="card-label">Média</span></div>
            <div class="card card-low"><span class="card-num">{sev_counts.get("LOW", 0)}</span><span class="card-label">Baixa</span></div>
            <div class="card card-info"><span class="card-num">{sev_counts.get("INFO", 0)}</span><span class="card-label">Info</span></div>
        </div>
        """

        # Linhas da tabela de vulnerabilidades
        finding_rows = []
        for fnd in findings:
            sev_class = f"badge-{fnd.get('severity', '').lower()}"
            repro_steps = "".join(f"<li>{_esc(s)}</li>" for s in fnd.get("reproduction_steps") or [])
            rem_info = fnd.get("remediation") or {}
            rem_text = (
                rem_info.get("explanation")
                or rem_info.get("general_guidance")
                or "Aplicar princípio de privilégio mínimo e boas práticas OWASP."
            )

            finding_rows.append(
                f"""
                <div class="finding-card">
                    <div class="finding-header">
                        <span class="badge {sev_class}">{_esc(fnd.get("severity"))}</span>
                        <span class="badge badge-status">{_esc(fnd.get("treatment_status"))}</span>
                        <span class="finding-title">{_esc(fnd.get("title"))}</span>
                    </div>
                    <div class="finding-body">
                        <p><strong>Endpoint Afetado:</strong> <code>{_esc(fnd.get("affected_endpoint"))}</code></p>
                        <p><strong>Categoria:</strong> {_esc(fnd.get("category"))} | <strong>Confiança:</strong> {_esc(fnd.get("confidence"))}</p>
                        <p><strong>Descrição:</strong> {_esc(fnd.get("description"))}</p>
                        <p><strong>Impacto:</strong> {_esc(fnd.get("impact"))}</p>
                        {f'<div class="repro-box"><strong>Passos de Reprodução:</strong><ol>{repro_steps}</ol></div>' if repro_steps else ""}
                        <div class="rem-box"><strong>Recomendação Técnica:</strong><p>{_esc(rem_text)}</p></div>
                    </div>
                </div>
                """
            )

        findings_html = (
            "\n".join(finding_rows)
            if finding_rows
            else "<p class='empty-state'>Nenhuma vulnerabilidade registrada para os filtros selecionados.</p>"
        )

        # Seção comparativa se aplicável
        comparison_html = ""
        if comparison:
            c_sum = comparison.get("comparison_summary", {})
            c_diff = comparison.get("coverage_diff", {})
            comparison_html = f"""
            <div class="section">
                <h2>Análise Comparativa entre Auditorias</h2>
                <div class="metrics-grid">
                    <div class="card"><span class="card-num">{c_sum.get("new_count", 0)}</span><span class="card-label">Novas Falhas</span></div>
                    <div class="card"><span class="card-num">{c_sum.get("persistent_count", 0)}</span><span class="card-label">Persistentes</span></div>
                    <div class="card card-passed"><span class="card-num">{c_sum.get("confirmed_remediated_count", 0)}</span><span class="card-label">Correções Validadas</span></div>
                    <div class="card"><span class="card-num">{c_sum.get("not_verified_coverage_count", 0)}</span><span class="card-label">Diferença Cobertura</span></div>
                </div>
                <p><strong>Paridade de Cobertura de Módulos:</strong> {c_sum.get("coverage_parity_percent", 100)}%</p>
                <p><strong>Módulos em Scan A:</strong> {", ".join(c_diff.get("modules_a", []))}</p>
                <p><strong>Módulos em Scan B:</strong> {", ".join(c_diff.get("modules_b", []))}</p>
            </div>
            """

        html_content = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{_esc(context.get("title"))}</title>
    <style>
        :root {{
            --bg: #0F172A;
            --surface: #1E293B;
            --border: #334155;
            --text: #F8FAFC;
            --text-muted: #94A3B8;
            --critical: #EF4444;
            --high: #F97316;
            --medium: #F59E0B;
            --low: #3B82F6;
            --info: #64748B;
            --passed: #10B981;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 32px 16px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1040px;
            margin: 0 auto;
        }}
        header {{
            border-bottom: 2px solid var(--border);
            padding-bottom: 24px;
            margin-bottom: 32px;
        }}
        h1 {{ margin: 0 0 8px 0; font-size: 26px; }}
        .meta {{ color: var(--text-muted); font-size: 14px; }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
            gap: 16px;
            margin-bottom: 32px;
        }}
        .card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
            text-align: center;
        }}
        .card-num {{ display: block; font-size: 28px; font-weight: bold; }}
        .card-label {{ font-size: 12px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; }}
        .card-critical .card-num {{ color: var(--critical); }}
        .card-high .card-num {{ color: var(--high); }}
        .card-medium .card-num {{ color: var(--medium); }}
        .card-low .card-num {{ color: var(--low); }}
        .card-info .card-num {{ color: var(--info); }}
        .card-passed .card-num {{ color: var(--passed); }}
        .finding-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            margin-bottom: 16px;
            overflow: hidden;
        }}
        .finding-header {{
            padding: 12px 16px;
            background: rgba(255,255,255,0.02);
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .badge {{
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
        }}
        .badge-critical {{ background: var(--critical); color: #fff; }}
        .badge-high {{ background: var(--high); color: #fff; }}
        .badge-medium {{ background: var(--medium); color: #000; }}
        .badge-low {{ background: var(--low); color: #fff; }}
        .badge-info {{ background: var(--info); color: #fff; }}
        .badge-status {{ background: #475569; color: #fff; }}
        .finding-title {{ font-weight: 600; font-size: 16px; }}
        .finding-body {{ padding: 16px; font-size: 14px; }}
        .finding-body code {{ background: #090D16; padding: 2px 6px; border-radius: 4px; font-family: monospace; }}
        .repro-box, .rem-box {{
            background: #0B1120;
            border-left: 3px solid var(--low);
            padding: 12px 16px;
            border-radius: 4px;
            margin-top: 12px;
        }}
        .rem-box {{ border-left-color: var(--passed); }}
        .footer {{
            margin-top: 48px;
            border-top: 1px solid var(--border);
            padding-top: 24px;
            font-size: 12px;
            color: var(--text-muted);
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>{_esc(context.get("title"))}</h1>
            <div class="meta">
                Organização: <strong>{_esc(context.get("organization_name"))}</strong> |
                Tipo: <strong>{_esc(context.get("report_type"))}</strong> |
                Gerado em: <strong>{_esc(context.get("created_at"))}</strong>
            </div>
        </header>

        <h2>Resumo Geral da Postura de Segurança</h2>
        {sev_cards_html}

        {comparison_html}

        <h2>Vulnerabilidades e Indícios Técnicos ({len(findings)})</h2>
        {findings_html}

        <div class="footer">
            Cyber-Security-Checker — Plataforma Defensiva de Gerenciamento de Vulnerabilidades Autorizadas.<br>
            A ausência de achados não assegura invulnerabilidade total. Recomenda-se auditoria contínua e defesa em profundidade.
        </div>
    </div>
</body>
</html>
"""
        with open(dest, "w", encoding="utf-8") as f:
            f.write(html_content)

    @classmethod
    def _render_pdf(cls, context: dict[str, Any], dest: Path) -> None:
        """Gera PDF profissional usando ReportLab (Platypus flowables)."""
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.platypus import (
            HRFlowable,
            KeepTogether,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )

        doc = SimpleDocTemplate(
            str(dest),
            pagesize=letter,
            leftMargin=36,
            rightMargin=36,
            topMargin=36,
            bottomMargin=36,
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "ReportTitle",
            parent=styles["Heading1"],
            fontSize=18,
            leading=22,
            textColor=colors.HexColor("#0F172A"),
            spaceAfter=6,
        )
        meta_style = ParagraphStyle(
            "ReportMeta",
            parent=styles["Normal"],
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#475569"),
            spaceAfter=12,
        )
        heading2_style = ParagraphStyle(
            "ReportH2",
            parent=styles["Heading2"],
            fontSize=13,
            leading=16,
            textColor=colors.HexColor("#1E293B"),
            spaceBefore=12,
            spaceAfter=8,
        )
        body_style = ParagraphStyle(
            "ReportBody",
            parent=styles["Normal"],
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#334155"),
        )
        code_style = ParagraphStyle(
            "ReportCode",
            parent=styles["Normal"],
            fontName="Courier",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#0F172A"),
        )

        story: list[Any] = []

        # Título e cabeçalho
        title_text = html.escape(context.get("title", "Relatório de Segurança"))
        org_name = html.escape(context.get("organization_name", "Organização"))
        rep_type = html.escape(context.get("report_type", "EXECUTIVE"))
        created_at = html.escape(context.get("created_at", ""))

        story.append(Paragraph(title_text, title_style))
        story.append(
            Paragraph(
                f"<b>Organização:</b> {org_name} &nbsp;|&nbsp; <b>Tipo:</b> {rep_type} &nbsp;|&nbsp; <b>Data:</b> {created_at}",
                meta_style,
            )
        )
        story.append(
            HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceAfter=12)
        )

        # Tabela de Indicadores / Severidades
        summary = context.get("summary", {})
        sev_counts = summary.get("severity_counts", {})
        metrics_data = [
            ["Crítica", "Alta", "Média", "Baixa", "Info", "Total Falhas"],
            [
                str(sev_counts.get("CRITICAL", 0)),
                str(sev_counts.get("HIGH", 0)),
                str(sev_counts.get("MEDIUM", 0)),
                str(sev_counts.get("LOW", 0)),
                str(sev_counts.get("INFO", 0)),
                str(summary.get("total_findings", 0)),
            ],
        ]
        t_metrics = Table(metrics_data, colWidths=[80, 80, 80, 80, 80, 90])
        t_metrics.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 9),
                    ("FONTSIZE", (0, 1), (-1, 1), 14),
                    ("TEXTCOLOR", (0, 1), (0, 1), colors.HexColor(COLOR_CRITICAL)),
                    ("TEXTCOLOR", (1, 1), (1, 1), colors.HexColor(COLOR_HIGH)),
                    ("TEXTCOLOR", (2, 1), (2, 1), colors.HexColor(COLOR_MEDIUM)),
                    ("TEXTCOLOR", (3, 1), (3, 1), colors.HexColor(COLOR_LOW)),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ]
            )
        )
        story.append(t_metrics)
        story.append(Spacer(1, 14))

        # Seção Comparativa
        comparison = context.get("comparison")
        if comparison:
            story.append(Paragraph("Análise Comparativa entre Auditorias", heading2_style))
            c_sum = comparison.get("comparison_summary", {})
            comp_table_data = [
                ["Novas Falhas", "Persistentes", "Correções Confirmadas", "Diferenças Cobertura"],
                [
                    str(c_sum.get("new_count", 0)),
                    str(c_sum.get("persistent_count", 0)),
                    str(c_sum.get("confirmed_remediated_count", 0)),
                    str(c_sum.get("not_verified_coverage_count", 0)),
                ],
            ]
            t_comp = Table(comp_table_data, colWidths=[120, 120, 130, 120])
            t_comp.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
                        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 1), (-1, 1), 12),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                        ("TOPPADDING", (0, 0), (-1, -1), 5),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ]
                )
            )
            story.append(t_comp)
            story.append(Spacer(1, 14))

        # Seção de Descobertas
        findings = context.get("findings", [])
        story.append(
            Paragraph(f"Inventário de Vulnerabilidades Identificadas ({len(findings)})", heading2_style)
        )

        if not findings:
            story.append(
                Paragraph(
                    "Nenhuma vulnerabilidade foi identificada para o escopo desta auditoria.",
                    body_style,
                )
            )
        else:
            for fnd in findings[:40]:  # Limite de segurança de volume por PDF
                sev = fnd.get("severity", "INFO")
                title = html.escape(fnd.get("title", ""))
                endpoint = html.escape(fnd.get("affected_endpoint", ""))
                impact = html.escape(fnd.get("impact", ""))
                status_txt = html.escape(fnd.get("treatment_status", "OPEN"))
                rem_data = fnd.get("remediation") or {}
                rem_text = html.escape(
                    rem_data.get("explanation")
                    or rem_data.get("general_guidance")
                    or "Aplicar correção conforme recomendações de segurança."
                )

                sev_color = colors.HexColor(
                    COLOR_CRITICAL
                    if sev == "CRITICAL"
                    else COLOR_HIGH
                    if sev == "HIGH"
                    else COLOR_MEDIUM
                    if sev == "MEDIUM"
                    else COLOR_LOW
                    if sev == "LOW"
                    else COLOR_INFO
                )

                f_content = [
                    Paragraph(
                        f"<b>[{sev}] {title}</b> &nbsp;(Status: {status_txt})",
                        ParagraphStyle(
                            "FTitle", parent=body_style, textColor=sev_color, fontSize=10, leading=13
                        ),
                    ),
                    Paragraph(f"<b>Endpoint:</b> {endpoint}", code_style),
                    Paragraph(f"<b>Impacto:</b> {impact}", body_style),
                    Paragraph(f"<b>Recomendação:</b> {rem_text}", body_style),
                    Spacer(1, 8),
                ]
                story.append(KeepTogether(f_content))

        # Rodapé / Metodologia
        story.append(Spacer(1, 16))
        story.append(
            HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E1"), spaceAfter=8)
        )
        story.append(
            Paragraph(
                "Relatório gerado pelo Cyber-Security-Checker. Metodologia: OWASP Top 10 / WSTG. "
                "Resultados válidos para a janela de teste auditada.",
                ParagraphStyle(
                    "RFooter",
                    parent=body_style,
                    fontSize=7,
                    textColor=colors.HexColor("#64748B"),
                    alignment=1,
                ),
            )
        )

        doc.build(story)

    # =========================================================================
    # CONSULTAS E GESTÃO DE RELATÓRIOS
    # =========================================================================

    @classmethod
    def list_reports(
        cls,
        db: Session,
        organization_id: str,
        *,
        asset_id: str | None = None,
        scan_id: str | None = None,
        report_type: str | None = None,
        export_format: str | None = None,
        status_filter: str | None = None,
        limit: int = 25,
        offset: int = 0,
    ) -> ReportPageResponse:
        """Lista relatórios gerados da organização com filtros e paginação no servidor."""
        stmt = select(ReportRecord).where(ReportRecord.organization_id == organization_id)
        if asset_id:
            stmt = stmt.where(ReportRecord.asset_id == asset_id)
        if scan_id:
            stmt = stmt.where(ReportRecord.scan_id == scan_id)
        if report_type:
            stmt = stmt.where(ReportRecord.report_type == report_type.upper().strip())
        if export_format:
            stmt = stmt.where(ReportRecord.format == export_format.upper().strip())
        if status_filter:
            stmt = stmt.where(ReportRecord.status == status_filter.upper().strip())

        from sqlalchemy import func

        total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
        stmt = stmt.order_by(ReportRecord.created_at.desc()).limit(limit).offset(offset)
        records = list(db.scalars(stmt).all())

        assets_ids = {r.asset_id for r in records if r.asset_id}
        assets_map = {a.id: a for a in db.scalars(select(Asset).where(Asset.id.in_(assets_ids))).all()}

        return ReportPageResponse(
            items=[cls._to_response(r, assets_map.get(r.asset_id)) for r in records],
            total=int(total),
            limit=limit,
            offset=offset,
        )

    @classmethod
    def get_report_or_404(
        cls,
        db: Session,
        organization_id: str,
        report_id: str,
    ) -> ReportRecord:
        report = db.scalar(
            select(ReportRecord).where(
                ReportRecord.id == report_id,
                ReportRecord.organization_id == organization_id,
            )
        )
        if not report:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Relatório não encontrado na organização ativa.",
            )
        return report

    @classmethod
    def get_report_by_token(
        cls,
        db: Session,
        token: str,
    ) -> ReportRecord:
        """Valida e recupera relatório por token seguro de download com verificação de expiração."""
        report = db.scalar(select(ReportRecord).where(ReportRecord.download_token == token))
        if not report:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Token de download inválido ou inexistente.",
            )
        if report.expires_at:
            exp_dt = (
                report.expires_at
                if report.expires_at.tzinfo is not None
                else report.expires_at.replace(tzinfo=UTC)
            )
            if exp_dt < utcnow():
                raise HTTPException(
                    status_code=status.HTTP_410_GONE,
                    detail="O link de download deste relatório expirou. Gere um novo relatório.",
                )
        if report.status != "COMPLETED" or not report.file_path or not os.path.exists(report.file_path):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="O arquivo do relatório não está pronto ou não foi encontrado no servidor.",
            )
        return report

    @classmethod
    def delete_report(
        cls,
        db: Session,
        organization_id: str,
        report_id: str,
    ) -> None:
        report = cls.get_report_or_404(db, organization_id, report_id)
        if report.file_path and os.path.exists(report.file_path):
            try:
                os.remove(report.file_path)
            except OSError as exc:
                logger.warning("Falha ao remover arquivo de relatório no disco: %s", exc)
        db.delete(report)
        db.commit()

    @classmethod
    def _to_response(cls, rec: ReportRecord, asset: Asset | None = None) -> ReportResponse:
        asset_name = asset.name if asset else (rec.asset.name if rec.asset else None)
        dl_url = None
        if rec.status == "COMPLETED":
            dl_url = f"/api/v1/reports/{rec.id}/download"

        return ReportResponse(
            id=rec.id,
            organization_id=rec.organization_id,
            created_by_user_id=rec.created_by_user_id,
            report_type=rec.report_type,
            format=rec.format,
            status=rec.status,
            title=rec.title,
            asset_id=rec.asset_id,
            asset_name=asset_name,
            scan_id=rec.scan_id,
            finding_id=rec.finding_id,
            comparison_scan_id_a=rec.comparison_scan_id_a,
            comparison_scan_id_b=rec.comparison_scan_id_b,
            filter_params=dict(rec.filter_params or {}),
            summary_data=dict(rec.summary_data or {}),
            file_size_bytes=rec.file_size_bytes,
            download_token=rec.download_token,
            download_url=dl_url,
            expires_at=rec.expires_at,
            error_message=rec.error_message,
            created_at=rec.created_at,
            completed_at=rec.completed_at,
        )
