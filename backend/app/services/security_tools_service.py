"""Serviço de aplicação para as ferramentas defensivas SOC e auditoria multi-tenant."""

from __future__ import annotations

import platform
import shutil
import subprocess
from collections import Counter
from datetime import UTC, datetime

from fastapi import HTTPException, status
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.api.deps import AuthenticatedPrincipal
from app.models.entities import Asset, FindingRecord, Scan, ScanCheckResultRecord
from app.repositories.finding_views import OPEN_TREATMENT_STATUSES, current_finding_ids_stmt
from app.schemas.security_tools import (
    DdosAnalyzeRequest,
    DdosAnalyzeResponse,
    FirewallAnalyzeRequest,
    FirewallAnalyzeResponse,
    ForensicsAnalyzeRequest,
    ForensicsAnalyzeResponse,
    MalwareAnalyzeRequest,
    MalwareAnalyzeResponse,
    PasswordAnalyzeRequest,
    PasswordAnalyzeResponse,
    PasswordGenerateRequest,
    PasswordGenerateResponse,
    PentestPlanRequest,
    PentestPlanResponse,
    WifiAnalyzeRequest,
    WifiAnalyzeResponse,
    WifiLocalScanResponse,
)
from app.services.audit_service import AuditLogService
from app.services.security_tools_logic import (
    analyze_ddos_defense,
    analyze_firewall_rules,
    analyze_forensics,
    analyze_malware_static,
    analyze_password,
    analyze_wifi_audit,
    build_pentest_plan,
    generate_password,
)


def _load_authorized_asset(
    db: Session,
    principal: AuthenticatedPrincipal | None,
    asset_id: str,
) -> Asset:
    if principal is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Autenticação obrigatória para vincular ferramentas a um ativo da organização.",
        )
    asset = db.scalar(
        select(Asset).where(
            Asset.id == asset_id,
            Asset.organization_id == principal.organization.id,
        )
    )
    if asset is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Ativo não encontrado na organização ativa.",
        )
    return asset


def _record_tool_audit(
    db: Session,
    principal: AuthenticatedPrincipal | None,
    *,
    action: str,
    resource_id: str | None = None,
    metadata: dict[str, object] | None = None,
) -> None:
    if principal is None:
        return
    AuditLogService.record(
        db=db,
        action=action,
        resource_type="security_tool",
        resource_id=resource_id,
        organization_id=principal.organization.id,
        user_id=principal.user.id,
        ip_address=principal.client_ip,
        metadata=metadata or {},
        commit=True,
    )


def create_pentest_plan(
    db: Session,
    principal: AuthenticatedPrincipal | None,
    payload: PentestPlanRequest,
) -> PentestPlanResponse:
    """Gera roteiro guiado WSTG integrado ao histórico real do ativo quando informado."""
    target_name = payload.target_label or "Alvo de planejamento manual"
    asset_type = payload.asset_type
    environment = payload.environment
    authorization_status = "MANUAL_UNVERIFIED"
    passed_checks: set[str] = set()
    finding_checks_count: dict[str, int] = {}

    if payload.asset_id:
        asset = _load_authorized_asset(db, principal, payload.asset_id)
        assert principal is not None
        target_name = f"{asset.name} ({asset.hostname})"
        asset_type = asset.asset_type
        environment = asset.environment
        authorization_status = asset.authorization_status

        latest_scan = db.scalar(
            select(Scan)
            .where(
                Scan.asset_id == asset.id,
                Scan.organization_id == principal.organization.id,
                Scan.status == "COMPLETED",
            )
            .order_by(desc(Scan.completed_at), desc(Scan.created_at))
            .limit(1)
        )
        if latest_scan is not None:
            check_rows = db.scalars(
                select(ScanCheckResultRecord).where(ScanCheckResultRecord.scan_id == latest_scan.id)
            ).all()
            passed_checks = {row.check_id for row in check_rows if row.status == "PASSED"}

        cur_ids = current_finding_ids_stmt(principal.organization.id)
        open_findings = db.scalars(
            select(FindingRecord).where(
                FindingRecord.asset_id == asset.id,
                FindingRecord.organization_id == principal.organization.id,
                FindingRecord.treatment_status.in_(list(OPEN_TREATMENT_STATUSES)),
                FindingRecord.id.in_(cur_ids),
            )
        ).all()
        finding_checks_count = dict(Counter(f.check_id for f in open_findings))

    plan = build_pentest_plan(
        target_name=target_name,
        asset_type=asset_type,
        environment=environment,
        authorization_status=authorization_status,
        passed_checks=passed_checks,
        finding_checks_count=finding_checks_count,
    )
    _record_tool_audit(
        db,
        principal,
        action="SECURITY_TOOL_PENTEST_PLAN",
        resource_id=payload.asset_id,
        metadata={
            "asset_type": asset_type,
            "environment": environment,
            "total_steps": plan.total_steps,
        },
    )
    return plan


def run_password_generate(
    db: Session,
    principal: AuthenticatedPrincipal | None,
    payload: PasswordGenerateRequest,
) -> PasswordGenerateResponse:
    """Gera credencial segura sem registrar o valor gerado em trilha ou log."""
    try:
        result = generate_password(payload)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc

    _record_tool_audit(
        db,
        principal,
        action="SECURITY_TOOL_PASSWORD_GENERATE",
        metadata={"mode": result.mode, "length": result.length, "entropy_bits": result.entropy_bits},
    )
    return result


def run_password_analyze(
    db: Session,
    principal: AuthenticatedPrincipal | None,
    payload: PasswordAnalyzeRequest,
) -> PasswordAnalyzeResponse:
    """Avalia força de senha sem armazenar ou auditar a senha fornecida."""
    result = analyze_password(payload.password)
    _record_tool_audit(
        db,
        principal,
        action="SECURITY_TOOL_PASSWORD_ANALYZE",
        metadata={
            "length": result.length,
            "score": result.score,
            "classification": result.classification,
        },
    )
    return result


def run_forensics_analysis(
    db: Session,
    principal: AuthenticatedPrincipal | None,
    payload: ForensicsAnalyzeRequest,
) -> ForensicsAnalyzeResponse:
    """Executa análise forense estática de texto/logs com defang opcional de IOCs."""
    result = analyze_forensics(payload)
    _record_tool_audit(
        db,
        principal,
        action="SECURITY_TOOL_FORENSICS_ANALYZE",
        metadata={
            "artifact_name": result.artifact_name,
            "sha256": result.hashes.sha256,
            "size_bytes": result.size_bytes,
            "secret_warnings": len(result.secret_leak_warnings),
        },
    )
    return result


def run_firewall_analysis(
    db: Session,
    principal: AuthenticatedPrincipal | None,
    payload: FirewallAnalyzeRequest,
) -> FirewallAnalyzeResponse:
    """Executa auditoria estática de regras de firewall e simulação de pacote."""
    result = analyze_firewall_rules(payload)
    _record_tool_audit(
        db,
        principal,
        action="SECURITY_TOOL_FIREWALL_TEST",
        metadata={
            "rules_parsed": result.total_rules_parsed,
            "posture_score": result.posture_score,
            "findings_count": len(result.findings),
        },
    )
    return result


def run_malware_analysis(
    db: Session,
    principal: AuthenticatedPrincipal | None,
    payload: MalwareAnalyzeRequest,
) -> MalwareAnalyzeResponse:
    """Executa análise estática segura de payload sem qualquer execução."""
    try:
        result = analyze_malware_static(payload)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc

    _record_tool_audit(
        db,
        principal,
        action="SECURITY_TOOL_MALWARE_ANALYZE",
        metadata={
            "filename": result.filename,
            "sha256": result.hashes.sha256,
            "verdict": result.verdict,
            "hits_count": len(result.signature_hits),
        },
    )
    return result


def run_wifi_audit(
    db: Session,
    principal: AuthenticatedPrincipal | None,
    payload: WifiAnalyzeRequest,
) -> WifiAnalyzeResponse:
    """Executa auditoria passiva de redes sem fio a partir de netsh/nmcli ou inventário."""
    if not payload.raw_scan_output and not payload.networks:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Informe a saída de varredura Wi-Fi (netsh/nmcli) ou ao menos uma rede para auditoria.",
        )
    result = analyze_wifi_audit(payload)
    _record_tool_audit(
        db,
        principal,
        action="SECURITY_TOOL_WIFI_AUDIT",
        metadata={
            "total_networks": result.total_networks,
            "overall_score": result.overall_score,
            "evil_twin_suspected": result.evil_twin_suspected,
        },
    )
    return result


def _decode_os_output(raw: bytes) -> str:
    for enc in ("utf-8", "cp850", "cp1252", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def run_wifi_local_scan(
    db: Session,
    principal: AuthenticatedPrincipal | None,
) -> WifiLocalScanResponse:
    """Executa leitura passiva da placa Wi-Fi do host via netsh (Windows) ou nmcli (Linux)."""
    system_name = platform.system()
    captured_at = datetime.now(UTC).isoformat()

    if system_name == "Windows":
        netsh_exe = shutil.which("netsh")
        if netsh_exe:
            try:
                nets_proc = subprocess.run(
                    [netsh_exe, "wlan", "show", "networks", "mode=bssid"],
                    capture_output=True,
                    timeout=8,
                    check=False,
                )
                iface_proc = subprocess.run(
                    [netsh_exe, "wlan", "show", "interfaces"],
                    capture_output=True,
                    timeout=8,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                return WifiLocalScanResponse(
                    available=False,
                    source="HOST_NETSH_ERROR",
                    detail=f"Falha ao consultar placa Wi-Fi via netsh: {exc}",
                )

            raw_nets = _decode_os_output(nets_proc.stdout or b"")
            raw_iface = _decode_os_output(iface_proc.stdout or b"")
            if nets_proc.returncode == 0 and raw_nets.strip():
                audit = analyze_wifi_audit(
                    WifiAnalyzeRequest(
                        raw_scan_output=raw_nets,
                        connected_interface_output=raw_iface or None,
                    )
                )
                _record_tool_audit(
                    db,
                    principal,
                    action="SECURITY_TOOL_WIFI_LOCAL_SCAN",
                    metadata={
                        "source": "HOST_NETSH",
                        "total_networks": audit.total_networks,
                        "overall_score": audit.overall_score,
                    },
                )
                return WifiLocalScanResponse(
                    available=True,
                    source="HOST_NETSH",
                    detail="Varredura real concluída via interface Wi-Fi do Windows (netsh).",
                    captured_at=captured_at,
                    raw_scan_output=raw_nets,
                    connected_interface_output=raw_iface or None,
                    audit=audit,
                )
            err_msg = _decode_os_output(nets_proc.stderr or nets_proc.stdout or b"").strip()
            return WifiLocalScanResponse(
                available=False,
                source="HOST_NETSH_UNAVAILABLE",
                detail=err_msg or "Nenhuma interface Wi-Fi ativa localizada via netsh.",
            )

    if system_name == "Linux":
        nmcli_exe = shutil.which("nmcli")
        if nmcli_exe:
            try:
                proc = subprocess.run(
                    [
                        nmcli_exe,
                        "-t",
                        "-f",
                        "SSID,BSSID,CHAN,SIGNAL,SECURITY",
                        "dev",
                        "wifi",
                        "list",
                    ],
                    capture_output=True,
                    timeout=8,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                return WifiLocalScanResponse(
                    available=False,
                    source="HOST_NMCLI_ERROR",
                    detail=f"Falha ao consultar nmcli: {exc}",
                )

            raw_nmcli = _decode_os_output(proc.stdout or b"")
            if proc.returncode == 0 and raw_nmcli.strip():
                audit = analyze_wifi_audit(WifiAnalyzeRequest(raw_scan_output=raw_nmcli))
                _record_tool_audit(
                    db,
                    principal,
                    action="SECURITY_TOOL_WIFI_LOCAL_SCAN",
                    metadata={
                        "source": "HOST_NMCLI",
                        "total_networks": audit.total_networks,
                        "overall_score": audit.overall_score,
                    },
                )
                return WifiLocalScanResponse(
                    available=True,
                    source="HOST_NMCLI",
                    detail="Varredura real concluída via NetworkManager (nmcli).",
                    captured_at=captured_at,
                    raw_scan_output=raw_nmcli,
                    audit=audit,
                )

    return WifiLocalScanResponse(
        available=False,
        source="CONTAINER_NO_WIFI_RADIO",
        detail=(
            "A API está rodando em container sem acesso direto ao adaptador Wi-Fi do host. "
            "Inicie o sensor local `python scripts/wifi_local_sensor.py` no host para capturar "
            "redes reais via loopback 127.0.0.1:8765."
        ),
    )


def run_ddos_analysis(
    db: Session,
    principal: AuthenticatedPrincipal | None,
    payload: DdosAnalyzeRequest,
) -> DdosAnalyzeResponse:
    """Avalia logs HTTP e postura defensiva anti-DDoS com contexto opcional de ativo."""
    module_f_context: list[str] = []
    if payload.asset_id:
        asset = _load_authorized_asset(db, principal, payload.asset_id)
        assert principal is not None
        cur_ids = current_finding_ids_stmt(principal.organization.id)
        mod_f_findings = db.scalars(
            select(FindingRecord).where(
                FindingRecord.asset_id == asset.id,
                FindingRecord.organization_id == principal.organization.id,
                FindingRecord.module_id == "mod_f_dos_resilience_posture",
                FindingRecord.treatment_status.in_(list(OPEN_TREATMENT_STATUSES)),
                FindingRecord.id.in_(cur_ids),
            )
        ).all()
        if mod_f_findings:
            module_f_context = [
                f"[{f.check_id} · {f.severity}] {f.title}" for f in mod_f_findings
            ]
        else:
            module_f_context = [
                f"Ativo '{asset.name}' sem achados abertos do Módulo F (Postura Anti-DoS)."
            ]

    result = analyze_ddos_defense(payload, asset_module_f_context=module_f_context)
    _record_tool_audit(
        db,
        principal,
        action="SECURITY_TOOL_DDOS_ANALYSIS",
        resource_id=payload.asset_id,
        metadata={
            "total_requests_parsed": result.total_requests_parsed,
            "resilience_score": result.resilience_score,
            "risk_level": result.risk_level,
            "anomalies_count": len(result.anomalies),
        },
    )
    return result
