"""Rotas REST v1 para as 7 ferramentas defensivas do Console SOC."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.deps import AuthenticatedPrincipal, DbSessionDep, get_optional_principal
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
from app.services.security_tools_service import (
    create_pentest_plan,
    run_ddos_analysis,
    run_firewall_analysis,
    run_forensics_analysis,
    run_malware_analysis,
    run_password_analyze,
    run_password_generate,
    run_wifi_audit,
    run_wifi_local_scan,
)

router = APIRouter(prefix="/api/v1/security-tools", tags=["Ferramentas SOC"])
OptionalPrincipalDep = Annotated[AuthenticatedPrincipal | None, Depends(get_optional_principal)]


@router.post("/pentest-assistant/plan", response_model=PentestPlanResponse)
def post_pentest_plan(
    payload: PentestPlanRequest,
    db: DbSessionDep,
    principal: OptionalPrincipalDep,
) -> PentestPlanResponse:
    """Gera plano guiado OWASP WSTG integrado ao histórico do ativo autorizado."""
    return create_pentest_plan(db, principal, payload)


@router.post("/password/generate", response_model=PasswordGenerateResponse)
def post_password_generate(
    payload: PasswordGenerateRequest,
    db: DbSessionDep,
    principal: OptionalPrincipalDep,
) -> PasswordGenerateResponse:
    """Gera senha aleatória ou passphrase com entropia criptográfica."""
    return run_password_generate(db, principal, payload)


@router.post("/password/analyze", response_model=PasswordAnalyzeResponse)
def post_password_analyze(
    payload: PasswordAnalyzeRequest,
    db: DbSessionDep,
    principal: OptionalPrincipalDep,
) -> PasswordAnalyzeResponse:
    """Analisa força, padrões previsíveis e conformidade NIST/OWASP sem armazenar a senha."""
    return run_password_analyze(db, principal, payload)


@router.post("/forensics/analyze", response_model=ForensicsAnalyzeResponse)
def post_forensics_analyze(
    payload: ForensicsAnalyzeRequest,
    db: DbSessionDep,
    principal: OptionalPrincipalDep,
) -> ForensicsAnalyzeResponse:
    """Executa análise forense estática de logs, artefatos e tokens JWT."""
    return run_forensics_analysis(db, principal, payload)


@router.post("/firewall/test", response_model=FirewallAnalyzeResponse)
def post_firewall_test(
    payload: FirewallAnalyzeRequest,
    db: DbSessionDep,
    principal: OptionalPrincipalDep,
) -> FirewallAnalyzeResponse:
    """Audita regras iptables/UFW/genéricas e simula pacotes em modo estático."""
    return run_firewall_analysis(db, principal, payload)


@router.post("/malware/analyze", response_model=MalwareAnalyzeResponse)
def post_malware_analyze(
    payload: MalwareAnalyzeRequest,
    db: DbSessionDep,
    principal: OptionalPrincipalDep,
) -> MalwareAnalyzeResponse:
    """Analisa payloads estaticamente sem execução, com heurísticas MITRE ATT&CK."""
    return run_malware_analysis(db, principal, payload)


@router.post("/wifi/audit", response_model=WifiAnalyzeResponse)
def post_wifi_audit(
    payload: WifiAnalyzeRequest,
    db: DbSessionDep,
    principal: OptionalPrincipalDep,
) -> WifiAnalyzeResponse:
    """Audita passivamente varreduras Wi-Fi (netsh/nmcli) ou inventários de AP."""
    return run_wifi_audit(db, principal, payload)


@router.post("/wifi/scan-local", response_model=WifiLocalScanResponse)
def post_wifi_scan_local(
    db: DbSessionDep,
    principal: OptionalPrincipalDep,
) -> WifiLocalScanResponse:
    """Captura passivamente as redes Wi-Fi visíveis pela placa do host (netsh/nmcli)."""
    return run_wifi_local_scan(db, principal)


@router.post("/ddos/analyze", response_model=DdosAnalyzeResponse)
def post_ddos_analyze(
    payload: DdosAnalyzeRequest,
    db: DbSessionDep,
    principal: OptionalPrincipalDep,
) -> DdosAnalyzeResponse:
    """Analisa logs de acesso e postura defensiva gerando snippets de mitigação."""
    return run_ddos_analysis(db, principal, payload)
