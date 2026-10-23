"""Suíte de testes automatizados da Fase 5: Módulos B, C, D, F, G, H e CHK-A12."""

from __future__ import annotations

from security_engine.core.contracts import (
    AssetType,
    CheckStatus,
    Severity,
)
from security_engine.core.http_client import SafeProbeResult
from security_engine.core.registry import default_registry
from security_engine.modules.builtin_modules import (
    ModuleAReconHeadersTLS,
    ModuleBAuthLogin,
    ModuleCXSSSafe,
    ModuleDSQLiIndicators,
    ModuleFDoSResiliencePosture,
    ModuleGAPISecurity,
    ModuleHMisconfigAndOther,
)


class MockProbeHttpClient:
    """Mock do cliente HTTP seguro para simular probes pontuais e consultas DNS."""

    def __init__(self, probe_responses: dict[str, SafeProbeResult] | None = None) -> None:
        self.probe_responses = probe_responses or {}
        self.probes_called: list[str] = []

    def probe(self, url: str, **kwargs) -> SafeProbeResult | None:
        self.probes_called.append(url)
        for pattern, res in self.probe_responses.items():
            if pattern in url:
                return res
        return SafeProbeResult(
            status_code=404,
            headers={"Content-Type": "text/html"},
            body="Not Found",
            elapsed_ms=10,
            url=url,
        )


def test_module_b_auth_login_all_checks() -> None:
    """Valida CHK-B01 (HTTPS no login), CHK-B02 (enumeração de usuários) e CHK-B03 (Cache-Control)."""
    mod_b = ModuleBAuthLogin()
    assert mod_b.metadata.module_id == "mod_b_auth_login"

    # 1. CHK-B01 VULNERABILITY: página de login servida via HTTP
    res_http = mod_b.inspect_response_snapshot(
        target_url="http://empresa.local/login",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body_excerpt='<html><body><form action="/login"><input type="password" name="pwd"/></form></body></html>',
    )
    chk_b01 = next(c for c in res_http.checks if c.check_id == "CHK-B01")
    assert chk_b01.status == CheckStatus.VULNERABILITY
    finding_b01 = next(f for f in res_http.findings if f.check_id == "CHK-B01")
    assert finding_b01.severity == Severity.CRITICAL

    # 2. CHK-B01 PASSED: página de login via HTTPS
    res_https = mod_b.inspect_response_snapshot(
        target_url="https://empresa.local/login",
        status_code=200,
        headers={"Content-Type": "text/html", "Cache-Control": "no-store, no-cache"},
        body_excerpt='<html><body><form action="/login"><input type="password" name="pwd"/></form></body></html>',
    )
    assert next(c for c in res_https.checks if c.check_id == "CHK-B01").status == CheckStatus.PASSED

    # 3. CHK-B02 POTENTIAL_VULNERABILITY: mensagem de erro com enumeração
    res_enum = mod_b.inspect_response_snapshot(
        target_url="https://empresa.local/login",
        status_code=401,
        headers={"Content-Type": "text/html", "Cache-Control": "no-store"},
        body_excerpt='<div class="alert">Erro: usuário não encontrado no sistema.</div>',
    )
    chk_b02 = next(c for c in res_enum.checks if c.check_id == "CHK-B02")
    assert chk_b02.status == CheckStatus.POTENTIAL_VULNERABILITY
    finding_b02 = next(f for f in res_enum.findings if f.check_id == "CHK-B02")
    assert "CWE-204" in finding_b02.cwe_ids

    # 4. CHK-B03 POTENTIAL_VULNERABILITY: login sem Cache-Control: no-store
    res_no_cache = mod_b.inspect_response_snapshot(
        target_url="https://empresa.local/login",
        status_code=200,
        headers={"Content-Type": "text/html", "Cache-Control": "public, max-age=3600"},
        body_excerpt='<input type="password" name="p" />',
    )
    chk_b03 = next(c for c in res_no_cache.checks if c.check_id == "CHK-B03")
    assert chk_b03.status == CheckStatus.POTENTIAL_VULNERABILITY


def test_module_c_xss_safe_checks() -> None:
    """Valida CHK-C01 (reflexão de caracteres), CHK-C02 (sinks DOM) e CHK-C03 (CSP)."""
    mod_c = ModuleCXSSSafe()
    assert mod_c.metadata.module_id == "mod_c_xss_safe"

    # 1. CHK-C01: Reflexão sem codificação (VULNERABILITY)
    mock_client_vuln = MockProbeHttpClient(
        probe_responses={
            "csc_probe": SafeProbeResult(
                status_code=200,
                headers={"Content-Type": "text/html"},
                body="<div>Busca por: cscxss7a8b<cscprobe></div>",
                elapsed_ms=15,
                url="https://app.local/?q=test",
            )
        }
    )
    res_xss = mod_c.inspect_response_snapshot(
        target_url="https://app.local/search?q=test",
        status_code=200,
        headers={"Content-Type": "text/html", "Content-Security-Policy": "default-src 'self'"},
        body_excerpt="<html><body>Resultados de busca</body></html>",
        http_client=mock_client_vuln,
    )
    chk_c01 = next(c for c in res_xss.checks if c.check_id == "CHK-C01")
    assert chk_c01.status == CheckStatus.VULNERABILITY
    finding_c01 = next(f for f in res_xss.findings if f.check_id == "CHK-C01")
    assert finding_c01.severity == Severity.HIGH

    # 2. CHK-C01: Reflexão codificada (PASSED)
    mock_client_safe = MockProbeHttpClient(
        probe_responses={
            "csc_probe": SafeProbeResult(
                status_code=200,
                headers={"Content-Type": "text/html"},
                body="<div>Busca por: cscxss7a8b&lt;cscprobe&gt;</div>",
                elapsed_ms=15,
                url="https://app.local/?q=test",
            )
        }
    )
    res_xss_safe = mod_c.inspect_response_snapshot(
        target_url="https://app.local/search?q=test",
        status_code=200,
        headers={"Content-Type": "text/html", "Content-Security-Policy": "default-src 'self'"},
        body_excerpt="<html><body>Resultados de busca</body></html>",
        http_client=mock_client_safe,
    )
    assert next(c for c in res_xss_safe.checks if c.check_id == "CHK-C01").status == CheckStatus.PASSED

    # 3. CHK-C02: Sink DOM perigoso identificado (POTENTIAL_VULNERABILITY)
    res_dom = mod_c.inspect_response_snapshot(
        target_url="https://app.local/dashboard",
        status_code=200,
        headers={"Content-Type": "text/html", "Content-Security-Policy": "default-src 'self'"},
        body_excerpt="<script>document.getElementById('content').innerHTML = location.search;</script>",
    )
    chk_c02 = next(c for c in res_dom.checks if c.check_id == "CHK-C02")
    assert chk_c02.status == CheckStatus.POTENTIAL_VULNERABILITY

    # 4. CHK-C03: CSP com unsafe-inline (POTENTIAL_VULNERABILITY)
    res_csp = mod_c.inspect_response_snapshot(
        target_url="https://app.local/dashboard",
        status_code=200,
        headers={
            "Content-Type": "text/html",
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'",
        },
        body_excerpt="<html><body>Dashboard</body></html>",
    )
    chk_c03 = next(c for c in res_csp.checks if c.check_id == "CHK-C03")
    assert chk_c03.status == CheckStatus.POTENTIAL_VULNERABILITY


def test_module_d_sqli_indicators() -> None:
    """Valida CHK-D01 (assinaturas de erro SQL) e restrição de ambiente."""
    mod_d = ModuleDSQLiIndicators()
    assert mod_d.metadata.module_id == "mod_d_sqli_indicators"
    assert mod_d.metadata.allow_in_production is False

    # 1. CHK-D01: Assinatura de erro PostgreSQL identificada (VULNERABILITY)
    res_sqli = mod_d.inspect_response_snapshot(
        target_url="https://staging.app.local/users?id=1",
        status_code=500,
        headers={"Content-Type": "text/html"},
        body_excerpt="Database exception: org.postgresql.util.PSQLException: ERROR: syntax error at or near",
    )
    chk_d01 = next(c for c in res_sqli.checks if c.check_id == "CHK-D01")
    assert chk_d01.status == CheckStatus.VULNERABILITY
    finding_d01 = next(f for f in res_sqli.findings if f.check_id == "CHK-D01")
    assert finding_d01.severity == Severity.HIGH
    assert "CWE-89" in finding_d01.cwe_ids

    # 2. CHK-D01: Resposta limpa com erro HTTP 400 genérico (PASSED)
    res_clean = mod_d.inspect_response_snapshot(
        target_url="https://staging.app.local/users?id=1",
        status_code=400,
        headers={"Content-Type": "application/json"},
        body_excerpt='{"detail": "Parâmetro id inválido"}',
    )
    assert next(c for c in res_clean.checks if c.check_id == "CHK-D01").status == CheckStatus.PASSED


def test_module_g_api_security() -> None:
    """Valida CHK-G01 (CORS), CHK-G02 (OpenAPI público) e CHK-G03 (métodos TRACE)."""
    mod_g = ModuleGAPISecurity()
    assert mod_g.metadata.module_id == "mod_g_api_security"

    # 1. CHK-G01: CORS com Wildcard e Allow-Credentials: true (VULNERABILITY)
    res_cors = mod_g.inspect_response_snapshot(
        target_url="https://api.empresa.local/v1/data",
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
            "Content-Type": "application/json",
        },
        asset_type=AssetType.REST_API,
    )
    chk_g01 = next(c for c in res_cors.checks if c.check_id == "CHK-G01")
    assert chk_g01.status == CheckStatus.VULNERABILITY

    # 2. CHK-G02: Exposição de OpenAPI (POTENTIAL_VULNERABILITY)
    res_openapi = mod_g.inspect_response_snapshot(
        target_url="https://api.empresa.local/openapi.json",
        status_code=200,
        headers={"Content-Type": "application/json"},
        body_excerpt='{"openapi": "3.1.0", "info": {"title": "API Interna"}}',
        asset_type=AssetType.REST_API,
    )
    chk_g02 = next(c for c in res_openapi.checks if c.check_id == "CHK-G02")
    assert chk_g02.status == CheckStatus.POTENTIAL_VULNERABILITY

    # 3. CHK-G03: Método TRACE habilitado em Allow (POTENTIAL_VULNERABILITY)
    res_trace = mod_g.inspect_response_snapshot(
        target_url="https://api.empresa.local/v1/users",
        status_code=200,
        headers={"Allow": "GET, POST, TRACE, OPTIONS"},
        asset_type=AssetType.REST_API,
    )
    chk_g03 = next(c for c in res_trace.checks if c.check_id == "CHK-G03")
    assert chk_g03.status == CheckStatus.POTENTIAL_VULNERABILITY


def test_module_f_dos_resilience_posture() -> None:
    """Valida CHK-F01 (CDN/WAF) e CHK-F02 (Rate Limiting)."""
    mod_f = ModuleFDoSResiliencePosture()

    # 1. Detecção de Cloudflare e RateLimit headers (PASSED)
    res_cf = mod_f.inspect_response_snapshot(
        target_url="https://empresa.com",
        status_code=200,
        headers={
            "cf-ray": "8d3e9124a8726b1c-GRU",
            "server": "cloudflare",
            "RateLimit-Limit": "100",
            "RateLimit-Remaining": "98",
        },
    )
    assert next(c for c in res_cf.checks if c.check_id == "CHK-F01").status == CheckStatus.PASSED
    assert next(c for c in res_cf.checks if c.check_id == "CHK-F02").status == CheckStatus.PASSED

    # 2. Ausência de WAF e ausência de Rate Limit (POTENTIAL_VULNERABILITY / INFO)
    res_bare = mod_f.inspect_response_snapshot(
        target_url="https://empresa.com",
        status_code=200,
        headers={"server": "nginx/1.24.0"},
    )
    assert next(c for c in res_bare.checks if c.check_id == "CHK-F01").status == CheckStatus.POTENTIAL_VULNERABILITY
    assert next(c for c in res_bare.checks if c.check_id == "CHK-F02").status == CheckStatus.POTENTIAL_VULNERABILITY


def test_module_h_misconfig_and_other() -> None:
    """Valida CHK-H01 (.env exposto), CHK-H02 (Directory Listing), CHK-H03 (Open Redirect) e CHK-H04 (CSRF)."""
    mod_h = ModuleHMisconfigAndOther()

    # 1. CHK-H01: Exposição de .env (VULNERABILITY CRITICAL)
    res_env = mod_h.inspect_response_snapshot(
        target_url="https://empresa.com/.env",
        status_code=200,
        headers={"Content-Type": "text/plain"},
        body_excerpt="DATABASE_URL=postgresql://postgres:secret@db:5432/csc\nSECRET_KEY=supersecretkey",
    )
    chk_h01 = next(c for c in res_env.checks if c.check_id == "CHK-H01")
    assert chk_h01.status == CheckStatus.VULNERABILITY
    finding_h01 = next(f for f in res_env.findings if f.check_id == "CHK-H01")
    assert finding_h01.severity == Severity.CRITICAL

    # 2. CHK-H02: Directory Listing (VULNERABILITY MEDIUM)
    res_dir = mod_h.inspect_response_snapshot(
        target_url="https://empresa.com/uploads/",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body_excerpt="<html><head><title>Index of /uploads</title></head><body><h1>Index of /uploads</h1></body></html>",
    )
    chk_h02 = next(c for c in res_dir.checks if c.check_id == "CHK-H02")
    assert chk_h02.status == CheckStatus.VULNERABILITY

    # 3. CHK-H03: Open Redirect (VULNERABILITY MEDIUM)
    res_redir = mod_h.inspect_response_snapshot(
        target_url="https://empresa.com/login?redirect=https://evil-phishing.com/steal",
        status_code=302,
        headers={"Location": "https://evil-phishing.com/steal"},
    )
    chk_h03 = next(c for c in res_redir.checks if c.check_id == "CHK-H03")
    assert chk_h03.status == CheckStatus.VULNERABILITY

    # 4. CHK-H04: Formulário POST sem CSRF token e sem SameSite (POTENTIAL_VULNERABILITY)
    res_csrf = mod_h.inspect_response_snapshot(
        target_url="https://empresa.com/transfer",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body_excerpt='<form method="POST" action="/transfer"><input name="amount" value="100"/><button>Enviar</button></form>',
        raw_set_cookies=["session_id=abc; Secure; HttpOnly"],  # Sem SameSite
    )
    chk_h04 = next(c for c in res_csrf.checks if c.check_id == "CHK-H04")
    assert chk_h04.status == CheckStatus.POTENTIAL_VULNERABILITY


def test_chk_a12_email_authentication() -> None:
    """Valida CHK-A12: registros de SPF e DMARC no Módulo A."""
    mod_a = ModuleAReconHeadersTLS()

    def mock_dns_resolver_ok(qname: str) -> list[str]:
        if "_dmarc" in qname:
            return ["v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@dominio.com"]
        return ["v=spf1 include:_spf.google.com ~all"]

    # 1. Domínio com SPF e DMARC configurados (PASSED)
    res_ok = mod_a.inspect_response_snapshot(
        target_url="https://dominio.com/app",
        status_code=200,
        headers={"Content-Type": "text/html"},
        dns_txt_resolver=mock_dns_resolver_ok,
    )
    chk_a12_ok = next(c for c in res_ok.checks if c.check_id == "CHK-A12")
    assert chk_a12_ok.status == CheckStatus.PASSED

    # 2. Domínio com SPF ausente (POTENTIAL_VULNERABILITY)
    def mock_dns_resolver_no_spf(qname: str) -> list[str]:
        if "_dmarc" in qname:
            return ["v=DMARC1; p=reject"]
        return []

    res_missing = mod_a.inspect_response_snapshot(
        target_url="https://dominio.com/app",
        status_code=200,
        headers={"Content-Type": "text/html"},
        dns_txt_resolver=mock_dns_resolver_no_spf,
    )
    chk_a12_missing = next(c for c in res_missing.checks if c.check_id == "CHK-A12")
    assert chk_a12_missing.status == CheckStatus.POTENTIAL_VULNERABILITY
    finding_a12 = next(f for f in res_missing.findings if f.check_id == "CHK-A12")
    assert "CWE-345" in finding_a12.cwe_ids
    assert finding_a12.severity == Severity.LOW

    # 3. IP address direto (CHK-A12 omitido / não aplicável)
    res_ip = mod_a.inspect_response_snapshot(
        target_url="https://127.0.0.1/app",
        status_code=200,
        headers={"Content-Type": "text/html"},
    )
    assert not any(c.check_id == "CHK-A12" for c in res_ip.checks)


def test_registry_has_all_eight_real_modules() -> None:
    """Valida se todos os 8 módulos (A, B, C, D, E, F, G, H) estão instanciados como classes reais."""
    modules = default_registry.list_metadata()
    assert len(modules) == 8
    mod_ids = {m.module_id for m in modules}
    expected_ids = {
        "mod_a_recon_headers_tls",
        "mod_b_auth_login",
        "mod_c_xss_safe",
        "mod_d_sqli_indicators",
        "mod_e_cookies_session",
        "mod_f_dos_resilience_posture",
        "mod_g_api_security",
        "mod_h_misconfig_and_other",
    }
    assert mod_ids == expected_ids

    # Verifica que Módulo D não é permitido em produção
    mod_d = default_registry.get_module("mod_d_sqli_indicators")
    assert mod_d.metadata.allow_in_production is False
