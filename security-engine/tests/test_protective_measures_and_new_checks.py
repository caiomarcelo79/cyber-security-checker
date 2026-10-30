"""Testes automatizados das 5 novas verificações de segurança e catálogo de medidas protetivas."""

from __future__ import annotations

import base64
import json
from unittest.mock import MagicMock

from security_engine.core.contracts import CheckStatus, Severity
from security_engine.core.remediation import REMEDIATION_CATALOG, RemediationEngine
from security_engine.modules.builtin_modules import (
    ModuleBAuthLogin,
    ModuleECookiesAndSession,
    ModuleFDoSResiliencePosture,
    ModuleGAPISecurity,
    ModuleHMisconfigAndOther,
)


def _b64_url_encode(data: dict) -> str:
    raw = json.dumps(data).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def test_remediation_catalog_has_all_five_protective_playbooks() -> None:
    expected_playbooks = [
        "credentials_in_query_string",
        "missing_cookie_security_prefixes",
        "http_request_smuggling_desync_risk",
        "insecure_jwt_token_configuration",
        "exposed_admin_or_debug_interface",
    ]
    for key in expected_playbooks:
        assert key in REMEDIATION_CATALOG
        guidance = RemediationEngine.get_guidance(key)
        assert guidance.what_was_identified
        assert guidance.why_it_is_dangerous
        assert guidance.how_it_was_detected
        assert guidance.how_to_fix
        assert len(guidance.secure_examples) >= 2
        assert guidance.how_to_validate
        assert len(guidance.references) >= 2


def test_chk_b04_credentials_in_query_string_and_get_form() -> None:
    mod = ModuleBAuthLogin()

    # Cenário 1: Query string com senha
    res_vulnerable_qs = mod.inspect_response_snapshot(
        target_url="https://lab.local/api/v1/auth/login?user=admin&password=SuperSecretPassword123",
        status_code=200,
        headers={"Content-Type": "application/json"},
        body_excerpt='{"status": "ok"}',
    )
    b04_checks = [c for c in res_vulnerable_qs.checks if c.check_id == "CHK-B04"]
    assert len(b04_checks) == 1
    assert b04_checks[0].status == CheckStatus.VULNERABILITY
    b04_findings = [f for f in res_vulnerable_qs.findings if f.check_id == "CHK-B04"]
    assert len(b04_findings) == 1
    assert b04_findings[0].severity == Severity.HIGH
    assert b04_findings[0].remediation.why_it_is_dangerous

    # Cenário 2: Formulário GET contendo campo de senha
    res_vulnerable_form = mod.inspect_response_snapshot(
        target_url="https://lab.local/login",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body_excerpt='<form method="get" action="/do-login"><input type="password" name="pwd" /></form>',
    )
    b04_form = [c for c in res_vulnerable_form.checks if c.check_id == "CHK-B04"]
    assert len(b04_form) == 1
    assert b04_form[0].status == CheckStatus.VULNERABILITY

    # Cenário 3: URL limpa sem credenciais
    res_clean = mod.inspect_response_snapshot(
        target_url="https://lab.local/search?q=cybersecurity&category=news",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body_excerpt="<html><body>Resultados de busca</body></html>",
    )
    b04_clean = [c for c in res_clean.checks if c.check_id == "CHK-B04"]
    assert len(b04_clean) == 1
    assert b04_clean[0].status == CheckStatus.PASSED


def test_chk_e03_missing_cookie_isolation_prefixes() -> None:
    mod = ModuleECookiesAndSession()

    # Cenário 1: Cookie de sessão sem prefixo __Host- ou __Secure-
    res_insecure = mod.inspect_response_snapshot(
        target_url="https://lab.local/dashboard",
        status_code=200,
        headers={"Set-Cookie": "session_token=abc123456789; Secure; HttpOnly; SameSite=Strict; Path=/"},
    )
    e03_checks = [c for c in res_insecure.checks if c.check_id == "CHK-E03"]
    assert len(e03_checks) == 1
    assert e03_checks[0].status == CheckStatus.POTENTIAL_VULNERABILITY
    e03_finding = next(f for f in res_insecure.findings if f.check_id == "CHK-E03")
    assert e03_finding.remediation.what_was_identified
    assert e03_finding.remediation.how_to_fix

    # Cenário 2: Cookie com prefixo de isolamento __Host-
    res_secure = mod.inspect_response_snapshot(
        target_url="https://lab.local/dashboard",
        status_code=200,
        headers={"Set-Cookie": "__Host-session_token=abc123456789; Secure; HttpOnly; SameSite=Strict; Path=/"},
    )
    e03_sec = [c for c in res_secure.checks if c.check_id == "CHK-E03"]
    assert len(e03_sec) == 1
    assert e03_sec[0].status == CheckStatus.PASSED


def test_chk_f04_http_request_smuggling_desync_risk() -> None:
    mod = ModuleFDoSResiliencePosture()

    # Cenário 1: Resposta snapshot contendo simultaneamente Content-Length e Transfer-Encoding
    res_vulnerable = mod.inspect_response_snapshot(
        target_url="https://lab.local/api",
        status_code=200,
        headers={
            "Content-Length": "128",
            "Transfer-Encoding": "chunked",
            "Server": "CustomProxy/1.0",
        },
    )
    f04_checks = [c for c in res_vulnerable.checks if c.check_id == "CHK-F04"]
    assert len(f04_checks) == 1
    assert f04_checks[0].status == CheckStatus.POTENTIAL_VULNERABILITY
    assert len(res_vulnerable.findings) >= 1
    f04_finding = next(f for f in res_vulnerable.findings if f.check_id == "CHK-F04")
    assert f04_finding.remediation.why_it_is_dangerous

    # Cenário 2: Cabeçalhos normais RFC 9112
    res_normal = mod.inspect_response_snapshot(
        target_url="https://lab.local/api",
        status_code=200,
        headers={"Content-Length": "128", "Server": "nginx"},
    )
    f04_norm = [c for c in res_normal.checks if c.check_id == "CHK-F04"]
    assert len(f04_norm) == 1
    assert f04_norm[0].status == CheckStatus.PASSED


def test_chk_g05_insecure_jwt_token_configuration() -> None:
    mod = ModuleGAPISecurity()

    # Cenário 1: Token JWT com algoritmo "none" e sem expiração
    header_none = _b64_url_encode({"alg": "none", "typ": "JWT"})
    payload_no_exp = _b64_url_encode({"sub": "user123", "role": "admin"})
    bad_jwt = f"{header_none}.{payload_no_exp}."

    res_vulnerable = mod.inspect_response_snapshot(
        target_url="https://lab.local/api/v1/auth/token",
        status_code=200,
        headers={"Content-Type": "application/json"},
        body_excerpt=f'{{"access_token": "{bad_jwt}"}}',
    )
    g05_checks = [c for c in res_vulnerable.checks if c.check_id == "CHK-G05"]
    assert len(g05_checks) == 1
    assert g05_checks[0].status == CheckStatus.VULNERABILITY
    g05_finding = next(f for f in res_vulnerable.findings if f.check_id == "CHK-G05")
    assert g05_finding.remediation.what_was_identified
    assert len(g05_finding.remediation.secure_examples) >= 2

    # Cenário 2: Token JWT assinado com RS256 e claim exp
    header_rs256 = _b64_url_encode({"alg": "RS256", "typ": "JWT"})
    payload_valid = _b64_url_encode({"sub": "user123", "role": "member", "exp": 1893456000})
    signature = base64.urlsafe_b64encode(b"dummy_rsa_signature_bytes_32").decode("ascii").rstrip("=")
    good_jwt = f"{header_rs256}.{payload_valid}.{signature}"

    res_good = mod.inspect_response_snapshot(
        target_url="https://lab.local/api/v1/auth/token",
        status_code=200,
        headers={"Authorization": f"Bearer {good_jwt}"},
        body_excerpt='{"status": "authenticated"}',
    )
    g05_good = [c for c in res_good.checks if c.check_id == "CHK-G05"]
    assert len(g05_good) == 1
    assert g05_good[0].status == CheckStatus.PASSED


def test_chk_h07_exposed_admin_or_debug_interface() -> None:
    mod = ModuleHMisconfigAndOther()

    # Cenário 1: Acesso direto à interface administrativa /actuator/health
    res_actuator = mod.inspect_response_snapshot(
        target_url="https://lab.local/actuator/health",
        status_code=200,
        headers={"Content-Type": "application/json"},
        body_excerpt='{"status": "UP", "components": {"db": {"status": "UP"}}}',
    )
    h07_checks = [c for c in res_actuator.checks if c.check_id == "CHK-H07"]
    assert len(h07_checks) == 1
    assert h07_checks[0].status == CheckStatus.VULNERABILITY
    h07_finding = next(f for f in res_actuator.findings if f.check_id == "CHK-H07")
    assert h07_finding.remediation.how_to_fix
    assert h07_finding.remediation.why_it_is_dangerous

    # Cenário 2: Acesso ativo via http_client.probe em /swagger-ui.html
    mock_client = MagicMock()
    mock_probe = MagicMock()
    mock_probe.status_code = 200
    mock_probe.body = "<html><head><title>Swagger UI</title></head></html>"
    mock_client.probe.return_value = mock_probe

    res_probe_swagger = mod.inspect_response_snapshot(
        target_url="https://lab.local/",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body_excerpt="<html>Home</html>",
        http_client=mock_client,
    )
    h07_swagger = [c for c in res_probe_swagger.checks if c.check_id == "CHK-H07"]
    assert len(h07_swagger) == 1
    assert h07_swagger[0].status == CheckStatus.VULNERABILITY

    # Cenário 3: Alvo protegido sem interfaces administrativas expostas
    mock_clean_client = MagicMock()
    clean_probe = MagicMock()
    clean_probe.status_code = 404
    clean_probe.body = "Not found"
    mock_clean_client.probe.return_value = clean_probe

    res_clean = mod.inspect_response_snapshot(
        target_url="https://lab.local/produtos",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body_excerpt="<html>Produtos à venda</html>",
        http_client=mock_clean_client,
    )
    h07_clean = [c for c in res_clean.checks if c.check_id == "CHK-H07"]
    assert len(h07_clean) == 1
    assert h07_clean[0].status == CheckStatus.PASSED
