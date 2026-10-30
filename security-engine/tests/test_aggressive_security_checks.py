"""Suíte de testes automatizados para verificações ativas e heurísticas profundas (DEEP_PENTEST).

Cobre:
- CHK-H05: Detecção de Path Traversal / Local File Inclusion (LFI)
- CHK-H06: Indicadores de Server-Side Request Forgery (SSRF) no Alvo
- CHK-D03: Indicadores de Injeção de Comandos de Sistema Operacional (OS Command Injection)
- CHK-D04: Heurística de SQL Injection Cego (Time/Boolean)
- CHK-G01: Detecção Ativa de Reflexão Arbitrária de Origin em CORS
- CHK-G04: Verificação Ativa de Métodos HTTP Perigosos (Verb Tampering & XST)
- CHK-C04: Fuzzing Ativo Contextual em Múltiplos Parâmetros (XSS)
- Perfil DEEP_PENTEST e regras de bloqueio para Produção
"""

from __future__ import annotations

from typing import Any

from security_engine.core.contracts import (
    AssetType,
    CheckStatus,
    ScanProfileType,
    Severity,
)
from security_engine.core.http_client import SafeProbeResult
from security_engine.modules.builtin_modules import (
    ModuleCXSSSafe,
    ModuleDSQLiIndicators,
    ModuleGAPISecurity,
    ModuleHMisconfigAndOther,
)
from security_engine.policies.execution_policy import get_scan_profiles


class MockAggressiveHttpClient:
    """Mock do cliente HTTP seguro para simular probes ativos específicos."""

    def __init__(
        self,
        probe_map: dict[str, SafeProbeResult] | None = None,
        default_result: SafeProbeResult | None = None,
    ) -> None:
        self.probe_map = probe_map or {}
        self.default_result = default_result
        self.probes_recorded: list[dict[str, Any]] = []

    def probe(
        self,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        **kwargs,
    ) -> SafeProbeResult | None:
        self.probes_recorded.append({"url": url, "method": method, "headers": headers})
        if method == "TRACE" and "TRACE" in self.probe_map:
            return self.probe_map["TRACE"]
        if headers and "Origin" in headers and "CORS" in self.probe_map:
            return self.probe_map["CORS"]
        for pattern, res in self.probe_map.items():
            if pattern in url:
                return res
        return self.default_result or SafeProbeResult(
            status_code=404,
            headers={"Content-Type": "text/html"},
            body="Not Found",
            elapsed_ms=10,
            url=url,
        )


def test_path_traversal_lfi_active_detection() -> None:
    """Valida que CHK-H05 identifica vazamento de /etc/passwd quando injetado probe em parâmetro."""
    mod_h = ModuleHMisconfigAndOther()
    probe_map = {
        "passwd": SafeProbeResult(
            status_code=200,
            headers={"Content-Type": "text/plain"},
            body="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
            elapsed_ms=25,
            url="https://lab.internal/view?file=..%2F..%2Fetc%2Fpasswd",
        )
    }
    client = MockAggressiveHttpClient(probe_map)

    result = mod_h.inspect_response_snapshot(
        target_url="https://lab.internal/view?file=home.html",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body_excerpt="<html>Home</html>",
        http_client=client,
    )

    chk_h05 = next(c for c in result.checks if c.check_id == "CHK-H05")
    assert chk_h05.status == CheckStatus.VULNERABILITY
    assert "Path Traversal" in chk_h05.title

    finding = next(f for f in result.findings if f.check_id == "CHK-H05")
    assert finding.severity == Severity.CRITICAL
    assert "CWE-22" in finding.cwe_ids
    assert finding.remediation.remediation_id == "path_traversal_lfi"


def test_path_traversal_lfi_passed_when_no_leak() -> None:
    """Valida que CHK-H05 retorna PASSED quando o alvo não vaza arquivos locais."""
    mod_h = ModuleHMisconfigAndOther()
    client = MockAggressiveHttpClient()

    result = mod_h.inspect_response_snapshot(
        target_url="https://lab.internal/view?file=home.html",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body_excerpt="<html>Home</html>",
        http_client=client,
    )

    chk_h05 = next(c for c in result.checks if c.check_id == "CHK-H05")
    assert chk_h05.status == CheckStatus.PASSED


def test_ssrf_target_indicator_detection() -> None:
    """Valida que CHK-H06 identifica erro de socket quando alvo tenta resolver URL externa arbitrária."""
    mod_h = ModuleHMisconfigAndOther()
    probe_map = {
        "canary.csc-ssrf-probe.internal": SafeProbeResult(
            status_code=500,
            headers={"Content-Type": "text/html"},
            body="Exception: Failed to connect to canary.csc-ssrf-probe.internal: ConnectionRefusedError (socket.gaierror)",
            elapsed_ms=150,
            url="https://lab.internal/fetch?url=http://canary.csc-ssrf-probe.internal/csc_token",
        )
    }
    client = MockAggressiveHttpClient(probe_map)

    result = mod_h.inspect_response_snapshot(
        target_url="https://lab.internal/fetch?url=https://example.com/data.json",
        status_code=200,
        headers={"Content-Type": "application/json"},
        body_excerpt='{"status": "ok"}',
        http_client=client,
    )

    chk_h06 = next(c for c in result.checks if c.check_id == "CHK-H06")
    assert chk_h06.status == CheckStatus.POTENTIAL_VULNERABILITY

    finding = next(f for f in result.findings if f.check_id == "CHK-H06")
    assert finding.severity == Severity.HIGH
    assert "CWE-918" in finding.cwe_ids
    assert finding.remediation.remediation_id == "ssrf_target_vulnerability"


def test_os_command_injection_active_detection() -> None:
    """Valida que CHK-D03 detecta canary echo de injeção de comando de SO."""
    mod_d = ModuleDSQLiIndicators()
    cmd_canary = "csc_cmd_canary_491"
    probe_map = {
        cmd_canary: SafeProbeResult(
            status_code=200,
            headers={"Content-Type": "text/html"},
            body=f"<html>Result: {cmd_canary}<br>Done</html>",
            elapsed_ms=40,
            url=f"https://lab.internal/ping?host=1;echo+{cmd_canary}",
        )
    }
    client = MockAggressiveHttpClient(probe_map)

    result = mod_d.inspect_response_snapshot(
        target_url="https://lab.internal/ping?host=127.0.0.1",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body_excerpt="<html>PING 127.0.0.1</html>",
        http_client=client,
    )

    chk_d03 = next(c for c in result.checks if c.check_id == "CHK-D03")
    assert chk_d03.status == CheckStatus.VULNERABILITY

    finding = next(f for f in result.findings if f.check_id == "CHK-D03")
    assert finding.severity == Severity.CRITICAL
    assert "CWE-78" in finding.cwe_ids
    assert finding.remediation.remediation_id == "os_command_injection"


def test_active_cors_arbitrary_origin_reflection() -> None:
    """Valida que CHK-G01 detecta reflexão ativa de Origin não confiável com credentials: true."""
    mod_g = ModuleGAPISecurity()
    probe_map = {
        "CORS": SafeProbeResult(
            status_code=200,
            headers={
                "Access-Control-Allow-Origin": "https://attacker.csc-test.internal",
                "Access-Control-Allow-Credentials": "true",
            },
            body='{"user": "admin"}',
            elapsed_ms=20,
            url="https://lab.internal/api/v1/user",
        )
    }
    client = MockAggressiveHttpClient(probe_map)

    result = mod_g.inspect_response_snapshot(
        target_url="https://lab.internal/api/v1/user",
        status_code=200,
        headers={"Content-Type": "application/json"},
        body_excerpt='{"user": "admin"}',
        asset_type=AssetType.REST_API,
        http_client=client,
    )

    chk_g01 = next(c for c in result.checks if c.check_id == "CHK-G01")
    assert chk_g01.status == CheckStatus.VULNERABILITY

    finding = next(f for f in result.findings if f.check_id == "CHK-G01")
    assert finding.severity == Severity.HIGH
    assert "CWE-346" in finding.cwe_ids
    assert finding.remediation.remediation_id == "cors_arbitrary_origin"


def test_active_http_trace_verb_tampering() -> None:
    """Valida que CHK-G04 detecta suporte ao método TRACE com eco de cabeçalhos (XST)."""
    mod_g = ModuleGAPISecurity()
    canary_header_val = "csc_xst_audit_canary_718"
    probe_map = {
        "TRACE": SafeProbeResult(
            status_code=200,
            headers={"Content-Type": "message/http"},
            body=f"TRACE /api/v1/resource HTTP/1.1\r\nHost: lab.internal\r\nX-CSC-Audit-Token: {canary_header_val}\r\n",
            elapsed_ms=15,
            url="https://lab.internal/api/v1/resource",
        )
    }
    client = MockAggressiveHttpClient(probe_map)

    result = mod_g.inspect_response_snapshot(
        target_url="https://lab.internal/api/v1/resource",
        status_code=200,
        headers={"Content-Type": "application/json"},
        body_excerpt='{"data": "public"}',
        asset_type=AssetType.REST_API,
        http_client=client,
    )

    chk_g04 = next(c for c in result.checks if c.check_id == "CHK-G04")
    assert chk_g04.status == CheckStatus.VULNERABILITY

    finding = next(f for f in result.findings if f.check_id == "CHK-G04")
    assert finding.severity == Severity.MEDIUM
    assert "CWE-650" in finding.cwe_ids
    assert finding.remediation.remediation_id == "http_dangerous_methods"


def test_contextual_multi_parameter_xss_fuzzing() -> None:
    """Valida que CHK-C04 identifica reflexão de breakout tag sem sanitização."""
    mod_c = ModuleCXSSSafe()
    probe_map = {
        "csc_tag_probe": SafeProbeResult(
            status_code=200,
            headers={"Content-Type": "text/html"},
            body='<div>Result: "><csc_tag_probe> found</div>',
            elapsed_ms=30,
            url="https://lab.internal/search?query=%22%3E%3Ccsc_tag_probe%3E",
        )
    }
    client = MockAggressiveHttpClient(probe_map)

    result = mod_c.inspect_response_snapshot(
        target_url="https://lab.internal/search?query=livros",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body_excerpt="<div>Result: livros found</div>",
        http_client=client,
    )

    chk_c04 = next(c for c in result.checks if c.check_id == "CHK-C04")
    assert chk_c04.status == CheckStatus.VULNERABILITY

    finding = next(f for f in result.findings if f.check_id == "CHK-C04")
    assert finding.severity == Severity.HIGH
    assert "CWE-79" in finding.cwe_ids


def test_deep_pentest_profile_restrictions() -> None:
    """Valida que o perfil DEEP_PENTEST está catalogado e é proibido em Produção."""
    profiles = get_scan_profiles()
    deep_pentest = next(p for p in profiles if p.profile_type == ScanProfileType.DEEP_PENTEST)

    assert deep_pentest.allowed_in_production is False
    assert len(deep_pentest.enabled_modules) == 8
    assert "mod_h_misconfig_and_other" in deep_pentest.enabled_modules
    assert "mod_d_sqli_indicators" in deep_pentest.enabled_modules
    assert "mod_c_xss_safe" in deep_pentest.enabled_modules
    assert "mod_g_api_security" in deep_pentest.enabled_modules
    assert any("lab" in p.lower() or "staging" in p.lower() for p in deep_pentest.prerequisites)
