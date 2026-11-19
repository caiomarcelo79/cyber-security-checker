"""Testes abrangentes para precisão anti-falso-positivo e 10 novos checks (CHK-A13 .. CHK-H09)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from collections.abc import Callable
from typing import Any

from security_engine.core.contracts import (
    AssetType,
    CheckStatus,
    Confidence,
    NormalizedFinding,
    SanitizedEvidence,
    Severity,
)
from security_engine.core.evidence import EvidenceManager
from security_engine.core.http_client import SafeProbeResult
from security_engine.core.remediation import REMEDIATION_CATALOG, RemediationEngine
from security_engine.core.risk import CHECK_CVSS_V4_CATALOG, RiskEngine
from security_engine.modules.builtin_modules import (
    ModuleAReconHeadersTLS,
    ModuleBAuthLogin,
    ModuleCXSSSafe,
    ModuleDSQLiIndicators,
    ModuleECookiesAndSession,
    ModuleFDoSResiliencePosture,
    ModuleGAPISecurity,
    ModuleHMisconfigAndOther,
    get_builtin_modules,
)


class _StubProbeClient:
    """Cliente de sondas determinístico em memória para testes de precisão e novos checks."""

    def __init__(self, handler: Callable[[str, str, dict[str, str] | None], SafeProbeResult]) -> None:
        self._handler = handler
        self.calls: list[tuple[str, str, dict[str, str] | None]] = []

    def probe(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        is_cancelled: Any = None,
        timeout_seconds: float | None = None,
    ) -> SafeProbeResult:
        self.calls.append((method, url, headers))
        return self._handler(method, url, headers)


def _check_map(result: Any) -> dict[str, Any]:
    return {chk.check_id: chk for chk in result.checks}


def _findings_by_check(result: Any) -> dict[str, list[NormalizedFinding]]:
    grouped: dict[str, list[NormalizedFinding]] = {}
    for finding in result.findings:
        grouped.setdefault(finding.check_id, []).append(finding)
    return grouped


def _build_hs256_jwt(header: dict[str, Any], payload: dict[str, Any], secret: str) -> str:
    def _b64(data: dict[str, Any]) -> str:
        raw = json.dumps(data, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    h_seg = _b64(header)
    p_seg = _b64(payload)
    signing_input = f"{h_seg}.{p_seg}".encode("ascii")
    sig = base64.urlsafe_b64encode(hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest())
    return f"{h_seg}.{p_seg}.{sig.rstrip(b'=').decode('ascii')}"


def test_evidence_manager_ensure_sanitized_and_expanded_query_keys() -> None:
    raw_url = "https://lab.local/login?pass=Sup3rS3cret&senha=123456&auth_token=tok123&id_token=idt999&safe=ok"
    sanitized_once, redactions = EvidenceManager.sanitize_url(raw_url)
    assert redactions == 4
    assert "Sup3rS3cret" not in sanitized_once
    assert "123456" not in sanitized_once
    assert "tok123" not in sanitized_once
    assert "idt999" not in sanitized_once
    assert "safe=ok" in sanitized_once

    # Idempotência de sanitize_url e sanitize_headers
    assert EvidenceManager.sanitize_url(sanitized_once) == (sanitized_once, 0)

    ev = SanitizedEvidence(
        request_url=raw_url,
        request_headers={"Authorization": "Bearer jwt_secret_token_abc", "X-Safe": "1"},
        response_headers={"Set-Cookie": "session_id=raw_cookie_secret_val; HttpOnly"},
        response_body_Excerpt="token: Bearer leak_token_999 and Authorization: Basic Zm9vOmJhcg==",
    )
    cleaned = EvidenceManager.ensure_sanitized(ev)
    assert "Sup3rS3cret" not in cleaned.request_url
    assert "jwt_secret_token_abc" not in cleaned.request_headers["Authorization"]
    assert "raw_cookie_secret_val" not in cleaned.response_headers["Set-Cookie"]
    assert "leak_token_999" not in (cleaned.response_body_Excerpt or "")
    assert EvidenceManager.ensure_sanitized(cleaned) == cleaned


def test_risk_engine_cvss_v4_catalog_and_evidence_sanitization() -> None:
    modules = get_builtin_modules()
    all_check_ids = [item.split(":", 1)[0].strip() for mod in modules for item in mod.metadata.checks_catalog]
    assert len(all_check_ids) == 53
    for check_id in all_check_ids:
        assert check_id in CHECK_CVSS_V4_CATALOG, f"Check {check_id} ausente no CHECK_CVSS_V4_CATALOG"

    new_playbooks = [
        "missing_subresource_integrity_sri",
        "client_side_token_or_secret_exposure",
        "server_side_template_injection_ssti",
        "nosql_ldap_xpath_injection",
        "cookie_weak_entropy_or_insecure_deserialization",
        "web_cache_poisoning_unkeyed_headers",
        "api_excessive_data_exposure_bopla",
        "graphql_introspection_and_batching_exposure",
        "host_header_injection",
        "exposed_sourcemaps_and_build_artifacts",
    ]
    for playbook_key in new_playbooks:
        guidance = REMEDIATION_CATALOG[playbook_key]
        assert len(guidance.secure_examples) >= 2
        assert len(guidance.references) >= 2

    finding = NormalizedFinding(
        endpoint="https://lab.local/api/users",
        module_id="mod_g_api_security",
        check_id="CHK-G06",
        fingerprint="fp-g06-test",
        title="BOPLA Test",
        description="Teste",
        category="API",
        result_classification=CheckStatus.POTENTIAL_VULNERABILITY,
        severity=Severity.HIGH,
        confidence=Confidence.FIRM,
        evidence=SanitizedEvidence(
            request_url="https://lab.local/api?pass=secret123",
            request_headers={"Authorization": "Bearer super_raw_token_12345"},
        ),
        impact="Exposição de credenciais internas.",
        remediation=RemediationEngine.get_guidance("api_excessive_data_exposure_bopla"),
    )
    validated = RiskEngine.validate_finding_consistency(finding)
    assert validated.cvss_v4_vector is not None
    assert validated.cvss_v4_vector.startswith("CVSS:4.0/")
    assert validated.cvss_v4_score == round(CHECK_CVSS_V4_CATALOG["CHK-G06"][1] * 0.85, 1)
    assert "secret123" not in validated.evidence.request_url
    assert "super_raw_token_12345" not in validated.evidence.request_headers["Authorization"]


def test_module_a_precision_improvements_and_chk_a13_sri() -> None:
    mod_a = ModuleAReconHeadersTLS()

    # 1. Alvo seguro: CSP com wildcard de subdomínio legítimo, Referrer-Policy multi-valor, SRI válido
    secure_res = mod_a.inspect_response_snapshot(
        target_url="https://app.lab.local/",
        status_code=200,
        headers={
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "Content-Security-Policy": (
                "default-src 'self'; script-src 'self' https://*.cdn.lab.local; "
                "frame-ancestors 'self'; object-src 'none'"
            ),
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer, strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), camera=()",
        },
        tls_info={
            "enabled": True,
            "handshake_succeeded": True,
            "trusted_chain": True,
            "hostname_matched": True,
            "days_until_expiration": 180,
            "negotiated_version": "TLSv1.3",
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
        },
        body_excerpt=(
            '<html><head><script src="https://cdn.example.invalid/app.js" '
            'integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"></script></head></html>'
        ),
        dns_txt_resolver=lambda q: ["v=DMARC1; p=reject"] if q.startswith("_dmarc.") else ["v=spf1 -all"],
    )
    chk_sec = _check_map(secure_res)
    for cid in ("CHK-A02", "CHK-A03", "CHK-A05", "CHK-A06", "CHK-A11", "CHK-A12", "CHK-A13"):
        assert chk_sec[cid].status == CheckStatus.PASSED, f"{cid} falhou no cenário seguro: {chk_sec[cid].summary}"

    # 2. Alvo com falhas sutis: HSTS max-age=0, CSP com * isolado + frame-ancestors *, cifra RC4, SPF +all, script externo sem SRI
    vuln_res = mod_a.inspect_response_snapshot(
        target_url="https://app.lab.local/",
        status_code=200,
        headers={
            "Strict-Transport-Security": "max-age=0; preload",
            "Content-Security-Policy": "script-src 'self' *; frame-ancestors *",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "unsafe-url",
            "Permissions-Policy": "geolocation=()",
        },
        tls_info={
            "enabled": True,
            "handshake_succeeded": True,
            "trusted_chain": True,
            "hostname_matched": True,
            "days_until_expiration": 180,
            "negotiated_version": "TLSv1.2",
            "cipher_suite": "TLS_RSA_WITH_RC4_128_SHA",
        },
        body_excerpt='<html><head><script src="https://thirdparty.invalid/widget.js"></script></head></html>',
        dns_txt_resolver=lambda q: ["v=DMARC1; p=none"] if q.startswith("_dmarc.") else ["v=spf1 +all"],
    )
    chk_vuln = _check_map(vuln_res)
    assert chk_vuln["CHK-A02"].status == CheckStatus.VULNERABILITY
    assert chk_vuln["CHK-A03"].status == CheckStatus.POTENTIAL_VULNERABILITY
    assert chk_vuln["CHK-A05"].status == CheckStatus.VULNERABILITY
    assert chk_vuln["CHK-A06"].status == CheckStatus.POTENTIAL_VULNERABILITY
    assert chk_vuln["CHK-A11"].status == CheckStatus.VULNERABILITY
    assert chk_vuln["CHK-A12"].status == CheckStatus.VULNERABILITY
    assert chk_vuln["CHK-A13"].status == CheckStatus.POTENTIAL_VULNERABILITY


def test_module_b_form_default_get_and_chk_b05_secrets_and_web_storage() -> None:
    mod_b = ModuleBAuthLogin()

    # Formulário com senha sem method= (default GET no HTML) + segredo hardcoded (construído em runtime)
    fake_aws_key = "AKIA" + "IOSFODNN7EXAMPLE"
    res_secret = mod_b.inspect_response_snapshot(
        target_url="https://app.lab.local/login",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body_excerpt=(
            f'<form action="/auth"><input type="password" name="pwd"></form>'
            f'<script>const cfg = "{fake_aws_key}";</script>'
        ),
    )
    chks = _check_map(res_secret)
    assert chks["CHK-B04"].status == CheckStatus.VULNERABILITY
    assert chks["CHK-B05"].status == CheckStatus.VULNERABILITY
    b05_finding = _findings_by_check(res_secret)["CHK-B05"][0]
    assert b05_finding.severity == Severity.HIGH
    assert fake_aws_key not in b05_finding.evidence.observed_value

    # Web storage token
    res_storage = mod_b.inspect_response_snapshot(
        target_url="https://app.lab.local/login",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body_excerpt="<script>localStorage.setItem('auth_token', resp.token);</script>",
    )
    assert _check_map(res_storage)["CHK-B05"].status == CheckStatus.POTENTIAL_VULNERABILITY

    # Limpo
    res_clean = mod_b.inspect_response_snapshot(
        target_url="https://app.lab.local/login",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body_excerpt='<form method="post" action="/auth"><input type="password" name="pwd"></form>',
    )
    assert _check_map(res_clean)["CHK-B04"].status == CheckStatus.PASSED
    assert _check_map(res_clean)["CHK-B05"].status == CheckStatus.PASSED


def test_module_c_json_anti_fp_and_chk_c05_ssti() -> None:
    mod_c = ModuleCXSSSafe()

    # Anti-FP: JSON com nosniff refletindo input não deve ser marcado como XSS
    json_res = mod_c.inspect_response_snapshot(
        target_url="https://api.lab.local/search?q=<script>alert(1)</script>",
        status_code=200,
        headers={"Content-Type": "application/json", "X-Content-Type-Options": "nosniff"},
        body_excerpt='{"query": "<script>alert(1)</script>"}',
        asset_type=AssetType.REST_API,
    )
    json_chks = _check_map(json_res)
    assert json_chks["CHK-C01"].status == CheckStatus.PASSED

    # SSTI ativo via sonda
    ssti_probe = _StubProbeClient(
        lambda m, url, h: SafeProbeResult(
            status_code=200,
            headers={"Content-Type": "text/html"},
            body="<html><body>Olá csc1337csc</body></html>" if "7*191" in url else "<html><body>OK</body></html>",
            elapsed_ms=10,
            url=url,
        )
    )
    ssti_res = mod_c.inspect_response_snapshot(
        target_url="https://app.lab.local/greet?name=visitante",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body_excerpt="<html><body>Olá visitante</body></html>",
        http_client=ssti_probe,
    )
    ssti_chks = _check_map(ssti_res)
    assert ssti_chks["CHK-C05"].status == CheckStatus.VULNERABILITY
    c05_f = _findings_by_check(ssti_res)["CHK-C05"][0]
    assert c05_f.severity == Severity.CRITICAL
    assert c05_f.cwe_ids == ["CWE-1336"]

    # SSTI limpo
    clean_probe = _StubProbeClient(
        lambda m, url, h: SafeProbeResult(
            status_code=200,
            headers={"Content-Type": "text/html"},
            body="<html><body>OK</body></html>",
            elapsed_ms=10,
            url=url,
        )
    )
    clean_res = mod_c.inspect_response_snapshot(
        target_url="https://app.lab.local/greet?name=visitante",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body_excerpt="<html><body>Olá visitante</body></html>",
        http_client=clean_probe,
    )
    assert _check_map(clean_res)["CHK-C05"].status == CheckStatus.PASSED


def test_module_d_baseline_differential_and_chk_d05_nosql_ldap_xpath() -> None:
    mod_d = ModuleDSQLiIndicators()

    # Sonda que aciona MongoServerError apenas no parâmetro NoSQL [$ne]
    nosql_probe = _StubProbeClient(
        lambda m, url, h: SafeProbeResult(
            status_code=500 if "csc_nosql_probe" in url else 200,
            headers={"Content-Type": "application/json"},
            body='{"error": "MongoServerError: unknown operator $ne"}' if "csc_nosql_probe" in url else '{"items": []}',
            elapsed_ms=12,
            url=url,
        )
    )
    res_nosql = mod_d.inspect_response_snapshot(
        target_url="https://api.lab.local/users?user=ana",
        status_code=200,
        headers={"Content-Type": "application/json"},
        body_excerpt='{"items": []}',
        http_client=nosql_probe,
        asset_type=AssetType.REST_API,
    )
    chks = _check_map(res_nosql)
    assert chks["CHK-D05"].status == CheckStatus.VULNERABILITY
    d05_f = _findings_by_check(res_nosql)["CHK-D05"][0]
    assert "CWE-943" in d05_f.cwe_ids

    # Passivo LDAP / XPath limpo vs erro
    res_ldap = mod_d.inspect_response_snapshot(
        target_url="https://app.lab.local/dir",
        status_code=500,
        headers={"Content-Type": "text/html"},
        body_excerpt="javax.naming.NamingException: Invalid DN syntax",
    )
    assert _check_map(res_ldap)["CHK-D05"].status == CheckStatus.POTENTIAL_VULNERABILITY

    clean_probe = _StubProbeClient(
        lambda m, url, h: SafeProbeResult(
            status_code=200,
            headers={"Content-Type": "application/json"},
            body='{"items": []}',
            elapsed_ms=10,
            url=url,
        )
    )
    res_clean = mod_d.inspect_response_snapshot(
        target_url="https://api.lab.local/users?user=ana",
        status_code=200,
        headers={"Content-Type": "application/json"},
        body_excerpt='{"items": []}',
        http_client=clean_probe,
        asset_type=AssetType.REST_API,
    )
    assert _check_map(res_clean)["CHK-D02"].status == CheckStatus.PASSED
    assert _check_map(res_clean)["CHK-D05"].status == CheckStatus.PASSED


def test_module_e_host_prefix_and_chk_e04_entropy_and_deserialization() -> None:
    mod_e = ModuleECookiesAndSession()

    # Cookie Java serializado + cookie __Host- inválido (contém Domain=)
    res_des = mod_e.inspect_response_snapshot(
        target_url="https://app.lab.local/",
        status_code=200,
        headers={},
        raw_set_cookies=[
            "__Host-sid=strongopaquevalue987654321; Secure; HttpOnly; Domain=app.lab.local; Path=/; SameSite=Strict",
            "viewstate=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA; Secure; HttpOnly; SameSite=Strict",
        ],
    )
    chks_des = _check_map(res_des)
    assert chks_des["CHK-E03"].status == CheckStatus.VULNERABILITY
    assert chks_des["CHK-E04"].status == CheckStatus.VULNERABILITY
    e04_f = _findings_by_check(res_des)["CHK-E04"][0]
    assert e04_f.severity == Severity.CRITICAL
    assert "Java Object Serialization" in (e04_f.evidence.observed_value or "")
    assert "rO0ABXNy" not in (e04_f.evidence.observed_value or "")

    # Cookie de sessão numérico/curto sem vazar valor na evidência
    res_low_ent = mod_e.inspect_response_snapshot(
        target_url="https://app.lab.local/",
        status_code=200,
        headers={},
        raw_set_cookies=["sessionid=998877; Secure; HttpOnly; Path=/; SameSite=Strict"],
    )
    chks_low = _check_map(res_low_ent)
    assert chks_low["CHK-E04"].status == CheckStatus.VULNERABILITY
    assert "998877" not in chks_low["CHK-E04"].summary
    assert "998877" not in str(_findings_by_check(res_low_ent)["CHK-E04"][0].evidence.model_dump())

    # Cookies seguros com alta entropia e __Host- válido
    res_ok = mod_e.inspect_response_snapshot(
        target_url="https://app.lab.local/",
        status_code=200,
        headers={},
        raw_set_cookies=["__Host-sessionid=A9fKp2mQz8Lx1VbN7wRc4Yt6; Secure; HttpOnly; Path=/; SameSite=Strict"],
    )
    chks_ok = _check_map(res_ok)
    assert chks_ok["CHK-E03"].status == CheckStatus.PASSED
    assert chks_ok["CHK-E04"].status == CheckStatus.PASSED


def test_module_f_chk_f05_web_cache_poisoning() -> None:
    mod_f = ModuleFDoSResiliencePosture()

    poisoned_probe = _StubProbeClient(
        lambda m, url, h: SafeProbeResult(
            status_code=200,
            headers={"Cache-Control": "public, max-age=300", "X-Cache": "HIT"},
            body=f'<link rel="canonical" href="https://{(h or {}).get("X-Forwarded-Host", "app.lab.local")}/home">',
            elapsed_ms=15,
            url=url,
        )
    )
    res_vuln = mod_f.inspect_response_snapshot(
        target_url="https://app.lab.local/home",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body_excerpt="<html><body>Home</body></html>",
        http_client=poisoned_probe,
    )
    chks_v = _check_map(res_vuln)
    assert chks_v["CHK-F05"].status == CheckStatus.VULNERABILITY
    assert _findings_by_check(res_vuln)["CHK-F05"][0].severity == Severity.HIGH

    clean_probe = _StubProbeClient(
        lambda m, url, h: SafeProbeResult(
            status_code=200,
            headers={"Content-Type": "text/html"},
            body='<link rel="canonical" href="https://app.lab.local/home">',
            elapsed_ms=12,
            url=url,
        )
    )
    res_ok = mod_f.inspect_response_snapshot(
        target_url="https://app.lab.local/home",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body_excerpt="<html><body>Home</body></html>",
        http_client=clean_probe,
    )
    assert _check_map(res_ok)["CHK-F05"].status == CheckStatus.PASSED


def test_module_g_jwt_hmac_jku_chk_g06_bopla_and_chk_g07_graphql() -> None:
    mod_g = ModuleGAPISecurity()

    # 1. JWT HS256 assinado com segredo fraco "secret" + payload BOPLA + GraphQL introspection via sonda
    weak_jwt = _build_hs256_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "u1", "exp": 9999999999}, "secret")
    gql_probe = _StubProbeClient(
        lambda m, url, h: SafeProbeResult(
            status_code=200 if "__schema" in url else 404,
            headers={"Content-Type": "application/json"},
            body='{"data":{"__schema":{"queryType":{"name":"Query"}}}}' if "__schema" in url else "",
            elapsed_ms=10,
            url=url,
        )
    )
    res_g = mod_g.inspect_response_snapshot(
        target_url="https://api.lab.local/v1/profile",
        status_code=200,
        headers={"Content-Type": "application/json", "Cache-Control": "public, max-age=60"},
        body_excerpt=json.dumps({
            "access_token": weak_jwt,
            "user": {"email": "a@b.c", "password_hash": "$2b$12$abcdef", "totp_secret": "JBSWY3DPEHPK3PXP"},
        }),
        asset_type=AssetType.REST_API,
        http_client=gql_probe,
    )
    chks_g = _check_map(res_g)
    assert chks_g["CHK-G03"].status == CheckStatus.VULNERABILITY
    assert chks_g["CHK-G05"].status == CheckStatus.VULNERABILITY
    assert _findings_by_check(res_g)["CHK-G05"][0].severity == Severity.CRITICAL
    assert weak_jwt not in _findings_by_check(res_g)["CHK-G05"][0].evidence.observed_value
    assert chks_g["CHK-G06"].status == CheckStatus.VULNERABILITY
    assert "CWE-213" in _findings_by_check(res_g)["CHK-G06"][0].cwe_ids
    assert chks_g["CHK-G07"].status == CheckStatus.VULNERABILITY

    # 2. JWT com header jku perigoso
    jku_jwt = _build_hs256_jwt(
        {"alg": "RS256", "jku": "https://attacker.invalid/jwks.json"},
        {"sub": "u1", "exp": 9999999999},
        "not_checked",
    )
    res_jku = mod_g.inspect_response_snapshot(
        target_url="https://api.lab.local/v1/auth",
        status_code=200,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {jku_jwt}"},
        body_excerpt='{"ok": true}',
        asset_type=AssetType.REST_API,
    )
    assert _check_map(res_jku)["CHK-G05"].status == CheckStatus.VULNERABILITY

    # 3. Anti-FP BOPLA em OpenAPI schema document e GraphQL limpo
    clean_g_probe = _StubProbeClient(
        lambda m, url, h: SafeProbeResult(status_code=404, headers={}, body="Not Found", elapsed_ms=5, url=url)
    )
    res_g_clean = mod_g.inspect_response_snapshot(
        target_url="https://api.lab.local/openapi.json",
        status_code=200,
        headers={"Content-Type": "application/json"},
        body_excerpt='{"openapi":"3.0.0","components":{"schemas":{"U":{"properties":{"password_hash":{"type":"string"}}}}}}',
        asset_type=AssetType.REST_API,
        http_client=clean_g_probe,
    )
    assert _check_map(res_g_clean)["CHK-G06"].status == CheckStatus.PASSED
    assert _check_map(res_g_clean)["CHK-G07"].status == CheckStatus.PASSED


def test_module_h_soft404_open_redirect_host_injection_and_sourcemaps() -> None:
    mod_h = ModuleHMisconfigAndOther()

    # 1. Soft-404 HTML em /.env e /Dockerfile NÃO deve gerar falso positivo; mas SourceMap .js.map real + Host Header Injection devem!
    def _h_handler(method: str, url: str, hdrs: dict[str, str] | None) -> SafeProbeResult:
        if hdrs and "X-Forwarded-Host" in hdrs:
            return SafeProbeResult(
                status_code=302,
                headers={"Location": f"https://{hdrs['X-Forwarded-Host']}/reset-password"},
                body="",
                elapsed_ms=8,
                url=url,
            )
        if url.endswith("/static/app.js.map"):
            return SafeProbeResult(
                status_code=200,
                headers={"Content-Type": "application/json"},
                body='{"version":3,"sources":["webpack:///src/auth.ts"]}',
                elapsed_ms=8,
                url=url,
            )
        if "/redirect?next=" in url and (
            "//canary.csc-redirect.internal" in url or "%2F%2Fcanary.csc-redirect.internal" in url
        ):
            return SafeProbeResult(
                status_code=302,
                headers={"Location": "//canary.csc-redirect.internal"},
                body="",
                elapsed_ms=8,
                url=url,
            )
        # SPA Soft-404 retornando HTML 200 com string enganosa
        return SafeProbeResult(
            status_code=200,
            headers={"Content-Type": "text/html"},
            body="<!doctype html><html><body>SPA App SECRET_KEY=demo FROM fake</body></html>",
            elapsed_ms=8,
            url=url,
        )

    probe_h = _StubProbeClient(_h_handler)
    res_h = mod_h.inspect_response_snapshot(
        target_url="https://app.lab.local/redirect?next=%2Fhome",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body_excerpt="<html><script>/* //# sourceMappingURL=/static/app.js.map */</script></html>",
        http_client=probe_h,
    )
    chks_h = _check_map(res_h)
    assert chks_h["CHK-H01"].status == CheckStatus.PASSED
    assert chks_h["CHK-H03"].status == CheckStatus.VULNERABILITY
    assert chks_h["CHK-H08"].status == CheckStatus.VULNERABILITY
    assert "CWE-644" in _findings_by_check(res_h)["CHK-H08"][0].cwe_ids
    assert chks_h["CHK-H09"].status == CheckStatus.POTENTIAL_VULNERABILITY
    assert "CWE-540" in _findings_by_check(res_h)["CHK-H09"][0].cwe_ids

    # 2. Alvo H completamente limpo (sem sourcemaps, sem Dockerfile, sem Host header injection)
    clean_h_probe = _StubProbeClient(
        lambda m, url, h: SafeProbeResult(status_code=404, headers={}, body="Not Found", elapsed_ms=5, url=url)
    )
    res_h_ok = mod_h.inspect_response_snapshot(
        target_url="https://app.lab.local/",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body_excerpt="<html><body>Clean page</body></html>",
        http_client=clean_h_probe,
    )
    chks_h_ok = _check_map(res_h_ok)
    assert chks_h_ok["CHK-H01"].status == CheckStatus.PASSED
    assert chks_h_ok["CHK-H03"].status == CheckStatus.PASSED
    assert chks_h_ok["CHK-H08"].status == CheckStatus.PASSED
    assert chks_h_ok["CHK-H09"].status == CheckStatus.PASSED
