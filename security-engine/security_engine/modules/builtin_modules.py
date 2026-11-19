"""Módulos de auditoria de segurança (Módulos A a H - Seção 6) com inspeção determinística real."""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import ipaddress
import json
import re
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qs, unquote, urlencode, urljoin, urlparse, urlunparse

from security_engine.core.contracts import (
    AssetType,
    BaseSecurityModule,
    CheckEvaluationResult,
    CheckStatus,
    Confidence,
    ImpactLevel,
    ModuleExecutionResult,
    ModuleMetadata,
    NormalizedFinding,
    SanitizedEvidence,
    Severity,
)
from security_engine.core.evidence import EvidenceManager
from security_engine.core.remediation import RemediationEngine
from security_engine.core.risk import RiskEngine

VERSION_REGEX = re.compile(r"\b\d+\.\d+(?:\.\d+)?\b")
STACK_TRACE_PATTERNS = [
    re.compile(r"Traceback \(most recent call last\):", re.IGNORECASE),
    re.compile(r"java\.lang\.[A-Za-z0-9_]+Exception", re.IGNORECASE),
    re.compile(r"Fatal error:\s+Uncaught", re.IGNORECASE),
    re.compile(r"SQLSTATE\[[0-9A-Z]+\]", re.IGNORECASE),
    re.compile(r"Werkzeug Debugger", re.IGNORECASE),
    re.compile(r"ReferenceError:\s+[A-Za-z0-9_]+\s+is not defined", re.IGNORECASE),
    re.compile(r"at\s+System\.[A-Za-z0-9_.]+\(", re.IGNORECASE),
    re.compile(r"You're seeing this error because you have\s+(?:<code>)?DEBUG\s*=\s*True", re.IGNORECASE),
    re.compile(r"Symfony\\Component\\HttpKernel", re.IGNORECASE),
    re.compile(r"Whitelabel Error Page", re.IGNORECASE),
    re.compile(r"\bat Object\.<anonymous>", re.IGNORECASE),
    re.compile(r"Server Error in '/' Application", re.IGNORECASE),
    re.compile(r"goroutine \d+ \[running\]:|panic: runtime error:", re.IGNORECASE),
    re.compile(r"ActionController::RoutingError", re.IGNORECASE),
]
SAFE_REFERRER_POLICIES = {
    "no-referrer",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "origin-when-cross-origin",
    "origin",
}
ALL_REFERRER_POLICIES = SAFE_REFERRER_POLICIES | {
    "no-referrer-when-downgrade",
    "unsafe-url",
}
WEAK_TLS_CIPHERS_REGEX = re.compile(
    r"(?:^|[-_.\s])(?:RC4|3DES|DES|NULL|EXPORT|EXP|MD5|ADH|AECDH)(?:$|[-_.\s])",
    re.IGNORECASE,
)
PHP_SERIALIZED_COOKIE_REGEX = re.compile(r'^(?:O|a):\d+:(?:\{|")')


def _extract_html_input_names(body: str) -> list[str]:
    """Extrai nomes únicos de parâmetros de formulários HTML (<input> e <textarea>)."""
    if not body:
        return []
    found = re.findall(
        r"<(?:input|textarea|select)\b[^>]*\bname=[\"']?([a-zA-Z0-9_.-]{1,64})[\"']?",
        body,
        re.IGNORECASE,
    )
    unique: list[str] = []
    for name in found:
        if name not in unique and name.lower() not in {"csrf_token", "csrfmiddlewaretoken", "_csrf"}:
            unique.append(name)
    return unique


def _is_soft_404_html(probe_body: str, baseline_body: str = "") -> bool:
    """Identifica respostas HTML de fallback SPA (Soft-404) retornadas com HTTP 200."""
    stripped = (probe_body or "").lstrip()
    if stripped.lower().startswith(("<!doctype html", "<html")):
        return True
    return bool(baseline_body and len(baseline_body.strip()) > 32 and stripped == baseline_body.lstrip())


def _safe_probe_headers(probe_res: Any) -> dict[str, str]:
    """Extrai dicionário de cabeçalhos em minúsculas com segurança contra mocks."""
    raw_headers = getattr(probe_res, "headers", None)
    if isinstance(raw_headers, dict):
        return {str(k).lower(): str(v) for k, v in raw_headers.items()}
    return {}


def _finalize_module_result(
    module_id: str,
    checks: list[CheckEvaluationResult],
    findings: list[NormalizedFinding],
    total_requests: int,
) -> ModuleExecutionResult:
    """Consolida resultado do módulo garantindo validação de consistência, CVSS v4.0 e sanitização."""
    validated_findings = [RiskEngine.validate_finding_consistency(f) for f in findings]
    exec_errors = sum(1 for c in checks if c.status == CheckStatus.EXECUTION_ERROR)
    return ModuleExecutionResult(
        module_id=module_id,
        checks=checks,
        findings=validated_findings,
        total_requests=total_requests,
        execution_errors=exec_errors,
    )


def _detect_cookie_deserialization(raw_value: str) -> str | None:
    """Inspeciona em memória apenas assinaturas conhecidas de serialização insegura sem persistir o valor."""
    decoded = unquote(raw_value or "").strip()
    if not decoded:
        return None
    if decoded.startswith("rO0AB"):
        return "Java Object Serialization (Base64 rO0AB)"
    if decoded.startswith(("gASV", "gAJ")):
        return "Python Pickle Serialization (Base64)"
    if PHP_SERIALIZED_COOKIE_REGEX.match(decoded):
        return "PHP Object Serialization"
    return None


def _parse_cookie_attributes(raw_cookie: str) -> dict[str, Any]:
    """Extrai nome e atributos estruturados de um cabeçalho Set-Cookie sem expor o valor secreto."""
    parts = [p.strip() for p in raw_cookie.split(";") if p.strip()]
    if not parts:
        return {
            "name": "unknown",
            "sanitized": "[REDACTED_COOKIE]",
            "secure": False,
            "httponly": False,
            "samesite": None,
            "domain": None,
            "path": None,
            "max_age": None,
            "expires": None,
            "value_len": 0,
            "is_numeric_value": False,
            "deserialization_kind": None,
        }

    first = parts[0]
    if "=" in first:
        cookie_name, cookie_val = first.split("=", 1)
        cookie_name = cookie_name.strip()
        clean_val = cookie_val.strip()
    else:
        cookie_name = first.strip()
        clean_val = ""

    attrs: dict[str, Any] = {
        "name": cookie_name or "unnamed",
        "sanitized": EvidenceManager.sanitize_set_cookie_header(raw_cookie),
        "secure": False,
        "httponly": False,
        "samesite": None,
        "domain": None,
        "path": None,
        "max_age": None,
        "expires": None,
        "value_len": len(clean_val),
        "is_numeric_value": clean_val.isdigit() if clean_val else False,
        "deserialization_kind": _detect_cookie_deserialization(clean_val),
    }
    for attr in parts[1:]:
        lower_attr = attr.lower()
        if lower_attr == "secure":
            attrs["secure"] = True
        elif lower_attr == "httponly":
            attrs["httponly"] = True
        elif lower_attr.startswith("samesite="):
            attrs["samesite"] = attr.split("=", 1)[1].strip().lower()
        elif lower_attr.startswith("domain="):
            attrs["domain"] = attr.split("=", 1)[1].strip().lower()
        elif lower_attr.startswith("path="):
            attrs["path"] = attr.split("=", 1)[1].strip()
        elif lower_attr.startswith("max-age="):
            raw_age = attr.split("=", 1)[1].strip()
            try:
                attrs["max_age"] = int(raw_age)
            except ValueError:
                attrs["max_age"] = None
        elif lower_attr.startswith("expires="):
            attrs["expires"] = attr.split("=", 1)[1].strip()
    return attrs


class ModuleAReconHeadersTLS(BaseSecurityModule):
    """MÓDULO A — Reconhecimento, TLS, HTTPS, Security Headers e Exposição de Informação."""

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            module_id="mod_a_recon_headers_tls",
            code="MÓDULO A",
            name="Reconhecimento e Configuração de Segurança (HTTPS, TLS, Headers, DNS)",
            version="1.1.0",
            description=(
                "Verifica disponibilidade HTTP/HTTPS, cadeia de redirecionamentos, validade de certificados "
                "e protocolos TLS, Security Headers com análise contextual (CSP, HSTS, X-Frame-Options, "
                "X-Content-Type-Options, Referrer-Policy, Permissions-Policy) e exposição de informações "
                "em cabeçalhos e corpos de resposta."
            ),
            category="Configuração de Segurança e Criptografia",
            impact_level=ImpactLevel.PASSIVE,
            supported_asset_types=[
                AssetType.WEB_APP,
                AssetType.REST_API,
                AssetType.GRAPHQL_API,
                AssetType.DOMAIN,
            ],
            owasp_references=[
                "A02:2021-Cryptographic Failures",
                "A05:2021-Security Misconfiguration",
                "A08:2021-Software and Data Integrity Failures",
            ],
            wstg_references=["WSTG-CONF-07", "WSTG-INFO-02", "WSTG-CRYP-01"],
            asvs_references=["ASVS-V9.1", "ASVS-V9.2", "ASVS-V14.4"],
            cwe_references=[
                "CWE-319",
                "CWE-693",
                "CWE-1021",
                "CWE-200",
                "CWE-295",
                "CWE-298",
                "CWE-345",
                "CWE-353",
            ],
            enabled_by_default=True,
            requires_authentication=False,
            allow_in_production=True,
            checks_catalog=[
                "CHK-A01: Uso de HTTPS e Redirecionamento Seguro",
                "CHK-A02: Cabeçalho Strict-Transport-Security (HSTS)",
                "CHK-A03: Cabeçalho Content-Security-Policy (CSP)",
                "CHK-A04: Cabeçalho X-Content-Type-Options (nosniff)",
                "CHK-A05: Proteção contra Clickjacking (X-Frame-Options / frame-ancestors)",
                "CHK-A06: Cabeçalhos Referrer-Policy e Permissions-Policy",
                "CHK-A07: Exposição de Versão em Server / X-Powered-By",
                "CHK-A08: Exposição de Stack Trace ou Erros Verbosos no Corpo HTTP",
                "CHK-A09: Validade e Expiração do Certificado TLS",
                "CHK-A10: Cadeia de Confiança TLS e Correspondência de Hostname",
                "CHK-A11: Versão Negociada do Protocolo TLS",
                "CHK-A12: Registros de Autenticação de E-mail (SPF e DMARC)",
                "CHK-A13: Subresource Integrity (SRI) e Isolamento Cross-Origin",
            ],
        )

    def inspect_response_snapshot(
        self,
        target_url: str,
        status_code: int,
        headers: dict[str, str],
        cookies: list[dict[str, Any]] | None = None,
        tls_info: dict[str, Any] | None = None,
        body_excerpt: str = "",
        is_Canceled: Callable[[], bool] | None = None,
        *,
        asset_type: AssetType = AssetType.WEB_APP,
        redirect_chain: list[dict[str, Any]] | None = None,
        raw_set_cookies: list[str] | None = None,
        http_to_https_redirected: bool | None = None,
        initial_url: str | None = None,
        http_client: Any | None = None,
        dns_txt_resolver: Callable[[str], list[str]] | None = None,
    ) -> ModuleExecutionResult:
        checks: list[CheckEvaluationResult] = []
        findings: list[NormalizedFinding] = []
        parsed = urlparse(target_url)
        hostname = parsed.hostname or "unknown"
        scheme = parsed.scheme.lower()
        lower_headers = {k.lower(): v for k, v in headers.items()}
        content_type = lower_headers.get("content-type", "").lower()
        is_pure_api_context = (
            asset_type in {AssetType.REST_API, AssetType.GRAPHQL_API}
            and "text/html" not in content_type
        )

        if is_Canceled and is_Canceled():
            return ModuleExecutionResult(module_id=self.metadata.module_id)

        # Se status_code == 0, houve falha operacional de transporte HTTP
        if status_code <= 0:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-A01",
                    module_id=self.metadata.module_id,
                    title="Disponibilidade HTTP/HTTPS e Redirecionamento Seguro",
                    status=CheckStatus.EXECUTION_ERROR,
                    summary="Falha técnica ao obter resposta HTTP do alvo (status_code=0).",
                    details={"target_url": target_url},
                )
            )
            return ModuleExecutionResult(
                module_id=self.metadata.module_id,
                checks=checks,
                findings=findings,
                total_requests=1,
                execution_errors=1,
            )

        # CHK-A01: Uso de HTTPS e Cadeia de Redirecionamentos
        hops = redirect_chain or []
        has_downgrade = any(bool(h.get("scheme_downgraded")) for h in hops)
        if scheme != "https" or has_downgrade:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-A01",
                    module_id=self.metadata.module_id,
                    title="Uso de HTTPS e Redirecionamento Seguro",
                    status=CheckStatus.VULNERABILITY,
                    summary=(
                        f"Alvo responde sobre HTTP não criptografado (status {status_code}) "
                        "sem redirecionar para HTTPS."
                    ),
                    details={"final_url": target_url, "redirect_hops": len(hops)},
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-A01",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-A01", target_url
                    ),
                    title="Comunicação HTTP sem criptografia TLS (Ausência de HTTPS)",
                    description=(
                        "O ativo atende requisições diretamente sobre HTTP em texto claro ou realiza "
                        "downgrade de protocolo, expondo dados e sessões em trânsito."
                    ),
                    category=self.metadata.category,
                    result_classification=CheckStatus.VULNERABILITY,
                    severity=Severity.HIGH,
                    confidence=Confidence.CERTAIN,
                    evidence=EvidenceManager.build_sanitized_evidence(
                        request_method="GET",
                        request_url=initial_url or target_url,
                        response_status_code=status_code,
                        response_headers=headers,
                        observed_value=f"Esquema final '{scheme}://' em {target_url} (hops={len(hops)})",
                        expected_baseline="Redirecionamento 301/308 obrigatório para https://",
                    ),
                    owasp_references=["A02:2021-Cryptographic Failures"],
                    cwe_ids=["CWE-319"],
                    impact="Interceptação e adulteração de tráfego em trânsito (Man-in-the-Middle).",
                    safe_reproduction_steps=[
                        f"Acessar {initial_url or target_url} e observar que a resposta final permanece em HTTP."
                    ],
                    remediation=RemediationEngine.get_guidance("cleartext_http_transport"),
                )
            )
        elif http_to_https_redirected is False:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-A01",
                    module_id=self.metadata.module_id,
                    title="Uso de HTTPS e Redirecionamento Seguro",
                    status=CheckStatus.POTENTIAL_VULNERABILITY,
                    summary="Alvo usa HTTPS, mas a sonda HTTP auxiliar não observou redirecionamento automático.",
                    details={"final_url": target_url, "redirect_hops": len(hops)},
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-A01",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-A01", target_url, "no-http-redirect"
                    ),
                    title="Ausência de redirecionamento automático de HTTP para HTTPS",
                    description="O endpoint HTTP associado não redirecionou automaticamente para HTTPS.",
                    category=self.metadata.category,
                    result_classification=CheckStatus.POTENTIAL_VULNERABILITY,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.FIRM,
                    evidence=EvidenceManager.build_sanitized_evidence(
                        request_method="GET",
                        request_url=target_url,
                        response_status_code=status_code,
                        response_headers=headers,
                        observed_value="http_to_https_redirected=False",
                        expected_baseline="HTTP 301/308 -> https://",
                    ),
                    owasp_references=["A02:2021-Cryptographic Failures"],
                    cwe_ids=["CWE-319"],
                    impact="Usuários que digitarem o endereço sem https:// podem acessar versão não criptografada.",
                    safe_reproduction_steps=[f"Testar requisição HTTP para {hostname} e verificar ausência de 301/308."],
                    remediation=RemediationEngine.get_guidance("cleartext_http_transport"),
                )
            )
        else:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-A01",
                    module_id=self.metadata.module_id,
                    title="Uso de HTTPS e Redirecionamento Seguro",
                    status=CheckStatus.PASSED,
                    summary=f"Transporte HTTPS ativo (HTTP {status_code}, {len(hops)} redirecionamento(s)).",
                    details={"final_url": target_url, "redirect_hops": len(hops)},
                )
            )

        # CHK-A02: HSTS
        hsts_val = lower_headers.get("strict-transport-security")
        if scheme == "https":
            if not hsts_val or "max-age=" not in hsts_val.lower():
                checks.append(
                    CheckEvaluationResult(
                        check_id="CHK-A02",
                        module_id=self.metadata.module_id,
                        title="Cabeçalho Strict-Transport-Security (HSTS)",
                        status=CheckStatus.VULNERABILITY,
                        summary="Cabeçalho HSTS ausente na resposta HTTPS.",
                    )
                )
                findings.append(
                    NormalizedFinding(
                        endpoint=target_url,
                        module_id=self.metadata.module_id,
                        check_id="CHK-A02",
                        fingerprint=RiskEngine.compute_finding_fingerprint(
                            hostname, self.metadata.module_id, "CHK-A02", target_url
                        ),
                        title="Ausência do cabeçalho HTTP Strict-Transport-Security (HSTS)",
                        description=(
                            "O endpoint HTTPS não retornou o cabeçalho Strict-Transport-Security, "
                            "permitindo que navegadores tentem conexões HTTP iniciais desprotegidas."
                        ),
                        category=self.metadata.category,
                        result_classification=CheckStatus.VULNERABILITY,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.CERTAIN,
                        evidence=EvidenceManager.build_sanitized_evidence(
                            request_method="GET",
                            request_url=target_url,
                            response_status_code=status_code,
                            response_headers=headers,
                            observed_value=hsts_val or "Header ausente",
                            expected_baseline="Strict-Transport-Security: max-age=31536000; includeSubDomains",
                        ),
                        owasp_references=["A05:2021-Security Misconfiguration"],
                        cwe_ids=["CWE-319"],
                        impact="Exposição a ataques de downgrade/SSL Stripping na primeira conexão do cliente.",
                        safe_reproduction_steps=[
                            f"Realizar requisição GET para {target_url}",
                            "Inspecionar os cabeçalhos HTTP da resposta e verificar ausência de 'Strict-Transport-Security'.",
                        ],
                        remediation=RemediationEngine.get_guidance("missing_hsts"),
                    )
                )
            else:
                max_age_match = re.search(r"max-age\s*=\s*(\d+)", hsts_val, re.IGNORECASE)
                max_age_val = int(max_age_match.group(1)) if max_age_match else 0
                lower_hsts = hsts_val.lower()
                if max_age_val == 0:
                    checks.append(
                        CheckEvaluationResult(
                            check_id="CHK-A02",
                            module_id=self.metadata.module_id,
                            title="Cabeçalho Strict-Transport-Security (HSTS)",
                            status=CheckStatus.VULNERABILITY,
                            summary="Cabeçalho HSTS com max-age=0 revoga a proteção HTTPS obrigatória no navegador.",
                        )
                    )
                    findings.append(
                        NormalizedFinding(
                            endpoint=target_url,
                            module_id=self.metadata.module_id,
                            check_id="CHK-A02",
                            fingerprint=RiskEngine.compute_finding_fingerprint(
                                hostname, self.metadata.module_id, "CHK-A02", target_url, "hsts-max-age-zero"
                            ),
                            title="Cabeçalho HSTS desativado explicitamente (max-age=0)",
                            description=(
                                "O cabeçalho Strict-Transport-Security define max-age=0, instruindo navegadores "
                                "a removerem imediatamente o domínio do cache HSTS."
                            ),
                            category=self.metadata.category,
                            result_classification=CheckStatus.VULNERABILITY,
                            severity=Severity.MEDIUM,
                            confidence=Confidence.CERTAIN,
                            evidence=EvidenceManager.build_sanitized_evidence(
                                request_method="GET",
                                request_url=target_url,
                                response_status_code=status_code,
                                response_headers=headers,
                                observed_value=hsts_val,
                                expected_baseline="Strict-Transport-Security: max-age=31536000; includeSubDomains",
                            ),
                            owasp_references=["A05:2021-Security Misconfiguration"],
                            cwe_ids=["CWE-319"],
                            impact="Exposição a ataques de downgrade/SSL Stripping em conexões subsequentes.",
                            safe_reproduction_steps=[f"Verificar diretiva max-age do header HSTS em {target_url}."],
                            remediation=RemediationEngine.get_guidance("missing_hsts"),
                        )
                    )
                elif max_age_val < 31536000 or ("preload" in lower_hsts and "includesubdomains" not in lower_hsts):
                    hsts_reason = (
                        f"HSTS presente, mas max-age={max_age_val} é inferior a 1 ano (31536000s)."
                        if max_age_val < 31536000
                        else "HSTS com 'preload' exige a diretiva 'includeSubDomains'."
                    )
                    checks.append(
                        CheckEvaluationResult(
                            check_id="CHK-A02",
                            module_id=self.metadata.module_id,
                            title="Cabeçalho Strict-Transport-Security (HSTS)",
                            status=CheckStatus.POTENTIAL_VULNERABILITY,
                            summary=hsts_reason,
                        )
                    )
                    findings.append(
                        NormalizedFinding(
                            endpoint=target_url,
                            module_id=self.metadata.module_id,
                            check_id="CHK-A02",
                            fingerprint=RiskEngine.compute_finding_fingerprint(
                                hostname, self.metadata.module_id, "CHK-A02", target_url, "weak-max-age"
                            ),
                            title="Cabeçalho HSTS configurado com parâmetros insuficientes",
                            description=hsts_reason,
                            category=self.metadata.category,
                            result_classification=CheckStatus.POTENTIAL_VULNERABILITY,
                            severity=Severity.LOW,
                            confidence=Confidence.CERTAIN,
                            evidence=EvidenceManager.build_sanitized_evidence(
                                request_method="GET",
                                request_url=target_url,
                                response_status_code=status_code,
                                response_headers=headers,
                                observed_value=hsts_val,
                                expected_baseline="Strict-Transport-Security: max-age=31536000; includeSubDomains",
                            ),
                            owasp_references=["A05:2021-Security Misconfiguration"],
                            cwe_ids=["CWE-319"],
                            impact="Janela reduzida ou cobertura incompleta de proteção HSTS no navegador.",
                            safe_reproduction_steps=[f"Verificar diretivas do header HSTS em {target_url}."],
                            remediation=RemediationEngine.get_guidance("missing_hsts"),
                        )
                    )
                else:
                    checks.append(
                        CheckEvaluationResult(
                            check_id="CHK-A02",
                            module_id=self.metadata.module_id,
                            title="Cabeçalho Strict-Transport-Security (HSTS)",
                            status=CheckStatus.PASSED,
                            summary=f"HSTS presente e robusto: {hsts_val}",
                        )
                    )
        else:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-A02",
                    module_id=self.metadata.module_id,
                    title="Cabeçalho Strict-Transport-Security (HSTS)",
                    status=CheckStatus.NOT_APPLICABLE,
                    summary="Alvo acessado via HTTP puro (HSTS só é processado por navegadores sobre HTTPS).",
                )
            )

        # CHK-A03: CSP (com avaliação de diretivas e contexto de ativo Web vs API)
        csp_val = lower_headers.get("content-security-policy")
        csp_report_only_val = lower_headers.get("content-security-policy-report-only")
        if not csp_val:
            if is_pure_api_context:
                checks.append(
                    CheckEvaluationResult(
                        check_id="CHK-A03",
                        module_id=self.metadata.module_id,
                        title="Cabeçalho Content-Security-Policy (CSP)",
                        status=CheckStatus.NOT_APPLICABLE,
                        summary=(
                            f"Ativo do tipo {asset_type.value} retornando {content_type or 'JSON/API'} "
                            "(CSP aplica-se primariamente a documentos HTML renderizados no navegador)."
                        ),
                    )
                )
            else:
                csp_missing_summary = (
                    "Apenas Content-Security-Policy-Report-Only presente (modo não bloqueante); cabeçalho Content-Security-Policy obrigatório ausente."
                    if csp_report_only_val
                    else "Cabeçalho Content-Security-Policy ausente."
                )
                checks.append(
                    CheckEvaluationResult(
                        check_id="CHK-A03",
                        module_id=self.metadata.module_id,
                        title="Cabeçalho Content-Security-Policy (CSP)",
                        status=CheckStatus.VULNERABILITY,
                        summary=csp_missing_summary,
                    )
                )
                findings.append(
                    NormalizedFinding(
                        endpoint=target_url,
                        module_id=self.metadata.module_id,
                        check_id="CHK-A03",
                        fingerprint=RiskEngine.compute_finding_fingerprint(
                            hostname, self.metadata.module_id, "CHK-A03", target_url
                        ),
                        title="Ausência de Content-Security-Policy (CSP)",
                        description=(
                            "A aplicação define apenas Content-Security-Policy-Report-Only (não bloqueante) sem política ativa."
                            if csp_report_only_val
                            else "A aplicação não define o cabeçalho Content-Security-Policy para restringir origens de scripts e recursos."
                        ),
                        category=self.metadata.category,
                        result_classification=CheckStatus.VULNERABILITY,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.CERTAIN,
                        evidence=EvidenceManager.build_sanitized_evidence(
                            request_method="GET",
                            request_url=target_url,
                            response_status_code=status_code,
                            response_headers=headers,
                            observed_value=(
                                f"Report-Only ativo sem CSP bloqueante: {csp_report_only_val}"
                                if csp_report_only_val
                                else "Header Content-Security-Policy ausente"
                            ),
                            expected_baseline="default-src 'self'; object-src 'none'; frame-ancestors 'none'",
                            technical_notes=(
                                ["Content-Security-Policy-Report-Only apenas notifica violações sem bloquear execução de scripts."]
                                if csp_report_only_val
                                else []
                            ),
                        ),
                        owasp_references=["A05:2021-Security Misconfiguration"],
                        cwe_ids=["CWE-693"],
                        impact="Redução da mitigação em profundidade contra execução de scripts não autorizados (XSS).",
                        safe_reproduction_steps=[
                            f"Enviar requisição GET para {target_url}",
                            "Confirmar ausência do cabeçalho 'Content-Security-Policy' na resposta.",
                        ],
                        remediation=RemediationEngine.get_guidance("missing_csp"),
                    )
                )
        else:
            lower_csp = csp_val.lower()
            has_nonce_or_hash = "'nonce-" in lower_csp or "'sha256-" in lower_csp or "'sha384-" in lower_csp
            weak_tokens: list[str] = []
            if "'unsafe-eval'" in lower_csp:
                weak_tokens.append("'unsafe-eval'")
            if "'unsafe-inline'" in lower_csp and not has_nonce_or_hash:
                weak_tokens.append("'unsafe-inline'")
            for directive_match in re.finditer(r"(?:^|;)\s*(?:default-src|script-src)\s+([^;]+)", lower_csp):
                directive_vals = directive_match.group(1)
                if re.search(r"(?:^|\s)\*(?=\s|$)", directive_vals) and "wildcard '*'" not in weak_tokens:
                    weak_tokens.append("wildcard '*'")
                if re.search(r"(?:^|\s)(?:https?|data|blob):(?=\s|$)", directive_vals):
                    perm_scheme_label = "esquema permissivo (http:/https:/data:/blob:)"
                    if perm_scheme_label not in weak_tokens:
                        weak_tokens.append(perm_scheme_label)

            if weak_tokens:
                checks.append(
                    CheckEvaluationResult(
                        check_id="CHK-A03",
                        module_id=self.metadata.module_id,
                        title="Cabeçalho Content-Security-Policy (CSP)",
                        status=CheckStatus.POTENTIAL_VULNERABILITY,
                        summary=f"CSP presente, mas contém diretivas permissivas: {', '.join(weak_tokens)}.",
                    )
                )
                findings.append(
                    NormalizedFinding(
                        endpoint=target_url,
                        module_id=self.metadata.module_id,
                        check_id="CHK-A03",
                        fingerprint=RiskEngine.compute_finding_fingerprint(
                            hostname, self.metadata.module_id, "CHK-A03", target_url, ",".join(weak_tokens)
                        ),
                        title=f"Política Content-Security-Policy permissiva ({', '.join(weak_tokens)})",
                        description=(
                            f"O cabeçalho Content-Security-Policy foi detectado, porém inclui {', '.join(weak_tokens)}, "
                            "enfraquecendo a proteção contra execução de scripts injetados."
                        ),
                        category=self.metadata.category,
                        result_classification=CheckStatus.POTENTIAL_VULNERABILITY,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.CERTAIN,
                        evidence=EvidenceManager.build_sanitized_evidence(
                            request_method="GET",
                            request_url=target_url,
                            response_status_code=status_code,
                            response_headers=headers,
                            observed_value=csp_val,
                            expected_baseline="default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'",
                        ),
                        owasp_references=["A05:2021-Security Misconfiguration"],
                        cwe_ids=["CWE-693"],
                        impact="Possibilidade de contorno da política CSP em caso de injeção HTML/JavaScript.",
                        safe_reproduction_steps=[f"Analisar as diretivas do cabeçalho Content-Security-Policy em {target_url}."],
                        remediation=RemediationEngine.get_guidance("weak_csp_directives"),
                    )
                )
            else:
                checks.append(
                    CheckEvaluationResult(
                        check_id="CHK-A03",
                        module_id=self.metadata.module_id,
                        title="Cabeçalho Content-Security-Policy (CSP)",
                        status=CheckStatus.PASSED,
                        summary="Cabeçalho Content-Security-Policy presente e sem diretivas inseguras óbvias.",
                    )
                )

        # CHK-A04: X-Content-Type-Options
        xcto_val = lower_headers.get("x-content-type-options", "").strip().lower()
        if xcto_val != "nosniff":
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-A04",
                    module_id=self.metadata.module_id,
                    title="Cabeçalho X-Content-Type-Options",
                    status=CheckStatus.VULNERABILITY,
                    summary="Cabeçalho X-Content-Type-Options: nosniff ausente.",
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-A04",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-A04", target_url
                    ),
                    title="Ausência do cabeçalho X-Content-Type-Options: nosniff",
                    description="O servidor não instrui o navegador a desabilitar MIME-sniffing.",
                    category=self.metadata.category,
                    result_classification=CheckStatus.VULNERABILITY,
                    severity=Severity.LOW,
                    confidence=Confidence.CERTAIN,
                    evidence=EvidenceManager.build_sanitized_evidence(
                        request_method="GET",
                        request_url=target_url,
                        response_status_code=status_code,
                        response_headers=headers,
                        observed_value=xcto_val or "Header ausente",
                        expected_baseline="nosniff",
                    ),
                    owasp_references=["A05:2021-Security Misconfiguration"],
                    cwe_ids=["CWE-16"],
                    impact="Possibilidade de interpretação incorreta de tipos MIME pelo navegador.",
                    safe_reproduction_steps=[f"Inspecionar resposta HTTP de {target_url}."],
                    remediation=RemediationEngine.get_guidance("missing_x_content_type_options"),
                )
            )
        else:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-A04",
                    module_id=self.metadata.module_id,
                    title="Cabeçalho X-Content-Type-Options",
                    status=CheckStatus.PASSED,
                    summary="X-Content-Type-Options: nosniff configurado.",
                )
            )

        # CHK-A05: Clickjacking (X-Frame-Options ou CSP frame-ancestors)
        xfo_val = lower_headers.get("x-frame-options", "").strip().upper()
        fa_match = re.search(r"(?:^|;)\s*frame-ancestors\s+([^;]+)", csp_val.lower()) if csp_val else None
        fa_directive = fa_match.group(1).strip() if fa_match else ""
        has_wildcard_frame_ancestors = bool(fa_directive) and bool(re.search(r"(?:^|\s)\*(?=\s|$)", fa_directive))
        has_safe_frame_ancestors = bool(fa_directive) and not has_wildcard_frame_ancestors
        if xfo_val not in {"DENY", "SAMEORIGIN"} and not has_safe_frame_ancestors:
            if is_pure_api_context and not has_wildcard_frame_ancestors:
                checks.append(
                    CheckEvaluationResult(
                        check_id="CHK-A05",
                        module_id=self.metadata.module_id,
                        title="Proteção contra Clickjacking",
                        status=CheckStatus.NOT_APPLICABLE,
                        summary=f"Ativo do tipo {asset_type.value} sem interface HTML interativa enquadrável.",
                    )
                )
            else:
                cj_summary = (
                    "Diretiva CSP frame-ancestors permite wildcard '*' sem X-Frame-Options restritivo."
                    if has_wildcard_frame_ancestors
                    else "Nem X-Frame-Options nem CSP frame-ancestors foram encontrados."
                )
                checks.append(
                    CheckEvaluationResult(
                        check_id="CHK-A05",
                        module_id=self.metadata.module_id,
                        title="Proteção contra Clickjacking",
                        status=CheckStatus.VULNERABILITY,
                        summary=cj_summary,
                    )
                )
                findings.append(
                    NormalizedFinding(
                        endpoint=target_url,
                        module_id=self.metadata.module_id,
                        check_id="CHK-A05",
                        fingerprint=RiskEngine.compute_finding_fingerprint(
                            hostname, self.metadata.module_id, "CHK-A05", target_url
                        ),
                        title=(
                            "Diretiva frame-ancestors permissiva ('*') permite Clickjacking"
                            if has_wildcard_frame_ancestors
                            else "Ausência de proteção contra Clickjacking (X-Frame-Options / frame-ancestors)"
                        ),
                        description="A página pode ser embutida em iframes arbitrários de domínios externos.",
                        category=self.metadata.category,
                        result_classification=CheckStatus.VULNERABILITY,
                        severity=Severity.LOW,
                        confidence=Confidence.CERTAIN,
                        evidence=EvidenceManager.build_sanitized_evidence(
                            request_method="GET",
                            request_url=target_url,
                            response_status_code=status_code,
                            response_headers=headers,
                            observed_value=f"frame-ancestors {fa_directive}" if has_wildcard_frame_ancestors else "X-Frame-Options e frame-ancestors ausentes",
                            expected_baseline="X-Frame-Options: DENY ou SAMEORIGIN; CSP frame-ancestors 'none' ou 'self'",
                        ),
                        owasp_references=["A05:2021-Security Misconfiguration"],
                        cwe_ids=["CWE-1021"],
                        impact="Risco de UI Redressing (Clickjacking) em páginas interativas.",
                        safe_reproduction_steps=[f"Verificar cabeçalhos de resposta em {target_url}."],
                        remediation=RemediationEngine.get_guidance("missing_clickjacking_protection"),
                    )
                )
        else:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-A05",
                    module_id=self.metadata.module_id,
                    title="Proteção contra Clickjacking",
                    status=CheckStatus.PASSED,
                    summary="Proteção anti-clickjacking ativa.",
                )
            )

        # CHK-A06: Referrer-Policy e Permissions-Policy
        referrer_val = lower_headers.get("referrer-policy", "").strip().lower()
        permissions_val = lower_headers.get("permissions-policy", "").strip()
        if is_pure_api_context and not referrer_val and not permissions_val:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-A06",
                    module_id=self.metadata.module_id,
                    title="Cabeçalhos Referrer-Policy e Permissions-Policy",
                    status=CheckStatus.NOT_APPLICABLE,
                    summary="Cabeçalhos de políticas de recursos de navegador não exigidos para respostas JSON puras.",
                )
            )
        else:
            ref_tokens = [t.strip() for t in referrer_val.split(",") if t.strip() in ALL_REFERRER_POLICIES]
            effective_ref = ref_tokens[-1] if ref_tokens else referrer_val
            ref_ok = effective_ref in SAFE_REFERRER_POLICIES
            perm_ok = bool(permissions_val) and "*" not in permissions_val
            if not ref_ok or not perm_ok:
                missing_parts: list[str] = []
                if not ref_ok:
                    missing_parts.append(f"Referrer-Policy ({referrer_val or 'ausente'})")
                if not perm_ok:
                    missing_parts.append(f"Permissions-Policy ({permissions_val or 'ausente'})")
                checks.append(
                    CheckEvaluationResult(
                        check_id="CHK-A06",
                        module_id=self.metadata.module_id,
                        title="Cabeçalhos Referrer-Policy e Permissions-Policy",
                        status=CheckStatus.POTENTIAL_VULNERABILITY,
                        summary=f"Configuração ausente ou incompleta: {', '.join(missing_parts)}",
                    )
                )
                findings.append(
                    NormalizedFinding(
                        endpoint=target_url,
                        module_id=self.metadata.module_id,
                        check_id="CHK-A06",
                        fingerprint=RiskEngine.compute_finding_fingerprint(
                            hostname, self.metadata.module_id, "CHK-A06", target_url
                        ),
                        title="Ausência ou fragilidade em Referrer-Policy / Permissions-Policy",
                        description=(
                            f"Foram identificadas lacunas nos cabeçalhos de controle de privacidade e recursos do navegador: "
                            f"{', '.join(missing_parts)}."
                        ),
                        category=self.metadata.category,
                        result_classification=CheckStatus.POTENTIAL_VULNERABILITY,
                        severity=Severity.LOW,
                        confidence=Confidence.CERTAIN,
                        evidence=EvidenceManager.build_sanitized_evidence(
                            request_method="GET",
                            request_url=target_url,
                            response_status_code=status_code,
                            response_headers=headers,
                            observed_value=", ".join(missing_parts),
                            expected_baseline=(
                                "Referrer-Policy: strict-origin-when-cross-origin | "
                                "Permissions-Policy: geolocation=(), microphone=(), camera=()"
                            ),
                        ),
                        owasp_references=["A05:2021-Security Misconfiguration"],
                        cwe_ids=["CWE-200"],
                        impact="Possível vazamento de URLs em cabeçalhos Referer ou acesso indevido a APIs de mídia.",
                        safe_reproduction_steps=[f"Inspecionar Referrer-Policy e Permissions-Policy em {target_url}."],
                        remediation=RemediationEngine.get_guidance("missing_referrer_or_permissions_policy"),
                    )
                )
            else:
                checks.append(
                    CheckEvaluationResult(
                        check_id="CHK-A06",
                        module_id=self.metadata.module_id,
                        title="Cabeçalhos Referrer-Policy e Permissions-Policy",
                        status=CheckStatus.PASSED,
                        summary=f"Referrer-Policy ({referrer_val}) e Permissions-Policy configurados.",
                    )
                )

        # CHK-A07: Exposição de versão em Server / X-Powered-By / X-AspNet-Version / X-Generator
        server_banner = lower_headers.get("server", "")
        powered_by = lower_headers.get("x-powered-by", "")
        aspnet_ver = lower_headers.get("x-aspnet-version", "")
        generator = lower_headers.get("x-generator", "")
        combined_banner = " ".join(
            part for part in [server_banner, powered_by, aspnet_ver, generator] if part
        ).strip()
        if VERSION_REGEX.search(combined_banner) or bool(powered_by) or bool(aspnet_ver) or bool(generator):
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-A07",
                    module_id=self.metadata.module_id,
                    title="Exposição de Versão de Servidor / Tecnologia",
                    status=CheckStatus.VULNERABILITY,
                    summary=f"Informação técnica exposta em cabeçalhos: {combined_banner}",
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-A07",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-A07", target_url
                    ),
                    title="Divulgação desnecessária de versão ou tecnologia em cabeçalhos HTTP",
                    description="Os cabeçalhos Server, X-Powered-By ou similares revelam detalhes da pilha tecnológica ou versão.",
                    category=self.metadata.category,
                    result_classification=CheckStatus.VULNERABILITY,
                    severity=Severity.LOW,
                    confidence=Confidence.CERTAIN,
                    evidence=EvidenceManager.build_sanitized_evidence(
                        request_method="GET",
                        request_url=target_url,
                        response_status_code=status_code,
                        response_headers=headers,
                        observed_value=combined_banner,
                        expected_baseline="Omitir X-Powered-By e versões numéricas no cabeçalho Server",
                    ),
                    owasp_references=["A05:2021-Security Misconfiguration"],
                    cwe_ids=["CWE-200"],
                    impact="Facilita enumeração passiva da infraestrutura e seleção de exploits por versão.",
                    safe_reproduction_steps=[f"Inspecionar cabeçalhos Server e X-Powered-By em {target_url}."],
                    remediation=RemediationEngine.get_guidance("server_version_disclosure"),
                )
            )
        else:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-A07",
                    module_id=self.metadata.module_id,
                    title="Exposição de Versão de Servidor / Tecnologia",
                    status=CheckStatus.PASSED,
                    summary="Nenhuma versão explícita exposta em Server / X-Powered-By.",
                )
            )

        # CHK-A08: Exposição de Stack Trace / Erros Verbosos no Corpo da Resposta
        matched_trace: str | None = None
        if body_excerpt:
            for pattern in STACK_TRACE_PATTERNS:
                m = pattern.search(body_excerpt)
                if m:
                    matched_trace = m.group(0)
                    break

        if matched_trace:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-A08",
                    module_id=self.metadata.module_id,
                    title="Exposição de Stack Trace ou Erros Verbosos no Corpo HTTP",
                    status=CheckStatus.VULNERABILITY,
                    summary=f"Assinatura de erro interno/stack trace detectada: '{matched_trace}'.",
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-A08",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-A08", target_url
                    ),
                    title="Divulgação de Stack Trace ou Detalhes Internos de Exceção",
                    description="O corpo da resposta HTTP contém assinaturas de stack trace ou depuração interna.",
                    category=self.metadata.category,
                    result_classification=CheckStatus.VULNERABILITY,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CERTAIN,
                    evidence=EvidenceManager.build_sanitized_evidence(
                        request_method="GET",
                        request_url=target_url,
                        response_status_code=status_code,
                        response_headers=headers,
                        response_body_excerpt=body_excerpt[:512],
                        observed_value=matched_trace,
                        expected_baseline="Mensagens de erro genéricas sem exposição de pilha interna",
                    ),
                    owasp_references=["A05:2021-Security Misconfiguration"],
                    cwe_ids=["CWE-209"],
                    impact="Exposição de caminhos internos, bibliotecas e estrutura lógica da aplicação.",
                    safe_reproduction_steps=[f"Enviar requisição GET para {target_url} e observar o corpo retornado."],
                    remediation=RemediationEngine.get_guidance("verbose_error_or_stack_trace_disclosure"),
                )
            )
        else:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-A08",
                    module_id=self.metadata.module_id,
                    title="Exposição de Stack Trace ou Erros Verbosos no Corpo HTTP",
                    status=CheckStatus.PASSED,
                    summary="Nenhum stack trace ou dump de depuração detectado na resposta.",
                )
            )

        # CHK-A09, CHK-A10, CHK-A11: Inspeção TLS (quando tls_info é fornecido)
        if tls_info is not None:
            conn_err = tls_info.get("connection_error")
            if conn_err:
                checks.append(
                    CheckEvaluationResult(
                        check_id="CHK-A09",
                        module_id=self.metadata.module_id,
                        title="Inspeção de Certificado e Handshake TLS",
                        status=CheckStatus.EXECUTION_ERROR,
                        summary=f"Erro técnico de conexão TLS: {conn_err}",
                        details=tls_info,
                    )
                )
            elif tls_info.get("enabled"):
                is_expired = bool(tls_info.get("is_expired"))
                days_left = tls_info.get("days_until_expiration")
                not_after = tls_info.get("not_after")

                # CHK-A09: Validade/Expiração do Certificado
                if is_expired:
                    checks.append(
                        CheckEvaluationResult(
                            check_id="CHK-A09",
                            module_id=self.metadata.module_id,
                            title="Validade e Expiração do Certificado TLS",
                            status=CheckStatus.VULNERABILITY,
                            summary=f"Certificado TLS expirado ou fora da janela de validade (notAfter={not_after}).",
                            details=tls_info,
                        )
                    )
                    findings.append(
                        NormalizedFinding(
                            endpoint=target_url,
                            module_id=self.metadata.module_id,
                            check_id="CHK-A09",
                            fingerprint=RiskEngine.compute_finding_fingerprint(
                                hostname, self.metadata.module_id, "CHK-A09", target_url
                            ),
                            title="Certificado TLS expirado ou fora do período de validade",
                            description=f"O certificado X.509 apresentado pelo servidor expirou em {not_after}.",
                            category=self.metadata.category,
                            result_classification=CheckStatus.VULNERABILITY,
                            severity=Severity.HIGH,
                            confidence=Confidence.CERTAIN,
                            evidence=EvidenceManager.build_sanitized_evidence(
                                request_method="TLS_HANDSHAKE",
                                request_url=target_url,
                                observed_value=f"is_expired=True, not_after={not_after}, days_left={days_left}",
                                expected_baseline="Certificado dentro do prazo de validade (days_until_expiration > 30)",
                            ),
                            owasp_references=["A02:2021-Cryptographic Failures"],
                            cwe_ids=["CWE-298"],
                            impact="Falha na validação criptográfica pelos clientes e risco de interceptação.",
                            safe_reproduction_steps=[f"Inspecionar certificado TLS apresentado por {hostname}."],
                            remediation=RemediationEngine.get_guidance("tls_certificate_expired_or_expiring"),
                        )
                    )
                elif isinstance(days_left, int) and days_left <= 30:
                    checks.append(
                        CheckEvaluationResult(
                            check_id="CHK-A09",
                            module_id=self.metadata.module_id,
                            title="Validade e Expiração do Certificado TLS",
                            status=CheckStatus.POTENTIAL_VULNERABILITY,
                            summary=f"Certificado TLS expira em breve ({days_left} dias restantes).",
                            details=tls_info,
                        )
                    )
                    findings.append(
                        NormalizedFinding(
                            endpoint=target_url,
                            module_id=self.metadata.module_id,
                            check_id="CHK-A09",
                            fingerprint=RiskEngine.compute_finding_fingerprint(
                                hostname, self.metadata.module_id, "CHK-A09", target_url, "expiring-soon"
                            ),
                            title=f"Certificado TLS próximo da expiração ({days_left} dias restantes)",
                            description=f"O certificado TLS expira em {not_after} ({days_left} dias restantes).",
                            category=self.metadata.category,
                            result_classification=CheckStatus.POTENTIAL_VULNERABILITY,
                            severity=Severity.LOW,
                            confidence=Confidence.CERTAIN,
                            evidence=EvidenceManager.build_sanitized_evidence(
                                request_method="TLS_HANDSHAKE",
                                request_url=target_url,
                                observed_value=f"days_until_expiration={days_left}, not_after={not_after}",
                                expected_baseline="Renovação preventiva antes de 30 dias para o vencimento",
                            ),
                            owasp_references=["A02:2021-Cryptographic Failures"],
                            cwe_ids=["CWE-298"],
                            impact="Risco operacional de indisponibilidade caso a renovação automática falhe.",
                            safe_reproduction_steps=[f"Verificar data notAfter do certificado de {hostname}."],
                            remediation=RemediationEngine.get_guidance("tls_certificate_expired_or_expiring"),
                        )
                    )
                else:
                    checks.append(
                        CheckEvaluationResult(
                            check_id="CHK-A09",
                            module_id=self.metadata.module_id,
                            title="Validade e Expiração do Certificado TLS",
                            status=CheckStatus.PASSED,
                            summary=f"Certificado válido (restam {days_left} dias).",
                            details=tls_info,
                        )
                    )

                # CHK-A10: Cadeia de Confiança e Hostname Match
                trusted_chain = bool(tls_info.get("trusted_chain"))
                hostname_matched = bool(tls_info.get("hostname_matched", True))
                is_self_signed = bool(tls_info.get("is_self_signed"))
                verify_err = tls_info.get("verification_error")

                if not trusted_chain or not hostname_matched:
                    reasons: list[str] = []
                    if not trusted_chain:
                        if is_self_signed:
                            reasons.append("certificado autoassinado (self-signed)")
                        else:
                            reasons.append("cadeia de certificação não confiável")
                    if not hostname_matched:
                        reasons.append(f"hostname '{hostname}' não corresponde ao Subject/SAN do certificado")
                    reason_str = ", ".join(reasons) or str(verify_err or "erro de validação X.509")

                    checks.append(
                        CheckEvaluationResult(
                            check_id="CHK-A10",
                            module_id=self.metadata.module_id,
                            title="Cadeia de Confiança TLS e Correspondência de Hostname",
                            status=CheckStatus.VULNERABILITY,
                            summary=f"Problema confirmado na validação do certificado: {reason_str}.",
                            details=tls_info,
                        )
                    )
                    findings.append(
                        NormalizedFinding(
                            endpoint=target_url,
                            module_id=self.metadata.module_id,
                            check_id="CHK-A10",
                            fingerprint=RiskEngine.compute_finding_fingerprint(
                                hostname, self.metadata.module_id, "CHK-A10", target_url, reason_str
                            ),
                            title=f"Falha na validação do certificado TLS ({reason_str})",
                            description=(
                                f"Durante o handshake TLS com {hostname}, o certificado apresentou falha de "
                                f"validação: {reason_str}."
                            ),
                            category=self.metadata.category,
                            result_classification=CheckStatus.VULNERABILITY,
                            severity=Severity.HIGH,
                            confidence=Confidence.CERTAIN,
                            evidence=EvidenceManager.build_sanitized_evidence(
                                request_method="TLS_HANDSHAKE",
                                request_url=target_url,
                                observed_value=(
                                    f"subject={tls_info.get('subject_cn')}, issuer={tls_info.get('issuer_cn')}, "
                                    f"SANs={tls_info.get('san_dns_names')}, trusted={trusted_chain}, "
                                    f"hostname_matched={hostname_matched}"
                                ),
                                expected_baseline="Certificado assinado por CA confiável com SAN correspondente ao hostname",
                            ),
                            owasp_references=["A02:2021-Cryptographic Failures"],
                            cwe_ids=["CWE-295", "CWE-297"],
                            impact="Permite ataques Man-in-the-Middle caso clientes aceitem certificados não confiáveis.",
                            safe_reproduction_steps=[f"Realizar handshake TLS com {target_url} validando CA e SAN."],
                            remediation=RemediationEngine.get_guidance("tls_untrusted_or_hostname_mismatch"),
                        )
                    )
                else:
                    checks.append(
                        CheckEvaluationResult(
                            check_id="CHK-A10",
                            module_id=self.metadata.module_id,
                            title="Cadeia de Confiança TLS e Correspondência de Hostname",
                            status=CheckStatus.PASSED,
                            summary="Cadeia de certificação confiável e hostname validado com sucesso.",
                            details=tls_info,
                        )
                    )

                # CHK-A11: Versão do Protocolo TLS e Cifras Negociadas
                neg_ver = tls_info.get("negotiated_version")
                weak_protos = tls_info.get("weak_protocols_accepted") or []
                cipher_suite = str(tls_info.get("cipher_suite") or "")
                weak_cipher_match = WEAK_TLS_CIPHERS_REGEX.search(cipher_suite) if cipher_suite else None
                if weak_protos or neg_ver in {"TLSv1", "TLSv1.0", "TLSv1.1"} or weak_cipher_match:
                    weak_reason = (
                        f"Protocolo TLS obsoleto ({neg_ver or weak_protos})"
                        if (weak_protos or neg_ver in {"TLSv1", "TLSv1.0", "TLSv1.1"})
                        else f"Suíte de cifra TLS fraca negociada ({cipher_suite})"
                    )
                    checks.append(
                        CheckEvaluationResult(
                            check_id="CHK-A11",
                            module_id=self.metadata.module_id,
                            title="Versão Negociada do Protocolo TLS e Cifras",
                            status=CheckStatus.VULNERABILITY,
                            summary=weak_reason,
                            details=tls_info,
                        )
                    )
                    findings.append(
                        NormalizedFinding(
                            endpoint=target_url,
                            module_id=self.metadata.module_id,
                            check_id="CHK-A11",
                            fingerprint=RiskEngine.compute_finding_fingerprint(
                                hostname, self.metadata.module_id, "CHK-A11", target_url
                            ),
                            title=f"Configuração Criptográfica TLS Fraca ({weak_reason})",
                            description="O servidor negociou versão TLS obsoleta (RFC 8996) ou suíte de cifra criptográfica fraca.",
                            category=self.metadata.category,
                            result_classification=CheckStatus.VULNERABILITY,
                            severity=Severity.HIGH,
                            confidence=Confidence.CERTAIN,
                            evidence=EvidenceManager.build_sanitized_evidence(
                                request_method="TLS_HANDSHAKE",
                                request_url=target_url,
                                observed_value=f"negotiated_version={neg_ver}, cipher_suite={cipher_suite}",
                                expected_baseline="TLSv1.2 ou TLSv1.3 com cifras AEAD modernas (AES-GCM / ChaCha20)",
                            ),
                            owasp_references=["A02:2021-Cryptographic Failures"],
                            cwe_ids=["CWE-326"],
                            impact="Exposição a ataques contra cifras fracas e protocolos TLS legados.",
                            safe_reproduction_steps=[f"Verificar versão TLS e suíte de cifra negociadas com {target_url}."],
                            remediation=RemediationEngine.get_guidance("tls_weak_protocol_version"),
                        )
                    )
                elif neg_ver in {"TLSv1.2", "TLSv1.3"}:
                    checks.append(
                        CheckEvaluationResult(
                            check_id="CHK-A11",
                            module_id=self.metadata.module_id,
                            title="Versão Negociada do Protocolo TLS e Cifras",
                            status=CheckStatus.PASSED,
                            summary=f"Protocolo moderno negociado: {neg_ver} ({cipher_suite}).",
                            details=tls_info,
                        )
                    )
                else:
                    checks.append(
                        CheckEvaluationResult(
                            check_id="CHK-A11",
                            module_id=self.metadata.module_id,
                            title="Versão Negociada do Protocolo TLS e Cifras",
                            status=CheckStatus.INCONCLUSIVE,
                            summary="Não foi possível determinar a versão exata do protocolo TLS negociado.",
                            details=tls_info,
                        )
                    )

        # CHK-A12: Registros de Autenticação de E-mail (SPF e DMARC)
        domain = hostname.lower()
        is_ip = False
        try:
            ipaddress.ip_address(domain)
            is_ip = True
        except ValueError:
            pass

        if not is_ip and domain not in {"localhost", "testserver", "unknown"} and "." in domain:
            txt_resolver = dns_txt_resolver or (
                getattr(http_client, "query_dns_txt_records", None) if http_client else None
            )
            if txt_resolver:
                try:
                    apex_txt = txt_resolver(domain)
                    dmarc_txt = txt_resolver(f"_dmarc.{domain}")
                    spf_records = [r for r in apex_txt if "v=spf1" in r.lower()]
                    dmarc_records = [r for r in dmarc_txt if "v=dmarc1" in r.lower()]
                    has_spf = bool(spf_records)
                    has_dmarc = bool(dmarc_records)
                    spf_plus_all = any(re.search(r"(?:^|\s)\+all(?:\s|$)", r.lower()) for r in spf_records)
                    spf_neutral_all = any(re.search(r"(?:^|\s)\?all(?:\s|$)", r.lower()) for r in spf_records)
                    dmarc_p_none = has_dmarc and any(
                        re.search(r"\bp\s*=\s*none\b", r.lower()) for r in dmarc_records
                    ) and not any(
                        re.search(r"\bp\s*=\s*(?:quarantine|reject)\b", r.lower()) for r in dmarc_records
                    )

                    if not has_spf or not has_dmarc:
                        missing_records = []
                        if not has_spf:
                            missing_records.append("SPF (v=spf1)")
                        if not has_dmarc:
                            missing_records.append("DMARC (v=DMARC1)")
                        reason = " e ".join(missing_records) + " ausente(s) na zona DNS"
                        checks.append(
                            CheckEvaluationResult(
                                check_id="CHK-A12",
                                module_id=self.metadata.module_id,
                                title="Registros de Autenticação de E-mail (SPF e DMARC)",
                                status=CheckStatus.POTENTIAL_VULNERABILITY,
                                summary=f"Domínio '{domain}' com {reason}.",
                                details={"domain": domain, "has_spf": has_spf, "has_dmarc": has_dmarc},
                            )
                        )
                        findings.append(
                            NormalizedFinding(
                                endpoint=domain,
                                module_id=self.metadata.module_id,
                                check_id="CHK-A12",
                                fingerprint=RiskEngine.compute_finding_fingerprint(
                                    domain, self.metadata.module_id, "CHK-A12", domain, "missing-email-auth"
                                ),
                                title=f"Ausência de Políticas de Autenticação de E-mail (SPF/DMARC) em '{domain}'",
                                description=(
                                    f"O domínio '{domain}' não possui configuração completa de SPF e/ou DMARC ({reason}), "
                                    "o que facilita a falsificação de e-mails (spoofing) em nome da organização."
                                ),
                                category="Configuração de DNS e Autenticação de Domínio",
                                result_classification=CheckStatus.POTENTIAL_VULNERABILITY,
                                severity=Severity.LOW,
                                confidence=Confidence.FIRM,
                                evidence=SanitizedEvidence(
                                    observed_value=f"SPF presente: {has_spf}, DMARC presente: {has_dmarc}",
                                    expected_baseline="Registros TXT com SPF 'v=spf1 ...' e DMARC 'v=DMARC1 ...'",
                                    technical_notes=[f"Domínio consultado: {domain}", f"Faltante: {reason}"],
                                ),
                                owasp_references=["A05:2021-Security Misconfiguration"],
                                cwe_ids=["CWE-345"],
                                impact="Permite envio de e-mails forjados em nome da organização, facilitando phishing e BEC.",
                                safe_reproduction_steps=[
                                    f"1. Consultar registros TXT de '{domain}'",
                                    f"2. Consultar registros TXT de '_dmarc.{domain}'",
                                ],
                                remediation=RemediationEngine.get_guidance("missing_spf_or_dmarc"),
                                technical_references=["RFC 7208", "RFC 7489"],
                            )
                        )
                    elif spf_plus_all:
                        checks.append(
                            CheckEvaluationResult(
                                check_id="CHK-A12",
                                module_id=self.metadata.module_id,
                                title="Registros de Autenticação de E-mail (SPF e DMARC)",
                                status=CheckStatus.VULNERABILITY,
                                summary=f"Registro SPF de '{domain}' utiliza '+all', autorizando qualquer servidor na internet.",
                                details={"domain": domain, "spf": spf_records[0]},
                            )
                        )
                        findings.append(
                            NormalizedFinding(
                                endpoint=domain,
                                module_id=self.metadata.module_id,
                                check_id="CHK-A12",
                                fingerprint=RiskEngine.compute_finding_fingerprint(
                                    domain, self.metadata.module_id, "CHK-A12", domain, "spf-plus-all"
                                ),
                                title=f"Política SPF Permissiva (+all) Permite Qualquer Remetente em '{domain}'",
                                description=(
                                    f"O registro SPF de '{domain}' termina com '+all', anulando qualquer restrição "
                                    "contra envio de e-mails forjados (spoofing)."
                                ),
                                category="Configuração de DNS e Autenticação de Domínio",
                                result_classification=CheckStatus.VULNERABILITY,
                                severity=Severity.MEDIUM,
                                confidence=Confidence.CERTAIN,
                                evidence=SanitizedEvidence(
                                    observed_value=spf_records[0],
                                    expected_baseline="Política SPF restritiva terminando com '-all' ou '~all'",
                                    technical_notes=[f"Domínio consultado: {domain}"],
                                ),
                                owasp_references=["A05:2021-Security Misconfiguration"],
                                cwe_ids=["CWE-345"],
                                impact="Qualquer servidor externo passa na validação SPF em nome do domínio da organização.",
                                safe_reproduction_steps=[f"Consultar registros TXT de '{domain}' e observar o qualificador '+all'."],
                                remediation=RemediationEngine.get_guidance("missing_spf_or_dmarc"),
                                technical_references=["RFC 7208", "RFC 7489"],
                            )
                        )
                    elif spf_neutral_all or dmarc_p_none:
                        weak_email_details = []
                        if spf_neutral_all:
                            weak_email_details.append("SPF com política neutra (?all)")
                        if dmarc_p_none:
                            weak_email_details.append("DMARC em modo somente monitoramento (p=none)")
                        weak_msg = " e ".join(weak_email_details)
                        checks.append(
                            CheckEvaluationResult(
                                check_id="CHK-A12",
                                module_id=self.metadata.module_id,
                                title="Registros de Autenticação de E-mail (SPF e DMARC)",
                                status=CheckStatus.POTENTIAL_VULNERABILITY,
                                summary=f"Políticas de e-mail em '{domain}' sem bloqueio ativo: {weak_msg}.",
                                details={"domain": domain, "spf_neutral": spf_neutral_all, "dmarc_p_none": dmarc_p_none},
                            )
                        )
                        findings.append(
                            NormalizedFinding(
                                endpoint=domain,
                                module_id=self.metadata.module_id,
                                check_id="CHK-A12",
                                fingerprint=RiskEngine.compute_finding_fingerprint(
                                    domain, self.metadata.module_id, "CHK-A12", domain, "weak-email-auth-policy"
                                ),
                                title=f"Política de Autenticação de E-mail Sem Rejeição Ativa em '{domain}' ({weak_msg})",
                                description=(
                                    f"O domínio '{domain}' possui registros SPF/DMARC, porém configurados de forma "
                                    f"não impositiva ({weak_msg}), sem instruir quarentena ou rejeição de e-mails forjados."
                                ),
                                category="Configuração de DNS e Autenticação de Domínio",
                                result_classification=CheckStatus.POTENTIAL_VULNERABILITY,
                                severity=Severity.LOW,
                                confidence=Confidence.FIRM,
                                evidence=SanitizedEvidence(
                                    observed_value=f"SPF={spf_records[0]} | DMARC={dmarc_records[0]}",
                                    expected_baseline="SPF com '-all' e DMARC com 'p=quarantine' ou 'p=reject'",
                                    technical_notes=[f"Domínio consultado: {domain}", weak_msg],
                                ),
                                owasp_references=["A05:2021-Security Misconfiguration"],
                                cwe_ids=["CWE-345"],
                                impact="E-mails forjados não são bloqueados ou colocados em quarentena pelos provedores destinatários.",
                                safe_reproduction_steps=[
                                    f"1. Consultar registros TXT de '{domain}'",
                                    f"2. Consultar registros TXT de '_dmarc.{domain}'",
                                ],
                                remediation=RemediationEngine.get_guidance("missing_spf_or_dmarc"),
                                technical_references=["RFC 7208", "RFC 7489"],
                            )
                        )
                    else:
                        checks.append(
                            CheckEvaluationResult(
                                check_id="CHK-A12",
                                module_id=self.metadata.module_id,
                                title="Registros de Autenticação de E-mail (SPF e DMARC)",
                                status=CheckStatus.PASSED,
                                summary=f"Registros SPF e DMARC configurados e impositivos para o domínio '{domain}'.",
                                details={"domain": domain, "has_spf": True, "has_dmarc": True},
                            )
                        )
                except Exception as exc:  # noqa: BLE001
                    checks.append(
                        CheckEvaluationResult(
                            check_id="CHK-A12",
                            module_id=self.metadata.module_id,
                            title="Registros de Autenticação de E-mail (SPF e DMARC)",
                            status=CheckStatus.INCONCLUSIVE,
                            summary=f"Não foi possível consultar os registros DNS TXT para '{domain}': {exc}",
                            details={"domain": domain, "error": str(exc)},
                        )
                    )
            else:
                checks.append(
                    CheckEvaluationResult(
                        check_id="CHK-A12",
                        module_id=self.metadata.module_id,
                        title="Registros de Autenticação de E-mail (SPF e DMARC)",
                        status=CheckStatus.INCONCLUSIVE,
                        summary=f"Resolvedor DNS não disponível durante a inspeção passiva de '{domain}'.",
                        details={"domain": domain},
                    )
                )

        # CHK-A13: Subresource Integrity (SRI) e Isolamento Cross-Origin
        if is_pure_api_context:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-A13",
                    module_id=self.metadata.module_id,
                    title="Subresource Integrity (SRI) em Recursos Externos",
                    status=CheckStatus.NOT_APPLICABLE,
                    summary=f"Ativo do tipo {asset_type.value} sem carregamento de scripts/estilos HTML.",
                )
            )
        else:
            missing_sri_urls: list[str] = []
            sri_tag_patterns = [
                re.compile(r'<script\b[^>]*\bsrc=["\'](https?://[^"\']+)["\'][^>]*>', re.IGNORECASE),
                re.compile(
                    r'<link\b[^>]*\brel=["\']?stylesheet["\']?[^>]*\bhref=["\'](https?://[^"\']+)["\'][^>]*>',
                    re.IGNORECASE,
                ),
                re.compile(
                    r'<link\b[^>]*\bhref=["\'](https?://[^"\']+)["\'][^>]*\brel=["\']?stylesheet["\']?[^>]*>',
                    re.IGNORECASE,
                ),
            ]
            integrity_attr_regex = re.compile(
                r'\bintegrity\s*=\s*["\']sha(?:256|384|512)-[A-Za-z0-9+/=]+["\']',
                re.IGNORECASE,
            )
            for pat in sri_tag_patterns:
                for m in pat.finditer(body_excerpt):
                    tag_html = m.group(0)
                    res_url = m.group(1)
                    res_host = (urlparse(res_url).hostname or "").lower()
                    if (
                        res_host
                        and res_host != hostname.lower()
                        and not integrity_attr_regex.search(tag_html)
                        and res_url not in missing_sri_urls
                    ):
                        missing_sri_urls.append(res_url)

            if missing_sri_urls:
                checks.append(
                    CheckEvaluationResult(
                        check_id="CHK-A13",
                        module_id=self.metadata.module_id,
                        title="Subresource Integrity (SRI) em Recursos Externos",
                        status=CheckStatus.POTENTIAL_VULNERABILITY,
                        summary=f"Recurso(s) externo(s) sem verificação de integridade SRI: {', '.join(missing_sri_urls[:3])}.",
                        details={"missing_sri_urls": missing_sri_urls[:10]},
                    )
                )
                findings.append(
                    NormalizedFinding(
                        endpoint=target_url,
                        module_id=self.metadata.module_id,
                        check_id="CHK-A13",
                        fingerprint=RiskEngine.compute_finding_fingerprint(
                            hostname, self.metadata.module_id, "CHK-A13", target_url, "missing-sri"
                        ),
                        title="Recursos Externos (Scripts/Estilos) Carregados Sem Subresource Integrity (SRI)",
                        description=(
                            f"A página HTML carrega recursos de origens externas ({', '.join(missing_sri_urls[:3])}) "
                            "sem o atributo criptográfico 'integrity' (SHA-256/384/512)."
                        ),
                        category="Integridade de Suprimentos e Front-end",
                        result_classification=CheckStatus.POTENTIAL_VULNERABILITY,
                        severity=Severity.LOW,
                        confidence=Confidence.FIRM,
                        evidence=EvidenceManager.build_sanitized_evidence(
                            request_method="GET",
                            request_url=target_url,
                            response_status_code=status_code,
                            response_headers=headers,
                            observed_value=f"Recursos externos sem SRI: {', '.join(missing_sri_urls[:3])}",
                            expected_baseline='Atributo integrity="sha384-..." e crossorigin="anonymous" em scripts/estilos externos',
                        ),
                        owasp_references=["A08:2021-Software and Data Integrity Failures"],
                        cwe_ids=["CWE-353"],
                        impact="Comprometimento de CDN externa permite execução de código malicioso na aplicação (Magecart / Supply Chain).",
                        safe_reproduction_steps=[f"Inspecionar tags <script> e <link> no HTML retornado por {target_url}."],
                        remediation=RemediationEngine.get_guidance("missing_subresource_integrity_sri"),
                    )
                )
            else:
                checks.append(
                    CheckEvaluationResult(
                        check_id="CHK-A13",
                        module_id=self.metadata.module_id,
                        title="Subresource Integrity (SRI) em Recursos Externos",
                        status=CheckStatus.PASSED,
                        summary="Nenhum script ou folha de estilo externo sem atributo Subresource Integrity (SRI) detectado.",
                    )
                )

        return _finalize_module_result(
            self.metadata.module_id,
            checks,
            findings,
            total_requests=1,
        )


class ModuleECookiesAndSession(BaseSecurityModule):
    """MÓDULO E — Cookies e Sessões (HttpOnly, Secure, SameSite, Escopo, Validade e Sanitização)."""

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            module_id="mod_e_cookies_session",
            code="MÓDULO E",
            name="Segurança de Cookies e Sessões",
            version="1.1.0",
            description=(
                "Analisa individualmente os cookies emitidos pela aplicação quanto a HttpOnly, Secure, "
                "SameSite, tempo de expiração, escopo de domínio/caminho, combinações incompatíveis "
                "(ex: SameSite=None sem Secure) e transmissão sem HTTPS, mascarando valores sensíveis."
            ),
            category="Gerenciamento de Sessão e Cookies",
            impact_level=ImpactLevel.PASSIVE,
            supported_asset_types=[AssetType.WEB_APP, AssetType.REST_API],
            owasp_references=["A07:2021-Identification and Authentication Failures", "A08:2021-Software and Data Integrity Failures"],
            wstg_references=["WSTG-SESS-02"],
            asvs_references=["ASVS-V3.2", "ASVS-V3.4.1", "ASVS-V3.4.2", "ASVS-V3.4.3"],
            cwe_references=["CWE-614", "CWE-1004", "CWE-1275", "CWE-502", "CWE-331"],
            enabled_by_default=True,
            requires_authentication=False,
            allow_in_production=True,
            checks_catalog=[
                "CHK-E01: Atributos de Segurança em Cookies (Secure, HttpOnly, SameSite)",
                "CHK-E02: Incompatibilidade de Flags (SameSite=None sem Secure), Escopo e Expiração",
                "CHK-E03: Ausência e Conformidade de Prefixos de Isolamento (__Host- / __Secure-)",
                "CHK-E04: Entropia de Cookies de Sessão e Desserialização Insegura",
            ],
        )

    def inspect_response_snapshot(
        self,
        target_url: str,
        status_code: int,
        headers: dict[str, str],
        cookies: list[dict[str, Any]] | None = None,
        tls_info: dict[str, Any] | None = None,
        body_excerpt: str = "",
        is_Canceled: Callable[[], bool] | None = None,
        *,
        asset_type: AssetType = AssetType.WEB_APP,
        redirect_chain: list[dict[str, Any]] | None = None,
        raw_set_cookies: list[str] | None = None,
        http_to_https_redirected: bool | None = None,
        initial_url: str | None = None,
        http_client: Any | None = None,
    ) -> ModuleExecutionResult:
        checks: list[CheckEvaluationResult] = []
        findings: list[NormalizedFinding] = []
        parsed = urlparse(target_url)
        hostname = parsed.hostname or "unknown"
        scheme = parsed.scheme.lower()

        if is_Canceled and is_Canceled():
            return ModuleExecutionResult(module_id=self.metadata.module_id)

        if status_code <= 0:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-E01",
                    module_id=self.metadata.module_id,
                    title="Análise de Atributos de Cookies",
                    status=CheckStatus.EXECUTION_ERROR,
                    summary="Não foi possível analisar cookies devido a erro de conexão HTTP.",
                )
            )
            return ModuleExecutionResult(
                module_id=self.metadata.module_id,
                checks=checks,
                findings=findings,
                total_requests=1,
                execution_errors=1,
            )

        cookie_strings: list[str] = []
        if raw_set_cookies:
            cookie_strings.extend([c for c in raw_set_cookies if c.strip()])
        else:
            for k, v in headers.items():
                if k.lower() == "set-cookie" and v.strip():
                    cookie_strings.append(v.strip())

        if not cookie_strings and not cookies:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-E01",
                    module_id=self.metadata.module_id,
                    title="Análise de Atributos de Cookies",
                    status=CheckStatus.NOT_APPLICABLE,
                    summary="Nenhum cabeçalho Set-Cookie retornado neste endpoint.",
                )
            )
            return ModuleExecutionResult(
                module_id=self.metadata.module_id,
                checks=checks,
                findings=findings,
                total_requests=1,
            )

        parsed_cookies = [_parse_cookie_attributes(raw_c) for raw_c in cookie_strings]
        all_missing_reports: list[str] = []
        incompatible_reports: list[str] = []
        sanitized_list: list[str] = [c["sanitized"] for c in parsed_cookies]

        for p_cookie in parsed_cookies:
            c_name = p_cookie["name"]
            missing_flags: list[str] = []
            if not p_cookie["secure"]:
                missing_flags.append("Secure")
            if not p_cookie["httponly"]:
                missing_flags.append("HttpOnly")
            if not p_cookie["samesite"]:
                missing_flags.append("SameSite")

            if missing_flags:
                all_missing_reports.append(f"{c_name}: {', '.join(missing_flags)}")

            # Verifica combinações incompatíveis ou inseguras (CHK-E02)
            if p_cookie["samesite"] == "none" and not p_cookie["secure"]:
                incompatible_reports.append(f"{c_name}: SameSite=None sem atributo Secure")
            if scheme == "http":
                incompatible_reports.append(f"{c_name}: emitido sobre conexão HTTP não criptografada")
            if isinstance(p_cookie["max_age"], int) and p_cookie["max_age"] > 31536000:
                incompatible_reports.append(f"{c_name}: expiração excessiva (Max-Age={p_cookie['max_age']}s)")
            if p_cookie["domain"] and p_cookie["domain"].startswith("."):
                incompatible_reports.append(f"{c_name}: escopo Domain amplo ({p_cookie['domain']})")

        if all_missing_reports:
            summary_flags = "; ".join(all_missing_reports)
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-E01",
                    module_id=self.metadata.module_id,
                    title="Atributos de Segurança do Cookie (Secure, HttpOnly, SameSite)",
                    status=CheckStatus.VULNERABILITY,
                    summary=f"Cookie(s) emitido(s) sem flags obrigatórias ({summary_flags})",
                    details={"cookies_analyzed": len(parsed_cookies), "issues": all_missing_reports},
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-E01",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-E01", target_url, summary_flags
                    ),
                    title=f"Cookie configurado sem atributos de segurança ({summary_flags})",
                    description=(
                        f"Foram identificados cookies sem os atributos de proteção recomendados ({summary_flags}), "
                        "expondo a sessão a interceptação, acesso por scripts ou requisições cross-site."
                    ),
                    category=self.metadata.category,
                    result_classification=CheckStatus.VULNERABILITY,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CERTAIN,
                    evidence=EvidenceManager.build_sanitized_evidence(
                        request_method="GET",
                        request_url=target_url,
                        response_status_code=status_code,
                        response_headers=headers,
                        observed_value=" | ".join(sanitized_list),
                        expected_baseline="Set-Cookie: <nome>=[REDACTED]; Secure; HttpOnly; SameSite=Lax",
                    ),
                    owasp_references=["A07:2021-Identification and Authentication Failures"],
                    cwe_ids=["CWE-614", "CWE-1004"],
                    impact="Maior risco de comprometimento de sessão via XSS, CSRF ou tráfego não criptografado.",
                    safe_reproduction_steps=[
                        f"Realizar requisição para {target_url} e observar as diretivas do cabeçalho Set-Cookie."
                    ],
                    remediation=RemediationEngine.get_guidance("insecure_cookie_flags"),
                )
            )
        else:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-E01",
                    module_id=self.metadata.module_id,
                    title="Atributos de Segurança do Cookie (Secure, HttpOnly, SameSite)",
                    status=CheckStatus.PASSED,
                    summary=f"Todos os {len(parsed_cookies)} cookie(s) possuem Secure, HttpOnly e SameSite.",
                )
            )

        if incompatible_reports:
            inc_summary = "; ".join(incompatible_reports)
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-E02",
                    module_id=self.metadata.module_id,
                    title="Coerência de Atributos, Escopo e Expiração de Cookies",
                    status=CheckStatus.VULNERABILITY,
                    summary=f"Configuração incompatível ou excessivamente ampla: {inc_summary}",
                    details={"issues": incompatible_reports},
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-E02",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-E02", target_url, inc_summary
                    ),
                    title=f"Configuração insegura de atributos ou escopo de Cookie ({inc_summary})",
                    description=(
                        f"A análise detalhada dos cookies detectou configurações incompatíveis ou arriscadas: "
                        f"{inc_summary}."
                    ),
                    category=self.metadata.category,
                    result_classification=CheckStatus.VULNERABILITY,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CERTAIN,
                    evidence=EvidenceManager.build_sanitized_evidence(
                        request_method="GET",
                        request_url=target_url,
                        response_status_code=status_code,
                        response_headers=headers,
                        observed_value=" | ".join(sanitized_list),
                        expected_baseline="SameSite=None requer obrigatoriamente Secure sob HTTPS; escopo restrito ao host",
                    ),
                    owasp_references=["A07:2021-Identification and Authentication Failures"],
                    cwe_ids=["CWE-1275", "CWE-614"],
                    impact="Exposição de cookies em contextos cross-site inseguros ou subdomínios não confiáveis.",
                    safe_reproduction_steps=[f"Inspecionar cabeçalhos Set-Cookie retornados por {target_url}."],
                    remediation=RemediationEngine.get_guidance("cookie_incompatible_or_broad_attributes"),
                )
            )
        else:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-E02",
                    module_id=self.metadata.module_id,
                    title="Coerência de Atributos, Escopo e Expiração de Cookies",
                    status=CheckStatus.PASSED,
                    summary="Nenhuma incompatibilidade de SameSite/Secure, escopo ou expiração detectada.",
                )
            )

        # CHK-E03: Ausência e Conformidade de Prefixos de Isolamento (__Host- / __Secure-)
        session_cookie_indicators = ["session", "token", "auth", "sid", "sessionid", "jwt", "connect.sid", "phpsessid", "jsessionid"]
        cookies_lacking_prefix: list[str] = []
        prefix_violations: list[str] = []
        for p_cookie in parsed_cookies:
            c_name = p_cookie["name"]
            c_name_lower = c_name.lower()
            is_session_cookie = (
                any(ind in c_name_lower for ind in session_cookie_indicators)
                or p_cookie.get("httponly")
            )
            if c_name.startswith("__Host-"):
                viol_reasons: list[str] = []
                if not p_cookie["secure"]:
                    viol_reasons.append("sem atributo Secure")
                if p_cookie["path"] != "/":
                    viol_reasons.append(f"Path={p_cookie['path'] or 'ausente'} (exige Path=/)")
                if p_cookie["domain"] is not None:
                    viol_reasons.append(f"Domain={p_cookie['domain']} (proibido para __Host-)")
                if viol_reasons:
                    prefix_violations.append(f"{c_name}: {', '.join(viol_reasons)}")
            elif c_name.startswith("__Secure-"):
                if not p_cookie["secure"]:
                    prefix_violations.append(f"{c_name}: sem atributo Secure")
            elif is_session_cookie:
                cookies_lacking_prefix.append(c_name)

        if prefix_violations:
            viol_summary = "; ".join(prefix_violations)
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-E03",
                    module_id=self.metadata.module_id,
                    title="Ausência e Conformidade de Prefixos de Isolamento (__Host- / __Secure-)",
                    status=CheckStatus.VULNERABILITY,
                    summary=f"Violação de contrato RFC 6265bis em cookie prefixado: {viol_summary}",
                    details={"prefix_violations": prefix_violations},
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-E03",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-E03", target_url, "invalid-cookie-prefix"
                    ),
                    title=f"Prefixo de Isolamento de Cookie Mal Configurado ({viol_summary})",
                    description=(
                        f"Um ou mais cookies utilizam prefixos __Host- ou __Secure- em desacordo com a RFC 6265bis "
                        f"({viol_summary}), fazendo com que navegadores modernos descartem ou não protejam o cookie."
                    ),
                    category=self.metadata.category,
                    result_classification=CheckStatus.VULNERABILITY,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CERTAIN,
                    evidence=EvidenceManager.build_sanitized_evidence(
                        request_method="GET",
                        request_url=target_url,
                        response_status_code=status_code,
                        response_headers=headers,
                        observed_value=" | ".join(sanitized_list),
                        expected_baseline="__Host- exige Secure, Path=/ e ausência de Domain; __Secure- exige Secure",
                    ),
                    owasp_references=["A07:2021-Identification and Authentication Failures"],
                    cwe_ids=["CWE-614", "CWE-1275"],
                    impact="Rejeição do cookie de sessão pelo navegador ou falha de isolamento de domínio.",
                    safe_reproduction_steps=[f"Inspecionar atributos Set-Cookie em {target_url}."],
                    remediation=RemediationEngine.get_guidance("missing_cookie_security_prefixes"),
                )
            )
        elif cookies_lacking_prefix:
            prefix_summary = ", ".join(cookies_lacking_prefix)
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-E03",
                    module_id=self.metadata.module_id,
                    title="Ausência e Conformidade de Prefixos de Isolamento (__Host- / __Secure-)",
                    status=CheckStatus.POTENTIAL_VULNERABILITY,
                    summary=f"Cookie(s) de sessão emitido(s) sem prefixos de isolamento: {prefix_summary}",
                    details={"cookies_without_prefix": cookies_lacking_prefix},
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-E03",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-E03", target_url, "missing-cookie-prefix"
                    ),
                    title=f"Cookie de Sessão Sem Prefixo de Isolamento ({prefix_summary})",
                    description=(
                        "Cookies de autenticação e sessão foram emitidos sem os prefixos padronizados "
                        "(__Host- ou __Secure-). Sem esses prefixos, subdomínios vulneráveis podem realizar "
                        "ataques de Cookie Tossing ou sobrescrever credenciais legítimas de sessão."
                    ),
                    category=self.metadata.category,
                    result_classification=CheckStatus.POTENTIAL_VULNERABILITY,
                    severity=Severity.LOW,
                    confidence=Confidence.CERTAIN,
                    evidence=EvidenceManager.build_sanitized_evidence(
                        request_method="GET",
                        request_url=target_url,
                        response_status_code=status_code,
                        response_headers=headers,
                        observed_value=f"Cookies sem prefixo de isolamento: {prefix_summary}",
                        expected_baseline="Cookies sensíveis de autenticação prefixados com __Host- ou __Secure-",
                    ),
                    owasp_references=["A07:2021-Identification and Authentication Failures"],
                    cwe_ids=["CWE-614", "CWE-1275"],
                    impact="Permite que subdomínios não confiáveis ou comprometidos no mesmo domínio base injetem ou sobrescrevam cookies de sessão.",
                    safe_reproduction_steps=[
                        f"Inspecionar cabeçalhos Set-Cookie retornados por {target_url} e verificar a ausência de prefixos __Host- ou __Secure-."
                    ],
                    remediation=RemediationEngine.get_guidance("missing_cookie_security_prefixes"),
                )
            )
        else:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-E03",
                    module_id=self.metadata.module_id,
                    title="Ausência e Conformidade de Prefixos de Isolamento (__Host- / __Secure-)",
                    status=CheckStatus.PASSED,
                    summary="Todos os cookies de sessão utilizam prefixos de isolamento conformes à RFC 6265bis ou nenhum cookie de sessão foi emitido.",
                )
            )

        # CHK-E04: Entropia de Cookies de Sessão e Desserialização Insegura
        deserialization_hits: list[str] = []
        low_entropy_hits: list[str] = []
        for p_cookie in parsed_cookies:
            c_name = p_cookie["name"]
            c_name_lower = c_name.lower()
            if p_cookie.get("deserialization_kind"):
                deserialization_hits.append(f"{c_name}: {p_cookie['deserialization_kind']}")
            is_named_session = any(ind in c_name_lower for ind in session_cookie_indicators)
            if (
                is_named_session
                and p_cookie.get("value_len", 0) > 0
                and (p_cookie["value_len"] < 12 or p_cookie.get("is_numeric_value"))
            ):
                reason = (
                    "identificador puramente numérico/previsível"
                    if p_cookie.get("is_numeric_value")
                    else f"comprimento insuficiente ({p_cookie['value_len']} chars < 12)"
                )
                low_entropy_hits.append(f"{c_name}: {reason}")

        if deserialization_hits:
            des_summary = "; ".join(deserialization_hits)
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-E04",
                    module_id=self.metadata.module_id,
                    title="Entropia de Cookies de Sessão e Desserialização Insegura",
                    status=CheckStatus.VULNERABILITY,
                    summary=f"Assinatura de objeto serializado detectada em cookie: {des_summary}",
                    details={"deserialization_hits": deserialization_hits},
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-E04",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-E04", target_url, "insecure-cookie-deserialization"
                    ),
                    title=f"Objeto Serializado Inseguro Detectado em Cookie ({des_summary})",
                    description=(
                        f"Um cookie emitido contém assinatura característica de serialização nativa ({des_summary}), "
                        "expondo o servidor a ataques críticos de desserialização insegura caso aceito sem assinatura."
                    ),
                    category=self.metadata.category,
                    result_classification=CheckStatus.VULNERABILITY,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CERTAIN,
                    evidence=EvidenceManager.build_sanitized_evidence(
                        request_method="GET",
                        request_url=target_url,
                        response_status_code=status_code,
                        response_headers=headers,
                        observed_value=des_summary,
                        expected_baseline="Identificadores opacos CSPRNG sem serialização nativa Java/Pickle/PHP",
                    ),
                    owasp_references=["A08:2021-Software and Data Integrity Failures"],
                    cwe_ids=["CWE-502"],
                    impact="Potencial Execução Remota de Código (RCE) ou adulteração de objetos no servidor.",
                    safe_reproduction_steps=[f"Inspecionar formato dos cookies emitidos por {target_url}."],
                    remediation=RemediationEngine.get_guidance("cookie_weak_entropy_or_insecure_deserialization"),
                )
            )
        elif low_entropy_hits:
            ent_summary = "; ".join(low_entropy_hits)
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-E04",
                    module_id=self.metadata.module_id,
                    title="Entropia de Cookies de Sessão e Desserialização Insegura",
                    status=CheckStatus.VULNERABILITY,
                    summary=f"Cookie(s) de sessão com baixa entropia detectado(s): {ent_summary}",
                    details={"low_entropy_hits": low_entropy_hits},
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-E04",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-E04", target_url, "weak-cookie-entropy"
                    ),
                    title=f"Identificador de Sessão em Cookie com Baixa Entropia ({ent_summary})",
                    description=(
                        f"Foram identificados cookies de sessão com valores curtos ou previsíveis ({ent_summary}), "
                        "permitindo enumeração ou sequestro de sessões ativas."
                    ),
                    category=self.metadata.category,
                    result_classification=CheckStatus.VULNERABILITY,
                    severity=Severity.HIGH,
                    confidence=Confidence.CERTAIN,
                    evidence=EvidenceManager.build_sanitized_evidence(
                        request_method="GET",
                        request_url=target_url,
                        response_status_code=status_code,
                        response_headers=headers,
                        observed_value=ent_summary,
                        expected_baseline="Token aleatório CSPRNG com >= 128 bits de entropia (>= 22 chars Base64url)",
                    ),
                    owasp_references=["A07:2021-Identification and Authentication Failures"],
                    cwe_ids=["CWE-331"],
                    impact="Sequestro de sessão de outros usuários por enumeração ou adivinhação.",
                    safe_reproduction_steps=[f"Analisar o comprimento e aleatoriedade dos cookies de sessão de {target_url}."],
                    remediation=RemediationEngine.get_guidance("cookie_weak_entropy_or_insecure_deserialization"),
                )
            )
        else:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-E04",
                    module_id=self.metadata.module_id,
                    title="Entropia de Cookies de Sessão e Desserialização Insegura",
                    status=CheckStatus.PASSED,
                    summary="Nenhum cookie de sessão com baixa entropia ou assinatura de desserialização insegura detectado.",
                )
            )

        return _finalize_module_result(
            self.metadata.module_id,
            checks,
            findings,
            total_requests=1,
        )


# =============================================================================
# MÓDULO B — Autenticação, Login e Política de Sessão
# =============================================================================
class ModuleBAuthLogin(BaseSecurityModule):
    """MÓDULO B — Autenticação, Login e Política de Sessão."""

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            module_id="mod_b_auth_login",
            code="MÓDULO B",
            name="Autenticação, Login e Política de Sessão",
            version="1.1.0",
            description=(
                "Verifica HTTPS obrigatório no login, exposição de enumeração de usuários em erros, "
                "e políticas de cache em endpoints de autenticação de acordo com OWASP ASVS e WSTG."
            ),
            category="Autenticação e Gerenciamento de Identidade",
            impact_level=ImpactLevel.LOW_IMPACT_ACTIVE,
            supported_asset_types=[AssetType.WEB_APP, AssetType.REST_API],
            owasp_references=["A07:2021-Identification and Authentication Failures"],
            wstg_references=["WSTG-ATHN-01", "WSTG-ATHN-02", "WSTG-SESS-03"],
            asvs_references=["ASVS-V2.1", "ASVS-V2.2", "ASVS-V8.3"],
            cwe_references=["CWE-287", "CWE-319", "CWE-204", "CWE-525", "CWE-598", "CWE-922", "CWE-798"],
            enabled_by_default=True,
            requires_authentication=False,
            allow_in_production=True,
            checks_catalog=[
                "CHK-B01: Transporte HTTPS Obrigatório em Formulários/Endpoints de Autenticação",
                "CHK-B02: Exposição de Enumeração de Usuários em Mensagens de Erro",
                "CHK-B03: Políticas de Cache e Proteção de Dados Sensíveis em Endpoints de Autenticação",
                "CHK-B04: Transmissão Insegura de Credenciais via Query String (GET Login/Token)",
                "CHK-B05: Exposição de Tokens em Web Storage e Segredos Hardcoded no Cliente",
            ],
        )

    def inspect_response_snapshot(
        self,
        target_url: str,
        status_code: int,
        headers: dict[str, str],
        cookies: list[dict[str, Any]] | None = None,
        tls_info: dict[str, Any] | None = None,
        body_excerpt: str = "",
        is_Canceled: Callable[[], bool] | None = None,
        *,
        asset_type: AssetType = AssetType.WEB_APP,
        redirect_chain: list[dict[str, Any]] | None = None,
        raw_set_cookies: list[str] | None = None,
        http_to_https_redirected: bool | None = None,
        initial_url: str | None = None,
        http_client: Any | None = None,
    ) -> ModuleExecutionResult:
        checks: list[CheckEvaluationResult] = []
        findings: list[NormalizedFinding] = []
        parsed = urlparse(target_url)
        hostname = parsed.hostname or "unknown"
        scheme = parsed.scheme.lower()
        lower_headers = {k.lower(): v for k, v in headers.items()}

        if is_Canceled and is_Canceled():
            return ModuleExecutionResult(module_id=self.metadata.module_id)

        if status_code <= 0:
            return ModuleExecutionResult(
                module_id=self.metadata.module_id,
                checks=[
                    CheckEvaluationResult(
                        check_id="CHK-B01",
                        module_id=self.metadata.module_id,
                        title="Transporte HTTPS em Formulários de Autenticação",
                        status=CheckStatus.EXECUTION_ERROR,
                        summary="Falha de conexão com o alvo; impossível avaliar transporte de autenticação.",
                    )
                ],
                findings=[],
                total_requests=1,
                execution_errors=1,
            )

        # CHK-B01: Transporte HTTPS Obrigatório em Formulários/Endpoints de Autenticação
        has_password_field = bool(re.search(r'<input[^>]+type=["\']?password["\']?', body_excerpt, re.IGNORECASE))
        has_login_form = has_password_field or any(
            t in target_url.lower() for t in ["/login", "/signin", "/auth", "/entrar"]
        )
        insecure_form_actions = re.findall(
            r'<form[^>]+action=["\'](http://[^"\']+)["\']', body_excerpt, re.IGNORECASE
        )

        if scheme == "http" and has_login_form:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-B01",
                    module_id=self.metadata.module_id,
                    title="Transporte HTTPS Obrigatório em Formulários/Endpoints de Autenticação",
                    status=CheckStatus.VULNERABILITY,
                    summary="Endpoint de autenticação é servido via HTTP em texto claro.",
                    details={"url": target_url, "scheme": scheme},
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-B01",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-B01", target_url, "http-auth-transport"
                    ),
                    title="Página de Autenticação Servida via HTTP em Texto Claro",
                    description="O formulário ou tela de autenticação é transmitido sem criptografia TLS/HTTPS, permitindo interceptação de credenciais.",
                    category="Autenticação e Criptografia em Trânsito",
                    result_classification=CheckStatus.VULNERABILITY,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CERTAIN,
                    evidence=SanitizedEvidence(
                        request_url=target_url,
                        observed_value=f"Scheme: {scheme}",
                        expected_baseline="HTTPS obrigatório em todas as páginas e ações de autenticação",
                    ),
                    owasp_references=["A07:2021-Identification and Authentication Failures"],
                    cwe_ids=["CWE-319", "CWE-287"],
                    impact="Interceptação direta de credenciais de login e senhas em trânsito por atacantes na mesma rede.",
                    remediation=RemediationEngine.get_guidance("insecure_auth_transport"),
                )
            )
        elif insecure_form_actions:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-B01",
                    module_id=self.metadata.module_id,
                    title="Transporte HTTPS Obrigatório em Formulários/Endpoints de Autenticação",
                    status=CheckStatus.VULNERABILITY,
                    summary=f"Formulário submete credenciais para URL HTTP insegura: {insecure_form_actions[0]}",
                    details={"insecure_actions": insecure_form_actions},
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-B01",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-B01", target_url, "insecure-form-action"
                    ),
                    title="Formulário de Login Submete Dados para URL HTTP Não Criptografada",
                    description=f"A ação do formulário de autenticação direciona para {insecure_form_actions[0]}, transmitindo credenciais em texto claro.",
                    category="Autenticação e Criptografia em Trânsito",
                    result_classification=CheckStatus.VULNERABILITY,
                    severity=Severity.HIGH,
                    confidence=Confidence.CERTAIN,
                    evidence=SanitizedEvidence(
                        request_url=target_url,
                        observed_value=f"Action: {insecure_form_actions[0]}",
                        expected_baseline="Ações de formulário apontando exclusivamente para HTTPS",
                    ),
                    owasp_references=["A07:2021-Identification and Authentication Failures"],
                    cwe_ids=["CWE-319"],
                    impact="Vazamento de credenciais durante o envio do formulário de login.",
                    remediation=RemediationEngine.get_guidance("insecure_auth_transport"),
                )
            )
        else:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-B01",
                    module_id=self.metadata.module_id,
                    title="Transporte HTTPS Obrigatório em Formulários/Endpoints de Autenticação",
                    status=CheckStatus.PASSED,
                    summary="Formulários e transporte de autenticação utilizam HTTPS de forma segura.",
                    details={"scheme": scheme, "has_login_form": has_login_form},
                )
            )

        # CHK-B02: Exposição de Enumeração de Usuários em Mensagens de Erro
        enum_patterns = [
            (re.compile(r"usu[aá]rio n[aã]o encontrado", re.IGNORECASE), "usuário não encontrado"),
            (re.compile(r"usu[aá]rio inexistente", re.IGNORECASE), "usuário inexistente"),
            (re.compile(r"email n[aã]o cadastrado", re.IGNORECASE), "email não cadastrado"),
            (re.compile(r"user not found", re.IGNORECASE), "user not found"),
            (re.compile(r"no account found with that email", re.IGNORECASE), "no account found with that email"),
            (re.compile(r"senha incorreta para este usu[aá]rio", re.IGNORECASE), "senha incorreta para este usuário"),
        ]
        matched_enum = None
        for pat, label in enum_patterns:
            if pat.search(body_excerpt):
                matched_enum = label
                break

        if matched_enum:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-B02",
                    module_id=self.metadata.module_id,
                    title="Exposição de Enumeração de Usuários em Mensagens de Erro",
                    status=CheckStatus.POTENTIAL_VULNERABILITY,
                    summary=f"Mensagem de erro de autenticação específica detectada ('{matched_enum}'), permitindo enumeração de contas.",
                    details={"matched_pattern": matched_enum},
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-B02",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-B02", target_url, "user-enumeration"
                    ),
                    title="Discrepância Observável em Mensagens de Autenticação (Enumeração de Usuários)",
                    description=(
                        f"A aplicação responde com mensagem que diferencia usuário inexistente ('{matched_enum}'), "
                        "permitindo que atacantes descubram e-mails e nomes de usuários válidos."
                    ),
                    category="Autenticação e Gerenciamento de Identidade",
                    result_classification=CheckStatus.POTENTIAL_VULNERABILITY,
                    severity=Severity.LOW,
                    confidence=Confidence.FIRM,
                    evidence=SanitizedEvidence(
                        request_url=target_url,
                        observed_value=matched_enum,
                        expected_baseline="Mensagem genérica como 'E-mail ou senha incorretos'",
                    ),
                    owasp_references=["A07:2021-Identification and Authentication Failures"],
                    cwe_ids=["CWE-204"],
                    impact="Permite montagem de listas de usuários válidos para ataques de credential stuffing ou força bruta direcionada.",
                    remediation=RemediationEngine.get_guidance("user_enumeration_in_auth"),
                )
            )
        else:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-B02",
                    module_id=self.metadata.module_id,
                    title="Exposição de Enumeração de Usuários em Mensagens de Erro",
                    status=CheckStatus.PASSED,
                    summary="Nenhuma evidência de enumeração de usuários detectada em mensagens de erro.",
                )
            )

        # CHK-B03: Políticas de Cache e Proteção de Dados Sensíveis em Endpoints de Autenticação
        cache_control = lower_headers.get("cache-control", "").lower()
        if has_login_form:
            if not cache_control or "no-store" not in cache_control:
                checks.append(
                    CheckEvaluationResult(
                        check_id="CHK-B03",
                        module_id=self.metadata.module_id,
                        title="Políticas de Cache em Endpoints de Autenticação",
                        status=CheckStatus.POTENTIAL_VULNERABILITY,
                        summary="Tela ou endpoint de autenticação não define 'Cache-Control: no-store'.",
                        details={"cache_control": cache_control or "ausente"},
                    )
                )
                findings.append(
                    NormalizedFinding(
                        endpoint=target_url,
                        module_id=self.metadata.module_id,
                        check_id="CHK-B03",
                        fingerprint=RiskEngine.compute_finding_fingerprint(
                            hostname, self.metadata.module_id, "CHK-B03", target_url, "auth-cache-control"
                        ),
                        title="Ausência de Cache-Control: no-store em Endpoint de Autenticação",
                        description="Endpoints e telas de login devem impedir o armazenamento em cache de navegador ou proxies para proteger credenciais.",
                        category="Gerenciamento de Sessão e Cache",
                        result_classification=CheckStatus.POTENTIAL_VULNERABILITY,
                        severity=Severity.LOW,
                        confidence=Confidence.CERTAIN,
                        evidence=SanitizedEvidence(
                            request_url=target_url,
                            observed_value=f"Cache-Control: {cache_control or 'ausente'}",
                            expected_baseline="Cache-Control: no-store, no-cache, must-revalidate",
                        ),
                        owasp_references=["A05:2021-Security Misconfiguration"],
                        cwe_ids=["CWE-525"],
                        impact="Respostas sensíveis de autenticação podem ser armazenadas no cache de navegadores ou proxies intermediários.",
                        remediation=RemediationEngine.get_guidance("auth_sensitive_caching"),
                    )
                )
            else:
                checks.append(
                    CheckEvaluationResult(
                        check_id="CHK-B03",
                        module_id=self.metadata.module_id,
                        title="Políticas de Cache em Endpoints de Autenticação",
                        status=CheckStatus.PASSED,
                        summary=f"Cabeçalho Cache-Control configurado com no-store ({cache_control}).",
                        details={"cache_control": cache_control},
                    )
                )
        else:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-B03",
                    module_id=self.metadata.module_id,
                    title="Políticas de Cache em Endpoints de Autenticação",
                    status=CheckStatus.NOT_APPLICABLE,
                    summary="O endpoint analisado não aparenta ser uma tela de login ou autenticação direta.",
                )
            )

        # CHK-B04: Transmissão Insegura de Credenciais via Query String (GET Login/Token)
        sensitive_param_names = {
            "password", "pass", "pwd", "senha", "secret", "user_password", "auth_token", "access_token", "api_key", "apikey"
        }
        parsed_qs = parse_qs(parsed.query, keep_blank_values=True)
        detected_sensitive_params = [
            p for p in parsed_qs if any(s == p.lower() or f"{s}_" in p.lower() or f"_{s}" in p.lower() for s in sensitive_param_names)
        ]
        has_get_password_form = False
        for form_match in re.finditer(r"<form([^>]*)>([\s\S]*?)(?:</form>|$)", body_excerpt, re.IGNORECASE):
            attrs, inner = form_match.group(1), form_match.group(2)
            if re.search(r'<input[^>]+type=["\']?password["\']?', inner, re.IGNORECASE):
                method_m = re.search(r'\bmethod\s*=\s*["\']?([a-z]+)["\']?', attrs, re.IGNORECASE)
                form_method = method_m.group(1).lower() if method_m else "get"
                if form_method == "get":
                    has_get_password_form = True
                    break

        if detected_sensitive_params or has_get_password_form:
            detail_msg = (
                f"Parâmetros sensíveis na URL: {', '.join(detected_sensitive_params)}"
                if detected_sensitive_params
                else "Formulário GET (ou sem atributo method explícito) com campo de senha detectado no corpo da resposta"
            )
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-B04",
                    module_id=self.metadata.module_id,
                    title="Transmissão Insegura de Credenciais via Query String (GET Login/Token)",
                    status=CheckStatus.VULNERABILITY,
                    summary=f"Credenciais ou segredos detectados em requisição GET/Query String ({detail_msg}).",
                    details={
                        "sensitive_params": detected_sensitive_params,
                        "has_get_password_form": has_get_password_form,
                    },
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-B04",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-B04", target_url, "credentials-in-qs"
                    ),
                    title="Transmissão Insegura de Credenciais via Query String / Método GET",
                    description=(
                        "Parâmetros de autenticação ou credenciais confidenciais foram identificados na query string "
                        "ou submetidos via formulário com método GET, expondo dados sensíveis em logs de servidores, "
                        "proxies reversos e histórico de navegação."
                    ),
                    category="Autenticação e Proteção de Segredos",
                    result_classification=CheckStatus.VULNERABILITY,
                    severity=Severity.HIGH,
                    confidence=Confidence.CERTAIN,
                    evidence=EvidenceManager.build_sanitized_evidence(
                        request_method="GET",
                        request_url=target_url,
                        observed_value=detail_msg,
                        expected_baseline="Submissão via corpo HTTP com método POST e cabeçalhos Authorization padronizados",
                    ),
                    owasp_references=["A07:2021-Identification and Authentication Failures"],
                    cwe_ids=["CWE-598", "CWE-522"],
                    impact="Vazamento de credenciais em registros de auditoria, servidores proxy, ferramentas de APM e cache de navegador.",
                    remediation=RemediationEngine.get_guidance("credentials_in_query_string"),
                )
            )
        else:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-B04",
                    module_id=self.metadata.module_id,
                    title="Transmissão Insegura de Credenciais via Query String (GET Login/Token)",
                    status=CheckStatus.PASSED,
                    summary="Nenhum parâmetro de credencial sensível detectado em query string ou formulário GET.",
                )
            )

        # CHK-B05: Exposição de Tokens em Web Storage e Segredos Hardcoded no Cliente
        hardcoded_secret_regex = re.compile(
            r"\b(?:AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|ghp_[0-9A-Za-z]{36}|sk_live_[0-9A-Za-z]{16,})\b"
            r"|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
        )
        web_storage_regex = re.compile(
            r"(?:localStorage|sessionStorage)\.setItem\s*\(\s*['\"]([a-z0-9_.-]*(?:token|jwt|auth|secret|session)[a-z0-9_.-]*)['\"]",
            re.IGNORECASE,
        )
        hardcoded_match = hardcoded_secret_regex.search(body_excerpt)
        storage_match = web_storage_regex.search(body_excerpt)

        if hardcoded_match:
            masked_secret = EvidenceManager.mask_secret_value(hardcoded_match.group(0), visible_prefix=4)
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-B05",
                    module_id=self.metadata.module_id,
                    title="Exposição de Tokens em Web Storage e Segredos Hardcoded no Cliente",
                    status=CheckStatus.VULNERABILITY,
                    summary=f"Chave privada ou credencial de API hardcoded detectada no código cliente ({masked_secret}).",
                    details={"secret_preview": masked_secret},
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-B05",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-B05", target_url, "hardcoded-client-secret"
                    ),
                    title="Credencial ou Chave Privada Hardcoded Exposta no Código Cliente",
                    description=(
                        "O código HTML/JavaScript servido ao navegador contém chaves privadas ou tokens de API "
                        "incorporados diretamente, permitindo uso indevido por qualquer usuário."
                    ),
                    category="Autenticação e Proteção de Segredos",
                    result_classification=CheckStatus.VULNERABILITY,
                    severity=Severity.HIGH,
                    confidence=Confidence.CERTAIN,
                    evidence=EvidenceManager.build_sanitized_evidence(
                        request_method="GET",
                        request_url=target_url,
                        observed_value=f"Assinatura de segredo detectada: {masked_secret}",
                        expected_baseline="Armazenamento exclusivo de chaves e segredos em cofre/variáveis de ambiente no backend",
                    ),
                    owasp_references=["A07:2021-Identification and Authentication Failures"],
                    cwe_ids=["CWE-798"],
                    impact="Comprometimento direto de integrações externas, contas de nuvem e assinaturas criptográficas.",
                    remediation=RemediationEngine.get_guidance("client_side_token_or_secret_exposure"),
                )
            )
        elif storage_match:
            storage_key = storage_match.group(1)
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-B05",
                    module_id=self.metadata.module_id,
                    title="Exposição de Tokens em Web Storage e Segredos Hardcoded no Cliente",
                    status=CheckStatus.POTENTIAL_VULNERABILITY,
                    summary=f"Persistência de token de autenticação em Web Storage detectada (chave '{storage_key}').",
                    details={"storage_key": storage_key},
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-B05",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-B05", target_url, f"web-storage-{storage_key}"
                    ),
                    title=f"Armazenamento de Token de Sessão em Web Storage ('{storage_key}')",
                    description=(
                        f"O código cliente armazena credenciais ou tokens ('{storage_key}') em localStorage/sessionStorage, "
                        "tornando-os acessíveis via JavaScript em caso de vulnerabilidade XSS."
                    ),
                    category="Autenticação e Proteção de Segredos",
                    result_classification=CheckStatus.POTENTIAL_VULNERABILITY,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.FIRM,
                    evidence=EvidenceManager.build_sanitized_evidence(
                        request_method="GET",
                        request_url=target_url,
                        observed_value=storage_match.group(0),
                        expected_baseline="Uso de cookies HttpOnly, Secure e SameSite em vez de localStorage/sessionStorage",
                    ),
                    owasp_references=["A07:2021-Identification and Authentication Failures"],
                    cwe_ids=["CWE-922"],
                    impact="Exfiltração direta de tokens de sessão por qualquer script malicioso executado na origem.",
                    remediation=RemediationEngine.get_guidance("client_side_token_or_secret_exposure"),
                )
            )
        else:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-B05",
                    module_id=self.metadata.module_id,
                    title="Exposição de Tokens em Web Storage e Segredos Hardcoded no Cliente",
                    status=CheckStatus.PASSED,
                    summary="Nenhum token em Web Storage ou segredo hardcoded detectado no código cliente.",
                )
            )

        return _finalize_module_result(
            self.metadata.module_id,
            checks,
            findings,
            total_requests=1,
        )


# =============================================================================
# MÓDULO C — Cross-Site Scripting (XSS) Controlado e Contexto DOM
# =============================================================================
class ModuleCXSSSafe(BaseSecurityModule):
    """MÓDULO C — Cross-Site Scripting (XSS) Controlado e Contexto DOM."""

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            module_id="mod_c_xss_safe",
            code="MÓDULO C",
            name="Cross-Site Scripting (XSS) Controlado e Contexto DOM",
            version="1.1.0",
            description=(
                "Avalia reflexão controlada de marcadores alfanuméricos inofensivos em parâmetros e formulários, "
                "sinks DOM perigosos em scripts e eficácia da Content-Security-Policy contra injeção de scripts."
            ),
            category="Validação e Codificação de Entrada/Saída",
            impact_level=ImpactLevel.LOW_IMPACT_ACTIVE,
            supported_asset_types=[AssetType.WEB_APP],
            owasp_references=["A03:2021-Injection"],
            wstg_references=["WSTG-INPV-01", "WSTG-CLNT-01"],
            asvs_references=["ASVS-V5.3"],
            cwe_references=["CWE-79", "CWE-1336"],
            enabled_by_default=True,
            requires_authentication=False,
            allow_in_production=True,
            checks_catalog=[
                "CHK-C01: Reflexão de Parâmetros e Tratamento de Caracteres Especiais",
                "CHK-C02: Sinks DOM Inseguros em Scripts e Páginas Web",
                "CHK-C03: Mitigação de Scripts via Content-Security-Policy (CSP)",
                "CHK-C04: Fuzzing Ativo Contextual em Múltiplos Parâmetros",
                "CHK-C05: Indicadores de Server-Side Template Injection (SSTI)",
            ],
        )

    def inspect_response_snapshot(
        self,
        target_url: str,
        status_code: int,
        headers: dict[str, str],
        cookies: list[dict[str, Any]] | None = None,
        tls_info: dict[str, Any] | None = None,
        body_excerpt: str = "",
        is_Canceled: Callable[[], bool] | None = None,
        *,
        asset_type: AssetType = AssetType.WEB_APP,
        redirect_chain: list[dict[str, Any]] | None = None,
        raw_set_cookies: list[str] | None = None,
        http_to_https_redirected: bool | None = None,
        initial_url: str | None = None,
        http_client: Any | None = None,
    ) -> ModuleExecutionResult:
        checks: list[CheckEvaluationResult] = []
        findings: list[NormalizedFinding] = []
        parsed = urlparse(target_url)
        hostname = parsed.hostname or "unknown"
        lower_headers = {k.lower(): v for k, v in headers.items()}
        requests_made = 1

        if is_Canceled and is_Canceled():
            return ModuleExecutionResult(module_id=self.metadata.module_id)

        if status_code <= 0:
            return ModuleExecutionResult(
                module_id=self.metadata.module_id,
                checks=[
                    CheckEvaluationResult(
                        check_id="CHK-C01",
                        module_id=self.metadata.module_id,
                        title="Reflexão de Parâmetros e Tratamento de Caracteres Especiais",
                        status=CheckStatus.EXECUTION_ERROR,
                        summary="Falha de conexão com o alvo; impossível avaliar XSS.",
                    )
                ],
                findings=[],
                total_requests=1,
                execution_errors=1,
            )

        def _classify_reflection_context(probe_headers: dict[str, str]) -> tuple[bool, bool]:
            """Retorna (is_exploitable_html, needs_nosniff_warning) para evitar FPs em JSON/text com nosniff."""
            ct = probe_headers.get("content-type", lower_headers.get("content-type", "")).lower()
            xcto = probe_headers.get("x-content-type-options", lower_headers.get("x-content-type-options", "")).strip().lower()
            if any(non_html in ct for non_html in ("application/json", "text/plain")):
                if xcto == "nosniff":
                    return False, False
                return False, True
            return True, False

        # CHK-C01: Reflexão de Parâmetros e Tratamento de Caracteres Especiais
        benign_marker = "cscxss7a8b"
        dangerous_test_chars = f"{benign_marker}<cscprobe>"
        encoded_expectation = html.escape(dangerous_test_chars)
        reflected_raw = False
        reflected_encoded = False
        reflected_non_html_warning = False
        reflected_safe_non_html = False

        if http_client and getattr(http_client, "probe", None):
            sep = "&" if "?" in target_url else "?"
            probe_url = f"{target_url}{sep}csc_probe={dangerous_test_chars}"
            try:
                probe_res = http_client.probe(probe_url, is_cancelled=is_Canceled)
                requests_made += 1
                if probe_res and probe_res.status_code == 200:
                    if dangerous_test_chars in probe_res.body:
                        is_html_ctx, needs_nosniff = _classify_reflection_context(_safe_probe_headers(probe_res))
                        if is_html_ctx:
                            reflected_raw = True
                        elif needs_nosniff:
                            reflected_non_html_warning = True
                        else:
                            reflected_safe_non_html = True
                    elif benign_marker in probe_res.body:
                        reflected_encoded = True
            except Exception:  # noqa: BLE001, S110
                pass

        if not reflected_raw and not reflected_encoded and not reflected_non_html_warning and not reflected_safe_non_html and parsed.query:
            qs = parse_qs(parsed.query)
            for param_val_list in qs.values():
                for pval in param_val_list:
                    if len(pval) >= 4 and pval in body_excerpt:
                        if any(c in pval for c in ["<", ">", '"', "'"]):
                            is_html_ctx, needs_nosniff = _classify_reflection_context(lower_headers)
                            if is_html_ctx:
                                reflected_raw = True
                            elif needs_nosniff:
                                reflected_non_html_warning = True
                            else:
                                reflected_safe_non_html = True
                        else:
                            reflected_encoded = True
                        break

        if reflected_raw or reflected_non_html_warning:
            chk_status = CheckStatus.VULNERABILITY if reflected_raw else CheckStatus.POTENTIAL_VULNERABILITY
            chk_sev = Severity.HIGH if reflected_raw else Severity.MEDIUM
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-C01",
                    module_id=self.metadata.module_id,
                    title="Reflexão de Parâmetros e Tratamento de Caracteres Especiais",
                    status=chk_status,
                    summary=(
                        "Marcador de teste com caracteres HTML (<, >) foi refletido no corpo da resposta sem codificação contextual."
                        if reflected_raw
                        else "Caracteres HTML refletidos em resposta não-HTML sem proteção X-Content-Type-Options: nosniff."
                    ),
                    details={"target_url": target_url, "reflected": True, "encoded": False, "html_context": reflected_raw},
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-C01",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-C01", target_url, "reflected-xss-chars"
                    ),
                    title=(
                        "Reflexão de Entrada sem Codificação Contextual HTML (XSS Refletido)"
                        if reflected_raw
                        else "Reflexão de HTML em Resposta JSON/Texto sem X-Content-Type-Options: nosniff"
                    ),
                    description=(
                        "A aplicação reflete dados fornecidos na URL diretamente no corpo da resposta sem aplicar "
                        "codificação HTML de caracteres especiais (<, >, \", '), permitindo potencial injeção de scripts."
                    ),
                    category="Validação e Codificação de Entrada/Saída",
                    result_classification=chk_status,
                    severity=chk_sev,
                    confidence=Confidence.FIRM,
                    evidence=SanitizedEvidence(
                        request_url=target_url,
                        observed_value=dangerous_test_chars,
                        expected_baseline=encoded_expectation,
                        technical_notes=["Marcador inofensivo refletido sem sanitização contextual."],
                    ),
                    owasp_references=["A03:2021-Injection"],
                    cwe_ids=["CWE-79"],
                    impact="Permite que invasores executem JavaScript no contexto de sessão do usuário através de links manipulados.",
                    safe_reproduction_steps=[
                        f"1. Enviar requisição com parâmetro de teste: {dangerous_test_chars}",
                        "2. Inspecionar se o corpo da resposta contém os caracteres < e > sem escape.",
                    ],
                    remediation=RemediationEngine.get_guidance("reflected_xss_indicator"),
                    technical_references=["OWASP WSTG-INPV-01", "OWASP ASVS 5.0 V5.3.1"],
                )
            )
        elif reflected_safe_non_html:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-C01",
                    module_id=self.metadata.module_id,
                    title="Reflexão de Parâmetros e Tratamento de Caracteres Especiais",
                    status=CheckStatus.PASSED,
                    summary="Reflexão em resposta não-HTML (JSON/texto) devidamente isolada com X-Content-Type-Options: nosniff.",
                )
            )
        elif reflected_encoded:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-C01",
                    module_id=self.metadata.module_id,
                    title="Reflexão de Parâmetros e Tratamento de Caracteres Especiais",
                    status=CheckStatus.PASSED,
                    summary="Entrada do usuário refletida com codificação contextual segura (HTML Entity Encoding).",
                )
            )
        else:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-C01",
                    module_id=self.metadata.module_id,
                    title="Reflexão de Parâmetros e Tratamento de Caracteres Especiais",
                    status=CheckStatus.PASSED,
                    summary="Nenhuma reflexão de entrada desprotegida identificada na resposta.",
                )
            )

        # CHK-C02: Sinks DOM Inseguros em Scripts e Páginas Web
        dom_sinks_regex = re.compile(
            r"(document\.write(?:ln)?\s*\(|\.innerHTML\s*=|\.outerHTML\s*=|\.insertAdjacentHTML\s*\(|"
            r"dangerouslySetInnerHTML|\beval\s*\(|(?:setTimeout|setInterval)\s*\(\s*[\"'\`]|"
            r"location\.href\s*=\s*(?:location|window)\.(?:search|hash))",
            re.IGNORECASE,
        )
        dom_sources_regex = re.compile(
            r"(?:location\.(?:search|hash|href|pathname)|document\.(?:URL|documentURI|referrer)|"
            r"window\.name|addEventListener\s*\(\s*['\"]message['\"])",
            re.IGNORECASE,
        )
        sink_match = dom_sinks_regex.search(body_excerpt)
        source_match = dom_sources_regex.search(body_excerpt)
        if sink_match:
            sink_str = sink_match.group(0).strip()
            has_source_and_sink = bool(source_match)
            dom_sev = Severity.HIGH if has_source_and_sink else Severity.MEDIUM
            dom_conf = Confidence.CERTAIN if has_source_and_sink else Confidence.FIRM
            dom_obs = (
                f"Sink '{sink_str}' combinado com fonte controlável '{source_match.group(0).strip()}'"
                if source_match
                else sink_str
            )
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-C02",
                    module_id=self.metadata.module_id,
                    title="Sinks DOM Inseguros em Scripts e Páginas Web",
                    status=CheckStatus.POTENTIAL_VULNERABILITY,
                    summary=(
                        f"Fonte DOM controlável conectada a sink perigoso: {dom_obs}."
                        if has_source_and_sink
                        else f"Sink DOM potencialmente perigoso identificado no código cliente: '{sink_str}'."
                    ),
                    details={"sink": sink_str, "has_controllable_source": has_source_and_sink},
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-C02",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-C02", target_url, "dom-xss-sink"
                    ),
                    title=(
                        f"Fluxo de DOM XSS Confirmado em Script Cliente ('{sink_str}')"
                        if has_source_and_sink
                        else f"Uso de Sink DOM Inseguro ('{sink_str}') em Script do Lado Cliente"
                    ),
                    description=(
                        f"O código JavaScript cliente utiliza manipulação direta de DOM via '{sink_str}'. "
                        "Quando alimentado por dados controláveis pelo usuário (como location.search ou hash), "
                        "permite DOM-based XSS."
                    ),
                    category="Validação e Codificação de Entrada/Saída",
                    result_classification=CheckStatus.POTENTIAL_VULNERABILITY,
                    severity=dom_sev,
                    confidence=dom_conf,
                    evidence=SanitizedEvidence(
                        request_url=target_url,
                        observed_value=dom_obs,
                        expected_baseline="Uso de textContent ou sanitização com DOMPurify antes de manipular o DOM",
                    ),
                    owasp_references=["A03:2021-Injection"],
                    cwe_ids=["CWE-79"],
                    impact="Execução de código JavaScript através de manipulação de fragmentos de URL no navegador.",
                    remediation=RemediationEngine.get_guidance("dangerous_dom_xss_sink"),
                    technical_references=["OWASP WSTG-CLNT-01", "OWASP ASVS 5.0 V5.3.3"],
                )
            )
        else:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-C02",
                    module_id=self.metadata.module_id,
                    title="Sinks DOM Inseguros em Scripts e Páginas Web",
                    status=CheckStatus.PASSED,
                    summary="Nenhum sink DOM perigoso identificado nos scripts analisados.",
                )
            )

        # CHK-C03: Mitigação de Scripts via Content-Security-Policy (CSP)
        csp_header = lower_headers.get("content-security-policy", "").lower()
        if not csp_header:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-C03",
                    module_id=self.metadata.module_id,
                    title="Mitigação de Scripts via Content-Security-Policy (CSP)",
                    status=CheckStatus.POTENTIAL_VULNERABILITY,
                    summary="Cabeçalho Content-Security-Policy ausente, deixando a aplicação sem camada de contenção contra XSS.",
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-C03",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-C03", target_url, "missing-csp-defense"
                    ),
                    title="Ausência de Content-Security-Policy para Defesa em Profundidade contra XSS",
                    description="A aplicação web não envia o cabeçalho Content-Security-Policy, impedindo a restrição de fontes de execução de scripts.",
                    category="Defesa em Profundidade e Headers",
                    result_classification=CheckStatus.POTENTIAL_VULNERABILITY,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CERTAIN,
                    evidence=SanitizedEvidence(
                        request_url=target_url,
                        observed_value="Content-Security-Policy: ausente",
                        expected_baseline="Content-Security-Policy: default-src 'self'; script-src 'self' ...",
                    ),
                    owasp_references=["A05:2021-Security Misconfiguration"],
                    cwe_ids=["CWE-79"],
                    impact="Scripts injetados via XSS podem ser executados livremente sem restrição de domínios ou nonces.",
                    remediation=RemediationEngine.get_guidance("ineffective_xss_csp"),
                )
            )
        elif "unsafe-inline" in csp_header and "nonce-" not in csp_header:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-C03",
                    module_id=self.metadata.module_id,
                    title="Mitigação de Scripts via Content-Security-Policy (CSP)",
                    status=CheckStatus.POTENTIAL_VULNERABILITY,
                    summary="CSP permite 'unsafe-inline' sem nonces, reduzindo a proteção contra execução de scripts maliciosos.",
                    details={"csp": csp_header},
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-C03",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-C03", target_url, "unsafe-inline-csp"
                    ),
                    title="Content-Security-Policy Permite 'unsafe-inline' sem Nonces Criptográficos",
                    description="O uso de 'unsafe-inline' na diretiva de script da CSP permite a execução de blocos de scripts inline arbitrários.",
                    category="Defesa em Profundidade e Headers",
                    result_classification=CheckStatus.POTENTIAL_VULNERABILITY,
                    severity=Severity.LOW,
                    confidence=Confidence.FIRM,
                    evidence=SanitizedEvidence(
                        request_url=target_url,
                        observed_value="script-src contém 'unsafe-inline'",
                        expected_baseline="Uso de nonces ('nonce-...') ou hashes em vez de 'unsafe-inline'",
                    ),
                    owasp_references=["A05:2021-Security Misconfiguration"],
                    cwe_ids=["CWE-79"],
                    impact="Enfraquecimento da proteção de defesa em profundidade da CSP contra ataques de XSS.",
                    remediation=RemediationEngine.get_guidance("ineffective_xss_csp"),
                )
            )
        else:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-C03",
                    module_id=self.metadata.module_id,
                    title="Mitigação de Scripts via Content-Security-Policy (CSP)",
                    status=CheckStatus.PASSED,
                    summary="Content-Security-Policy configurada e ativa para mitigação de scripts.",
                    details={"csp": csp_header},
                )
            )

        # CHK-C04: Fuzzing Ativo Contextual em Múltiplos Parâmetros
        qs = parse_qs(parsed.query)
        html_inputs = _extract_html_input_names(body_excerpt)
        discovered_params = list(qs.keys()) + [p for p in html_inputs if p not in qs]
        contextual_xss_found = None
        contextual_non_html_warn = None
        if http_client and getattr(http_client, "probe", None):
            test_params = discovered_params if discovered_params else ["q", "search", "msg", "name"]
            xss_test_vectors = [
                ("\"><csc_tag_probe>", "><csc_tag_probe>"),
                ("\" onfocus=\"csc_attr_probe", "\" onfocus=\"csc_attr_probe"),
                ("';csc_js_probe('1')//", "';csc_js_probe('1')//"),
            ]
            for param in test_params[:3]:
                for payload, raw_needle in xss_test_vectors:
                    sep = "&" if "?" in target_url else "?"
                    probe_url = f"{target_url}{sep}{param}={payload}"
                    try:
                        probe_res = http_client.probe(probe_url, is_cancelled=is_Canceled)
                        requests_made += 1
                        if probe_res and raw_needle in probe_res.body:
                            is_html_ctx, needs_nosniff = _classify_reflection_context(_safe_probe_headers(probe_res))
                            if is_html_ctx:
                                contextual_xss_found = (param, raw_needle)
                                break
                            if needs_nosniff and contextual_non_html_warn is None:
                                contextual_non_html_warn = (param, raw_needle)
                    except Exception:  # noqa: BLE001, S110
                        pass
                if contextual_xss_found:
                    break

        if contextual_xss_found or contextual_non_html_warn:
            is_confirmed = contextual_xss_found is not None
            param, vector = contextual_xss_found or contextual_non_html_warn  # type: ignore[misc]
            c04_status = CheckStatus.VULNERABILITY if is_confirmed else CheckStatus.POTENTIAL_VULNERABILITY
            c04_sev = Severity.HIGH if is_confirmed else Severity.MEDIUM
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-C04",
                    module_id=self.metadata.module_id,
                    title="Fuzzing Ativo Contextual em Múltiplos Parâmetros",
                    status=c04_status,
                    summary=(
                        f"Parâmetro '{param}' reflete payload contextual de XSS sem sanitização."
                        if is_confirmed
                        else f"Parâmetro '{param}' reflete vetor XSS em resposta não-HTML sem X-Content-Type-Options: nosniff."
                    ),
                    details={"param": param, "vector": vector, "html_context": is_confirmed},
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-C04",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-C04", target_url, f"contextual-xss-{param}"
                    ),
                    title=f"Reflexão de Vetor de XSS Contextual no Parâmetro '{param}'",
                    description=(
                        f"O parâmetro '{param}' permitiu a injeção do vetor contextual '{vector}' diretamente "
                        "na resposta sem escape de aspas ou delimitadores de tag."
                    ),
                    category="Validação e Codificação de Entrada/Saída",
                    result_classification=c04_status,
                    severity=c04_sev,
                    confidence=Confidence.CERTAIN if is_confirmed else Confidence.FIRM,
                    evidence=SanitizedEvidence(
                        request_url=target_url,
                        observed_value=f"Parâmetro '{param}' refletiu '{vector}' sem codificação",
                        expected_baseline="Codificação contextual HTML/Atributo/JavaScript antes da renderização",
                    ),
                    owasp_references=["A03:2021-Injection"],
                    cwe_ids=["CWE-79"],
                    impact="Permite execução arbitrária de scripts no navegador da vítima via URLs manipuladas.",
                    remediation=RemediationEngine.get_guidance("reflected_xss_indicator"),
                )
            )
        else:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-C04",
                    module_id=self.metadata.module_id,
                    title="Fuzzing Ativo Contextual em Múltiplos Parâmetros",
                    status=CheckStatus.PASSED,
                    summary="Nenhum vetor contextual de XSS foi refletido sem escape nos parâmetros testados.",
                )
            )

        # CHK-C05: Indicadores de Server-Side Template Injection (SSTI)
        ssti_error_patterns = [
            (re.compile(r"jinja2\.exceptions\.TemplateSyntaxError", re.IGNORECASE), "Jinja2 TemplateSyntaxError"),
            (re.compile(r"Twig\\Error\\SyntaxError", re.IGNORECASE), "Twig SyntaxError"),
            (re.compile(r"freemarker\.core\.ParseException", re.IGNORECASE), "FreeMarker ParseException"),
            (re.compile(r"org\.apache\.velocity\.exception", re.IGNORECASE), "Apache Velocity Exception"),
        ]
        ssti_detected: tuple[str, str, CheckStatus, Confidence] | None = None
        for pat, label in ssti_error_patterns:
            m = pat.search(body_excerpt)
            if m:
                ssti_detected = (label, f"Assinatura passiva '{m.group(0)}' detectada na resposta", CheckStatus.POTENTIAL_VULNERABILITY, Confidence.FIRM)
                break

        if not ssti_detected and http_client and getattr(http_client, "probe", None) and "csc1337csc" not in body_excerpt:
            ssti_params = discovered_params if discovered_params else ["name", "template", "q"]
            ssti_payloads = ["csc{{7*191}}csc", "csc${7*191}csc"]
            for param in ssti_params[:2]:
                for payload in ssti_payloads:
                    sep = "&" if "?" in target_url else "?"
                    probe_url = f"{target_url}{sep}{param}={payload}"
                    try:
                        probe_res = http_client.probe(probe_url, is_cancelled=is_Canceled)
                        requests_made += 1
                        if probe_res and "csc1337csc" in probe_res.body:
                            ssti_detected = (
                                param,
                                f"Expressão de template '{payload}' avaliada no servidor para 'csc1337csc' via parâmetro '{param}'",
                                CheckStatus.VULNERABILITY,
                                Confidence.CERTAIN,
                            )
                            break
                        if probe_res:
                            for pat, label in ssti_error_patterns:
                                if pat.search(probe_res.body):
                                    ssti_detected = (
                                        param,
                                        f"Exceção de motor de template ({label}) disparada no parâmetro '{param}'",
                                        CheckStatus.POTENTIAL_VULNERABILITY,
                                        Confidence.FIRM,
                                    )
                                    break
                    except Exception:  # noqa: BLE001, S110
                        pass
                    if ssti_detected:
                        break
                if ssti_detected:
                    break

        if ssti_detected:
            target_hint, ssti_ev, ssti_status, ssti_conf = ssti_detected
            ssti_sev = Severity.CRITICAL if ssti_status == CheckStatus.VULNERABILITY else Severity.HIGH
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-C05",
                    module_id=self.metadata.module_id,
                    title="Indicadores de Server-Side Template Injection (SSTI)",
                    status=ssti_status,
                    summary=ssti_ev,
                    details={"target": target_hint, "evidence": ssti_ev},
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-C05",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-C05", target_url, f"ssti-{target_hint}"
                    ),
                    title="Vulnerabilidade a Server-Side Template Injection (SSTI)",
                    description=(
                        f"A aplicação demonstrou avaliação de expressões de template no servidor ({ssti_ev}). "
                        "Isso permite execução arbitrária de código no servidor (RCE)."
                    ),
                    category="Injeção e Renderização Segura",
                    result_classification=ssti_status,
                    severity=ssti_sev,
                    confidence=ssti_conf,
                    evidence=SanitizedEvidence(
                        request_url=target_url,
                        observed_value=ssti_ev,
                        expected_baseline="Passagem de dados do usuário exclusivamente como variáveis de contexto em templates pré-compilados",
                    ),
                    owasp_references=["A03:2021-Injection"],
                    cwe_ids=["CWE-1336"],
                    impact="Execução Remota de Código (RCE) e comprometimento completo do servidor da aplicação.",
                    remediation=RemediationEngine.get_guidance("server_side_template_injection_ssti"),
                    technical_references=["OWASP WSTG-INPV-18"],
                )
            )
        else:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-C05",
                    module_id=self.metadata.module_id,
                    title="Indicadores de Server-Side Template Injection (SSTI)",
                    status=CheckStatus.PASSED,
                    summary="Nenhuma avaliação de expressão de template ou exceção SSTI detectada.",
                )
            )

        return _finalize_module_result(
            self.metadata.module_id,
            checks,
            findings,
            total_requests=requests_made,
        )


# =============================================================================
# MÓDULO D — Indicadores Seguros de SQL Injection
# =============================================================================
SQL_ERROR_PATTERNS = [
    (re.compile(r"You have an error in your SQL syntax", re.IGNORECASE), "MySQL/MariaDB Syntax Error"),
    (re.compile(r"warning:\s+mysql_", re.IGNORECASE), "PHP MySQL Driver Warning"),
    (re.compile(r"PostgreSQL query failed:", re.IGNORECASE), "PostgreSQL Driver Error"),
    (re.compile(r"PG::SyntaxError:", re.IGNORECASE), "PostgreSQL Ruby PG Error"),
    (re.compile(r"org\.postgresql\.util\.PSQLException", re.IGNORECASE), "PostgreSQL Java PSQLException"),
    (re.compile(r"ERROR:\s+syntax error at or near", re.IGNORECASE), "PostgreSQL Syntax Error"),
    (re.compile(r"ORA-00933|ORA-00921|ORA-01756", re.IGNORECASE), "Oracle SQL Exception"),
    (re.compile(r"Microsoft OLE DB Provider for SQL Server", re.IGNORECASE), "MS SQL Server OLE DB Error"),
    (re.compile(r"Unclosed quotation mark after the character string", re.IGNORECASE), "MS SQL Server Syntax Error"),
    (re.compile(r"SqlException \(0x80131904\)", re.IGNORECASE), ".NET SqlException"),
    (re.compile(r"sqlite3\.OperationalError:", re.IGNORECASE), "SQLite OperationalError"),
    (re.compile(r"SQLite/JDBCDriver", re.IGNORECASE), "SQLite JDBC Driver Error"),
    (re.compile(r"SQLSTATE\[[0-9A-Z]{5}\]", re.IGNORECASE), "ANSI SQLSTATE Error Code"),
]


class ModuleDSQLiIndicators(BaseSecurityModule):
    """MÓDULO D — Indicadores Seguros de SQL Injection."""

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            module_id="mod_d_sqli_indicators",
            code="MÓDULO D",
            name="Indicadores Seguros de SQL Injection",
            version="1.1.0",
            description=(
                "Identifica exposições de erros de banco de dados e indícios de consultas não parametrizadas "
                "usando testes não destrutivos em ambientes de homologação e laboratório."
            ),
            category="Injeção e Persistência Segura",
            impact_level=ImpactLevel.CONTROLLED_ASSESSMENT,
            supported_asset_types=[AssetType.WEB_APP, AssetType.REST_API],
            owasp_references=["A03:2021-Injection"],
            wstg_references=["WSTG-INPV-05"],
            asvs_references=["ASVS-V5.3.4"],
            cwe_references=["CWE-89", "CWE-209", "CWE-943", "CWE-90", "CWE-643"],
            enabled_by_default=False,
            requires_authentication=False,
            allow_in_production=False,
            checks_catalog=[
                "CHK-D01: Assinaturas de Erros e Exceções Verbosas de Banco de Dados",
                "CHK-D02: Comportamento Anômalo Não Destrutivo e Exposição de Estrutura Interna",
                "CHK-D03: Indicadores de Injeção de Comandos de Sistema Operacional (OS Command Injection)",
                "CHK-D04: Indicadores de SQL Injection Cego Baseado em Tempo / Booleano",
                "CHK-D05: Indicadores de Injeção NoSQL, LDAP e XPath",
            ],
        )

    def inspect_response_snapshot(
        self,
        target_url: str,
        status_code: int,
        headers: dict[str, str],
        cookies: list[dict[str, Any]] | None = None,
        tls_info: dict[str, Any] | None = None,
        body_excerpt: str = "",
        is_Canceled: Callable[[], bool] | None = None,
        *,
        asset_type: AssetType = AssetType.WEB_APP,
        redirect_chain: list[dict[str, Any]] | None = None,
        raw_set_cookies: list[str] | None = None,
        http_to_https_redirected: bool | None = None,
        initial_url: str | None = None,
        http_client: Any | None = None,
    ) -> ModuleExecutionResult:
        checks: list[CheckEvaluationResult] = []
        findings: list[NormalizedFinding] = []
        parsed = urlparse(target_url)
        hostname = parsed.hostname or "unknown"
        requests_made = 1

        if is_Canceled and is_Canceled():
            return ModuleExecutionResult(module_id=self.metadata.module_id)

        if status_code <= 0:
            return ModuleExecutionResult(
                module_id=self.metadata.module_id,
                checks=[
                    CheckEvaluationResult(
                        check_id="CHK-D01",
                        module_id=self.metadata.module_id,
                        title="Assinaturas de Erros e Exceções Verbosas de Banco de Dados",
                        status=CheckStatus.EXECUTION_ERROR,
                        summary="Falha de conexão com o alvo; impossível avaliar indicadores SQLi.",
                    )
                ],
                findings=[],
                total_requests=1,
                execution_errors=1,
            )

        # CHK-D01: Assinaturas de Erros e Exceções Verbosas de Banco de Dados
        baseline_sql_labels: set[str] = set()
        detected_sql_error = None
        for pattern, label in SQL_ERROR_PATTERNS:
            match = pattern.search(body_excerpt)
            if match:
                baseline_sql_labels.add(label)
                if detected_sql_error is None:
                    detected_sql_error = (label, match.group(0))

        if detected_sql_error:
            label, snippet = detected_sql_error
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-D01",
                    module_id=self.metadata.module_id,
                    title="Assinaturas de Erros e Exceções Verbosas de Banco de Dados",
                    status=CheckStatus.VULNERABILITY,
                    summary=f"Assinatura de erro de SGBD detectada na resposta: '{label}'.",
                    details={"error_label": label, "snippet": snippet},
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-D01",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-D01", target_url, "sql-error-signature"
                    ),
                    title=f"Exposição de Mensagem de Erro de Banco de Dados ({label})",
                    description=(
                        f"A aplicação expos a assinatura de erro de banco '{label}' no corpo da resposta HTTP. "
                        "Isso confirma que exceções de banco de dados não estão sendo tratadas e indica alto risco de SQL Injection."
                    ),
                    category="Injeção e Persistência Segura",
                    result_classification=CheckStatus.VULNERABILITY,
                    severity=Severity.HIGH,
                    confidence=Confidence.CERTAIN,
                    evidence=SanitizedEvidence(
                        request_url=target_url,
                        observed_value=snippet,
                        expected_baseline="Tratamento global de exceções retornando respostas HTTP padronizadas e limpas",
                    ),
                    owasp_references=["A03:2021-Injection"],
                    cwe_ids=["CWE-89", "CWE-209"],
                    impact="Revela tecnologia de banco de dados, estrutura de tabelas e potencial vulnerabilidade a SQL Injection.",
                    safe_reproduction_steps=[
                        f"1. Acessar endpoint: {target_url}",
                        f"2. Localizar padrão de erro no corpo: '{snippet}'",
                    ],
                    remediation=RemediationEngine.get_guidance("database_error_disclosure_sqli"),
                    technical_references=["OWASP WSTG-INPV-05", "OWASP ASVS 5.0 V5.3.4"],
                )
            )
        else:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-D01",
                    module_id=self.metadata.module_id,
                    title="Assinaturas de Erros e Exceções Verbosas de Banco de Dados",
                    status=CheckStatus.PASSED,
                    summary="Nenhuma assinatura ou mensagem de erro de banco de dados detectada na resposta.",
                )
            )

        qs_d = parse_qs(parsed.query)
        html_inputs_d = _extract_html_input_names(body_excerpt)
        discovered_d_params = list(qs_d.keys()) + [p for p in html_inputs_d if p not in qs_d]

        # CHK-D02: Comportamento Anômalo Não Destrutivo e Exposição de Estrutura Interna
        boundary_probe_triggered = False
        vulnerable_param = "id"
        if http_client and getattr(http_client, "probe", None):
            test_params = discovered_d_params if discovered_d_params else ["id", "cat", "search"]
            for param in test_params[:3]:
                sep = "&" if "?" in target_url else "?"
                probe_url = f"{target_url}{sep}{param}=1%27"
                try:
                    probe_res = http_client.probe(probe_url, is_cancelled=is_Canceled)
                    requests_made += 1
                    if probe_res:
                        for pattern, label in SQL_ERROR_PATTERNS:
                            if label not in baseline_sql_labels and pattern.search(probe_res.body):
                                boundary_probe_triggered = True
                                vulnerable_param = param
                                break
                    if boundary_probe_triggered:
                        break
                except Exception:  # noqa: BLE001, S110
                    pass

        if boundary_probe_triggered:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-D02",
                    module_id=self.metadata.module_id,
                    title="Comportamento Anômalo Não Destrutivo e Exposição de Estrutura Interna",
                    status=CheckStatus.VULNERABILITY,
                    summary=f"Teste de limite não destrutivo com caractere de controle no parâmetro '{vulnerable_param}' desencadeou erro interno de sintaxe SQL.",
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-D02",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-D02", target_url, f"sqli-boundary-anomaly-{vulnerable_param}"
                    ),
                    title=f"Vulnerabilidade Potencial a SQL Injection no Parâmetro '{vulnerable_param}'",
                    description=f"O envio de caractere de escape de string no parâmetro '{vulnerable_param}' provocou falha de banco de dados, evidenciando ausência de Prepared Statements.",
                    category="Injeção e Persistência Segura",
                    result_classification=CheckStatus.VULNERABILITY,
                    severity=Severity.HIGH,
                    confidence=Confidence.CERTAIN,
                    evidence=SanitizedEvidence(
                        request_url=target_url,
                        observed_value=f"Falha de sintaxe SQL disparada por caractere de controle no parâmetro '{vulnerable_param}'",
                        expected_baseline="Consultas parametrizadas que tratam entradas como literais",
                    ),
                    owasp_references=["A03:2021-Injection"],
                    cwe_ids=["CWE-89"],
                    impact="Permite manipulação direta de comandos SQL e vazamento ou alteração indevida de dados.",
                    remediation=RemediationEngine.get_guidance("unparameterized_query_pattern"),
                )
            )
        else:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-D02",
                    module_id=self.metadata.module_id,
                    title="Comportamento Anômalo Não Destrutivo e Exposição de Estrutura Interna",
                    status=CheckStatus.PASSED,
                    summary="Tratamento seguro de parâmetros; nenhuma anomalia de sintaxe disparada.",
                )
            )

        # CHK-D03: Indicadores de Injeção de Comandos de Sistema Operacional (OS Command Injection)
        os_cmd_found = False
        shell_error_detected = None
        vulnerable_cmd_param = "cmd"
        cmd_canary = "csc_cmd_canary_491"
        shell_error_patterns = [
            re.compile(r"sh:\s*(line\s*\d+:)?.*?: command not found", re.IGNORECASE),
            re.compile(r"/bin/(ba)?sh:\s*.*?: not found", re.IGNORECASE),
            re.compile(r"'cmd\.exe' is not recognized as an internal or external command", re.IGNORECASE),
            re.compile(r"syntax error near unexpected token", re.IGNORECASE),
        ]
        if http_client and getattr(http_client, "probe", None):
            test_params = discovered_d_params if discovered_d_params else ["cmd", "exec", "ping", "host", "target", "query"]
            for param in test_params[:3]:
                sep = "&" if "?" in target_url else "?"
                probe_url = f"{target_url}{sep}{param}=1;echo+{cmd_canary}"
                try:
                    probe_res = http_client.probe(probe_url, is_cancelled=is_Canceled)
                    requests_made += 1
                    if probe_res:
                        if (
                            cmd_canary in probe_res.body
                            and f"echo {cmd_canary}" not in probe_res.body
                            and f"echo+{cmd_canary}" not in probe_res.body
                        ):
                            os_cmd_found = True
                            vulnerable_cmd_param = param
                            break
                        for serr in shell_error_patterns:
                            m = serr.search(probe_res.body)
                            if m:
                                shell_error_detected = m.group(0)
                                vulnerable_cmd_param = param
                                break
                    if shell_error_detected or os_cmd_found:
                        break
                except Exception:  # noqa: BLE001, S110
                    pass

        if os_cmd_found:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-D03",
                    module_id=self.metadata.module_id,
                    title="Indicadores de Injeção de Comandos de Sistema Operacional (OS Command Injection)",
                    status=CheckStatus.VULNERABILITY,
                    summary=f"Injeção de comandos de sistema operacional confirmada no parâmetro '{vulnerable_cmd_param}' via eco de canário.",
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-D03",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-D03", target_url, f"os-cmd-injection-{vulnerable_cmd_param}"
                    ),
                    title=f"Injeção de Comandos de Sistema Operacional no Parâmetro '{vulnerable_cmd_param}'",
                    description=(
                        f"O parâmetro '{vulnerable_cmd_param}' permitiu a execução do comando de eco seguro, "
                        "confirmando vulnerabilidade crítica a OS Command Injection."
                    ),
                    category="Injeção e Persistência Segura",
                    result_classification=CheckStatus.VULNERABILITY,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CERTAIN,
                    evidence=SanitizedEvidence(
                        request_url=target_url,
                        observed_value=f"Canário '{cmd_canary}' refletido na resposta através de delimitador de comando",
                        expected_baseline="Execução parametrizada sem invocação de shell do sistema",
                    ),
                    owasp_references=["A03:2021-Injection"],
                    cwe_ids=["CWE-78"],
                    impact="Permite execução arbitrária de comandos no sistema operacional do servidor.",
                    remediation=RemediationEngine.get_guidance("os_command_injection"),
                )
            )
        elif shell_error_detected:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-D03",
                    module_id=self.metadata.module_id,
                    title="Indicadores de Injeção de Comandos de Sistema Operacional (OS Command Injection)",
                    status=CheckStatus.POTENTIAL_VULNERABILITY,
                    summary=f"Mensagem de erro de interpretador de comandos (shell) detectada no parâmetro '{vulnerable_cmd_param}'.",
                    details={"error": shell_error_detected},
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-D03",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-D03", target_url, f"os-cmd-error-{vulnerable_cmd_param}"
                    ),
                    title=f"Indício de Injeção de Comandos de Shell no Parâmetro '{vulnerable_cmd_param}'",
                    description=f"A resposta revelou a mensagem de erro de shell '{shell_error_detected}', indicando interpolação em interpretador de comandos.",
                    category="Injeção e Persistência Segura",
                    result_classification=CheckStatus.POTENTIAL_VULNERABILITY,
                    severity=Severity.HIGH,
                    confidence=Confidence.FIRM,
                    evidence=SanitizedEvidence(
                        request_url=target_url,
                        observed_value=shell_error_detected,
                        expected_baseline="Nenhum interpretador de shell acionado por dados de entrada",
                    ),
                    owasp_references=["A03:2021-Injection"],
                    cwe_ids=["CWE-78"],
                    impact="Potencial execução de comandos no servidor.",
                    remediation=RemediationEngine.get_guidance("os_command_injection"),
                )
            )
        else:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-D03",
                    module_id=self.metadata.module_id,
                    title="Indicadores de Injeção de Comandos de Sistema Operacional (OS Command Injection)",
                    status=CheckStatus.PASSED,
                    summary="Nenhum indício ou execução de comando de shell detectado nos parâmetros testados.",
                )
            )

        # CHK-D04: Indicadores de SQL Injection Cego Baseado em Tempo / Booleano
        blind_sqli_found = False
        blind_boolean_found = False
        vulnerable_blind_param = "id"
        blind_evidence_detail = ""
        if http_client and getattr(http_client, "probe", None):
            test_params = discovered_d_params if discovered_d_params else ["id", "filter", "query"]
            for param in test_params[:2]:
                sep = "&" if "?" in target_url else "?"
                probe_url = f"{target_url}{sep}{param}=1%20AND%20pg_sleep(2)--"
                try:
                    start_probe = time.monotonic()
                    probe_res = http_client.probe(probe_url, is_cancelled=is_Canceled)
                    duration_ms = int((time.monotonic() - start_probe) * 1000)
                    requests_made += 1
                    reported_ms = getattr(probe_res, "elapsed_ms", 0) if probe_res else 0
                    effective_ms = max(duration_ms, int(reported_ms) if isinstance(reported_ms, (int, float)) else 0)
                    if probe_res and effective_ms >= 1850:
                        ctrl_start = time.monotonic()
                        ctrl_res = http_client.probe(f"{target_url}{sep}{param}=1", is_cancelled=is_Canceled)
                        ctrl_duration_ms = int((time.monotonic() - ctrl_start) * 1000)
                        requests_made += 1
                        ctrl_reported = getattr(ctrl_res, "elapsed_ms", 0) if ctrl_res else 0
                        ctrl_ms = max(ctrl_duration_ms, int(ctrl_reported) if isinstance(ctrl_reported, (int, float)) else 0)
                        if ctrl_res and ctrl_ms < 1200:
                            blind_sqli_found = True
                            vulnerable_blind_param = param
                            blind_evidence_detail = (
                                f"Atraso temporal diferencial ({effective_ms}ms vs baseline {ctrl_ms}ms) no parâmetro '{param}'"
                            )
                            break

                    # Verificação diferencial booleana (1 AND 1=1 vs 1 AND 1=2)
                    true_res = http_client.probe(f"{target_url}{sep}{param}=1%20AND%201=1", is_cancelled=is_Canceled)
                    false_res = http_client.probe(f"{target_url}{sep}{param}=1%20AND%201=2", is_cancelled=is_Canceled)
                    requests_made += 2
                    if (
                        true_res
                        and false_res
                        and true_res.status_code == 200
                        and "1=1" not in true_res.body
                        and "1=2" not in false_res.body
                        and true_res.body != false_res.body
                    ):
                        len_diff_ratio = len(false_res.body) < max(1, int(len(true_res.body) * 0.4))
                        if false_res.status_code in {404, 500} or (len(true_res.body) >= 100 and len_diff_ratio):
                            ctrl_bool = http_client.probe(f"{target_url}{sep}{param}=1", is_cancelled=is_Canceled)
                            requests_made += 1
                            if ctrl_bool and ctrl_bool.status_code == 200 and abs(len(true_res.body) - len(ctrl_bool.body)) <= 20:
                                blind_boolean_found = True
                                vulnerable_blind_param = param
                                blind_evidence_detail = (
                                    f"Divergência booleana SQLi em '{param}': 1 AND 1=1 (HTTP {true_res.status_code}, {len(true_res.body)}B) "
                                    f"vs 1 AND 1=2 (HTTP {false_res.status_code}, {len(false_res.body)}B)"
                                )
                                break
                except Exception:  # noqa: BLE001, S110
                    pass

        if blind_sqli_found or blind_boolean_found:
            d04_status = CheckStatus.VULNERABILITY if blind_sqli_found else CheckStatus.POTENTIAL_VULNERABILITY
            d04_conf = Confidence.CERTAIN if blind_sqli_found else Confidence.FIRM
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-D04",
                    module_id=self.metadata.module_id,
                    title="Indicadores de SQL Injection Cego Baseado em Tempo / Booleano",
                    status=d04_status,
                    summary=blind_evidence_detail,
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-D04",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-D04", target_url, f"blind-sqli-{vulnerable_blind_param}"
                    ),
                    title=(
                        f"Vulnerabilidade a SQL Injection Cego Baseado em Tempo no Parâmetro '{vulnerable_blind_param}'"
                        if blind_sqli_found
                        else f"Indício de SQL Injection Cego Booleano no Parâmetro '{vulnerable_blind_param}'"
                    ),
                    description=f"O envio de payload de inferência SQL no parâmetro '{vulnerable_blind_param}' induziu resposta diferencial no servidor ({blind_evidence_detail}).",
                    category="Injeção e Persistência Segura",
                    result_classification=d04_status,
                    severity=Severity.HIGH,
                    confidence=d04_conf,
                    evidence=SanitizedEvidence(
                        request_url=target_url,
                        observed_value=blind_evidence_detail,
                        expected_baseline="Consultas parametrizadas que impedem a execução de funções e expressões lógicas SQL",
                    ),
                    owasp_references=["A03:2021-Injection"],
                    cwe_ids=["CWE-89"],
                    impact="Permite extração cega e manipulação de registros de banco de dados via inferência temporal ou booleana.",
                    remediation=RemediationEngine.get_guidance("unparameterized_query_pattern"),
                )
            )
        else:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-D04",
                    module_id=self.metadata.module_id,
                    title="Indicadores de SQL Injection Cego Baseado em Tempo / Booleano",
                    status=CheckStatus.PASSED,
                    summary="Nenhum comportamento diferencial ou retenção temporal detectada nos parâmetros testados.",
                )
            )

        # CHK-D05: Indicadores de Injeção NoSQL, LDAP e XPath
        nosql_ldap_xpath_patterns = [
            (re.compile(r"MongoServerError|MongoError|BSONTypeError|MongoDB\\Driver\\Exception", re.IGNORECASE), "NoSQL/MongoDB Error", "CWE-943"),
            (re.compile(r"CastError:\s*Cast to ObjectId failed", re.IGNORECASE), "Mongoose ObjectId CastError", "CWE-943"),
            (re.compile(r"javax\.naming\.NamingException|LDAPException|Invalid DN syntax|ldap_search\(\)", re.IGNORECASE), "LDAP Injection Error", "CWE-90"),
            (re.compile(r"XPathException|DOMXPath::query\(\)|SimpleXMLElement::xpath\(\)", re.IGNORECASE), "XPath Injection Error", "CWE-643"),
        ]
        baseline_nlx_labels: set[str] = set()
        nlx_detected: tuple[str, str, str, CheckStatus, Confidence] | None = None
        for pat, label, cwe_id in nosql_ldap_xpath_patterns:
            m = pat.search(body_excerpt)
            if m:
                baseline_nlx_labels.add(label)
                if nlx_detected is None:
                    nlx_detected = (label, m.group(0), cwe_id, CheckStatus.POTENTIAL_VULNERABILITY, Confidence.FIRM)

        if nlx_detected is None and http_client and getattr(http_client, "probe", None):
            nlx_params = discovered_d_params if discovered_d_params else ["user", "id", "filter"]
            for param in nlx_params[:2]:
                sep = "&" if "?" in target_url else "?"
                probe_url = f"{target_url}{sep}{param}[$ne]=csc_nosql_probe"
                try:
                    probe_res = http_client.probe(probe_url, is_cancelled=is_Canceled)
                    requests_made += 1
                    if probe_res and probe_res.body:
                        for pat, label, cwe_id in nosql_ldap_xpath_patterns:
                            m = pat.search(probe_res.body)
                            if m and label not in baseline_nlx_labels:
                                nlx_detected = (
                                    label,
                                    f"Erro '{m.group(0)}' disparado via operador '{param}[$ne]'",
                                    cwe_id,
                                    CheckStatus.VULNERABILITY,
                                    Confidence.CERTAIN,
                                )
                                break
                    if nlx_detected:
                        break
                except Exception:  # noqa: BLE001, S110
                    pass

        if nlx_detected:
            nlx_label, nlx_ev, nlx_cwe, nlx_status, nlx_conf = nlx_detected
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-D05",
                    module_id=self.metadata.module_id,
                    title="Indicadores de Injeção NoSQL, LDAP e XPath",
                    status=nlx_status,
                    summary=f"Indicador de injeção {nlx_label} detectado ({nlx_ev}).",
                    details={"error_type": nlx_label, "cwe": nlx_cwe},
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-D05",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-D05", target_url, f"nlx-{nlx_label}"
                    ),
                    title=f"Indicadores de Injeção Estruturada ({nlx_label})",
                    description=(
                        f"A aplicação expôs erro ou comportamento anômalo característico de {nlx_label} "
                        "ao processar filtros ou parâmetros de consulta."
                    ),
                    category="Injeção e Persistência Segura",
                    result_classification=nlx_status,
                    severity=Severity.HIGH,
                    confidence=nlx_conf,
                    evidence=SanitizedEvidence(
                        request_url=target_url,
                        observed_value=nlx_ev,
                        expected_baseline="Validação estrita de tipo primitivo e escape de operadores em consultas NoSQL/LDAP/XPath",
                    ),
                    owasp_references=["A03:2021-Injection"],
                    cwe_ids=[nlx_cwe],
                    impact="Bypass de autenticação ou extração não autorizada de documentos e registros de diretório.",
                    remediation=RemediationEngine.get_guidance("nosql_ldap_xpath_injection"),
                )
            )
        else:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-D05",
                    module_id=self.metadata.module_id,
                    title="Indicadores de Injeção NoSQL, LDAP e XPath",
                    status=CheckStatus.PASSED,
                    summary="Nenhum indicador de erro ou injeção NoSQL, LDAP ou XPath detectado.",
                )
            )

        return _finalize_module_result(
            self.metadata.module_id,
            checks,
            findings,
            total_requests=requests_made,
        )


# =============================================================================
# MÓDULO F — Postura de Proteção e Resiliência contra DoS/DDoS
# =============================================================================
class ModuleFDoSResiliencePosture(BaseSecurityModule):
    """MÓDULO F — Postura de Proteção e Resiliência contra DoS/DDoS."""

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            module_id="mod_f_dos_resilience_posture",
            code="MÓDULO F",
            name="Postura de Proteção e Resiliência contra DoS/DDoS",
            version="1.1.0",
            description=(
                "Avalia de forma passiva e com amostragem conservadora a presença de WAF/CDN, "
                "cabeçalhos de Rate Limiting (RateLimit-*, Retry-After) e limites de tamanho de payload."
            ),
            category="Resiliência Operacional e Limitação de Taxa",
            impact_level=ImpactLevel.LOW_IMPACT_ACTIVE,
            supported_asset_types=[AssetType.WEB_APP, AssetType.REST_API, AssetType.GRAPHQL_API],
            owasp_references=["API4:2023-Unrestricted Resource Consumption"],
            wstg_references=["WSTG-CONF-01", "WSTG-INPV-15"],
            asvs_references=["ASVS-V11.1.4", "ASVS-V13.1"],
            cwe_references=["CWE-770", "CWE-400", "CWE-444", "CWE-349"],
            enabled_by_default=True,
            requires_authentication=False,
            allow_in_production=True,
            checks_catalog=[
                "CHK-F01: Detecção de Controles de Borda (CDN / WAF)",
                "CHK-F02: Presença de Políticas de Rate Limiting (RateLimit-* / X-RateLimit-*)",
                "CHK-F03: Limite de Tamanho de Requisição e Proteção de Endpoints Sensíveis",
                "CHK-F04: Inconsistência de Cabeçalhos HTTP (Risco de HTTP Request Smuggling / Desync)",
                "CHK-F05: Risco de Envenenamento de Cache (Web Cache Poisoning)",
            ],
        )

    def inspect_response_snapshot(
        self,
        target_url: str,
        status_code: int,
        headers: dict[str, str],
        cookies: list[dict[str, Any]] | None = None,
        tls_info: dict[str, Any] | None = None,
        body_excerpt: str = "",
        is_Canceled: Callable[[], bool] | None = None,
        *,
        asset_type: AssetType = AssetType.WEB_APP,
        redirect_chain: list[dict[str, Any]] | None = None,
        raw_set_cookies: list[str] | None = None,
        http_to_https_redirected: bool | None = None,
        initial_url: str | None = None,
        http_client: Any | None = None,
    ) -> ModuleExecutionResult:
        checks: list[CheckEvaluationResult] = []
        findings: list[NormalizedFinding] = []
        parsed = urlparse(target_url)
        hostname = parsed.hostname or "unknown"
        lower_headers = {k.lower(): v for k, v in headers.items()}
        requests_made = 1

        if is_Canceled and is_Canceled():
            return ModuleExecutionResult(module_id=self.metadata.module_id)

        if status_code <= 0:
            return ModuleExecutionResult(
                module_id=self.metadata.module_id,
                checks=[
                    CheckEvaluationResult(
                        check_id="CHK-F01",
                        module_id=self.metadata.module_id,
                        title="Detecção de Controles de Borda (CDN / WAF)",
                        status=CheckStatus.EXECUTION_ERROR,
                        summary="Falha de conexão com o alvo; impossível avaliar controles de borda.",
                    )
                ],
                findings=[],
                total_requests=1,
                execution_errors=1,
            )

        # CHK-F01: Detecção de Controles de Borda (CDN / WAF)
        edge_signatures = {
            "Cloudflare": ["cf-ray", "cf-cache-status"],
            "AWS CloudFront": ["x-amz-cf-id", "x-amz-cf-pop"],
            "Fastly": ["x-fastly-request-id"],
            "Akamai": ["x-akamai-transformed", "akamai-origin-hop"],
            "Imperva/Incapsula": ["x-iinfo", "x-cdn"],
            "Azure Front Door": ["x-azure-ref"],
        }
        detected_edge = []
        for provider, head_keys in edge_signatures.items():
            if any(k in lower_headers for k in head_keys) or provider.lower() in lower_headers.get("server", "").lower():
                detected_edge.append(provider)

        if detected_edge:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-F01",
                    module_id=self.metadata.module_id,
                    title="Detecção de Controles de Borda (CDN / WAF)",
                    status=CheckStatus.PASSED,
                    summary=f"Camada de borda/CDN identificada ({', '.join(detected_edge)}). Nota: WAF não substitui proteção volumétrica dedicada.",
                    details={"providers": detected_edge},
                )
            )
        else:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-F01",
                    module_id=self.metadata.module_id,
                    title="Detecção de Controles de Borda (CDN / WAF)",
                    status=CheckStatus.POTENTIAL_VULNERABILITY,
                    summary="Nenhum indicador de CDN ou Web Application Firewall detectado nos cabeçalhos de resposta.",
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-F01",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-F01", target_url, "missing-edge-waf"
                    ),
                    title="Ausência de Proteção de Borda (CDN / WAF) Detectada",
                    description=(
                        "A aplicação aparenta estar exposta diretamente sem uma camada de filtragem de borda "
                        "(CDN / WAF gerenciado), aumentando o risco diante de ataques volumétricos ou bots."
                    ),
                    category="Resiliência Operacional e Infraestrutura",
                    result_classification=CheckStatus.POTENTIAL_VULNERABILITY,
                    severity=Severity.INFO,
                    confidence=Confidence.FIRM,
                    evidence=SanitizedEvidence(
                        request_url=target_url,
                        observed_value=f"Server: {lower_headers.get('server', 'não informado')}",
                        expected_baseline="Presença de CDN gerenciada (Cloudflare, CloudFront, etc.)",
                    ),
                    owasp_references=["API4:2023-Unrestricted Resource Consumption"],
                    cwe_ids=["CWE-770"],
                    impact="Maior exposição do servidor de origem a tráfego excessivo e escaneamentos automatizados.",
                    remediation=RemediationEngine.get_guidance("missing_waf_cdn_protection"),
                )
            )

        # CHK-F02: Presença de Políticas de Rate Limiting
        rate_headers = [
            "ratelimit-limit",
            "ratelimit-remaining",
            "ratelimit-reset",
            "x-ratelimit-limit",
            "x-ratelimit-remaining",
            "retry-after",
        ]
        found_rate_headers = [k for k in rate_headers if k in lower_headers]
        if found_rate_headers:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-F02",
                    module_id=self.metadata.module_id,
                    title="Presença de Políticas de Rate Limiting",
                    status=CheckStatus.PASSED,
                    summary=f"Cabeçalhos de Rate Limiting ativos detectados: {', '.join(found_rate_headers)}.",
                    details={"rate_headers": found_rate_headers},
                )
            )
        else:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-F02",
                    module_id=self.metadata.module_id,
                    title="Presença de Políticas de Rate Limiting",
                    status=CheckStatus.POTENTIAL_VULNERABILITY,
                    summary="Ausência de cabeçalhos padronizados de Rate Limiting (RateLimit-* / X-RateLimit-*).",
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-F02",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-F02", target_url, "missing-rate-limit-headers"
                    ),
                    title="Ausência de Cabeçalhos de Rate Limiting em Respostas",
                    description=(
                        "O servidor não informa cotas de requisição por cliente via cabeçalhos padronizados "
                        "(RateLimit-Limit / RateLimit-Remaining), reduzindo a transparência e controle de fluxo."
                    ),
                    category="Resiliência Operacional e Limitação de Taxa",
                    result_classification=CheckStatus.POTENTIAL_VULNERABILITY,
                    severity=Severity.LOW,
                    confidence=Confidence.FIRM,
                    evidence=SanitizedEvidence(
                        request_url=target_url,
                        observed_value="Cabeçalhos RateLimit-* ausentes",
                        expected_baseline="Cabeçalhos IETF RateLimit-Limit, RateLimit-Remaining, RateLimit-Reset",
                    ),
                    owasp_references=["API4:2023-Unrestricted Resource Consumption"],
                    cwe_ids=["CWE-770"],
                    impact="Dificulta a adaptação de clientes legítimos e indica potencial ausência de limitação de requisições.",
                    remediation=RemediationEngine.get_guidance("missing_rate_limiting_policy"),
                )
            )

        # CHK-F03: Limite de Tamanho de Requisição e Proteção de Endpoints Sensíveis
        raw_cl = lower_headers.get("content-length", "").strip()
        parsed_cl = int(raw_cl) if raw_cl.isdigit() else 0
        has_ranges = "accept-ranges" in lower_headers
        if parsed_cl > 5 * 1024 * 1024 and not has_ranges:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-F03",
                    module_id=self.metadata.module_id,
                    title="Limite de Tamanho de Requisição e Proteção de Recursos",
                    status=CheckStatus.POTENTIAL_VULNERABILITY,
                    summary=f"Resposta HTTP com payload extenso (Content-Length={parsed_cl} bytes > 5 MB) sem controle de faixas.",
                    details={"content_length": parsed_cl},
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-F03",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-F03", target_url, "excessive-payload-size"
                    ),
                    title="Ausência de Limite de Tamanho de Payload ou Paginação Adequada",
                    description=f"O endpoint retornou resposta de {parsed_cl} bytes (> 5 MB) sem restrições aparentes de paginação ou tamanho máximo.",
                    category="Resiliência Operacional e Limitação de Taxa",
                    result_classification=CheckStatus.POTENTIAL_VULNERABILITY,
                    severity=Severity.LOW,
                    confidence=Confidence.FIRM,
                    evidence=SanitizedEvidence(
                        request_url=target_url,
                        observed_value=f"Content-Length: {parsed_cl} bytes",
                        expected_baseline="Limites explícitos de tamanho de corpo (<= 5 MB) e paginação de respostas",
                    ),
                    owasp_references=["API4:2023-Unrestricted Resource Consumption"],
                    cwe_ids=["CWE-400"],
                    impact="Consumo excessivo de banda e memória facilitando ataques de exaustão de recursos.",
                    remediation=RemediationEngine.get_guidance("unrestricted_payload_resource_consumption"),
                )
            )
        else:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-F03",
                    module_id=self.metadata.module_id,
                    title="Limite de Tamanho de Requisição e Proteção de Recursos",
                    status=CheckStatus.PASSED,
                    summary=f"Tamanho de resposta controlado (Content-Length={parsed_cl or 'streaming/bounded'}) sem sinais de exaustão.",
                )
            )

        # CHK-F04: Inconsistência de Cabeçalhos HTTP (Risco de HTTP Request Smuggling / Desync)
        smuggling_risk = False
        smuggling_evidence = ""
        if "content-length" in lower_headers and "transfer-encoding" in lower_headers:
            smuggling_risk = True
            smuggling_evidence = (
                f"Resposta recebida com cabeçalhos conflitantes: Content-Length ({lower_headers['content-length']}) "
                f"e Transfer-Encoding ({lower_headers['transfer-encoding']})"
            )
        elif http_client and getattr(http_client, "probe", None):
            try:
                probe_res = http_client.probe(
                    target_url,
                    method="POST",
                    headers={"Transfer-Encoding": "chunked", "Content-Length": "4"},
                    is_cancelled=is_Canceled,
                )
                if probe_res:
                    requests_made += 1
                    resp_headers = _safe_probe_headers(probe_res)
                    if probe_res.status_code == 200 and ("transfer-encoding" in resp_headers or "content-length" in resp_headers):
                        smuggling_risk = True
                        smuggling_evidence = "Servidor aceitou payload com Transfer-Encoding e Content-Length simultâneos sem rejeição (HTTP 400)"
            except Exception:  # noqa: BLE001, S110
                pass

        if smuggling_risk:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-F04",
                    module_id=self.metadata.module_id,
                    title="Inconsistência de Cabeçalhos HTTP (Risco de HTTP Request Smuggling / Desync)",
                    status=CheckStatus.POTENTIAL_VULNERABILITY,
                    summary=f"Inconsistência de enquadramento HTTP detectada ({smuggling_evidence}).",
                    details={"evidence": smuggling_evidence},
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-F04",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-F04", target_url, "http-smuggling-risk"
                    ),
                    title="Risco de HTTP Request Smuggling / Dessincronização de Proxies (TE/CL Ambíguo)",
                    description=(
                        "A infraestrutura aceita requisições com cabeçalhos conflitantes de enquadramento HTTP "
                        "(Content-Length e Transfer-Encoding simultâneos) sem rejeição estrita (HTTP 400), "
                        "o que pode possibilitar ataques de dessincronização entre reverse proxy e origin server."
                    ),
                    category="Resiliência Operacional e Infraestrutura",
                    result_classification=CheckStatus.POTENTIAL_VULNERABILITY,
                    severity=Severity.HIGH,
                    confidence=Confidence.FIRM,
                    evidence=SanitizedEvidence(
                        request_url=target_url,
                        observed_value=smuggling_evidence,
                        expected_baseline="Rejeição estrita com HTTP 400 Bad Request ou normalização imediata pelo proxy reverso (RFC 9112)",
                    ),
                    owasp_references=["API4:2023-Unrestricted Resource Consumption", "A05:2021-Security Misconfiguration"],
                    cwe_ids=["CWE-444"],
                    impact="Dessincronização de filas de requisições HTTP permitindo envenenamento de cache, sequestro de requisições de outros usuários ou bypass de controles de autenticação.",
                    remediation=RemediationEngine.get_guidance("http_request_smuggling_desync_risk"),
                )
            )
        else:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-F04",
                    module_id=self.metadata.module_id,
                    title="Inconsistência de Cabeçalhos HTTP (Risco de HTTP Request Smuggling / Desync)",
                    status=CheckStatus.PASSED,
                    summary="Enquadramento de mensagens HTTP e conformidade de cabeçalhos RFC 9112 validados sem inconsistências.",
                )
            )

        # CHK-F05: Risco de Envenenamento de Cache (Web Cache Poisoning)
        cache_poison_reflected = False
        cache_poison_public = False
        cache_canary = "canary.csc-cache-poison.internal"
        if http_client and getattr(http_client, "probe", None) and cache_canary not in body_excerpt:
            try:
                cp_res = http_client.probe(
                    target_url,
                    headers={"X-Forwarded-Host": cache_canary, "X-Forwarded-Scheme": "http"},
                    is_cancelled=is_Canceled,
                )
                requests_made += 1
                if cp_res:
                    cp_headers = _safe_probe_headers(cp_res)
                    cp_loc = cp_headers.get("location", "").lower()
                    if cache_canary in (cp_res.body or "").lower() or cache_canary in cp_loc:
                        cache_poison_reflected = True
                        merged_cc = (cp_headers.get("cache-control", "") or lower_headers.get("cache-control", "")).lower()
                        max_age_m = re.search(r"max-age\s*=\s*(\d+)", merged_cc)
                        cache_poison_public = (
                            "public" in merged_cc
                            or (
                                max_age_m is not None
                                and int(max_age_m.group(1)) > 0
                                and "private" not in merged_cc
                                and "no-store" not in merged_cc
                            )
                            or "x-cache" in cp_headers
                            or "x-cache" in lower_headers
                            or "cf-cache-status" in cp_headers
                            or "age" in cp_headers
                        )
            except Exception:  # noqa: BLE001, S110
                pass

        if cache_poison_reflected:
            f05_status = CheckStatus.VULNERABILITY if cache_poison_public else CheckStatus.POTENTIAL_VULNERABILITY
            f05_sev = Severity.HIGH if cache_poison_public else Severity.MEDIUM
            f05_conf = Confidence.CERTAIN if cache_poison_public else Confidence.FIRM
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-F05",
                    module_id=self.metadata.module_id,
                    title="Risco de Envenenamento de Cache (Web Cache Poisoning)",
                    status=f05_status,
                    summary=(
                        f"Cabeçalho não chaveado X-Forwarded-Host refletido com cache público ativo ({cache_canary})."
                        if cache_poison_public
                        else f"Cabeçalho X-Forwarded-Host refletido na resposta ({cache_canary}), criando risco de Web Cache Poisoning."
                    ),
                    details={"canary": cache_canary, "public_cache_headers": cache_poison_public},
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-F05",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-F05", target_url, "web-cache-poisoning"
                    ),
                    title="Risco de Web Cache Poisoning via Cabeçalhos Não Chaveados (X-Forwarded-Host)",
                    description=(
                        "A aplicação incorpora o valor do cabeçalho X-Forwarded-Host na resposta ou em redirecionamentos "
                        "sem incluí-lo na chave de cache, permitindo contaminação de respostas em cache compartilhado."
                    ),
                    category="Resiliência Operacional e Infraestrutura",
                    result_classification=f05_status,
                    severity=f05_sev,
                    confidence=f05_conf,
                    evidence=SanitizedEvidence(
                        request_url=target_url,
                        observed_value=f"X-Forwarded-Host '{cache_canary}' refletido (cache_publico={cache_poison_public})",
                        expected_baseline="Ignorar cabeçalhos X-Forwarded-Host não confiáveis ou usar domínio canônico fixo",
                    ),
                    owasp_references=["API4:2023-Unrestricted Resource Consumption", "A05:2021-Security Misconfiguration"],
                    cwe_ids=["CWE-444", "CWE-349"],
                    impact="Redirecionamento ou entrega de scripts maliciosos armazenados em cache para todos os visitantes.",
                    remediation=RemediationEngine.get_guidance("web_cache_poisoning_unkeyed_headers"),
                )
            )
        else:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-F05",
                    module_id=self.metadata.module_id,
                    title="Risco de Envenenamento de Cache (Web Cache Poisoning)",
                    status=CheckStatus.PASSED,
                    summary="Nenhuma reflexão de cabeçalhos não chaveados (X-Forwarded-Host) detectada.",
                )
            )

        return _finalize_module_result(
            self.metadata.module_id,
            checks,
            findings,
            total_requests=requests_made,
        )


# =============================================================================
# MÓDULO G — Segurança de APIs REST e GraphQL
# =============================================================================
class ModuleGAPISecurity(BaseSecurityModule):
    """MÓDULO G — Segurança de APIs REST e GraphQL."""

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            module_id="mod_g_api_security",
            code="MÓDULO G",
            name="Segurança de APIs REST e GraphQL",
            version="1.1.0",
            description=(
                "Verifica políticas de CORS, exposição de especificações OpenAPI/Swagger, introspecção GraphQL, "
                "métodos HTTP permitidos, cabeçalhos de cache e tratamento de erros em APIs."
            ),
            category="Segurança de APIs (OWASP API Top 10)",
            impact_level=ImpactLevel.LOW_IMPACT_ACTIVE,
            supported_asset_types=[AssetType.REST_API, AssetType.GRAPHQL_API],
            owasp_references=[
                "API1:2023-Broken Object Level Authorization",
                "API3:2023-Broken Object Property Level Authorization",
                "API8:2023-Security Misconfiguration",
                "API9:2023-Improper Inventory Management",
            ],
            wstg_references=["WSTG-APIT-01", "WSTG-CLNT-07"],
            asvs_references=["ASVS-V13", "ASVS-V14.5"],
            cwe_references=["CWE-942", "CWE-200", "CWE-213", "CWE-639", "CWE-345", "CWE-347"],
            enabled_by_default=True,
            requires_authentication=False,
            allow_in_production=True,
            checks_catalog=[
                "CHK-G01: Configuração Insegura de CORS (Access-Control-Allow-Origin / Credentials)",
                "CHK-G02: Exposição Pública de Documentação OpenAPI/Swagger e GraphQL Introspection",
                "CHK-G03: Métodos HTTP Desnecessários e Cabeçalhos de Cache em Respostas de API",
                "CHK-G04: Verificação Ativa de Métodos HTTP Perigosos (Verb Tampering & XST)",
                "CHK-G05: Configuração e Validação Insegura de Tokens JWT (Chaves Fracas / Algoritmo Permissivo)",
                "CHK-G06: Exposição Excessiva de Dados Sensíveis em APIs (BOPLA / OWASP API3:2023)",
                "CHK-G07: Introspecção e Sugestões de Esquema GraphQL Expostas Publicamente",
            ],
        )

    def inspect_response_snapshot(
        self,
        target_url: str,
        status_code: int,
        headers: dict[str, str],
        cookies: list[dict[str, Any]] | None = None,
        tls_info: dict[str, Any] | None = None,
        body_excerpt: str = "",
        is_Canceled: Callable[[], bool] | None = None,
        *,
        asset_type: AssetType = AssetType.WEB_APP,
        redirect_chain: list[dict[str, Any]] | None = None,
        raw_set_cookies: list[str] | None = None,
        http_to_https_redirected: bool | None = None,
        initial_url: str | None = None,
        http_client: Any | None = None,
    ) -> ModuleExecutionResult:
        checks: list[CheckEvaluationResult] = []
        findings: list[NormalizedFinding] = []
        parsed = urlparse(target_url)
        hostname = parsed.hostname or "unknown"
        lower_headers = {k.lower(): v for k, v in headers.items()}
        requests_made = 1

        if is_Canceled and is_Canceled():
            return ModuleExecutionResult(module_id=self.metadata.module_id)

        if status_code <= 0:
            return ModuleExecutionResult(
                module_id=self.metadata.module_id,
                checks=[
                    CheckEvaluationResult(
                        check_id="CHK-G01",
                        module_id=self.metadata.module_id,
                        title="Configuração de CORS em Endpoints de API",
                        status=CheckStatus.EXECUTION_ERROR,
                        summary="Falha de conexão com o endpoint de API.",
                    )
                ],
                findings=[],
                total_requests=1,
                execution_errors=1,
            )

        # CHK-G01: Configuração Insegura de CORS
        allow_origin = lower_headers.get("access-control-allow-origin", "").strip()
        allow_credentials = lower_headers.get("access-control-allow-credentials", "").strip().lower()

        if allow_origin == "*" and allow_credentials == "true":
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-G01",
                    module_id=self.metadata.module_id,
                    title="Configuração Insegura de CORS",
                    status=CheckStatus.VULNERABILITY,
                    summary="CORS configurado com wildcard '*' em conjunto com Allow-Credentials 'true'.",
                    details={"allow_origin": allow_origin, "allow_credentials": allow_credentials},
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-G01",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-G01", target_url, "cors-wildcard-credentials"
                    ),
                    title="Configuração Inválida e Insegura de CORS (Wildcard com Credenciais)",
                    description="A resposta combina 'Access-Control-Allow-Origin: *' com 'Access-Control-Allow-Credentials: true', uma configuração insegura e rejeitada por navegadores.",
                    category="Segurança de APIs e CORS",
                    result_classification=CheckStatus.VULNERABILITY,
                    severity=Severity.HIGH,
                    confidence=Confidence.CERTAIN,
                    evidence=SanitizedEvidence(
                        request_url=target_url,
                        observed_value=f"Allow-Origin: {allow_origin}, Allow-Credentials: {allow_credentials}",
                        expected_baseline="Lista explícita de domínios permitidos em Allow-Origin",
                    ),
                    owasp_references=["API8:2023-Security Misconfiguration"],
                    cwe_ids=["CWE-942"],
                    impact="Permite que domínios arbitrários realizem requisições autenticadas para ler dados da API.",
                    remediation=RemediationEngine.get_guidance("insecure_cors_policy"),
                )
            )
        elif allow_origin == "null":
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-G01",
                    module_id=self.metadata.module_id,
                    title="Configuração Insegura de CORS",
                    status=CheckStatus.POTENTIAL_VULNERABILITY,
                    summary="CORS configurado com 'Access-Control-Allow-Origin: null', permitindo requisições de documentos locais/sandboxed.",
                    details={"allow_origin": "null"},
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-G01",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-G01", target_url, "cors-origin-null"
                    ),
                    title="Política de CORS com Origem 'null' Habilitada",
                    description="O valor 'null' em Access-Control-Allow-Origin pode ser explorado por iframes sandboxed para realizar requisições cross-origin.",
                    category="Segurança de APIs e CORS",
                    result_classification=CheckStatus.POTENTIAL_VULNERABILITY,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.FIRM,
                    evidence=SanitizedEvidence(
                        request_url=target_url,
                        observed_value="Access-Control-Allow-Origin: null",
                        expected_baseline="Origem restrita a domínio específico",
                    ),
                    owasp_references=["API8:2023-Security Misconfiguration"],
                    cwe_ids=["CWE-942"],
                    impact="Bypass de políticas cross-origin via origens anônimas.",
                    remediation=RemediationEngine.get_guidance("insecure_cors_policy"),
                )
            )
        else:
            # Teste ativo de reflexão arbitrária de origem
            active_cors_reflection_vuln = False
            attacker_origin = "https://attacker.csc-test.internal"
            if http_client and getattr(http_client, "probe", None):
                try:
                    cors_probe = http_client.probe(
                        target_url,
                        headers={"Origin": attacker_origin},
                        is_cancelled=is_Canceled,
                    )
                    requests_made += 1
                    if cors_probe:
                        probe_lower_headers = _safe_probe_headers(cors_probe)
                        resp_origin = probe_lower_headers.get("access-control-allow-origin", "").strip()
                        resp_creds = probe_lower_headers.get("access-control-allow-credentials", "").strip().lower()
                        if resp_origin == attacker_origin and resp_creds == "true":
                            active_cors_reflection_vuln = True
                except Exception:  # noqa: BLE001, S110
                    pass

            if active_cors_reflection_vuln:
                checks.append(
                    CheckEvaluationResult(
                        check_id="CHK-G01",
                        module_id=self.metadata.module_id,
                        title="Configuração Insegura de CORS",
                        status=CheckStatus.VULNERABILITY,
                        summary="A API reflete arbitrariamente qualquer cabeçalho 'Origin' em conjunto com 'Access-Control-Allow-Credentials: true'.",
                        details={"reflected_origin": attacker_origin, "credentials": "true"},
                    )
                )
                findings.append(
                    NormalizedFinding(
                        endpoint=target_url,
                        module_id=self.metadata.module_id,
                        check_id="CHK-G01",
                        fingerprint=RiskEngine.compute_finding_fingerprint(
                            hostname, self.metadata.module_id, "CHK-G01", target_url, "cors-arbitrary-reflection"
                        ),
                        title="Reflexão Arbitrária de Origem CORS com Credenciais Habilitadas",
                        description=(
                            "A API respondeu ao cabeçalho Origin arbitrário ('https://attacker.csc-test.internal') "
                            "refletindo-o em 'Access-Control-Allow-Origin' e autorizando 'Access-Control-Allow-Credentials: true'. "
                            "Isso permite que qualquer website malicioso leia dados confidenciais e autenticados de usuários."
                        ),
                        category="Segurança de APIs e CORS",
                        result_classification=CheckStatus.VULNERABILITY,
                        severity=Severity.HIGH,
                        confidence=Confidence.CERTAIN,
                        evidence=SanitizedEvidence(
                            request_url=target_url,
                            observed_value=f"Allow-Origin: {attacker_origin}, Allow-Credentials: true",
                            expected_baseline="Lista explícita e fixa de origens confiáveis sem reflexão cega",
                        ),
                        owasp_references=["API8:2023-Security Misconfiguration"],
                        cwe_ids=["CWE-942", "CWE-346"],
                        impact="Exfiltração de dados confidenciais e chamadas à API autenticadas via navegador de vítimas.",
                        remediation=RemediationEngine.get_guidance("cors_arbitrary_origin"),
                    )
                )
            else:
                checks.append(
                    CheckEvaluationResult(
                        check_id="CHK-G01",
                        module_id=self.metadata.module_id,
                        title="Configuração Insegura de CORS",
                        status=CheckStatus.PASSED,
                        summary="Configuração de cabeçalhos CORS segura ou não exposta publicamente.",
                        details={"allow_origin": allow_origin or "não configurado"},
                    )
                )

        # CHK-G02: Exposição Pública de Documentação OpenAPI/Swagger e GraphQL Introspection
        docs_exposed = False
        docs_path = ""
        if any(p in parsed.path.lower() for p in ["/openapi.json", "/swagger.json", "/docs", "/api-docs"]):
            docs_exposed = True
            docs_path = parsed.path
        elif http_client and getattr(http_client, "probe", None):
            origin = f"{parsed.scheme}://{parsed.netloc}"
            for doc_candidate, doc_marker in (
                ("/openapi.json", '"openapi"'),
                ("/swagger.json", '"swagger"'),
            ):
                if is_Canceled and is_Canceled():
                    break
                try:
                    probe_res = http_client.probe(f"{origin}{doc_candidate}", is_cancelled=is_Canceled)
                    requests_made += 1
                    if (
                        probe_res
                        and probe_res.status_code == 200
                        and doc_marker in probe_res.body
                        and not _is_soft_404_html(probe_res.body, body_excerpt)
                    ):
                        docs_exposed = True
                        docs_path = doc_candidate
                        break
                except Exception:  # noqa: BLE001, S110
                    pass

        if docs_exposed:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-G02",
                    module_id=self.metadata.module_id,
                    title="Exposição Pública de Documentação OpenAPI/Swagger",
                    status=CheckStatus.POTENTIAL_VULNERABILITY,
                    summary=f"Especificação OpenAPI/Swagger acessível publicamente em '{docs_path}'.",
                    details={"path": docs_path},
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-G02",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-G02", target_url, "public-openapi-docs"
                    ),
                    title="Especificação OpenAPI/Swagger Exposta Publicamente",
                    description=f"A documentação técnica da API está exposta em '{docs_path}' sem autenticação, facilitando a enumeração de rotas e parâmetros.",
                    category="Gerenciamento de Superfície de Ataque e Inventário",
                    result_classification=CheckStatus.POTENTIAL_VULNERABILITY,
                    severity=Severity.LOW,
                    confidence=Confidence.CERTAIN,
                    evidence=SanitizedEvidence(
                        request_url=target_url,
                        observed_value=f"Documentação pública em {docs_path}",
                        expected_baseline="Documentação desabilitada em produção ou restrita por autenticação",
                    ),
                    owasp_references=["API9:2023-Improper Inventory Management"],
                    cwe_ids=["CWE-200"],
                    impact="Facilita o mapeamento da superfície de ataque da API por agentes maliciosos.",
                    remediation=RemediationEngine.get_guidance("public_api_docs_or_graphql_introspection"),
                )
            )
        else:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-G02",
                    module_id=self.metadata.module_id,
                    title="Exposição Pública de Documentação OpenAPI/Swagger",
                    status=CheckStatus.PASSED,
                    summary="Documentação de API protegida ou não identificada publicamente.",
                )
            )

        # CHK-G03: Métodos HTTP Desnecessários e Cabeçalhos de Cache em Respostas de API
        allow_methods = lower_headers.get("allow", "").upper()
        cache_control = lower_headers.get("cache-control", "").lower()
        has_trace = "TRACE" in allow_methods or "TRACK" in allow_methods
        body_lower = (body_excerpt or "").lower()
        sensitive_api_payload = any(
            tok in body_lower
            for tok in ('"access_token"', '"refresh_token"', '"api_key"', '"client_secret"', '"password"')
        )
        public_cache_sensitive = ("public" in cache_control) and sensitive_api_payload

        if has_trace:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-G03",
                    module_id=self.metadata.module_id,
                    title="Métodos HTTP Desnecessários e Cabeçalhos de Cache",
                    status=CheckStatus.POTENTIAL_VULNERABILITY,
                    summary="Método HTTP inseguro TRACE/TRACK indicado nos métodos permitidos.",
                    details={"allow": allow_methods},
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-G03",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-G03", target_url, "trace-method-enabled"
                    ),
                    title="Método HTTP TRACE Habilitado na API",
                    description="O método TRACE ecoa o conteúdo recebido pelo servidor e pode ser utilizado para capturar cookies HttpOnly (Cross-Site Tracing).",
                    category="Configurações de Segurança e Métodos HTTP",
                    result_classification=CheckStatus.POTENTIAL_VULNERABILITY,
                    severity=Severity.LOW,
                    confidence=Confidence.FIRM,
                    evidence=SanitizedEvidence(
                        request_url=target_url,
                        observed_value=f"Allow: {allow_methods}",
                        expected_baseline="Métodos TRACE e TRACK desabilitados no servidor web",
                    ),
                    owasp_references=["API8:2023-Security Misconfiguration"],
                    cwe_ids=["CWE-200"],
                    impact="Potencial exfiltração de tokens via Cross-Site Tracing (XST).",
                    remediation=RemediationEngine.get_guidance("insecure_api_http_methods_and_cache"),
                )
            )
        elif public_cache_sensitive:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-G03",
                    module_id=self.metadata.module_id,
                    title="Métodos HTTP Desnecessários e Cabeçalhos de Cache",
                    status=CheckStatus.VULNERABILITY,
                    summary="Resposta de API com tokens ou credenciais marcada com Cache-Control público.",
                    details={"cache_control": cache_control},
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-G03",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-G03", target_url, "public-cache-sensitive-api"
                    ),
                    title="Cache Público Habilitado em Resposta Sensível de API",
                    description="A API retornou credenciais ou tokens acompanhados da diretiva 'Cache-Control: public', permitindo armazenamento em proxies compartilhados e CDNs.",
                    category="Configurações de Segurança e Métodos HTTP",
                    result_classification=CheckStatus.VULNERABILITY,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CERTAIN,
                    evidence=SanitizedEvidence(
                        request_url=target_url,
                        observed_value=f"Cache-Control: {cache_control}",
                        expected_baseline="Cache-Control: no-store, no-cache, private em respostas autenticadas/sensíveis",
                    ),
                    owasp_references=["API8:2023-Security Misconfiguration"],
                    cwe_ids=["CWE-524", "CWE-200"],
                    impact="Risco de vazamento de tokens de acesso armazenados em caches intermediários compartilhados.",
                    remediation=RemediationEngine.get_guidance("insecure_api_http_methods_and_cache"),
                )
            )
        else:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-G03",
                    module_id=self.metadata.module_id,
                    title="Métodos HTTP Desnecessários e Cabeçalhos de Cache",
                    status=CheckStatus.PASSED,
                    summary="Métodos HTTP permitidos e diretivas de cache da API adequados.",
                    details={"allow": allow_methods or "não especificado", "cache_control": cache_control or "padrão"},
                )
            )

        # CHK-G04: Verificação Ativa de Métodos HTTP Perigosos (Verb Tampering & XST)
        trace_active_vulnerable = False
        if http_client and getattr(http_client, "probe", None):
            canary_header_val = "csc_xst_audit_canary_718"
            try:
                trace_res = http_client.probe(
                    target_url,
                    method="TRACE",
                    headers={"X-CSC-Audit-Token": canary_header_val},
                    is_cancelled=is_Canceled,
                )
                requests_made += 1
                if trace_res and trace_res.status_code == 200 and canary_header_val in trace_res.body:
                    trace_active_vulnerable = True
            except Exception:  # noqa: BLE001, S110
                pass

        if trace_active_vulnerable:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-G04",
                    module_id=self.metadata.module_id,
                    title="Verificação Ativa de Métodos HTTP Perigosos (Verb Tampering & XST)",
                    status=CheckStatus.VULNERABILITY,
                    summary="O método TRACE está ativo e ecoou cabeçalhos de requisição na resposta (Vulnerabilidade a Cross-Site Tracing / XST).",
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-G04",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-G04", target_url, "xst-active-trace-confirmed"
                    ),
                    title="Método HTTP TRACE Ativo com Eco de Cabeçalhos (XST Confirmado)",
                    description="O servidor web aceitou o método TRACE com status HTTP 200 e ecoou cabeçalhos confidenciais da requisição. Isso permite que invasores explorem XSS para extrair cookies marcados com HttpOnly.",
                    category="Configurações de Segurança e Métodos HTTP",
                    result_classification=CheckStatus.VULNERABILITY,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CERTAIN,
                    evidence=SanitizedEvidence(
                        request_url=target_url,
                        observed_value="HTTP 200 OK com eco do cabeçalho de teste X-CSC-Audit-Token",
                        expected_baseline="HTTP 405 Method Not Allowed ou HTTP 501 Not Implemented para TRACE",
                    ),
                    owasp_references=["API8:2023-Security Misconfiguration"],
                    cwe_ids=["CWE-650", "CWE-200"],
                    impact="Bypass da proteção HttpOnly via Cross-Site Tracing.",
                    remediation=RemediationEngine.get_guidance("http_dangerous_methods"),
                )
            )
        else:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-G04",
                    module_id=self.metadata.module_id,
                    title="Verificação Ativa de Métodos HTTP Perigosos (Verb Tampering & XST)",
                    status=CheckStatus.PASSED,
                    summary="Método TRACE desabilitado ou rejeitado com segurança pelo servidor.",
                )
            )

        # CHK-G05: Configuração e Validação Insegura de Tokens JWT (Chaves Fracas / Algoritmo Permissivo)
        jwt_pattern = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_-]*)?\b")
        found_jwt = None
        for h_val in headers.values():
            m = jwt_pattern.search(h_val)
            if m:
                found_jwt = m.group(0)
                break
        if not found_jwt and body_excerpt:
            m = jwt_pattern.search(body_excerpt)
            if m:
                found_jwt = m.group(0)

        if found_jwt:
            jwt_issue = None
            jwt_severity = Severity.HIGH
            jwt_parts = found_jwt.split(".")
            try:
                def _b64_url_decode(segment: str) -> dict[str, Any]:
                    padding = len(segment) % 4
                    if padding:
                        segment += "=" * (4 - padding)
                    decoded = base64.urlsafe_b64decode(segment.encode("ascii", errors="ignore"))
                    return json.loads(decoded.decode("utf-8", errors="ignore"))

                jwt_header = _b64_url_decode(jwt_parts[0])
                jwt_payload = _b64_url_decode(jwt_parts[1]) if len(jwt_parts) > 1 else {}
                alg = str(jwt_header.get("alg", "")).lower()

                if alg in ("none", "") or len(jwt_parts) < 3 or not jwt_parts[2]:
                    jwt_issue = "Token JWT configurado com algoritmo 'none' ou assinatura vazia (permite falsificação total de identidade)"
                    jwt_severity = Severity.CRITICAL
                elif alg in ("hs256", "hs384", "hs512"):
                    hash_map = {
                        "hs256": hashlib.sha256,
                        "hs384": hashlib.sha384,
                        "hs512": hashlib.sha512,
                    }
                    signing_input = f"{jwt_parts[0]}.{jwt_parts[1]}".encode("ascii", errors="ignore")
                    weak_secrets = (
                        "secret",
                        "password",
                        "123456",
                        "jwt_secret",
                        "changeme",
                        "dev",
                        "default",
                        "admin",
                        "your-256-bit-secret",
                    )
                    for candidate_secret in weak_secrets:
                        digest = hmac.new(
                            candidate_secret.encode("utf-8"),
                            signing_input,
                            hash_map[alg],
                        ).digest()
                        encoded_sig = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
                        if hmac.compare_digest(encoded_sig, jwt_parts[2]):
                            jwt_issue = (
                                "Token JWT assinado com segredo HMAC fraco/previsível "
                                "(sujeito a forja imediata de assinatura)"
                            )
                            jwt_severity = Severity.CRITICAL
                            break

                if not jwt_issue:
                    if any(k in jwt_header for k in ("jku", "x5u", "jwk")):
                        jwt_issue = (
                            "Cabeçalho JWT contém parâmetro externo/embutido de chave "
                            "('jku'/'x5u'/'jwk') com risco de SSRF ou falsificação de assinatura"
                        )
                        jwt_severity = Severity.HIGH
                    elif isinstance(jwt_header.get("kid"), str) and any(
                        tok in str(jwt_header.get("kid")) for tok in ("../", "..\\", "'", '"', ";")
                    ):
                        jwt_issue = "Parâmetro 'kid' do cabeçalho JWT contém sequência suspeita de injeção/traversal"
                        jwt_severity = Severity.HIGH
                    elif "exp" not in jwt_payload:
                        jwt_issue = "Token JWT sem claim de expiração ('exp'), permitindo sessões perpétuas"
                        jwt_severity = Severity.HIGH
            except Exception:  # noqa: BLE001
                jwt_issue = None

            if jwt_issue:
                checks.append(
                    CheckEvaluationResult(
                        check_id="CHK-G05",
                        module_id=self.metadata.module_id,
                        title="Configuração e Validação Insegura de Tokens JWT",
                        status=CheckStatus.VULNERABILITY,
                        summary=f"Token JWT inseguro detectado: {jwt_issue}.",
                        details={"issue": jwt_issue, "severity": jwt_severity.value},
                    )
                )
                findings.append(
                    NormalizedFinding(
                        endpoint=target_url,
                        module_id=self.metadata.module_id,
                        check_id="CHK-G05",
                        fingerprint=RiskEngine.compute_finding_fingerprint(
                            hostname, self.metadata.module_id, "CHK-G05", target_url, "insecure-jwt-config"
                        ),
                        title="Configuração Insegura de Token JWT (Algoritmo/Segredo Fraco ou Cabeçalho Permissivo)",
                        description=(
                            f"A inspeção criptográfica de tokens emitidos revelou vulnerabilidade: {jwt_issue}. "
                            "Isso pode permitir a falsificação de tokens sem conhecimento da chave privada ou a persistência perpétua de credenciais vazadas."
                        ),
                        category="Segurança de APIs e Criptografia",
                        result_classification=CheckStatus.VULNERABILITY,
                        severity=jwt_severity,
                        confidence=Confidence.CERTAIN,
                        evidence=SanitizedEvidence(
                            request_url=target_url,
                            observed_value=f"Token JWT detectado: {jwt_issue}",
                            expected_baseline="Assinatura assimétrica obrigatória (RS256/EdDSA) ou segredo HMAC de alta entropia, com 'exp' estrita e bloqueio de 'none'/'jku'",
                        ),
                        owasp_references=["API2:2023-Broken Authentication"],
                        cwe_ids=["CWE-345", "CWE-347"],
                        impact="Falsificação de credenciais e elevação não autorizada de privilégios na API.",
                        remediation=RemediationEngine.get_guidance("insecure_jwt_token_configuration"),
                    )
                )
            else:
                checks.append(
                    CheckEvaluationResult(
                        check_id="CHK-G05",
                        module_id=self.metadata.module_id,
                        title="Configuração e Validação Insegura de Tokens JWT",
                        status=CheckStatus.PASSED,
                        summary="Token JWT analisado possui assinatura criptográfica forte, cabeçalho seguro e claim de expiração (exp).",
                    )
                )
        else:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-G05",
                    module_id=self.metadata.module_id,
                    title="Configuração e Validação Insegura de Tokens JWT",
                    status=CheckStatus.PASSED,
                    summary="Nenhum token JWT inseguro detectado nos cabeçalhos ou no corpo da resposta da API.",
                )
            )

        # CHK-G06: Exposição Excessiva de Dados Sensíveis em APIs (BOPLA / OWASP API3:2023)
        sensitive_bopla_fields: list[str] = []
        is_schema_doc = ('"openapi"' in (body_excerpt or "")) or ('"swagger"' in (body_excerpt or ""))
        if body_excerpt and not is_schema_doc:
            bopla_pattern = re.compile(
                r'"(password_hash|hashed_password|password_salt|private_key|secret_key|mfa_secret|totp_secret|cvv|credit_card_number|ssn)"\s*:',
                re.IGNORECASE,
            )
            for match in bopla_pattern.finditer(body_excerpt):
                field_name = match.group(1)
                if field_name.lower() not in [x.lower() for x in sensitive_bopla_fields]:
                    sensitive_bopla_fields.append(field_name)

        if sensitive_bopla_fields:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-G06",
                    module_id=self.metadata.module_id,
                    title="Exposição Excessiva de Dados Sensíveis em APIs (BOPLA)",
                    status=CheckStatus.VULNERABILITY,
                    summary=(
                        f"Campos internos sensíveis expostos na resposta da API: {', '.join(sensitive_bopla_fields[:5])}."
                    ),
                    details={"exposed_fields": sensitive_bopla_fields[:10]},
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-G06",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-G06", target_url, "bopla-sensitive-fields"
                    ),
                    title="Exposição Excessiva de Propriedades Sensíveis em Resposta de API (BOPLA)",
                    description=(
                        f"O payload JSON retornado pela API expõe propriedades internas sensíveis "
                        f"({', '.join(sensitive_bopla_fields[:5])}) sem filtragem por DTO ou serializer restritivo."
                    ),
                    category="Segurança de APIs e Privacidade de Dados (OWASP API3:2023)",
                    result_classification=CheckStatus.VULNERABILITY,
                    severity=Severity.HIGH,
                    confidence=Confidence.CERTAIN,
                    evidence=SanitizedEvidence(
                        request_url=target_url,
                        observed_value=f"Propriedades JSON detectadas: {', '.join(sensitive_bopla_fields[:5])}",
                        expected_baseline="Serialização restrita apenas aos atributos públicos necessários via schema/DTO explícito",
                    ),
                    owasp_references=["API3:2023-Broken Object Property Level Authorization"],
                    cwe_ids=["CWE-213", "CWE-200", "CWE-359"],
                    impact="Vazamento direto de hashes de senha, segredos criptográficos/MFA ou dados financeiros em respostas de API.",
                    remediation=RemediationEngine.get_guidance("api_excessive_data_exposure_bopla"),
                )
            )
        else:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-G06",
                    module_id=self.metadata.module_id,
                    title="Exposição Excessiva de Dados Sensíveis em APIs (BOPLA)",
                    status=CheckStatus.PASSED,
                    summary="Nenhum campo interno sensível (hashes de senha, chaves privadas, segredos MFA ou CVV) identificado na resposta.",
                )
            )

        # CHK-G07: Introspecção e Sugestões de Esquema GraphQL Expostas Publicamente
        graphql_issue_status: CheckStatus | None = None
        graphql_issue_summary = ""
        graphql_observed = ""
        body_str = body_excerpt or ""
        if ('"__schema"' in body_str or '"__type"' in body_str) and (
            '"queryType"' in body_str or '"types"' in body_str or '"data"' in body_str
        ):
            graphql_issue_status = CheckStatus.VULNERABILITY
            graphql_issue_summary = "Schema GraphQL de introspecção (__schema/__type) retornado na resposta."
            graphql_observed = "Resposta contém payload de introspecção GraphQL (__schema)"
        elif "Cannot query field" in body_str and "Did you mean" in body_str:
            graphql_issue_status = CheckStatus.POTENTIAL_VULNERABILITY
            graphql_issue_summary = "Motor GraphQL ativo com sugestões de campo habilitadas em mensagens de erro."
            graphql_observed = "Erro GraphQL com 'Cannot query field ... Did you mean'"
        elif http_client and getattr(http_client, "probe", None):
            origin = f"{parsed.scheme}://{parsed.netloc}"
            gql_base = f"{origin}{parsed.path}" if "graphql" in parsed.path.lower() else f"{origin}/graphql"
            gql_probe_url = f"{gql_base}?query=%7B__schema%7BqueryType%7Bname%7D%7D%7D"
            try:
                gql_res = http_client.probe(gql_probe_url, is_cancelled=is_Canceled)
                requests_made += 1
                if gql_res and gql_res.status_code == 200 and not _is_soft_404_html(gql_res.body, body_excerpt):
                    if '"__schema"' in gql_res.body and ('"queryType"' in gql_res.body or '"data"' in gql_res.body):
                        graphql_issue_status = CheckStatus.VULNERABILITY
                        graphql_issue_summary = f"Introspecção GraphQL habilitada publicamente em '{gql_base}'."
                        graphql_observed = f"GET {gql_probe_url} retornou HTTP 200 com '__schema'"
                    elif "Cannot query field" in gql_res.body and "Did you mean" in gql_res.body:
                        graphql_issue_status = CheckStatus.POTENTIAL_VULNERABILITY
                        graphql_issue_summary = f"Sugestões de schema GraphQL habilitadas em '{gql_base}'."
                        graphql_observed = "Erro GraphQL com 'Did you mean' detectado na sonda"
            except Exception:  # noqa: BLE001, S110
                pass

        if graphql_issue_status is not None:
            is_confirmed_gql = graphql_issue_status == CheckStatus.VULNERABILITY
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-G07",
                    module_id=self.metadata.module_id,
                    title="Introspecção e Sugestões de Esquema GraphQL Expostas",
                    status=graphql_issue_status,
                    summary=graphql_issue_summary,
                    details={"observed": graphql_observed},
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-G07",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-G07", target_url, "graphql-introspection-exposed"
                    ),
                    title="Introspecção ou Enumeração de Esquema GraphQL Exposta Publicamente",
                    description=(
                        f"{graphql_issue_summary} A exposição do grafo completo de tipos, queries e mutations "
                        "permite mapear operações internas e facilita ataques de batching ou profundidade excessiva."
                    ),
                    category="Segurança de APIs GraphQL e Inventário",
                    result_classification=graphql_issue_status,
                    severity=Severity.MEDIUM if is_confirmed_gql else Severity.LOW,
                    confidence=Confidence.CERTAIN if is_confirmed_gql else Confidence.FIRM,
                    evidence=SanitizedEvidence(
                        request_url=target_url,
                        observed_value=graphql_observed,
                        expected_baseline="Introspecção (__schema) e sugestões de erro desabilitadas em produção",
                    ),
                    owasp_references=["API8:2023-Security Misconfiguration", "API9:2023-Improper Inventory Management"],
                    cwe_ids=["CWE-200"],
                    impact="Enumeração completa de tipos, mutações administrativas e superfície de ataque GraphQL.",
                    remediation=RemediationEngine.get_guidance("graphql_introspection_and_batching_exposure"),
                )
            )
        else:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-G07",
                    module_id=self.metadata.module_id,
                    title="Introspecção e Sugestões de Esquema GraphQL Expostas",
                    status=CheckStatus.PASSED,
                    summary="Introspecção e sugestões de esquema GraphQL não expostas publicamente.",
                )
            )

        return _finalize_module_result(self.metadata.module_id, checks, findings, requests_made)


# =============================================================================
# MÓDULO H — Configurações Inseguras, Exposição de Arquivos e Controle de Acesso
# =============================================================================
class ModuleHMisconfigAndOther(BaseSecurityModule):
    """MÓDULO H — Configurações Inseguras, Exposição de Arquivos e Controle de Acesso."""

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            module_id="mod_h_misconfig_and_other",
            code="MÓDULO H",
            name="Configurações Inseguras, Exposição de Arquivos e Controle de Acesso",
            version="1.1.0",
            description=(
                "Avalia exposição de arquivos sensíveis (.env, .git/config, backups), Directory Listing, "
                "Open Redirect e proteção contra CSRF em formulários."
            ),
            category="Configuração e Controle de Acesso",
            impact_level=ImpactLevel.LOW_IMPACT_ACTIVE,
            supported_asset_types=[AssetType.WEB_APP, AssetType.REST_API],
            owasp_references=[
                "A01:2021-Broken Access Control",
                "A05:2021-Security Misconfiguration",
            ],
            wstg_references=["WSTG-CONF-04", "WSTG-ATHZ-01", "WSTG-CLNT-04"],
            asvs_references=["ASVS-V4", "ASVS-V14"],
            cwe_references=["CWE-352", "CWE-538", "CWE-540", "CWE-548", "CWE-601", "CWE-644", "CWE-306"],
            enabled_by_default=True,
            requires_authentication=False,
            allow_in_production=True,
            checks_catalog=[
                "CHK-H01: Exposição de Arquivos Sensíveis e Metadados de Sistema",
                "CHK-H02: Detecção de Directory Listing Habilitado",
                "CHK-H03: Proteção contra Redirecionamento Aberto (Open Redirect)",
                "CHK-H04: Proteção contra Cross-Site Request Forgery (CSRF)",
                "CHK-H05: Detecção de Path Traversal / Local File Inclusion (LFI)",
                "CHK-H06: Indicadores de Server-Side Request Forgery (SSRF) no Alvo",
                "CHK-H07: Exposição de Interfaces de Administração e Depuração (Admin/Actuator/Debug Panels)",
                "CHK-H08: Injeção de Cabeçalho Host (Host Header Injection / Web Cache & Password Reset Poisoning)",
                "CHK-H09: Exposição de Source Maps (.js.map) e Artefatos de Build/Infraestrutura",
            ],
        )

    def inspect_response_snapshot(
        self,
        target_url: str,
        status_code: int,
        headers: dict[str, str],
        cookies: list[dict[str, Any]] | None = None,
        tls_info: dict[str, Any] | None = None,
        body_excerpt: str = "",
        is_Canceled: Callable[[], bool] | None = None,
        *,
        asset_type: AssetType = AssetType.WEB_APP,
        redirect_chain: list[dict[str, Any]] | None = None,
        raw_set_cookies: list[str] | None = None,
        http_to_https_redirected: bool | None = None,
        initial_url: str | None = None,
        http_client: Any | None = None,
    ) -> ModuleExecutionResult:
        checks: list[CheckEvaluationResult] = []
        findings: list[NormalizedFinding] = []
        parsed = urlparse(target_url)
        hostname = parsed.hostname or "unknown"
        lower_headers = {k.lower(): v for k, v in headers.items()}
        requests_made = 1

        if is_Canceled and is_Canceled():
            return ModuleExecutionResult(module_id=self.metadata.module_id)

        if status_code <= 0:
            return ModuleExecutionResult(
                module_id=self.metadata.module_id,
                checks=[
                    CheckEvaluationResult(
                        check_id="CHK-H01",
                        module_id=self.metadata.module_id,
                        title="Exposição de Arquivos Sensíveis e Metadados de Sistema",
                        status=CheckStatus.EXECUTION_ERROR,
                        summary="Falha de conexão com o alvo.",
                    )
                ],
                findings=[],
                total_requests=1,
                execution_errors=1,
            )

        # CHK-H01: Exposição de Arquivos Sensíveis e Metadados de Sistema
        sensitive_exposed = None
        sensitive_file_probes = [
            ("/.env", ["DATABASE_URL", "SECRET_KEY", "PASSWORD", "APP_KEY", "_KEY=", "_SECRET="]),
            ("/.git/HEAD", ["ref: refs/"]),
            ("/.git/config", ["[core]", "repositoryformatversion"]),
            ("/.env.local", ["DATABASE", "KEY=", "SECRET="]),
            ("/backup.sql", ["CREATE TABLE", "INSERT INTO", "-- MySQL dump", "-- PostgreSQL"]),
            ("/dump.sql", ["CREATE TABLE", "INSERT INTO"]),
            ("/docker-compose.yml", ["services:", "version:"]),
            ("/web.config", ["<configuration>", "<system.webServer>"]),
            ("/package.json", ['"name":', '"dependencies":']),
        ]
        if any(parsed.path.lower().endswith(ext) for ext in [".env", ".git/config", "backup.sql", "dump.sql"]):
            if status_code == 200 and any(s in body_excerpt for s in ["=", "[core]", "DATABASE", "CREATE TABLE"]):
                sensitive_exposed = parsed.path
        elif http_client and getattr(http_client, "probe", None):
            origin = f"{parsed.scheme}://{parsed.netloc}"
            for spath, signatures in sensitive_file_probes:
                if is_Canceled and is_Canceled():
                    break
                try:
                    probe_res = http_client.probe(f"{origin}{spath}", is_cancelled=is_Canceled)
                    requests_made += 1
                    if (
                        probe_res
                        and probe_res.status_code == 200
                        and not _is_soft_404_html(probe_res.body, body_excerpt)
                        and any(k in probe_res.body for k in signatures)
                    ):
                        sensitive_exposed = spath
                        break
                except Exception:  # noqa: BLE001, S110
                    pass

        if sensitive_exposed:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-H01",
                    module_id=self.metadata.module_id,
                    title="Exposição de Arquivos Sensíveis e Metadados de Sistema",
                    status=CheckStatus.VULNERABILITY,
                    summary=f"Arquivo sensível exposto publicamente com status 200: '{sensitive_exposed}'.",
                    details={"path": sensitive_exposed},
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-H01",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-H01", target_url, "sensitive-file-leak"
                    ),
                    title="Arquivo de Configuração Sensível (.env / git) Exposto Publicamente",
                    description=f"O caminho '{sensitive_exposed}' está acessível publicamente, revelando dados confidenciais de ambiente.",
                    category="Configuração e Controle de Acesso",
                    result_classification=CheckStatus.VULNERABILITY,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CERTAIN,
                    evidence=SanitizedEvidence(
                        request_url=target_url,
                        observed_value=f"Arquivo {sensitive_exposed} acessível com HTTP 200",
                        expected_baseline="Bloqueio total com HTTP 404/403 para arquivos ocultos e de configuração",
                    ),
                    owasp_references=["A05:2021-Security Misconfiguration"],
                    cwe_ids=["CWE-538"],
                    impact="Vazamento direto de senhas, credenciais de banco e chaves de API da aplicação.",
                    remediation=RemediationEngine.get_guidance("sensitive_files_exposure"),
                )
            )
        else:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-H01",
                    module_id=self.metadata.module_id,
                    title="Exposição de Arquivos Sensíveis e Metadados de Sistema",
                    status=CheckStatus.PASSED,
                    summary="Nenhum arquivo de configuração ou controle de versão exposto publicamente.",
                )
            )

        # CHK-H02: Detecção de Directory Listing Habilitado
        dir_listing_patterns = [
            re.compile(r"<title>Index of /", re.IGNORECASE),
            re.compile(r"<h1>Index of /", re.IGNORECASE),
            re.compile(r"\[To Parent Directory\]", re.IGNORECASE),
            re.compile(r"Directory Listing For /", re.IGNORECASE),
        ]
        has_dir_listing = any(p.search(body_excerpt) for p in dir_listing_patterns)
        if has_dir_listing:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-H02",
                    module_id=self.metadata.module_id,
                    title="Detecção de Directory Listing Habilitado",
                    status=CheckStatus.VULNERABILITY,
                    summary="Listagem automática de diretórios (Directory Listing / Index of) habilitada no servidor.",
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-H02",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-H02", target_url, "directory-listing-enabled"
                    ),
                    title="Indexação e Listagem de Diretórios Habilitada no Servidor Web",
                    description="O servidor web permite a navegação e listagem pública de pastas e arquivos locais.",
                    category="Configuração e Controle de Acesso",
                    result_classification=CheckStatus.VULNERABILITY,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CERTAIN,
                    evidence=SanitizedEvidence(
                        request_url=target_url,
                        observed_value="Padrão 'Index of /' identificado no HTML",
                        expected_baseline="autoindex off (Nginx) ou Options -Indexes (Apache)",
                    ),
                    owasp_references=["A05:2021-Security Misconfiguration"],
                    cwe_ids=["CWE-548"],
                    impact="Permite download de backups, arquivos residuais e enumeração de arquivos da aplicação.",
                    remediation=RemediationEngine.get_guidance("directory_listing_enabled"),
                )
            )
        else:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-H02",
                    module_id=self.metadata.module_id,
                    title="Detecção de Directory Listing Habilitado",
                    status=CheckStatus.PASSED,
                    summary="Listagem de diretórios desabilitada ou não identificada.",
                )
            )

        # CHK-H03: Proteção contra Redirecionamento Aberto (Open Redirect)
        open_redirect_found = False
        redirect_param_names = ["redirect", "url", "next", "return_to", "goto", "dest"]
        qs = parse_qs(parsed.query)
        for rparam in redirect_param_names:
            if rparam in qs:
                for rval in qs[rparam]:
                    normalized_rval = rval.strip().replace("\\", "/")
                    if normalized_rval.startswith(("http://", "https://", "//")):
                        dest_url = normalized_rval if "://" in normalized_rval else f"https:{normalized_rval}"
                        dest_host = urlparse(dest_url).hostname or ""
                        if dest_host and dest_host.lower() != hostname:
                            loc_head = lower_headers.get("location", "")
                            if loc_head and dest_host.lower() in loc_head.lower():
                                open_redirect_found = True
                                break

        # Prova ativa de Open Redirect quando http_client estiver disponível
        if not open_redirect_found and http_client and getattr(http_client, "probe", None):
            canary_candidates = [
                "https://canary.csc-redirect.internal",
                "//canary.csc-redirect.internal",
                "/\\canary.csc-redirect.internal",
            ]
            test_params = [p for p in qs if p in redirect_param_names]
            if not test_params and parsed.path.rstrip("/").split("/")[-1] in ("login", "redirect", "auth"):
                test_params = ["next", "redirect"]
            for rparam in test_params[:2]:
                if open_redirect_found or (is_Canceled and is_Canceled()):
                    break
                for canary_target in canary_candidates:
                    if is_Canceled and is_Canceled():
                        break
                    probe_qs = dict(qs)
                    probe_qs[rparam] = [canary_target]
                    probe_url = urlunparse((
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        urlencode(probe_qs, doseq=True),
                        parsed.fragment,
                    ))
                    try:
                        probe_res = http_client.probe(probe_url, is_cancelled=is_Canceled)
                        requests_made += 1
                        if probe_res and probe_res.status_code in (301, 302, 303, 307, 308):
                            loc_header = _safe_probe_headers(probe_res).get("location", "")
                            if "canary.csc-redirect.internal" in loc_header.lower():
                                open_redirect_found = True
                                break
                    except Exception:  # noqa: BLE001, S110
                        pass

        if open_redirect_found:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-H03",
                    module_id=self.metadata.module_id,
                    title="Proteção contra Redirecionamento Aberto (Open Redirect)",
                    status=CheckStatus.VULNERABILITY,
                    summary="Parâmetro de redirecionamento aceita domínios externos arbitrários sem validação.",
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-H03",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-H03", target_url, "open-redirect-arbitrary"
                    ),
                    title="Redirecionamento Aberto para Destino Externo Arbitrário (Open Redirect)",
                    description="A aplicação redireciona usuários para domínios externos sem validação de whitelist.",
                    category="Controle de Acesso e Redirecionamento",
                    result_classification=CheckStatus.VULNERABILITY,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.FIRM,
                    evidence=SanitizedEvidence(
                        request_url=target_url,
                        observed_value="Location reflete parâmetro externo",
                        expected_baseline="Redirecionamento restrito a caminhos relativos ou domínios explicitamente permitidos",
                    ),
                    owasp_references=["A01:2021-Broken Access Control"],
                    cwe_ids=["CWE-601"],
                    impact="Facilita campanhas de phishing e roubo de credenciais utilizando a reputação do domínio confiável.",
                    remediation=RemediationEngine.get_guidance("open_redirect_vulnerability"),
                )
            )
        else:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-H03",
                    module_id=self.metadata.module_id,
                    title="Proteção contra Redirecionamento Aberto (Open Redirect)",
                    status=CheckStatus.PASSED,
                    summary="Parâmetros de redirecionamento validados ou ausentes.",
                )
            )

        # CHK-H04: Proteção contra Cross-Site Request Forgery (CSRF)
        post_forms = re.findall(r'<form[^>]+method=["\']?post["\']?[^>]*>(.*?)</form>', body_excerpt, re.DOTALL | re.IGNORECASE)
        csrf_missing_form = False
        if post_forms:
            csrf_tokens = ["csrf_token", "csrfmiddlewaretoken", "_csrf", "authenticity_token", "__requestverificationtoken"]
            has_samesite_cookie = any(
                "samesite=strict" in c.lower() or "samesite=lax" in c.lower()
                for c in (raw_set_cookies or [])
            )
            for fcontent in post_forms:
                if not any(t in fcontent.lower() for t in csrf_tokens) and not has_samesite_cookie:
                    csrf_missing_form = True
                    break

        if csrf_missing_form:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-H04",
                    module_id=self.metadata.module_id,
                    title="Proteção contra Cross-Site Request Forgery (CSRF)",
                    status=CheckStatus.POTENTIAL_VULNERABILITY,
                    summary="Formulário POST identificado sem campo de token anti-CSRF e sem cookies SameSite de proteção.",
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-H04",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-H04", target_url, "missing-csrf-token"
                    ),
                    title="Formulário POST sem Proteção contra Cross-Site Request Forgery (CSRF)",
                    description="O formulário HTML realiza requisições POST que alteram estado sem token anti-CSRF e sem cookie com atributo SameSite.",
                    category="Configuração e Controle de Acesso",
                    result_classification=CheckStatus.POTENTIAL_VULNERABILITY,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.FIRM,
                    evidence=SanitizedEvidence(
                        request_url=target_url,
                        observed_value="Formulário POST sem token CSRF",
                        expected_baseline="Uso de Synchronizer Token Pattern e cookies de sessão com SameSite=Lax",
                    ),
                    owasp_references=["A01:2021-Broken Access Control"],
                    cwe_ids=["CWE-352"],
                    impact="Permite que páginas maliciosas de terceiros forjem requisições não autorizadas em nome do usuário autenticado.",
                    remediation=RemediationEngine.get_guidance("missing_anti_csrf_protection"),
                )
            )
        else:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-H04",
                    module_id=self.metadata.module_id,
                    title="Proteção contra Cross-Site Request Forgery (CSRF)",
                    status=CheckStatus.PASSED,
                    summary="Mecanismos anti-CSRF (tokens ou cookies SameSite) identificados ou inexistência de formulários POST desprotegidos.",
                )
            )

        # CHK-H05: Detecção de Path Traversal / Local File Inclusion (LFI)
        lfi_detected = False
        lfi_evidence_val = ""
        linux_passwd_regex = re.compile(r"root:[^:]*:[0-9]+:[0-9]+:[^:]*:[^:]*:", re.IGNORECASE)
        win_ini_regex = re.compile(r"\[(fonts|extensions|mci extensions|files)\]", re.IGNORECASE)

        if linux_passwd_regex.search(body_excerpt):
            lfi_detected = True
            lfi_evidence_val = "Assinatura do /etc/passwd detectada na resposta inicial"
        elif win_ini_regex.search(body_excerpt):
            lfi_detected = True
            lfi_evidence_val = "Assinatura do win.ini detectada na resposta inicial"

        if not lfi_detected and http_client and getattr(http_client, "probe", None):
            qs_lfi = parse_qs(parsed.query)
            candidate_params = list(qs_lfi.keys()) if qs_lfi else ["file", "page", "path", "doc", "view", "include"]
            lfi_payloads = [
                "../../../../../../../../etc/passwd",
                "..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd",
                "..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
            ]
            for param in candidate_params[:3]:
                if is_Canceled and is_Canceled():
                    break
                for payload in lfi_payloads:
                    if is_Canceled and is_Canceled():
                        break
                    probe_params = dict(qs_lfi)
                    probe_params[param] = [payload]
                    probe_url = urlunparse((
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        urlencode(probe_params, doseq=True),
                        parsed.fragment,
                    ))
                    try:
                        probe_res = http_client.probe(probe_url, is_cancelled=is_Canceled)
                        requests_made += 1
                        if probe_res and probe_res.status_code == 200:
                            if linux_passwd_regex.search(probe_res.body):
                                lfi_detected = True
                                lfi_evidence_val = f"Conteúdo de /etc/passwd vazado via parâmetro '{param}={payload}'"
                                break
                            if win_ini_regex.search(probe_res.body):
                                lfi_detected = True
                                lfi_evidence_val = f"Conteúdo de win.ini vazado via parâmetro '{param}={payload}'"
                                break
                    except Exception:  # noqa: BLE001, S110
                        pass
                if lfi_detected:
                    break

        if lfi_detected:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-H05",
                    module_id=self.metadata.module_id,
                    title="Detecção de Path Traversal / Local File Inclusion (LFI)",
                    status=CheckStatus.VULNERABILITY,
                    summary="Vulnerabilidade de Path Traversal / LFI confirmada: acesso a arquivos locais do sistema.",
                    details={"evidence": lfi_evidence_val},
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-H05",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-H05", target_url, "path-traversal-lfi"
                    ),
                    title="Vulnerabilidade de Path Traversal / Inclusão de Arquivos Locais (LFI)",
                    description="O alvo permite navegação em diretórios e leitura arbitrária de arquivos do sistema operacional através de sequências '../' ou '..\\'.",
                    category="Configuração e Controle de Acesso",
                    result_classification=CheckStatus.VULNERABILITY,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CERTAIN,
                    evidence=SanitizedEvidence(
                        request_url=target_url,
                        observed_value=lfi_evidence_val,
                        expected_baseline="Validação estrita de nomes de arquivos com whitelist e canonicalização de caminhos com restrição de diretório raiz",
                    ),
                    owasp_references=["A01:2021-Broken Access Control"],
                    cwe_ids=["CWE-22"],
                    impact="Permite leitura de arquivos confidenciais do sistema (/etc/passwd, configurações, chaves privadas) e potencial execução de código remoto.",
                    safe_reproduction_steps=[
                        f"Enviar requisição HTTP para {target_url} com parâmetro de caminho contendo sequências de traversal ('../../etc/passwd')."
                    ],
                    remediation=RemediationEngine.get_guidance("path_traversal_lfi"),
                )
            )
        else:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-H05",
                    module_id=self.metadata.module_id,
                    title="Detecção de Path Traversal / Local File Inclusion (LFI)",
                    status=CheckStatus.PASSED,
                    summary="Nenhum indicador de Path Traversal ou vazamento de arquivos locais identificado.",
                )
            )

        # CHK-H06: Indicadores de Server-Side Request Forgery (SSRF) no Alvo
        ssrf_detected = False
        ssrf_evidence_val = ""
        ssrf_error_patterns = [
            re.compile(r"getaddrinfo.*canary\.csc-ssrf-probe\.internal", re.IGNORECASE),
            re.compile(r"Could not resolve host.*canary\.csc-ssrf-probe\.internal", re.IGNORECASE),
            re.compile(r"Failed to connect to canary\.csc-ssrf-probe\.internal", re.IGNORECASE),
            re.compile(r"Name or service not known", re.IGNORECASE),
            re.compile(r"socket\.gaierror", re.IGNORECASE),
            re.compile(r"ConnectionRefusedError", re.IGNORECASE),
            re.compile(r"cURL error 6:", re.IGNORECASE),
        ]
        if http_client and getattr(http_client, "probe", None):
            qs_ssrf = parse_qs(parsed.query)
            ssrf_candidates = [
                p for p in qs_ssrf
                if p.lower() in ("url", "dest", "target", "uri", "webhook", "feed", "link", "callback", "src")
            ]
            if not ssrf_candidates and not qs_ssrf:
                ssrf_candidates = ["url", "target", "dest", "webhook"]
            canary_probe_target = "http://canary.csc-ssrf-probe.internal/csc_token"
            for sparam in ssrf_candidates[:2]:
                if is_Canceled and is_Canceled():
                    break
                probe_params = dict(qs_ssrf)
                probe_params[sparam] = [canary_probe_target]
                probe_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    urlencode(probe_params, doseq=True),
                    parsed.fragment,
                ))
                try:
                    probe_res = http_client.probe(probe_url, is_cancelled=is_Canceled)
                    requests_made += 1
                    if probe_res and probe_res.body:
                        for pattern in ssrf_error_patterns:
                            m = pattern.search(probe_res.body)
                            if m:
                                ssrf_detected = True
                                ssrf_evidence_val = (
                                    f"Erro de rede de backend exposto ('{m.group(0)}') "
                                    f"ao fornecer canary probe no parâmetro '{sparam}'"
                                )
                                break
                except Exception:  # noqa: BLE001, S110
                    pass
                if ssrf_detected:
                    break

        if ssrf_detected:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-H06",
                    module_id=self.metadata.module_id,
                    title="Indicadores de Server-Side Request Forgery (SSRF) no Alvo",
                    status=CheckStatus.POTENTIAL_VULNERABILITY,
                    summary="O alvo revelou erros internos de conexão ao tentar resolver URL externa arbitrária fornecida como entrada.",
                    details={"evidence": ssrf_evidence_val},
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-H06",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-H06", target_url, "ssrf-target-vulnerability"
                    ),
                    title="Indicadores de Server-Side Request Forgery (SSRF) no Alvo",
                    description="A aplicação auditada processa parâmetros contendo URLs e tenta efetuar conexões de rede no backend, expondo erros de socket ou resolução DNS.",
                    category="Configuração e Controle de Acesso",
                    result_classification=CheckStatus.POTENTIAL_VULNERABILITY,
                    severity=Severity.HIGH,
                    confidence=Confidence.FIRM,
                    evidence=SanitizedEvidence(
                        request_url=target_url,
                        observed_value=ssrf_evidence_val,
                        expected_baseline="Validação estrita de URLs recebidas com whitelist de domínios permitidos e desabilitação de conexões arbitrárias no backend",
                    ),
                    owasp_references=["A10:2021-Server-Side Request Forgery (SSRF)"],
                    cwe_ids=["CWE-918"],
                    impact="Permite que invasores induzam o servidor a realizar requisições não autorizadas contra serviços internos da rede local, instâncias de metadados de nuvem e portas restritas.",
                    safe_reproduction_steps=[
                        f"Enviar requisição HTTP para {target_url} fornecendo canary probe URL e verificar se ocorrem tentativas de conexão no backend."
                    ],
                    remediation=RemediationEngine.get_guidance("ssrf_target_vulnerability"),
                )
            )
        else:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-H06",
                    module_id=self.metadata.module_id,
                    title="Indicadores de Server-Side Request Forgery (SSRF) no Alvo",
                    status=CheckStatus.PASSED,
                    summary="Nenhum indicador de processamento inseguro de requisições de backend (SSRF) identificado.",
                )
            )

        # CHK-H07: Exposição de Interfaces de Administração e Depuração (Admin/Actuator/Debug Panels)
        admin_debug_probes = [
            ("/admin", ["Dashboard", "Administration", "Django administration", "Admin Panel", "Laravel Nova", "phpMyAdmin"]),
            ("/actuator/health", ['"status"', "UP", "DOWN"]),
            ("/actuator/env", ["activeProfiles", "propertySources"]),
            ("/swagger-ui.html", ["Swagger UI", "swagger-ui"]),
            ("/_profiler", ["Symfony Profiler", "Web Profiler"]),
            ("/phpinfo.php", ["PHP Version", "Configuration File"]),
        ]
        admin_exposed_path = None
        admin_evidence = ""
        current_path_clean = parsed.path.rstrip("/")
        for apath, signatures in admin_debug_probes:
            if current_path_clean == apath and status_code == 200 and any(s.lower() in body_excerpt.lower() for s in signatures):
                admin_exposed_path = apath
                admin_evidence = f"Interface administrativa acessível diretamente sem autenticação em '{apath}' (HTTP 200)"
                break

        if not admin_exposed_path and http_client and getattr(http_client, "probe", None):
            origin = f"{parsed.scheme}://{parsed.netloc}"
            for apath, signatures in admin_debug_probes:
                if is_Canceled and is_Canceled():
                    break
                try:
                    probe_res = http_client.probe(f"{origin}{apath}", is_cancelled=is_Canceled)
                    requests_made += 1
                    if probe_res and probe_res.status_code == 200 and any(s.lower() in probe_res.body.lower() for s in signatures):
                        admin_exposed_path = apath
                        admin_evidence = f"Interface administrativa acessível publicamente em '{apath}' (HTTP 200)"
                        break
                except Exception:  # noqa: BLE001, S110
                    pass

        if admin_exposed_path:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-H07",
                    module_id=self.metadata.module_id,
                    title="Exposição de Interfaces de Administração e Depuração (Admin/Actuator/Debug Panels)",
                    status=CheckStatus.VULNERABILITY,
                    summary=f"Painel administrativo ou interface de diagnóstico exposta publicamente: {admin_evidence}.",
                    details={"path": admin_exposed_path, "evidence": admin_evidence},
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-H07",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-H07", target_url, "admin-debug-interface-leak"
                    ),
                    title=f"Interface de Administração ou Depuração Exposta Publicamente ({admin_exposed_path})",
                    description=(
                        "Painéis administrativos, interfaces de gerenciamento ou endpoints de métricas internas "
                        "(como Spring Actuator, Swagger UI ou Django Admin) estão acessíveis diretamente sem "
                        "restrição de rede ou autenticação prévia, permitindo reconhecimento e controle indevido."
                    ),
                    category="Configuração e Controle de Acesso",
                    result_classification=CheckStatus.VULNERABILITY,
                    severity=Severity.HIGH,
                    confidence=Confidence.CERTAIN,
                    evidence=SanitizedEvidence(
                        request_url=target_url,
                        observed_value=admin_evidence,
                        expected_baseline="Restrição estrita por VPN, IP allowlist ou autenticação multifator antes de qualquer exposição",
                    ),
                    owasp_references=["A01:2021-Broken Access Control", "A05:2021-Security Misconfiguration"],
                    cwe_ids=["CWE-306", "CWE-200"],
                    impact="Acesso não autorizado a funções de gerenciamento, configuração de ambiente e dados internos de operação.",
                    remediation=RemediationEngine.get_guidance("exposed_admin_or_debug_interface"),
                )
            )
        else:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-H07",
                    module_id=self.metadata.module_id,
                    title="Exposição de Interfaces de Administração e Depuração (Admin/Actuator/Debug Panels)",
                    status=CheckStatus.PASSED,
                    summary="Nenhum painel administrativo ou endpoint de diagnóstico exposto publicamente sem autenticação.",
                )
            )

        # CHK-H08: Injeção de Cabeçalho Host (Host Header Injection / Web Cache & Password Reset Poisoning)
        host_injection_evidence = ""
        if http_client and getattr(http_client, "probe", None):
            canary_host = "canary.csc-host-inject.internal"
            try:
                host_probe = http_client.probe(
                    target_url,
                    headers={"X-Forwarded-Host": canary_host},
                    is_cancelled=is_Canceled,
                )
                requests_made += 1
                if host_probe:
                    hp_headers = _safe_probe_headers(host_probe)
                    hp_loc = hp_headers.get("location", "")
                    if canary_host in hp_loc.lower():
                        host_injection_evidence = f"Location redirecionou para domínio injetado: {hp_loc[:120]}"
                    elif host_probe.body and re.search(
                        r'(?:href|src|action|canonical|url|https?:)\s*[=:]\s*["\']?(?:https?:)?//[^"\'>\s]*canary\.csc-host-inject\.internal',
                        host_probe.body,
                        re.IGNORECASE,
                    ):
                        host_injection_evidence = (
                            "X-Forwarded-Host injetado refletido em URL/link absoluto no corpo HTML"
                        )
            except Exception:  # noqa: BLE001, S110
                pass

        if host_injection_evidence:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-H08",
                    module_id=self.metadata.module_id,
                    title="Injeção de Cabeçalho Host (Host Header Injection)",
                    status=CheckStatus.VULNERABILITY,
                    summary="Aplicação confiou no cabeçalho X-Forwarded-Host e o refletiu em redirecionamentos ou links.",
                    details={"evidence": host_injection_evidence},
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-H08",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-H08", target_url, "host-header-injection"
                    ),
                    title="Injeção de Cabeçalho Host (Host Header Injection / X-Forwarded-Host)",
                    description=(
                        f"Ao enviar um cabeçalho X-Forwarded-Host arbitrário, o servidor gerou URLs absolutas ou redirecionamentos "
                        f"confiando no domínio injetado ({host_injection_evidence}). Isso viabiliza envenenamento de e-mails de "
                        "redefinição de senha e cache poisoning."
                    ),
                    category="Configuração e Controle de Acesso",
                    result_classification=CheckStatus.VULNERABILITY,
                    severity=Severity.HIGH,
                    confidence=Confidence.CERTAIN,
                    evidence=SanitizedEvidence(
                        request_url=target_url,
                        observed_value=host_injection_evidence,
                        expected_baseline="Ignorar X-Forwarded-Host não confiável e validar Host contra allowlist explícita",
                    ),
                    owasp_references=["A05:2021-Security Misconfiguration", "A04:2021-Insecure Design"],
                    cwe_ids=["CWE-644", "CWE-20"],
                    impact="Sequestro de tokens em links de redefinição de senha e envenenamento de cache web.",
                    remediation=RemediationEngine.get_guidance("host_header_injection"),
                )
            )
        else:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-H08",
                    module_id=self.metadata.module_id,
                    title="Injeção de Cabeçalho Host (Host Header Injection)",
                    status=CheckStatus.PASSED,
                    summary="Cabeçalho X-Forwarded-Host não refletido em links absolutos nem em cabeçalhos Location.",
                )
            )

        # CHK-H09: Exposição de Source Maps (.js.map) e Artefatos de Build/Infraestrutura
        exposed_artifact = ""
        artifact_confidence = Confidence.FIRM
        sourcemap_header = (lower_headers.get("sourcemap") or lower_headers.get("x-sourcemap") or "").strip()
        sourcemap_match = re.search(r"sourceMappingURL=([^\s<>\"']+\.map)", body_excerpt or "", re.IGNORECASE)
        map_ref = sourcemap_header or (sourcemap_match.group(1).strip() if sourcemap_match else "")

        if map_ref:
            if http_client and getattr(http_client, "probe", None):
                resolved_map = urljoin(target_url, map_ref)
                if urlparse(resolved_map).netloc == parsed.netloc:
                    try:
                        map_res = http_client.probe(resolved_map, is_cancelled=is_Canceled)
                        requests_made += 1
                        if (
                            map_res
                            and map_res.status_code == 200
                            and '"version"' in map_res.body
                            and '"sources"' in map_res.body
                            and not _is_soft_404_html(map_res.body, body_excerpt)
                        ):
                            exposed_artifact = f"Source Map acessível em {urlparse(resolved_map).path}"
                            artifact_confidence = Confidence.CERTAIN
                    except Exception:  # noqa: BLE001, S110
                        pass
            else:
                exposed_artifact = f"Referência de Source Map exposta: {map_ref[:100]}"

        if not exposed_artifact:
            if parsed.path.lower().endswith("/dockerfile") and status_code == 200 and "FROM " in (body_excerpt or ""):
                exposed_artifact = "Arquivo Dockerfile acessível diretamente no endpoint"
                artifact_confidence = Confidence.CERTAIN
            elif http_client and getattr(http_client, "probe", None):
                origin = f"{parsed.scheme}://{parsed.netloc}"
                try:
                    docker_res = http_client.probe(f"{origin}/Dockerfile", is_cancelled=is_Canceled)
                    requests_made += 1
                    if (
                        docker_res
                        and docker_res.status_code == 200
                        and not _is_soft_404_html(docker_res.body, body_excerpt)
                        and "FROM " in docker_res.body
                        and any(kw in docker_res.body for kw in ("RUN ", "WORKDIR ", "COPY ", "EXPOSE ", "CMD "))
                    ):
                        exposed_artifact = "Dockerfile exposto publicamente em /Dockerfile"
                        artifact_confidence = Confidence.CERTAIN
                except Exception:  # noqa: BLE001, S110
                    pass

        if exposed_artifact:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-H09",
                    module_id=self.metadata.module_id,
                    title="Exposição de Source Maps e Artefatos de Build",
                    status=CheckStatus.POTENTIAL_VULNERABILITY,
                    summary=f"Artefato de build ou código-fonte reconstruível exposto: {exposed_artifact}.",
                    details={"artifact": exposed_artifact},
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-H09",
                    fingerprint=RiskEngine.compute_finding_fingerprint(
                        hostname, self.metadata.module_id, "CHK-H09", target_url, "exposed-sourcemaps-or-build-artifacts"
                    ),
                    title="Exposição de Source Maps (.js.map) ou Artefato de Build/Infraestrutura",
                    description=(
                        f"Foi detectada a exposição de artefato técnico de construção ({exposed_artifact}), "
                        "permitindo reconstrução do código-fonte original ou mapeamento detalhado da imagem e dependências do serviço."
                    ),
                    category="Configuração e Controle de Acesso",
                    result_classification=CheckStatus.POTENTIAL_VULNERABILITY,
                    severity=Severity.LOW,
                    confidence=artifact_confidence,
                    evidence=SanitizedEvidence(
                        request_url=target_url,
                        observed_value=exposed_artifact,
                        expected_baseline="Remover arquivos .map e artefatos de build/Dockerfile da raiz pública de produção",
                    ),
                    owasp_references=["A05:2021-Security Misconfiguration"],
                    cwe_ids=["CWE-540", "CWE-200"],
                    impact="Facilita engenharia reversa do cliente/aplicação e descoberta de fluxos ou endpoints internos.",
                    remediation=RemediationEngine.get_guidance("exposed_sourcemaps_and_build_artifacts"),
                )
            )
        else:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-H09",
                    module_id=self.metadata.module_id,
                    title="Exposição de Source Maps e Artefatos de Build",
                    status=CheckStatus.PASSED,
                    summary="Nenhum Source Map público ou Dockerfile exposto identificado.",
                )
            )

        return _finalize_module_result(self.metadata.module_id, checks, findings, requests_made)


class DescriptorSecurityModule(BaseSecurityModule):
    """Módulo genérico para extensões ou plugins externos com contrato padronizado."""

    def __init__(self, meta: ModuleMetadata) -> None:
        self._meta = meta

    @property
    def metadata(self) -> ModuleMetadata:
        return self._meta

    def inspect_response_snapshot(
        self,
        target_url: str,
        status_code: int,
        headers: dict[str, str],
        cookies: list[dict[str, Any]] | None = None,
        tls_info: dict[str, Any] | None = None,
        body_excerpt: str = "",
        is_Canceled: Callable[[], bool] | None = None,
        *,
        asset_type: AssetType = AssetType.WEB_APP,
        redirect_chain: list[dict[str, Any]] | None = None,
        raw_set_cookies: list[str] | None = None,
        http_to_https_redirected: bool | None = None,
        initial_url: str | None = None,
        http_client: Any | None = None,
    ) -> ModuleExecutionResult:
        if status_code <= 0:
            return ModuleExecutionResult(
                module_id=self._meta.module_id,
                checks=[
                    CheckEvaluationResult(
                        check_id=f"{self._meta.code}-BASELINE",
                        module_id=self._meta.module_id,
                        title=f"Verificação base do {self._meta.name}",
                        status=CheckStatus.EXECUTION_ERROR,
                        summary="Falha de conexão ao coletar resposta do alvo.",
                    )
                ],
                findings=[],
                total_requests=1,
                execution_errors=1,
            )
        return ModuleExecutionResult(
            module_id=self._meta.module_id,
            checks=[
                CheckEvaluationResult(
                    check_id=f"{self._meta.code}-BASELINE",
                    module_id=self._meta.module_id,
                    title=f"Verificação base do {self._meta.name}",
                    status=CheckStatus.PASSED,
                    summary="Contrato do módulo inicializado e validado.",
                )
            ],
            findings=[],
            total_requests=1,
        )


def get_builtin_modules() -> list[BaseSecurityModule]:
    """Retorna os 8 módulos reais (Módulos A a H) registrados no security-engine."""
    return [
        ModuleAReconHeadersTLS(),
        ModuleBAuthLogin(),
        ModuleCXSSSafe(),
        ModuleDSQLiIndicators(),
        ModuleECookiesAndSession(),
        ModuleFDoSResiliencePosture(),
        ModuleGAPISecurity(),
        ModuleHMisconfigAndOther(),
    ]
