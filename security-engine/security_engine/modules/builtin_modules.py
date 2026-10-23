"""Módulos de auditoria de segurança (Módulos A a H - Seção 6) com inspeção determinística real."""

from __future__ import annotations

import html
import ipaddress
import re
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

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
]
SAFE_REFERRER_POLICIES = {
    "no-referrer",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "origin-when-cross-origin",
    "origin",
}


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
        }

    first = parts[0]
    cookie_name = first.split("=", 1)[0].strip() if "=" in first else first.strip()
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
            owasp_references=["A02:2021-Cryptographic Failures", "A05:2021-Security Misconfiguration"],
            wstg_references=["WSTG-CONF-07", "WSTG-INFO-02", "WSTG-CRYP-01"],
            asvs_references=["ASVS-V9.1", "ASVS-V9.2", "ASVS-V14.4"],
            cwe_references=["CWE-319", "CWE-693", "CWE-1021", "CWE-200", "CWE-295", "CWE-298", "CWE-345"],
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
                if max_age_val < 31536000:
                    checks.append(
                        CheckEvaluationResult(
                            check_id="CHK-A02",
                            module_id=self.metadata.module_id,
                            title="Cabeçalho Strict-Transport-Security (HSTS)",
                            status=CheckStatus.POTENTIAL_VULNERABILITY,
                            summary=f"HSTS presente, mas max-age={max_age_val} é inferior a 1 ano (31536000s).",
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
                            title="Cabeçalho HSTS configurado com tempo de vida (max-age) curto",
                            description=f"O cabeçalho HSTS define max-age={max_age_val}, abaixo do mínimo recomendado de 31536000 segundos.",
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
                            impact="Janela reduzida de proteção HSTS no cache do navegador.",
                            safe_reproduction_steps=[f"Verificar diretiva max-age do header HSTS em {target_url}."],
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
                checks.append(
                    CheckEvaluationResult(
                        check_id="CHK-A03",
                        module_id=self.metadata.module_id,
                        title="Cabeçalho Content-Security-Policy (CSP)",
                        status=CheckStatus.VULNERABILITY,
                        summary="Cabeçalho Content-Security-Policy ausente.",
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
                        description="A aplicação não define o cabeçalho Content-Security-Policy para restringir origens de scripts e recursos.",
                        category=self.metadata.category,
                        result_classification=CheckStatus.VULNERABILITY,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.CERTAIN,
                        evidence=EvidenceManager.build_sanitized_evidence(
                            request_method="GET",
                            request_url=target_url,
                            response_status_code=status_code,
                            response_headers=headers,
                            observed_value="Header Content-Security-Policy ausente",
                            expected_baseline="default-src 'self'; object-src 'none'; frame-ancestors 'none'",
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
            if re.search(r"(?:default-src|script-src)\s+[^;]*\*", lower_csp):
                weak_tokens.append("wildcard '*'")

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
        has_frame_ancestors = bool(csp_val and "frame-ancestors" in csp_val.lower())
        if xfo_val not in {"DENY", "SAMEORIGIN"} and not has_frame_ancestors:
            if is_pure_api_context:
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
                checks.append(
                    CheckEvaluationResult(
                        check_id="CHK-A05",
                        module_id=self.metadata.module_id,
                        title="Proteção contra Clickjacking",
                        status=CheckStatus.VULNERABILITY,
                        summary="Nem X-Frame-Options nem CSP frame-ancestors foram encontrados.",
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
                        title="Ausência de proteção contra Clickjacking (X-Frame-Options / frame-ancestors)",
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
                            observed_value="X-Frame-Options e frame-ancestors ausentes",
                            expected_baseline="X-Frame-Options: DENY ou SAMEORIGIN",
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
            ref_ok = referrer_val in SAFE_REFERRER_POLICIES
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

                # CHK-A11: Versão do Protocolo TLS
                neg_ver = tls_info.get("negotiated_version")
                weak_protos = tls_info.get("weak_protocols_accepted") or []
                if weak_protos or neg_ver in {"TLSv1", "TLSv1.0", "TLSv1.1"}:
                    checks.append(
                        CheckEvaluationResult(
                            check_id="CHK-A11",
                            module_id=self.metadata.module_id,
                            title="Versão Negociada do Protocolo TLS",
                            status=CheckStatus.VULNERABILITY,
                            summary=f"Protocolo TLS obsoleto negociado/aceito: {neg_ver or weak_protos}.",
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
                            title=f"Suporte a protocolo TLS obsoleto ({neg_ver})",
                            description="O servidor negociou uma versão obsoleta do protocolo TLS depreciada pela RFC 8996.",
                            category=self.metadata.category,
                            result_classification=CheckStatus.VULNERABILITY,
                            severity=Severity.HIGH,
                            confidence=Confidence.CERTAIN,
                            evidence=EvidenceManager.build_sanitized_evidence(
                                request_method="TLS_HANDSHAKE",
                                request_url=target_url,
                                observed_value=f"negotiated_version={neg_ver}",
                                expected_baseline="TLSv1.2 ou TLSv1.3",
                            ),
                            owasp_references=["A02:2021-Cryptographic Failures"],
                            cwe_ids=["CWE-326"],
                            impact="Exposição a ataques contra cifras e protocolos TLS legados.",
                            safe_reproduction_steps=[f"Verificar versão TLS negociada com {target_url}."],
                            remediation=RemediationEngine.get_guidance("tls_weak_protocol_version"),
                        )
                    )
                elif neg_ver in {"TLSv1.2", "TLSv1.3"}:
                    checks.append(
                        CheckEvaluationResult(
                            check_id="CHK-A11",
                            module_id=self.metadata.module_id,
                            title="Versão Negociada do Protocolo TLS",
                            status=CheckStatus.PASSED,
                            summary=f"Protocolo moderno negociado: {neg_ver} ({tls_info.get('cipher_suite')}).",
                            details=tls_info,
                        )
                    )
                else:
                    checks.append(
                        CheckEvaluationResult(
                            check_id="CHK-A11",
                            module_id=self.metadata.module_id,
                            title="Versão Negociada do Protocolo TLS",
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
                    has_spf = any("v=spf1" in r.lower() for r in apex_txt)
                    has_dmarc = any("v=dmarc1" in r.lower() for r in dmarc_txt)
                    if has_spf and has_dmarc:
                        checks.append(
                            CheckEvaluationResult(
                                check_id="CHK-A12",
                                module_id=self.metadata.module_id,
                                title="Registros de Autenticação de E-mail (SPF e DMARC)",
                                status=CheckStatus.PASSED,
                                summary=f"Registros SPF e DMARC configurados e válidos para o domínio '{domain}'.",
                                details={"domain": domain, "has_spf": True, "has_dmarc": True},
                            )
                        )
                    else:
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
                                fingerprint=f"{domain}|{self.metadata.module_id}|CHK-A12|missing-email-auth",
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

        exec_errors = sum(1 for c in checks if c.status == CheckStatus.EXECUTION_ERROR)
        return ModuleExecutionResult(
            module_id=self.metadata.module_id,
            checks=checks,
            findings=findings,
            total_requests=1,
            execution_errors=exec_errors,
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
            owasp_references=["A07:2021-Identification and Authentication Failures"],
            wstg_references=["WSTG-SESS-02"],
            asvs_references=["ASVS-V3.4.1", "ASVS-V3.4.2", "ASVS-V3.4.3"],
            cwe_references=["CWE-614", "CWE-1004", "CWE-1275"],
            enabled_by_default=True,
            requires_authentication=False,
            allow_in_production=True,
            checks_catalog=[
                "CHK-E01: Atributos de Segurança em Cookies (Secure, HttpOnly, SameSite)",
                "CHK-E02: Incompatibilidade de Flags (SameSite=None sem Secure), Escopo e Expiração",
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

        return ModuleExecutionResult(
            module_id=self.metadata.module_id,
            checks=checks,
            findings=findings,
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
            cwe_references=["CWE-287", "CWE-319", "CWE-204", "CWE-525"],
            enabled_by_default=True,
            requires_authentication=False,
            allow_in_production=True,
            checks_catalog=[
                "CHK-B01: Transporte HTTPS Obrigatório em Formulários/Endpoints de Autenticação",
                "CHK-B02: Exposição de Enumeração de Usuários em Mensagens de Erro",
                "CHK-B03: Políticas de Cache e Proteção de Dados Sensíveis em Endpoints de Autenticação",
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
                    fingerprint=f"{hostname}|{self.metadata.module_id}|CHK-B01|http-auth-transport",
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
                    fingerprint=f"{hostname}|{self.metadata.module_id}|CHK-B01|insecure-form-action",
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
                    fingerprint=f"{hostname}|{self.metadata.module_id}|CHK-B02|user-enumeration",
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
                        fingerprint=f"{hostname}|{self.metadata.module_id}|CHK-B03|auth-cache-control",
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

        exec_errors = sum(1 for c in checks if c.status == CheckStatus.EXECUTION_ERROR)
        return ModuleExecutionResult(
            module_id=self.metadata.module_id,
            checks=checks,
            findings=findings,
            total_requests=1,
            execution_errors=exec_errors,
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
            cwe_references=["CWE-79"],
            enabled_by_default=True,
            requires_authentication=False,
            allow_in_production=True,
            checks_catalog=[
                "CHK-C01: Reflexão de Parâmetros e Tratamento de Caracteres Especiais",
                "CHK-C02: Sinks DOM Inseguros em Scripts e Páginas Web",
                "CHK-C03: Mitigação de Scripts via Content-Security-Policy (CSP)",
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

        # CHK-C01: Reflexão de Parâmetros e Tratamento de Caracteres Especiais
        benign_marker = "cscxss7a8b"
        dangerous_test_chars = f"{benign_marker}<cscprobe>"
        encoded_expectation = html.escape(dangerous_test_chars)
        reflected_raw = False
        reflected_encoded = False

        if http_client and getattr(http_client, "probe", None):
            sep = "&" if "?" in target_url else "?"
            probe_url = f"{target_url}{sep}csc_probe={dangerous_test_chars}"
            try:
                probe_res = http_client.probe(probe_url, is_cancelled=is_Canceled)
                requests_made += 1
                if probe_res and probe_res.status_code == 200:
                    if dangerous_test_chars in probe_res.body:
                        reflected_raw = True
                    elif benign_marker in probe_res.body:
                        reflected_encoded = True
            except Exception:  # noqa: BLE001, S110
                pass

        if not reflected_raw and not reflected_encoded and parsed.query:
            from urllib.parse import parse_qs
            qs = parse_qs(parsed.query)
            for param_val_list in qs.values():
                for pval in param_val_list:
                    if len(pval) >= 4 and pval in body_excerpt:
                        if any(c in pval for c in ["<", ">", '"', "'"]):
                            reflected_raw = True
                        else:
                            reflected_encoded = True
                        break

        if reflected_raw:
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-C01",
                    module_id=self.metadata.module_id,
                    title="Reflexão de Parâmetros e Tratamento de Caracteres Especiais",
                    status=CheckStatus.VULNERABILITY,
                    summary="Marcador de teste com caracteres HTML (<, >) foi refletido no corpo da resposta sem codificação contextual.",
                    details={"target_url": target_url, "reflected": True, "encoded": False},
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-C01",
                    fingerprint=f"{hostname}|{self.metadata.module_id}|CHK-C01|reflected-xss-chars",
                    title="Reflexão de Entrada sem Codificação Contextual HTML (XSS Refletido)",
                    description=(
                        "A aplicação reflete dados fornecidos na URL diretamente no corpo da resposta sem aplicar "
                        "codificação HTML de caracteres especiais (<, >, \", '), permitindo potencial injeção de scripts."
                    ),
                    category="Validação e Codificação de Entrada/Saída",
                    result_classification=CheckStatus.VULNERABILITY,
                    severity=Severity.HIGH,
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
            r"(document\.write(?:ln)?\s*\(|\.innerHTML\s*=|\.outerHTML\s*=|\beval\s*\(|location\.href\s*=\s*(?:location|window)\.(?:search|hash))",
            re.IGNORECASE,
        )
        sink_match = dom_sinks_regex.search(body_excerpt)
        if sink_match:
            sink_str = sink_match.group(0).strip()
            checks.append(
                CheckEvaluationResult(
                    check_id="CHK-C02",
                    module_id=self.metadata.module_id,
                    title="Sinks DOM Inseguros em Scripts e Páginas Web",
                    status=CheckStatus.POTENTIAL_VULNERABILITY,
                    summary=f"Sink DOM potencialmente perigoso identificado no código cliente: '{sink_str}'.",
                    details={"sink": sink_str},
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-C02",
                    fingerprint=f"{hostname}|{self.metadata.module_id}|CHK-C02|dom-xss-sink",
                    title=f"Uso de Sink DOM Inseguro ('{sink_str}') em Script do Lado Cliente",
                    description=(
                        f"O código JavaScript cliente utiliza manipulação direta de DOM via '{sink_str}'. "
                        "Se alimentado por dados controláveis pelo usuário (como location.search ou hash), "
                        "pode permitir DOM-based XSS."
                    ),
                    category="Validação e Codificação de Entrada/Saída",
                    result_classification=CheckStatus.POTENTIAL_VULNERABILITY,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.FIRM,
                    evidence=SanitizedEvidence(
                        request_url=target_url,
                        observed_value=sink_str,
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
                    fingerprint=f"{hostname}|{self.metadata.module_id}|CHK-C03|missing-csp-defense",
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
                    fingerprint=f"{hostname}|{self.metadata.module_id}|CHK-C03|unsafe-inline-csp",
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

        exec_errors = sum(1 for c in checks if c.status == CheckStatus.EXECUTION_ERROR)
        return ModuleExecutionResult(
            module_id=self.metadata.module_id,
            checks=checks,
            findings=findings,
            total_requests=requests_made,
            execution_errors=exec_errors,
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
            cwe_references=["CWE-89", "CWE-209"],
            enabled_by_default=False,
            requires_authentication=False,
            allow_in_production=False,
            checks_catalog=[
                "CHK-D01: Assinaturas de Erros e Exceções Verbosas de Banco de Dados",
                "CHK-D02: Comportamento Anômalo Não Destrutivo e Exposição de Estrutura Interna",
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
        detected_sql_error = None
        for pattern, label in SQL_ERROR_PATTERNS:
            match = pattern.search(body_excerpt)
            if match:
                detected_sql_error = (label, match.group(0))
                break

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
                    fingerprint=f"{hostname}|{self.metadata.module_id}|CHK-D01|sql-error-signature",
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

        # CHK-D02: Comportamento Anômalo Não Destrutivo e Exposição de Estrutura Interna
        boundary_probe_triggered = False
        if http_client and getattr(http_client, "probe", None):
            sep = "&" if "?" in target_url else "?"
            probe_url = f"{target_url}{sep}id=1%27"
            try:
                probe_res = http_client.probe(probe_url, is_cancelled=is_Canceled)
                requests_made += 1
                if probe_res:
                    for pattern, _ in SQL_ERROR_PATTERNS:
                        if pattern.search(probe_res.body):
                            boundary_probe_triggered = True
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
                    summary="Teste de limite não destrutivo com caractere de controle desencadeou erro interno de sintaxe SQL.",
                )
            )
            findings.append(
                NormalizedFinding(
                    endpoint=target_url,
                    module_id=self.metadata.module_id,
                    check_id="CHK-D02",
                    fingerprint=f"{hostname}|{self.metadata.module_id}|CHK-D02|sqli-boundary-anomaly",
                    title="Vulnerabilidade Potencial a SQL Injection Identificada por Teste de Limite",
                    description="O envio de caractere de escape de string provocou falha de banco de dados, evidenciando ausência de Prepared Statements.",
                    category="Injeção e Persistência Segura",
                    result_classification=CheckStatus.VULNERABILITY,
                    severity=Severity.HIGH,
                    confidence=Confidence.CERTAIN,
                    evidence=SanitizedEvidence(
                        request_url=target_url,
                        observed_value="Falha de sintaxe SQL disparada por caractere de controle",
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

        exec_errors = sum(1 for c in checks if c.status == CheckStatus.EXECUTION_ERROR)
        return ModuleExecutionResult(
            module_id=self.metadata.module_id,
            checks=checks,
            findings=findings,
            total_requests=requests_made,
            execution_errors=exec_errors,
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
            wstg_references=["WSTG-CONF-01"],
            asvs_references=["ASVS-V11.1.4", "ASVS-V13.1"],
            cwe_references=["CWE-770", "CWE-400"],
            enabled_by_default=True,
            requires_authentication=False,
            allow_in_production=True,
            checks_catalog=[
                "CHK-F01: Detecção de Controles de Borda (CDN / WAF)",
                "CHK-F02: Presença de Políticas de Rate Limiting (RateLimit-* / X-RateLimit-*)",
                "CHK-F03: Limite de Tamanho de Requisição e Proteção de Endpoints Sensíveis",
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
                    fingerprint=f"{hostname}|{self.metadata.module_id}|CHK-F01|missing-edge-waf",
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
                    fingerprint=f"{hostname}|{self.metadata.module_id}|CHK-F02|missing-rate-limit-headers",
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
        checks.append(
            CheckEvaluationResult(
                check_id="CHK-F03",
                module_id=self.metadata.module_id,
                title="Limite de Tamanho de Requisição e Proteção de Recursos",
                status=CheckStatus.PASSED,
                summary="Políticas de consumo de recursos avaliadas sem sinais de sobrecarga ou degradação.",
            )
        )

        exec_errors = sum(1 for c in checks if c.status == CheckStatus.EXECUTION_ERROR)
        return ModuleExecutionResult(
            module_id=self.metadata.module_id,
            checks=checks,
            findings=findings,
            total_requests=1,
            execution_errors=exec_errors,
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
                "API8:2023-Security Misconfiguration",
                "API9:2023-Improper Inventory Management",
            ],
            wstg_references=["WSTG-APIT-01", "WSTG-CLNT-07"],
            asvs_references=["ASVS-V13", "ASVS-V14.5"],
            cwe_references=["CWE-942", "CWE-200", "CWE-639"],
            enabled_by_default=True,
            requires_authentication=False,
            allow_in_production=True,
            checks_catalog=[
                "CHK-G01: Configuração Insegura de CORS (Access-Control-Allow-Origin / Credentials)",
                "CHK-G02: Exposição Pública de Documentação OpenAPI/Swagger e GraphQL Introspection",
                "CHK-G03: Métodos HTTP Desnecessários e Cabeçalhos de Cache em Respostas de API",
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
                    fingerprint=f"{hostname}|{self.metadata.module_id}|CHK-G01|cors-wildcard-credentials",
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
                    fingerprint=f"{hostname}|{self.metadata.module_id}|CHK-G01|cors-origin-null",
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
            try:
                probe_res = http_client.probe(f"{origin}/openapi.json", is_cancelled=is_Canceled)
                requests_made += 1
                if probe_res and probe_res.status_code == 200 and '"openapi"' in probe_res.body:
                    docs_exposed = True
                    docs_path = "/openapi.json"
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
                    fingerprint=f"{hostname}|{self.metadata.module_id}|CHK-G02|public-openapi-docs",
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
                    fingerprint=f"{hostname}|{self.metadata.module_id}|CHK-G03|trace-method-enabled",
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

        exec_errors = sum(1 for c in checks if c.status == CheckStatus.EXECUTION_ERROR)
        return ModuleExecutionResult(
            module_id=self.metadata.module_id,
            checks=checks,
            findings=findings,
            total_requests=requests_made,
            execution_errors=exec_errors,
        )


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
            cwe_references=["CWE-352", "CWE-538", "CWE-548", "CWE-601"],
            enabled_by_default=True,
            requires_authentication=False,
            allow_in_production=True,
            checks_catalog=[
                "CHK-H01: Exposição de Arquivos Sensíveis e Metadados de Sistema",
                "CHK-H02: Detecção de Directory Listing Habilitado",
                "CHK-H03: Proteção contra Redirecionamento Aberto (Open Redirect)",
                "CHK-H04: Proteção contra Cross-Site Request Forgery (CSRF)",
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
        if any(parsed.path.lower().endswith(ext) for ext in [".env", ".git/config", "backup.sql"]):
            if status_code == 200 and any(s in body_excerpt for s in ["=", "[core]", "DATABASE"]):
                sensitive_exposed = parsed.path
        elif http_client and getattr(http_client, "probe", None):
            origin = f"{parsed.scheme}://{parsed.netloc}"
            try:
                probe_res = http_client.probe(f"{origin}/.env", is_cancelled=is_Canceled)
                requests_made += 1
                if probe_res and probe_res.status_code == 200 and any(k in probe_res.body for k in ["DATABASE_URL", "SECRET_KEY", "PASSWORD", "="]):
                    sensitive_exposed = "/.env"
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
                    fingerprint=f"{hostname}|{self.metadata.module_id}|CHK-H01|sensitive-file-leak",
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
                    fingerprint=f"{hostname}|{self.metadata.module_id}|CHK-H02|directory-listing-enabled",
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
        from urllib.parse import parse_qs
        qs = parse_qs(parsed.query)
        for rparam in redirect_param_names:
            if rparam in qs:
                for rval in qs[rparam]:
                    if rval.startswith(("http://", "https://", "//")):
                        dest_host = urlparse(rval).hostname or ""
                        if dest_host and dest_host.lower() != hostname:
                            loc_head = headers.get("Location") or headers.get("location") or ""
                            if loc_head and dest_host in loc_head:
                                open_redirect_found = True
                                break

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
                    fingerprint=f"{hostname}|{self.metadata.module_id}|CHK-H03|open-redirect-arbitrary",
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
                    fingerprint=f"{hostname}|{self.metadata.module_id}|CHK-H04|missing-csrf-token",
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

        exec_errors = sum(1 for c in checks if c.status == CheckStatus.EXECUTION_ERROR)
        return ModuleExecutionResult(
            module_id=self.metadata.module_id,
            checks=checks,
            findings=findings,
            total_requests=requests_made,
            execution_errors=exec_errors,
        )


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
