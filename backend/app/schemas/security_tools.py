"""Contratos Pydantic v2 das ferramentas defensivas e utilitários SOC."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class PentestPlanRequest(BaseModel):
    """Parâmetros para geração de plano guiado de testes de penetração (OWASP WSTG)."""

    model_config = ConfigDict(extra="forbid")

    asset_id: str | None = Field(default=None, max_length=64)
    asset_type: Literal["WEB_APP", "REST_API", "GRAPHQL_API", "DOMAIN"] = "WEB_APP"
    environment: Literal["PRODUCTION", "STAGING", "DEVELOPMENT", "LAB"] = "LAB"
    target_label: str | None = Field(default=None, max_length=160)


class PentestStepItem(BaseModel):
    """Etapa individual de teste guiado mapeada ao WSTG e checks do motor."""

    step_id: str
    wstg_ref: str
    title: str
    objective: str
    safe_technique: str
    mapped_checks: list[str]
    allowed_in_production: bool
    automated_status: Literal[
        "COVERED_PASSED",
        "COVERED_WITH_FINDINGS",
        "NOT_YET_RUN",
        "BLOCKED_IN_PRODUCTION",
    ]
    related_findings_count: int = 0


class PentestPhase(BaseModel):
    """Fase do roteiro estruturado de testes de penetração."""

    phase_number: int
    name: str
    description: str
    steps: list[PentestStepItem]


class PentestPlanResponse(BaseModel):
    """Plano completo de testes de penetração guiados com guarda de escopo."""

    target_name: str
    asset_type: str
    environment: str
    authorization_status: str
    authorization_warning: str | None = None
    total_steps: int
    automated_covered_steps: int
    open_findings_count: int
    phases: list[PentestPhase]


class PasswordGenerateRequest(BaseModel):
    """Parâmetros de geração criptograficamente segura de senha ou passphrase."""

    model_config = ConfigDict(extra="forbid")

    mode: Literal["RANDOM", "PASSPHRASE"] = "RANDOM"
    length: int = Field(default=20, ge=8, le=128)
    include_uppercase: bool = True
    include_lowercase: bool = True
    include_digits: bool = True
    include_symbols: bool = True
    exclude_ambiguous: bool = False
    word_count: int = Field(default=5, ge=4, le=10)
    separator: str = Field(default="-", max_length=3)
    include_number: bool = True


class PasswordGenerateResponse(BaseModel):
    """Resultado da geração segura de senha sem persistência ou registro em logs."""

    generated: str
    mode: str
    length: int
    entropy_bits: float
    strength_label: str


class PasswordAnalyzeRequest(BaseModel):
    """Entrada para avaliação defensiva de força, entropia e conformidade de senha."""

    model_config = ConfigDict(extra="forbid")

    password: str = Field(..., min_length=1, max_length=256)


class PasswordComplianceCheck(BaseModel):
    """Item de conformidade frente a normas de autenticação."""

    standard: str
    passed: bool
    detail: str


class PasswordAnalyzeResponse(BaseModel):
    """Diagnóstico técnico de força, entropia e conformidade da senha."""

    length: int
    score: int = Field(ge=0, le=100)
    classification: Literal["CRITICAL_WEAK", "WEAK", "FAIR", "STRONG", "VERY_STRONG"]
    pool_size: int
    keyspace_entropy_bits: float
    shannon_entropy_bits: float
    crack_time_offline_slow: str
    crack_time_offline_fast: str
    detected_patterns: list[str]
    compliance_checks: list[PasswordComplianceCheck]
    recommendations: list[str]


class ForensicsAnalyzeRequest(BaseModel):
    """Entrada de artefato textual, log ou token para análise forense estática."""

    model_config = ConfigDict(extra="forbid")

    content: str = Field(..., min_length=1, max_length=262144)
    artifact_name: str | None = Field(default=None, max_length=180)
    defang_iocs: bool = True


class ForensicsHashes(BaseModel):
    """Hashes criptográficos calculados sobre os bytes do artefato."""

    md5: str
    sha1: str
    sha256: str
    sha512: str


class ForensicsIocs(BaseModel):
    """Indicadores de comprometimento (IOCs) extraídos e categorizados."""

    ipv4_public: list[str]
    ipv4_private: list[str]
    ipv6: list[str]
    domains: list[str]
    urls: list[str]
    emails: list[str]
    hashes: list[str]
    cves: list[str]


class ForensicsTimelineSummary(BaseModel):
    """Resumo de linha do tempo e códigos HTTP em artefatos de log."""

    events_detected: int
    first_timestamp: str | None = None
    last_timestamp: str | None = None
    http_status_counts: dict[str, int]


class ForensicsJwtInspection(BaseModel):
    """Inspeção passiva de tokens JWT presentes no artefato com sanitização."""

    detected: bool
    header: dict[str, Any] | None = None
    payload_sanitized: dict[str, Any] | None = None
    warnings: list[str]


class ForensicsAnalyzeResponse(BaseModel):
    """Relatório estruturado de análise forense digital de artefato."""

    artifact_name: str
    size_bytes: int
    line_count: int
    shannon_entropy: float
    hashes: ForensicsHashes
    iocs: ForensicsIocs
    timeline: ForensicsTimelineSummary
    jwt_inspection: ForensicsJwtInspection
    secret_leak_warnings: list[str]
    summary: str


class FirewallTestPacket(BaseModel):
    """Pacote sintético para simulação de correspondência ordenada nas regras."""

    model_config = ConfigDict(extra="forbid")

    protocol: Literal["TCP", "UDP", "ICMP"] = "TCP"
    source_ip: str = Field(..., min_length=3, max_length=64)
    destination_port: int = Field(..., ge=1, le=65535)


class FirewallAnalyzeRequest(BaseModel):
    """Conjunto de regras de firewall e pacote opcional para auditoria estática."""

    model_config = ConfigDict(extra="forbid")

    rules_text: str = Field(..., min_length=1, max_length=131072)
    test_packet: FirewallTestPacket | None = None


class FirewallParsedRule(BaseModel):
    """Regra normalizada extraída de iptables, UFW ou política genérica."""

    line_number: int
    raw: str
    action: Literal["ALLOW", "DENY"]
    protocol: str
    source_cidr: str
    port_spec: str


class FirewallFinding(BaseModel):
    """Achado de auditoria de regras de firewall com CWE e recomendação."""

    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    line_number: int | None = None
    title: str
    description: str
    cwe_id: str
    remediation: str


class FirewallSimulationResult(BaseModel):
    """Resultado da simulação de tráfego contra as regras ordenadas."""

    verdict: Literal["ALLOW", "DENY", "DEFAULT_IMPLICIT"]
    matched_line: int | None = None
    matched_rule: str | None = None
    explanation: str


class FirewallAnalyzeResponse(BaseModel):
    """Diagnóstico de postura, riscos e simulação de regras de firewall."""

    total_rules_parsed: int
    unparsed_lines: list[int]
    posture_score: int = Field(ge=0, le=100)
    has_default_deny: bool
    parsed_rules: list[FirewallParsedRule]
    findings: list[FirewallFinding]
    simulation: FirewallSimulationResult | None = None


class MalwareAnalyzeRequest(BaseModel):
    """Payload textual ou codificado para análise estática sem execução."""

    model_config = ConfigDict(extra="forbid")

    payload: str = Field(..., min_length=1, max_length=262144)
    filename: str | None = Field(default=None, max_length=180)
    input_encoding: Literal["TEXT", "BASE64", "HEX"] = "TEXT"


class MalwareSignatureHit(BaseModel):
    """Assinatura ou heurística estática acionada com mapeamento MITRE ATT&CK."""

    rule_id: str
    name: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    mitre_attack: str
    matched_excerpt: str
    description: str


class MalwareDeobfuscationItem(BaseModel):
    """Prévia segura de conteúdo decodificado estaticamente."""

    encoding: str
    decoded_preview: str


class MalwareAnalyzeResponse(BaseModel):
    """Resultado completo da inspeção estática de payload ou artefato suspeito."""

    filename: str
    size_bytes: int
    file_type_guess: str
    hashes: ForensicsHashes
    shannon_entropy: float
    high_entropy_warning: bool
    risk_score: int = Field(ge=0, le=100)
    verdict: Literal["CLEAN_NO_INDICATORS", "SUSPICIOUS", "HIGH_RISK_MALICIOUS_INDICATORS"]
    signature_hits: list[MalwareSignatureHit]
    deobfuscated_previews: list[MalwareDeobfuscationItem]
    extracted_urls: list[str]
    extracted_ips: list[str]
    containment_recommendations: list[str]


class WifiConnectedInterface(BaseModel):
    """Estado da interface Wi-Fi conectada capturado do sistema operacional."""

    interface_name: str | None = None
    adapter_description: str | None = None
    state: str | None = None
    ssid: str | None = None
    bssid: str | None = None
    radio_type: str | None = None
    authentication: str | None = None
    encryption: str | None = None
    channel: int | None = None
    signal_percent: int | None = None
    receive_rate_mbps: str | None = None
    transmit_rate_mbps: str | None = None


class WifiNetworkInput(BaseModel):
    """Registro estruturado de rede sem fio para auditoria passiva."""

    model_config = ConfigDict(extra="forbid")

    ssid: str = Field(..., min_length=1, max_length=128)
    bssid: str | None = Field(default=None, max_length=64)
    authentication: str = Field(..., min_length=1, max_length=80)
    encryption: str = Field(default="", max_length=80)
    radio_type: str | None = Field(default=None, max_length=40)
    channel: int | None = Field(default=None, ge=1, le=200)
    signal_percent: int | None = Field(default=None, ge=0, le=100)
    wps_enabled: bool = False
    pmf_enabled: bool | None = None


class WifiAnalyzeRequest(BaseModel):
    """Saída bruta de varredura (netsh/nmcli) ou lista estruturada de APs."""

    model_config = ConfigDict(extra="forbid")

    raw_scan_output: str | None = Field(default=None, max_length=131072)
    connected_interface_output: str | None = Field(default=None, max_length=32768)
    networks: list[WifiNetworkInput] = Field(default_factory=list, max_length=256)


class WifiFinding(BaseModel):
    """Achado de segurança em rede sem fio avaliada passivamente."""

    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    ssid: str
    bssid: str | None = None
    title: str
    description: str
    cwe_id: str
    remediation: str


class WifiNetworkAssessment(BaseModel):
    """Classificação individual de um ponto de acesso ou SSID."""

    ssid: str
    bssid: str | None = None
    security_grade: Literal["A", "B", "C", "D", "F"]
    authentication: str
    encryption: str
    radio_type: str | None = None
    band: str | None = None
    channel: int | None = None
    signal_percent: int | None = None
    issues_count: int


class WifiAnalyzeResponse(BaseModel):
    """Relatório consolidado da auditoria passiva de redes Wi-Fi."""

    total_networks: int
    overall_score: int = Field(ge=0, le=100)
    evil_twin_suspected: bool
    connected_interface: WifiConnectedInterface | None = None
    assessments: list[WifiNetworkAssessment]
    findings: list[WifiFinding]
    hardening_checklist: list[str]


class WifiLocalScanResponse(BaseModel):
    """Resultado de tentativa de varredura Wi-Fi local real no host da API."""

    available: bool
    source: str
    detail: str
    captured_at: str | None = None
    raw_scan_output: str | None = None
    connected_interface_output: str | None = None
    audit: WifiAnalyzeResponse | None = None


class DdosPostureConfig(BaseModel):
    """Controles defensivos ativos na borda e aplicação do alvo."""

    model_config = ConfigDict(extra="forbid")

    has_cdn_waf: bool = False
    has_rate_limiting: bool = False
    has_syn_cookies: bool = False
    has_upstream_timeouts: bool = False
    has_autoscaling_or_anycast: bool = False


class DdosAnalyzeRequest(BaseModel):
    """Logs de acesso e postura defensiva para diagnóstico e mitigação DDoS."""

    model_config = ConfigDict(extra="forbid")

    access_logs: str | None = Field(default=None, max_length=262144)
    posture: DdosPostureConfig = Field(default_factory=DdosPostureConfig)
    asset_id: str | None = Field(default=None, max_length=64)


class DdosIpMetric(BaseModel):
    """Métricas agregadas por endereço IP de origem."""

    ip: str
    request_count: int
    share_percent: float
    error_rate_percent: float


class DdosAnomaly(BaseModel):
    """Anomalia de volume, saturação ou camada 7 detectada nos logs."""

    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    anomaly_type: str
    title: str
    description: str
    evidence: str


class DdosMitigationSnippet(BaseModel):
    """Snippet pronto de mitigação para Nginx, WAF ou firewall de borda."""

    platform: str
    title: str
    code: str


class DdosAnalyzeResponse(BaseModel):
    """Diagnóstico defensivo de DDoS, postura e recomendações de mitigação."""

    total_requests_parsed: int
    unique_ips: int
    peak_rps: float
    error_5xx_429_rate_percent: float
    resilience_score: int = Field(ge=0, le=100)
    risk_level: Literal["LOW", "MODERATE", "HIGH", "CRITICAL"]
    top_ips: list[DdosIpMetric]
    top_paths: list[dict[str, Any]]
    anomalies: list[DdosAnomaly]
    asset_module_f_context: list[str]
    mitigation_snippets: list[DdosMitigationSnippet]
