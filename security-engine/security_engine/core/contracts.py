"""Contratos padronizados e modelos de domínio do motor de segurança (security-engine)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class CheckStatus(str, Enum):
    """Categorias estritas de resultado de uma verificação individual (Seção 9)."""

    PASSED = "PASSED"  # Aprovado
    VULNERABILITY = "VULNERABILITY"  # Falha identificada e comprovada
    POTENTIAL_VULNERABILITY = "POTENTIAL_VULNERABILITY"  # Indício técnico / suspeita fundamentada
    INCONCLUSIVE = "INCONCLUSIVE"  # Inconclusivo
    NOT_APPLICABLE = "NOT_APPLICABLE"  # Não aplicável ao ativo/contexto
    EXECUTION_ERROR = "EXECUTION_ERROR"  # Erro técnico/operacional (jamais tratar como aprovado)


class Severity(str, Enum):
    """Níveis padronizados de severidade de risco."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    """Grau de confiança técnica na descoberta."""

    CERTAIN = "CERTAIN"
    FIRM = "FIRM"
    TENTATIVE = "TENTATIVE"


class ImpactLevel(str, Enum):
    """Nível de intrusividade/impacto operacional do módulo (Seção 2 e Seção 7)."""

    PASSIVE = "PASSIVE"
    LOW_IMPACT_ACTIVE = "LOW_IMPACT_ACTIVE"
    CONTROLLED_ASSESSMENT = "CONTROLLED_ASSESSMENT"


class AssetType(str, Enum):
    """Tipos de ativos suportados pela plataforma."""

    WEB_APP = "WEB_APP"
    REST_API = "REST_API"
    GRAPHQL_API = "GRAPHQL_API"
    DOMAIN = "DOMAIN"


class EnvironmentType(str, Enum):
    """Ambientes operacionais do ativo."""

    PRODUCTION = "PRODUCTION"
    STAGING = "STAGING"
    DEVELOPMENT = "DEVELOPMENT"
    LAB = "LAB"


class ScanProfileType(str, Enum):
    """Perfis padronizados de execução de auditoria (Seção 7)."""

    QUICK = "QUICK"
    STANDARD = "STANDARD"
    AUTHENTICATED = "AUTHENTICATED"
    API = "API"
    DEEP_ASSESSMENT = "DEEP_ASSESSMENT"
    DEEP_PENTEST = "DEEP_PENTEST"
    CUSTOM = "CUSTOM"


class StackCodeExample(BaseModel):
    """Exemplo de código ou configuração segura para uma tecnologia específica."""

    technology: str = Field(..., description="Tecnologia alvo (ex: Nginx, Node.js, Python/FastAPI)")
    language: str = Field(..., description="Linguagem para syntax highlight (ex: nginx, typescript, python)")
    description: str = Field(..., description="Explicação do trecho seguro")
    code: str = Field(..., description="Trecho de configuração ou código seguro")


class RemediationGuidance(BaseModel):
    """Estrutura obrigatória de recomendação técnica de correção (Seção 10)."""

    remediation_id: str = Field(..., description="Identificador único na base de recomendações")
    version: str = Field(default="1.0.0", description="Versão da orientação na base de conhecimento")
    what_was_identified: str = Field(..., description="1. O que foi identificado: explicação objetiva")
    why_it_is_dangerous: str = Field(..., description="2. Por que é perigoso: impacto potencial")
    how_it_was_detected: str = Field(..., description="3. Como foi detectado: metodologia e evidências")
    how_to_fix: str = Field(..., description="4. Como corrigir: instruções técnicas claras")
    secure_examples: list[StackCodeExample] = Field(
        default_factory=list,
        description="5. Exemplo seguro por tecnologia (Node.js, Python, Nginx, Apache, etc.)",
    )
    how_to_validate: str = Field(..., description="6. Como validar: procedimento para confirmar a correção")
    references: list[str] = Field(
        default_factory=list,
        description="7. Referências oficiais (OWASP, WSTG, ASVS 5.0, CWE, RFCs)",
    )


class SanitizedEvidence(BaseModel):
    """Evidência técnica sanitizada pelo EvidenceManager."""

    request_method: str | None = None
    request_url: str | None = None
    request_headers: dict[str, str] = Field(default_factory=dict)
    response_status_code: int | None = None
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_body_Excerpt: str | None = None
    observed_value: str | None = None
    expected_baseline: str | None = None
    technical_notes: list[str] = Field(default_factory=list)
    redacted_fields_count: int = 0


class CheckEvaluationResult(BaseModel):
    """Resultado individual de uma verificação executada por um módulo."""

    check_id: str
    module_id: str
    title: str
    status: CheckStatus
    duration_ms: int = 0
    summary: str
    details: dict[str, Any] = Field(default_factory=dict)


class NormalizedFinding(BaseModel):
    """Modelo padronizado de descoberta de segurança (Seção 9)."""

    finding_id: UUID = Field(default_factory=uuid4)
    scan_id: UUID | None = None
    asset_id: UUID | None = None
    endpoint: str
    module_id: str
    check_id: str
    fingerprint: str
    title: str
    description: str
    category: str
    result_classification: CheckStatus = Field(
        ...,
        description="Restrito a VULNERABILITY ou POTENTIAL_VULNERABILITY",
    )
    severity: Severity
    confidence: Confidence
    evidence: SanitizedEvidence
    owasp_references: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    cve_ids: list[str] = Field(
        default_factory=list,
        description="Apenas preenchido quando houver comprovação determinística de versão/CVE",
    )
    cvss_v4_vector: str | None = None
    cvss_v4_score: float | None = None
    impact: str
    safe_reproduction_steps: list[str] = Field(default_factory=list)
    remediation: RemediationGuidance
    technical_references: list[str] = Field(default_factory=list)
    detected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ModuleMetadata(BaseModel):
    """Metadados descritivos de um módulo de segurança."""

    module_id: str
    code: str = Field(..., description="Código do módulo (ex: MÓDULO A, MÓDULO B)")
    name: str
    version: str = Field(default="1.0.0", description="Versão semântica do módulo de verificação")
    description: str
    category: str
    impact_level: ImpactLevel
    supported_asset_types: list[AssetType]
    prerequisites: list[str] = Field(
        default_factory=lambda: ["Alvo cadastrado com autorização comprovada (VERIFIED)."],
        description="Requisitos obrigatórios para execução do módulo",
    )
    allowed_config_keys: list[str] = Field(
        default_factory=lambda: [
            "request_timeout_seconds",
            "max_redirects",
            "max_requests_per_second",
            "max_response_body_bytes",
        ],
        description="Chaves de configuração operacional aceitas pelo módulo",
    )
    owasp_references: list[str]
    wstg_references: list[str]
    asvs_references: list[str]
    cwe_references: list[str]
    enabled_by_default: bool = True
    requires_authentication: bool = False
    allow_in_production: bool = True
    checks_catalog: list[str] = Field(default_factory=list)


class RedirectHop(BaseModel):
    """Representa um salto individual na cadeia de redirecionamento HTTP/HTTPS."""

    step: int
    source_url: str
    status_code: int
    target_url: str
    scheme_upgraded: bool = False
    scheme_downgraded: bool = False


class TlsInspectionDetail(BaseModel):
    """Resultado estruturado da inspeção não invasiva de certificado e protocolo TLS."""

    enabled: bool = False
    handshake_succeeded: bool = False
    trusted_chain: bool = False
    hostname_matched: bool = False
    negotiated_version: str | None = None
    cipher_suite: str | None = None
    subject_cn: str | None = None
    issuer_cn: str | None = None
    san_dns_names: list[str] = Field(default_factory=list)
    not_before: str | None = None
    not_after: str | None = None
    days_until_expiration: int | None = None
    is_expired: bool = False
    is_self_signed: bool = False
    weak_protocols_accepted: list[str] = Field(default_factory=list)
    verification_error: str | None = None
    connection_error: str | None = None


class HttpInspectionSnapshot(BaseModel):
    """Snapshot completo coletado pelo ScopedSafeHttpClient para avaliação pelos módulos."""

    initial_url: str
    final_url: str
    status_code: int = 0
    headers: dict[str, str] = Field(default_factory=dict)
    raw_set_cookies: list[str] = Field(default_factory=list)
    redirect_chain: list[RedirectHop] = Field(default_factory=list)
    http_to_https_redirected: bool | None = None
    http_probe_status_code: int | None = None
    tls_info: TlsInspectionDetail | None = None
    body_excerpt: str = ""
    body_truncated: bool = False
    elapsed_ms: int = 0
    total_requests_made: int = 0
    asset_type: AssetType = AssetType.WEB_APP
    environment: EnvironmentType = EnvironmentType.STAGING
    connection_error: str | None = None


class ModuleExecutionResult(BaseModel):
    """Resultado consolidado da execução de um módulo."""

    module_id: str
    checks: list[CheckEvaluationResult] = Field(default_factory=list)
    findings: list[NormalizedFinding] = Field(default_factory=list)
    total_requests: int = 0
    execution_errors: int = 0
    duration_ms: int = 0


class ScanProfileDescriptor(BaseModel):
    """Especificação transparente de um perfil de auditoria (Seção 7)."""

    profile_type: ScanProfileType
    name: str
    description: str
    what_is_analyzed: list[str]
    what_is_not_analyzed: list[str]
    potential_impact: str
    impact_level: ImpactLevel
    default_max_rps: int
    default_max_concurrency: int
    default_timeout_seconds: int
    prerequisites: list[str]
    dependencies: list[str]
    known_risks: list[str]
    enabled_modules: list[str]
    allowed_in_production: bool


class BaseSecurityModule(ABC):
    """Interface base que todo módulo de verificação do security-engine deve implementar."""

    @property
    @abstractmethod
    def metadata(self) -> ModuleMetadata:
        """Retorna os metadados técnicos e referências normativas do módulo."""

    @abstractmethod
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
        """Executa verificações determinísticas sobre um snapshot HTTP/TLS real."""
