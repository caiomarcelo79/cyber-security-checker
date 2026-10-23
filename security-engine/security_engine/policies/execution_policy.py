"""Políticas de limites operacionais e perfis de execução de auditorias."""

from __future__ import annotations

from pydantic import BaseModel, Field, model_validator

from security_engine.core.contracts import (
    ImpactLevel,
    ScanProfileDescriptor,
    ScanProfileType,
)

# Tetos máximos intransponíveis (Hard Guardrails - Seção 12)
HARD_CAP_MAX_RPS = 20
HARD_CAP_MIN_RPS = 1
HARD_CAP_MAX_CONCURRENCY = 10
HARD_CAP_MIN_CONCURRENCY = 1
HARD_CAP_MAX_REQUEST_TIMEOUT = 30
HARD_CAP_MIN_REQUEST_TIMEOUT = 2
HARD_CAP_MAX_GLOBAL_TIMEOUT = 3600
HARD_CAP_MIN_GLOBAL_TIMEOUT = 30
HARD_CAP_MAX_REDIRECTS = 10
HARD_CAP_MAX_DEPTH = 5
HARD_CAP_MAX_RESPONSE_BYTES = 10 * 1024 * 1024  # 10 MB
HARD_CAP_MAX_CIRCUIT_BREAKER_ERRORS = 10


class ScanExecutionPolicy(BaseModel):
    """Limites operacionais obrigatórios de uma execução de auditoria (Seção 12).

    Mesmo que um usuário tente fornecer valores superiores aos tetos de segurança
    ou desativar proteções obrigatórias, o validador impõe os guardrails.
    """

    max_requests_per_second: int = Field(default=5, description="Limite de requisições por segundo")
    max_concurrency: int = Field(default=3, description="Limite de conexões simultâneas")
    request_timeout_seconds: int = Field(default=10, description="Timeout por requisição em segundos")
    global_timeout_seconds: int = Field(default=600, description="Timeout global da auditoria em segundos")
    max_crawl_depth: int = Field(default=2, description="Profundidade máxima de navegação")
    max_redirects: int = Field(default=5, description="Limite máximo de redirecionamentos seguidos")
    max_response_body_bytes: int = Field(
        default=2 * 1024 * 1024,
        description="Tamanho máximo lido por resposta HTTP (bytes)",
    )
    excluded_endpoints: list[str] = Field(
        default_factory=lambda: ["/logout", "/signout", "/delete", "/reset"],
        description="Lista de caminhos excluídos da varredura",
    )
    respect_http_429_and_503: bool = Field(
        default=True,
        description="Obrigatório: recuar ou interromper diante de HTTP 429/503",
    )
    abort_on_target_degradation: bool = Field(
        default=True,
        description="Obrigatório: parar execução em caso de erros sucessivos ou sinais de degradação",
    )
    circuit_breaker_error_threshold: int = Field(
        default=5,
        description="Quantidade de falhas/429/503 consecutivas antes de acionar parada",
    )
    prevent_redirect_loops: bool = Field(
        default=True,
        description="Obrigatório: detectar e interromper loops de redirecionamento",
    )

    @model_validator(mode="after")
    def enforce_mandatory_guardrails(self) -> ScanExecutionPolicy:
        """Garante que nenhum parâmetro ultrapasse os limites de segurança nem desative proteções obrigatórias."""
        self.max_requests_per_second = max(
            HARD_CAP_MIN_RPS, min(self.max_requests_per_second, HARD_CAP_MAX_RPS)
        )
        self.max_concurrency = max(
            HARD_CAP_MIN_CONCURRENCY, min(self.max_concurrency, HARD_CAP_MAX_CONCURRENCY)
        )
        self.request_timeout_seconds = max(
            HARD_CAP_MIN_REQUEST_TIMEOUT,
            min(self.request_timeout_seconds, HARD_CAP_MAX_REQUEST_TIMEOUT),
        )
        self.global_timeout_seconds = max(
            HARD_CAP_MIN_GLOBAL_TIMEOUT,
            min(self.global_timeout_seconds, HARD_CAP_MAX_GLOBAL_TIMEOUT),
        )
        self.max_crawl_depth = max(0, min(self.max_crawl_depth, HARD_CAP_MAX_DEPTH))
        self.max_redirects = max(0, min(self.max_redirects, HARD_CAP_MAX_REDIRECTS))
        self.max_response_body_bytes = max(
            4096, min(self.max_response_body_bytes, HARD_CAP_MAX_RESPONSE_BYTES)
        )
        self.circuit_breaker_error_threshold = max(
            2, min(self.circuit_breaker_error_threshold, HARD_CAP_MAX_CIRCUIT_BREAKER_ERRORS)
        )

        # Proteções obrigatórias nunca podem ser desativadas (Seção 12)
        self.respect_http_429_and_503 = True
        self.abort_on_target_degradation = True
        self.prevent_redirect_loops = True

        # Normaliza endpoints excluídos
        normalized_exclusions: list[str] = []
        for path in self.excluded_endpoints:
            cleaned = path.strip()
            if cleaned:
                if not cleaned.startswith("/"):
                    cleaned = f"/{cleaned}"
                if cleaned not in normalized_exclusions:
                    normalized_exclusions.append(cleaned)
        self.excluded_endpoints = normalized_exclusions
        return self


SCAN_PROFILES_CATALOG: dict[ScanProfileType, ScanProfileDescriptor] = {
    ScanProfileType.QUICK: ScanProfileDescriptor(
        profile_type=ScanProfileType.QUICK,
        name="Quick Scan (Rápido e Passivo)",
        description="Verificações rápidas, passivas e de baixíssimo impacto focadas em TLS, HTTPS, Security Headers e Cookies.",
        what_is_analyzed=[
            "Disponibilidade HTTP/HTTPS e cadeia de redirecionamento inicial",
            "Configuração TLS e validade de certificado",
            "Security Headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)",
            "Exposição de banners de servidor (Server, X-Powered-By)",
            "Flags de segurança de Cookies (HttpOnly, Secure, SameSite)",
        ],
        what_is_not_analyzed=[
            "Fluxos autenticados de sessão",
            "Testes ativos de reflexão de parâmetros (XSS)",
            "Indicadores de SQL Injection",
            "Autorização entre recursos de API",
        ],
        potential_impact="Mínimo (1 a 5 requisições HTTP GET/HEAD passivas).",
        impact_level=ImpactLevel.PASSIVE,
        default_max_rps=3,
        default_max_concurrency=2,
        default_timeout_seconds=180,
        prerequisites=["Alvo cadastrado com autorização comprovada."],
        dependencies=["Conectividade HTTP/HTTPS com o alvo autorizado."],
        known_risks=["Nenhum risco de alteração de estado; tráfego equivalente a um acesso comum de navegador."],
        enabled_modules=["mod_a_recon_headers_tls", "mod_e_cookies_session"],
        allowed_in_production=True,
    ),
    ScanProfileType.STANDARD: ScanProfileDescriptor(
        profile_type=ScanProfileType.STANDARD,
        name="Standard Scan (Padrão Web)",
        description="Cobertura ampliada de segurança web com controles conservadores e verificações de baixo impacto.",
        what_is_analyzed=[
            "Todas as verificações do Quick Scan (TLS, Headers, Cookies, DNS)",
            "Postura da página de login e transporte seguro de autenticação",
            "Reflexão controlada com marcadores alfanuméricos inofensivos",
            "Indicadores de rate limiting, CDN/WAF e postura contra sobrecarga",
            "Exposição de arquivos sensíveis e configurações comuns",
        ],
        what_is_not_analyzed=[
            "Rotas internas pós-autenticação que exigem credenciais de teste",
            "Testes profundos de autorização cruzada (IDOR multi-identidade)",
        ],
        potential_impact="Baixo (requisições controladas limitadas a 5 req/s com circuit breaker ativo).",
        impact_level=ImpactLevel.LOW_IMPACT_ACTIVE,
        default_max_rps=5,
        default_max_concurrency=3,
        default_timeout_seconds=600,
        prerequisites=["Alvo cadastrado com autorização comprovada."],
        dependencies=["Conectividade HTTP/HTTPS e resolução DNS."],
        known_risks=["Geração moderada de logs de acesso e possíveis alertas informativos em WAF."],
        enabled_modules=[
            "mod_a_recon_headers_tls",
            "mod_b_auth_login",
            "mod_c_xss_safe",
            "mod_e_cookies_session",
            "mod_f_dos_resilience_posture",
            "mod_h_misconfig_and_other",
        ],
        allowed_in_production=True,
    ),
    ScanProfileType.AUTHENTICATED: ScanProfileDescriptor(
        profile_type=ScanProfileType.AUTHENTICATED,
        name="Authenticated Scan (Varredura Autenticada)",
        description="Verificações de sessão, rotação de tokens, logout e controles de acesso utilizando credenciais de teste autorizadas.",
        what_is_analyzed=[
            "Segurança completa de sessão, expiração e invalidação no logout",
            "Rotação de identificadores de sessão pós-login",
            "Políticas de cookies autenticados e tokens JWT",
            "Controles de acesso em endpoints autenticados",
        ],
        what_is_not_analyzed=[
            "Força bruta de senhas ou enumeração massiva de contas (proibido por política)",
        ],
        potential_impact="Baixo a Moderado nas contas de teste fornecidas.",
        impact_level=ImpactLevel.LOW_IMPACT_ACTIVE,
        default_max_rps=4,
        default_max_concurrency=2,
        default_timeout_seconds=900,
        prerequisites=[
            "Alvo com autorização comprovada.",
            "Credenciais dedicadas de conta de teste fornecidas pelo responsável.",
        ],
        dependencies=["Configuração de credenciais de teste no cofre do ativo."],
        known_risks=["Invalidação de sessões concorrentes da mesma conta de teste durante a verificação de logout."],
        enabled_modules=[
            "mod_a_recon_headers_tls",
            "mod_b_auth_login",
            "mod_e_cookies_session",
            "mod_g_api_security",
            "mod_h_misconfig_and_other",
        ],
        allowed_in_production=True,
    ),
    ScanProfileType.API: ScanProfileDescriptor(
        profile_type=ScanProfileType.API,
        name="API Security Scan (REST & GraphQL)",
        description="Auditoria especializada em APIs REST e GraphQL baseada no OWASP API Security Top 10.",
        what_is_analyzed=[
            "Políticas de CORS e permissividade de origens/credenciais",
            "Exposição indevida de especificações OpenAPI/Swagger e introspecção GraphQL",
            "Métodos HTTP habilitados, validação de Content-Type e cabeçalhos de cache",
            "Tratamento de erros verbosos (stack traces) e cabeçalhos de Rate Limiting",
        ],
        what_is_not_analyzed=[
            "Renderização de DOM HTML em navegadores",
        ],
        potential_impact="Baixo (chamadas estruturadas de inspeção de metadados e métodos HTTP).",
        impact_level=ImpactLevel.LOW_IMPACT_ACTIVE,
        default_max_rps=5,
        default_max_concurrency=3,
        default_timeout_seconds=600,
        prerequisites=["Endpoint de API com autorização comprovada."],
        dependencies=["Opcional: especificação OpenAPI/Swagger ou token de leitura de teste."],
        known_risks=["Registros de requisições OPTIONS/HEAD e erros 400/405 nos logs da API."],
        enabled_modules=[
            "mod_a_recon_headers_tls",
            "mod_f_dos_resilience_posture",
            "mod_g_api_security",
            "mod_h_misconfig_and_other",
        ],
        allowed_in_production=True,
    ),
    ScanProfileType.DEEP_ASSESSMENT: ScanProfileDescriptor(
        profile_type=ScanProfileType.DEEP_ASSESSMENT,
        name="Deep Assessment (Homologação / Laboratório)",
        description="Auditoria técnica detalhada incluindo verificações controladas de entrada, SQLi não destrutivo e controle de acesso em ambientes não produtivos.",
        what_is_analyzed=[
            "Todos os módulos A a H habilitados",
            "Testes controlados não destrutivos de sintaxe/parametrização (SQLi seguro)",
            "Verificação de Path Traversal, Open Redirect, CSRF e controle de acesso entre papéis",
        ],
        what_is_not_analyzed=[
            "Ataques destrutivos, extração de dados reais ou geração de carga de DoS",
        ],
        potential_impact="Moderado (restrito a ambientes de Homologação, Desenvolvimento ou Laboratório).",
        impact_level=ImpactLevel.CONTROLLED_ASSESSMENT,
        default_max_rps=8,
        default_max_concurrency=4,
        default_timeout_seconds=1800,
        prerequisites=[
            "Ambiente classificado como STAGING, DEVELOPMENT ou LAB (bloqueado para PRODUCTION por padrão).",
            "Autorização comprovada e janela de testes válida.",
        ],
        dependencies=["Conectividade com ambiente de homologação/laboratório."],
        known_risks=["Pode acionar regras de bloqueio em WAF ou gerar entradas de erro nos logs da aplicação de homologação."],
        enabled_modules=[
            "mod_a_recon_headers_tls",
            "mod_b_auth_login",
            "mod_c_xss_safe",
            "mod_d_sqli_indicators",
            "mod_e_cookies_session",
            "mod_f_dos_resilience_posture",
            "mod_g_api_security",
            "mod_h_misconfig_and_other",
        ],
        allowed_in_production=False,
    ),
    ScanProfileType.CUSTOM: ScanProfileDescriptor(
        profile_type=ScanProfileType.CUSTOM,
        name="Custom Scan (Seleção Manual de Módulos)",
        description="Permite selecionar manualmente os módulos desejados respeitando os limites operacionais obrigatórios e restrições de ambiente.",
        what_is_analyzed=["Definido pela seleção manual de módulos habilitados pelo analista."],
        what_is_not_analyzed=["Módulos desmarcados pelo usuário ou incompatíveis com o ambiente de produção."],
        potential_impact="Variável conforme módulos selecionados, sempre limitado pelos guardrails operacionais.",
        impact_level=ImpactLevel.LOW_IMPACT_ACTIVE,
        default_max_rps=5,
        default_max_concurrency=3,
        default_timeout_seconds=600,
        prerequisites=["Alvo cadastrado com autorização comprovada."],
        dependencies=["Ao menos um módulo de segurança habilitado."],
        known_risks=["Dependente dos módulos selecionados."],
        enabled_modules=["mod_a_recon_headers_tls"],
        allowed_in_production=True,
    ),
}


def get_scan_profiles() -> list[ScanProfileDescriptor]:
    """Retorna a lista completa de perfis de auditoria disponíveis."""
    return list(SCAN_PROFILES_CATALOG.values())
