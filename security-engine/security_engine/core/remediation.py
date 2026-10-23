"""Motor de recomendações técnicas de correção versionadas (RemediationEngine - Seção 10)."""

from __future__ import annotations

from abc import ABC, abstractmethod

from security_engine.core.contracts import RemediationGuidance, StackCodeExample

REMEDIATION_CATALOG: dict[str, RemediationGuidance] = {
    "missing_hsts": RemediationGuidance(
        remediation_id="missing_hsts",
        version="1.0.0",
        what_was_identified=(
            "O cabeçalho HTTP Strict-Transport-Security (HSTS) está ausente ou configurado com "
            "tempo de vida (max-age) insuficiente na resposta HTTPS."
        ),
        why_it_is_dangerous=(
            "Sem o cabeçalho HSTS, navegadores podem realizar a primeira conexão via HTTP em texto claro, "
            "expondo o usuário a ataques de interceptação (SSL Stripping / Man-in-the-Middle) antes que "
            "o redirecionamento para HTTPS ocorra."
        ),
        how_it_was_detected=(
            "Inspeção passiva dos cabeçalhos de resposta HTTP do endpoint principal, verificando a presença "
            "e as diretivas do cabeçalho 'Strict-Transport-Security'."
        ),
        how_to_fix=(
            "Configure o servidor web, proxy reverso ou camada de aplicação para enviar o cabeçalho "
            "'Strict-Transport-Security' em todas as respostas HTTPS com 'max-age' mínimo de 31536000 (1 ano) "
            "e adicione 'includeSubDomains' caso todos os subdomínios suportem HTTPS."
        ),
        secure_examples=[
            StackCodeExample(
                technology="Nginx",
                language="nginx",
                description="Adicionar no bloco server SSL (443):",
                code='add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
            ),
            StackCodeExample(
                technology="Apache",
                language="apache",
                description="Habilitar mod_headers e adicionar no VirtualHost *:443:",
                code='Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"',
            ),
            StackCodeExample(
                technology="Node.js (Express / Helmet)",
                language="typescript",
                description="Configuração explícita do HSTS via Helmet:",
                code=(
                    "import helmet from 'helmet';\n"
                    "app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true }));"
                ),
            ),
            StackCodeExample(
                technology="Python (FastAPI)",
                language="python",
                description="Middleware de cabeçalho de segurança em FastAPI:",
                code=(
                    '@app.middleware("http")\n'
                    "async def add_hsts_header(request: Request, call_next):\n"
                    "    response = await call_next(request)\n"
                    '    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"\n'
                    "    return response"
                ),
            ),
        ],
        how_to_validate=(
            "Execute 'curl -s -D- https://<seu-dominio> -o /dev/null | grep -i Strict-Transport-Security' "
            "ou rode novamente o Módulo A no cyber-security-checker e confirme o status PASSED."
        ),
        references=[
            "OWASP ASVS 5.0 - V9.2.1 (HTTP Strict Transport Security)",
            "OWASP WSTG - WSTG-CONF-07 (Test HTTP Strict Transport Security)",
            "CWE-319: Cleartext Transmission of Sensitive Information",
            "RFC 6797 - HTTP Strict Transport Security (HSTS)",
        ],
    ),
    "missing_csp": RemediationGuidance(
        remediation_id="missing_csp",
        version="1.0.0",
        what_was_identified=(
            "O cabeçalho Content-Security-Policy (CSP) está ausente ou utiliza diretivas excessivamente "
            "permissivas como 'unsafe-inline' / 'unsafe-eval' sem proteção complementar por nonces ou hashes."
        ),
        why_it_is_dangerous=(
            "A ausência de uma Content-Security-Policy robusta reduz significativamente a defesa em profundidade "
            "contra ataques de Cross-Site Scripting (XSS), injeção de scripts de terceiros e clickjacking via frame-ancestors."
        ),
        how_it_was_detected=(
            "Análise passiva do cabeçalho 'Content-Security-Policy' e avaliação sintática de suas diretivas "
            "('default-src', 'script-src', 'object-src', 'frame-ancestors')."
        ),
        how_to_fix=(
            "Defina uma política Content-Security-Policy restritiva iniciando com 'default-src \\'self\\'', "
            "'object-src \\'none\\'', 'base-uri \\'self\\'' e 'frame-ancestors \\'none\\'' (ou '\\'self\\''). "
            "Substitua scripts inline por arquivos externos ou utilize 'nonce-<valor-aleatorio>' por requisição."
        ),
        secure_examples=[
            StackCodeExample(
                technology="Nginx",
                language="nginx",
                description="Política CSP restritiva padrão:",
                code=(
                    'add_header Content-Security-Policy '
                    '"default-src \'self\'; script-src \'self\'; object-src \'none\'; '
                    'frame-ancestors \'none\'; base-uri \'self\';" always;'
                ),
            ),
            StackCodeExample(
                technology="Node.js (Next.js / Express)",
                language="typescript",
                description="Cabeçalho Content-Security-Policy seguro:",
                code=(
                    "res.setHeader(\n"
                    "  'Content-Security-Policy',\n"
                    "  \"default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'\"\n"
                    ");"
                ),
            ),
        ],
        how_to_validate=(
            "Verifique os cabeçalhos HTTP de resposta no navegador ou reexecute a verificação de Security Headers "
            "no cyber-security-checker garantindo que nenhum recurso legítimo foi bloqueado no console."
        ),
        references=[
            "OWASP Top 10 2021 - A05:2021 Security Misconfiguration",
            "OWASP ASVS 5.0 - V14.4.3 (Content-Security-Policy)",
            "OWASP Cheat Sheet: Content Security Policy",
            "CWE-693: Protection Mechanism Failure",
        ],
    ),
    "missing_x_content_type_options": RemediationGuidance(
        remediation_id="missing_x_content_type_options",
        version="1.0.0",
        what_was_identified=(
            "O cabeçalho 'X-Content-Type-Options: nosniff' não foi encontrado na resposta HTTP."
        ),
        why_it_is_dangerous=(
            "Sem a diretiva 'nosniff', navegadores podem tentar adivinhar o tipo MIME de uma resposta "
            "(MIME sniffing) e executar arquivos enviados por usuários como HTML ou JavaScript ativo."
        ),
        how_it_was_detected="Inspeção do cabeçalho 'X-Content-Type-Options' na resposta HTTP do servidor.",
        how_to_fix="Adicione o cabeçalho 'X-Content-Type-Options: nosniff' em todas as respostas da aplicação.",
        secure_examples=[
            StackCodeExample(
                technology="Nginx",
                language="nginx",
                description="Adicionar diretiva nosniff:",
                code='add_header X-Content-Type-Options "nosniff" always;',
            ),
            StackCodeExample(
                technology="Python (FastAPI)",
                language="python",
                description="Definir cabeçalho nosniff no middleware:",
                code='response.headers["X-Content-Type-Options"] = "nosniff"',
            ),
        ],
        how_to_validate="Reexecute o Módulo A e verifique que 'X-Content-Type-Options' retorna exatamente 'nosniff'.",
        references=[
            "OWASP ASVS 5.0 - V14.4.1",
            "CWE-16: Configuration",
        ],
    ),
    "missing_clickjacking_protection": RemediationGuidance(
        remediation_id="missing_clickjacking_protection",
        version="1.0.0",
        what_was_identified=(
            "A aplicação não define 'X-Frame-Options' (DENY ou SAMEORIGIN) nem a diretiva 'frame-ancestors' "
            "no Content-Security-Policy."
        ),
        why_it_is_dangerous=(
            "Páginas desprotegidas podem ser embutidas em um '<iframe>' invisível dentro de um domínio malicioso, "
            "induzindo usuários autenticados a clicarem em botões críticos sem perceber (Clickjacking / UI Redressing)."
        ),
        how_it_was_detected=(
            "Verificação simultânea da ausência de 'X-Frame-Options' e da diretiva 'frame-ancestors' em 'Content-Security-Policy'."
        ),
        how_to_fix=(
            "Defina 'X-Frame-Options: DENY' (ou 'SAMEORIGIN') e adicione 'frame-ancestors \\'none\\'' no cabeçalho "
            "Content-Security-Policy."
        ),
        secure_examples=[
            StackCodeExample(
                technology="Nginx",
                language="nginx",
                description="Bloqueio de enquadramento (Clickjacking):",
                code='add_header X-Frame-Options "DENY" always;',
            ),
            StackCodeExample(
                technology="Apache",
                language="apache",
                description="Configuração via mod_headers:",
                code='Header always set X-Frame-Options "DENY"',
            ),
        ],
        how_to_validate="Confirme a presença do cabeçalho 'X-Frame-Options: DENY' ou 'SAMEORIGIN' na resposta HTTP.",
        references=[
            "OWASP WSTG - WSTG-CLNT-09 (Testing for Clickjacking)",
            "CWE-1021: Improper Restriction of Rendered UI Layers or Frames",
        ],
    ),
    "server_version_disclosure": RemediationGuidance(
        remediation_id="server_version_disclosure",
        version="1.0.0",
        what_was_identified=(
            "O servidor expõe informações detalhadas de versão ou tecnologia nos cabeçalhos 'Server' ou 'X-Powered-By'."
        ),
        why_it_is_dangerous=(
            "A divulgação exata de versões de servidor e runtime facilita o reconhecimento automatizado por atacantes "
            "que buscam vulnerabilidades públicas específicas daquela versão."
        ),
        how_it_was_detected=(
            "Análise de expressões de versão numérica nos cabeçalhos 'Server', 'X-Powered-By' e 'X-AspNet-Version'."
        ),
        how_to_fix=(
            "Oculte a versão detalhada no servidor web (ex: 'server_tokens off' no Nginx) e desative o cabeçalho "
            "'X-Powered-By' no framework de aplicação."
        ),
        secure_examples=[
            StackCodeExample(
                technology="Nginx",
                language="nginx",
                description="Desativar exposição de versão no bloco http:",
                code="server_tokens off;",
            ),
            StackCodeExample(
                technology="Node.js (Express)",
                language="typescript",
                description="Desabilitar cabeçalho X-Powered-By:",
                code="app.disable('x-powered-by');",
            ),
        ],
        how_to_validate="Inspecione os cabeçalhos HTTP de resposta e confirme que números de versão não são mais exibidos.",
        references=[
            "OWASP WSTG - WSTG-INFO-02 (Fingerprint Web Server)",
            "OWASP Top 10 2021 - A05:2021 Security Misconfiguration",
            "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
        ],
    ),
    "insecure_cookie_flags": RemediationGuidance(
        remediation_id="insecure_cookie_flags",
        version="1.0.0",
        what_was_identified=(
            "Um ou mais cookies de sessão ou estado foram emitidos sem os atributos de segurança obrigatórios "
            "('Secure', 'HttpOnly' e 'SameSite')."
        ),
        why_it_is_dangerous=(
            "Cookies sem 'Secure' podem vazar em conexões HTTP não criptografadas; sem 'HttpOnly' podem ser lidos "
            "por scripts via 'document.cookie' em caso de XSS; sem 'SameSite' ficam mais expostos a requisições "
            "forjadas entre sites (CSRF)."
        ),
        how_it_was_detected=(
            "Análise individual dos cabeçalhos 'Set-Cookie' com valores sensíveis mascarados pelo EvidenceManager."
        ),
        how_to_fix=(
            "Configure todos os cookies de sessão e autenticação com as flags 'Secure', 'HttpOnly' e "
            "'SameSite=Lax' (ou 'Strict')."
        ),
        secure_examples=[
            StackCodeExample(
                technology="Python (FastAPI / Starlette)",
                language="python",
                description="Definição segura de cookie:",
                code=(
                    "response.set_cookie(\n"
                    '    key="session_id",\n'
                    "    value=session_token,\n"
                    "    httponly=True,\n"
                    "    secure=True,\n"
                    '    samesite="lax",\n'
                    "    max_age=3600,\n"
                    ")"
                ),
            ),
            StackCodeExample(
                technology="Node.js (Express)",
                language="typescript",
                description="Configuração de cookie de sessão:",
                code=(
                    "res.cookie('session_id', token, {\n"
                    "  httpOnly: true,\n"
                    "  secure: true,\n"
                    "  sameSite: 'lax',\n"
                    "  maxAge: 3600000,\n"
                    "});"
                ),
            ),
        ],
        how_to_validate=(
            "Verifique o cabeçalho 'Set-Cookie' retornado no login e reexecute o Módulo E no cyber-security-checker."
        ),
        references=[
            "OWASP ASVS 5.0 - V3.4 (Cookie-based Session Management)",
            "OWASP WSTG - WSTG-SESS-02 (Testing for Cookies Attributes)",
            "CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
            "CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag",
        ],
    ),
    "cleartext_http_transport": RemediationGuidance(
        remediation_id="cleartext_http_transport",
        version="1.0.0",
        what_was_identified=(
            "O serviço responde diretamente sobre HTTP em texto claro ou não redireciona automaticamente "
            "requisições HTTP (porta 80) para HTTPS (porta 443)."
        ),
        why_it_is_dangerous=(
            "Tráfego HTTP não criptografado permite interceptação passiva e modificação ativa de credenciais, "
            "tokens de sessão e dados sensíveis em trânsito (Man-in-the-Middle)."
        ),
        how_it_was_detected=(
            "Inspeção do esquema da URL final e análise da cadeia de redirecionamento HTTP -> HTTPS."
        ),
        how_to_fix=(
            "Configure redirecionamento permanente (HTTP 301 ou 308) de todas as requisições HTTP para HTTPS "
            "no proxy reverso ou balanceador de carga e habilite HSTS."
        ),
        secure_examples=[
            StackCodeExample(
                technology="Nginx",
                language="nginx",
                description="Redirecionamento permanente de HTTP para HTTPS:",
                code=(
                    "server {\n"
                    "    listen 80;\n"
                    "    server_name exemplo.interno;\n"
                    "    return 301 https://$host$request_uri;\n"
                    "}"
                ),
            ),
        ],
        how_to_validate="Realize uma requisição HTTP e confirme que o servidor responde com 301/308 apontando para https://.",
        references=[
            "OWASP Top 10 2021 - A02:2021 Cryptographic Failures",
            "OWASP ASVS 5.0 - V9.1.1",
            "CWE-319: Cleartext Transmission of Sensitive Information",
        ],
    ),
    "weak_csp_directives": RemediationGuidance(
        remediation_id="weak_csp_directives",
        version="1.0.0",
        what_was_identified=(
            "O cabeçalho Content-Security-Policy está presente, mas contém diretivas permissivas como "
            "'unsafe-inline', 'unsafe-eval' ou origens curinga ('*') sem proteção por nonce/hash."
        ),
        why_it_is_dangerous=(
            "Diretivas como 'unsafe-inline' e 'unsafe-eval' anulam a principal proteção do CSP contra "
            "execução de código arbitrário via Cross-Site Scripting (XSS)."
        ),
        how_it_was_detected="Análise sintática das diretivas script-src e default-src do cabeçalho Content-Security-Policy.",
        how_to_fix=(
            "Remova 'unsafe-inline', 'unsafe-eval' e origens '*' de script-src/default-src, utilizando "
            "hashes criptográficos (sha256-...) ou nonces gerados por requisição."
        ),
        secure_examples=[
            StackCodeExample(
                technology="HTTP Header",
                language="http",
                description="CSP sem unsafe-inline/unsafe-eval:",
                code="Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'",
            ),
        ],
        how_to_validate="Inspecione o cabeçalho Content-Security-Policy e confirme a ausência de 'unsafe-inline' e 'unsafe-eval'.",
        references=[
            "OWASP ASVS 5.0 - V14.4.3",
            "OWASP WSTG - WSTG-CONF-12",
            "CWE-693: Protection Mechanism Failure",
        ],
    ),
    "missing_referrer_or_permissions_policy": RemediationGuidance(
        remediation_id="missing_referrer_or_permissions_policy",
        version="1.0.0",
        what_was_identified=(
            "Os cabeçalhos Referrer-Policy e/ou Permissions-Policy estão ausentes ou configurados "
            "com diretivas inseguras (como 'unsafe-url')."
        ),
        why_it_is_dangerous=(
            "Sem Referrer-Policy adequado, URLs internas e parâmetros sensíveis podem vazar no cabeçalho "
            "Referer para terceiros; sem Permissions-Policy, APIs sensíveis do navegador (câmera, microfone, "
            "geolocalização) permanecem disponíveis para contextos incorporados."
        ),
        how_it_was_detected="Inspeção passiva dos cabeçalhos Referrer-Policy e Permissions-Policy na resposta HTTP.",
        how_to_fix=(
            "Adicione 'Referrer-Policy: strict-origin-when-cross-origin' (ou 'no-referrer') e "
            "'Permissions-Policy: geolocation=(), microphone=(), camera=()' nas respostas HTTP."
        ),
        secure_examples=[
            StackCodeExample(
                technology="Nginx",
                language="nginx",
                description="Configuração de Referrer-Policy e Permissions-Policy:",
                code=(
                    'add_header Referrer-Policy "strict-origin-when-cross-origin" always;\n'
                    'add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;'
                ),
            ),
        ],
        how_to_validate="Confirme a presença de ambos os cabeçalhos nas respostas HTTP do ativo.",
        references=[
            "OWASP ASVS 5.0 - V14.4.5 & V14.4.6",
            "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
        ],
    ),
    "tls_certificate_expired_or_expiring": RemediationGuidance(
        remediation_id="tls_certificate_expired_or_expiring",
        version="1.0.0",
        what_was_identified="O certificado TLS apresentado pelo servidor está expirado ou próximo da data de expiração.",
        why_it_is_dangerous=(
            "Certificados expirados interrompem conexões seguras, causam alertas críticos nos clientes "
            "e incentivam usuários a contornarem avisos de segurança."
        ),
        how_it_was_detected="Inspeção dos campos notBefore e notAfter do certificado X.509 apresentado no handshake TLS.",
        how_to_fix="Renove imediatamente o certificado TLS e automatize a renovação periódica (ex: ACME / Let's Encrypt).",
        secure_examples=[],
        how_to_validate="Execute uma nova verificação TLS e confirme que a validade restante é superior a 30 dias.",
        references=[
            "OWASP ASVS 5.0 - V9.1.2",
            "OWASP WSTG - WSTG-CRYP-01",
            "CWE-298: Improper Validation of Certificate Expiration",
        ],
    ),
    "tls_untrusted_or_hostname_mismatch": RemediationGuidance(
        remediation_id="tls_untrusted_or_hostname_mismatch",
        version="1.0.0",
        what_was_identified=(
            "O certificado TLS possui falha na validação da cadeia de confiança (ex: autoassinado ou CA "
            "intermediária ausente) ou não corresponde ao hostname do ativo (Subject CN / SAN)."
        ),
        why_it_is_dangerous=(
            "Sem validação confiável da cadeia e do hostname, clientes não conseguem distinguir o servidor "
            "legítimo de um atacante posicionado na rede (Man-in-the-Middle)."
        ),
        how_it_was_detected="Validação da cadeia X.509 e correspondência de hostname (SubjectAltName) durante o handshake TLS.",
        how_to_fix=(
            "Instale um certificado emitido por uma Autoridade Certificadora (CA) confiável contendo o hostname "
            "exato na extensão Subject Alternative Name (SAN) e inclua toda a cadeia intermediária."
        ),
        secure_examples=[],
        how_to_validate="Reexecute o scanner TLS e verifique que trusted_chain e hostname_matched resultam em PASSED.",
        references=[
            "OWASP Top 10 2021 - A02:2021 Cryptographic Failures",
            "OWASP WSTG - WSTG-CRYP-01",
            "CWE-295: Improper Certificate Validation",
            "CWE-297: Improper Validation of Certificate with Host Mismatch",
        ],
    ),
    "tls_weak_protocol_version": RemediationGuidance(
        remediation_id="tls_weak_protocol_version",
        version="1.0.0",
        what_was_identified="O servidor suporta ou negociou versões obsoletas do protocolo TLS (TLS 1.0 ou TLS 1.1).",
        why_it_is_dangerous=(
            "Protocolos legados (TLS 1.0/1.1) possuem fraquezas criptográficas conhecidas (como BEAST, CRIME, "
            "ausência de AEAD moderno) e foram formalmente depreciados pela RFC 8996."
        ),
        how_it_was_detected="Verificação não invasiva da versão negociada de protocolo TLS no handshake.",
        how_to_fix="Desabilite TLS 1.0 e TLS 1.1 no servidor web/balanceador, permitindo exclusivamente TLS 1.2 e TLS 1.3.",
        secure_examples=[
            StackCodeExample(
                technology="Nginx",
                language="nginx",
                description="Habilitar apenas TLS 1.2 e TLS 1.3:",
                code="ssl_protocols TLSv1.2 TLSv1.3;",
            ),
        ],
        how_to_validate="Reexecute a verificação TLS e confirme que apenas TLSv1.2 ou TLSv1.3 são negociados.",
        references=[
            "RFC 8996 - Deprecating TLS 1.0 and TLS 1.1",
            "OWASP ASVS 5.0 - V9.1.3",
            "CWE-326: Inadequate Encryption Strength",
        ],
    ),
    "verbose_error_or_stack_trace_disclosure": RemediationGuidance(
        remediation_id="verbose_error_or_stack_trace_disclosure",
        version="1.0.0",
        what_was_identified=(
            "O corpo da resposta HTTP contém stack traces, caminhos internos de arquivos, detalhes de banco de dados "
            "ou mensagens de depuração verbosas."
        ),
        why_it_is_dangerous=(
            "Mensagens de erro técnicas revelam estrutura de diretórios, versões de bibliotecas, consultas internas "
            "e lógica de negócio para atacantes."
        ),
        how_it_was_detected="Inspeção determinística de assinaturas de stack traces e páginas de debug no corpo da resposta HTTP.",
        how_to_fix=(
            "Desative o modo debug em produção (DEBUG=False) e implemente tratadores globais de exceção que "
            "retornem mensagens genéricas ao cliente, registrando detalhes apenas nos logs internos."
        ),
        secure_examples=[
            StackCodeExample(
                technology="Python (FastAPI)",
                language="python",
                description="Exception handler global sem exposição de stack trace:",
                code=(
                    "@app.exception_handler(Exception)\n"
                    "async def generic_exception_handler(request: Request, exc: Exception):\n"
                    '    return JSONResponse(status_code=500, content={"detail": "Erro interno do servidor."})'
                ),
            ),
        ],
        how_to_validate="Inspecione respostas de erro da aplicação e confirme que nenhum stack trace é retornado.",
        references=[
            "OWASP Top 10 2021 - A05:2021 Security Misconfiguration",
            "OWASP ASVS 5.0 - V7.4.1",
            "CWE-209: Generation of Error Message Containing Sensitive Information",
        ],
    ),
    "cookie_incompatible_or_broad_attributes": RemediationGuidance(
        remediation_id="cookie_incompatible_or_broad_attributes",
        version="1.0.0",
        what_was_identified=(
            "O cookie apresenta combinação inválida ou arriscada de atributos, como 'SameSite=None' sem a flag "
            "'Secure', escopo de Domain excessivamente amplo ou validade excessiva."
        ),
        why_it_is_dangerous=(
            "Cookies com 'SameSite=None' sem 'Secure' são rejeitados por navegadores modernos ou transmitidos "
            "de forma insegura em contextos cross-site; domínios amplos expõem o cookie a subdomínios menos seguros."
        ),
        how_it_was_detected="Análise individual das diretivas Set-Cookie (SameSite, Secure, Domain, Path, Max-Age/Expires).",
        how_to_fix=(
            "Sempre que utilizar 'SameSite=None', inclua obrigatoriamente a flag 'Secure'. Restrinja o atributo "
            "'Domain' ao host estritamente necessário e limite 'Max-Age' para cookies de sessão."
        ),
        secure_examples=[],
        how_to_validate="Reexecute o Módulo E e confirme a aprovação de todos os atributos do cookie.",
        references=[
            "OWASP ASVS 5.0 - V3.4",
            "CWE-1275: Sensitive Cookie with Improper SameSite Attribute",
        ],
    ),
    "missing_spf_or_dmarc": RemediationGuidance(
        remediation_id="missing_spf_or_dmarc",
        version="1.0.0",
        what_was_identified="Registros DNS SPF (Sender Policy Framework) e/ou DMARC ausentes ou configurados de forma permissiva na zona de domínio.",
        why_it_is_dangerous="Permite que terceiros forjem e-mails utilizando o nome de domínio da organização (email spoofing, phishing e BEC).",
        how_it_was_detected="Consulta passiva aos registros DNS TXT do domínio principal e do subdomínio '_dmarc.<dominio>'.",
        how_to_fix="Adicione um registro TXT com política SPF restritiva (ex: 'v=spf1 -all' ou com os IPs dos remetentes autorizados) e uma política DMARC com rejeição (ex: 'v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s').",
        secure_examples=[
            StackCodeExample(
                technology="DNS (Zona BIND / Cloudflare)",
                language="text",
                description="Registros TXT recomendados na zona DNS:",
                code='@ TXT "v=spf1 -all"\n_dmarc TXT "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; rua=mailto:dmarc-reports@exemplo.com"',
            )
        ],
        how_to_validate="Execute uma nova auditoria ou consulte via 'dig TXT <dominio>' e 'dig TXT _dmarc.<dominio>'.",
        references=["RFC 7208 (SPF)", "RFC 7489 (DMARC)", "NIST SP 800-177"],
    ),
    "insecure_auth_transport": RemediationGuidance(
        remediation_id="insecure_auth_transport",
        version="1.0.0",
        what_was_identified="Formulário ou endpoint de autenticação servido ou submetido via HTTP em texto claro.",
        why_it_is_dangerous="Credenciais e senhas transitam em texto claro na rede, permitindo interceptação por agentes maliciosos no mesmo segmento de rede (MitM).",
        how_it_was_detected="Inspeção da URL de entrega da página de autenticação e do atributo 'action' dos formulários de login.",
        how_to_fix="Garanta que todas as páginas de login sejam acessadas exclusivamente via HTTPS e que o formulário aponte para uma URL segura HTTPS.",
        secure_examples=[
            StackCodeExample(
                technology="HTML",
                language="html",
                description="Formulário de login seguro apontando para HTTPS:",
                code='<form method="POST" action="https://exemplo.com/api/v1/auth/login">\n  <input type="email" name="email" required />\n  <input type="password" name="password" required />\n  <button type="submit">Entrar</button>\n</form>',
            )
        ],
        how_to_validate="Reexecute a auditoria do Módulo B e verifique se todas as ações de autenticação utilizam HTTPS.",
        references=["OWASP Top 10 A07:2021", "OWASP ASVS 5.0 V2.1.1", "CWE-319: Cleartext Transmission of Sensitive Information"],
    ),
    "user_enumeration_in_auth": RemediationGuidance(
        remediation_id="user_enumeration_in_auth",
        version="1.0.0",
        what_was_identified="Mensagens de erro de autenticação distinguem entre nome de usuário inexistente e senha incorreta.",
        why_it_is_dangerous="Permite que invasores descubram contas válidas no sistema por tentativa e erro (enumeração de usuários para ataques de força bruta).",
        how_it_was_detected="Análise de respostas de erro na submissão de credenciais com mensagens verbosas de distinção de usuário.",
        how_to_fix="Adote mensagens de erro genéricas e unificadas, como 'E-mail ou senha inválidos', em todas as respostas de falha de login.",
        secure_examples=[
            StackCodeExample(
                technology="Python (FastAPI)",
                language="python",
                description="Tratamento unificado de erro de autenticação:",
                code='if not user or not verify_password(password, user.password_hash):\n    raise HTTPException(status_code=401, detail="Credenciais inválidas")',
            )
        ],
        how_to_validate="Submeta credenciais inválidas com usuário existente e inexistente; ambas devem produzir exatamente a mesma resposta genérica.",
        references=["OWASP WSTG-ATHN-02", "OWASP ASVS 5.0 V2.2.2", "CWE-204: Observable Response Discrepancy"],
    ),
    "auth_sensitive_caching": RemediationGuidance(
        remediation_id="auth_sensitive_caching",
        version="1.0.0",
        what_was_identified="Páginas ou respostas de autenticação não configuram 'Cache-Control: no-store'.",
        why_it_is_dangerous="Tokens de sessão, credenciais ou dados pessoais podem ser armazenados em cache de navegador ou proxies intermediários compartilhados.",
        how_it_was_detected="Inspeção dos cabeçalhos Cache-Control e Pragma em endpoints e telas de autenticação.",
        how_to_fix="Adicione o cabeçalho 'Cache-Control: no-store, no-cache, must-revalidate' e 'Pragma: no-cache' em todos os fluxos de login.",
        secure_examples=[
            StackCodeExample(
                technology="FastAPI",
                language="python",
                description="Desabilitar cache em respostas de autenticação:",
                code='response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"\nresponse.headers["Pragma"] = "no-cache"',
            )
        ],
        how_to_validate="Verifique se as respostas HTTP do endpoint de autenticação contêm o cabeçalho 'Cache-Control: no-store'.",
        references=["OWASP ASVS 5.0 V8.3.4", "CWE-525: Use of Web Browser Cache Containing Sensitive Information"],
    ),
    "reflected_xss_indicator": RemediationGuidance(
        remediation_id="reflected_xss_indicator",
        version="1.0.0",
        what_was_identified="Parâmetros de entrada enviados na URL são refletidos diretamente na resposta HTML sem codificação contextual apropriada.",
        why_it_is_dangerous="Possibilita a injeção e execução de scripts maliciosos (Cross-Site Scripting) no navegador dos usuários que acessarem a URL manipulada.",
        how_it_was_detected="Envio de marcadores alfanuméricos inofensivos em parâmetros de teste e verificação de reflexão de caracteres especiais (<, >, \", ') sem escape.",
        how_to_fix="Aplique codificação contextual de saída (HTML Entity Encoding) antes de renderizar dados fornecidos pelo usuário no HTML.",
        secure_examples=[
            StackCodeExample(
                technology="Python (Jinja2 / FastAPI)",
                language="python",
                description="Auto-escaping ativado por padrão em templates Jinja2 e uso de markupsafe:",
                code="from markupsafe import escape\nsafe_output = escape(user_input)",
            ),
            StackCodeExample(
                technology="Node.js / React",
                language="typescript",
                description="Uso seguro de JSX/React (evitar dangerouslySetInnerHTML):",
                code="return <div>{userInput}</div>; // O React realiza escape automático por padrão",
            ),
        ],
        how_to_validate="Reexecute a auditoria do Módulo C e confirme que os caracteres especiais são codificados (ex: &lt;, &gt;, &quot;).",
        references=["OWASP Top 10 A03:2021", "OWASP WSTG-INPV-01", "OWASP ASVS 5.0 V5.3.1", "CWE-79: Cross-site Scripting"],
    ),
    "dangerous_dom_xss_sink": RemediationGuidance(
        remediation_id="dangerous_dom_xss_sink",
        version="1.0.0",
        what_was_identified="Presença de sinks DOM perigosos (ex: innerHTML, document.write, eval) manipulando dados dinâmicos em scripts clientes.",
        why_it_is_dangerous="Permite que dados manipulados pelo usuário no lado cliente (como location.hash ou location.search) sejam interpretados como código JavaScript.",
        how_it_was_detected="Inspeção estática não invasiva do corpo HTML e de scripts embutidos na resposta.",
        how_to_fix="Substitua o uso de 'innerHTML' por 'textContent' ou sanitize o HTML utilizando bibliotecas consolidadas como DOMPurify.",
        secure_examples=[
            StackCodeExample(
                technology="JavaScript / TypeScript",
                language="javascript",
                description="Substituir innerHTML por textContent ou sanitizar:",
                code="// Inseguro: element.innerHTML = userParam;\n// Seguro:\nelement.textContent = userParam;\n// Ou se precisar de HTML seguro:\nelement.innerHTML = DOMPurify.sanitize(userHtml);",
            )
        ],
        how_to_validate="Confirme que nenhum sink dinâmico manipula entradas de URL sem sanitização prévia.",
        references=["OWASP WSTG-CLNT-01", "OWASP ASVS 5.0 V5.3.3", "CWE-79: Cross-site Scripting"],
    ),
    "ineffective_xss_csp": RemediationGuidance(
        remediation_id="ineffective_xss_csp",
        version="1.0.0",
        what_was_identified="A Content-Security-Policy (CSP) permite 'unsafe-inline' ou 'unsafe-eval' sem nonces ou hashes criptográficos na diretiva script-src.",
        why_it_is_dangerous="Anula a eficácia da CSP como camada de defesa em profundidade contra execução de scripts injetados via XSS.",
        how_it_was_detected="Análise das diretivas de script-src e default-src do cabeçalho Content-Security-Policy.",
        how_to_fix="Remova 'unsafe-inline' e utilize nonces dinâmicos ('nonce-...') ou hashes SHA-256 para permitir apenas scripts confiáveis.",
        secure_examples=[
            StackCodeExample(
                technology="Nginx",
                language="nginx",
                description="Configurar CSP estrita com nonces:",
                code='add_header Content-Security-Policy "default-src \'self\'; script-src \'self\' \'nonce-$request_id\'; object-src \'none\';" always;',
            )
        ],
        how_to_validate="Verifique no Módulo A / Módulo C se a diretiva script-src não contém 'unsafe-inline'.",
        references=["OWASP CSP Cheat Sheet", "OWASP ASVS 5.0 V14.4.1", "CWE-79: Cross-site Scripting"],
    ),
    "database_error_disclosure_sqli": RemediationGuidance(
        remediation_id="database_error_disclosure_sqli",
        version="1.0.0",
        what_was_identified="Mensagens de erro ou exceções de banco de dados (ex: SQLSTATE, syntax error, driver exceptions) foram expostas na resposta HTTP.",
        why_it_is_dangerous="Expõe detalhes de implementação do SGBD, estrutura de tabelas/colunas e indica ausência de tratamento seguro de exceções, facilitando a exploração de SQL Injection.",
        how_it_was_detected="Detecção determinística de assinaturas de erro de SGBD (PostgreSQL, MySQL, Oracle, SQL Server, SQLite) no corpo da resposta.",
        how_to_fix="Implemente tratamento global de exceções na aplicação para retornar respostas genéricas e utilize exclusivamente consultas parametrizadas (Prepared Statements).",
        secure_examples=[
            StackCodeExample(
                technology="Python (SQLAlchemy / FastAPI)",
                language="python",
                description="Consulta parametrizada segura via ORM / Prepared Statements:",
                code='stmt = select(User).where(User.username == param_username)\nresult = session.execute(stmt).scalars().first()',
            )
        ],
        how_to_validate="Reexecute o Módulo D e confirme que erros internos resultam em HTTP 400/500 genérico sem vazamento de detalhes de banco.",
        references=["OWASP Top 10 A03:2021", "OWASP WSTG-INPV-05", "OWASP ASVS 5.0 V5.3.4", "CWE-89: SQL Injection", "CWE-209"],
    ),
    "unparameterized_query_pattern": RemediationGuidance(
        remediation_id="unparameterized_query_pattern",
        version="1.0.0",
        what_was_identified="Comportamento de resposta anômalo indicando potencial construção de consultas SQL via concatenação de strings.",
        why_it_is_dangerous="Permite que comandos SQL arbitrários sejam executados no banco de dados, possibilitando vazamento ou destruição de dados.",
        how_it_was_detected="Análise não destrutiva de parâmetros de entrada e comportamento da resposta sob condições limítrofes.",
        how_to_fix="Substitua todas as interpolações de strings por consultas parametrizadas com bind variables nativas do driver de banco de dados.",
        secure_examples=[
            StackCodeExample(
                technology="Node.js (pg / PostgreSQL)",
                language="typescript",
                description="Uso de queries parametrizadas com placeholders $1, $2:",
                code='const result = await pool.query("SELECT * FROM users WHERE id = $1", [userId]);',
            )
        ],
        how_to_validate="Audite as chamadas a bancos de dados no código e confirme o uso de prepared statements.",
        references=["OWASP SQL Injection Prevention Cheat Sheet", "CWE-89: SQL Injection"],
    ),
    "missing_waf_cdn_protection": RemediationGuidance(
        remediation_id="missing_waf_cdn_protection",
        version="1.0.0",
        what_was_identified="Nenhum indicador de CDN (Content Delivery Network) ou Web Application Firewall (WAF) foi detectado nas respostas.",
        why_it_is_dangerous="A infraestrutura de origem fica exposta diretamente a ataques de sobrecarga, bots maliciosos e varreduras automatizadas.",
        how_it_was_detected="Inspeção passiva de cabeçalhos de borda característicos de provedores de CDN/WAF.",
        how_to_fix="Posicione a aplicação atrás de um serviço de borda confiável com CDN e regras de WAF gerenciadas (ex: Cloudflare, AWS CloudFront, Fastly).",
        secure_examples=[],
        how_to_validate="Verifique no Módulo F se os cabeçalhos de borda (ex: cf-ray, x-amz-cf-id) são detectados.",
        references=["OWASP API Security Top 10 API4:2023", "CWE-770"],
    ),
    "missing_rate_limiting_policy": RemediationGuidance(
        remediation_id="missing_rate_limiting_policy",
        version="1.0.0",
        what_was_identified="Ausência de cabeçalhos de limitação de taxa (RateLimit-* ou X-RateLimit-*) informando cotas por cliente.",
        why_it_is_dangerous="Sem controle de taxa, a aplicação pode sofrer exaustão de recursos por requisições concorrentes abusivas.",
        how_it_was_detected="Inspeção passiva de cabeçalhos de limitação de taxa na resposta HTTP.",
        how_to_fix="Implemente controle de taxa na camada de proxy reverso ou API Gateway retornando cabeçalhos padronizados IETF (RateLimit-Limit, RateLimit-Remaining, RateLimit-Reset).",
        secure_examples=[
            StackCodeExample(
                technology="Nginx",
                language="nginx",
                description="Configurar rate limiting no Nginx:",
                code="limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;\nlocation /api/ {\n    limit_req zone=api_limit burst=20 nodelay;\n}",
            )
        ],
        how_to_validate="Envie requisições sucessivas e verifique a presença dos cabeçalhos RateLimit-* na resposta.",
        references=["IETF RFC Draft RateLimit Header Fields for HTTP", "OWASP API4:2023", "CWE-770"],
    ),
    "unrestricted_payload_resource_consumption": RemediationGuidance(
        remediation_id="unrestricted_payload_resource_consumption",
        version="1.0.0",
        what_was_identified="Ausência de restrição explícita no tamanho máximo do corpo de requisições aceitas pela aplicação.",
        why_it_is_dangerous="Envio de cargas massivas pode esgotar memória e capacidade de I/O do servidor, causando negação de serviço.",
        how_it_was_detected="Verificação de configurações e limites declarados de requisição.",
        how_to_fix="Configure limites rígidos de tamanho máximo de payload (ex: 2 MB a 10 MB) na camada de borda e nos parsers de corpo da aplicação.",
        secure_examples=[
            StackCodeExample(
                technology="Nginx",
                language="nginx",
                description="Limitar tamanho de corpo no Nginx:",
                code="client_max_body_size 5M;",
            )
        ],
        how_to_validate="Envie payload acima do limite e verifique se o servidor retorna HTTP 413 Payload Too Large.",
        references=["OWASP ASVS 5.0 V11.1.4", "CWE-400: Uncontrolled Resource Consumption"],
    ),
    "insecure_cors_policy": RemediationGuidance(
        remediation_id="insecure_cors_policy",
        version="1.0.0",
        what_was_identified="Configuração de CORS excessivamente permissiva ('Access-Control-Allow-Origin: *' com credenciais ou reflexão arbitrária de Origin).",
        why_it_is_dangerous="Permite que sites maliciosos de terceiros façam requisições cross-origin autenticadas e capturem dados sensíveis dos usuários.",
        how_it_was_detected="Inspeção dos cabeçalhos Access-Control-Allow-Origin e Access-Control-Allow-Credentials nas respostas HTTP.",
        how_to_fix="Defina uma lista explícita de origens permitidas e nunca retorne '*' quando 'Access-Control-Allow-Credentials' for 'true'.",
        secure_examples=[
            StackCodeExample(
                technology="FastAPI",
                language="python",
                description="Configurar CORS com origens estritas:",
                code='from fastapi.middleware.cors import CORSMiddleware\napp.add_middleware(\n    CORSMiddleware,\n    allow_origins=["https://painel.exemplo.com"],\n    allow_credentials=True,\n    allow_methods=["GET", "POST", "PUT", "DELETE"],\n    allow_headers=["*"],\n)',
            )
        ],
        how_to_validate="Envie uma requisição com 'Origin: https://site-malicioso.com' e confirme que o cabeçalho Access-Control-Allow-Origin não reflete a origem arbitrária.",
        references=["OWASP CORS Cheat Sheet", "OWASP ASVS 5.0 V14.5.3", "CWE-942: Permissive Cross-domain Policy with Untrusted Domains"],
    ),
    "public_api_docs_or_graphql_introspection": RemediationGuidance(
        remediation_id="public_api_docs_or_graphql_introspection",
        version="1.0.0",
        what_was_identified="Documentação de API (Swagger / OpenAPI) ou Introspecção GraphQL acessível publicamente em ambiente produtivo.",
        why_it_is_dangerous="Expõe toda a superfície de ataque, rotas internas, parâmetros e esquemas de dados a usuários não autenticados.",
        how_it_was_detected="Verificação de disponibilidade pública de rotas comuns como /docs, /openapi.json ou /graphql com query de introspecção.",
        how_to_fix="Desabilite a interface de documentação pública e a introspecção GraphQL em produção, ou restrinja o acesso a redes internas autenticadas.",
        secure_examples=[
            StackCodeExample(
                technology="FastAPI",
                language="python",
                description="Desabilitar Swagger/OpenAPI em produção:",
                code='app = FastAPI(\n    docs_url=None if is_production else "/docs",\n    redoc_url=None if is_production else "/redoc",\n    openapi_url=None if is_production else "/openapi.json"\n)',
            )
        ],
        how_to_validate="Acesse /docs e /openapi.json e confirme que retornam HTTP 404 Not Found em produção.",
        references=["OWASP API Security Top 10 API9:2023", "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor"],
    ),
    "insecure_api_http_methods_and_cache": RemediationGuidance(
        remediation_id="insecure_api_http_methods_and_cache",
        version="1.0.0",
        what_was_identified="Métodos HTTP inseguros (como TRACE) habilitados ou ausência de 'Cache-Control: no-store' em respostas de API com dados dinâmicos.",
        why_it_is_dangerous="Métodos como TRACE facilitam ataques de Cross-Site Tracing (XST); falta de no-store pode armazenar respostas sensíveis em caches intermediários.",
        how_it_was_detected="Inspeção dos cabeçalhos Allow / métodos HTTP suportados e políticas de cache em respostas de API.",
        how_to_fix="Desabilite métodos HTTP não utilizados (especialmente TRACE e TRACK) e adicione 'Cache-Control: no-store' para dados de API privados.",
        secure_examples=[
            StackCodeExample(
                technology="Nginx",
                language="nginx",
                description="Bloquear métodos HTTP inseguros no Nginx:",
                code='if ($request_method !~ ^(GET|POST|PUT|DELETE|HEAD|OPTIONS)$) {\n    return 405;\n}',
            )
        ],
        how_to_validate="Envie requisições OPTIONS e TRACE e verifique se o servidor retorna HTTP 405 Method Not Allowed.",
        references=["OWASP WSTG-CONF-06", "OWASP ASVS 5.0 V13.1.5", "CWE-525"],
    ),
    "sensitive_files_exposure": RemediationGuidance(
        remediation_id="sensitive_files_exposure",
        version="1.0.0",
        what_was_identified="Arquivo de configuração sensível, controle de versão ou backup (ex: .env, .git, backup.sql) acessível publicamente no servidor.",
        why_it_is_dangerous="Vaza segredos de aplicação, senhas de banco de dados, chaves de API e código-fonte diretamente para a internet.",
        how_it_was_detected="Tentativa de acesso pontual e não destrutiva a caminhos de arquivos sensíveis comuns com validação de status HTTP 200.",
        how_to_fix="Bloqueie o acesso a arquivos ocultos (iniciados por '.') e extensões de backup (.bak, .sql, .swp) na configuração do servidor web.",
        secure_examples=[
            StackCodeExample(
                technology="Nginx",
                language="nginx",
                description="Bloquear arquivos ocultos e sensíveis no Nginx:",
                code="location ~ /\\.(?!well-known) {\n    deny all;\n    return 404;\n}",
            )
        ],
        how_to_validate="Acesse /.env e /.git/config e confirme que o servidor responde com HTTP 404 ou 403.",
        references=["OWASP WSTG-CONF-04", "OWASP ASVS 5.0 V14.3.3", "CWE-538: Insertion of Sensitive Information into Externally-Accessible File"],
    ),
    "directory_listing_enabled": RemediationGuidance(
        remediation_id="directory_listing_enabled",
        version="1.0.0",
        what_was_identified="A listagem de diretórios (Directory Listing / Index of /) está habilitada no servidor web.",
        why_it_is_dangerous="Permite a enumeração completa de pastas e arquivos estáticos, expondo artefatos que não deveriam ser públicos.",
        how_it_was_detected="Detecção de cabeçalhos e estrutura HTML característica de listagem de diretórios em pastas do servidor.",
        how_to_fix="Desative a funcionalidade de listagem de diretórios no servidor web.",
        secure_examples=[
            StackCodeExample(
                technology="Nginx",
                language="nginx",
                description="Desabilitar autoindex no Nginx:",
                code="autoindex off;",
            ),
            StackCodeExample(
                technology="Apache",
                language="apache",
                description="Desabilitar Indexes no Apache:",
                code="Options -Indexes",
            ),
        ],
        how_to_validate="Acesse diretórios estáticos sem arquivo index padrão e confirme que o acesso é negado (HTTP 403 ou 404).",
        references=["OWASP WSTG-CONF-04", "CWE-548: Exposure of Information Through Directory Listing"],
    ),
    "open_redirect_vulnerability": RemediationGuidance(
        remediation_id="open_redirect_vulnerability",
        version="1.0.0",
        what_was_identified="Parâmetro de redirecionamento (ex: ?redirect=, ?next=, ?url=) aceita domínios externos arbitrários sem validação.",
        why_it_is_dangerous="Facilita ataques de phishing confiáveis, onde o usuário clica em um link do domínio legítimo mas é redirecionado a um site malicioso.",
        how_it_was_detected="Identificação de parâmetros de redirecionamento que refletem URLs com destinos externos sem restrição.",
        how_to_fix="Valide os destinos de redirecionamento contra uma lista restrita de caminhos relativos (iniciados com '/') ou domínios explicitamente permitidos.",
        secure_examples=[
            StackCodeExample(
                technology="Python (FastAPI)",
                language="python",
                description="Validação estrita de redirecionamento relativo:",
                code='def safe_redirect(target_url: str):\n    if not target_url.startswith("/") or target_url.startswith("//"):\n        return RedirectResponse(url="/")\n    return RedirectResponse(url=target_url)',
            )
        ],
        how_to_validate="Tente redirecionar para 'https://exemplo-externo.com' e confirme que a aplicação rejeita o redirecionamento externo.",
        references=["OWASP WSTG-CLNT-04", "OWASP ASVS 5.0 V5.1.5", "CWE-601: URL Redirection to Untrusted Site ('Open Redirect')"],
    ),
    "missing_anti_csrf_protection": RemediationGuidance(
        remediation_id="missing_anti_csrf_protection",
        version="1.0.0",
        what_was_identified="Formulários com método POST ou ações que alteram estado não contêm tokens anti-CSRF e não contam com proteção de cookies SameSite.",
        why_it_is_dangerous="Permite que páginas maliciosas de terceiros forjem requisições não autorizadas em nome do usuário autenticado.",
        how_it_was_detected="Inspeção da estrutura de formulários HTML em busca de campos de token anti-CSRF e das flags SameSite dos cookies de sessão.",
        how_to_fix="Implemente tokens anti-CSRF em todos os formulários que realizem alterações de estado e configure os cookies de sessão com 'SameSite=Lax' ou 'Strict'.",
        secure_examples=[
            StackCodeExample(
                technology="HTML / Django / Flask",
                language="html",
                description="Incluir token CSRF em formulários POST:",
                code='<form method="POST" action="/transfer">\n  <input type="hidden" name="csrf_token" value="{{ csrf_token }}" />\n  ...\n</form>',
            )
        ],
        how_to_validate="Submeta o formulário sem o token anti-CSRF e confirme que o servidor rejeita com HTTP 403 Forbidden.",
        references=["OWASP CSRF Prevention Cheat Sheet", "OWASP ASVS 5.0 V4.2", "CWE-352: Cross-Site Request Forgery (CSRF)"],
    ),
}


class ContextualRemediationAdvisorInterface(ABC):
    """Interface futura para provedores opcionais de explicação contextualizada (Seção 10).

    Garante que nenhuma informação confidencial seja enviada sem consentimento explícito.
    """

    @abstractmethod
    def explain_for_context(
        self,
        remediation_id: str,
        target_stack: str,
        user_consented_to_external_processing: bool = False,
    ) -> RemediationGuidance:
        """Retorna orientação adaptada à stack informada."""


class RemediationEngine:
    """Fornece orientações técnicas determinísticas, versionadas e testáveis para correção de vulnerabilidades."""

    @staticmethod
    def get_guidance(remediation_id: str) -> RemediationGuidance:
        """Busca uma orientação de correção pelo ID ou retorna orientação estruturada padrão."""
        if remediation_id in REMEDIATION_CATALOG:
            return REMEDIATION_CATALOG[remediation_id]

        return RemediationGuidance(
            remediation_id=remediation_id,
            version="1.0.0",
            what_was_identified=f"Descoberta associada ao identificador técnico '{remediation_id}'.",
            why_it_is_dangerous="Pode enfraquecer a postura de defesa em profundidade do ativo analisado.",
            how_it_was_detected="Verificação automatizada executada pelo módulo correspondente do security-engine.",
            how_to_fix="Aplique as configurações recomendadas pelo padrão OWASP ASVS 5.0 para o controle afetado.",
            secure_examples=[],
            how_to_validate="Execute uma nova auditoria no cyber-security-checker após aplicar a correção.",
            references=["OWASP Application Security Verification Standard (ASVS 5.0)"],
        )

    @staticmethod
    def list_all_guidance() -> list[RemediationGuidance]:
        """Lista todo o catálogo de recomendações técnicas disponível."""
        return list(REMEDIATION_CATALOG.values())
