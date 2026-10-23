# DECISIONS.md — Registro de Decisões de Arquitetura (ADRs)

Este documento registra as decisões arquiteturais e técnicas adotadas no desenvolvimento do `cyber-security-checker`, incluindo contexto, alternativas consideradas e justificativas.

---

## ADR-001: Separação do `security-engine` como Pacote Python Independente

- **Status**: Aceito (Fase 0 / Fase 1)
- **Contexto**: O sistema requer que o motor de auditoria seja modular, extensível, testável isoladamente e compartilhável tanto pela API FastAPI (para descoberta de módulos, validação de perfis e catálogo de recomendações) quanto pelos workers Celery (para execução assíncrona das verificações).
- **Decisão**: Estruturar `security-engine/` como um pacote Python instalável (`pyproject.toml` com namespace `security_engine`), contendo `core/` (contratos, políticas, cliente HTTP seguro, sanitizador de evidências, motor de risco e motor de remediação), `modules/` (plugins de verificação A–H), `adapters/` (integrações externas opcionais) e `policies/` (guardrails de escopo e anti-SSRF).
- **Consequências**:
  - Os testes do motor de segurança rodam em milissegundos sem depender de banco de dados.
  - Novos módulos são adicionados em `security-engine/security_engine/modules/` e descobertos automaticamente pelo `PluginRegistry`.

---

## ADR-002: Stack Backend com FastAPI, SQLAlchemy 2.0, Alembic, PostgreSQL 16 e Celery + Redis

- **Status**: Aceito (Fase 0 / Fase 1)
- **Contexto**: Auditorias de segurança envolvem operações de I/O intensivas (conexões TLS, consultas DNS, múltiplas requisições HTTP controladas) que não podem bloquear o event loop da API web. Além disso, os resultados de auditorias exigem integridade transacional e suporte a metadados estruturados (evidências, mapeamentos CWE/OWASP).
- **Decisão**:
  - **FastAPI + Pydantic v2**: Validação rigorosa de esquemas e documentação OpenAPI 3.1 automática.
  - **PostgreSQL 16 + SQLAlchemy 2.0 + Alembic**: Persistência relacional forte combinada com colunas `JSON` / `JSONB` para evidências sanitizadas e playbooks de correção. Compatível em testes unitários/rápidos com SQLite em memória quando necessário e PostgreSQL 16 completo em integração/Docker.
  - **Celery 5 + Redis 7**: Fila de tarefas consolidada com suporte nativo a revogação/cancelamento de tarefas, rastreamento de estado e agendamento via Celery Beat.

---

## ADR-003: Cliente HTTP Encapsulado com Validação Anti-SSRF e Rate Limiting Obrigatório (`ScopedSafeHttpClient`)

- **Status**: Aceito (Fase 0 / Fase 1 / Implementado na Fase 3)
- **Contexto**: Permitir que módulos de segurança façam requisições arbitrárias diretamente via `httpx` ou `requests` criaria risco de SSRF contra a rede interna do servidor onde o scanner está hospedado, além de risco de sobrecarga acidental do alvo.
- **Decisão**: Proibir chamadas diretas de rede nos módulos e exigir o uso do `ScopedSafeHttpClient` fornecido pelo `SecurityEngineRunner`. O cliente aplica:
  1. Resolução DNS prévia e bloqueio de IPs privados/loopback/link-local (exceto alvos explicitamente autorizados no laboratório local via `LAB_ALLOWED_HOSTS`).
  2. *Throttling* baseado em `max_requests_per_second` e semáforo de concorrência (`max_concurrency`).
  3. Inspeção manual de cada redirecionamento HTTP (`follow_redirects=False` nativo + loop controlado validando cada salto via `ScopePolicyValidator.validate_redirect_target`).
  4. Leitura em streaming limitada em bytes (`max_response_body_bytes`) e *circuit breaker* ao detectar respostas `429`/`503` ou timeouts consecutivos.
  5. Inspeção não invasiva de certificados X.509 DER via `ssl` + `cryptography.x509` (validade temporal, SAN/CN, autoassinatura, cadeia de confiança e versão negociada do protocolo TLS).

---

## ADR-004: Distinção Estrita entre Verificação Executada (`ScanCheckResult`) e Vulnerabilidade (`Finding`)

- **Status**: Aceito (Fase 0 / Fase 1)
- **Contexto**: Muitos scanners amadores confundem "teste falhou por timeout" com "sistema seguro", ou tratam qualquer indício superficial como vulnerabilidade confirmada.
- **Decisão**:
  - Toda verificação individual gera um `CheckEvaluationResult` com status explícito: `PASSED`, `VULNERABILITY`, `POTENTIAL_VULNERABILITY`, `INCONCLUSIVE`, `NOT_APPLICABLE` ou `EXECUTION_ERROR`.
  - Somente resultados `VULNERABILITY` e `POTENTIAL_VULNERABILITY` geram registros na tabela de vulnerabilidades (`findings`), sempre acompanhados do grau de confiança (`CERTAIN`, `FIRM`, `TENTATIVE`) e evidências sanitizadas.
  - Falhas técnicas (`EXECUTION_ERROR`) são contabilizadas separadamente no resumo da execução para alertar o analista de que determinada verificação não pôde ser concluída.

---

## ADR-005: Base de Recomendações Determinística e Versionada (Sem Dependência de IA Paga)

- **Status**: Aceito (Fase 0 / Fase 1)
- **Contexto**: O sistema precisa orientar desenvolvedores e administradores sobre como corrigir cada problema com exemplos seguros em múltiplas stacks (Node.js, Python, Nginx, Apache, etc.), sem depender de chaves de API pagas de LLMs externos.
- **Decisão**: Implementar o `RemediationEngine` no `security-engine` com um catálogo estruturado, testável e versionado de playbooks de correção indexados por `check_id` / `cwe_id`, mantendo uma interface abstrata (`RemediationAdvisorInterface`) preparada para futura extensão opcional com IA local ou externa sob consentimento explícito.

---

## ADR-006: Frontend Next.js App Router com Identidade Visual SOC e Dados 100% Reais

- **Status**: Aceito (Fase 0 / Fase 1)
- **Contexto**: A interface deve transmitir confiabilidade técnica de um *Security Operations Center (SOC)*, suportar tema escuro e claro, responder em português brasileiro e nunca apresentar métricas fictícias.
- **Decisão**: Utilizar Next.js (App Router, TypeScript estrito), Tailwind CSS, componentes baseados em `shadcn/ui`, `lucide-react`, `@tanstack/react-query` para sincronização de estado em tempo real com a API FastAPI e `recharts` para visualizações baseadas exclusivamente nos dados persistidos no PostgreSQL.

---

## ADR-007: Autenticação Híbrida (JWT + Cookie HttpOnly), RBAC Multi-Organização e Comprovação Técnica de Domínio

- **Status**: Aceito (Fase 2)
- **Contexto**: A Fase 2 exige isolamento rigoroso entre múltiplas organizações, quatro papéis hierárquicos (`ADMIN`, `SECURITY_ANALYST`, `DEVELOPER`, `VIEWER`) e comprovação técnica real de propriedade/autorização dos alvos antes de qualquer varredura.
- **Decisão**:
  - **Hashing de Senha**: Utilizar `hashlib.scrypt` (`N=16384, r=8, p=1`, salt aleatório de 16 bytes) com comparação em tempo constante (`hmac.compare_digest`), garantindo independência de compiladores C externos em qualquer plataforma.
  - **Sessão Autenticada**: Suportar simultaneamente `Authorization: Bearer <jwt>` e cookie `csc_access_token` (`HttpOnly`, `SameSite=Lax`, `Secure` em produção), revalidando o vínculo `OrganizationMembership` no banco a cada requisição para efeito imediato de revogação de acesso.
  - **Validação de Autorização do Alvo (`TargetAuthorization`)**: Gerar tokens `cyber-sec-checker-verify=<hmac_sha256>` e validar tecnicamente via consulta DNS TXT RFC 1035 (`_cybersecuritychecker.<host>`), requisição HTTP controlada a `/.well-known/cyber-security-checker.txt` (protegida pelo `ScopePolicyValidator`) ou modo `LAB_INTERNAL` restrito a ambientes `LAB`/`DEVELOPMENT` e hosts locais autorizados.

---

## ADR-008: Orquestração Assíncrona (`ScanOrchestrator`), Persistência Incremental e Cancelamento Cooperativo

- **Status**: Aceito (Fase 3)
- **Contexto**: Auditorias de segurança executam múltiplos módulos em sequência ou concorrência controlada. Em caso de falha de um módulo específico, cancelamento solicitado pelo usuário ou indisponibilidade do alvo, o sistema não deve perder as verificações já concluídas nem deixar execuções presas indefinidamente em estado `RUNNING`.
- **Decisão**:
  - **Separar `SecurityEngineRunner` (motor puro em `security-engine`) e `ScanOrchestrator` (persistência e ciclo de vida em `backend/app/services/scan_orchestrator.py`)**:
    - O `SecurityEngineRunner` realiza a coleta de snapshot HTTP/TLS uma única vez por alvo via `ScopedSafeHttpClient`, executa cada módulo selecionado com isolamento de exceções (convertendo falhas inesperadas em `EXECUTION_ERROR` sem derrubar os demais módulos) e dispara callbacks de progresso após cada módulo.
    - O `ScanOrchestrator` persiste incrementalmente cada `ScanCheckResultRecord` e `FindingRecord` (com deduplicação determinística por `fingerprint` dentro da mesma execução), atualiza `progress_percent` e `summary_counts`, e recalcula `asset.risk_score` via `RiskEngine.calculate_asset_risk_score`.
  - **Cancelamento Cooperativo Duplo (Redis + Banco)**: O pedido de cancelamento (`POST /api/v1/scans/{id}/cancel`) grava imediatamente uma chave de sinalização no Redis (`csc:scan:cancel:{scan_id}`), atualiza o estado no PostgreSQL e revoga a task Celery quando aplicável. O callback `is_cancelled()` do `ScopedSafeHttpClient` e do `SecurityEngineRunner` consulta o sinal antes de cada requisição ou módulo, encerrando a execução de forma limpa e preservando os resultados parciais já coletados.

---

## ADR-009: Streaming Server-Sent Events (SSE) com Limite por Organização e Deduplicação Ativa no Banco

- **Status**: Aceito (Fase 4)
- **Contexto**: Acompanhamento de auditorias em tempo real no console SOC não pode saturar conexões do servidor com polling indiscriminado, nem gerar inconsistências nas métricas ativas quando múltiplas auditorias detectam o mesmo problema ao longo do tempo.
- **Decisão**:
  - Implementar streaming unidirecional via Server-Sent Events (`/api/v1/scans/{id}/stream`) com heartbeat periódico a cada 15s e semáforo atômico por organização no Redis (`SSE_MAX_STREAMS_PER_ORG = 5`).
  - Utilizar a CTE/subquery `current_finding_ids_stmt` para deduplicar achados ativos no banco, assegurando que apenas o registro mais recente por `(asset_id, fingerprint)` seja contabilizado no cálculo de risco e nos KPIs do dashboard.

---

## ADR-010: Motor de Relatórios Profissionais (`ReportEngine`), Mitigação de Formula Injection e Comparação Determinística

- **Status**: Aceito (Fase 6)
- **Contexto**: Relatórios de segurança precisam atender a diferentes públicos (executivos, técnicos, auditores) em múltiplos formatos (PDF, HTML, JSON, CSV). A exportação de dados em CSV apresenta risco crítico de *CSV Formula Injection* (DDE/RCE no leitor de planilhas). Além disso, a comparação entre auditorias do mesmo ativo exige diferenciar rigorosamente entre vulnerabilidades corrigidas (comprovadas por verificação `PASSED`), não detectadas por omissão de módulo (`NOT_VERIFIED`), persistentes e novas.
- **Decisão**:
  - **Relatórios Multi-Formato com Isolamento de Tenant**: `ReportEngine` gera PDFs profissionais com diagramação vetorial via ReportLab Platypus, HTML responsivo autônomo, JSON padronizado e CSV tabular.
  - **Sanitização Obrigatória de Células CSV (`sanitize_csv_cell`)**: Qualquer célula que comece com `=`, `+`, `-`, `@`, `\t` ou `\r` (incluindo variações precedidas por espaços) recebe escape seguro com aspas simples (`'`), neutralizando vetores de execução de código em Excel/Calc.
  - **Download Seguro com Tokens Temporários**: URLs públicas de compartilhamento utilizam tokens criptográficos de uso restrito (`download_token`) com expiração temporal (`download_token_expires_at`), registrando cada download em `AuditLog`.
  - **Comparação Determinística com Cobertura Técnica (`ScanComparisonService`)**: Apenas auditorias do mesmo ativo podem ser comparadas. Uma falha só é considerada *Confirmada Remediada* se o módulo e a verificação técnica correspondente foram executados e retornaram `PASSED`. Caso o módulo não tenha sido executado na auditoria B, a falha é classificada como `NOT_VERIFIED` com aviso de diferença de cobertura.
  - **Revalidação Preservativa (`RevalidationService`)**: A revalidação dispara uma execução direcionada do scanner específico no alvo sem sobrescrever nem apagar o registro histórico original da detecção. Se o teste passar, o status de tratamento transita para `RESOLVED_VERIFIED`; se a vulnerabilidade continuar ativa, o status permanece `OPEN`/`IN_PROGRESS` e uma nota de revalidação falha é registrada.

---

## ADR-011: Automação Contínua, Agendamentos com Fuso Horário, Webhooks Assinados (HMAC-SHA256) com Anti-SSRF e Chaves de API para CI/CD

- **Status**: Aceito (Fase 7)
- **Contexto**: A plataforma deve automatizar auditorias periódicas, alertar equipes em canais internos/externos (in-app, email, chat) e permitir integração direta com pipelines CI/CD e sistemas externos (SIEM, SOAR, Jira). Essa automação não pode permitir que ativos não autorizados sejam verificados em segundo plano, que receptores de webhook sejam usados para ataques de SSRF/Port Scanning interno, ou que chaves de API fiquem vulneráveis a vazamentos no banco de dados.
- **Decisão**:
  - **Agendamento Seguro e Revalidação Prévia Obrigatória (`SchedulerService` + `CronSchedulerUtil`)**:
    - Suporte a frequências canônicas (`DAILY`, `WEEKLY`, `MONTHLY`, `ONCE`) e expressões `CRON` de 5 campos validadas com fusos horários IANA (`zoneinfo`), convertendo o cálculo de `next_run_at` de forma determinística em UTC.
    - Antes de qualquer despacho automático, o serviço verifica se o ativo possui autorização ativa e comprovada (`Asset.authorization_status == "VERIFIED"`). Se a autorização expirou ou foi revogada, a execução é interrompida, o status do agendamento é marcado como `FAILED_AUTH`, falhas consecutivas são incrementadas e um alerta de segurança de severidade ALTA é emitido.
    - Políticas de concorrência e *misfire* (`SKIP` vs `RUN_ONCE`) previnem duplicidade de scans concorrentes no mesmo ativo.
  - **Prevenção Anti-SSRF e Tolerância a Falhas em Webhooks (`WebhookService`)**:
    - Endpoints receptores devem ser URLs HTTPS absolutas (ou HTTP restrito a hosts permitidos em laboratório local).
    - A validação de IP resolve DNS e rejeita incondicionalmente endereços de loopback, redes privadas RFC 1918 e metadados de nuvem (`169.254.169.254`), aplicando `ScopePolicyValidator`.
    - Cada entrega HTTP recebe assinatura criptográfica no cabeçalho `X-CSC-Signature: sha256=<hmac>` calculada sobre `timestamp.canonical_payload` usando a chave secreta gerada do webhook, além de `X-CSC-Timestamp` e `X-CSC-Delivery` para proteção contra *replay attacks*.
    - Falhas de entrega registram retentativas com backoff exponencial (`2^attempt * 15s`). Após 10 falhas consecutivas, o endpoint é auto-desativado preventivamente.
  - **Armazenamento Seguro de Chaves de API (`ApiTokenService`)**:
    - Chaves para CI/CD recebem prefixo identificador `csc_live_...` e têm seu segredo exibido **UMA ÚNICA VEZ** no ato da criação.
    - O banco de dados armazena estritamente o hash criptográfico SHA-256 (`token_hash`), o prefixo público e os escopos RBAC granulares (`scans:read`, `scans:write`, etc.).
    - A autenticação Bearer unificada no FastAPI (`deps.py`) reconhece tanto JWT de sessão de usuário quanto tokens `csc_live_...`, validando expiração e revogação e registrando `last_used_at`.
  - **Canal de Alertas e Deduplicação In-App (`NotificationService` + `EmailDeliveryAdapter`)**:
    - Notificações in-app estruturadas por organização com deduplicação temporal configurável para mitigar flood de alertas.
    - O `EmailDeliveryAdapter` suporta SMTP com TLS e modo desenvolvimento local com buffer em memória inspecionável para testes automatizados.
    - O `TemplateService` provê padrões da indústria (OWASP Web, APIs REST, Perímetro) e adaptadores para geração de alertas em formato Slack Block Kit e Discord Rich Embeds.

---

## ADR-012: Hardening de Produção, Revogação Imediata de Sessões (`RevokedToken`), Readiness Check e Validação End-to-End da Release v1.0

- **Status**: Aceito (Fase 8)
- **Contexto**: A consolidação final para a versão 1.0.0 requer que todo o sistema seja auditado, testado de ponta a ponta e protegido contra configurações perigosas que possam ser introduzidas inadvertidamente na implantação em produção.
- **Decisão**:
  - **Hardening e Gates de Produção (`validate_production_safety`)**:
    - O startup do backend valida a entropia das chaves e senhas e proíbe termos comuns (`dev`, `test`, `secret`, `change_me`) em `APP_ENV=production`.
    - Bloqueia `CORS_ORIGINS=*` ou origens locais em produção.
    - Exige que `BLOCK_PRIVATE_NETWORKS=true` e `ALLOW_LOCAL_LAB_TARGETS=false` em produção real.
  - **Revogação Imediata no Servidor (`RevokedToken`)**:
    - Criação da tabela `revoked_tokens` e migração Alembic `0004_phase8_revoked_tokens` para armazenar o JTI ou assinatura de tokens revogados no logout, garantindo invalidação imediata mesmo antes do vencimento temporal do JWT.
  - **Proteção Anti-Abuso e Defesa em Profundidade na Autenticação**:
    - *Rate limiting* deslizante baseado em consultas aos logs de auditoria (máximo de 8 falhas por e-mail e 20 por IP em 15 minutos).
    - Mitigação de ataques de temporização (*timing attacks*) via hash scrypt computacional equivalente quando o usuário não existe.
    - Validação de cabeçalho `Origin` contra `trusted_origins` em requisições mutantes que usam autenticação via cookie.
    - Desativação do processamento cego de `X-Forwarded-For` a menos que explicitamente autorizado via `TRUST_FORWARDED_FOR=true`.
  - **Readiness Check Real (`/api/v1/ready`)**:
    - Retorna HTTP 200 somente se PostgreSQL (`SELECT 1`) e Redis (`PING`) responderem positivamente; caso contrário, retorna HTTP 503 com detalhes de degradação.
  - **Validação E2E Automatizada (TM-020)**:
    - Suíte `test_phase8_e2e_flows.py` cobrindo 100% dos cinco fluxos fundamentais (Fluxos A a E) de forma contínua e determinística.
    - O banco de dados armazena estritamente o hash criptográfico SHA-256 (`token_hash`), o prefixo público e os escopos RBAC granulares (`scans:read`, `scans:write`, etc.).
    - A autenticação Bearer unificada no FastAPI (`deps.py`) reconhece tanto JWT de sessão de usuário quanto tokens `csc_live_...`, validando expiração e revogação e registrando `last_used_at`.
  - **Canal de Alertas e Deduplicação In-App (`NotificationService` + `EmailDeliveryAdapter`)**:
    - Notificações in-app estruturadas por organização com deduplicação temporal configurável para mitigar flood de alertas.
    - O `EmailDeliveryAdapter` suporta SMTP com TLS e modo desenvolvimento local com buffer em memória inspecionável para testes automatizados.
    - O `TemplateService` provê padrões da indústria (OWASP Web, APIs REST, Perímetro) e adaptadores para geração de alertas em formato Slack Block Kit e Discord Rich Embeds.
