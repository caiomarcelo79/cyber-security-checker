# ROADMAP.md — Plano de Engenharia por Fases (`cyber-security-checker`)

O desenvolvimento do `cyber-security-checker` é estruturado por fases sequenciais baseadas em dependências técnicas e critérios objetivos de conclusão verificáveis por testes automatizados.

---

## FASE 0 — Planejamento e Arquitetura
**Status:** `CONCLUÍDA`

### Entregas
- [x] Definição de requisitos funcionais, não funcionais e guardrails éticos/operacionais (`SECURITY_SCOPE.md`).
- [x] Arquitetura de componentes, modelo de dados relacional e contratos do motor de segurança (`ARCHITECTURE.md`).
- [x] Registro de decisões arquiteturais justificadas (`DECISIONS.md`).
- [x] Regras permanentes para agentes de IA e continuidade (`AGENTS.md`).
- [x] Estrutura de fases, matriz de testes e próximos passos (`ROADMAP.md`, `TEST_MATRIX.md`, `PROJECT_STATE.md`, `NEXT_STEPS.md`).

**Critério Objetivo de Conclusão:** Documentação arquitetural completa, contratos definidos e backlog estruturado com critérios verificáveis.

---

## FASE 1 — Fundação do Projeto
**Status:** `CONCLUÍDA`
**Dependências:** FASE 0

### Entregas
- [x] Inicialização do repositório Git e estrutura completa de diretórios (`frontend/`, `backend/`, `security-engine/`, `workers/`, `infrastructure/`, `docs/`, `scripts/`, `tests/`).
- [x] Pacote `security-engine` estruturado com contratos base (`BaseSecurityModule`, `ScopePolicyValidator`, `EvidenceManager`, `RiskEngine`, `RemediationEngine`, `PluginRegistry`).
- [x] Backend FastAPI operacional (`backend/app`) com configuração centralizada, conexão SQLAlchemy 2.0 com PostgreSQL, migrações Alembic configuradas e modelos fundamentais.
- [x] Configuração do Redis e Workers Celery (`workers/`) integrados ao backend e ao `security-engine`.
- [x] Endpoints de Health Check profundos (`GET /api/v1/health` e `GET /api/v1/system/status`) verificando banco de dados, Redis, motor de segurança e workers.
- [x] Frontend Next.js + TypeScript + Tailwind CSS + shadcn/ui operacional (`frontend/`), conectado em tempo real à API FastAPI, exibindo o estado real da plataforma e dos serviços, com suporte a tema escuro/claro em Português Brasileiro.
- [x] `docker-compose.yml` funcional com PostgreSQL, Redis, Backend, Worker e Frontend, incluindo volumes persistentes e health checks.
- [x] Suíte inicial de testes automatizados (unitários, escopo anti-SSRF, sanitização de evidências, API health/system e testes de frontend/build) e linters configurados.

**Critério Objetivo de Conclusão:** Aplicação inicia localmente e via Docker Compose, migrações executam sem erros, todos os serviços respondem aos health checks e a suíte de testes automatizados da Fase 1 passa integralmente.

---

## FASE 2 — Autenticação, RBAC Multi-Organização e Gestão de Ativos Autorizados
**Status:** `CONCLUÍDA`
**Dependências:** FASE 1

### Entregas
- [x] Autenticação JWT + Cookies HttpOnly seguros (Login, Logout, Registro, Hash scrypt).
- [x] Isolamento multi-organização (`Organization`) e controle de acesso baseado em papéis (`ADMIN`, `SECURITY_ANALYST`, `DEVELOPER`, `VIEWER`).
- [x] CRUD completo de Ativos (`Assets`: Web App, REST API, GraphQL API, Domain) com ambientes (`PRODUCTION`, `STAGING`, `DEVELOPMENT`, `LAB`), tags e proprietários.
- [x] Fluxo de comprovação de autorização de alvos (`DNS_TXT`, `HTTP_WELL_KNOWN`, `LAB_INTERNAL`) com geração de token criptográfico e validador real.
- [x] Registro automático em `audit_logs` para todas as ações críticas.
- [x] Telas de Login, Gestão de Ativos, RBAC/Audit Log e Comprovação de Autorização no Frontend.

**Critério Objetivo de Conclusão:** Usuário autenticado cadastra um ativo e valida sua autorização com isolamento estrito entre organizações comprovado por testes automatizados.

---

## FASE 3 — Motor de Auditoria, Orquestração e Primeiros Verificadores Passivos
**Status:** `CONCLUÍDA`
**Dependências:** FASE 2

### Entregas
- [x] `ScanOrchestrator` completo com criação de auditoria, enfileiramento no Celery (`execute_scan_task`), rastreamento de progresso por módulo, controle de idempotência, cancelamento cooperativo em tempo real e persistência incremental de `ScanCheckResultRecord` e `FindingRecord`.
- [x] Implementação completa do `ScopedSafeHttpClient` (validação de escopo e anti-SSRF em cada requisição e salto de redirecionamento, rate limiting RPS, limite de bytes de resposta, *circuit breaker* e inspeção real de certificados X.509 e protocolos TLS).
- [x] Implementação completa do **Módulo A** (`CHK-A01` a `CHK-A11`: Disponibilidade, Redirecionamentos HTTP/HTTPS, Certificados TLS/Protocolos, Security Headers sensíveis ao contexto: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, exposição de versões Server/X-Powered-By, stack traces e DNS/SPF/DMARC).
- [x] Implementação completa do **Módulo E** (`CHK-E01` e `CHK-E02`: Análise individual de Cookies `Set-Cookie`: `HttpOnly`, `Secure`, `SameSite`, conflito `SameSite=None` sem `Secure`, expiração, escopo de domínio/path, transmissão sem HTTPS, sanitização de valores).
- [x] Servidores de laboratório local HTTP e HTTPS/TLS isolados para validação real fim a fim e integração completa na aba `Auditorias & Vulnerabilidades` do Frontend SOC.

**Critério Objetivo de Conclusão:** Execução real de uma auditoria contra alvo de laboratório local, persistindo verificações aprovadas e vulnerabilidades reais com evidências sanitizadas e recomendações técnicas.

---

## FASE 4 — Dashboard SOC, Triagem de Vulnerabilidades e Interface de Auditorias
**Status:** `CONCLUÍDA`
**Dependências:** FASE 3

### Entregas
- [x] Dashboard SOC com 11 KPIs reais, gráficos de severidade, status de auditorias, tendências temporais de 30 dias (`/dashboard/trends`) e ranking dos Top 5 ativos de maior risco (`MetricsRepository`).
- [x] Deduplicação consistente de vulnerabilidades via `current_finding_ids_stmt` para que apenas o último achado por `(asset_id, fingerprint)` componha as métricas ativas da organização.
- [x] Catálogo e Triagem de Vulnerabilidades com filtros avançados no servidor (severidade, status de tratamento, confiança, ativo, módulo, categoria OWASP/CWE, período e busca textual), ordenação e paginação (`GET /findings/page`).
- [x] Transição de status de triagem (`PATCH /findings/{id}/status`: `OPEN`, `IN_PROGRESS`, `MITIGATED`, `ACCEPTED_RISK`, `FALSE_POSITIVE`, `RESOLVED_VERIFIED`) com RBAC (`DEVELOPER`+), registro obrigatório em `AuditLog` e recálculo automático do `risk_score` do ativo.
- [x] Trilha de histórico completa (`GET /findings/{id}/history`, `GET /scans/{id}/events`) e visualização sanitizada de evidências contra XSS.
- [x] Acompanhamento em tempo real via Server-Sent Events (`GET /scans/{id}/stream`) com limite de conexões por organização (`SSE_MAX_STREAMS_PER_ORG = 5`), heartbeats periódicos, hook com auto-reconnect backoff e fallback adaptativo por polling.
- [x] Diretório e gerenciamento de ativos com edição inline de metadados (`PATCH /assets/{id}`).

**Critério Objetivo de Conclusão:** Jornada completa do cadastro do ativo até a triagem interativa das vulnerabilidades e acompanhamento em tempo real funciona de ponta a ponta sem dados fictícios, com testes automatizados verdes (`TM-016`).

---

## FASE 5 — Ampliação dos Módulos de Segurança (B, C, D, F, G, H)
**Status:** `CONCLUÍDA`
**Dependências:** FASE 4

### Entregas
- [x] **Módulo A (Expansão)**: Implementação de `CHK-A12` (autenticação de e-mail SPF e DMARC via inspeção de registros DNS TXT padrão RFC 1035).
- [x] **Módulo B**: Autenticação e login (detecção de transporte inseguro HTTP em forms de autenticação `CHK-B01`, enumeração de usuários por discrepância de mensagens `CHK-B02`, e ausência de `Cache-Control: no-store` em credenciais `CHK-B03`).
- [x] **Módulo C**: XSS controlado (reflexão de marcadores inofensivos alfanuméricos `CHK-C01`, auditoria estática de sinks DOM inseguros como `innerHTML`/`eval` `CHK-C02`, e análise de robustez mitigadora do Content Security Policy `CHK-C03`).
- [x] **Módulo D**: Indicadores seguros de SQL Injection (detecção passiva de assinaturas de erro multi-SGBD: MySQL, PostgreSQL, Oracle, MSSQL e SQLite `CHK-D01`, teste restrito de limite com guardrail intransponível `allow_in_production=False` `CHK-D02`).
- [x] **Módulo F**: Postura contra DoS/DDoS (detecção passiva de provedores CDN/WAF como Cloudflare, AWS CloudFront, Fastly e Akamai `CHK-F01`, inspeção de cabeçalhos padronizados de rate limiting `RateLimit-*` e `Retry-After` `CHK-F02`, e postura de limites de recurso `CHK-F03`).
- [x] **Módulo G**: APIs REST e GraphQL (configurações inseguras de CORS com credenciais ou origem nula `CHK-G01`, endpoints públicos de documentação Swagger/OpenAPI e GraphQL schema `CHK-G02`, e exposição desnecessária do método HTTP perigoso `TRACE` `CHK-G03`).
- [x] **Módulo H**: Outras vulnerabilidades e configurações (arquivos sensíveis e diretórios administrativos expostos `.env`, `.git` `CHK-H01`, Directory Listing ativado `CHK-H02`, parâmetros de Open Redirect com validação segura de protocolo/host `CHK-H03`, e ausência de tokens anti-CSRF em formulários POST com cookies `CHK-H04`).
- [x] **Mecanismo de Probing Centralizado**: Expansão do `ScopedSafeHttpClient.probe()` com suporte a anti-SSRF, controle de taxa, headers e DNS TXT sem dependências externas binárias.
- [x] **Base de Conhecimento de Remediação**: Catálogo de 19 novas diretrizes de remediação estruturadas e versionadas com exemplos de código multi-stack (FastAPI, Express, Nginx, Django, React).

**Critério Objetivo de Conclusão:** Todos os módulos A–H contam com implementações reais determinísticas, sem mocks camuflados, testes automatizados cobrindo todos os cenários e 100% de conformidade com os guardrails éticos (`TM-017`).

---

## FASE 6 — Relatórios Profissionais e Ciclo de Vida de Correções
**Status:** `CONCLUÍDA`
**Dependências:** FASE 5

### Entregas
- [x] Geração e exportação de relatórios profissionais (Executivo para C-Level, Técnico Detalhado SecOps, Comparativo entre Execuções e Acompanhamento de SLA) em HTML, JSON, CSV com sanitização contra Formula Injection/DDE, e PDF vetorial via ReportLab Platypus.
- [x] Motor de Comparação Determinística entre Auditorias (`ScanComparisonService`) analisando duas execuções do mesmo ativo com identificação rigorosa de New, Persistent, Confirmed Remediated (`PASSED`), Unverified Coverage e Reopened, com cálculo de paridade de cobertura.
- [x] Gestão estendida de ciclo de vida de vulnerabilidades (`OPEN`, `IN_ANALYSIS`, `IN_PROGRESS`, `WAITING_VALIDATION`, `RESOLVED_VERIFIED`, `FALSE_POSITIVE`, `ACCEPTED_RISK`, `REOPENED`) com atribuição de prioridades P1–P4, prazos de SLA e justificativa formal obrigatória para aceitação de risco.
- [x] Fluxo de Revalidação Técnica direcionada (`RevalidationService`) que reexecuta o módulo específico no alvo sem alterar o histórico de detecções e evidências originais.
- [x] Endpoint de evolução temporal e MTTR em dias (`/api/v1/dashboard/evolution`) e integração completa no Console SOC (`ReportsPanel`, `ScanComparisonModal`, seleção de 2 auditorias para comparação e botão de revalidação técnica).

**Critério Objetivo de Conclusão:** Rastreamento completo de uma vulnerabilidade desde a detecção até a verificação da correção no alvo e exportação de relatório profissional com testes automatizados verdes (`TM-018`).

---

## FASE 7 — Automação, Agendamentos e Integrações
**Status:** `CONCLUÍDA`
**Dependências:** FASE 6

### Entregas
- [x] Agendador de auditorias recorrentes (`ScanSchedule` + Celery Beat / `SchedulerService` + `CronSchedulerUtil`) com fusos horários IANA, políticas de misfire (`SKIP`, `RUN_ONCE`), bloqueio atômico contra concorrência e revalidação mandatória de autorização do ativo antes de cada disparo.
- [x] Centro de Notificações in-app (`NotificationService`) com contagem de não lidas, janelas de deduplicação móveis e adaptador de e-mail SMTP com TLS e buffer local (`EmailDeliveryAdapter`).
- [x] Sistema de Webhooks seguros (`WebhookService`) com validação anti-SSRF via `ScopePolicyValidator`, assinaturas criptográficas HMAC-SHA256 (`X-CSC-Signature`), proteção anti-replay, tentativas com backoff exponencial e disparador assíncrono para eventos críticos (`SCAN_COMPLETED`, `VULNERABILITY_CRITICAL_DETECTED`, `SLA_BREACH_WARNING`).
- [x] Chaves de API (`ApiTokenService`) para integração contínua (CI/CD) com prefixo `csc_live_...`, armazenamento por hash SHA-256 no PostgreSQL, escopos granulares de permissão, data de expiração, revogação instantânea e autenticação unificada Bearer.
- [x] Templates de auditoria customizáveis (`TemplateService`) com carga de padrões da indústria (OWASP Top 10, REST API, Perímetro) e adaptadores para Slack Block Kit e Discord Embeds.
- [x] Painel frontend SOC completo de Automações & Integrações (`AutomationsPanel`) com 5 sub-abas: Agendamentos, Notificações, Webhooks, Chaves de API e Templates de Auditoria.

**Critério Objetivo de Conclusão:** Rotinas recorrentes, notificações in-app/e-mail, webhooks assinados e autenticação via API Token operam de ponta a ponta respeitando janelas, limites e escopo autorizado, validados por testes automatizados (`TM-019`).

---

## FASE 8 — Consolidação da Versão 1.0 e Hardening
**Status:** `CONCLUÍDA`
**Dependências:** FASE 7

### Entregas
- [x] Auditoria de segurança interna e hardening (RBAC, CSRF origin check, headers X-Request-ID, CSP, HSTS, DENY, rate limiting anti-brute force, dummy timing attack defense, revogação imediata no servidor via `RevokedToken`).
- [x] Suíte completa de testes E2E dos 5 fluxos fundamentais (`test_phase8_e2e_flows.py`: Fluxos A a E aprovados 100%).
- [x] Scripts de backup/restauração (`scripts/backup_db.ps1`, `scripts/restore_db_verify.ps1`) com auditoria das 18 tabelas.
- [x] Stack Docker completa (6 serviços `healthy` incluindo Celery Beat e unprivileged users `csc` e `node`).
- [x] Documentação completa de release (`INSTALLATION.md`, `DEPLOYMENT.md`, `OPERATIONS.md`, `SECURITY.md`, `BACKUP_RECOVERY.md`, `CHANGELOG.md` e `RELEASE_READINESS.md`).

**Critério Objetivo de Conclusão:** Versão 1.0 testada de ponta a ponta, auditada, resiliente e formalmente aprovada com status **READY FOR RELEASE v1.0.0** (`TM-020`).
