# TEST_MATRIX.md — Matriz de Testes e Verificação de Qualidade

Este documento rastreia todas as capacidades implementadas no `cyber-security-checker`, seus respectivos testes automatizados, comandos de execução e status de verificação.

---

## 1. Matriz de Cobertura por Componente (Fases 0 a 5)

| ID | Componente | Funcionalidade / Regra Testada | Tipo de Teste | Arquivo de Teste | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `TM-001` | `security-engine` | Validação de escopo, bloqueio anti-SSRF (loopback, RFC 1918, cloud metadata `169.254.169.254`), não-herança de subdomínios, redirecionamentos e permissão controlada de laboratório | Unitário / Segurança | `security-engine/tests/test_scope_policy.py` | **APROVADO** (6/6 testes) |
| `TM-002` | `security-engine` | Sanitização de evidências (`EvidenceManager`): mascaramento de `Authorization`, `Cookie`, `Set-Cookie`, `X-API-Key`, tokens JWT e senhas em JSON/URL | Unitário / Segurança | `security-engine/tests/test_evidence_sanitizer.py` | **APROVADO** (1/1 teste) |
| `TM-003` | `security-engine` | Registro e descoberta de plugins (`PluginRegistry`), contratos `BaseSecurityModule`, inspeção real dos Módulos A e E, `RiskEngine` e `RemediationEngine` | Unitário / Contrato | `security-engine/tests/test_engine_contracts.py` | **APROVADO** (3/3 testes) |
| `TM-004` | `security-engine` | Limites operacionais (`ScanExecutionPolicy`): *hard caps* intransponíveis de RPS, concorrência, timeout, redirecionamentos e catálogo de 6 perfis | Unitário / Guardrails | `security-engine/tests/test_execution_policy.py` | **APROVADO** (2/2 testes) |
| `TM-005` | `backend` | Healthcheck da API (`GET /api/v1/health`), cabeçalhos de segurança da API e diagnóstico profundo de subsistemas (`GET /api/v1/system/status`) com zero dados fictícios | Integração / API | `backend/tests/test_health_and_system.py` | **APROVADO** (2/2 testes) |
| `TM-006` | `backend` | Catálogo de módulos, perfis, recomendações e endpoint de validação de escopo (`GET /api/v1/modules`, `GET /api/v1/profiles`, `GET /api/v1/remediation`, `POST /api/v1/scope/validate`) | Integração / API | `backend/tests/test_modules_and_profiles_api.py` | **APROVADO** (2/2 testes) |
| `TM-007` | `backend` | Modelos SQLAlchemy 2.0, integridade relacional (Organização, Usuário, Ativo, Autorização, Scan, Finding), métricas reais no Dashboard e migrações Alembic | Integração / DB | `backend/tests/test_models_and_migrations.py` | **APROVADO** (1/1 teste + Migração `0001_initial_foundation`) |
| `TM-008` | `workers` | Registro e execução das tarefas Celery (`workers.tasks.ping_worker`, `workers.tasks.evaluate_snapshot_task` e `workers.tasks.execute_scan_task`) integradas ao `security-engine` | Integração / Worker | `backend/tests/test_worker_tasks.py` | **APROVADO** (1/1 teste) |
| `TM-009` | `frontend` | Compilação TypeScript estrita (`tsc --noEmit`), build de produção Next.js (`next build`) e testes de renderização Vitest/Testing Library do console SOC | Qualidade / UI | `frontend/src/__tests__/dashboard.test.tsx` | **APROVADO** (`tsc`, `vitest` e `next build` sem erros) |
| `TM-010` | `infrastructure` | Validação de `docker-compose.yml`, containers `postgres` e `redis`, migrações Alembic e integridade dos arquivos de memória persistente | End-to-End / Infra | `tests/test_infrastructure_smoke.py` | **APROVADO** (3/3 testes + `docker compose`) |
| `TM-011` | `backend` (Fase 2) | Registro de usuário/organização, login/logout, JWT + Cookie `HttpOnly`, hierarquia RBAC (`ADMIN`, `SECURITY_ANALYST`, `DEVELOPER`, `VIEWER`) e isolamento multi-organização (anti-IDOR entre tenants) | Integração / Segurança | `backend/tests/test_auth_rbac_isolation.py` | **APROVADO** (2/2 testes) |
| `TM-012` | `backend` (Fase 2) | CRUD de Ativos (`Assets`), bloqueio Anti-SSRF no cadastro, geração de token criptográfico e verificação real de autorização (`DNS_TXT`, `HTTP_WELL_KNOWN`, `LAB_INTERNAL`), revogação e `AuditLog` | Integração / Domínio | `backend/tests/test_assets_and_authorizations.py` | **APROVADO** (2/2 testes) |
| `TM-013` | `frontend` (Fase 2 & 3) | Navegação e renderização das telas de Autenticação/Registro, Sistemas/Ativos, Auditorias & Vulnerabilidades, Comprovação de Autorização e RBAC/Audit Log no Console SOC | Qualidade / UI | `frontend/src/__tests__/dashboard.test.tsx` | **APROVADO** (2/2 testes Vitest) |
| `TM-014` | `security-engine` (Fase 3) | `ScopedSafeHttpClient` e `SecurityEngineRunner` contra servidores de laboratório HTTP e HTTPS/TLS locais: inspeção de certificado X.509 autoassinado vs. confiável, cadeia de redirecionamento, bloqueio anti-SSRF em redirect para IP privado/metadados, `WEB_APP` vs `REST_API` Security Headers, `Set-Cookie` múltiplos e sanitização de segredos | Integração / Scanners Reais | `security-engine/tests/test_phase3_scanners_and_http_client.py` | **APROVADO** (5/5 testes) |
| `TM-015` | `backend` (Fase 3) | `ScanOrchestrator` e rotas `/api/v1/scans` + `/api/v1/findings`: bloqueio de ativo `PENDING`, bloqueio de perfil não permitido em `PRODUCTION`, execução fim a fim contra servidor local, idempotência, cancelamento cooperativo e isolamento multi-tenant de scans/findings | Integração / Orquestração | `backend/tests/test_phase3_scans_orchestration.py` | **APROVADO** (3/3 testes) |
| `TM-016` | `fullstack` (Fase 4) | Dashboard SOC consolidado com 11 KPIs reais, agregação temporal de tendências (30 dias), Top 5 ativos de risco, deduplicação de vulnerabilidades via `current_finding_ids_stmt`, paginação/ordenação/filtros no servidor (`/scans/page`, `/findings/page`), triagem com RBAC (`PATCH /findings/{id}/status`), recálculo automático de risco do ativo, histórico de detecções e auditoria (`/findings/{id}/history`, `/scans/{id}/events`), streaming em tempo real SSE (`/scans/{id}/stream`) com controle de concorrência por org e fallback resiliente | Integração & UI E2E | `backend/tests/test_phase4_dashboard_and_triage.py`, `backend/tests/test_phase4_ui_apis.py`, `frontend/src/__tests__/phase4.test.tsx` | **APROVADO** (2 backend suites 15/15 + 14/14 Vitest + `tsc` + `next build`) |
| `TM-017` | `security-engine` (Fase 5) | Ampliação do motor com 8 módulos canônicos: `CHK-A12` (SPF/DMARC DNS TXT), `Módulo B` (Autenticação/Login, HTTP no form, account enumeration, cache em auth), `Módulo C` (XSS controlado com marcadores inofensivos, DOM sinks, CSP mitigador), `Módulo D` (SQLi seguro: assinaturas de erro multi-SGBD, verificação restrita com `allow_in_production=False`), `Módulo F` (Resiliência DoS: detecção passiva de WAF/CDN, cabeçalhos `RateLimit-*`/`Retry-After`, postura), `Módulo G` (APIs REST/GraphQL: CORS inseguro com credenciais, OpenAPI/Swagger públicos, schema GraphQL, método TRACE), `Módulo H` (Configuração/Arquivos: `.env`/`.git` expostos, Directory Listing, Open Redirect com parâmetros de salto, formulários POST sem anti-CSRF) e 19 novas diretrizes de remediação com exemplos multi-stack | Unitário & Scanners Reais | `security-engine/tests/test_phase5_modules.py` | **APROVADO** (8/8 testes da suíte, totalizando 25/25 no engine) |
| `TM-018` | `fullstack` (Fase 6) | Motor de Relatórios Profissionais (`ReportEngine`) com geração PDF (ReportLab Platypus), HTML, JSON e CSV (mitigação contra Formula Injection / DDE), tipos Executivo, Técnico, Comparativo e SLA; Comparação de Auditorias (`ScanComparisonService`) identificando New, Persistent, Confirmed Remediated (`PASSED`), Unverified Coverage e Reopened; Gestão de Correções e Revalidação (`RevalidationService`) com execução direcionada de scanner sem alterar evidência histórica, prioridades P1–P4, prazos SLA, justificativa formal de risco aceito e evolução temporal com MTTR | Integração, DB & UI E2E | `backend/tests/test_phase6_reports_and_remediation.py`, `frontend/src/__tests__/phase6.test.tsx` | **APROVADO** (4/4 suítes backend 19/19 total + 8/8 testes frontend 22/22 total + `tsc` + `next build`) |
| `TM-019` | `fullstack` (Fase 7) | Automação, Agendamentos (`ScanScheduleRecord`, `CronSchedulerUtil`, `SchedulerService` com fusos IANA, misfire policies e revalidação de ativo), Notificações In-App e Email (`NotificationRecord`, `NotificationPreferenceRecord`, `NotificationService`, `EmailDeliveryAdapter`), Webhooks com Anti-SSRF (`ScopePolicyValidator`), assinatura HMAC-SHA256 (`X-CSC-Signature`), histórico de entregas e backoff exponencial, Chaves de API para CI/CD (`ApiTokenRecord`, `ApiTokenService` com prefixo `csc_live_...`, hash SHA-256 e escopos granulares), Templates de Auditoria (`ScanTemplateRecord`) e console SOC com sub-abas dedicadas | Integração, DB & UI E2E | `backend/tests/test_phase7_automations.py`, `frontend/src/__tests__/phase7.test.tsx` | **APROVADO** (11/11 testes backend + 5/5 testes frontend, totalizando 31/31 backend + 27/27 frontend + `tsc` + `next build`) |

---

## 2. Comandos de Execução Verificados

```bash
# Suíte completa Python (Security Engine 25 testes + Backend 31 testes + Infra 3 testes + Ruff linter)
.\.venv\Scripts\python.exe scripts/verify_foundation.py

# Suíte Frontend (TypeScript estrito + Vitest 22 testes + Next.js Production Build)
cd frontend
npm run typecheck
npx vitest run --pool=forks
npm run build
```

| `TM-020` | Fase 8: Consolidação, Hardening, Auditoria Auth, E2E e Release v1.0 | 72 pytest, 27 Vitest, ruff, tsc, next build, pip-audit (0 falhas), backup+restore isolado, stack Docker (6 serviços healthy) | PASSOU INTEGRALMENTE — Verificado e validado em 2026-10-23 |
| `TM-021` | Fase 8: Revisão e Refatoração da Tela de Auditorias (`soc-console.tsx` e `scans-history-panel.tsx`) | Eliminação de requisições 404 (`/scans/null`), eliminação de React Hydration Mismatch #423 via `mounted` guard, reorganização para layout SOC vertical em largura total (formulário responsivo de 4 colunas + monitor de telemetria em tempo real com botão de fecho + painel de histórico de auditorias em largura total com filtro de 6 colunas, `whitespace-nowrap`, larguras mínimas e destaque do scan ativo). 27/27 Vitest, Next.js build standalone 100% OK e fluxo live E2E via proxy validado. | **APROVADO** (100% funcional sem regressões) |
| `TM-022` | Fase 8: Verificações de Segurança Agressivas e Perfil DEEP_PENTEST | Implementação e validação de verificações profundas não destrutivas: CHK-C04 (Fuzzing Ativo Contextual XSS), CHK-D03 (Heurísticas de Injeção de Comandos de SO), CHK-D04 (SQLi Cego Baseado em Tempo/Booleano), CHK-G01 (Detecção Ativa de Origens Arbitrárias CORS com Credenciais), CHK-G04 (Detecção de Métodos HTTP Perigosos TRACE/XST), CHK-H05 (Path Traversal / Local File Inclusion LFI) e CHK-H06 (Indicadores de SSRF no Alvo). Cadastro do perfil `DEEP_PENTEST` com bloqueio obrigatório contra Produção (HTTP 422 para `PRODUCTION`), 5 novos playbooks de remediação estruturada e aviso de escopo no frontend. | **APROVADO** (33/33 engine, 47/47 backend, 27/27 Vitest, Next.js build standalone e stack Docker 100% healthy) |
| `TM-023` | Fase 8: Novas Verificações de Segurança Especializadas, Playbooks Prescritivos de Remediação e Exportação de Relatório Executivo/Técnico em PDF | Adição de 5 novas verificações determinísticas de segurança (`CHK-B04`: Exposição de Credenciais em Query String e Formulários GET; `CHK-E03`: Ausência de Prefixos Seguros de Cookies `__Host-` / `__Secure-`; `CHK-F04`: Risco de Request Smuggling / Desync Canary via Conflito CL-TE; `CHK-G05`: Má Configuração de Tokens JWT com `alg: none` ou ausência de expiração/assinatura; `CHK-H07`: Exposição de Painéis Administrativos e Interfaces de Debug `/actuator`, `/swagger-ui.html`, `/_profiler`, `/admin`). Adição dos respectivos 5 playbooks prescritivos ao catálogo `REMEDIATION_CATALOG` (totalizando 29 playbooks) com explicação de perigo, método de detecção, passo a passo de correção, snippets multi-stack (FastAPI/Python, Express/Node.js, Spring Boot/Java, Nginx/Caddy) e referências CWE/OWASP. Implementação da geração de relatórios PDF aprimorados via ReportLab (`_render_pdf`) com telemetria de alvos, matriz de severidades, seção dedicada a Erros de Execução (`EXECUTION_ERROR`) com diagnóstico de infraestrutura, caixas de evidências sanitizadas e playbooks de remediação estruturados. Endpoint dedicado `GET /api/v1/scans/{scan_id}/export-pdf` com isolamento multi-tenant e geração síncrona/assíncrona. Integração de botões de extração PDF na tabela de auditorias (`scans-history-panel.tsx`) e no monitor de auditoria (`soc-console.tsx`). | **APROVADO** (39/39 security-engine, 49/49 backend, 27/27 Vitest, Next.js build compilado com sucesso e stack Docker 100% atualizada) |

### Detalhamento das Evidências de TM-020 (Fase 8)

1. **Testes Unitários, de Integração e E2E**:
   - `backend/tests/`: 47 testes (`test_phase8_auth_audit.py`, `test_phase8_hardening.py`, `test_phase8_e2e_flows.py`, etc.) — 100% passaram.
   - `security-engine/tests/`: 28 testes de conformidade, sanitização e módulos — 100% passaram.
   - Total backend: **75 testes aprovados**.
2. **Qualidade e Tipagem Estática**:
   - `ruff check .`: 100% aprovado (zero erros).
   - `frontend/npm run test`: 27 testes Vitest aprovados.
   - `frontend/npm run build`: Build Next.js 14 em modo standalone compilado com sucesso, TypeScript e ESLint sem erros.
3. **Auditoria de Vulnerabilidades em Dependências**:
   - `pip-audit --skip-editable`: **0 vulnerabilidades conhecidas** após atualização de `setuptools >= 83.0.0`.
   - `npm audit`: CVE do PostCSS documentada em `RELEASE_READINESS.md` com justificativa técnica formal (impacta apenas processamento de CSS no build local, sem exposição de runtime ou produção).
4. **Resiliência e Recuperação de Desastres**:
   - `scripts/backup_db.ps1`: Execução de dump SQL compactado.
   - `scripts/restore_db_verify.ps1`: Restauração validada com sucesso em container isolado de teste, confirmando as 18 tabelas e migração `0004_phase8_revoked_tokens`.
5. **Stack Docker e Orquestração Completa**:
   - Imagens construídas: `csc-backend`, `csc-worker`, `csc-beat`, `csc-frontend`.
   - Inicialização em modo controlado via `docker compose up -d`: Todos os 6 containers (`csc-postgres`, `csc-redis`, `csc-backend`, `csc-worker`, `csc-beat`, `csc-frontend`) reportam status `healthy`/`Up`.
   - Endpoints validados via HTTP:
     - `GET /api/v1/health`: HTTP 200 com cabeçalhos de segurança (`X-Request-ID`, `CSP`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`).
     - `GET /api/v1/ready`: HTTP 200 `{"status": "READY", "checks": {"database": "UP", "redis": "UP"}}`.
     - `GET /api/health` (frontend): HTTP 200.
     - Celery Beat + Celery Worker: Tarefa periódica `process_due_schedules_task` executada com sucesso a cada minuto.
