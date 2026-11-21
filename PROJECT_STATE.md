# PROJECT_STATE.md — Estado Atual do Projeto (`cyber-security-checker`)

**Última atualização:** 2026-11-18 (Conclusão da FASE 8, Homologação v1.0.0, Ampliação de Cobertura para 53 Checks / 39 Playbooks e Melhoria de Precisão Anti-Falso-Positivo)

**2026-11-20 · Pós-v1.0:** Fase 1 de SSH concluída em laboratório. A CLI lê as políticas globais de senha e acesso de root. A API registra a evidência mínima, o Console mostra os resultados e o exercício de autenticação publica uma notificação sintética no painel. Migrações e suítes validadas. Consulte [PROGRESS.md](PROGRESS.md) para reproduzir e retomar pela Fase 2.

**2026-11-20 · Fase 2 de telemetria:** Importação passiva e piloto desktop validados em laboratório com Zeek, API e PostgreSQL. O Console mostra o segmento, a recepção e a contagem. O desktop pausa, retoma e persiste a posição confirmada sem armazenar a credencial. Consulte [PROGRESS.md](PROGRESS.md) para executar o piloto e [NEXT_STEPS.md](NEXT_STEPS.md) para a Fase 3.

**2026-11-20 · Fase 3.1 de disponibilidade:** Exercício sintético de degradação e recuperação validado em laboratório com servidor HTTP determinístico, sonda CLI, API, PostgreSQL 16, Redis 7 e Console SOC. Abertura por amostras consecutivas, recuperação, notificações in-app e comparação de linha do tempo verificadas e cronometradas. Consulte [PROGRESS.md](PROGRESS.md) para reproduzir e [NEXT_STEPS.md](NEXT_STEPS.md) para o item 3.2.

**2026-11-20 · Fase 3.2 de disponibilidade:** Cenários `LATENCY`, `ERRORS` (HTTP `503`) e `SATURATION` (HTTP `429`) e correlação opcional de sinais de borda/provedor (`FIREWALL`, `CDN`, `PROVIDER`) validados em laboratório com migração `0009_availability_signals`, PostgreSQL 16, Redis 7, sonda CLI e painel do Console SOC. Fase 3 concluída; próxima etapa em [ROADMAP.md](ROADMAP.md): Fase 4 (Tráfego suspeito).

**2026-11-20 · Fase 4.1 de tráfego suspeito:** Detecção explicável de anomalias de conexões (`CONNECTION_PORT_SWEEP`, `CONNECTION_REPEATED_BURST`), DNS (`DNS_NXDOMAIN_BURST`, `DNS_HIGH_ENTROPY_QUERY`) e identidade TLS (`TLS_POSSIBLE_INTERCEPTION` vs. `BENIGN_ROTATION` sem falso positivo) validada em laboratório com migração `0010_suspicious_traffic`, PostgreSQL 16, Redis 7, Uvicorn e CLI [scripts/analyze_traffic.py](scripts/analyze_traffic.py).

**2026-11-20 · Fase 4.2 de tráfego suspeito:** Correlação opcional com sinais de antivírus/EDR (`ANTIVIRUS`, `EDR` por `host_ip`, elevando cobertura para `EDR` e confiança para `HIGH`) e painel **Tráfego suspeito** no Console SOC ([suspicious-traffic-panel.tsx](frontend/src/components/suspicious-traffic-panel.tsx)) validados com migração `0011_traffic_edr_signals`, PostgreSQL 16, Redis 7, CLI `--edr-log` e build/testes do frontend.

**2026-11-20 · Fase 5.1 de triagem assistida:** Serviço de sugestões revisáveis para alertas de tráfego e vulnerabilidades ([ai_triage_service.py](backend/app/services/ai_triage_service.py), [ai_triage_logic.py](backend/app/services/ai_triage_logic.py)) com validação de citações sobre evidência sanitizada e fallback determinístico quando a IA está desligada/indisponível validado com migração `0012_ai_triage_suggestions`, PostgreSQL 16, Redis 7 e Uvicorn.

**2026-11-20 · Fase 5.2 de triagem assistida:** Revisão humana (`APPROVED` / `REJECTED`) em `PATCH /api/v1/triage-suggestions/{suggestion_id}/review` e componente [ai-triage-card.tsx](frontend/src/components/ai-triage-card.tsx) integrado em [suspicious-traffic-panel.tsx](frontend/src/components/suspicious-traffic-panel.tsx) e [vulnerabilities-panel.tsx](frontend/src/components/vulnerabilities-panel.tsx) validados em testes de backend e Console SOC.

**2026-11-20 · Fase 6 de piloto e expansão:** Ciclo operacional completo das fontes de telemetria (`ACTIVE` / `PAUSED` / `REVOKED` / `RECOVERY` com rotação segura de credencial, atualização via `config_version` + `heartbeat` e retomada no checkpoint), gate formal de prontidão em ambiente próprio (`OWN_ENVIRONMENT`) e habilitação estrita de cliente autorizado (`AUTHORIZED_CLIENT` com `DNS_TXT`/`HTTP_WELL_KNOWN`, CIDRs, capacidades e `max_sources`) validados com migração `0013_pilot_rollout`, PostgreSQL 16, Redis 7, Uvicorn e Console SOC ([pilot-rollout-panel.tsx](frontend/src/components/pilot-rollout-panel.tsx)). Todas as fases 1 a 6 do plano pós-v1.0 estão concluídas; consulte [PROGRESS.md](PROGRESS.md) e [TEST_MATRIX.md](TEST_MATRIX.md).

**2026-11-20 · Hub Segurança & Ferramentas SOC:** Adicionados 7 utilitários defensivos integrados na aba **Segurança & Ferramentas** ([security-tools-panel.tsx](frontend/src/components/security-tools-panel.tsx)) e nas rotas `/api/v1/security-tools/*` ([security_tools_routes.py](backend/app/api/v1/security_tools_routes.py), [security_tools_logic.py](backend/app/services/security_tools_logic.py), [security_tools_service.py](backend/app/services/security_tools_service.py)): **Pentest Assistant** (OWASP WSTG + correlação com ativo/checks), **Password Tools** (CSPRNG + análise NIST/OWASP sem persistência), **Forensics** (hashes, defang de IOCs, timeline e JWT), **Firewall Tester** (iptables/UFW, sombreamento e simulação de pacote), **Malware Analysis** (análise estática sem execução e MITRE ATT&CK), **WiFi Auditor** (`netsh`/`nmcli`, WPS e Evil Twin) e **DDoS Analyzer** (logs L7/RPS, postura Módulo F e snippets defensivos). Suítes validadas (`backend` `92/92`, `security-engine` `49/49`, `ruff` 0 erros, `frontend` `51/51` Vitest, `tsc --noEmit` e `next build`).

---

## 1. Resumo Executivo do Estado Atual

- **Fases Concluídas:**
  - `FASE 0 — Planejamento e Arquitetura` (100%)
  - `FASE 1 — Fundação do Projeto` (100%)
  - `FASE 2 — Autenticação, RBAC Multi-Organização e Gestão de Ativos Autorizados` (100%)
  - `FASE 3 — Motor de Auditoria, Orquestração e Primeiros Verificadores Passivos` (100%)
  - `FASE 4 — Dashboard SOC, Triagem de Vulnerabilidades e Interface de Auditorias` (100%)
  - `FASE 5 — Ampliação do Security Engine e Módulos Canônicos (A a H)` (100%)
  - `FASE 6 — Relatórios Profissionais, Histórico, Comparação de Auditorias e Gestão de Correções` (100%)
  - `FASE 7 — Automação, Agendamentos, Notificações, Webhooks e Integrações` (100%)
  - `FASE 8 — Auditoria Geral, Hardening, Testes E2E e Preparação da Versão 1.0` (100%)
- **Status da Release:** 🟢 **READY FOR RELEASE v1.0.0**

---

## 2. Componentes Implementados e Validados

| Componente | Estado Atual | Detalhes |
| :--- | :--- | :--- |
| Documentação de Memória Persistente | `CONSOLIDADA` | `AGENTS.md`, `ARCHITECTURE.md`, `DECISIONS.md` (ADRs 001–015), `SECURITY_SCOPE.md`, `ROADMAP.md`, `TEST_MATRIX.md`, `PROJECT_STATE.md`, `NEXT_STEPS.md`, `README.md`, `RELEASE_READINESS.md`, `INSTALLATION.md`, `DEPLOYMENT.md`, `OPERATIONS.md`, `SECURITY.md`, `BACKUP_RECOVERY.md`, `CHANGELOG.md` 100% atualizados. |
| `security-engine/` (Fases 1–8) | `OPERACIONAL` | Todos os 8 módulos canônicos (Módulos A a H, **53 checks determinísticos** `CHK-A01` a `CHK-H09`), incluindo as verificações ampliadas (`CHK-A13` SRI, `CHK-B05` Segredos Hardcoded/Web Storage, `CHK-C05` SSTI, `CHK-D05` NoSQL/LDAP/XPath Injection, `CHK-E04` Entropia/Desserialização de Cookies, `CHK-F05` Web Cache Poisoning, `CHK-G06` Exposição Excessiva de Dados BOPLA, `CHK-G07` Introspecção/Sugestões GraphQL, `CHK-H08` Host Header Injection, `CHK-H09` Source Maps/Artefatos de Build), além das verificações especializadas e agressivas (`CHK-B04`, `CHK-C04`, `CHK-D03`, `CHK-D04`, `CHK-E03`, `CHK-F04`, `CHK-G01`, `CHK-G04`, `CHK-G05`, `CHK-H05`, `CHK-H06`, `CHK-H07`). Guards contextuais anti-falso-positivo (HTML vs JSON/API, SPA Soft-404, SQLi diferencial por baseline/latência, RFC 6265bis `__Host-`/`__Secure-`, regex de cifras TLS fracas, validação HMAC/cabeçalho JWT), enriquecimento determinístico `CHECK_CVSS_V4_CATALOG`, sanitização idempotente `EvidenceManager.ensure_sanitized()` e **39 playbooks** multi-stack no `REMEDIATION_CATALOG`. **49/49 testes aprovados**. |
| `backend/` (Fases 1–8) | `OPERACIONAL` | FastAPI com tipagem estrita, autenticação JWT com revogação no servidor (`RevokedToken`), rate limiting deslizante anti-brute force, dummy scrypt timing attack defense, CSRF origin check, gates de produção (`validate_production_safety`), `/api/v1/ready` probe, cabeçalhos de segurança (X-Request-ID, CSP, HSTS, DENY), fallback rápido quando Redis está indisponível. Endpoint de exportação de relatório PDF (`GET /api/v1/scans/{scan_id}/export-pdf`) com telemetria, diagnóstico para falhas operacionais (`EXECUTION_ERROR`) e playbooks com código multi-stack. **49/49 testes aprovados** (e 3/3 testes de smoke/infraestrutura aprovados). |
| `workers/` & `beat` (Fases 1–8) | `OPERACIONAL` | Celery Worker e Celery Beat ativos na stack Docker compartilhando volume de relatórios e variáveis de escopo. Tarefa periódica `process_due_schedules_task` executada com sucesso a cada minuto. |
| `frontend/` (Fases 1–8) | `OPERACIONAL` | Console SOC Next.js 14 App Router completo (TypeScript estrito, Tailwind CSS, shadcn/ui): Dashboard com KPIs e gráficos Recharts, abas de Ativos, Scans com SSE e extração rápida de PDF de auditorias, Triagem de Vulnerabilidades, Relatórios/Comparação e Automações. 27/27 testes Vitest, `tsc --noEmit` e build standalone de produção aprovados. |
| `infrastructure/` & `docker-compose.yml` | `OPERACIONAL` | Stack completa de 6 serviços (`csc-postgres`, `csc-redis`, `csc-backend`, `csc-worker`, `csc-beat`, `csc-frontend`) em execução e saudáveis (`healthy`), com usuários não-privilegiados (`csc` e `node`). |
| Resiliência & Disaster Recovery | `VALIDADO` | Scripts de backup compactado (`scripts/backup_db.ps1`) e restauração isolada (`scripts/restore_db_verify.ps1`) validados contra PostgreSQL 16 com as 18 tabelas relacionais e migração `0004_phase8_revoked_tokens`. |

---

## 3. Portas Padrão e Serviços

- **Frontend (Next.js):** `http://localhost:3000`
- **Backend API (FastAPI):** `http://localhost:8000`
- **Readiness Probe:** `http://localhost:8000/api/v1/ready`
- **Documentação Swagger:** `http://localhost:8000/docs`
- **PostgreSQL 16:** `localhost:5432`
- **Redis 7:** `localhost:6379`
