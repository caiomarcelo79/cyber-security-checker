# NEXT_STEPS.md — Próximas Tarefas Priorizadas (`cyber-security-checker`)

Este arquivo documenta as tarefas concluídas em todas as fases do projeto (FASES 0 a 8) e as recomendações para manutenção contínua e futuras evoluções pós-v1.0.

---

## Tarefas Concluídas (FASES 0 a 8 — 100% Concluídas)

- [x] **`[T0.1]` Arquitetura, Políticas de Escopo e Memória Persistente**: Documentação completa e ADRs 001–012.
- [x] **`[T1.1]` Pacote `security-engine/`**: Contratos, `ScopePolicyValidator`, `ScanExecutionPolicy`, `EvidenceManager`, `RiskEngine`, `RemediationEngine` e `PluginRegistry`.
- [x] **`[T1.2]` `backend/` e `workers/`**: Modelos SQLAlchemy 2.0, Alembic e healthchecks.
- [x] **`[T1.3]` `frontend/` (Fundação SOC)**: Painel SOC Next.js + TypeScript + Tailwind + shadcn/ui.
- [x] **`[T1.4]` Infraestrutura Docker Compose**: Containers `postgres` e `redis` integrados e saudáveis.
- [x] **`[T2.1]` Autenticação Segura, Organizações e RBAC Multi-Tenant**: Hash `scrypt`, JWT + Cookie `HttpOnly`, papéis `ADMIN`, `SECURITY_ANALYST`, `DEVELOPER`, `VIEWER` e isolamento multi-tenant.
- [x] **`[T2.2]` Ativos (`Assets`), Comprovação de Autorização e `AuditLog`**: `DNS_TXT`, `HTTP_WELL_KNOWN`, `LAB_INTERNAL` e auditoria.
- [x] **`[T2.3]` Integração Frontend da Fase 2**: Abas de Autenticação, Sistemas/Ativos, Autorização, Membros RBAC e Logs.
- [x] **`[T3.1]` Cliente HTTP Seguro, `SecurityEngineRunner` e Módulos Passivos (A e E)**: Probing seguro, SSL/TLS, Security Headers e Cookies.
- [x] **`[T3.2]` `ScanOrchestrator`, Persistência Incremental e Cancelamento Cooperativo**: Orquestração com Celery e Redis.
- [x] **`[T3.3]` Testes Fim a Fim e Integração Frontend**: Acompanhamento de progresso e detalhamento de verificações.
- [x] **`[T4.1]` Dashboard SOC com Agregações Reais e Tendências**: Telemetria sem mocks, KPIs reais e ranking de risco.
- [x] **`[T4.2]` Gestão e Triagem de Vulnerabilidades**: Triagem com RBAC, SLA, notas técnicas e trilha de histórico.
- [x] **`[T4.3]` Monitoramento em Tempo Real via SSE**: Server-Sent Events com limite por organização e fallback adaptativo.
- [x] **`[T5.1]` Módulos Canônicos (A–H) e CHK-A12**: XSS, SQLi com heurísticas seguras, DoS posture, APIs e SPF/DMARC.
- [x] **`[T6.1]` Motor de Relatórios Profissionais (`ReportEngine`)**: PDF, HTML, JSON e CSV sanitizado contra Formula Injection.
- [x] **`[T6.2]` Comparação Determinística de Auditorias**: Comparação diferencial entre auditorias com paridade de cobertura.
- [x] **`[T6.3]` Revalidação Técnica e Ciclo de Vida de Correções**: Revalidação direcionada com MTTR em dias.
- [x] **`[T6.4]` Interface Frontend SOC para Relatórios e Revalidação**: Painel de relatórios, modal de comparação e revalidação.
- [x] **`[T7.1]` Agendamento Recorrente de Auditorias**: Frequências padrão e Cron com fusos horários IANA.
- [x] **`[T7.2]` Centro de Notificações In-App e Email**: Central de alertas com deduplicação e SMTP com TLS.
- [x] **`[T7.3]` Webhooks Seguros com HMAC-SHA256**: Anti-SSRF, assinaturas criptográficas e histórico de entregas.
- [x] **`[T7.4]` Chaves de API para CI/CD**: Tokens com prefixo `csc_live_...` e armazenamento em hash SHA-256.
- [x] **`[T7.5]` Templates de Auditoria e ChatOps**: Padrões da indústria e adaptadores para Slack e Discord.
- [x] **`[T7.6]` Painel Frontend de Automações & Integrações**: 5 sub-abas completas de automação.
- [x] **`[T8.1]` Hardening da Aplicação e Segurança de Produção**:
  - `validate_production_safety` rejeitando senhas/chaves padrão, CORS * e alvos locais em produção.
  - Revogação imediata de JWT no logout via `RevokedToken` e migração Alembic `0004_phase8_revoked_tokens`.
  - Rate limiting deslizante (8 falhas por e-mail e 20 por IP) e dummy scrypt hash contra timing attacks.
  - Defesa contra CSRF em requisições cookie-mutantes verificando cabeçalho `Origin`.
  - Cabeçalhos de segurança na API (`X-Request-ID`, `CSP`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `HSTS` em produção).
- [x] **`[T8.2]` Testes de Integração End-to-End (E2E) dos 5 Fluxos**:
  - `test_flow_a_user_assets_and_multitenant_isolation`: Aprovado.
  - `test_flow_b_scans_execution_and_cancellation`: Aprovado.
  - `test_flow_c_vulnerability_lifecycle_sanitization_and_revalidation`: Aprovado.
  - `test_flow_d_reports_generation_and_export_permissions`: Aprovado.
  - `test_flow_e_automations_scheduler_notifications_and_webhooks`: Aprovado.
- [x] **`[T8.3]` Infraestrutura Docker Completa e Procedimentos Operacionais**:
  - Imagens Docker construídas para todos os serviços com usuários não privilegiados (`csc` e `node`).
  - Serviço `csc-beat` integrado ao `docker-compose.yml`.
  - Inicialização e health checks reais de todos os 6 containers (`csc-postgres`, `csc-redis`, `csc-backend`, `csc-worker`, `csc-beat`, `csc-frontend`).
  - Scripts de backup (`scripts/backup_db.ps1`) e restauração verificada (`scripts/restore_db_verify.ps1`) com auditoria das 18 tabelas.
- [x] **`[T8.4]` Documentação Operacional e de Release v1.0**:
  - `INSTALLATION.md`, `DEPLOYMENT.md`, `OPERATIONS.md`, `SECURITY.md`, `BACKUP_RECOVERY.md`, `CHANGELOG.md` e `RELEASE_READINESS.md` homologando o status **READY**.
- [x] **`[T8.5]` Refatoração e Homologação da Tela de Auditorias (Console SOC)**:
  - Reorganização para fluxo vertical SOC em largura total (Formulário responsivo com grid de 4 colunas para parâmetros + Monitor de telemetria em tempo real com botão de fechamento + Tabela de histórico de auditorias em largura total com filtro de 6 colunas, `whitespace-nowrap` e largura mínima por coluna).
  - Eliminação de requisições 404 para `/api/v1/scans/null/progress` e `/api/v1/scans/null/results` através de guards defensivos e prefetch determinístico com o ID real do scan criado.
  - Eliminação do erro de hidratação React #423 via `mounted` guard no alternador de temas.
  - Validação fim a fim contra a stack Docker e proxy da API do Next.js.

---

## Próximos Passos Pós-v1.0 (Backlog Versão 1.1)

1. **Atualização do Next.js**: Atualizar para versão mais recente para sanar o alerta residual de PostCSS em `npm audit`.
2. **Alertas Push e Web Push**: Notificações push no navegador via Service Workers para analistas do SOC.
3. **Módulos Adicionais de Auditoria**: Suporte a GraphQL Introspection and Injection Testing.
