# Registro de Alterações (`CHANGELOG.md`)

Todas as modificações relevantes do projeto **Cyber-Security-Checker** estão documentadas neste arquivo, seguindo as diretrizes do [Keep a Changelog](https://keepachangelog.com/pt-BR/1.0.0/) e versionamento semântico [SemVer](https://semver.org/lang/pt-BR/).

---

## [1.0.0] - 2026-10-23 — Versão Consolidada v1.0 (Fase 8)

### Adicionado
- **Hardening e Gates de Produção (`validate_production_safety`)**:
  - Validação estrita de entropia e complexidade de `SECRET_KEY` e `POSTGRES_PASSWORD` na inicialização do backend.
  - Bloqueio incondicional de configurações inseguras (`CORS_ORIGINS=*`, `ALLOW_LOCAL_LAB_TARGETS=true` em produção).
- **Endpoint de Readiness (`GET /api/v1/ready`)**:
  - Verificação ativa e em tempo real da integridade do banco de dados PostgreSQL e do Redis antes de rotear tráfego.
- **Revogação Imediata de Sessão (`RevokedToken`)**:
  - Tabela relacional e migração Alembic (`0004_phase8_revoked_tokens`) para invalidar tokens JWT no servidor ao efetuar logout.
- **Auditoria de Autenticação e Hardening Anti-Abuso**:
  - *Rate limiting* deslizante baseado em logs de auditoria (máximo de 8 falhas por e-mail e 20 por IP em 15 minutos).
  - Mitigação de ataques de temporização (*timing attacks*) via hash computacional equivalente para usuários inexistentes.
  - Defesa em profundidade contra CSRF inspecionando cabeçalho `Origin` em mutações via cookie.
  - Mitigação de spoofing de IP ignorando `X-Forwarded-For` por padrão, a menos que `TRUST_FORWARDED_FOR=true`.
- **Suíte de Testes End-to-End (`test_phase8_e2e_flows.py`)**:
  - Validação automatizada completa dos 5 fluxos fundamentais:
    - **Fluxo A**: Usuário, RBAC, Ativos e Isolamento Multi-Organização.
    - **Fluxo B**: Orquestração de Auditorias, Scanners Seguros e Cancelamento Cooperativo.
    - **Fluxo C**: Ciclo de Vida de Vulnerabilidades, Sanitização de Evidências, Triagem e Revalidação.
    - **Fluxo D**: Geração de Relatórios (Técnico e Executivo em JSON e CSV) com Controle de Acesso por Tenant.
    - **Fluxo E**: Automações, Agendamento no Scheduler, Notificações In-App com Deduplicação e Webhooks Assinados com HMAC-SHA256.
- **Rotinas de Backup e Recuperação de Desastres**:
  - Scripts utilitários `scripts/backup_db.ps1` e `scripts/restore_db_verify.ps1`.
  - Manual operacional completo de backup e recuperação (`BACKUP_RECOVERY.md`).
- **Agendador Celery Beat (`csc-beat`)**:
  - Integração no `docker-compose.yml` para disparo automatizado de auditorias periódicas e rotinas de manutenção.

### Corrigido
- Resolução de sombreamento de rota no FastAPI: reordenação de `/webhooks/deliveries` antes de `/webhooks/{webhook_id}`.
- Instanciação de `NotificationService` no disparador de agendamentos (`SchedulerService`).
- Adição do método auxiliar `create_scan` em `ScanOrchestrator` para suporte a criações programáticas de auditorias agendadas.
- Atualização e alinhamento de esquemas de `FindingRecord` e `ScanScheduleCreateRequest`.

---

## [0.7.0] - 2026-10-22 — Automações, Agendamentos e Alertas (Fase 7)

### Adicionado
- Agendamento de auditorias recorrentes via expressões Cron e frequências padrão (`ONCE`, `DAILY`, `WEEKLY`, `MONTHLY`).
- Notificações internas no painel com janela de deduplicação e preferências por usuário.
- Webhooks com validação anti-SSRF e assinatura criptográfica HMAC-SHA256 no cabeçalho `X-CSC-Signature`.
- Gestão de API Tokens com escopos granulares de permissão (`read:scans`, `write:scans`, `read:reports`, etc.).
- Templates de auditoria pré-configurados e personalizáveis.

---

## [0.6.0] - 2026-10-21 — Relatórios Profissionais e Revalidação (Fase 6)

### Adicionado
- Motor de relatórios (`ReportEngine`) com suporte aos formatos PDF, HTML, JSON e CSV.
- Sanitização de células CSV contra injeção de fórmulas (*CSV Formula Injection*).
- Comparação técnica de auditorias (*diff* entre execuções) com paridade de cobertura.
- Fluxo de revalidação técnica de vulnerabilidades e métricas de evolução temporal de risco.

---

## [0.5.0] - 2026-10-20 — Módulos Avançados de Auditoria (Fase 5)

### Adicionado
- Módulo B: Autenticação, Proteção contra Força Bruta e Políticas de Senha.
- Módulo C: Indicadores de Cross-Site Scripting (XSS) com payloads não destrutivos.
- Módulo D: Indicadores de SQL Injection (SQLi) com heurísticas seguras.
- Módulo F: Postura e Resiliência contra Ataques de Negação de Serviço.
- Módulo G: Segurança de APIs REST e GraphQL (CORS, Métodos HTTP, Tipos MIME).
- Módulo H: Configurações Inseguras, Clickjacking, Open Redirect e Exposição de Informações.
- Verificação CHK-A12: Validação de Registros DNS SPF e DMARC.

---

## [0.4.0] - 2026-10-19 — Dashboard SOC e Triagem de Falhas (Fase 4)

### Adicionado
- Console SOC em Next.js com estética escura de alto contraste, KPIs reais e zero dados fictícios.
- Acompanhamento de progresso de auditorias em tempo real via Server-Sent Events (SSE).
- Filtros avançados, busca e paginação de auditorias e vulnerabilidades no servidor.
- Ciclo de vida e triagem de falhas (`OPEN`, `IN_ANALYSIS`, `WAITING_VALIDATION`, `RESOLVED_VERIFIED`, `ACCEPTED_RISK`).

---

## [0.3.0] - 2026-10-18 — Motor de Auditoria e Orquestração (Fase 3)

### Adicionado
- Motor central `security_engine` modular com catálogo de plugins.
- Validador de escopo `ScopePolicyValidator` com bloqueio inviolável de RFC 1918 e metadados de nuvem.
- Módulo A: Reconhecimento HTTP, TLS/SSL e Cabeçalhos de Segurança.
- Módulo E: Cookies de Sessão, Flags `HttpOnly`, `Secure` e `SameSite`.
- Orquestrador de auditorias com enfileiramento assíncrono no Celery e cancelamento cooperativo.

---

## [0.2.0] - 2026-10-17 — Autenticação, RBAC e Gestão de Ativos (Fase 2)

### Adicionado
- Autenticação JWT com cookies seguros e suporte a cabeçalho `Authorization: Bearer`.
- Modelo de controle de acesso baseado em papéis (RBAC): `ADMIN`, `SECURITY_ANALYST`, `DEVELOPER`, `VIEWER`.
- Isolamento multi-tenant estrito por organização.
- Cadastro de ativos com validação de formato e comprovação de autorização via DNS TXT e HTTP Well-Known.

---

## [0.1.0] - 2026-10-16 — Fundação e Infraestrutura (Fase 1)

### Adicionado
- Orquestração base via Docker Compose (PostgreSQL 16 e Redis 7).
- Aplicação FastAPI estruturada em camadas com SQLAlchemy 2.0 e Alembic.
- Aplicação Next.js 14 com Tailwind CSS e componentes shadcn/ui.
- Health checks de liveness e prontidão de infraestrutura.
