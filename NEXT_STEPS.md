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
- [x] **`[T8.6]` Verificações de Segurança Agressivas e Perfil DEEP_PENTEST**:
  - Implementação de `CHK-C04` (Fuzzing Ativo Contextual XSS em múltiplos parâmetros).
  - Implementação de `CHK-D03` (Heurísticas não destrutivas de Injeção de Comandos de SO).
  - Implementação de `CHK-D04` (Heurística de SQL Injection Cego baseado em tempo com medição de delay diferencial).
  - Implementação de `CHK-G01` (Prova ativa de reflexão arbitrária de cabeçalho Origin em CORS com credenciais).
  - Implementação de `CHK-G04` (Verificação ativa de métodos HTTP perigosos TRACE e Cross-Site Tracing XST).
  - Implementação de `CHK-H01` ampliado (Wordlist de 15 caminhos sensíveis de sistema e ambiente).
  - Implementação de `CHK-H03` ampliado (Prova ativa de Open Redirect com canários de redirecionamento).
  - Implementação de `CHK-H05` (Detecção ativa de Path Traversal e Local File Inclusion LFI).
  - Implementação de `CHK-H06` (Indicadores de Server-Side Request Forgery SSRF no alvo via canários e erros de rede).
  - Cadastro do perfil `DEEP_PENTEST` no catálogo com bloqueio obrigatório contra Produção (`allowed_in_production=False` e HTTP 422 para `PRODUCTION`).
  - 5 novos playbooks determinísticos de remediação estruturada no `RemediationEngine`.
  - Opção no console SOC com banner de aviso de escopo.
  - 33 testes no `security-engine` aprovados, 47 no backend aprovados e 27 no frontend aprovados.
- [x] **`[T8.7]` Verificações Especializadas, Medidas Protetivas Prescritivas e Exportação de PDF com Diagnósticos**:
  - Adição de 5 novas verificações de segurança (`CHK-B04`, `CHK-E03`, `CHK-F04`, `CHK-G05`, `CHK-H07`).
  - Adição de 5 playbooks prescritivos ao `REMEDIATION_CATALOG` com perigo, diagnóstico, passo a passo, código multi-stack (Python, Node.js, Java, Nginx/Caddy) e referências CWE/OWASP.
  - Reestruturação do motor ReportLab (`_render_pdf`) gerando relatórios PDF completos com telemetria, matriz de severidades, seção detalhada de Erros de Execução (`EXECUTION_ERROR`) com orientações de diagnóstico de infraestrutura, caixas de evidências sanitizadas e playbooks de remediação.
  - Rota dedicada `GET /api/v1/scans/{scan_id}/export-pdf` com isolamento multi-tenant, auditoria e geração síncrona/assíncrona.
  - Botões de extração PDF na tabela de auditorias (`scans-history-panel.tsx`) e no monitor de auditoria (`soc-console.tsx`).
  - 39 testes no `security-engine` aprovados, 49 no backend aprovados, 27 no frontend aprovados.
- [x] **`[T8.8]` Auditoria Completa, Ampliação de Cobertura (53 Checks / 39 Playbooks) e Aumento de Precisão Anti-Falso-Positivo**:
  - Expansão do catálogo de verificações determinísticas nos Módulos A–H com **10 novos checks** (`CHK-A13` SRI em scripts/estilos externos, `CHK-B05` Segredos hardcoded no cliente e tokens em Web Storage, `CHK-C05` Server-Side Template Injection SSTI, `CHK-D05` NoSQL/LDAP/XPath Injection, `CHK-E04` Entropia fraca e assinaturas de desserialização em cookies Java/Pickle/PHP, `CHK-F05` Web Cache Poisoning via cabeçalhos não chaveados, `CHK-G06` Exposição Excessiva de Propriedades Sensíveis BOPLA, `CHK-G07` GraphQL Introspection e Field Suggestions, `CHK-H08` Host Header Injection, `CHK-H09` Source Maps `.js.map` e `/Dockerfile`).
  - Melhorias substanciais de precisão e redução de falsos positivos/negativos: análise contextual de CSP sem falso positivo em subdomínios `https://*.cdn...` e detecção de `frame-ancestors *` / HSTS `max-age=0` / cifras TLS fracas (`RC4`/`3DES`/`DES`/`NULL`/`MD5`) / políticas SPF `+all` vs `?all` e DMARC `p=none`; detecção de formulários com senha sem atributo `method=` (`CHK-B04`); prevenção de falso positivo XSS em payloads JSON com `X-Content-Type-Options: nosniff` e descoberta dinâmica de parâmetros HTML `<input>`; SQLi diferencial por baseline/latência efetiva e checagem booleana (`CHK-D02`/`CHK-D04`); validação estrita RFC 6265bis em prefixos `__Host-`/`__Secure-` (`CHK-E03`); verificação de segredo HMAC fraco e cabeçalhos `jku`/`x5u`/`jwk`/`kid` em JWT (`CHK-G05`); filtragem de páginas HTML Soft-404 de SPAs (`CHK-H01`/`CHK-H09`) e detecção de bypass `//`/`/\` em Open Redirect (`CHK-H03`).
  - Catálogo determinístico `CHECK_CVSS_V4_CATALOG` para todos os 53 checks no `RiskEngine` e enforcement automático de `EvidenceManager.ensure_sanitized()` com `SENSITIVE_QUERY_KEYS` ampliado e sanitização idempotente.
  - Adição de 10 novos playbooks multi-stack ao `REMEDIATION_CATALOG` (totalizando **39 playbooks**).
  - Resiliência do `ScanOrchestrator`, `database.py` e `celery_app.py` para fail-fast de broker/Redis em testes locais.
  - Validação completa: 49 testes no `security-engine`, 49 no `backend`, 3 na suíte de infraestrutura (`tests/`) e 0 erros no `ruff check` (totalizando 101 testes Python aprovados).

---

## Próximos Passos Pós-v1.0 (Backlog Versão 1.1)

O ponto de retomada e o roteiro de validação ficam em [PROGRESS.md](PROGRESS.md). As fases futuras e seus critérios de aceite ficam em [ROADMAP.md](ROADMAP.md).

### Fase 1 — SSH

- [x] **1.1 — Verificar a diretiva global de senha.** OpenSSH real, CLI, API e PostgreSQL validados em laboratório, com estados e evidências conferidos nos testes do Console. Os testes cobrem autorização revogada ou expirada, isolamento entre organizações e evidência insuficiente.
- [x] **1.2 — Verificar a política de acesso de root.** A coleta global classifica o bloqueio integral como conforme e registra divergência quando algum acesso de root permanece permitido.
- [x] **1.3 — Validar o fluxo de notificação de autenticação.** O exercício publica um evento sintético identificado na caixa de notificações do próprio analista e mede o tempo até a publicação.

### Checklist antes da Fase 2

- [x] Os resultados de senha e root correspondem à configuração OpenSSH avaliada em laboratório. A renderização no Console foi verificada em testes de componente.
- [x] Falha de coleta e evidência insuficiente são exibidas como estados próprios. Autorizações ausentes, expiradas e revogadas bloqueiam novas coletas.
- [x] Os testes de isolamento entre organizações e minimização de evidência passam.
- [x] O alerta sintético aparece na caixa de notificações do analista e o exercício retorna o tempo de publicação.
- [x] Migrações, testes do backend e validação do frontend passaram. A [matriz de testes](TEST_MATRIX.md) e o [arquivo de progresso](PROGRESS.md) registram os resultados e o ponto de retomada.

### Fase 2 — Coletor desktop

- [x] **2.1 — Definir e provar a primeira integração.** O Console cadastra uma instalação Zeek e seu segmento. A CLI importa o `conn.log`, e a API valida escopo, deduplica reenvios e aplica retenção. Os campos e o tamanho de lote estão documentados em [PROGRESS.md](PROGRESS.md).
- [x] **2.2 — Entregar o piloto desktop.** A janela mostra a fonte, o segmento, o último envio e o atraso. Os controles pausam e retomam um lote em memória. O leitor mantém a posição confirmada entre reinícios e trata indisponibilidade, rotação com a janela aberta e revogação.

### Fase 3 — Disponibilidade

- [x] **3.1 — Criar o primeiro exercício de disponibilidade.** Preparar em laboratório uma sequência sintética com estado normal, degradação e recuperação. Validar um limiar de alerta e a publicação na caixa de notificações do analista. Registrar a linha do tempo esperada e a observada.
- [x] **3.2 — Ampliar métricas e fontes de observação.** Adicionar cenários de latência, erros e saturação. Quando uma fonte autorizada estiver disponível, incorporar alertas de firewall, CDN ou provedor.

### Fase 4 — Tráfego suspeito

- [x] **4.1 — Detectar anomalias explicáveis de conexões, DNS e identidade TLS.** Ingestão autenticada em fonte `TelemetrySource` via [scripts/analyze_traffic.py](scripts/analyze_traffic.py) (`conn.log`, `dns.log` e `ssl.log`) e `POST /api/v1/telemetry/sources/{source_id}/traffic-analyses`, avaliação determinística em [suspicious_traffic_logic.py](backend/app/services/suspicious_traffic_logic.py) (`CONNECTION_PORT_SWEEP`, `CONNECTION_REPEATED_BURST`, `DNS_NXDOMAIN_BURST`, `DNS_HIGH_ENTROPY_QUERY` e `TLS_POSSIBLE_INTERCEPTION`), distinção explícita de rotação legítima de certificado (`BENIGN_ROTATION`) sem falso positivo e persistência com evidência sanitizada, confiança e cobertura por camada.
- [x] **4.2 — Correlacionar sinais de antivírus/EDR e exibir no Console SOC.** Sinais opcionais (`ANTIVIRUS`, `EDR`) ingeridos via `edr_signals` / `--edr-log` ([analyze_traffic.py](scripts/analyze_traffic.py)), validados no segmento CIDR autorizado, correlacionados por `host_ip` em [suspicious_traffic_logic.py](backend/app/services/suspicious_traffic_logic.py) (elevando cobertura para `EDR` e confiança/severidade para `HIGH` nos alertas do mesmo host) e exibidos em modo somente leitura em [suspicious-traffic-panel.tsx](frontend/src/components/suspicious-traffic-panel.tsx) dentro de **Sistemas e Ativos → Ver detalhes**.

### Fase 5 — Triagem assistida por IA

- [x] **5.1 — Resumir evidências sanitizadas, explicar alertas e sugerir correções com fallback resiliente.** Motor [ai_triage_logic.py](backend/app/services/ai_triage_logic.py), serviço [ai_triage_service.py](backend/app/services/ai_triage_service.py), rotas [ai_triage_routes.py](backend/app/api/v1/ai_triage_routes.py) e migração [0012_ai_triage_suggestions.py](backend/alembic/versions/0012_ai_triage_suggestions.py) para alertas de tráfego suspeito (`SuspiciousTrafficAlert`) e vulnerabilidades (`FindingRecord`), validando citações na evidência sanitizada e degradando graciosamente para síntese determinística (`DETERMINISTIC_FALLBACK`) quando a IA está desligada, indisponível ou sem fundamentação.
- [x] **5.2 — Revisão e decisão pelo analista no Console SOC.** Endpoint `PATCH /api/v1/triage-suggestions/{suggestion_id}/review` (`APPROVED` / `REJECTED` com sanitização de nota do revisor e auditoria `AI_TRIAGE_SUGGESTION_REVIEWED`) e componente [ai-triage-card.tsx](frontend/src/components/ai-triage-card.tsx) integrado em [suspicious-traffic-panel.tsx](frontend/src/components/suspicious-traffic-panel.tsx) e [vulnerabilities-panel.tsx](frontend/src/components/vulnerabilities-panel.tsx).

### Fase 6 — Piloto e expansão

- [x] **6.1 — Demonstrar instalação, pausa, atualização, revogação, recuperação e revisar cobertura, latência e falsos positivos em ambiente próprio (`OWN_ENVIRONMENT`).** Ciclo operacional estendido em `TelemetrySource` ([network_telemetry.py](backend/app/services/network_telemetry.py), [network_telemetry_routes.py](backend/app/api/v1/network_telemetry_routes.py), [telemetry-sources-panel.tsx](frontend/src/components/telemetry-sources-panel.tsx), [desktop_collector.py](scripts/desktop_collector.py) e [pilot_lifecycle.py](scripts/pilot_lifecycle.py)), migração [0013_pilot_rollout.py](backend/alembic/versions/0013_pilot_rollout.py) e consolidação real de prontidão em [pilot_logic.py](backend/app/services/pilot_logic.py).
- [x] **6.2 — Habilitar cliente autorizado (`AUTHORIZED_CLIENT`) com escopo definido após aprovação.** Governança multi-tenant em [pilot_service.py](backend/app/services/pilot_service.py), [pilot_routes.py](backend/app/api/v1/pilot_routes.py), guarda compartilhada em [lab_authorization.py](backend/app/services/lab_authorization.py) e painel **Piloto & Expansão** ([pilot-rollout-panel.tsx](frontend/src/components/pilot-rollout-panel.tsx)) exigindo pré-requisito aprovado em ambiente próprio, papel `ADMIN`, autorização `DNS_TXT`/`HTTP_WELL_KNOWN` vigente, limites de CIDR (`allowed_cidrs`), capacidade (`enabled_capabilities`) e `max_sources`.

### Outros itens do backlog 1.1

1. **Atualização do Next.js**: Atualizar para versão mais recente para sanar o alerta residual de PostCSS em `npm audit`.
2. **Alertas Push e Web Push**: Notificações push no navegador via Service Workers para analistas do SOC.
3. **Módulos Adicionais de Auditoria**: Suporte a GraphQL Introspection and Injection Testing.
