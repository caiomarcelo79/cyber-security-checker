# Manual de Operações e Runbook (`OPERATIONS.md`)

Este manual estabelece os procedimentos operacionais padrão (SOP), monitoramento, resolução de incidentes e rotinas de manutenção para o **Cyber-Security-Checker**.

---

## 1. Monitoramento e Health Checks

A plataforma expõe endpoints determinísticos para observabilidade contínua:

### 1.1 Liveness Probe (Saúde Imediata do Processo)
- **Endpoint**: `GET http://localhost:8000/api/v1/health`
- **Uso**: Kubernetes Liveness Probe ou verificação simples de que a API responde.
- **Resposta normal**:
  ```json
  {
    "status": "UP",
    "service": "cyber-security-checker",
    "version": "1.0.0",
    "environment": "production"
  }
  ```

### 1.2 Readiness Probe (Disponibilidade Operacional com Dependências)
- **Endpoint**: `GET http://localhost:8000/api/v1/ready`
- **Uso**: Kubernetes Readiness Probe ou verificação de balanceador antes de rotear tráfego.
- **Comportamento**:
  - Testa conectividade real com PostgreSQL via consulta `SELECT 1`.
  - Testa conectividade real com Redis via comando `PING`.
  - Se todas as dependências estiverem disponíveis: HTTP 200 `{"status": "READY", "checks": {"database": "UP", "redis": "UP"}}`.
  - Se qualquer dependência falhar: HTTP 503 Service Unavailable `{"status": "DEGRADED", "checks": {"database": "DOWN", "redis": "UP"}}`.

### 1.3 Telemetria do Sistema
- **Endpoint**: `GET http://localhost:8000/api/v1/system/status`
- **Requer**: Autenticação (Viewer, Developer, Analyst ou Admin).
- **Conteúdo**: Contadores consolidados de ativos, auditorias ativas, vulnerabilidades abertas e métricas operacionais.

---

## 2. Gestão de Logs e Rastreabilidade

O sistema gera logs estruturados no padrão RFC 5424 em formato JSON ou texto com correlação ponta a ponta:

- **Correlation ID / X-Request-ID**: Toda requisição HTTP recebe ou propaga um cabeçalho `X-Request-ID`. Qualquer falha técnica registrada em log inclui o identificador correlacionado.
- **Audit Logs Imutáveis**: Todas as operações críticas de segurança (login, criação de ativo, início de scan, alteração de triagem, revogação de tokens e download de relatórios) são gravadas na tabela `audit_logs` com IP de origem, usuário, organização e timestamp UTC.

### Inspecionando Logs em Containers
```bash
# Logs do backend em tempo real
docker compose logs -f backend

# Logs dos workers de auditoria
docker compose logs -f worker

# Logs do agendador Celery Beat
docker compose logs -f beat
```

---

## 3. Gestão e Escalonamento dos Workers Celery

O processamento das auditorias é assíncrono e isolado em filas gerenciadas pelo Celery:

### 3.1 Filas do Sistema
- **`default` / `scans`**: Fila principal de despacho de auditorias autorizadas (`workers.tasks.execute_scan_task`).
- **`periodic`**: Fila de execução de tarefas agendadas (`workers.tasks.process_due_schedules_task`).

### 3.2 Escalonamento de Workers
Para aumentar a capacidade de auditorias concorrentes em picos operacionais:
```bash
# Escalonar para 4 instâncias de workers
docker compose up -d --scale worker=4
```

### 3.3 Recuperação de Auditorias Interrompidas
Se um container de worker for reiniciado abruptamente durante a execução de uma auditoria, o backend recupera auditorias travadas em `RUNNING` através da rotina `ScanOrchestrator.recover_interrupted_scans()`, marcando auditorias órfãs com status `ABORTED` ou `FAILED` e liberando os semáforos de concorrência.

---

## 4. Rotinas de Backup e Recuperação de Desastres

A rotina operacional de backup deve ser executada diariamente. A documentação completa de procedimentos de recuperação está disponível em [`BACKUP_RECOVERY.md`](file:///c:/Users/GTI-LABSP/Documents/caio/cyber-security-checker/BACKUP_RECOVERY.md).

### 4.1 Execução de Backup Diário
```powershell
# Execução no Windows PowerShell
.\scripts\backup_db.ps1
```
Gera arquivo compactado `.sql.gz` versionado no diretório `backups/`.

### 4.2 Teste Automatizado de Restauração em Ambiente Isolado
```powershell
# Valida a integridade do backup restaurando em container temporário e auditando as 18 tabelas
.\scripts\restore_db_verify.ps1
```

---

## 5. Procedimentos de Resolução de Problemas (Troubleshooting)

### Problema 1: Falha 503 no endpoint `/ready`
- **Sintoma**: A aplicação retorna HTTP 503 com `database: DOWN` ou `redis: DOWN`.
- **Ação**:
  1. Verifique se o container `csc-postgres` está saudável: `docker compose ps csc-postgres`.
  2. Verifique se as credenciais de `DATABASE_URL` no `.env` correspondem ao banco.
  3. Verifique se o Redis atingiu o limite de conexões: `docker compose logs redis`.

### Problema 2: Auditoria permanece em status `QUEUED` sem iniciar
- **Sintoma**: A auditoria foi criada com sucesso, mas o progresso permanece em 0%.
- **Ação**:
  1. Verifique se o serviço `csc-worker` está ativo: `docker compose ps csc-worker`.
  2. Inspecione os logs do worker: `docker compose logs --tail 50 csc-worker`.
  3. Reinicie o worker se necessário: `docker compose restart csc-worker`.

### Problema 3: Agendamentos de auditorias não disparam no horário
- **Sintoma**: O agendamento está `ACTIVE` e com data vencida, mas nenhuma auditoria foi criada.
- **Ação**:
  1. Verifique se o serviço `csc-beat` está em execução: `docker compose ps csc-beat`.
  2. Verifique se a autorização do ativo associado não expirou (`authorization_status` deve ser `VERIFIED`).
  3. Verifique os logs de scheduler: `docker compose logs --tail 50 csc-beat`.
