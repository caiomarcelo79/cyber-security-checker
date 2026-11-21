# Progresso e retomada do desenvolvimento

Atualizado em 2026-11-20.

## Trabalho atual

- Fase 1 do plano pós-v1.0 concluída em laboratório. A CLI coleta a política de senha e de acesso de root, e o exercício de alerta usa a caixa de notificações do Console SOC.
- Fase 2 concluída em laboratório. O piloto desktop lê o `conn.log` do Zeek e retoma a partir do último lote confirmado.
- Fase 3 concluída em laboratório (itens 3.1 e 3.2). O exercício de disponibilidade cobre os cenários `LATENCY`, `ERRORS` (HTTP `503`) e `SATURATION` (HTTP `429` com atraso), avalia amostras consecutivas e integra sinais opcionais de firewall, CDN ou provedor correlacionados à linha do tempo no Console.
- Fase 4 concluída em laboratório (itens 4.1 e 4.2). O analisador determinístico avalia conexões (`CONNECTION_PORT_SWEEP`, `CONNECTION_REPEATED_BURST`), DNS (`DNS_NXDOMAIN_BURST`, `DNS_HIGH_ENTROPY_QUERY`), identidade TLS (`TLS_POSSIBLE_INTERCEPTION` vs. `BENIGN_ROTATION` sem falso positivo) e correlaciona sinais opcionais de antivírus/EDR (`ANTIVIRUS`, `EDR`) por `host_ip`, expondo cobertura por camada, decisões TLS, sinais AV/EDR e alertas com evidência e confiança no Console SOC.
- Fase 5 concluída em laboratório (itens 5.1 e 5.2). O serviço de triagem assistida gera sugestões revisáveis para alertas de tráfego suspeito e vulnerabilidades referenciando explicitamente as evidências sanitizadas, mantém continuidade com fallback determinístico quando a IA está indisponível e permite aprovação ou rejeição pelo analista no Console SOC.
- Fase 6 concluída em laboratório e validação de expansão controlada (itens 6.1 e 6.2). As fontes de telemetria suportam pausa, retomada sem perda de posição, atualização de configuração/versão via heartbeat, revogação imediata e recuperação com rotação de credencial preservando histórico e baseline TLS. O Console SOC e a CLI avaliam os 5 marcos operacionais, cobertura, latência e falsos positivos em ambiente próprio (`OWN_ENVIRONMENT`) antes de habilitar clientes autorizados (`AUTHORIZED_CLIENT`) com escopo estrito de CIDRs, capacidades e comprovação `DNS_TXT`/`HTTP_WELL_KNOWN`. Todas as fases 1 a 6 do plano pós-v1.0 estão concluídas.

## Primeiro incremento de SSH

| Componente | Localização e responsabilidade |
| :--- | :--- |
| CLI | [scripts/audit_ssh.py](scripts/audit_ssh.py) consulta a autorização, compara o hostname local e lê as duas diretivas globais com `sshd -T`. Envia apenas o hostname e os estados observados. A opção `--test-alert` aciona o exercício local. |
| Backend | [ssh_audit_routes.py](backend/app/api/v1/ssh_audit_routes.py) expõe autorização, coleta, consulta e exercício. [ssh_audit_service.py](backend/app/services/ssh_audit_service.py) aplica o escopo de laboratório, classifica a evidência e registra as operações na trilha de auditoria. |
| Banco | [0005_ssh_audits.py](backend/alembic/versions/0005_ssh_audits.py) cria o histórico SSH. [0006_ssh_root_policy.py](backend/alembic/versions/0006_ssh_root_policy.py) adiciona a observação sobre root e preserva os registros anteriores. |
| Console | [assets-directory.tsx](frontend/src/components/assets-directory.tsx) mostra o resultado em **Sistemas e Ativos → Ver detalhes**. O exercício aparece em **Automações → Notificações** para o usuário que o iniciou. |

A coleta inicial é Linux, em host explícito na lista do laboratório com autorização vigente `LAB_INTERNAL`. A avaliação cobre as diretivas globais `PasswordAuthentication` e `PermitRootLogin`, sem contextos condicionais `Match`. A política do laboratório considera conforme somente o bloqueio integral de root. A observação é enviada por um analista autenticado e representa o arquivo avaliado localmente pelo OpenSSH.

O exercício publica um evento identificado como sintético na caixa de notificações do próprio analista. O tempo registrado vai da criação do evento até a criação do registro da notificação. Os canais de e-mail e webhooks ficam fora do exercício.

## Validação e ponto de retomada

- OpenSSH real em container Linux, PostgreSQL 17 e Redis em rede Docker isolada. Migrações aplicadas. A API retornou os resultados esperados para senha e root, registrou o erro de coleta e entregou o alerta sintético na caixa do analista. A revogação bloqueou novas coletas e exercícios.
- Backend com 54 testes aprovados, incluindo 5 casos de SSH. Motor de segurança com 49 testes aprovados e infraestrutura com 3 testes aprovados.
- Frontend com 31 testes, checagem de tipos e build aprovados. Os testes de componente verificaram a renderização dos estados de SSH.
- Casos e evidências registrados como TM-025 a TM-027 em [TEST_MATRIX.md](TEST_MATRIX.md).

Roteiro para repetir o teste local:

1. Aplique a migração em uma instância local descartável com `alembic upgrade head` a partir de `backend/` no ambiente Python do projeto.
2. No Console, cadastre um ativo `LAB` com o hostname do container OpenSSH em `LAB_ALLOWED_HOSTS` e verifique uma autorização `LAB_INTERNAL`.
3. No host Linux de laboratório, forneça o token temporário de sessão via `CSC_SSH_SESSION_TOKEN` e execute `python scripts/audit_ssh.py --api-url http://127.0.0.1:8000 --asset-id <id-do-ativo>`. Use o endereço de loopback quando a API estiver acessível no mesmo espaço de rede, ou a origem HTTPS da API.
4. Avalie configurações conhecidas no container, incluindo `PasswordAuthentication no` com `PermitRootLogin no` e uma configuração divergente das duas políticas. Confira **Conforme** e **Divergência de política** em **Sistemas e Ativos → Ver detalhes**.
5. Acrescente `--test-alert` ao comando e confira o tempo informado. Em **Automações → Notificações**, verifique o evento marcado **[Exercício]**.
6. Revogue a autorização e confirme que a API bloqueia a coleta e o exercício. Siga o próximo item em [NEXT_STEPS.md](NEXT_STEPS.md).

## Como retomar em outra IA ou ambiente

1. Leia [AGENTS.md](AGENTS.md), [PROJECT_STATE.md](PROJECT_STATE.md), este arquivo e [NEXT_STEPS.md](NEXT_STEPS.md).
2. Confira o estado do Git e o [TEST_MATRIX.md](TEST_MATRIX.md) antes de retomar. Preserve as alterações que já estiverem no ambiente.
3. Atualize este arquivo e os arquivos de continuidade ao concluir um incremento ou interromper o trabalho. Registre os arquivos relevantes, os testes executados e os pontos pendentes.

## Primeira integração de telemetria de rede

O item 2.1 usa o `conn.log` do Zeek em JSON por linha. O importador lê um arquivo já gerado pelo sensor. A fonte no Console representa uma instalação e um segmento de laboratório cadastrado em CIDR. O Zeek registra tempo, identificador, endereços e portas dos dois lados da conexão, além de protocolo e contagens opcionais de bytes. [Referência do conn.log](https://docs.zeek.org/en/current/reference/logs/conn.html)

- [scripts/import_zeek.py](scripts/import_zeek.py) extrai identificador, horário, IPs, portas, protocolo TCP/UDP/ICMP e contagens de bytes. A API aceita conexões com pelo menos um lado no segmento cadastrado. A política usa metadados e contagens, com retenção de sete dias a partir do recebimento e limpeza horária pelo Celery.
- [network_telemetry_routes.py](backend/app/api/v1/network_telemetry_routes.py) expõe cadastro, consulta, revogação e publicação em lotes. O segredo da instalação é retornado no cadastro. O banco conserva o hash. A chave tem validade padrão de 30 dias e só autoriza importações para a instalação que a recebeu.
- A migração [0007_network_telemetry.py](backend/alembic/versions/0007_network_telemetry.py) cria fontes e conexões. A deduplicação usa instalação e identificador Zeek na janela de retenção. O lote aceita até 200 conexões e 128 KiB. Uma rodada piloto de 1.000 conexões válidas corresponde a cinco lotes.
- [telemetry-sources-panel.tsx](frontend/src/components/telemetry-sources-panel.tsx) mostra segmento cadastrado, estado da credencial, contagem armazenada e horários do último envio e evento.

### Reprodução em laboratório

1. Aplique `alembic upgrade head` em um banco local descartável.
2. Cadastre um ativo de laboratório com hostname em `LAB_ALLOWED_HOSTS` e verifique a autorização `LAB_INTERNAL`.
3. Em **Sistemas e Ativos → Ver detalhes → Telemetria de rede**, cadastre a fonte com o segmento que o sensor observa. Guarde o identificador e a credencial da instalação.
4. Configure `CSC_COLLECTOR_TOKEN` no ambiente local e execute a importação a partir da raiz do repositório. Para HTTP local, a API precisa estar acessível por loopback na máquina do importador. Em outro endereço, use a origem HTTPS da API.

   ```text
   python scripts/import_zeek.py --api-url http://127.0.0.1:8000 --source-id <id-da-fonte> <caminho-do-conn.log>
   ```

5. Reenvie o mesmo arquivo e use **Atualizar fontes** para conferir o total. Revogue a credencial no painel e confirme que a próxima importação falha.

- O Zeek 9.0.1 processou um arquivo PCAP com um fluxo benigno de laboratório, em Docker com rede desativada. A CLI importou o `conn.log` resultante em uma API com PostgreSQL e Redis reais.
- O PostgreSQL confirmou deduplicação em reenvio e em dois envios concorrentes. A limpeza por retenção, a revogação da credencial e a revogação da autorização do ativo foram verificadas.
- Backend com 58 testes aprovados, infraestrutura com 3 e frontend com 33. Build, checagem de tipos e Ruff aprovados. Consulte TM-028 em [TEST_MATRIX.md](TEST_MATRIX.md).

### Piloto desktop

Execute com Python 3.11 ou superior com Tkinter, a partir da raiz do repositório.

```text
python scripts/desktop_collector.py
```

Informe a origem da API, o identificador e a credencial da fonte cadastrada no Console. Selecione o `conn.log` no próprio aplicativo. Os controles iniciam, pausam, retomam e encerram a coleta. O painel desktop apresenta o segmento, o último envio aceito e a diferença entre esse envio e o horário do evento mais recente.

- [desktop_collector.py](scripts/desktop_collector.py) roda a coleta em uma thread e consulta o estado da instalação com a própria credencial. Uma falha temporária da API mantém o lote pendente e aciona nova tentativa. A revogação interrompe a coleta.
- [zeek_file_collector.py](scripts/zeek_file_collector.py) mantém até um lote em memória e grava a posição local após a confirmação da API. O estado local contém a posição e a assinatura do trecho confirmado, sem armazenar a credencial ou o conteúdo do log.
- Com o aplicativo aberto, o coletor drena o arquivo anterior antes de passar para o novo. Caso o arquivo seja arquivado enquanto o aplicativo estiver fechado, use o importador de arquivo para recuperar o arquivo anterior pela mesma fonte.
- O Windows passou em oito testes de pausa, reconexão, reinício, rotação, truncamento e revogação. A janela Tkinter foi instanciada em teste. O núcleo desktop também confirmou um lote e retomou a posição usando a API e o PostgreSQL reais. Consulte TM-029 em [TEST_MATRIX.md](TEST_MATRIX.md).

## Exercício de disponibilidade (Fase 3.1)

O item 3.1 executa um experimento híbrido controlado em laboratório (normal → degradação → recuperação):

| Componente | Localização e responsabilidade |
| :--- | :--- |
| CLI e servidor | [scripts/availability_exercise.py](scripts/availability_exercise.py) expõe `serve` (servidor HTTP local com roteiro determinístico iniciado na primeira requisição) e `probe` (medição real de latência com relógio monotônico contra o hostname do ativo autorizado). |
| Regras puras | [availability_logic.py](backend/app/services/availability_logic.py) define `ExercisePlan`, aplica a janela de N amostras consecutivas acima/abaixo do limiar (contando timeouts e falhas de conexão como violação) e classifica como `PASSED`, `FAILED`, `INCONCLUSIVE` ou `EXECUTION_ERROR`. |
| Serviço e rotas | [availability_routes.py](backend/app/api/v1/availability_routes.py) e [availability_service.py](backend/app/services/availability_service.py) validam autorização `LAB_INTERNAL`, registram amostras sequenciais, disparam notificações in-app de degradação (`HIGH`) e recuperação (`INFO`) e gravam a linha do tempo esperada vs. observada. |
| Banco | [0008_availability_exercises.py](backend/alembic/versions/0008_availability_exercises.py) cria `availability_exercises` e `availability_samples`. |
| Console | [availability-panel.tsx](frontend/src/components/availability-panel.tsx) exibe o painel somente leitura em **Sistemas e Ativos → Ver detalhes → Disponibilidade** comparando eventos esperados, observados e diferenças em segundos. |

### Reprodução em laboratório

1. Aplique as migrações com `alembic upgrade head` a partir de `backend/`.
2. Cadastre um ativo `LAB` com hostname na `LAB_ALLOWED_HOSTS` (por exemplo `127.0.0.1`) e verifique uma autorização `LAB_INTERNAL`.
3. Em um terminal, inicie o servidor sintético:

   ```text
   python scripts/availability_exercise.py serve --host 127.0.0.1 --port 8081 --normal-ms 1500 --degraded-ms 2000 --degraded-delay-ms 400
   ```

4. Em outro terminal, defina `CSC_SESSION_TOKEN` com o token de sessão do analista e execute a sonda:

   ```text
   python scripts/availability_exercise.py probe --api-url http://127.0.0.1:8000 --asset-id <id-do-ativo> --target-url http://127.0.0.1:8081/ --threshold-ms 250 --consecutive-samples 3 --interval-ms 500 --normal-ms 1500 --degraded-ms 2000
   ```

5. Confira `Resultado: PASSED`, a linha do tempo impressa, o painel **Disponibilidade** em **Sistemas e Ativos → Ver detalhes** e os dois alertas marcados **[Exercício]** em **Automações → Notificações**.

- Validado em laboratório contra PostgreSQL 16, Redis 7 e Uvicorn reais: exercício `PASSED`, estado final `RECOVERED`, `DEGRADATION_START` e `RECOVERY_START` em `0 ms` de diferença, `ALERT_OPENED` e `RECOVERY_DETECTED` dentro da tolerância (`-500 ms`) e publicação in-app medida em `10 ms` (alerta) e `11 ms` (recuperação).
- Suítes aprovadas: `security-engine` (49/49), `backend` (66/66, incluindo 8 casos de disponibilidade), infraestrutura `tests/` (3/3), `scripts/tests` (14/14, incluindo 6 casos de `availability_exercise`), `ruff check .` (0 erros) e frontend (`tsc --noEmit`, 36/36 Vitest incluindo 3 casos de `availability-panel` e `npm run build`). Consulte TM-030 em [TEST_MATRIX.md](TEST_MATRIX.md).

## Ampliação de cenários e sinais externos (Fase 3.2)

- **Cenários (`LATENCY`, `ERRORS`, `SATURATION`)**: [availability_logic.py](backend/app/services/availability_logic.py) classifica violações por falha de rede, latência acima do limiar ou HTTP `>= 500` / `429` e agrega `SampleSummary` (`peak_latency_ms`, `error_5xx_count`, `rate_limited_429_count`, `timeout_or_connection_error_count`). O servidor e a sonda em [scripts/availability_exercise.py](scripts/availability_exercise.py) aceitam `--scenario` (`ERRORS` retorna HTTP `503`; `SATURATION` retorna HTTP `429` com `Retry-After: 1` e atraso configurável).
- **Sinais de firewall, CDN ou provedor**: [0009_availability_scenarios_and_signals.py](backend/alembic/versions/0009_availability_scenarios_and_signals.py) (revisão `0009_availability_signals`) adiciona a coluna `scenario` e cria a tabela `availability_signals`. O endpoint `POST /api/v1/assets/{asset_id}/availability-exercises/{exercise_id}/signals` registra sinais tipados (`FIREWALL`, `CDN`, `PROVIDER`) sem exigir presença de fonte externa para aprovar o exercício. Na sonda CLI, `--edge-source` envia os sinais sintéticos de início da degradação e de recuperação.
- **Console SOC**: [availability-panel.tsx](frontend/src/components/availability-panel.tsx) exibe o cenário, o resumo de métricas observadas e os sinais de borda/provedor correlacionados.

### Reprodução do cenário `SATURATION` com fonte `CDN`

```text
python scripts/availability_exercise.py serve --host 127.0.0.1 --port 8081 --normal-ms 1500 --degraded-ms 2000 --degraded-delay-ms 350 --scenario SATURATION
python scripts/availability_exercise.py probe --api-url http://127.0.0.1:8000 --asset-id <id-do-ativo> --target-url http://127.0.0.1:8081/ --threshold-ms 250 --consecutive-samples 3 --interval-ms 500 --normal-ms 1500 --degraded-ms 2000 --scenario SATURATION --edge-source CDN
```

- Validado em laboratório contra PostgreSQL 16, Redis 7 e Uvicorn reais: exercício `SATURATION` + `CDN` `PASSED`, `rate_limited_429_count=4`, `peak_latency_ms=366.3 ms`, sinais `RATE_LIMITED` (`1500 ms`, HTTP `429`) e `RECOVERED` (`4500 ms`, HTTP `200`), publicação in-app em `22 ms` (alerta) e `17 ms` (recuperação).
- Suítes aprovadas: `security-engine` (49/49), `backend` (69/69, incluindo 11 casos em [test_availability.py](backend/tests/test_availability.py)), infraestrutura `tests/` (3/3), `scripts/tests` (16/16, incluindo 8 casos em [test_availability_exercise.py](scripts/tests/test_availability_exercise.py)), `ruff check .` (0 erros) e frontend (`tsc --noEmit`, 37/37 Vitest incluindo 4 casos em [availability-panel.test.tsx](frontend/src/__tests__/availability-panel.test.tsx) e `npm run build`). Consulte TM-031 em [TEST_MATRIX.md](TEST_MATRIX.md).

## Detecção explicável de tráfego suspeito (Fase 4.1)

| Componente | Localização e responsabilidade |
| :--- | :--- |
| Regras puras | [suspicious_traffic_logic.py](backend/app/services/suspicious_traffic_logic.py) avalia varredura de portas (`>= 5` portas), rajada repetitiva (`>= 10` conexões), rajada `NXDOMAIN` (`>= 4`), subdomínio de alta entropia (`>= 24` chars e entropia `>= 3.8` bits/char) e identidade TLS distinguindo `BASELINE_ESTABLISHED`, `UNCHANGED`, `BENIGN_ROTATION` (mesma CA org, status `ok`, vigência não regressiva, sem alerta) e `TLS_POSSIBLE_INTERCEPTION`. |
| Contratos e serviço | [suspicious_traffic.py](backend/app/schemas/suspicious_traffic.py), [suspicious_traffic.py](backend/app/repositories/suspicious_traffic.py) e [suspicious_traffic_service.py](backend/app/services/suspicious_traffic_service.py) validam CIDR da fonte e autorização `LAB_INTERNAL`, atualizam `TelemetryTlsBaseline`, deduplicam conexões e sanitizam evidências via `EvidenceManager.sanitize_text_snippet`. |
| Rotas e banco | [suspicious_traffic_routes.py](backend/app/api/v1/suspicious_traffic_routes.py) expõe `POST /api/v1/telemetry/sources/{source_id}/traffic-analyses` (token do coletor, limite 256 KiB) e `GET /api/v1/assets/{asset_id}/traffic-analyses` (sessão do analista). [0010_suspicious_traffic.py](backend/alembic/versions/0010_suspicious_traffic.py) cria `telemetry_tls_baselines`, `traffic_analysis_runs`, `suspicious_traffic_alerts` e `traffic_tls_decisions`. |
| CLI | [scripts/analyze_traffic.py](scripts/analyze_traffic.py) lê arquivos JSONL do Zeek (`--conn-log`, `--dns-log`, `--ssl-log`) autenticando com `CSC_COLLECTOR_TOKEN` e imprime cobertura por camada, decisões TLS e alertas com explicação e evidência. |

### Reprodução em laboratório

```text
python scripts/analyze_traffic.py --api-url http://127.0.0.1:8000 --source-id <id-da-fonte> --conn-log conn.log --dns-log dns.log --ssl-log ssl.log
```

- Validado contra PostgreSQL 16 (migração `0010_suspicious_traffic` com ciclo upgrade → downgrade → upgrade), Redis 7 e Uvicorn reais em três rodadas consecutivas via `scripts/analyze_traffic.py`: Rodada 1 (`BASELINE_ESTABLISHED`, cobertura `TLS`, 0 alertas), Rodada 2 (`BENIGN_ROTATION` pela mesma CA `Let's Encrypt`, 0 alertas) e Rodada 3 (cobertura completa `CONNECTIONS, DNS, TLS`, `CONNECTION_PORT_SWEEP` 8 portas `HIGH`, `DNS_NXDOMAIN_BURST` 5 `NXDOMAIN` `MEDIUM`, `DNS_HIGH_ENTROPY_QUERY` 4.47 bits `HIGH` e `TLS_POSSIBLE_INTERCEPTION` autoassinado `HIGH` preservando o baseline confiável).
- Suítes aprovadas: `security-engine` (49/49), `backend` (74/74, incluindo 5 casos em [test_suspicious_traffic.py](backend/tests/test_suspicious_traffic.py)), infraestrutura `tests/` (3/3), `scripts/tests` (19/19, incluindo 3 casos em [test_analyze_traffic.py](scripts/tests/test_analyze_traffic.py)) e `ruff check .` (0 erros). Consulte TM-032 em [TEST_MATRIX.md](TEST_MATRIX.md).

## Correlação AV/EDR e Painel no Console SOC (Fase 4.2)

- **Correlação opcional por host**: [suspicious_traffic_logic.py](backend/app/services/suspicious_traffic_logic.py) amplia `CORE_LAYERS` para `("CONNECTIONS", "DNS", "TLS", "EDR")` e correlaciona sinais de endpoint (`ANTIVIRUS`, `EDR`) com alertas de rede, DNS ou TLS no mesmo `host_ip`, elevando confiança e severidade para `HIGH`, anexando `correlated_edr_signals` à evidência e adicionando `EDR` à cobertura observada sem exigir a presença de EDR para aprovar análises.
- **Migração, API e CLI**: [0011_traffic_edr_signals.py](backend/alembic/versions/0011_traffic_edr_signals.py) adiciona `edr_count` e cria `traffic_edr_signals`. [suspicious_traffic_service.py](backend/app/services/suspicious_traffic_service.py) valida o CIDR de `host_ip` e sanitiza textos com `EvidenceManager.sanitize_text_snippet`. A CLI [scripts/analyze_traffic.py](scripts/analyze_traffic.py) aceita `--edr-log <arquivo.jsonl>`.
- **Console SOC**: [suspicious-traffic-panel.tsx](frontend/src/components/suspicious-traffic-panel.tsx), integrado em [assets-directory.tsx](frontend/src/components/assets-directory.tsx), exibe em **Sistemas e Ativos → Ver detalhes** (para ativos `LAB`) cobertura observada/ausente, rotações legítimas vs. alertas de interceptação TLS, sinais AV/EDR e alertas com explicação, confiança e evidência.

### Reprodução com `--edr-log`

```text
python scripts/analyze_traffic.py --api-url http://127.0.0.1:8000 --source-id <id-da-fonte> --conn-log conn.log --dns-log dns.log --ssl-log ssl.log --edr-log edr.log
```

- Validado contra PostgreSQL 16 (migração `0011_traffic_edr_signals` em ciclo upgrade → downgrade → upgrade), Redis 7 e Uvicorn reais: cobertura `CONNECTIONS, DNS, TLS, EDR`, sinal `EDR:BEACONING_DETECTED` (`python3`), elevação automática para `HIGH` nos dois alertas do mesmo `host_ip` e persistência consultada em `GET /api/v1/assets/{asset_id}/traffic-analyses`.
- Suítes aprovadas: `security-engine` (49/49), `backend` (75/75, incluindo 6 casos em [test_suspicious_traffic.py](backend/tests/test_suspicious_traffic.py)), infraestrutura `tests/` (3/3), `scripts/tests` (19/19, incluindo [test_analyze_traffic.py](scripts/tests/test_analyze_traffic.py)), `ruff check .` (0 erros) e frontend (`tsc --noEmit`, 40/40 Vitest em 8 arquivos incluindo [suspicious-traffic-panel.test.tsx](frontend/src/__tests__/suspicious-traffic-panel.test.tsx) e `npm run build`). Consulte TM-033 em [TEST_MATRIX.md](TEST_MATRIX.md).

## Triagem assistida por IA e fallback resiliente (Fase 5.1)

| Componente | Localização e responsabilidade |
| :--- | :--- |
| Regras e validação | [ai_triage_logic.py](backend/app/services/ai_triage_logic.py) sanitiza evidências via `EvidenceManager.sanitize_text_snippet`, extrai `EvidenceCitation`, valida se respostas do provedor citam chaves/valores reais (`validate_grounded_draft`) e sintetiza sugestões determinísticas citadas (`build_deterministic_suggestion`). |
| Banco | [0012_ai_triage_suggestions.py](backend/alembic/versions/0012_ai_triage_suggestions.py) cria `ai_triage_suggestions` vinculada a `suspicious_traffic_alerts` ou `findings`, mantendo `review_status="PENDING_REVIEW"`. |
| Serviço e rotas | [ai_triage_service.py](backend/app/services/ai_triage_service.py) e [ai_triage_routes.py](backend/app/api/v1/ai_triage_routes.py) expõem geração (`SECURITY_ANALYST`+) e consulta (`VIEWER`+) para alertas de tráfego e vulnerabilidades, além de auditoria `AI_TRIAGE_SUGGESTION_GENERATED`. |

- Validado contra PostgreSQL 16 (migração `0012_ai_triage_suggestions` em ciclo upgrade → downgrade → upgrade), Redis 7 e Uvicorn reais: geração com provedor local de IA (`AI_PROVIDER`, `AVAILABLE`) e degradação graciosa para `DETERMINISTIC_FALLBACK` (`UNAVAILABLE`) com citação explícita da evidência após desligamento do provedor.
- Suítes aprovadas: `security-engine` (49/49), `backend` (79/79, incluindo 4 casos em [test_ai_triage.py](backend/tests/test_ai_triage.py)), infraestrutura `tests/` (3/3), `scripts/tests` (19/19) e `ruff check .` (0 erros). Consulte TM-034 em [TEST_MATRIX.md](TEST_MATRIX.md).

## Revisão e decisão humana no Console SOC (Fase 5.2)

- **Revisão humana na API**: `PATCH /api/v1/triage-suggestions/{suggestion_id}/review` ([ai_triage_routes.py](backend/app/api/v1/ai_triage_routes.py) e [ai_triage_service.py](backend/app/services/ai_triage_service.py)) valida papel `SECURITY_ANALYST`+ na organização, sanitiza `reviewer_notes` via `EvidenceManager.sanitize_text_snippet`, grava `review_status` (`APPROVED` / `REJECTED`), `reviewer_user_id` e `reviewed_at`, e registra `AI_TRIAGE_SUGGESTION_REVIEWED` em `AuditLog`.
- **Console SOC**: [ai-triage-card.tsx](frontend/src/components/ai-triage-card.tsx) integrado aos alertas de [suspicious-traffic-panel.tsx](frontend/src/components/suspicious-traffic-panel.tsx) e ao detalhe de vulnerabilidades em [vulnerabilities-panel.tsx](frontend/src/components/vulnerabilities-panel.tsx) permite gerar sugestões sob demanda, visualizar modo/fallback, resumo, explicação, citações verificadas e passos sugeridos, além de aprovar ou rejeitar com nota opcional do analista.
- **Suítes aprovadas**: `security-engine` (49/49), `backend` (80/80, incluindo 5 casos em [test_ai_triage.py](backend/tests/test_ai_triage.py)), infraestrutura `tests/` (3/3), `scripts/tests` (19/19), `ruff check .` (0 erros) e frontend (`tsc --noEmit`, 42/42 Vitest em 9 arquivos incluindo [ai-triage-card.test.tsx](frontend/src/__tests__/ai-triage-card.test.tsx) e `npm run build`). Consulte TM-035 em [TEST_MATRIX.md](TEST_MATRIX.md).

## Piloto operacional e expansão controlada (Fase 6)

| Componente | Localização e responsabilidade |
| :--- | :--- |
| Regras puras | [pilot_logic.py](backend/app/services/pilot_logic.py) valida CIDRs dentro de escopo (`cidr_within_allowed`), deriva estado efetivo e consolida prontidão (`evaluate_pilot_readiness`) em 5 marcos operacionais, cobertura por camada, latência real e indicadores de falsos positivos. |
| Ciclo da fonte e guarda | [network_telemetry.py](backend/app/services/network_telemetry.py), [network_telemetry_routes.py](backend/app/api/v1/network_telemetry_routes.py) e [lab_authorization.py](backend/app/services/lab_authorization.py) expõem pausa (`HTTP 409` para ingestão), retomada, atualização (`PATCH` com `config_version`/`desired_version`), recuperação (`/recover` mantendo histórico e baseline TLS) e `POST /api/v1/telemetry/sources/{source_id}/heartbeat`, além de aplicar `require_authorized_operational_asset` por capacidade. |
| Governança e banco | [pilot.py](backend/app/schemas/pilot.py), [pilot.py](backend/app/repositories/pilot.py), [pilot_service.py](backend/app/services/pilot_service.py), [pilot_routes.py](backend/app/api/v1/pilot_routes.py) e [0013_pilot_rollout.py](backend/alembic/versions/0013_pilot_rollout.py) gerenciam `pilot_enrollments` e `pilot_reviews`, bloqueando `APPROVED_FOR_EXPANSION` com pendências (`422`) e exigindo pré-requisito aprovado, perfil `ADMIN`, autorização `DNS_TXT`/`HTTP_WELL_KNOWN` e limites estritos para `AUTHORIZED_CLIENT`. |
| Coletor e CLI | [import_zeek.py](scripts/import_zeek.py), [desktop_collector.py](scripts/desktop_collector.py) e [pilot_lifecycle.py](scripts/pilot_lifecycle.py) aplicam configuração/intervalo dinâmicos via heartbeat, aguardam pausas remotas (`PAUSED`/`409`) sem avançar o checkpoint local e exibem o relatório completo de prontidão no terminal. |
| Console SOC | [telemetry-sources-panel.tsx](frontend/src/components/telemetry-sources-panel.tsx), [pilot-rollout-panel.tsx](frontend/src/components/pilot-rollout-panel.tsx), [assets-directory.tsx](frontend/src/components/assets-directory.tsx) e [soc-console.tsx](frontend/src/components/soc-console.tsx) expõem pausa/retomada/atualização/recuperação das fontes e a nova aba **Piloto & Expansão**. |

### Reprodução em laboratório e cliente autorizado

```text
python scripts/pilot_lifecycle.py heartbeat --api-url http://127.0.0.1:8000 --source-id <id-da-fonte>
python scripts/pilot_lifecycle.py readiness --api-url http://127.0.0.1:8000 --pilot-id <id-do-piloto>
```

- Validado de ponta a ponta contra PostgreSQL 16 (migração `0013_pilot_rollout` com ciclo `upgrade -> downgrade -> upgrade`), Redis 7, Uvicorn e servidor HTTP local (`HTTP_WELL_KNOWN`): piloto `OWN_ENVIRONMENT` concluído com 5 marcos `[OK]`, cobertura `100.0%` (`CONNECTIONS, DNS, TLS, EDR`), `analyze_traffic.py`, `availability_exercise.py SATURATION+CDN PASSED`, ciclo completo `pause -> 409 -> resume -> patch + heartbeat -> revoke -> 401 -> recover` preservando checkpoint (`1` nova conexão, `0` duplicatas) e baseline TLS, aprovação `APPROVED_FOR_EXPANSION` e habilitação em 2ª organização `AUTHORIZED_CLIENT` validando CIDR estrito (`422` fora / `201` dentro) e bloqueio imediato (`403`) após revogação.
- **Suítes aprovadas**: `security-engine` (49/49), `backend` (84/84, incluindo 4 suítes em [test_pilot_rollout.py](backend/tests/test_pilot_rollout.py)), infraestrutura `tests/` (3/3), `scripts/tests` (23/23, incluindo [test_pilot_lifecycle.py](scripts/tests/test_pilot_lifecycle.py) e [test_desktop_collector.py](scripts/tests/test_desktop_collector.py)), `ruff check .` (0 erros) e frontend (`tsc --noEmit`, 45/45 Vitest em 10 arquivos incluindo [pilot-rollout-panel.test.tsx](frontend/src/__tests__/pilot-rollout-panel.test.tsx) e [telemetry-sources.test.tsx](frontend/src/__tests__/telemetry-sources.test.tsx), e `npm run build`). Consulte TM-036 e TM-037 em [TEST_MATRIX.md](TEST_MATRIX.md).

## Edição segura de URL/domínio de ativos

- **Backend**: `AssetUpdateRequest` em [auth_assets.py](backend/app/schemas/auth_assets.py) passou a aceitar `target_url` opcional. `AssetAuthorizationService.update_asset` em [asset_service.py](backend/app/services/asset_service.py) valida e normaliza a URL via `_extract_and_validate_target` (bloqueando esquemas inválidos, credenciais na URL e alvos Anti-SSRF com HTTP `422`), bloqueia alteração de origem/hostname quando há auditoria ativa (`PENDING`, `QUEUED` ou `RUNNING`) retornando HTTP `409`, redefine `authorization_status` para `PENDING` revogando autorizações `PENDING`/`VERIFIED` quando a origem/hostname muda (mantendo `VERIFIED` apenas em alteração de path), revoga autorizações `LAB_INTERNAL` quando o ambiente passa para `PRODUCTION`/`STAGING` e registra a mudança e `authorization_reset` em `AuditLog`.
- **Console SOC**: [api.ts](frontend/src/lib/api.ts) e [assets-directory.tsx](frontend/src/components/assets-directory.tsx) passam a expor o campo **URL ou domínio do ativo** no formulário **Ver detalhes → Editar ativo / domínio** com validação client-side e aviso explícito de redefinição para `PENDING`; [soc-console.tsx](frontend/src/components/soc-console.tsx) exibe `assetFeedback` inline dentro do card **Comprovação de Autorização do Alvo**.
- **Suítes aprovadas**: `backend` `85/85` (incluindo `3/3` em [test_assets_and_authorizations.py](backend/tests/test_assets_and_authorizations.py)), `ruff check .` (0 erros) e `frontend` (`tsc --noEmit`, `47/47` Vitest em 11 arquivos incluindo `2/2` em [assets-edit.test.tsx](frontend/src/__tests__/assets-edit.test.tsx), e `npm run build`). Consulte `TM-012` em [TEST_MATRIX.md](TEST_MATRIX.md).

## Segurança & Ferramentas SOC (7 utilitários defensivos integrados)

- **Backend**: [security_tools.py](backend/app/schemas/security_tools.py), [security_tools_logic.py](backend/app/services/security_tools_logic.py), [security_tools_service.py](backend/app/services/security_tools_service.py) e [security_tools_routes.py](backend/app/api/v1/security_tools_routes.py) (registrado em [main.py](backend/app/main.py)) entregam 8 endpoints defensivos sob `/api/v1/security-tools/*`: **Pentest Assistant** (roteiro OWASP WSTG correlacionado a checks `CHK-*` e achados reais do ativo com bloqueio em `PRODUCTION` e isolamento multi-tenant), **Password Tools** (gerador CSPRNG `secrets`/passphrase e analisador de entropia/NIST/OWASP sem jamais persistir ou auditar senhas), **Forensics** (hashes, extração/defang de IOCs, timeline de logs, inspeção passiva de JWT e detecção de vazamento de segredos), **Firewall Tester** (parser `iptables`/`ufw`/genérico, detecção de portas críticas expostas, regras sombreadas, Default-Deny e simulador de pacotes), **Malware Analysis** (inspeção estática sem execução, decodificação segura Base64/Hex/PowerShell `-EncodedCommand` e heurísticas MITRE ATT&CK), **WiFi Auditor** (auditoria passiva `netsh` PT-BR/EN e `nmcli` para OPEN/WEP/TKIP/WPS/Evil Twin) e **DDoS Analyzer** (análise de picos RPS, concentração por IP, saturação 429/5xx, L7 Cache-Busting, postura + contexto Módulo F e snippets Nginx/Cloudflare/sysctl).
- **Console SOC**: [api.ts](frontend/src/lib/api.ts), [security-tools-panel.tsx](frontend/src/components/security-tools-panel.tsx) e aba **Segurança & Ferramentas** em [soc-console.tsx](frontend/src/components/soc-console.tsx).
- **Suítes aprovadas**: `security-engine` `49/49`, `backend` `92/92` (incluindo `7/7` em [test_security_tools.py](backend/tests/test_security_tools.py)), `ruff check .` (0 erros) e `frontend` (`tsc --noEmit`, `51/51` Vitest em 12 arquivos incluindo `4/4` em [security-tools-panel.test.tsx](frontend/src/__tests__/security-tools-panel.test.tsx), e `npm run build`). Consulte `TM-038` em [TEST_MATRIX.md](TEST_MATRIX.md).

## Persistência segura da sessão no recarregamento (F5)

- **Causa e correção**: O estado `authSession` em [soc-console.tsx](frontend/src/components/soc-console.tsx) existia apenas em memória React, sem restauração no mount, e o proxy [route.ts](frontend/src/app/api/v1/%5B...path%5D/route.ts) não encaminhava cabeçalhos `Set-Cookie` explicitamente via `getSetCookie()`. Agora o proxy preserva todos os `Set-Cookie`, `GET /api/v1/auth/me` em [auth_assets_routes.py](backend/app/api/v1/auth_assets_routes.py) renova o cookie `HttpOnly` e [api.ts](frontend/src/lib/api.ts) expõe `fetchCurrentSession()`, chamado no carregamento do `SocConsole` sem gravar tokens em `localStorage`/`sessionStorage`.
- **Suítes aprovadas**: `backend` `92/92` (incluindo restauração por cookie em [test_auth_rbac_isolation.py](backend/tests/test_auth_rbac_isolation.py)), `ruff check .` (0 erros), `tsc --noEmit`, `vitest run` (`12` arquivos / `52` testes, incluindo [dashboard.test.tsx](frontend/src/__tests__/dashboard.test.tsx)) e `npm run build`.

## WiFi Auditor com captura real da placa sem fio

- **Backend e sensor loopback**: [security_tools_routes.py](backend/app/api/v1/security_tools_routes.py) e [security_tools_service.py](backend/app/services/security_tools_service.py) expõem `POST /api/v1/security-tools/wifi/scan-local` (`netsh` no Windows / `nmcli` no Linux, retornando fallback `CONTAINER_NO_WIFI_RADIO` em container), enquanto [wifi_local_sensor.py](scripts/wifi_local_sensor.py) executa no host em `http://127.0.0.1:8765` com `WlanScan` (`wlanapi.dll`) + `netsh` (`wlan show networks mode=bssid` e `wlan show interfaces`) e CORS restrito às origens locais. [security_tools_logic.py](backend/app/services/security_tools_logic.py) agora identifica `"Abrir"`, banda (`2.4 GHz`/`5 GHz`/`6 GHz`), `Tipo de rádio`, SSID oculto sem duplicatas e interface conectada.
- **Console SOC e Docker**: [api.ts](frontend/src/lib/api.ts) e [security-tools-panel.tsx](frontend/src/components/security-tools-panel.tsx) adicionam **Escanear Wi-Fi Real Agora**, **Auto-atualizar (15s)**, cartão **Conexão Wi-Fi Ativa** e barra de sinal/banda na tabela; containers `csc-backend` e `csc-frontend` reconstruídos e validados ponta a ponta contra o adaptador Wi-Fi real do Windows (`18` BSSIDs reais auditados).
- **Suítes aprovadas**: `backend` `93/93` (`8/8` em [test_security_tools.py](backend/tests/test_security_tools.py)), `ruff check . ..\scripts\wifi_local_sensor.py` (`0` erros), `tsc --noEmit`, `vitest run` (`12` arquivos / `53` testes, `5/5` em [security-tools-panel.test.tsx](frontend/src/__tests__/security-tools-panel.test.tsx)) e `npm run build`. Consulte `TM-039` em [TEST_MATRIX.md](TEST_MATRIX.md).
