# Progresso e retomada do desenvolvimento

Atualizado em 2026-11-20.

## Trabalho atual

- Fase 1 do plano pós-v1.0 concluída em laboratório. A CLI coleta a política de senha e de acesso de root, e o exercício de alerta usa a caixa de notificações do Console SOC.
- Fase 2 concluída em laboratório. O piloto desktop lê o `conn.log` do Zeek e retoma a partir do último lote confirmado. Consulte [NEXT_STEPS.md](NEXT_STEPS.md) para iniciar a Fase 3 e [ROADMAP.md](ROADMAP.md) para as fases futuras.

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
