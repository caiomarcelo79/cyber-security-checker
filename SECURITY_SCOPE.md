# SECURITY_SCOPE.md — Políticas de Escopo, Autorização e Limites Operacionais

Este documento estabelece os controles obrigatórios de segurança, comprovação de autorização, prevenção contra uso abusivo (SSRF, DoS, varredura não autorizada) e limites operacionais do `cyber-security-checker`.

---

## 1. Princípio da Autorização Comprovada

Nenhuma auditoria pode ser executada sem que o alvo (`Asset`) esteja vinculado a uma organização e possua um registro válido de autorização (`TargetAuthorization`) com status `VERIFIED` (ou `LAB_LOCAL` exclusivamente em ambiente de laboratório isolado).

### 1.1 Métodos de Comprovação Suportados
1. **Desafio DNS TXT (`DNS_TXT`)**:
   - O sistema gera um token criptográfico único por ativo/organização: `cyber-sec-checker-verify=<token_hmac_sha256>`.
   - O proprietário publica um registro TXT em `_cybersecuritychecker.<dominio>` ou na raiz do domínio.
   - O validador consulta o DNS e confirma a correspondência exata dentro da janela de validade.
2. **Desafio Arquivo HTTP Well-Known (`HTTP_WELL_KNOWN`)**:
   - O proprietário disponibiliza o arquivo `/.well-known/cyber-security-checker.txt` no host autorizado contendo o token de verificação e o identificador da organização.
   - O validador realiza uma requisição HTTP/HTTPS controlada (`GET`, timeout 5s, sem seguir redirecionamentos para fora do host) e valida o conteúdo.
3. **Alvo de Laboratório Isolado (`LAB_INTERNAL`)**:
   - Exclusivo para containers e serviços internos de teste (ex.: `http://lab-target:8080`), habilitado somente quando a política de ambiente `ALLOW_LOCAL_LAB_TARGETS=true` estiver ativa e o host pertencer à whitelist de laboratório (`LAB_ALLOWED_HOSTS`).

### 1.2 Regras de Escopo Estrito
- **Não Herança Automática de Subdomínios**: A autorização para `app.exemplo.com.br` **não** autoriza varreduras em `api.exemplo.com.br` ou `*.exemplo.com.br`, a menos que o escopo wildcard seja explicitamente comprovado via DNS TXT no domínio raiz e registrado na política de autorização.
- **Expiração de Autorização**: Toda autorização possui data de expiração (`expires_at`). Auditorias agendadas ou manuais revalidam o status da autorização antes do início da execução.
- **Lista de Exclusão (`excluded_paths`)**: Cada ativo e perfil de auditoria pode definir caminhos excluídos (ex.: `/logout`, `/admin/delete`, `/billing/charge`) que o orquestrador e os módulos nunca devem requisitar.

---

## 2. Prevenção de SSRF e Revalidação de Destino (DNS Pinning / Anti-Rebinding)

Para impedir que o `cyber-security-checker` seja utilizado como vetor de *Server-Side Request Forgery (SSRF)* ou *DNS Rebinding*:

1. **Bloqueio de Redes Internas e Reservadas**:
   Por padrão (`BLOCK_PRIVATE_NETWORKS=true`), qualquer resolução de nome para os seguintes blocos IPv4/IPv6 é imediatamente abortada pelo `ScopePolicyValidator`:
   - `127.0.0.0/8`, `::1/128` (Loopback)
   - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7` (Redes Privadas RFC 1918 / ULA)
   - `169.254.0.0/16`, `fe80::/10` (Link-Local e Cloud Metadata Services como `169.254.169.254`)
   - `100.64.0.0/10` (CGNAT)
   - `0.0.0.0/8`, `224.0.0.0/4`, `240.0.0.0/4` (Multicast / Reservados)
2. **Inspeção de Redirecionamentos Passo a Passo**:
   - O cliente HTTP do `security-engine` não segue redirecionamentos cegamente. Cada salto `301/302/303/307/308` tem sua URL de destino validada contra o `ScopePolicyValidator`.
   - Se um redirecionamento apontar para fora do escopo autorizado ou para um IP privado bloqueado, o redirecionamento é interrompido e registrado nas evidências sem efetuar a requisição ao destino externo.
3. **Revalidação Durante a Execução**:
   - Antes de cada módulo iniciar suas requisições, o endereço IP resolvido é verificado novamente para mitigar ataques de *DNS Rebinding*.

---

## 3. Classificação de Impacto das Verificações

| Nível de Impacto | Descrição | Exemplos de Módulos | Ambiente Permitido |
| :--- | :--- | :--- | :--- |
| **Passivo (`PASSIVE`)** | Analisa apenas respostas de requisições normais, certificados TLS, cabeçalhos HTTP, cookies e DNS. | Módulo A (Headers, TLS, DNS), Módulo E (Cookies passivo) | Produção, Homologação, Laboratório |
| **Ativo de Baixo Impacto (`LOW_IMPACT_ACTIVE`)** | Envia número reduzido e controlado de requisições com marcadores inofensivos (`canary strings`), verificação de métodos HTTP (`OPTIONS`/`HEAD`) e validação de CORS. | Módulo B (Configuração de Login), Módulo C (Reflexão segura com marcador alfanumérico), Módulo F (Inspeção de cabeçalhos de Rate Limit), Módulo G (API Schema/CORS) | Produção (com limites conservadores), Homologação, Laboratório |
| **Avaliação Profunda Controlada (`CONTROLLED_ASSESSMENT`)** | Testes autenticados multi-identidade (IDOR/BOLA com contas de teste), verificação não destrutiva de erros de sintaxe/parametrização. | Módulo D (Indicadores seguros de SQLi), Módulo G (Autorização com identidades de teste), Módulo H | Homologação, Laboratório (Bloqueado em Produção por padrão) |

---

## 4. Limites Operacionais Obrigatórios (Hard Guardrails)

Nenhum usuário pode desativar os seguintes limites de segurança operacional impostos pelo `ScanExecutionPolicy`:

| Parâmetro | Limite Padrão (Quick/Standard) | Teto Máximo Permitido (Hard Cap) | Comportamento ao Atingir |
| :--- | :--- | :--- | :--- |
| `max_requests_per_second` | 5 req/s | 20 req/s | *Throttling* automático no cliente HTTP |
| `max_concurrency` | 3 conexões simultâneas | 10 conexões simultâneas | Semáforo assíncrono (`asyncio.Semaphore`) |
| `request_timeout_seconds` | 10 segundos | 30 segundos | Cancela requisição e registra `EXECUTION_ERROR` |
| `scan_global_timeout_seconds` | 600 segundos (10 min) | 3600 segundos (60 min) | Encerra execução com status `TIMED_OUT` |
| `max_redirects` | 5 saltos | 10 saltos | Interrompe cadeia de redirecionamento |
| `max_response_body_bytes` | 2 MB (`2_097_152` bytes) | 10 MB (`10_485_760` bytes) | Trunca leitura da stream para proteger memória |
| `max_crawl_depth` | 2 níveis | 5 níveis | Ignora links além da profundidade máxima |
| `circuit_breaker_threshold` | 5 respostas consecutivas `429`/`503`/`504` ou timeouts | 10 falhas consecutivas | Pausa/aborta scan (`ABORTED_TARGET_DEGRADED`) para proteger o alvo |

---

## 5. Proteção de Evidências e Dados Sensíveis

O `EvidenceManager` aplica sanitização automática antes de gravar qualquer evidência no PostgreSQL:
- Cabeçalhos `Authorization`, `Proxy-Authorization`, `X-API-Key` e `Cookie` têm seus valores sensíveis mascarados (ex.: `Bearer eyJhbGci...[REDACTED]`), preservando apenas metadados necessários para análise (como flags `HttpOnly`, `Secure`, `SameSite`, tamanho e prefixo).
- Senhas de contas de teste nunca são exibidas em logs, evidências ou relatórios exportados.
- Limite máximo de tamanho por trecho de evidência textual (4 KB por snippet HTTP) para evitar poluição do banco e vazamento acidental de payloads extensos.
