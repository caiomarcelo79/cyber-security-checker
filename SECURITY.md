# Política de Segurança e Limites Éticos (`SECURITY.md`)

O **Cyber-Security-Checker** é uma plataforma defensiva projetada exclusivamente para identificação de falhas de segurança e gestão de vulnerabilidades em aplicações web e APIs sob responsabilidade autorizada e legal dos seus operadores.

---

## 1. Princípios Éticos e Legais Invioláveis

1. **Autorização Comprovada Obrigatória**:
   - Nenhum módulo de auditoria executa contra alvos sem comprovação prévia de propriedade (`TargetAuthorization`) através dos métodos determinísticos:
     - Registro DNS TXT (`_csc-challenge.<host>`)
     - Arquivo HTTP em caminho seguro (`/.well-known/csc-challenge/<token>`)
     - Modo de Laboratório Controlado (`LAB_INTERNAL` restrito a hosts autorizados em `LAB_ALLOWED_HOSTS`).
2. **Proteção Anti-SSRF e Restrição de Redes**:
   - O validador de escopo (`ScopePolicyValidator`) é executado antes e durante toda requisição do motor de segurança, inspecionando redirecionamentos e resolução DNS:
     - Endereços de loopback (`127.0.0.0/8`, `::1`) são bloqueados por padrão.
     - Redes privadas RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) são bloqueadas por padrão.
     - Endereços de metadados de nuvem pública (`169.254.169.254`) são bloqueados incondicionalmente, mesmo em modo de laboratório.
3. **Proibição Estrita de Ataques Destrutivos**:
   - O motor de segurança **jamais** executa ataques de negação de serviço (DoS/DDoS floods), exaustão de recursos, força bruta cega em credenciais, extração em massa de dados via SQLi ou injeção de comandos destrutivos.
   - Toda verificação visa confirmar a presença ou ausência de controles defensivos e sanitizações sem corromper ou comprometer a integridade dos dados do alvo.

---

## 2. Sanitização de Evidências Sensíveis (`EvidenceManager`)

A persistência de evidências de vulnerabilidades obedece aos mais rigorosos critérios de proteção de dados:

- Credenciais de login, senhas e chaves de API são automaticamente mascaradas (`[REDACTED]`).
- Cabeçalhos HTTP sensíveis (`Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`) têm seus valores sensíveis ofuscados antes de serem gravados no banco de dados relacional ou exibidos em relatórios.
- Células exportadas para relatórios CSV passam por sanitização estrita para prevenir injeção de fórmulas (*CSV Formula Injection* / CWE-1236).

---

## 3. Gestão de Sessões e Autenticação Defensiva

- **Revogação Imediata no Logout**: Tokens JWT são invalidados no servidor através da tabela de controle `revoked_tokens`, impedindo reutilização após encerramento da sessão.
- **Proteção Anti-Brute Force**: O sistema impõe rate limiting deslizante baseado em logs imutáveis (máximo de 8 tentativas consecutivas por e-mail e 20 tentativas por IP em janela de 15 minutos).
- **Proteção Contra Timing Attacks**: Tentativas de login para usuários inexistentes executam derivação de hash de senha fictícia com mesmo custo computacional para neutralizar enumeração de contas por tempo de resposta.
- **Proteção Anti-CSRF**: Requisições de mutação de dados que utilizam cookies de autenticação têm a origem inspecionada contra a lista estrita de domínios confiáveis.

---

## 4. Reporte de Vulnerabilidades no Próprio Software

Caso identifique qualquer vulnerabilidade de segurança na própria plataforma **Cyber-Security-Checker**:

1. Envie uma descrição detalhada para: `security@cybersecuritychecker.local`.
2. Inclua passos reproduzíveis, versão da plataforma e impacto potencial.
3. Não divulgue a vulnerabilidade publicamente antes que nossa equipe técnica analise e disponibilize uma correção (*Responsible Disclosure*).
4. Comprometemo-nos a acusar o recebimento em até 48 horas úteis e disponibilizar um plano de remediação transparente.
