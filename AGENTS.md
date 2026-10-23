# AGENTS.md — Diretrizes Permanentes para Agentes de IA (`cyber-security-checker`)

Este documento define as regras obrigatórias, princípios arquiteturais, restrições de segurança e protocolos operacionais para qualquer agente de inteligência artificial que atue no repositório `cyber-security-checker`.

---

## 1. Protocolo de Continuidade e Memória Persistente

Antes de iniciar qualquer implementação ou decisão arquitetural relevante:

1. **Leitura Obrigatória de Contexto**:
   - Leia `PROJECT_STATE.md` para compreender o estado real do sistema, serviços ativos, portas configuradas e limitações atuais.
   - Leia `NEXT_STEPS.md` e `ROADMAP.md` para identificar a fase atual, tarefas desbloqueadas e critérios objetivos de aceite.
   - Consulte `ARCHITECTURE.md`, `DECISIONS.md` e `SECURITY_SCOPE.md` antes de criar novos módulos, contratos ou alterar fluxos de segurança.
2. **Atualização Pós-Entrega**:
   - Ao concluir cada etapa verificável, atualize `PROJECT_STATE.md`, `NEXT_STEPS.md`, `ROADMAP.md` e `TEST_MATRIX.md`.
   - Registre decisões estruturais relevantes em `DECISIONS.md` sob o formato ADR (Architecture Decision Record).
3. **Proibição de Falsa Conclusão**:
   - Nenhuma tarefa ou fase pode ser marcada como concluída (`[x]`) sem que o código exista, integre com as camadas reais e passe nos testes automatizados correspondentes.

---

## 2. Regras Éticas e Limites de Segurança Cibernética (Invioláveis)

O `cyber-security-checker` é uma plataforma defensiva de gerenciamento de vulnerabilidades e auditoria autorizada.

1. **Autorização Comprovada Obrigatória**:
   - Nenhum scan ativo ou passivo deve executar contra alvos que não possuam comprovação de autorização válida vinculada à organização (`TargetAuthorization`) ou que não pertençam explicitamente ao laboratório local isolado.
2. **Proteção Anti-SSRF e Validação de Escopo**:
   - Todo módulo do `security-engine` deve passar pelo validador de escopo (`ScopePolicyValidator`) antes e durante as requisições (incluindo resolução DNS e redirecionamentos HTTP).
   - Endereços de loopback (`127.0.0.0/8`, `::1`), redes privadas RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local/metadados de nuvem (`169.254.169.254`) e a própria infraestrutura do scanner são **bloqueados por padrão**, exceto quando explicitamente habilitados em modo de laboratório local controlado (`ALLOW_LOCAL_LAB_TARGETS=true` restrito a containers/hosts de laboratório autorizados).
3. **Proibição de Ataques Destrutivos**:
   - É estritamente proibido implementar módulos de negação de serviço real (DoS/DDoS floods, amplificação, exaustão), força bruta indiscriminada, *credential stuffing*, extração de dados reais via SQLi, *shells* reversos ou modificação destrutiva de registros em alvos auditados.
4. **Testes Exclusivamente em Laboratório Local**:
   - Nunca utilize domínios ou sistemas públicos de terceiros em testes automatizados ou manuais. Utilize exclusivamente fixtures locais, servidores de teste internos ou aplicações de laboratório em containers isolados.

---

## 3. Regras Contra Implementações Fictícias (Zero Mock-Only Product)

1. **Proibido Dados Estáticos Camuflados**:
   - Dashboards, tabelas, relatórios e contadores devem refletir consultas reais ao banco de dados PostgreSQL via API FastAPI. Quando não houver registros, exiba estados vazios claros (*empty states*) orientando o usuário a cadastrar um ativo ou iniciar uma auditoria.
2. **Proibido Scanners Simulados**:
   - Nenhum módulo do `security-engine` pode retornar vulnerabilidades pré-fabricadas (`hardcoded`). Cada verificação deve inspecionar respostas, cabeçalhos, certificados ou configurações reais e distinguir rigorosamente entre:
     - `PASSED` (Aprovado)
     - `VULNERABILITY` (Falha identificada com evidência técnica)
     - `POTENTIAL_VULNERABILITY` (Indício técnico que requer confirmação)
     - `INCONCLUSIVE` (Inconclusivo)
     - `NOT_APPLICABLE` (Não aplicável ao alvo)
     - `EXECUTION_ERROR` (Erro operacional/técnico durante o teste — jamais classificar como aprovado)
3. **Fundamentação Técnica Obrigatória**:
   - Não atribua identificadores CVE ou pontuações CVSS 4.0 sem evidência técnica determinística. Utilize mapeamentos CWE, OWASP Top 10 (2021/API 2023), OWASP ASVS 5.0 e OWASP WSTG com precisão.
4. **Sanitização de Evidências**:
   - Credenciais, cabeçalhos `Authorization`, tokens de sessão e valores de cookies sensíveis devem ser mascarados pelo `EvidenceManager` antes de persistência no banco ou exibição em relatórios.

---

## 4. Padrões de Engenharia e Qualidade de Código

- **Idioma da Interface e Documentação**: Português Brasileiro (`pt-BR`) como idioma principal de UI, mensagens de domínio, recomendações de correção e documentação; identificadores de código (classes, funções, variáveis, tabelas) em Inglês técnico claro.
- **Backend & Security Engine (Python 3.11+)**:
  - Tipagem estática rigorosa (`typing`, Pydantic v2, SQLAlchemy 2.0 `Mapped`).
  - Arquitetura em camadas: `api` (rotas/dependências) -> `services` (regras de negócio/orquestração) -> `repositories` (acesso a dados) -> `models` (entidades ORM).
  - Isolamento do motor de segurança no pacote `security_engine` (instalável/importável pelo backend e pelos workers Celery).
- **Frontend (Next.js App Router + TypeScript)**:
  - Tipagem estrita (`strict: true`), validação com `zod` + `react-hook-form`, gerenciamento de estado assíncrono com `@tanstack/react-query`.
  - Estética *Security Operations Center (SOC)* sóbria, alto contraste, acessível, com suporte a tema escuro (padrão) e claro.
- **Testes Automatizados**:
  - Toda nova funcionalidade requer testes automatizados correspondentes (`pytest` no backend/security-engine, validação de tipos/build/testes no frontend) registrados em `TEST_MATRIX.md`.
