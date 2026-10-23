# Cyber-Security-Checker

Plataforma modular de gerenciamento de vulnerabilidades, auditoria técnica autorizada e orientação de correção (DevSecOps / AppSec).

---

## 1. Visão Geral

O **cyber-security-checker** permite que administradores, desenvolvedores e analistas de segurança auditem aplicações web, APIs REST/GraphQL e domínios sob sua responsabilidade comprovada, identificando vulnerabilidades reais com evidências técnicas sanitizadas e instruções práticas de correção baseadas nos padrões:

- **OWASP Top 10 (2021)** e **OWASP API Security Top 10 (2023)**
- **OWASP Application Security Verification Standard (ASVS 5.0)**
- **OWASP Web Security Testing Guide (WSTG)**
- **MITRE CWE**, **CVSS v4.0**, **NIST** e **CIS Controls**

> **Princípio Inegociável de Segurança:** O sistema opera exclusivamente sobre alvos com autorização comprovada (`DNS_TXT`, `HTTP_WELL_KNOWN` ou laboratório local isolado), aplicando bloqueio anti-SSRF, *rate limiting* obrigatório e proibição de testes destrutivos.

---

## 2. Estrutura do Repositório

```text
cyber-security-checker/
├── frontend/               # Next.js (App Router), React, TypeScript, Tailwind CSS, shadcn/ui
├── backend/                # FastAPI, SQLAlchemy 2.0, Alembic, Pydantic v2, API REST
│   ├── app/
│   │   ├── api/            # Endpoints REST (/api/v1/*)
│   │   ├── core/           # Configurações, logging estruturado e banco de dados
│   │   ├── models/         # Entidades ORM SQLAlchemy 2.0
│   │   ├── schemas/        # Contratos Pydantic v2
│   │   ├── services/       # Orquestração, status do sistema e regras de domínio
│   │   └── repositories/   # Camada de acesso a dados
│   ├── alembic/            # Migrações de banco de dados PostgreSQL
│   └── tests/              # Testes automatizados do backend
├── security-engine/        # Motor modular de segurança em Python (pacote security_engine)
│   ├── security_engine/
│   │   ├── core/           # Contratos, EvidenceManager, RiskEngine, RemediationEngine, Registry
│   │   ├── modules/        # Módulos de auditoria (Módulos A a H)
│   │   ├── adapters/       # Adaptadores isolados para ferramentas externas opcionais
│   │   └── policies/       # ScopePolicyValidator (anti-SSRF) e ScanExecutionPolicy
│   └── tests/              # Testes unitários e de segurança do motor
├── workers/                # Workers Celery para execução assíncrona e isolada de auditorias
├── infrastructure/         # Dockerfiles e configurações de infraestrutura
├── docs/                   # Documentação complementar técnica
├── scripts/                # Scripts utilitários de inicialização, migração e verificação
├── tests/                  # Testes integrados e smoke tests de infraestrutura
├── docker-compose.yml      # Orquestração completa (PostgreSQL, Redis, Backend, Worker, Beat, Frontend)
├── .env.example            # Modelo de variáveis de ambiente
├── AGENTS.md               # Diretrizes permanentes para agentes de IA
├── ARCHITECTURE.md         # Arquitetura detalhada e contratos
├── BACKUP_RECOVERY.md      # Procedimentos de backup e recuperação de desastres
├── CHANGELOG.md            # Histórico de alterações e versões
├── DECISIONS.md            # Registro de decisões arquiteturais (ADRs)
├── DEPLOYMENT.md           # Guia de implantação em produção e hardening
├── INSTALLATION.md         # Guia de instalação e configuração local
├── NEXT_STEPS.md           # Próximas tarefas priorizadas
├── OPERATIONS.md           # Manual de operações, runbook e monitoramento
├── PROJECT_STATE.md        # Estado atual da implementação
├── RELEASE_READINESS.md    # Critérios e status de prontidão para release
├── ROADMAP.md              # Fases de desenvolvimento e critérios de conclusão
├── SECURITY.md             # Política de segurança, limites éticos e reporte
├── SECURITY_SCOPE.md       # Políticas de autorização, anti-SSRF e limites operacionais
└── TEST_MATRIX.md          # Matriz de testes automatizados e resultados
```

---

## 3. Guias e Documentação Técnica

- 📘 [Guia de Instalação Local](INSTALLATION.md) — Pré-requisitos, Docker Compose e execução em modo desenvolvimento.
- 🚀 [Guia de Implantação em Produção](DEPLOYMENT.md) — Variáveis obrigatórias, Nginx com TLS e checklist de segurança.
- 🛠️ [Manual de Operações e Runbook](OPERATIONS.md) — Monitoramento, health checks, troubleshooting e escalonamento.
- 🛡️ [Política de Segurança e Limites Éticos](SECURITY.md) — Escopo de auditoria, anti-SSRF e reporte responsável.
- 💾 [Plano de Backup e Recuperação](BACKUP_RECOVERY.md) — Procedimentos de contingência e restauração comprovada.
- 📝 [Changelog de Versões](CHANGELOG.md) — Histórico detalhado de entregas da v0.1.0 à v1.0.0.

---

## 4. Como Executar com Docker Compose

1. Copie o arquivo de variáveis de ambiente:
   ```bash
   cp .env.example .env
   ```
2. Suba os serviços com Docker Compose:
   ```bash
   docker compose up -d --build
   ```
3. Acesse os serviços:
   - **Painel Web (SOC UI):** `http://localhost:3000`
   - **API Backend (FastAPI):** `http://localhost:8000/api/v1/health`
   - **Documentação OpenAPI (Swagger):** `http://localhost:8000/docs`

---

## 5. Como Executar os Testes Automatizados

### Motor de Segurança (`security-engine`)
```bash
pytest security-engine/tests -v
```

### Backend & Workers (`backend`)
```bash
pytest backend/tests -v
```

### Frontend (`frontend`)
```bash
cd frontend
npm run typecheck
npm run test
npm run build
```
