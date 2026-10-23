# Guia de Instalação e Execução Local (`INSTALLATION.md`)

Este guia detalha o processo passo a passo para configurar e executar o **Cyber-Security-Checker** em ambiente de desenvolvimento ou laboratório local isolado.

---

## 1. Pré-Requisitos do Sistema

- **Docker & Docker Compose**: Docker Engine 24.0+ e Docker Compose v2.20+
- **Python**: Versão 3.11 ou 3.12 (caso execute fora de containers)
- **Node.js**: Versão 20.x ou 22.x LTS com `npm` 10+
- **Git**: 2.40+
- **Memória RAM Mínima**: 4 GB (recomendado 8 GB para stack completa com Next.js e Celery)
- **Espaço em Disco**: 5 GB livres

---

## 2. Instalação e Execução via Docker Compose (Recomendado)

O método mais rápido e seguro para rodar a stack completa (PostgreSQL, Redis, Backend FastAPI, Worker Celery, Beat Scheduler e Frontend Next.js).

### Passo 1 — Clonar o Repositório
```bash
git clone https://github.com/your-org/cyber-security-checker.git
cd cyber-security-checker
```

### Passo 2 — Configurar Variáveis de Ambiente
Copie o arquivo de exemplo para `.env`:
```bash
cp .env.example .env
```
Para ambiente de desenvolvimento local, os valores padrão de `.env.example` são pré-configurados para funcionamento imediato.

### Passo 3 — Construir e Iniciar os Serviços
```bash
docker compose up -d --build
```

### Passo 4 — Verificar o Estado dos Serviços
```bash
docker compose ps
```
Todos os serviços devem exibir status `Up` ou `(healthy)`:
- `csc-postgres` (porta 5432)
- `csc-redis` (porta 6379)
- `csc-backend` (porta 8000)
- `csc-worker` (fila Celery de auditorias)
- `csc-beat` (agendador de auditorias periódicas)
- `csc-frontend` (porta 3000)

### Passo 5 — Testar Conectividade e Endpoints
- **Readiness Check (API + DB + Redis)**:
  ```bash
  curl http://localhost:8000/api/v1/ready
  ```
  *Resposta esperada:* `{"status":"READY","checks":{"database":"UP","redis":"UP"}}`
- **Painel SOC Web**: Acesse `http://localhost:3000`
- **Documentação Interativa OpenAPI / Swagger**: Acesse `http://localhost:8000/docs`

---

## 3. Instalação Manual para Desenvolvimento Ativo (Bare Metal / Host)

Para desenvolvimento direto com recarga dinâmica de código (*hot reload*):

### Passo 1 — Subir PostgreSQL e Redis
```bash
docker compose up -d postgres redis
```

### Passo 2 — Configurar Ambiente Virtual Python
```bash
# Criar ambiente virtual
python -m venv .venv

# Ativar no Windows (PowerShell)
.\.venv\Scripts\Activate.ps1

# Ativar no Linux / macOS (Bash)
source .venv/bin/activate

# Atualizar pip e instalar dependências em modo editável
python -m pip install --upgrade pip
pip install -r backend/requirements.txt -e security-engine
```

### Passo 3 — Executar Migrações do Banco de Dados
```bash
cd backend
alembic upgrade head
cd ..
```

### Passo 4 — Iniciar o Servidor Backend (FastAPI)
```bash
cd backend
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Passo 5 — Iniciar o Worker Celery e Scheduler
Em novos terminais (com `.venv` ativado e a partir da raiz do repositório):
```bash
# Terminal 2 — Worker
celery -A workers.celery_app:celery_app worker --loglevel=info --concurrency=2

# Terminal 3 — Celery Beat (Scheduler)
celery -A workers.celery_app:celery_app beat --loglevel=info
```

### Passo 6 — Configurar e Iniciar o Frontend (Next.js)
Em outro terminal:
```bash
cd frontend
npm install
npm run dev
```
Acesse a aplicação em `http://localhost:3000`.

---

## 4. Execução da Suíte de Testes Automatizados

### Backend & Fluxos E2E (75 testes)
```bash
# Executa todos os testes do backend e de ponta a ponta
pytest backend/tests -v

# Executa testes do motor de segurança
pytest security-engine/tests -v
```

### Frontend (27 testes Vitest + Checagem de Tipos)
```bash
cd frontend
npm run test
npm run build
```

---

## 5. Parada e Limpeza dos Containers
Para encerrar os containers preservando dados em volumes:
```bash
docker compose down
```

Para remover containers, redes e volumes de desenvolvimento:
```bash
docker compose down -v
```
