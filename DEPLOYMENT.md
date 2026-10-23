# Guia de Implantação em Produção (`DEPLOYMENT.md`)

Este documento fornece as diretrizes completas de arquitetura, segurança e configuração necessárias para implantar o **Cyber-Security-Checker** em ambiente produtivo seguro (*Production-Grade*).

---

## 1. Princípios Arquiteturais e Proteções de Produção

O sistema incorpora um mecanismo rígido de proteção contra execuções com configurações inseguras (`validate_production_safety` em `backend/app/core/config.py`).
Caso `APP_ENV=production` seja configurado com valores padrão ou inseguros, a aplicação aborta a inicialização com erro fatal imediato.

### Critérios Obrigatórios para Produção
1. **`SECRET_KEY`**: Chave criptográfica aleatória de alta entropia com no mínimo 32 caracteres (recomendado 64 caracteres hexadecimais). Segredos que contenham as palavras `dev`, `test`, `secret`, `replace` ou `change` são bloqueados.
2. **`POSTGRES_PASSWORD`**: Senha forte e dedicada para o banco de dados. Senhas contendo `change_me`, `postgres` ou `admin` são terminantemente rejeitadas.
3. **`CORS_ORIGINS`**: É proibido utilizar `*` (wildcard) ou origens contendo `localhost` / `127.0.0.1` em produção. Apenas os domínios corporativos HTTPS autorizados devem constar nesta lista.
4. **`BLOCK_PRIVATE_NETWORKS=true`**: Deve permanecer estritamente habilitado para mitigar ataques de SSRF (Server-Side Request Forgery) contra serviços internos, bancos e metadados de nuvem (`169.254.169.254`).
5. **`ALLOW_LOCAL_LAB_TARGETS=false`**: Deve estar desligado em produção real para impedir que requisições de auditoria atinjam o loopback ou redes internas do servidor.

---

## 2. Geração de Segredos Seguros

Gere tokens criptográficos antes de gerar o arquivo de ambiente de produção:

```bash
# Gerar SECRET_KEY (64 bytes hex)
python -c "import secrets; print(secrets.token_hex(32))"

# Gerar senha forte para o PostgreSQL
python -c "import secrets; print(secrets.token_urlsafe(24))"

# Gerar token para webhook signing secret padrão
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

---

## 3. Matriz de Variáveis de Ambiente de Produção (`.env.production`)

```ini
# ==============================================================================
# Aplicação e Ambiente
# ==============================================================================
APP_NAME=cyber-security-checker
APP_ENV=production
LOG_LEVEL=INFO
APP_VERSION=1.0.0

# Chave criptográfica mestra (gerada via secrets.token_hex)
SECRET_KEY=9f83a21b47c059e61234567890abcdef1234567890abcdef1234567890abcdef
ACCESS_TOKEN_EXPIRE_MINUTES=60
REFRESH_TOKEN_EXPIRE_DAYS=7

# Origens CORS autorizadas (somente domínios HTTPS reais)
CORS_ORIGINS=https://soc.empresa.com.br,https://app.empresa.com.br

# ==============================================================================
# Banco de Dados PostgreSQL 16
# ==============================================================================
POSTGRES_USER=csc_prod_user
POSTGRES_PASSWORD=UltraSecurePassw0rd_Generated_2026_XYZ!
POSTGRES_DB=csc_production
DATABASE_URL=postgresql+psycopg://csc_prod_user:UltraSecurePassw0rd_Generated_2026_XYZ!@postgres:5432/csc_production

# ==============================================================================
# Redis 7 (Cache e Fila Celery)
# ==============================================================================
REDIS_URL=redis://:RedisProdAuthPasswordXYZ!@redis:6379/0
CELERY_BROKER_URL=redis://:RedisProdAuthPasswordXYZ!@redis:6379/0
CELERY_RESULT_BACKEND=redis://:RedisProdAuthPasswordXYZ!@redis:6379/1

# ==============================================================================
# Políticas de Escopo e Proteção de Rede (Anti-SSRF)
# ==============================================================================
BLOCK_PRIVATE_NETWORKS=true
ALLOW_LOCAL_LAB_TARGETS=false
LAB_ALLOWED_HOSTS=

# ==============================================================================
# Notificações e Alertas SMTP (Opcional)
# ==============================================================================
SMTP_ENABLED=true
SMTP_HOST=smtp.sendgrid.net
SMTP_PORT=587
SMTP_USER=apikey
SMTP_PASSWORD=SG.your_sendgrid_production_key
SMTP_FROM=security-alerts@empresa.com.br
SMTP_USE_TLS=true

# ==============================================================================
# Frontend Next.js
# ==============================================================================
NEXT_PUBLIC_API_URL=https://soc.empresa.com.br/api/v1
INTERNAL_API_URL=http://backend:8000/api/v1
```

---

## 4. Configuração do Reverse Proxy (Nginx com TLS e Hardening)

Recomenda-se utilizar um proxy reverso Nginx na borda terminando TLS 1.3:

```nginx
# /etc/nginx/conf.d/cyber_security_checker.conf

server {
    listen 80;
    server_name soc.empresa.com.br;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name soc.empresa.com.br;

    ssl_certificate /etc/letsencrypt/live/soc.empresa.com.br/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/soc.empresa.com.br/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    # Cabeçalhos de Segurança na Borda
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Roteamento da API Backend
    location /api/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 300s;
        proxy_connect_timeout 60s;
    }

    # Roteamento de SSE (Server-Sent Events) para acompanhamento em tempo real
    location /api/v1/scans/stream {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Connection '';
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 900s;
    }

    # Roteamento do Frontend Next.js
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

---

## 5. Check-list Pré-Entrada em Produção

- [ ] Todas as variáveis de ambiente sensíveis foram geradas com entropia adequada.
- [ ] O banco de dados PostgreSQL possui volume persistente mapeado em disco seguro/RAID.
- [ ] A migração Alembic `alembic upgrade head` foi executada com sucesso.
- [ ] O endpoint de readiness `GET /api/v1/ready` retorna status `200 READY`.
- [ ] Rotina de backup automatizado diário configurada e testada (`scripts/backup_db.ps1`).
- [ ] Limites de recursos (CPU e Memória) configurados nos containers ou pods do Kubernetes.
- [ ] Os containers backend e frontend executam com usuários não privilegiados (`csc` e `node`).
