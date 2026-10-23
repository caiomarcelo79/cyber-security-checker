"""Configurações centralizadas da aplicação Backend e Workers."""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configurações tipadas carregadas de variáveis de ambiente ou arquivo .env."""

    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = Field(default="cyber-security-checker", alias="APP_NAME")
    app_env: str = Field(default="development", alias="APP_ENV")
    app_version: str = Field(default="0.1.0", alias="APP_VERSION")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    database_url: str = Field(
        default="postgresql+psycopg://postgres:postgres_dev_password_change_me@localhost:5432/cybersecuritychecker",
        alias="DATABASE_URL",
    )
    redis_url: str = Field(default="redis://localhost:6379/0", alias="REDIS_URL")
    celery_broker_url: str = Field(default="redis://localhost:6379/0", alias="CELERY_BROKER_URL")
    celery_result_backend: str = Field(default="redis://localhost:6379/1", alias="CELERY_RESULT_BACKEND")

    secret_key: str = Field(
        default="dev-only-secret-key-replace-in-production-with-64-hex-chars",
        alias="SECRET_KEY",
    )
    access_token_expire_minutes: int = Field(default=60, alias="ACCESS_TOKEN_EXPIRE_MINUTES")
    cors_origins: list[str] = Field(
        default=["http://localhost:3000", "http://127.0.0.1:3000"],
        alias="CORS_ORIGINS",
    )

    trust_forwarded_for: bool = Field(default=False, alias="TRUST_FORWARDED_FOR")
    login_max_failures_per_ip: int = Field(default=20, alias="LOGIN_MAX_FAILURES_PER_IP")
    login_max_failures_per_email: int = Field(default=8, alias="LOGIN_MAX_FAILURES_PER_EMAIL")
    login_failure_window_minutes: int = Field(default=15, alias="LOGIN_FAILURE_WINDOW_MINUTES")

    reports_dir: str = Field(default="data/reports", alias="REPORTS_DIR")
    reports_download_expire_minutes: int = Field(default=1440, alias="REPORTS_DOWNLOAD_EXPIRE_MINUTES")

    block_private_networks: bool = Field(default=True, alias="BLOCK_PRIVATE_NETWORKS")
    allow_local_lab_targets: bool = Field(default=True, alias="ALLOW_LOCAL_LAB_TARGETS")
    lab_allowed_hosts: str = Field(
        default="lab-target,localhost-lab.internal,127.0.0.1,localhost",
        alias="LAB_ALLOWED_HOSTS",
    )

    # Automações, Alertas e Webhooks (Fase 7)
    smtp_enabled: bool = Field(default=False, alias="SMTP_ENABLED")
    smtp_host: str = Field(default="localhost", alias="SMTP_HOST")
    smtp_port: int = Field(default=587, alias="SMTP_PORT")
    smtp_user: str = Field(default="", alias="SMTP_USER")
    smtp_password: str = Field(default="", alias="SMTP_PASSWORD")
    smtp_from: str = Field(default="alerts@cybersecuritychecker.local", alias="SMTP_FROM")
    smtp_use_tls: bool = Field(default=True, alias="SMTP_USE_TLS")

    webhook_delivery_timeout_sec: int = Field(default=10, alias="WEBHOOK_DELIVERY_TIMEOUT_SEC")
    webhook_max_retries: int = Field(default=3, alias="WEBHOOK_MAX_RETRIES")

    @property
    def is_production(self) -> bool:
        return self.app_env.lower() in {"production", "prod"}

    def validate_production_safety(self) -> list[str]:
        """Retorna problemas de configuração inseguros (lista vazia = seguro)."""
        problems: list[str] = []
        if not self.is_production:
            return problems
        if self.secret_key.startswith("dev-only") or len(self.secret_key) < 32:
            problems.append("SECRET_KEY padrão/curta: defina um valor aleatório de >= 32 caracteres.")
        if "postgres_dev_password_change_me" in self.database_url:
            problems.append("DATABASE_URL usa a senha de desenvolvimento.")
        if self.allow_local_lab_targets:
            problems.append("ALLOW_LOCAL_LAB_TARGETS=true não é permitido em produção.")
        if not self.block_private_networks:
            problems.append("BLOCK_PRIVATE_NETWORKS deve permanecer true em produção.")
        if any("localhost" in o or "127.0.0.1" in o for o in self.cors_origins):
            problems.append("CORS_ORIGINS contém origens locais.")
        if "*" in self.cors_origins:
            problems.append("CORS_ORIGINS não pode conter '*'.")
        return problems

    @property
    def parsed_lab_allowed_hosts(self) -> list[str]:
        return [h.strip() for h in self.lab_allowed_hosts.split(",") if h.strip()]


@lru_cache
def get_settings() -> Settings:
    """Retorna instância singleton das configurações."""
    return Settings()
