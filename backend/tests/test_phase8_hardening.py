"""Testes de hardening da Fase 8: validação de configuração de produção, headers e readiness."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app


def _prod(**overrides: object) -> Settings:
    base: dict[str, object] = {
        "APP_ENV": "production",
        "SECRET_KEY": "x" * 64,
        "DATABASE_URL": "postgresql+psycopg://u:strongpw@db:5432/csc",
        "ALLOW_LOCAL_LAB_TARGETS": False,
        "BLOCK_PRIVATE_NETWORKS": True,
        "CORS_ORIGINS": ["https://csc.example.org"],
    }
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


def test_production_defaults_are_rejected() -> None:
    problems = Settings(APP_ENV="production").validate_production_safety()  # type: ignore[call-arg]
    assert len(problems) >= 4


def test_secure_production_config_is_accepted() -> None:
    assert _prod().validate_production_safety() == []


def test_development_never_fails_validation() -> None:
    assert Settings(APP_ENV="development").validate_production_safety() == []  # type: ignore[call-arg]


def test_production_rejects_wildcard_and_local_cors() -> None:
    assert _prod(CORS_ORIGINS=["*"]).validate_production_safety()
    assert _prod(CORS_ORIGINS=["http://localhost:3000"]).validate_production_safety()


def test_security_headers_and_correlation_id() -> None:
    client = TestClient(create_app())
    response = client.get("/api/v1/health", headers={"X-Request-ID": "abc-123"})
    assert response.headers["X-Request-ID"] == "abc-123"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]


def test_readiness_reports_503_when_dependencies_down(monkeypatch) -> None:
    monkeypatch.setenv("REDIS_URL", "redis://127.0.0.1:1/0")
    from app.core.config import get_settings

    get_settings.cache_clear()
    try:
        response = TestClient(create_app()).get("/api/v1/ready")
        assert response.status_code == 503
        assert response.json()["checks"]["redis"] == "DOWN"
    finally:
        get_settings.cache_clear()
