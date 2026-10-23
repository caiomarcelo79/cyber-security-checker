"""Smoke tests e validação de infraestrutura e arquivos de memória persistente (TM-010)."""

from __future__ import annotations

from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent

REQUIRED_MEMORY_FILES = [
    "AGENTS.md",
    "PROJECT_STATE.md",
    "NEXT_STEPS.md",
    "ROADMAP.md",
    "ARCHITECTURE.md",
    "DECISIONS.md",
    "SECURITY_SCOPE.md",
    "TEST_MATRIX.md",
    "README.md",
    ".env.example",
    "docker-compose.yml",
]

REQUIRED_DIRECTORIES = [
    "frontend",
    "backend",
    "security-engine",
    "workers",
    "infrastructure",
    "docs",
    "scripts",
    "tests",
]


def test_persistent_memory_and_directory_structure_exist() -> None:
    for filename in REQUIRED_MEMORY_FILES:
        file_path = ROOT_DIR / filename
        assert file_path.exists(), f"Arquivo obrigatório ausente: {filename}"
        assert file_path.stat().st_size > 100, f"Arquivo obrigatório vazio ou incompleto: {filename}"

    for dirname in REQUIRED_DIRECTORIES:
        dir_path = ROOT_DIR / dirname
        assert dir_path.is_dir(), f"Diretório obrigatório ausente: {dirname}"


def test_docker_compose_defines_all_core_services_with_healthchecks() -> None:
    compose_text = (ROOT_DIR / "docker-compose.yml").read_text(encoding="utf-8")
    for service_name in ["postgres:", "redis:", "backend:", "worker:", "frontend:"]:
        assert service_name in compose_text, f"Serviço {service_name} ausente no docker-compose.yml"
    assert compose_text.count("healthcheck:") >= 5


def test_live_postgresql_and_redis_integration_via_api() -> None:
    import sys

    sys.path.insert(0, str(ROOT_DIR / "backend"))
    from app.main import app
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        resp = client.get("/api/v1/system/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "UP"
        assert data["components"]["database"]["status"] == "UP"
        assert data["components"]["database"]["details"]["dialect"] == "postgresql"
        assert data["components"]["redis"]["status"] == "UP"
        assert data["components"]["security_engine"]["status"] == "UP"

