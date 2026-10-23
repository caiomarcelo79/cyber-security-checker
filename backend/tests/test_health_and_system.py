"""Testes dos endpoints de health check, diagnóstico do sistema e cabeçalhos de segurança (TM-005)."""

from fastapi.testclient import TestClient


def test_health_endpoint_and_security_headers(client: TestClient) -> None:
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "UP"
    assert payload["service"] == "cyber-security-checker"

    # Valida que o próprio backend aplica cabeçalhos de segurança (Seção 12)
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"


def test_system_status_and_real_zero_metrics_on_empty_db(client: TestClient) -> None:
    response = client.get("/api/v1/system/status?skip_redis=true")
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "UP"
    assert data["registered_modules_count"] == 8
    assert data["available_profiles_count"] == 6
    assert data["components"]["database"]["status"] == "UP"
    assert data["components"]["security_engine"]["status"] == "UP"

    # Garante a regra contra dados fictícios (Seção 19): banco vazio deve retornar zeros reais
    metrics = data["metrics"]
    assert metrics["total_assets"] == 0
    assert metrics["total_scans_executed"] == 0
    assert metrics["open_vulnerabilities"] == 0
    assert metrics["critical_vulnerabilities"] == 0
