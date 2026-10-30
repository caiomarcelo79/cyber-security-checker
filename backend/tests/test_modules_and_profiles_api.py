"""Testes dos endpoints de catálogo de módulos, perfis, recomendações e validação de escopo (TM-006)."""

from fastapi.testclient import TestClient


def test_modules_and_profiles_catalog_endpoints(client: TestClient) -> None:
    mod_resp = client.get("/api/v1/modules")
    assert mod_resp.status_code == 200
    modules = mod_resp.json()
    assert len(modules) == 8
    assert any(m["module_id"] == "mod_a_recon_headers_tls" for m in modules)

    prof_resp = client.get("/api/v1/profiles")
    assert prof_resp.status_code == 200
    profiles = prof_resp.json()
    assert len(profiles) == 7
    assert any(p["profile_type"] == "QUICK" for p in profiles)
    assert any(p["profile_type"] == "DEEP_PENTEST" for p in profiles)

    rem_resp = client.get("/api/v1/remediation")
    assert rem_resp.status_code == 200
    remediations = rem_resp.json()
    assert len(remediations) >= 5


def test_scope_validation_endpoint_blocks_ssrf_and_unauthorized_hosts(client: TestClient) -> None:
    blocked_ssrf = client.post(
        "/api/v1/scope/validate",
        json={
            "target_url": "http://169.254.169.254/latest/meta-data/",
            "authorized_hosts": ["169.254.169.254"],
            "allow_subdomains": False,
        },
    )
    assert blocked_ssrf.status_code == 200
    assert blocked_ssrf.json()["allowed"] is False
    assert "metadados de nuvem" in blocked_ssrf.json()["reason"]

    allowed_scope = client.post(
        "/api/v1/scope/validate",
        json={
            "target_url": "https://sistema.empresa.com.br/api/status",
            "authorized_hosts": ["sistema.empresa.com.br"],
            "allow_subdomains": False,
        },
    )
    assert allowed_scope.status_code == 200
    assert allowed_scope.json()["allowed"] is True
    assert allowed_scope.json()["hostname"] == "sistema.empresa.com.br"
