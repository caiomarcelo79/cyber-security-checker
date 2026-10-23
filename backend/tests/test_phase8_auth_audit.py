"""Testes de auditoria de autenticação da Fase 8: rate limit, enumeração, revogação e CSRF por Origin."""

from __future__ import annotations

from fastapi.testclient import TestClient

PASSWORD = "StrongPassword!2026"


def _register(client: TestClient, email: str = "owner@lab-auth.test") -> dict:
    resp = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": PASSWORD, "full_name": "Owner", "organization_name": f"Org {email}"},
    )
    assert resp.status_code == 201
    return resp.json()


def test_login_failure_messages_do_not_distinguish_unknown_user(client: TestClient) -> None:
    _register(client)
    wrong_pw = client.post("/api/v1/auth/login", json={"email": "owner@lab-auth.test", "password": "Wrong!12345"})
    unknown = client.post("/api/v1/auth/login", json={"email": "ghost@lab-auth.test", "password": "Wrong!12345"})
    assert wrong_pw.status_code == unknown.status_code == 401
    assert wrong_pw.json()["detail"] == unknown.json()["detail"]


def test_login_rate_limit_by_email_is_temporary_and_logged(client: TestClient) -> None:
    _register(client)
    codes = [
        client.post("/api/v1/auth/login", json={"email": "owner@lab-auth.test", "password": "Wrong!12345"}).status_code
        for _ in range(10)
    ]
    assert codes[:8] == [401] * 8
    assert 429 in codes[8:]
    blocked = client.post("/api/v1/auth/login", json={"email": "owner@lab-auth.test", "password": PASSWORD})
    assert blocked.status_code == 429
    assert "Retry-After" in blocked.headers
    # Outro usuário não é afetado (sem negação de serviço entre contas).
    _register(client, "other@lab-auth.test")
    ok = client.post("/api/v1/auth/login", json={"email": "other@lab-auth.test", "password": PASSWORD})
    assert ok.status_code == 200


def test_logout_revokes_token_server_side(client: TestClient) -> None:
    token = _register(client)["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 200
    assert client.post("/api/v1/auth/logout", headers=headers).status_code == 200
    replay = client.get("/api/v1/auth/me", headers=headers)
    assert replay.status_code == 401


def test_cookie_auth_rejects_untrusted_origin_on_mutation(client: TestClient) -> None:
    _register(client)  # define cookie de sessão no cliente
    evil = client.post("/api/v1/auth/logout", headers={"Origin": "https://evil.example"})
    assert evil.status_code == 403
    good = client.post("/api/v1/auth/logout", headers={"Origin": "http://localhost:3000"})
    assert good.status_code == 200


def test_forged_x_forwarded_for_is_ignored_by_default(client: TestClient) -> None:
    _register(client)
    for i in range(25):
        client.post(
            "/api/v1/auth/login",
            json={"email": f"nobody{i}@lab-auth.test", "password": "Wrong!12345"},
            headers={"X-Forwarded-For": f"10.9.8.{i}"},
        )
    # Todas as tentativas contam para o mesmo IP real, então o limite por IP é atingido.
    resp = client.post(
        "/api/v1/auth/login",
        json={"email": "fresh@lab-auth.test", "password": "Wrong!12345"},
        headers={"X-Forwarded-For": "10.1.1.1"},
    )
    assert resp.status_code == 429
