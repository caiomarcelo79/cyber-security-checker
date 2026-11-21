"""Testes automatizados de Cadastro de Ativos, Comprovação de Autorização (DNS_TXT, HTTP_WELL_KNOWN, LAB_INTERNAL) e AuditLog (TM-012 - Fase 2)."""

from __future__ import annotations

import httpx
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.entities import Scan
from app.services.asset_service import AssetAuthorizationService


def _register_and_get_headers(
    client: TestClient, email: str = "secops@lab.local"
) -> tuple[dict[str, str], str, str]:
    resp = client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "password": "SecOpsPassword!2026",
            "full_name": "Engenheiro SecOps",
            "organization_name": "Lab SecOps Corp",
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    return (
        {"Authorization": f"Bearer {data['access_token']}"},
        data["active_organization"]["id"],
        data["user"]["id"],
    )


def test_asset_creation_blocks_ssrf_metadata_and_validates_lab_authorization(
    client: TestClient,
) -> None:
    headers, _, _ = _register_and_get_headers(client)

    # Tentar cadastrar IP de metadados de nuvem deve falhar imediatamente (422)
    ssrf_resp = client.post(
        "/api/v1/assets",
        headers=headers,
        json={
            "name": "Metadata Inseguro",
            "target_url": "http://169.254.169.254/latest/meta-data/",
            "asset_type": "WEB_APP",
            "environment": "LAB",
            "owner_name": "Teste",
            "owner_email": "teste@lab.local",
        },
    )
    assert ssrf_resp.status_code == 422
    assert "Anti-SSRF" in ssrf_resp.json()["detail"]

    # Cadastrar ativo de laboratório válido
    asset_resp = client.post(
        "/api/v1/assets",
        headers=headers,
        json={
            "name": "Aplicação Laboratório Local",
            "target_url": "http://lab-target.internal:8080/app",
            "asset_type": "WEB_APP",
            "environment": "LAB",
            "owner_name": "Equipe AppSec",
            "owner_email": "appsec@lab.local",
            "tags": ["laboratorio", "owasp"],
            "excluded_paths": ["/logout"],
        },
    )
    assert asset_resp.status_code == 201
    asset = asset_resp.json()
    asset_id = asset["id"]
    assert asset["hostname"] == "lab-target.internal"
    assert asset["authorization_status"] == "PENDING"

    # Inicia desafio LAB_INTERNAL
    init_resp = client.post(
        f"/api/v1/assets/{asset_id}/authorizations",
        headers=headers,
        json={
            "method": "LAB_INTERNAL",
            "scope_notes": "Ambiente de laboratório isolado para validação de scanners.",
            "expires_in_days": 30,
        },
    )
    assert init_resp.status_code == 201
    auth_data = init_resp.json()
    auth_id = auth_data["id"]
    assert auth_data["status"] == "PENDING"
    assert auth_data["verification_token"].startswith("cyber-sec-checker-verify=")

    # Verifica autorização LAB_INTERNAL
    verify_resp = client.post(
        f"/api/v1/assets/{asset_id}/authorizations/{auth_id}/verify",
        headers=headers,
    )
    assert verify_resp.status_code == 200
    assert verify_resp.json()["status"] == "VERIFIED"

    # Confirma que o status do ativo mudou para VERIFIED
    updated_asset = client.get(f"/api/v1/assets/{asset_id}", headers=headers)
    assert updated_asset.status_code == 200
    assert updated_asset.json()["authorization_status"] == "VERIFIED"

    # Revoga autorização e confirma transição para REVOKED
    revoke_resp = client.post(
        f"/api/v1/assets/{asset_id}/authorizations/{auth_id}/revoke",
        headers=headers,
    )
    assert revoke_resp.status_code == 200
    assert revoke_resp.json()["status"] == "REVOKED"

    revoked_asset = client.get(f"/api/v1/assets/{asset_id}", headers=headers)
    assert revoked_asset.json()["authorization_status"] == "REVOKED"

    # Verifica registros no AuditLog
    logs_resp = client.get("/api/v1/audit-logs", headers=headers)
    assert logs_resp.status_code == 200
    actions = [entry["action"] for entry in logs_resp.json()]
    assert "ASSET_CREATED" in actions
    assert "AUTH_CHALLENGE_CREATED" in actions
    assert "AUTH_CHALLENGE_VERIFIED" in actions
    assert "AUTH_REVOKED" in actions


def test_dns_txt_and_http_well_known_verification_methods(
    client: TestClient,
    db_session: Session,
) -> None:
    headers, org_id, user_id = _register_and_get_headers(client, email="dns-verifier@lab.local")

    # Cria um ativo corporativo em homologação
    asset_resp = client.post(
        "/api/v1/assets",
        headers=headers,
        json={
            "name": "Portal Homologação",
            "target_url": "https://homolog.empresa-autorizada.com.br",
            "asset_type": "WEB_APP",
            "environment": "STAGING",
            "owner_name": "DevSecOps",
            "owner_email": "devsecops@empresa-autorizada.com.br",
        },
    )
    assert asset_resp.status_code == 201
    asset_id = asset_resp.json()["id"]

    # 1. Desafio DNS_TXT
    dns_init = client.post(
        f"/api/v1/assets/{asset_id}/authorizations",
        headers=headers,
        json={"method": "DNS_TXT", "scope_notes": "Validação via registro TXT"},
    )
    assert dns_init.status_code == 201
    dns_auth_id = dns_init.json()["id"]
    expected_dns_token = dns_init.json()["verification_token"]

    # Quando o DNS não retorna o token, deve falhar com 422 e manter status PENDING
    with pytest.raises(HTTPException) as exc_info:
        AssetAuthorizationService.verify_authorization(
            db=db_session,
            organization_id=org_id,
            user_id=user_id,
            asset_id=asset_id,
            authorization_id=dns_auth_id,
            dns_txt_resolver=lambda _qname: ["v=spf1 -all"],
        )
    assert exc_info.value.status_code == 422

    # Quando o registro DNS TXT contém o token exato, aprova e marca VERIFIED
    verified_dns = AssetAuthorizationService.verify_authorization(
        db=db_session,
        organization_id=org_id,
        user_id=user_id,
        asset_id=asset_id,
        authorization_id=dns_auth_id,
        dns_txt_resolver=lambda qname: (
            [expected_dns_token]
            if qname == "_cybersecuritychecker.homolog.empresa-autorizada.com.br"
            else []
        ),
    )
    assert verified_dns.status == "VERIFIED"

    # 2. Desafio HTTP_WELL_KNOWN
    http_init = client.post(
        f"/api/v1/assets/{asset_id}/authorizations",
        headers=headers,
        json={"method": "HTTP_WELL_KNOWN", "scope_notes": "Validação via arquivo Well-Known"},
    )
    assert http_init.status_code == 201
    http_auth_id = http_init.json()["id"]
    expected_http_token = http_init.json()["verification_token"]

    mock_transport = httpx.MockTransport(
        lambda request: (
            httpx.Response(
                200,
                text=f"# Comprovante de Autorização\n{expected_http_token}\n",
            )
            if request.url.path == "/.well-known/cyber-security-checker.txt"
            else httpx.Response(404)
        )
    )

    verified_http = AssetAuthorizationService.verify_authorization(
        db=db_session,
        organization_id=org_id,
        user_id=user_id,
        asset_id=asset_id,
        authorization_id=http_auth_id,
        http_transport=mock_transport,
    )
    assert verified_http.status == "VERIFIED"


def test_update_asset_target_url_resets_authorization_and_blocks_ssrf(
    client: TestClient,
    db_session: Session,
) -> None:
    headers, org_id, user_id = _register_and_get_headers(
        client, email="asset-editor@lab.local"
    )

    asset_resp = client.post(
        "/api/v1/assets",
        headers=headers,
        json={
            "name": "Alvo Editável",
            "target_url": "http://lab-target.internal:8080/app",
            "asset_type": "WEB_APP",
            "environment": "LAB",
            "owner_name": "Equipe AppSec",
            "owner_email": "appsec@lab.local",
        },
    )
    assert asset_resp.status_code == 201
    asset_id = asset_resp.json()["id"]

    init_resp = client.post(
        f"/api/v1/assets/{asset_id}/authorizations",
        headers=headers,
        json={"method": "LAB_INTERNAL", "scope_notes": "Lab inicial"},
    )
    assert init_resp.status_code == 201
    first_auth_id = init_resp.json()["id"]

    verify_resp = client.post(
        f"/api/v1/assets/{asset_id}/authorizations/{first_auth_id}/verify",
        headers=headers,
    )
    assert verify_resp.status_code == 200
    assert verify_resp.json()["status"] == "VERIFIED"

    # Mesma origem (alteração apenas de nome e path) mantém autorização VERIFIED
    same_origin_resp = client.patch(
        f"/api/v1/assets/{asset_id}",
        headers=headers,
        json={
            "name": "Alvo Editável v2",
            "target_url": "http://lab-target.internal:8080/v2",
        },
    )
    assert same_origin_resp.status_code == 200
    same_origin_data = same_origin_resp.json()
    assert same_origin_data["name"] == "Alvo Editável v2"
    assert same_origin_data["target_url"] == "http://lab-target.internal:8080/v2"
    assert same_origin_data["authorization_status"] == "VERIFIED"

    # Tentar atualizar para IP de metadados de nuvem deve falhar com 422 (Anti-SSRF)
    ssrf_resp = client.patch(
        f"/api/v1/assets/{asset_id}",
        headers=headers,
        json={"target_url": "http://169.254.169.254/latest/meta-data/"},
    )
    assert ssrf_resp.status_code == 422
    assert "Anti-SSRF" in ssrf_resp.json()["detail"]

    # Alterar origem/domínio redefine autorização para PENDING e revoga autorizações antigas
    change_host_resp = client.patch(
        f"/api/v1/assets/{asset_id}",
        headers=headers,
        json={"target_url": "http://localhost:8080/"},
    )
    assert change_host_resp.status_code == 200
    changed_data = change_host_resp.json()
    assert changed_data["hostname"] == "localhost"
    assert changed_data["target_url"] == "http://localhost:8080/"
    assert changed_data["authorization_status"] == "PENDING"

    auths_resp = client.get(f"/api/v1/assets/{asset_id}/authorizations", headers=headers)
    assert auths_resp.status_code == 200
    auth_by_id = {item["id"]: item for item in auths_resp.json()}
    assert auth_by_id[first_auth_id]["status"] == "REVOKED"

    logs_resp = client.get("/api/v1/audit-logs", headers=headers)
    assert logs_resp.status_code == 200
    updated_logs = [
        entry for entry in logs_resp.json() if entry["action"] == "ASSET_UPDATED"
    ]
    assert any(entry["metadata_json"].get("authorization_reset") is True for entry in updated_logs)

    # Revalida LAB_INTERNAL para o novo host localhost
    second_init = client.post(
        f"/api/v1/assets/{asset_id}/authorizations",
        headers=headers,
        json={"method": "LAB_INTERNAL", "scope_notes": "Novo alvo localhost"},
    )
    assert second_init.status_code == 201
    second_auth_id = second_init.json()["id"]
    second_verify = client.post(
        f"/api/v1/assets/{asset_id}/authorizations/{second_auth_id}/verify",
        headers=headers,
    )
    assert second_verify.status_code == 200
    assert second_verify.json()["status"] == "VERIFIED"

    # Mudar ambiente para PRODUCTION revoga LAB_INTERNAL e volta status do ativo para PENDING
    prod_resp = client.patch(
        f"/api/v1/assets/{asset_id}",
        headers=headers,
        json={"environment": "PRODUCTION"},
    )
    assert prod_resp.status_code == 200
    assert prod_resp.json()["environment"] == "PRODUCTION"
    assert prod_resp.json()["authorization_status"] == "PENDING"

    auths_after_prod = client.get(
        f"/api/v1/assets/{asset_id}/authorizations", headers=headers
    )
    assert auths_after_prod.status_code == 200
    assert all(item["status"] == "REVOKED" for item in auths_after_prod.json())

    # Bloqueia alteração de domínio/URL quando há scan ativo (RUNNING)
    running_scan = Scan(
        organization_id=org_id,
        asset_id=asset_id,
        initiated_by_user_id=user_id,
        profile_type="QUICK",
        status="RUNNING",
    )
    db_session.add(running_scan)
    db_session.commit()

    conflict_resp = client.patch(
        f"/api/v1/assets/{asset_id}",
        headers=headers,
        json={"target_url": "http://lab-target.internal:8080/"},
    )
    assert conflict_resp.status_code == 409
