"""Testes automatizados de Autenticação, RBAC e Isolamento Multi-Organização (TM-011 - Fase 2)."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_register_login_me_and_logout_flow(client: TestClient) -> None:
    reg_resp = client.post(
        "/api/v1/auth/register",
        json={
            "email": "admin@secops-alpha.com.br",
            "password": "StrongPassword!2026",
            "full_name": "Admin SecOps Alpha",
            "organization_name": "SecOps Alpha Ltda",
        },
    )
    assert reg_resp.status_code == 201
    reg_data = reg_resp.json()
    assert reg_data["user"]["email"] == "admin@secops-alpha.com.br"
    assert reg_data["active_role"] == "ADMIN"
    assert reg_data["active_organization"]["slug"] == "secops-alpha-ltda"
    assert "csc_access_token" in reg_resp.cookies

    token = reg_data["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    me_resp = client.get("/api/v1/auth/me", headers=headers)
    assert me_resp.status_code == 200
    assert me_resp.json()["user"]["full_name"] == "Admin SecOps Alpha"

    # Login com senha incorreta deve retornar 401
    bad_login = client.post(
        "/api/v1/auth/login",
        json={
            "email": "admin@secops-alpha.com.br",
            "password": "WrongPassword!999",
        },
    )
    assert bad_login.status_code == 401

    # Login válido
    ok_login = client.post(
        "/api/v1/auth/login",
        json={
            "email": "admin@secops-alpha.com.br",
            "password": "StrongPassword!2026",
        },
    )
    assert ok_login.status_code == 200
    assert ok_login.json()["active_role"] == "ADMIN"

    # Logout
    logout_resp = client.post("/api/v1/auth/logout", headers=headers)
    assert logout_resp.status_code == 200
    assert logout_resp.json()["status"] == "LOGGED_OUT"


def test_rbac_roles_and_multi_tenant_isolation(client: TestClient) -> None:
    # 1. Cria Organização A (Admin A)
    org_a_resp = client.post(
        "/api/v1/auth/register",
        json={
            "email": "admin@org-a.com.br",
            "password": "AdminAPassword!123",
            "full_name": "Admin Org A",
            "organization_name": "Organização A",
        },
    )
    assert org_a_resp.status_code == 201
    admin_a_token = org_a_resp.json()["access_token"]
    org_a_id = org_a_resp.json()["active_organization"]["id"]
    admin_a_headers = {"Authorization": f"Bearer {admin_a_token}"}

    # 2. Admin A adiciona um ANALISTA e um VISUALIZADOR na Organização A
    add_analyst = client.post(
        "/api/v1/organizations/members",
        headers=admin_a_headers,
        json={
            "email": "analista@org-a.com.br",
            "full_name": "Analista Org A",
            "password": "AnalystPassword!123",
            "role": "SECURITY_ANALYST",
        },
    )
    assert add_analyst.status_code == 201
    assert add_analyst.json()["role"] == "SECURITY_ANALYST"

    add_viewer = client.post(
        "/api/v1/organizations/members",
        headers=admin_a_headers,
        json={
            "email": "viewer@org-a.com.br",
            "full_name": "Viewer Org A",
            "password": "ViewerPassword!123",
            "role": "VIEWER",
        },
    )
    assert add_viewer.status_code == 201
    assert add_viewer.json()["role"] == "VIEWER"

    # 3. Login do Viewer e do Analista
    viewer_login = client.post(
        "/api/v1/auth/login",
        json={"email": "viewer@org-a.com.br", "password": "ViewerPassword!123"},
    )
    viewer_headers = {"Authorization": f"Bearer {viewer_login.json()['access_token']}"}

    analyst_login = client.post(
        "/api/v1/auth/login",
        json={"email": "analista@org-a.com.br", "password": "AnalystPassword!123"},
    )
    analyst_headers = {"Authorization": f"Bearer {analyst_login.json()['access_token']}"}

    # 4. Viewer NÃO pode cadastrar ativo (403 Forbidden) nem consultar audit-logs (403)
    viewer_create_asset = client.post(
        "/api/v1/assets",
        headers=viewer_headers,
        json={
            "name": "API Pagamentos",
            "target_url": "https://api.org-a.com.br",
            "asset_type": "REST_API",
            "environment": "PRODUCTION",
            "owner_name": "Time Pagamentos",
            "owner_email": "pagamentos@org-a.com.br",
        },
    )
    assert viewer_create_asset.status_code == 403

    viewer_audit = client.get("/api/v1/audit-logs", headers=viewer_headers)
    assert viewer_audit.status_code == 403

    # 5. Analista PODE cadastrar ativo e consultar audit-logs, mas NÃO pode deletar ativo (apenas ADMIN)
    analyst_create_asset = client.post(
        "/api/v1/assets",
        headers=analyst_headers,
        json={
            "name": "API Pagamentos Org A",
            "target_url": "https://api.org-a.com.br",
            "asset_type": "REST_API",
            "environment": "STAGING",
            "owner_name": "Time Pagamentos",
            "owner_email": "pagamentos@org-a.com.br",
            "tags": ["financeiro", "api"],
        },
    )
    assert analyst_create_asset.status_code == 201
    asset_a_id = analyst_create_asset.json()["id"]

    analyst_delete = client.delete(f"/api/v1/assets/{asset_a_id}", headers=analyst_headers)
    assert analyst_delete.status_code == 403

    # 6. Cria Organização B totalmente separada (Admin B)
    org_b_resp = client.post(
        "/api/v1/auth/register",
        json={
            "email": "admin@org-b.com.br",
            "password": "AdminBPassword!123",
            "full_name": "Admin Org B",
            "organization_name": "Organização B",
        },
    )
    assert org_b_resp.status_code == 201
    admin_b_headers = {"Authorization": f"Bearer {org_b_resp.json()['access_token']}"}

    # 7. Isolamento estrito: Admin B não enxerga nem acessa o ativo da Organização A
    org_b_assets = client.get("/api/v1/assets", headers=admin_b_headers)
    assert org_b_assets.status_code == 200
    assert org_b_assets.json() == []

    cross_tenant_get = client.get(f"/api/v1/assets/{asset_a_id}", headers=admin_b_headers)
    assert cross_tenant_get.status_code == 404

    cross_tenant_switch = client.post(
        "/api/v1/auth/switch-organization",
        headers=admin_b_headers,
        json={"organization_id": org_a_id},
    )
    assert cross_tenant_switch.status_code == 403
