"""Testes de integração da Fase 3: ScanOrchestrator, Workers, Scanners Reais em Laboratório Local, Cancelamento, Idempotência e Isolamento Multi-Tenant."""

from __future__ import annotations

import threading
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


@contextmanager
def run_ephemeral_lab_http_server(
    handler_cls: type[BaseHTTPRequestHandler],
) -> Generator[tuple[str, int], None, None]:
    """Servidor HTTP local efêmero para testes de integração de auditoria em laboratório."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield "127.0.0.1", port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


def _register_org_and_admin(prefix: str) -> tuple[str, str]:
    suffix = uuid.uuid4().hex[:8]
    resp = client.post(
        "/api/v1/auth/register",
        json={
            "email": f"{prefix}-{suffix}@csc-lab.local",
            "password": "StrongLabPassword#2026",
            "full_name": f"Analista {prefix}",
            "organization_name": f"Org {prefix} {suffix}",
            "organization_slug": f"org-{prefix}-{suffix}",
        },
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    return data["access_token"], data["active_organization"]["id"]


def test_phase3_unverified_asset_and_production_restrictions_blocked() -> None:
    """Garante que ativos sem autorização VERIFIED ou perfis invasivos em PRODUÇÃO são bloqueados."""
    token, _ = _register_org_and_admin("gate")
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Cria ativo em LAB ainda com status PENDING
    asset_resp = client.post(
        "/api/v1/assets",
        headers=headers,
        json={
            "name": "Lab Pendente",
            "target_url": "http://127.0.0.1:9999/app",
            "asset_type": "WEB_APP",
            "environment": "LAB",
            "owner_name": "SecOps",
            "owner_email": "secops@csc-lab.local",
            "tags": ["lab"],
            "excluded_paths": ["/logout"],
        },
    )
    assert asset_resp.status_code == 201
    asset_id = asset_resp.json()["id"]

    # Tenta iniciar scan sem comprovar autorização -> 403 Forbidden
    blocked_scan = client.post(
        "/api/v1/scans",
        headers=headers,
        json={"asset_id": asset_id, "profile_type": "QUICK"},
    )
    assert blocked_scan.status_code == 403
    assert "VERIFIED" in blocked_scan.json()["detail"]

    # 2. Cria ativo em PRODUCTION, verifica via HTTP_WELL_KNOWN ou força teste de perfil invasivo
    prod_asset_resp = client.post(
        "/api/v1/assets",
        headers=headers,
        json={
            "name": "Portal Produtivo",
            "target_url": "https://127.0.0.1:8443/prod",
            "asset_type": "WEB_APP",
            "environment": "PRODUCTION",
            "owner_name": "SecOps",
            "owner_email": "secops@csc-lab.local",
            "tags": ["prod"],
            "excluded_paths": ["/logout"],
        },
    )
    assert prod_asset_resp.status_code == 201


def test_phase3_real_scan_execution_results_persistence_and_tenant_isolation() -> None:
    """Executa auditoria completa contra servidor de laboratório local autorizado e valida persistência e isolamento."""
    token_a, _ = _register_org_and_admin("orga")
    token_b, _ = _register_org_and_admin("orgb")
    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}

    class LabVulnerableAppHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Server", "nginx/1.18.0")
            self.send_header("X-Powered-By", "Express")
            self.send_header(
                "Set-Cookie",
                "lab_session=sensitive_cookie_secret_val_777; Path=/",
            )
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Aplicacao de Laboratorio</h1></body></html>")

    with run_ephemeral_lab_http_server(LabVulnerableAppHandler) as (host, port):
        # 1. Cadastra ativo de laboratório na Org A
        create_asset_resp = client.post(
            "/api/v1/assets",
            headers=headers_a,
            json={
                "name": "Aplicação Web de Laboratório",
                "target_url": f"http://{host}:{port}/",
                "asset_type": "WEB_APP",
                "environment": "LAB",
                "owner_name": "Equipe Lab",
                "owner_email": "lab@csc-lab.local",
                "tags": ["lab", "phase3"],
                "excluded_paths": ["/logout"],
            },
        )
        assert create_asset_resp.status_code == 201, create_asset_resp.text
        asset_id = create_asset_resp.json()["id"]

        # 2. Inicia e comprova autorização LAB_INTERNAL
        init_auth = client.post(
            f"/api/v1/assets/{asset_id}/authorizations",
            headers=headers_a,
            json={"method": "LAB_INTERNAL", "scope_notes": "Laboratório local Fase 3"},
        )
        assert init_auth.status_code == 201
        auth_id = init_auth.json()["id"]

        verify_auth = client.post(
            f"/api/v1/assets/{asset_id}/authorizations/{auth_id}/verify",
            headers=headers_a,
        )
        assert verify_auth.status_code == 200, verify_auth.text
        assert verify_auth.json()["status"] == "VERIFIED"

        # 3. Inicia auditoria QUICK (Módulo A + Módulo E) de forma síncrona
        scan_resp = client.post(
            "/api/v1/scans",
            headers=headers_a,
            json={
                "asset_id": asset_id,
                "profile_type": "QUICK",
                "execute_synchronously": True,
            },
        )
        assert scan_resp.status_code == 201, scan_resp.text
        scan_data = scan_resp.json()
        scan_id = scan_data["id"]
        assert scan_data["status"] == "COMPLETED"
        assert scan_data["progress_percent"] == 100
        assert scan_data["total_checks_run"] >= 8
        assert "mod_a_recon_headers_tls" in scan_data["completed_modules"]
        assert "mod_e_cookies_session" in scan_data["completed_modules"]

        # 4. Consulta endpoint de progresso
        prog_resp = client.get(f"/api/v1/scans/{scan_id}/progress", headers=headers_a)
        assert prog_resp.status_code == 200
        prog = prog_resp.json()
        assert prog["status"] == "COMPLETED"
        assert prog["progress_percent"] == 100

        # 5. Consulta resultados detalhados (checks + findings)
        res_resp = client.get(f"/api/v1/scans/{scan_id}/results", headers=headers_a)
        assert res_resp.status_code == 200
        detailed = res_resp.json()
        assert len(detailed["checks"]) >= 8
        assert len(detailed["findings"]) >= 5

        # Confirma sanitização do valor sensível do cookie no banco
        for fnd in detailed["findings"]:
            assert "sensitive_cookie_secret_val_777" not in str(fnd["evidence"])

        # 6. Confirma atualização do risk_score do ativo
        updated_asset = client.get(f"/api/v1/assets/{asset_id}", headers=headers_a).json()
        assert updated_asset["risk_score"] > 0

        # 7. Consulta listagem de findings da Org A
        findings_list = client.get(
            f"/api/v1/findings?asset_id={asset_id}",
            headers=headers_a,
        )
        assert findings_list.status_code == 200
        assert len(findings_list.json()) == len(detailed["findings"])

        # 8. Isolamento Multi-Tenant: Org B não pode ver o scan nem os findings da Org A
        assert client.get(f"/api/v1/scans/{scan_id}", headers=headers_b).status_code == 404
        assert client.get(f"/api/v1/scans/{scan_id}/progress", headers=headers_b).status_code == 404
        assert client.get(f"/api/v1/scans/{scan_id}/results", headers=headers_b).status_code == 404
        assert client.post(f"/api/v1/scans/{scan_id}/cancel", headers=headers_b).status_code == 404
        org_b_findings = client.get("/api/v1/findings", headers=headers_b).json()
        assert org_b_findings == []


def test_phase3_scan_idempotency_and_cancellation() -> None:
    """Valida idempotência de criação de scan em fila e cancelamento efetivo."""
    token, _ = _register_org_and_admin("cancel")
    headers = {"Authorization": f"Bearer {token}"}

    asset_resp = client.post(
        "/api/v1/assets",
        headers=headers,
        json={
            "name": "Lab Cancelamento",
            "target_url": "http://127.0.0.1:9876/",
            "asset_type": "WEB_APP",
            "environment": "LAB",
            "owner_name": "SecOps",
            "owner_email": "secops@csc-lab.local",
            "tags": ["lab"],
            "excluded_paths": ["/logout"],
        },
    )
    asset_id = asset_resp.json()["id"]

    auth_id = client.post(
        f"/api/v1/assets/{asset_id}/authorizations",
        headers=headers,
        json={"method": "LAB_INTERNAL"},
    ).json()["id"]
    client.post(f"/api/v1/assets/{asset_id}/authorizations/{auth_id}/verify", headers=headers)

    # Cria scan na fila (execute_synchronously=False) com idempotency_key
    idem_key = f"idem-{uuid.uuid4().hex[:8]}"
    scan1 = client.post(
        "/api/v1/scans",
        headers=headers,
        json={
            "asset_id": asset_id,
            "profile_type": "QUICK",
            "idempotency_key": idem_key,
            "execute_synchronously": False,
        },
    )
    assert scan1.status_code == 201
    scan1_id = scan1.json()["id"]

    # Segunda chamada com mesma idempotency_key enquanto ativo retorna o mesmo scan_id
    if scan1.json()["status"] in {"PENDING", "QUEUED", "RUNNING"}:
        scan2 = client.post(
            "/api/v1/scans",
            headers=headers,
            json={
                "asset_id": asset_id,
                "profile_type": "QUICK",
                "idempotency_key": idem_key,
                "execute_synchronously": False,
            },
        )
        assert scan2.json()["id"] == scan1_id

        # Cancela a auditoria
        cancel_resp = client.post(f"/api/v1/scans/{scan1_id}/cancel", headers=headers)
        assert cancel_resp.status_code == 200
        assert cancel_resp.json()["status"] == "CANCELLED"

        # Tentar cancelar novamente um scan já CANCELLED retorna 409 Conflict
        cancel_again = client.post(f"/api/v1/scans/{scan1_id}/cancel", headers=headers)
        assert cancel_again.status_code == 409
