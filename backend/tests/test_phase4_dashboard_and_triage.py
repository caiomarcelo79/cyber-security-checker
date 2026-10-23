"""Testes de integração da Fase 4: Dashboard SOC enriquecido, Filtros Avançados e Triagem de Vulnerabilidades (TM-016)."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from fastapi.testclient import TestClient


class _Phase4LabHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        return

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Server", "Apache/2.4.49")
        self.send_header("Set-Cookie", "sid=secret_val_999; Path=/")
        self.end_headers()
        self.wfile.write(b"<html><body>Phase 4 Lab Target</body></html>")


def _register_and_headers(client: TestClient, email: str, org_name: str) -> dict[str, str]:
    resp = client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "password": "StrongPassword!2026",
            "full_name": "SecOps Phase 4 Lead",
            "organization_name": org_name,
        },
    )
    assert resp.status_code == 201, resp.text
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_phase4_dashboard_aggregations_advanced_filters_and_finding_triage(
    client: TestClient,
) -> None:
    server = HTTPServer(("127.0.0.1", 0), _Phase4LabHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        admin_headers = _register_and_headers(
            client,
            "admin.phase4@secops.local",
            "Org Phase 4 SOC",
        )

        # Cria um membro VIEWER e um membro DEVELOPER na mesma organização
        add_viewer = client.post(
            "/api/v1/organizations/members",
            headers=admin_headers,
            json={
                "email": "viewer.phase4@secops.local",
                "full_name": "Viewer User",
                "password": "StrongPassword!2026",
                "role": "VIEWER",
            },
        )
        assert add_viewer.status_code == 201

        add_dev = client.post(
            "/api/v1/organizations/members",
            headers=admin_headers,
            json={
                "email": "dev.phase4@secops.local",
                "full_name": "Developer User",
                "password": "StrongPassword!2026",
                "role": "DEVELOPER",
            },
        )
        assert add_dev.status_code == 201

        # Login no contexto da organização principal
        viewer_login = client.post(
            "/api/v1/auth/login",
            json={
                "email": "viewer.phase4@secops.local",
                "password": "StrongPassword!2026",
            },
        )
        viewer_headers = {"Authorization": f"Bearer {viewer_login.json()['access_token']}"}

        dev_login = client.post(
            "/api/v1/auth/login",
            json={
                "email": "dev.phase4@secops.local",
                "password": "StrongPassword!2026",
            },
        )
        dev_headers = {"Authorization": f"Bearer {dev_login.json()['access_token']}"}

        # Cadastra ativo LAB, valida autorização e executa auditoria real
        asset_resp = client.post(
            "/api/v1/assets",
            headers=admin_headers,
            json={
                "name": "Portal Financeiro Lab",
                "target_url": f"http://127.0.0.1:{port}",
                "asset_type": "WEB_APP",
                "environment": "LAB",
                "owner_name": "Squad Financeiro",
                "owner_email": "fin@secops.local",
                "tags": ["financeiro", "critico"],
                "excluded_paths": ["/logout"],
            },
        )
        assert asset_resp.status_code == 201
        asset_id = asset_resp.json()["id"]

        ch_resp = client.post(
            f"/api/v1/assets/{asset_id}/authorizations",
            headers=admin_headers,
            json={"method": "LAB_INTERNAL", "scope_notes": "Lab autorizado Fase 4"},
        )
        auth_id = ch_resp.json()["id"]
        ver_resp = client.post(
            f"/api/v1/assets/{asset_id}/authorizations/{auth_id}/verify",
            headers=admin_headers,
        )
        assert ver_resp.status_code == 200

        scan_resp = client.post(
            "/api/v1/scans",
            headers=admin_headers,
            json={
                "asset_id": asset_id,
                "profile_type": "QUICK",
                "execute_synchronously": True,
            },
        )
        assert scan_resp.status_code == 201
        scan_data = scan_resp.json()
        assert scan_data["status"] == "COMPLETED"

        # 1. Verifica agregações reais no Dashboard SOC (/api/v1/dashboard/summary)
        dash_resp = client.get("/api/v1/dashboard/summary", headers=admin_headers)
        assert dash_resp.status_code == 200
        dash = dash_resp.json()
        assert dash["total_assets"] == 1
        assert dash["verified_assets"] == 1
        assert dash["total_scans_executed"] == 1
        assert dash["open_vulnerabilities"] > 0
        assert dash["treatment_status_counts"]["OPEN"] == dash["open_vulnerabilities"]
        assert len(dash["top_risky_assets"]) == 1
        assert dash["top_risky_assets"][0]["id"] == asset_id
        assert dash["top_risky_assets"][0]["risk_score"] > 0
        assert len(dash["owasp_category_distribution"]) > 0
        assert len(dash["cwe_distribution"]) > 0
        assert len(dash["recent_scans"]) == 1

        initial_risk_score = dash["top_risky_assets"][0]["risk_score"]
        initial_open_count = dash["open_vulnerabilities"]

        # 2. Testa filtros avançados em GET /api/v1/findings
        all_findings = client.get("/api/v1/findings", headers=admin_headers).json()
        assert len(all_findings) == initial_open_count

        # Filtro por CWE-319 (transporte HTTP claro / HSTS)
        cwe_filtered = client.get(
            "/api/v1/findings?cwe_id=CWE-319",
            headers=admin_headers,
        ).json()
        assert len(cwe_filtered) >= 1
        assert all(any("CWE-319" in c for c in f["cwe_ids"]) for f in cwe_filtered)

        # Filtro textual (search)
        search_filtered = client.get(
            "/api/v1/findings?search=Content-Security-Policy",
            headers=admin_headers,
        ).json()
        assert len(search_filtered) >= 1

        target_finding_id = all_findings[0]["id"]

        # Consulta individual GET /api/v1/findings/{finding_id}
        single_resp = client.get(f"/api/v1/findings/{target_finding_id}", headers=admin_headers)
        assert single_resp.status_code == 200
        assert single_resp.json()["id"] == target_finding_id

        # 3. VIEWER não pode alterar status de triagem (403 Forbidden)
        forbidden_triage = client.patch(
            f"/api/v1/findings/{target_finding_id}/status",
            headers=viewer_headers,
            json={"treatment_status": "MITIGATED", "triage_note": "Tentativa por viewer"},
        )
        assert forbidden_triage.status_code == 403

        # 4. DEVELOPER pode realizar triagem de vulnerabilidades
        for fnd in all_findings:
            triage_resp = client.patch(
                f"/api/v1/findings/{fnd['id']}/status",
                headers=dev_headers,
                json={
                    "treatment_status": "MITIGATED",
                    "triage_note": "Corrigido no proxy reverso Nginx em homologação.",
                },
            )
            assert triage_resp.status_code == 200
            updated_fnd = triage_resp.json()
            assert updated_fnd["treatment_status"] == "MITIGATED"
            assert updated_fnd["triage_note"] == "Corrigido no proxy reverso Nginx em homologação."
            assert updated_fnd["resolved_at"] is not None

        # 5. Verifica que o risk_score do ativo caiu para 0 após mitigar todas as vulnerabilidades
        dash_after = client.get("/api/v1/dashboard/summary", headers=admin_headers).json()
        assert dash_after["open_vulnerabilities"] == 0
        assert dash_after["treatment_status_counts"]["MITIGATED"] == initial_open_count
        assert dash_after["top_risky_assets"][0]["risk_score"] == 0
        assert dash_after["top_risky_assets"][0]["risk_score"] < initial_risk_score

        # Filtro por treatment_status=MITIGATED retorna todas as mitigadas
        mitigated_list = client.get(
            "/api/v1/findings?treatment_status=MITIGATED",
            headers=admin_headers,
        ).json()
        assert len(mitigated_list) == initial_open_count

        # Verifica registro em AuditLog
        logs_resp = client.get("/api/v1/audit-logs", headers=admin_headers)
        assert logs_resp.status_code == 200
        actions = [entry["action"] for entry in logs_resp.json()]
        assert "FINDING_STATUS_UPDATED" in actions
    finally:
        server.shutdown()
        server.server_close()
