"""Testes da Fase 4 (TM-016b): paginação no servidor, histórico, deduplicação, SSE e isolamento."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from fastapi.testclient import TestClient


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        return

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Server", "Apache/2.4.49")
        self.end_headers()
        self.wfile.write(b"<html><body>Lab UI APIs</body></html>")


def _register(client: TestClient, email: str, org: str) -> dict[str, str]:
    resp = client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "password": "StrongPassword!2026",
            "full_name": "Analista UI",
            "organization_name": org,
        },
    )
    assert resp.status_code == 201, resp.text
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def _verified_asset(client: TestClient, headers: dict[str, str], port: int) -> str:
    asset = client.post(
        "/api/v1/assets",
        headers=headers,
        json={
            "name": "Portal UI Lab",
            "target_url": f"http://127.0.0.1:{port}",
            "asset_type": "WEB_APP",
            "environment": "LAB",
            "owner_name": "Squad",
            "owner_email": "sq@secops.local",
            "tags": [],
            "excluded_paths": [],
        },
    )
    assert asset.status_code == 201, asset.text
    asset_id = asset.json()["id"]
    auth = client.post(
        f"/api/v1/assets/{asset_id}/authorizations",
        headers=headers,
        json={"method": "LAB_INTERNAL", "scope_notes": "Lab"},
    )
    assert auth.status_code == 201
    ver = client.post(
        f"/api/v1/assets/{asset_id}/authorizations/{auth.json()['id']}/verify",
        headers=headers,
    )
    assert ver.status_code == 200
    return asset_id


def _run_scan(client: TestClient, headers: dict[str, str], asset_id: str) -> dict:
    resp = client.post(
        "/api/v1/scans",
        headers=headers,
        json={"asset_id": asset_id, "profile_type": "QUICK", "execute_synchronously": True},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_phase4_pagination_history_dedup_sse_and_isolation(client: TestClient) -> None:
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        headers = _register(client, "ui.admin@secops.local", "Org UI APIs")
        other = _register(client, "ui.other@secops.local", "Org Outra")
        asset_id = _verified_asset(client, headers, port)

        scan1 = _run_scan(client, headers, asset_id)
        page = client.get("/api/v1/findings/page?limit=2&offset=0", headers=headers).json()
        total_after_first = page["total"]
        assert total_after_first > 2 and len(page["items"]) == 2 and page["limit"] == 2
        page2 = client.get("/api/v1/findings/page?limit=2&offset=2", headers=headers).json()
        assert {i["id"] for i in page["items"]}.isdisjoint({i["id"] for i in page2["items"]})

        # Ordenação por severidade (servidor) e busca textual
        by_sev = client.get(
            "/api/v1/findings/page?sort_by=severity&sort_desc=true&limit=100", headers=headers
        ).json()["items"]
        rank = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
        ranks = [rank[i["severity"]] for i in by_sev]
        assert ranks == sorted(ranks, reverse=True)
        assert by_sev[0]["asset_name"] == "Portal UI Lab"
        found = client.get(
            "/api/v1/findings/page?search=Content-Security-Policy", headers=headers
        ).json()
        assert found["total"] >= 1

        # Triagem de um achado e reincidência: nova auditoria NÃO duplica contagem e herda estado
        target = by_sev[0]
        client.patch(
            f"/api/v1/findings/{target['id']}/status",
            headers=headers,
            json={"treatment_status": "FALSE_POSITIVE", "triage_note": "Confirmado como FP."},
        )
        _run_scan(client, headers, asset_id)
        after = client.get("/api/v1/findings/page?limit=100", headers=headers).json()
        assert after["total"] == total_after_first  # deduplicado por (ativo, fingerprint)
        fp_items = [i for i in after["items"] if i["fingerprint"] == target["fingerprint"]]
        assert len(fp_items) == 1 and fp_items[0]["treatment_status"] == "FALSE_POSITIVE"
        assert fp_items[0]["id"] != target["id"]
        dash = client.get("/api/v1/dashboard/summary", headers=headers).json()
        assert dash["total_scans_executed"] == 2
        assert dash["scan_status_counts"].get("COMPLETED") == 2
        assert dash["treatment_status_counts"]["FALSE_POSITIVE"] == 1
        assert dash["open_vulnerabilities"] == total_after_first - 1
        top = dash["top_risky_assets"][0]
        assert top["open_findings_count"] == dash["open_vulnerabilities"]
        assert top["last_scan_at"] is not None

        # Histórico: duas detecções + evento de triagem
        hist = client.get(f"/api/v1/findings/{fp_items[0]['id']}/history", headers=headers).json()
        assert len(hist["detections"]) == 2
        assert any(e["new_status"] == "FALSE_POSITIVE" for e in hist["triage_events"])

        # Auditorias paginadas, filtradas e eventos
        sp = client.get("/api/v1/scans/page?status=COMPLETED&limit=1", headers=headers).json()
        assert sp["total"] == 2 and len(sp["items"]) == 1
        assert client.get("/api/v1/scans/page?status=FAILED", headers=headers).json()["total"] == 0
        assert client.get("/api/v1/scans/page?search=Portal UI", headers=headers).json()["total"] == 2
        events = client.get(f"/api/v1/scans/{scan1['id']}/events", headers=headers).json()
        assert any(e["action"] == "SCAN_CREATED" for e in events)

        # Tendências persistidas
        trends = client.get("/api/v1/dashboard/trends?days=7", headers=headers).json()
        assert len(trends["points"]) == 7
        assert sum(p["scans"] for p in trends["points"]) == 2
        assert sum(p["detected"] for p in trends["points"]) == total_after_first

        # SSE: auditoria concluída emite progresso + fim; sem token → 401/403; outra org → 404
        with client.stream("GET", f"/api/v1/scans/{scan1['id']}/stream", headers=headers) as resp:
            assert resp.status_code == 200
            body = "".join(resp.iter_text())
        assert "event: progress" in body and "event: end" in body
        data_line = next(ln for ln in body.splitlines() if ln.startswith('data: {"scan_id"'))
        payload = json.loads(data_line[6:])
        assert payload["status"] == "COMPLETED" and payload["progress_percent"] == 100
        client.cookies.clear()
        assert client.get(f"/api/v1/scans/{scan1['id']}/stream").status_code in (401, 403)
        assert client.get(f"/api/v1/scans/{scan1['id']}/stream", headers=other).status_code == 404

        # Isolamento entre organizações
        assert client.get("/api/v1/findings/page", headers=other).json()["total"] == 0
        assert client.get("/api/v1/scans/page", headers=other).json()["total"] == 0
        assert client.get(f"/api/v1/findings/{target['id']}/history", headers=other).status_code == 404
        assert client.get("/api/v1/dashboard/trends", headers=other).json()["points"][-1]["scans"] == 0
    finally:
        server.shutdown()
        server.server_close()
