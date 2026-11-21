"""Testes para triagem assistida por IA, citação de evidências e fallback resiliente (Fase 5.1)."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from test_network_telemetry import sensor  # noqa: F401
from test_ssh_audits import register

from app.core.config import get_settings
from app.models.entities import Asset, FindingRecord, Organization, Scan
from app.services import ai_triage_service

BASE_TIME = datetime(2026, 11, 20, 14, 0, tzinfo=UTC)


def _create_traffic_alert_run(client: TestClient, source: dict) -> tuple[str, str]:
    resp = client.post(
        f"/api/v1/telemetry/sources/{source['id']}/traffic-analyses",
        headers={"Authorization": f"Bearer {source['collector_token']}"},
        json={
            "connections": [
                {
                    "uid": f"CT{port}",
                    "observed_at": BASE_TIME.isoformat(),
                    "origin_ip": "192.168.50.10",
                    "origin_port": 44000 + port,
                    "responder_ip": "198.51.100.40",
                    "responder_port": port,
                    "transport": "tcp",
                    "origin_bytes": 64,
                }
                for port in (21, 22, 80, 443, 8000, 8080, 8443, 9000)
            ]
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    return body["id"], body["alerts"][0]["id"]


def _seed_finding(db_session: Session, asset_id: str) -> FindingRecord:
    asset = db_session.get(Asset, asset_id)
    assert asset is not None
    org = db_session.get(Organization, asset.organization_id)
    assert org is not None
    scan = Scan(
        organization_id=org.id,
        asset_id=asset.id,
        profile_type="QUICK",
        status="COMPLETED",
        enabled_modules=["mod_a_recon_headers_tls"],
        total_checks_run=1,
        findings_summary={"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
    )
    db_session.add(scan)
    db_session.flush()
    finding = FindingRecord(
        organization_id=org.id,
        asset_id=asset.id,
        scan_id=scan.id,
        fingerprint="fp-hsts-missing-1",
        module_id="mod_a_recon_headers_tls",
        check_id="CHK-A05",
        title="Ausência de cabeçalho Strict-Transport-Security (HSTS)",
        description="A resposta HTTPS do alvo não declara cabeçalho Strict-Transport-Security.",
        category="Security Headers",
        result_classification="VULNERABILITY",
        severity="HIGH",
        confidence="CERTAIN",
        cwe_ids=["CWE-319"],
        owasp_categories=["A05:2021"],
        affected_endpoint="http://lab-target/login",
        evidence={
            "request_method": "GET",
            "request_url": "http://lab-target/login?token=super-secret-jwt-999",
            "response_status_code": 200,
            "observed_value": "Strict-Transport-Security ausente com Bearer raw-secret-token-777",
        },
        impact="Permite downgrade de conexão para HTTP em texto claro.",
        reproduction_steps=["Acessar a URL inicial e inspecionar cabeçalhos."],
        remediation_data={
            "how_to_fix": "Configurar Strict-Transport-Security com max-age >= 31536000.",
            "how_to_validate": "Confirmar presença do cabeçalho via requisição HTTPS.",
        },
        treatment_status="OPEN",
    )
    db_session.add(finding)
    db_session.commit()
    return finding


def test_deterministic_triage_for_traffic_alert_and_finding_cites_sanitized_evidence(
    client: TestClient,
    db_session: Session,
    sensor: tuple[dict[str, str], str, str, dict],  # noqa: F811
) -> None:
    operator, _, _, source = sensor
    asset_id = client.get("/api/v1/assets", headers=operator).json()[0]["id"]
    run_id, alert_id = _create_traffic_alert_run(client, source)

    triage_url = (
        f"/api/v1/assets/{asset_id}/traffic-analyses/{run_id}/alerts/{alert_id}/triage-suggestion"
    )
    assert client.get(triage_url, headers=operator).json() is None

    created = client.post(triage_url, headers=operator)
    assert created.status_code == 201, created.text
    suggestion = created.json()
    assert suggestion["target_type"] == "TRAFFIC_ALERT"
    assert suggestion["generation_mode"] == "DETERMINISTIC_FALLBACK"
    assert suggestion["ai_status"] == "UNCONFIGURED"
    assert suggestion["review_status"] == "PENDING_REVIEW"
    assert suggestion["requires_analyst_review"] is True
    assert suggestion["recommended_action"] == "CONTAIN"
    assert len(suggestion["remediation_steps"]) >= 3
    citation_fields = {item["field"]: item["value_excerpt"] for item in suggestion["evidence_citations"]}
    assert citation_fields["origin_ip"] == "192.168.50.10"
    assert citation_fields["distinct_ports_count"] == "8"
    assert "192.168.50.10" in suggestion["summary"]
    assert len(suggestion["sanitized_evidence_hash"]) == 64

    loaded = client.get(triage_url, headers=operator)
    assert loaded.status_code == 200 and loaded.json()["id"] == suggestion["id"]

    finding = _seed_finding(db_session, asset_id)
    finding_url = f"/api/v1/findings/{finding.id}/triage-suggestion"
    finding_resp = client.post(finding_url, headers=operator)
    assert finding_resp.status_code == 201, finding_resp.text
    finding_body = finding_resp.json()
    assert finding_body["target_type"] == "FINDING"
    assert finding_body["recommended_action"] == "REMEDIATE"
    assert "Configurar Strict-Transport-Security" in finding_body["remediation_steps"][0]
    assert "raw-secret-token-777" not in finding_body["summary"]
    assert "[REDACTED_TOKEN]" in finding_body["summary"]
    db_session.expire(finding)
    refreshed = db_session.get(FindingRecord, finding.id)
    assert refreshed is not None and refreshed.treatment_status == "OPEN"

    actions = [entry["action"] for entry in client.get("/api/v1/audit-logs", headers=operator).json()]
    assert actions.count("AI_TRIAGE_SUGGESTION_GENERATED") == 2


def test_ai_provider_grounded_output_accepted_and_ungrounded_rejected(
    client: TestClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
    sensor: tuple[dict[str, str], str, str, dict],  # noqa: F811
) -> None:
    operator, _, _, _ = sensor
    asset_id = client.get("/api/v1/assets", headers=operator).json()[0]["id"]
    finding = _seed_finding(db_session, asset_id)
    sent_payloads: list[dict[str, Any]] = []

    ai_settings = SimpleNamespace(
        ai_triage_enabled=True,
        ai_triage_endpoint_url="http://127.0.0.1:19999/v1/triage",
        ai_triage_model="local-soc-llm",
        ai_triage_timeout_seconds=2.0,
        ai_triage_api_key="test-provider-key",
    )
    monkeypatch.setattr(ai_triage_service, "get_settings", lambda: ai_settings)

    class GroundedResp:
        status_code = 200

        def json(self) -> dict[str, Any]:
            return {
                "model_name": "local-soc-llm",
                "summary": "Ativo lab-target em response_status_code 200 sem HSTS no login.",
                "explanation": "Cabeçalho Strict-Transport-Security ausente conforme observed_value.",
                "recommended_action": "REMEDIATE",
                "remediation_steps": [
                    "Ativar Strict-Transport-Security max-age=31536000 no servidor web.",
                    "Revalidar cabeçalho em conexão HTTPS.",
                ],
                "evidence_citations": [
                    {"field": "response_status_code", "value_excerpt": "200"},
                    {"field": "observed_value", "value_excerpt": "Strict-Transport-Security ausente"},
                ],
            }

    def fake_grounded_post(url: str, *, json: dict[str, Any], **_kwargs: Any) -> GroundedResp:
        sent_payloads.append(json)
        return GroundedResp()

    monkeypatch.setattr(ai_triage_service.httpx, "post", fake_grounded_post)
    ok = client.post(f"/api/v1/findings/{finding.id}/triage-suggestion", headers=operator)
    assert ok.status_code == 201, ok.text
    ok_body = ok.json()
    assert ok_body["generation_mode"] == "AI_PROVIDER"
    assert ok_body["ai_status"] == "AVAILABLE"
    assert ok_body["model_name"] == "local-soc-llm"
    assert len(sent_payloads) == 1
    assert "raw-secret-token-777" not in str(sent_payloads[0]["sanitized_evidence"])

    class HallucinatedResp:
        status_code = 200

        def json(self) -> dict[str, Any]:
            return {
                "model_name": "local-soc-llm",
                "summary": "Há uma vulnerabilidade crítica inventada sem base real.",
                "explanation": "Texto genérico.",
                "recommended_action": "REMEDIATE",
                "remediation_steps": ["Fazer algo genérico."],
                "evidence_citations": [
                    {"field": "nonexistent_field", "value_excerpt": "inventado"},
                ],
            }

    monkeypatch.setattr(ai_triage_service.httpx, "post", lambda *a, **k: HallucinatedResp())
    rejected = client.post(f"/api/v1/findings/{finding.id}/triage-suggestion", headers=operator)
    assert rejected.status_code == 201, rejected.text
    rej_body = rejected.json()
    assert rej_body["generation_mode"] == "DETERMINISTIC_FALLBACK"
    assert rej_body["ai_status"] == "INVALID_OUTPUT_FALLBACK"
    assert "response_status_code=200" in rej_body["summary"]


def test_resilience_when_ai_provider_is_unavailable_or_blocked_ssrf(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    sensor: tuple[dict[str, str], str, str, dict],  # noqa: F811
) -> None:
    operator, _, _, source = sensor
    asset_id = client.get("/api/v1/assets", headers=operator).json()[0]["id"]

    down_settings = SimpleNamespace(
        ai_triage_enabled=True,
        ai_triage_endpoint_url="http://127.0.0.1:19999/v1/triage",
        ai_triage_model="local-soc-llm",
        ai_triage_timeout_seconds=1.0,
        ai_triage_api_key="",
    )
    monkeypatch.setattr(ai_triage_service, "get_settings", lambda: down_settings)

    def raise_timeout(*_args: Any, **_kwargs: Any) -> Any:
        raise httpx.ConnectTimeout("timeout simulado")

    monkeypatch.setattr(ai_triage_service.httpx, "post", raise_timeout)

    run_id, alert_id = _create_traffic_alert_run(client, source)
    triage_url = (
        f"/api/v1/assets/{asset_id}/traffic-analyses/{run_id}/alerts/{alert_id}/triage-suggestion"
    )
    fallback = client.post(triage_url, headers=operator)
    assert fallback.status_code == 201, fallback.text
    body = fallback.json()
    assert body["generation_mode"] == "DETERMINISTIC_FALLBACK"
    assert body["ai_status"] == "UNAVAILABLE"
    assert "192.168.50.10" in body["summary"]

    ssrf_settings = SimpleNamespace(
        ai_triage_enabled=True,
        ai_triage_endpoint_url="http://169.254.169.254/latest/meta-data/",
        ai_triage_model="local-soc-llm",
        ai_triage_timeout_seconds=1.0,
        ai_triage_api_key="",
    )
    monkeypatch.setattr(ai_triage_service, "get_settings", lambda: ssrf_settings)
    called: list[str] = []
    monkeypatch.setattr(ai_triage_service.httpx, "post", lambda url, **_k: called.append(url))

    blocked = client.post(triage_url, headers=operator)
    assert blocked.status_code == 201
    assert blocked.json()["ai_status"] == "UNAVAILABLE"
    assert called == []


def test_rbac_and_multi_tenant_isolation_for_triage_suggestions(
    client: TestClient,
    db_session: Session,
    sensor: tuple[dict[str, str], str, str, dict],  # noqa: F811
) -> None:
    operator, _, _, source = sensor
    asset_id = client.get("/api/v1/assets", headers=operator).json()[0]["id"]
    run_id, alert_id = _create_traffic_alert_run(client, source)
    finding = _seed_finding(db_session, asset_id)

    assert (
        client.post(
            "/api/v1/organizations/members",
            headers=operator,
            json={
                "email": "triage-viewer@lab.local",
                "full_name": "Viewer Triagem",
                "password": "ViewerPassword!2026",
                "role": "VIEWER",
            },
        ).status_code
        == 201
    )
    viewer_login = client.post(
        "/api/v1/auth/login",
        json={"email": "triage-viewer@lab.local", "password": "ViewerPassword!2026"},
    )
    viewer = {"Authorization": f"Bearer {viewer_login.json()['access_token']}"}
    outsider = register(client, "triage-outsider@lab.local")

    alert_url = (
        f"/api/v1/assets/{asset_id}/traffic-analyses/{run_id}/alerts/{alert_id}/triage-suggestion"
    )
    finding_url = f"/api/v1/findings/{finding.id}/triage-suggestion"

    assert client.post(alert_url, headers=viewer).status_code == 403
    assert client.post(finding_url, headers=viewer).status_code == 403
    assert client.post(alert_url, headers=operator).status_code == 201
    assert client.post(finding_url, headers=operator).status_code == 201

    assert client.get(alert_url, headers=viewer).status_code == 200
    assert client.get(finding_url, headers=viewer).status_code == 200
    assert client.get(alert_url, headers=outsider).status_code == 404
    assert client.post(alert_url, headers=outsider).status_code == 404
    assert client.get(finding_url, headers=outsider).status_code == 404
    assert client.post(finding_url, headers=outsider).status_code == 404
    get_settings.cache_clear()


def test_analyst_review_approves_or_rejects_suggestion_with_sanitized_notes_and_audit_log(
    client: TestClient,
    sensor: tuple[dict[str, str], str, str, dict],  # noqa: F811
) -> None:
    operator, _, _, source = sensor
    asset_id = client.get("/api/v1/assets", headers=operator).json()[0]["id"]
    run_id, alert_id = _create_traffic_alert_run(client, source)

    assert (
        client.post(
            "/api/v1/organizations/members",
            headers=operator,
            json={
                "email": "review-viewer@lab.local",
                "full_name": "Viewer Revisao",
                "password": "ViewerPassword!2026",
                "role": "VIEWER",
            },
        ).status_code
        == 201
    )
    viewer_login = client.post(
        "/api/v1/auth/login",
        json={"email": "review-viewer@lab.local", "password": "ViewerPassword!2026"},
    )
    viewer = {"Authorization": f"Bearer {viewer_login.json()['access_token']}"}
    outsider = register(client, "review-outsider@lab.local")

    triage_url = (
        f"/api/v1/assets/{asset_id}/traffic-analyses/{run_id}/alerts/{alert_id}/triage-suggestion"
    )
    suggestion = client.post(triage_url, headers=operator).json()
    review_url = f"/api/v1/triage-suggestions/{suggestion['id']}/review"

    assert client.patch(review_url, headers=viewer, json={"decision": "APPROVED"}).status_code == 403
    assert client.patch(review_url, headers=outsider, json={"decision": "APPROVED"}).status_code == 404
    assert client.patch(review_url, headers=operator, json={"decision": "AUTO_CLOSE"}).status_code == 422

    approved = client.patch(
        review_url,
        headers=operator,
        json={
            "decision": "APPROVED",
            "reviewer_notes": "Validado no host com Bearer secret-review-token-999",
        },
    )
    assert approved.status_code == 200, approved.text
    approved_body = approved.json()
    assert approved_body["review_status"] == "APPROVED"
    assert approved_body["requires_analyst_review"] is False
    assert approved_body["reviewer_user_id"] is not None
    assert approved_body["reviewed_at"] is not None
    assert "secret-review-token-999" not in approved_body["reviewer_notes"]
    assert "[REDACTED_TOKEN]" in approved_body["reviewer_notes"]

    rejected = client.patch(
        review_url,
        headers=operator,
        json={"decision": "REJECTED", "reviewer_notes": "   "},
    )
    assert rejected.status_code == 200
    assert rejected.json()["review_status"] == "REJECTED"
    assert rejected.json()["reviewer_notes"] is None

    actions = [entry["action"] for entry in client.get("/api/v1/audit-logs", headers=operator).json()]
    assert actions.count("AI_TRIAGE_SUGGESTION_REVIEWED") == 2
