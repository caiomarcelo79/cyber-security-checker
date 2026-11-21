"""Testes de ciclo de vida do coletor, gate do piloto e expansão para cliente autorizado (Fase 6)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from test_network_telemetry import connection
from test_ssh_audits import authorize_lab, create_lab_asset, register

from app.models.entities import OrganizationMembership, TelemetryTlsBaseline
from app.services.asset_service import AssetAuthorizationService
from app.services.pilot_logic import (
    SourceLifecycleInput,
    cidr_within_allowed,
    evaluate_pilot_readiness,
)

BASE_TIME = datetime(2026, 11, 20, 15, 0, tzinfo=UTC)


def _switch_to_second_org(
    client: TestClient, headers: dict[str, str], name: str = "Cliente Autorizado S.A."
) -> tuple[dict[str, str], str]:
    created_org = client.post("/api/v1/organizations", headers=headers, json={"name": name})
    assert created_org.status_code == 201, created_org.text
    org_id = created_org.json()["id"]
    switched = client.post(
        "/api/v1/auth/switch-organization",
        headers=headers,
        json={"organization_id": org_id},
    )
    assert switched.status_code == 200, switched.text
    return {"Authorization": f"Bearer {switched.json()['access_token']}"}, org_id


def _create_staging_or_prod_asset(
    client: TestClient,
    headers: dict[str, str],
    *,
    environment: str = "STAGING",
    url: str = "https://client-pilot.example",
) -> dict:
    resp = client.post(
        "/api/v1/assets",
        headers=headers,
        json={
            "name": f"Ativo Cliente {environment}",
            "target_url": url,
            "asset_type": "WEB_APP",
            "environment": environment,
            "owner_name": "SecOps Cliente",
            "owner_email": "secops@cliente.example",
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _verify_http_well_known(
    client: TestClient,
    db_session: Session,
    headers: dict[str, str],
    asset: dict,
) -> str:
    init_resp = client.post(
        f"/api/v1/assets/{asset['id']}/authorizations",
        headers=headers,
        json={"method": "HTTP_WELL_KNOWN", "scope_notes": "Piloto cliente controlado"},
    )
    assert init_resp.status_code == 201, init_resp.text
    auth_data = init_resp.json()
    token = auth_data["verification_token"]

    me = client.get("/api/v1/auth/me", headers=headers).json()
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, text=token)
        if request.url.path == "/.well-known/cyber-security-checker.txt"
        else httpx.Response(404)
    )
    AssetAuthorizationService.verify_authorization(
        db=db_session,
        organization_id=me["active_organization"]["id"],
        user_id=me["user"]["id"],
        asset_id=asset["id"],
        authorization_id=auth_data["id"],
        http_transport=transport,
    )
    return auth_data["id"]


def _traffic_payload(
    *,
    uid_prefix: str = "P6",
    cert_sha256: str = "a" * 64,
    issuer: str = "CN=R10, O=Let's Encrypt, C=US",
    include_sweep: bool = False,
) -> dict:
    base_not_before = (BASE_TIME - timedelta(days=5)).isoformat()
    base_not_after = (BASE_TIME + timedelta(days=85)).isoformat()
    payload: dict = {
        "tls_handshakes": [
            {
                "uid": f"{uid_prefix}TLS1",
                "observed_at": BASE_TIME.isoformat(),
                "client_ip": "192.168.50.10",
                "responder_ip": "198.51.100.80",
                "responder_port": 443,
                "server_name": "app.lab.local",
                "cert_sha256": cert_sha256,
                "subject": "CN=app.lab.local",
                "issuer": issuer,
                "validation_status": "ok",
                "self_signed": False,
                "not_before": base_not_before,
                "not_after": base_not_after,
            }
        ],
        "dns_queries": [
            {
                "uid": f"{uid_prefix}DNS1",
                "observed_at": BASE_TIME.isoformat(),
                "client_ip": "192.168.50.10",
                "responder_ip": "192.168.50.53",
                "query": "app.lab.local",
                "qtype": "A",
                "rcode": "NOERROR",
            }
        ],
        "edr_signals": [
            {
                "uid": f"{uid_prefix}EDR1",
                "observed_at": BASE_TIME.isoformat(),
                "host_ip": "192.168.50.10",
                "source_type": "EDR",
                "signal": "BEACONING_DETECTED" if include_sweep else "SUSPICIOUS_PROCESS",
                "process_name": "python3",
                "detail": "observacao de laboratorio",
            }
        ],
    }
    if include_sweep:
        payload["connections"] = [
            {
                "uid": f"{uid_prefix}C{port}",
                "observed_at": BASE_TIME.isoformat(),
                "origin_ip": "192.168.50.10",
                "origin_port": 44000 + port,
                "responder_ip": "198.51.100.80",
                "responder_port": port,
                "transport": "tcp",
                "origin_bytes": 64,
            }
            for port in (21, 22, 80, 443, 8080)
        ]
    return payload


def test_pilot_logic_cidr_and_readiness_rules() -> None:
    assert cidr_within_allowed("10.20.0.0/25", ["10.20.0.0/24"]) is True
    assert cidr_within_allowed("10.20.0.0/23", ["10.20.0.0/24"]) is False
    assert cidr_within_allowed("0.0.0.0/0", ["0.0.0.0/0"]) is False
    assert cidr_within_allowed("fd00:10::/64", ["fd00:10::/48", "10.20.0.0/24"]) is True
    assert cidr_within_allowed("10.20.0.0/24", ["fd00:10::/48"]) is False

    incomplete = evaluate_pilot_readiness(
        asset_authorization_valid=False,
        pilot_status="PAUSED",
        sources=[SourceLifecycleInput("PAUSED", False, "UPDATE_AVAILABLE", 1)],
        audit_actions={"TELEMETRY_SOURCE_PAUSED"},
        traffic_runs_observed_layers=[],
        benign_rotations_count=0,
        suspicious_alerts_total=0,
        ssh_audits_count=0,
        availability_exercises_total=0,
        availability_exercises_passed=0,
        telemetry_delays_seconds=[],
        availability_alert_pub_ms=[],
        availability_recovery_pub_ms=[],
        triage_review_statuses=[],
        findings_total=0,
        findings_false_positive_count=0,
    )
    assert incomplete.ready_for_expansion_approval is False
    assert incomplete.lifecycle.all_demonstrated is False
    assert len(incomplete.blocking_reasons) >= 7

    complete = evaluate_pilot_readiness(
        asset_authorization_valid=True,
        pilot_status="ACTIVE",
        sources=[SourceLifecycleInput("ACTIVE", True, "UP_TO_DATE", 2)],
        audit_actions={
            "TELEMETRY_SOURCE_PAUSED",
            "TELEMETRY_SOURCE_RESUMED",
            "TELEMETRY_SOURCE_UPDATED",
            "TELEMETRY_SOURCE_REVOKED",
            "TELEMETRY_SOURCE_RECOVERED",
        },
        traffic_runs_observed_layers=[["CONNECTIONS", "DNS", "TLS"], ["CONNECTIONS", "EDR"]],
        benign_rotations_count=1,
        suspicious_alerts_total=1,
        ssh_audits_count=1,
        availability_exercises_total=1,
        availability_exercises_passed=1,
        telemetry_delays_seconds=[1.0, 3.0],
        availability_alert_pub_ms=[20],
        availability_recovery_pub_ms=[15],
        triage_review_statuses=["APPROVED", "REJECTED"],
        findings_total=4,
        findings_false_positive_count=1,
    )
    assert complete.ready_for_expansion_approval is True
    assert complete.blocking_reasons == ()
    assert complete.coverage.layer_coverage_percent == 100.0
    assert complete.latency.telemetry_avg_delay_seconds == 2.0
    assert complete.latency.telemetry_max_delay_seconds == 3.0
    assert complete.false_positives.findings_false_positive_rate_percent == 25.0


def test_source_lifecycle_install_pause_resume_update_revoke_recover(
    client: TestClient,
    db_session: Session,
) -> None:
    operator = register(client, "lifecycle-owner@lab.local")
    asset_url = create_lab_asset(client, operator)
    authorize_lab(client, operator, asset_url)
    sources_url = f"{asset_url}/telemetry-sources"
    created = client.post(
        sources_url,
        headers=operator,
        json={"name": "Sensor do laboratório", "network": "192.168.50.0/24"},
    )
    assert created.status_code == 201, created.text
    source = created.json()
    asset_source_url = f"{sources_url}/{source['id']}"
    ingest_url = f"/api/v1/telemetry/sources/{source['id']}/connections"
    traffic_url = f"/api/v1/telemetry/sources/{source['id']}/traffic-analyses"
    status_url = f"/api/v1/telemetry/sources/{source['id']}"
    heartbeat_url = f"{status_url}/heartbeat"
    collector_headers = {"Authorization": f"Bearer {source['collector_token']}"}

    assert source["status"] == "ACTIVE"
    assert source["update_status"] == "UNKNOWN"
    assert source["config_version"] == 1
    assert source["token_generation"] == 1

    # Instalação e baseline TLS
    assert (
        client.post(
            ingest_url, headers=collector_headers, json={"events": [connection("CInstall")]}
        ).status_code
        == 200
    )
    first_analysis = client.post(
        traffic_url, headers=collector_headers, json=_traffic_payload(uid_prefix="R1")
    )
    assert first_analysis.status_code == 201, first_analysis.text
    assert first_analysis.json()["tls_decisions"][0]["outcome"] == "BASELINE_ESTABLISHED"

    # Pausa e bloqueio imediato de ingestão mantendo status legível para retomada
    paused = client.post(f"{asset_source_url}/pause", headers=operator)
    assert paused.status_code == 200, paused.text
    assert paused.json()["status"] == "PAUSED"
    assert (
        client.post(
            ingest_url, headers=collector_headers, json={"events": [connection("CPaused")]}
        ).status_code
        == 409
    )
    assert (
        client.post(
            traffic_url, headers=collector_headers, json=_traffic_payload(uid_prefix="RP")
        ).status_code
        == 409
    )
    collector_status = client.get(status_url, headers=collector_headers)
    assert collector_status.status_code == 200
    assert collector_status.json()["status"] == "PAUSED"

    # Retomada e deduplicação
    resumed = client.post(f"{asset_source_url}/resume", headers=operator)
    assert resumed.status_code == 200, resumed.text
    assert resumed.json()["status"] == "ACTIVE"
    replay = client.post(
        ingest_url, headers=collector_headers, json={"events": [connection("CInstall")]}
    )
    assert replay.status_code == 200
    assert replay.json() == {"inserted": 0, "duplicates": 1}

    # Atualização de configuração/versão desejada e heartbeat
    updated = client.patch(
        asset_source_url,
        headers=operator,
        json={"desired_version": "1.1.0", "poll_interval_seconds": 5},
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["config_version"] == 2
    assert updated.json()["update_status"] == "UPDATE_AVAILABLE"

    hb = client.post(
        heartbeat_url,
        headers=collector_headers,
        json={"collector_version": "1.1.0", "applied_config_version": 2},
    )
    assert hb.status_code == 200, hb.text
    assert hb.json()["update_status"] == "UP_TO_DATE"
    assert hb.json()["collector_version"] == "1.1.0"
    assert hb.json()["applied_config_version"] == 2

    # Revogação e bloqueio
    assert client.delete(asset_source_url, headers=operator).status_code == 204
    assert (
        client.post(
            ingest_url, headers=collector_headers, json={"events": [connection("CRevoked")]}
        ).status_code
        == 401
    )
    assert client.post(f"{asset_source_url}/resume", headers=operator).status_code == 409

    # Recuperação mantendo baseline TLS e invalidando token antigo
    recovered = client.post(f"{asset_source_url}/recover", headers=operator)
    assert recovered.status_code == 200, recovered.text
    rec_body = recovered.json()
    assert rec_body["id"] == source["id"]
    assert rec_body["status"] == "ACTIVE"
    assert rec_body["token_generation"] == 2
    assert rec_body["collector_token"] != source["collector_token"]
    assert (
        client.post(
            ingest_url, headers=collector_headers, json={"events": [connection("COldToken")]}
        ).status_code
        == 401
    )

    new_headers = {"Authorization": f"Bearer {rec_body['collector_token']}"}
    rotated = client.post(
        traffic_url,
        headers=new_headers,
        json=_traffic_payload(uid_prefix="R2", cert_sha256="b" * 64),
    )
    assert rotated.status_code == 201, rotated.text
    assert rotated.json()["benign_rotations_count"] == 1
    assert rotated.json()["tls_decisions"][0]["outcome"] == "BENIGN_ROTATION"
    assert db_session.query(TelemetryTlsBaseline).count() == 1


def test_own_environment_pilot_gate_and_readiness_review(client: TestClient) -> None:
    operator = register(client, "pilot-own@lab.local")
    asset_url = create_lab_asset(client, operator)
    asset_id = asset_url.rsplit("/", 1)[-1]
    authorize_lab(client, operator, asset_url)

    pilot_resp = client.post(
        "/api/v1/pilots",
        headers=operator,
        json={
            "asset_id": asset_id,
            "stage": "OWN_ENVIRONMENT",
            "allowed_cidrs": ["192.168.50.0/24"],
            "enabled_capabilities": [
                "TELEMETRY",
                "TRAFFIC_ANALYSIS",
                "SSH_AUDIT",
                "AI_TRIAGE",
            ],
            "max_sources": 2,
            "expires_in_days": 30,
            "scope_notes": "Piloto inicial em laboratório isolado Bearer secret-note-999",
        },
    )
    assert pilot_resp.status_code == 201, pilot_resp.text
    pilot = pilot_resp.json()
    assert "[REDACTED" in (pilot["scope_notes"] or "")
    assert "secret-note-999" not in (pilot["scope_notes"] or "")

    # Impede duplicidade para o mesmo ativo enquanto ativo/pausado
    dup_resp = client.post(
        "/api/v1/pilots",
        headers=operator,
        json={
            "asset_id": asset_id,
            "stage": "OWN_ENVIRONMENT",
            "allowed_cidrs": ["192.168.50.0/24"],
            "enabled_capabilities": ["TELEMETRY"],
            "max_sources": 1,
        },
    )
    assert dup_resp.status_code == 409

    # Aprovação prematura bloqueada até demonstrar marcos e métricas
    premature = client.post(
        f"/api/v1/pilots/{pilot['id']}/reviews",
        headers=operator,
        json={
            "decision": "APPROVED_FOR_EXPANSION",
            "coverage_ok": True,
            "latency_ok": True,
            "false_positives_ok": True,
        },
    )
    assert premature.status_code == 422

    # Revisão intermediária NEEDS_ADJUSTMENT permitida
    interim = client.post(
        f"/api/v1/pilots/{pilot['id']}/reviews",
        headers=operator,
        json={
            "decision": "NEEDS_ADJUSTMENT",
            "coverage_ok": False,
            "latency_ok": True,
            "false_positives_ok": True,
            "notes": "Completar ciclo de revogação e recuperação antes de expandir.",
        },
    )
    assert interim.status_code == 201

    # Cadastra fonte e executa ciclo completo + análise + triagem IA + SSH
    src = client.post(
        f"{asset_url}/telemetry-sources",
        headers=operator,
        json={"name": "Coletor piloto", "network": "192.168.50.0/24"},
    ).json()
    src_url = f"{asset_url}/telemetry-sources/{src['id']}"
    col_headers = {"Authorization": f"Bearer {src['collector_token']}"}

    assert (
        client.post(
            f"/api/v1/telemetry/sources/{src['id']}/connections",
            headers=col_headers,
            json={"events": [connection("CP1")]},
        ).status_code
        == 200
    )
    analysis = client.post(
        f"/api/v1/telemetry/sources/{src['id']}/traffic-analyses",
        headers=col_headers,
        json=_traffic_payload(uid_prefix="P6FULL", include_sweep=True),
    )
    assert analysis.status_code == 201, analysis.text
    run_data = analysis.json()
    alert_id = run_data["alerts"][0]["id"]

    triage = client.post(
        f"{asset_url}/traffic-analyses/{run_data['id']}/alerts/{alert_id}/triage-suggestion",
        headers=operator,
    )
    assert triage.status_code == 201
    assert (
        client.patch(
            f"/api/v1/triage-suggestions/{triage.json()['id']}/review",
            headers=operator,
            json={"decision": "APPROVED", "reviewer_notes": "Alerta confirmado no piloto"},
        ).status_code
        == 200
    )
    assert (
        client.post(
            f"{asset_url}/ssh-audit",
            headers=operator,
            json={
                "hostname": "lab-target",
                "password_authentication": "disabled",
                "permit_root_login": "no",
            },
        ).status_code
        == 201
    )

    assert client.post(f"{src_url}/pause", headers=operator).status_code == 200
    assert client.post(f"{src_url}/resume", headers=operator).status_code == 200
    assert (
        client.patch(
            src_url,
            headers=operator,
            json={"desired_version": "1.1.0", "poll_interval_seconds": 3},
        ).status_code
        == 200
    )
    assert (
        client.post(
            f"/api/v1/telemetry/sources/{src['id']}/heartbeat",
            headers=col_headers,
            json={"collector_version": "1.1.0", "applied_config_version": 2},
        ).status_code
        == 200
    )
    assert client.delete(src_url, headers=operator).status_code == 204
    assert client.post(f"{src_url}/recover", headers=operator).status_code == 200

    readiness = client.get(f"/api/v1/pilots/{pilot['id']}/readiness", headers=operator)
    assert readiness.status_code == 200, readiness.text
    rd = readiness.json()
    assert rd["ready_for_expansion_approval"] is True
    assert rd["lifecycle"]["all_demonstrated"] is True
    assert rd["coverage"]["layer_coverage_percent"] == 100.0
    assert rd["coverage"]["ssh_audits_count"] == 1
    assert rd["latency"]["telemetry_samples_count"] >= 1
    assert rd["false_positives"]["triage_approved_count"] == 1
    assert rd["blocking_reasons"] == []

    approved = client.post(
        f"/api/v1/pilots/{pilot['id']}/reviews",
        headers=operator,
        json={
            "decision": "APPROVED_FOR_EXPANSION",
            "coverage_ok": True,
            "latency_ok": True,
            "false_positives_ok": True,
            "notes": "Pronto para expansão em cliente com escopo restrito.",
        },
    )
    assert approved.status_code == 201, approved.text
    assert approved.json()["metrics_snapshot"]["coverage"]["layer_coverage_percent"] == 100.0

    listed = client.get("/api/v1/pilots", headers=operator).json()
    assert listed[0]["latest_review_decision"] == "APPROVED_FOR_EXPANSION"


def _approve_own_pilot(client: TestClient, operator: dict[str, str]) -> str:
    asset_url = create_lab_asset(client, operator)
    asset_id = asset_url.rsplit("/", 1)[-1]
    authorize_lab(client, operator, asset_url)
    pilot = client.post(
        "/api/v1/pilots",
        headers=operator,
        json={
            "asset_id": asset_id,
            "stage": "OWN_ENVIRONMENT",
            "allowed_cidrs": ["192.168.50.0/24"],
            "enabled_capabilities": ["TELEMETRY", "TRAFFIC_ANALYSIS"],
            "max_sources": 2,
        },
    ).json()
    src = client.post(
        f"{asset_url}/telemetry-sources",
        headers=operator,
        json={"name": "Base lab", "network": "192.168.50.0/24"},
    ).json()
    src_url = f"{asset_url}/telemetry-sources/{src['id']}"
    col = {"Authorization": f"Bearer {src['collector_token']}"}
    client.post(
        f"/api/v1/telemetry/sources/{src['id']}/connections",
        headers=col,
        json={"events": [connection("CBase1")]},
    )
    client.post(
        f"/api/v1/telemetry/sources/{src['id']}/traffic-analyses",
        headers=col,
        json=_traffic_payload(uid_prefix="BASE"),
    )
    client.post(f"{src_url}/pause", headers=operator)
    client.post(f"{src_url}/resume", headers=operator)
    client.patch(src_url, headers=operator, json={"desired_version": "1.1.0"})
    client.delete(src_url, headers=operator)
    client.post(f"{src_url}/recover", headers=operator)
    rev = client.post(
        f"/api/v1/pilots/{pilot['id']}/reviews",
        headers=operator,
        json={
            "decision": "APPROVED_FOR_EXPANSION",
            "coverage_ok": True,
            "latency_ok": True,
            "false_positives_ok": True,
        },
    )
    assert rev.status_code == 201, rev.text
    return pilot["id"]


def test_authorized_client_expansion_strict_scope_rbac_and_isolation(
    client: TestClient, db_session: Session
) -> None:
    admin_org1 = register(client, "expansion-admin@secops.local")
    own_asset_url = create_lab_asset(client, admin_org1, hostname="lab-target")
    own_asset_id = own_asset_url.rsplit("/", 1)[-1]
    authorize_lab(client, admin_org1, own_asset_url)
    unapproved_own = client.post(
        "/api/v1/pilots",
        headers=admin_org1,
        json={
            "asset_id": own_asset_id,
            "stage": "OWN_ENVIRONMENT",
            "allowed_cidrs": ["192.168.50.0/24"],
            "enabled_capabilities": ["TELEMETRY"],
            "max_sources": 1,
        },
    ).json()

    org2_headers, _ = _switch_to_second_org(client, admin_org1)
    client_asset = _create_staging_or_prod_asset(client, org2_headers, environment="STAGING")
    prod_asset = _create_staging_or_prod_asset(
        client, org2_headers, environment="PRODUCTION", url="https://prod-client.example"
    )

    # Sem pré-requisito aprovado -> 422; sem autorização DNS/HTTP -> 403
    assert (
        client.post(
            "/api/v1/pilots",
            headers=org2_headers,
            json={
                "asset_id": client_asset["id"],
                "stage": "AUTHORIZED_CLIENT",
                "allowed_cidrs": ["10.20.0.0/24"],
                "enabled_capabilities": ["TELEMETRY"],
            },
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/api/v1/pilots",
            headers=org2_headers,
            json={
                "asset_id": client_asset["id"],
                "stage": "AUTHORIZED_CLIENT",
                "prerequisite_pilot_id": unapproved_own["id"],
                "allowed_cidrs": ["10.20.0.0/24"],
                "enabled_capabilities": ["TELEMETRY"],
            },
        ).status_code
        == 422
    )

    # Aprova piloto em ambiente próprio numa 3ª org gerida pelo mesmo usuário (ou org própria)
    # e verifica pré-requisito antes da comprovação HTTP_WELL_KNOWN do ativo cliente
    org3_headers, _ = _switch_to_second_org(client, admin_org1, name="Operacao Interna")
    approved_own_id = _approve_own_pilot(client, org3_headers)

    assert (
        client.post(
            "/api/v1/pilots",
            headers=org2_headers,
            json={
                "asset_id": client_asset["id"],
                "stage": "AUTHORIZED_CLIENT",
                "prerequisite_pilot_id": approved_own_id,
                "allowed_cidrs": ["10.20.0.0/24"],
                "enabled_capabilities": ["TELEMETRY"],
            },
        ).status_code
        == 403
    )

    # Verifica autorização HTTP_WELL_KNOWN para staging e production do cliente
    client_auth_id = _verify_http_well_known(client, db_session, org2_headers, client_asset)
    _verify_http_well_known(client, db_session, org2_headers, prod_asset)

    # Bloqueia AVAILABILITY em produção
    assert (
        client.post(
            "/api/v1/pilots",
            headers=org2_headers,
            json={
                "asset_id": prod_asset["id"],
                "stage": "AUTHORIZED_CLIENT",
                "prerequisite_pilot_id": approved_own_id,
                "allowed_cidrs": ["10.30.0.0/24"],
                "enabled_capabilities": ["TELEMETRY", "AVAILABILITY"],
            },
        ).status_code
        == 422
    )

    # RBAC: SECURITY_ANALYST não habilita cliente e VIEWER não muta piloto
    analyst_added = client.post(
        "/api/v1/organizations/members",
        headers=org2_headers,
        json={
            "full_name": "Analista Cliente",
            "email": "analyst-client@secops.local",
            "password": "AnalystPassword!2026",
            "role": "SECURITY_ANALYST",
        },
    )
    assert analyst_added.status_code == 201
    analyst_headers = {
        "Authorization": "Bearer "
        + client.post(
            "/api/v1/auth/login",
            json={"email": "analyst-client@secops.local", "password": "AnalystPassword!2026"},
        ).json()["access_token"]
    }
    assert (
        client.post(
            "/api/v1/pilots",
            headers=analyst_headers,
            json={
                "asset_id": client_asset["id"],
                "stage": "AUTHORIZED_CLIENT",
                "prerequisite_pilot_id": approved_own_id,
                "allowed_cidrs": ["10.20.0.0/24"],
                "enabled_capabilities": ["TELEMETRY"],
            },
        ).status_code
        == 403
    )

    # Admin habilita cliente autorizado com escopo estrito
    enabled = client.post(
        "/api/v1/pilots",
        headers=org2_headers,
        json={
            "asset_id": client_asset["id"],
            "stage": "AUTHORIZED_CLIENT",
            "prerequisite_pilot_id": approved_own_id,
            "allowed_cidrs": ["10.20.0.0/24"],
            "enabled_capabilities": ["TELEMETRY", "TRAFFIC_ANALYSIS"],
            "max_sources": 1,
            "expires_in_days": 15,
            "scope_notes": "Segmento homologado do cliente",
        },
    )
    assert enabled.status_code == 201, enabled.text
    client_pilot = enabled.json()

    # Fora do CIDR -> 422; dentro do CIDR -> 201; 2ª fonte além de max_sources=1 -> 409
    assert (
        client.post(
            f"/api/v1/assets/{client_asset['id']}/telemetry-sources",
            headers=org2_headers,
            json={"name": "Fora do CIDR", "network": "10.99.0.0/24"},
        ).status_code
        == 422
    )
    src_resp = client.post(
        f"/api/v1/assets/{client_asset['id']}/telemetry-sources",
        headers=org2_headers,
        json={"name": "Sensor Cliente 1", "network": "10.20.0.0/25"},
    )
    assert src_resp.status_code == 201, src_resp.text
    src = src_resp.json()
    assert (
        client.post(
            f"/api/v1/assets/{client_asset['id']}/telemetry-sources",
            headers=org2_headers,
            json={"name": "Excesso", "network": "10.20.0.128/25"},
        ).status_code
        == 409
    )

    # Redução de CIDR incompatível com fonte existente -> 409
    assert (
        client.patch(
            f"/api/v1/pilots/{client_pilot['id']}",
            headers=org2_headers,
            json={"allowed_cidrs": ["10.20.1.0/24"]},
        ).status_code
        == 409
    )

    # Capacidade fora do escopo -> 403
    assert (
        client.post(
            f"/api/v1/assets/{client_asset['id']}/ssh-audit",
            headers=org2_headers,
            json={"hostname": "client-pilot.example", "password_authentication": "disabled"},
        ).status_code
        == 403
    )

    # Telemetria + análise dentro do escopo funcionam
    col_headers = {"Authorization": f"Bearer {src['collector_token']}"}
    assert (
        client.post(
            f"/api/v1/telemetry/sources/{src['id']}/connections",
            headers=col_headers,
            json={"events": [connection("Client1", origin_ip="10.20.0.10")]},
        ).status_code
        == 200
    )

    # Isolamento multi-tenant
    outsider = register(client, "outsider-pilot@other.local")
    assert client.get(f"/api/v1/pilots/{client_pilot['id']}", headers=outsider).status_code == 404
    outsider_asset = _create_staging_or_prod_asset(client, outsider, url="https://other.example")
    _verify_http_well_known(client, db_session, outsider, outsider_asset)
    assert (
        client.post(
            "/api/v1/pilots",
            headers=outsider,
            json={
                "asset_id": outsider_asset["id"],
                "stage": "AUTHORIZED_CLIENT",
                "prerequisite_pilot_id": approved_own_id,
                "allowed_cidrs": ["10.40.0.0/24"],
                "enabled_capabilities": ["TELEMETRY"],
            },
        ).status_code
        == 403
    )

    # Pausa do piloto bloqueia imediatamente e retomada libera; revogação bloqueia definitivamente
    assert (
        client.post(f"/api/v1/pilots/{client_pilot['id']}/pause", headers=org2_headers).status_code
        == 200
    )
    assert (
        client.post(
            f"/api/v1/telemetry/sources/{src['id']}/connections",
            headers=col_headers,
            json={"events": [connection("ClientPaused", origin_ip="10.20.0.10")]},
        ).status_code
        == 403
    )
    assert (
        client.post(f"/api/v1/pilots/{client_pilot['id']}/resume", headers=org2_headers).status_code
        == 200
    )
    assert (
        client.post(
            f"/api/v1/telemetry/sources/{src['id']}/connections",
            headers=col_headers,
            json={"events": [connection("ClientResumed", origin_ip="10.20.0.10")]},
        ).status_code
        == 200
    )

    # Revogar autorização do alvo também bloqueia coleta do cliente
    assert (
        client.post(
            f"/api/v1/assets/{client_asset['id']}/authorizations/{client_auth_id}/revoke",
            headers=org2_headers,
        ).status_code
        == 200
    )
    assert (
        client.post(
            f"/api/v1/telemetry/sources/{src['id']}/connections",
            headers=col_headers,
            json={"events": [connection("ClientAuthRevoked", origin_ip="10.20.0.10")]},
        ).status_code
        == 403
    )

    # Confirmar bloqueio também ao tentar referenciar UUID inexistente
    assert (
        client.get(f"/api/v1/pilots/{uuid4()}/readiness", headers=org2_headers).status_code == 404
    )

    # Verificar que membro VIEWER não muta revisões ou ciclo de vida
    client.post(
        "/api/v1/organizations/members",
        headers=org2_headers,
        json={
            "full_name": "Leitor Cliente",
            "email": "viewer-client@secops.local",
            "password": "ViewerPassword!2026",
            "role": "VIEWER",
        },
    )
    viewer_headers = {
        "Authorization": "Bearer "
        + client.post(
            "/api/v1/auth/login",
            json={"email": "viewer-client@secops.local", "password": "ViewerPassword!2026"},
        ).json()["access_token"]
    }
    assert (
        client.post(
            f"/api/v1/pilots/{client_pilot['id']}/revoke", headers=viewer_headers
        ).status_code
        == 403
    )
    assert (
        client.get(
            f"/api/v1/pilots/{client_pilot['id']}/readiness", headers=viewer_headers
        ).status_code
        == 200
    )
    assert (
        client.post(f"/api/v1/pilots/{client_pilot['id']}/revoke", headers=org2_headers).status_code
        == 200
    )
    # Após revogar piloto, membership/outros estados permanecem íntegros
    assert (
        db_session.query(OrganizationMembership)
        .filter(OrganizationMembership.role == "ADMIN")
        .count()
        >= 1
    )
