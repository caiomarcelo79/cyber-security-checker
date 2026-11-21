"""Testes das regras explicáveis e da API de detecção de tráfego suspeito."""

from datetime import UTC, datetime, timedelta
from hashlib import sha256

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session
from test_network_telemetry import sensor  # noqa: F401
from test_ssh_audits import register

from app.models.entities import TelemetryTlsBaseline, TrafficAnalysisRun
from app.services.suspicious_traffic_logic import (
    ConnectionEvent,
    DnsEvent,
    TlsBaselineState,
    TlsEvent,
    evaluate_connections,
    evaluate_dns,
    evaluate_tls,
)

BASE_TIME = datetime(2026, 11, 20, 12, 0, tzinfo=UTC)


def _fp(seed: str) -> str:
    return sha256(seed.encode("utf-8")).hexdigest()


def _conn_payload(
    uid: str,
    port: int,
    *,
    origin_ip: str = "192.168.50.10",
    responder_ip: str = "198.51.100.20",
) -> dict:
    return {
        "uid": uid,
        "observed_at": BASE_TIME.isoformat(),
        "origin_ip": origin_ip,
        "origin_port": 45000 + (port % 1000),
        "responder_ip": responder_ip,
        "responder_port": port,
        "transport": "tcp",
        "origin_bytes": 120,
    }


def _dns_payload(
    uid: str,
    query: str,
    rcode: str = "NOERROR",
    *,
    client_ip: str = "192.168.50.15",
) -> dict:
    return {
        "uid": uid,
        "observed_at": BASE_TIME.isoformat(),
        "client_ip": client_ip,
        "responder_ip": "192.168.50.2",
        "query": query,
        "qtype": "A",
        "rcode": rcode,
    }


def _tls_payload(
    uid: str,
    cert_sha256: str,
    issuer: str,
    *,
    offset_hours: int = 0,
    server_name: str = "api.lab.internal",
    validation_status: str = "ok",
    self_signed: bool = False,
    not_after_days: int = 90,
) -> dict:
    observed = BASE_TIME + timedelta(hours=offset_hours)
    return {
        "uid": uid,
        "observed_at": observed.isoformat(),
        "client_ip": "192.168.50.25",
        "responder_ip": "198.51.100.30",
        "responder_port": 443,
        "server_name": server_name,
        "cert_sha256": cert_sha256,
        "subject": f"CN={server_name}",
        "issuer": issuer,
        "validation_status": validation_status,
        "self_signed": self_signed,
        "not_before": (observed - timedelta(days=1)).isoformat(),
        "not_after": (observed + timedelta(days=not_after_days)).isoformat(),
    }


def test_connection_rules_distinguish_benign_sweep_and_burst() -> None:
    normal = [
        ConnectionEvent(f"CN{idx}", BASE_TIME, "192.168.50.10", 40000 + idx, "198.51.100.1", port, "tcp")
        for idx, port in enumerate((80, 443, 8443))
    ]
    assert evaluate_connections(normal) == []

    sweep = [
        ConnectionEvent(f"CS{port}", BASE_TIME, "192.168.50.10", 41000 + port, "198.51.100.1", port, "tcp")
        for port in (21, 22, 25, 80, 443, 8080, 8443, 9000)
    ]
    sweep_alerts = evaluate_connections(sweep)
    assert len(sweep_alerts) == 1
    assert sweep_alerts[0].rule_id == "CONNECTION_PORT_SWEEP"
    assert sweep_alerts[0].confidence == "HIGH"
    assert sweep_alerts[0].evidence["distinct_ports_count"] == 8

    burst = [
        ConnectionEvent(f"CB{idx}", BASE_TIME, "192.168.50.11", 50000 + idx, "198.51.100.2", 443, "tcp")
        for idx in range(12)
    ]
    burst_alerts = evaluate_connections(burst)
    assert len(burst_alerts) == 1
    assert burst_alerts[0].rule_id == "CONNECTION_REPEATED_BURST"
    assert burst_alerts[0].confidence == "MEDIUM"
    assert burst_alerts[0].evidence["connection_count"] == 12


def test_dns_rules_avoid_false_positive_on_normal_names_and_detect_dga_nxdomain() -> None:
    legit = [
        DnsEvent("DL1", BASE_TIME, "192.168.50.15", "192.168.50.2", "api-gateway-v2.lab.internal", "A", "NOERROR"),
        DnsEvent("DL2", BASE_TIME, "192.168.50.15", "192.168.50.2", "auth.lab.internal", "A", "NOERROR"),
        DnsEvent("DL3", BASE_TIME, "192.168.50.15", "192.168.50.2", "missing.lab.internal", "A", "NXDOMAIN"),
    ]
    assert evaluate_dns(legit) == []

    suspicious = [
        DnsEvent(
            f"DN{idx}",
            BASE_TIME,
            "192.168.50.99",
            "192.168.50.2",
            f"x9k2m7q4z1w8c3v5b6n0r2t4p7y{idx}.dga.lab.internal",
            "A",
            "NXDOMAIN",
        )
        for idx in range(5)
    ]
    alerts = evaluate_dns(suspicious)
    rules = {item.rule_id: item for item in alerts}
    assert set(rules) == {"DNS_NXDOMAIN_BURST", "DNS_HIGH_ENTROPY_QUERY"}
    assert rules["DNS_NXDOMAIN_BURST"].confidence == "MEDIUM"
    assert rules["DNS_HIGH_ENTROPY_QUERY"].confidence == "HIGH"
    assert rules["DNS_HIGH_ENTROPY_QUERY"].evidence["combined_with_nxdomain"] is True


def test_tls_distinguishes_benign_rotation_from_interception_and_unexpected_ca() -> None:
    fp_initial = _fp("cert-v1")
    fp_rotated = _fp("cert-v2")
    fp_wrong_ca = _fp("cert-other-ca")

    baseline = {
        ("api.lab.internal", "198.51.100.30", 443): TlsBaselineState(
            server_name="api.lab.internal",
            responder_ip="198.51.100.30",
            responder_port=443,
            cert_sha256=fp_initial,
            subject="CN=api.lab.internal",
            issuer="CN=R10, O=Let's Encrypt, C=US",
            not_before=BASE_TIME - timedelta(days=5),
            not_after=BASE_TIME + timedelta(days=60),
        )
    }

    rotation_event = TlsEvent(
        uid="TRot1",
        observed_at=BASE_TIME + timedelta(hours=1),
        client_ip="192.168.50.25",
        responder_ip="198.51.100.30",
        responder_port=443,
        server_name="api.lab.internal",
        cert_sha256=fp_rotated,
        subject="CN=api.lab.internal",
        issuer="CN=R11, O=Let's Encrypt, C=US",
        validation_status="ok",
        self_signed=False,
        not_before=BASE_TIME,
        not_after=BASE_TIME + timedelta(days=90),
    )
    alerts, decisions, updated, benign_count = evaluate_tls([rotation_event], baseline)
    assert alerts == []
    assert benign_count == 1
    assert decisions[0].outcome == "BENIGN_ROTATION"
    assert updated[("api.lab.internal", "198.51.100.30", 443)].cert_sha256 == fp_rotated

    unexpected_ca_event = TlsEvent(
        uid="TCA1",
        observed_at=BASE_TIME + timedelta(hours=2),
        client_ip="192.168.50.25",
        responder_ip="198.51.100.30",
        responder_port=443,
        server_name="api.lab.internal",
        cert_sha256=fp_wrong_ca,
        subject="CN=api.lab.internal",
        issuer="CN=Root, O=Unknown Intercept Corp, C=XX",
        validation_status="ok",
        self_signed=False,
        not_before=BASE_TIME,
        not_after=BASE_TIME + timedelta(days=120),
    )
    ca_alerts, ca_decisions, kept, ca_benign = evaluate_tls([unexpected_ca_event], updated)
    assert ca_benign == 0
    assert ca_decisions[0].outcome == "INTERCEPTION_ALERT"
    assert len(ca_alerts) == 1
    assert ca_alerts[0].confidence == "MEDIUM"
    assert "unexpected_issuer_change" in ca_alerts[0].evidence["reasons"]
    assert kept[("api.lab.internal", "198.51.100.30", 443)].cert_sha256 == fp_rotated


def test_api_tls_rotation_vs_interception_coverage_and_persistence(
    client: TestClient,
    db_session: Session,
    sensor: tuple[dict[str, str], str, str, dict],  # noqa: F811
) -> None:
    operator, _, _, source = sensor
    asset_id = client.get("/api/v1/assets", headers=operator).json()[0]["id"]
    analyze_url = f"/api/v1/telemetry/sources/{source['id']}/traffic-analyses"
    collector = {"Authorization": f"Bearer {source['collector_token']}"}
    fp_a, fp_b, fp_rogue = _fp("le-a"), _fp("le-b"), _fp("rogue")

    first = client.post(
        analyze_url,
        headers=collector,
        json={"tls_handshakes": [_tls_payload("TT1", fp_a, "CN=R10, O=Let's Encrypt, C=US")]},
    )
    assert first.status_code == 201, first.text
    first_body = first.json()
    assert first_body["coverage"] == {
        "observed_layers": ["TLS"],
        "missing_layers": ["CONNECTIONS", "DNS", "EDR"],
    }
    assert first_body["alerts_count"] == 0
    assert first_body["benign_rotations_count"] == 0
    assert first_body["tls_decisions"][0]["outcome"] == "BASELINE_ESTABLISHED"

    second = client.post(
        analyze_url,
        headers=collector,
        json={
            "tls_handshakes": [
                _tls_payload("TT2", fp_b, "CN=R11, O=Let's Encrypt, C=US", offset_hours=1, not_after_days=120)
            ]
        },
    )
    assert second.status_code == 201, second.text
    second_body = second.json()
    assert second_body["alerts_count"] == 0
    assert second_body["benign_rotations_count"] == 1
    assert second_body["tls_decisions"][0]["outcome"] == "BENIGN_ROTATION"

    third = client.post(
        analyze_url,
        headers=collector,
        json={
            "tls_handshakes": [
                _tls_payload(
                    "TT3",
                    fp_rogue,
                    "CN=Intercept Bearer secret-token-99999, O=Rogue Proxy",
                    offset_hours=2,
                    validation_status="self signed certificate",
                    self_signed=True,
                )
            ]
        },
    )
    assert third.status_code == 201, third.text
    third_body = third.json()
    assert third_body["alerts_count"] == 1
    assert third_body["tls_decisions"][0]["outcome"] == "INTERCEPTION_ALERT"
    alert = third_body["alerts"][0]
    assert alert["rule_id"] == "TLS_POSSIBLE_INTERCEPTION"
    assert alert["severity"] == "HIGH" and alert["confidence"] == "HIGH"
    assert alert["evidence"]["previous_cert_sha256"] == fp_b
    assert alert["evidence"]["observed_cert_sha256"] == fp_rogue
    assert "secret-token-99999" not in alert["evidence"]["observed_issuer"]
    assert "[REDACTED_TOKEN]" in alert["evidence"]["observed_issuer"]

    baseline_row = db_session.scalar(
        select(TelemetryTlsBaseline).where(TelemetryTlsBaseline.source_id == source["id"])
    )
    assert baseline_row is not None
    assert baseline_row.cert_sha256 == fp_b
    assert baseline_row.rotation_count == 1

    runs = client.get(f"/api/v1/assets/{asset_id}/traffic-analyses", headers=operator)
    assert runs.status_code == 200
    assert len(runs.json()) == 3
    detail = client.get(f"/api/v1/assets/{asset_id}/traffic-analyses/{third_body['id']}", headers=operator)
    assert detail.status_code == 200 and detail.json()["id"] == third_body["id"]


def test_api_all_layers_scope_validation_limits_and_isolation(
    client: TestClient,
    db_session: Session,
    sensor: tuple[dict[str, str], str, str, dict],  # noqa: F811
) -> None:
    operator, sources_url, authorization_url, source = sensor
    asset_id = client.get("/api/v1/assets", headers=operator).json()[0]["id"]
    analyze_url = f"/api/v1/telemetry/sources/{source['id']}/traffic-analyses"
    list_url = f"/api/v1/assets/{asset_id}/traffic-analyses"
    collector = {"Authorization": f"Bearer {source['collector_token']}"}
    outsider = register(client, "traffic-outsider@lab.local")

    full_run = client.post(
        analyze_url,
        headers=collector,
        json={
            "connections": [_conn_payload(f"C{p}", p) for p in (22, 80, 443, 8000, 8080)],
            "dns_queries": [_dns_payload(f"D{i}", f"missing-{i}.lab.internal", "NXDOMAIN") for i in range(4)],
            "tls_handshakes": [_tls_payload("T1", _fp("ok-cert"), "CN=R10, O=Lab CA")],
        },
    )
    assert full_run.status_code == 201, full_run.text
    full_body = full_run.json()
    assert full_body["coverage"] == {
        "observed_layers": ["CONNECTIONS", "DNS", "TLS"],
        "missing_layers": ["EDR"],
    }
    assert {a["rule_id"] for a in full_body["alerts"]} == {"CONNECTION_PORT_SWEEP", "DNS_NXDOMAIN_BURST"}
    assert client.get(sources_url, headers=operator).json()[0]["connection_count"] == 5

    actions = [entry["action"] for entry in client.get("/api/v1/audit-logs", headers=operator).json()]
    assert "TRAFFIC_ANALYSIS_EXECUTED" in actions

    assert client.post(analyze_url, headers=collector, json={}).status_code == 422
    assert client.post(analyze_url, headers=collector, content=b"x" * (256 * 1024 + 1)).status_code == 413
    out_of_scope = client.post(
        analyze_url,
        headers=collector,
        json={
            "dns_queries": [
                {
                    "uid": "DOut1",
                    "observed_at": BASE_TIME.isoformat(),
                    "client_ip": "203.0.113.50",
                    "responder_ip": "198.51.100.53",
                    "query": "example.invalid",
                    "qtype": "A",
                    "rcode": "NOERROR",
                }
            ]
        },
    )
    assert out_of_scope.status_code == 422
    assert len(db_session.scalars(select(TrafficAnalysisRun)).all()) == 1

    assert client.post(analyze_url, headers=operator, json={"dns_queries": [_dns_payload("DOp", "ok.lab", "NOERROR")]}).status_code == 401
    assert client.get(list_url, headers=collector).status_code == 401
    assert client.get(list_url, headers=outsider).status_code == 404
    assert client.get(f"{list_url}/{full_body['id']}", headers=outsider).status_code == 404

    assert client.delete(f"{sources_url}/{source['id']}", headers=operator).status_code == 204
    assert client.post(analyze_url, headers=collector, json={"dns_queries": [_dns_payload("DRev", "ok.lab", "NOERROR")]}).status_code == 401

    second = client.post(
        sources_url, headers=operator, json={"name": "Segundo sensor", "network": "192.168.50.0/24"}
    ).json()
    second_url = f"/api/v1/telemetry/sources/{second['id']}/traffic-analyses"
    second_collector = {"Authorization": f"Bearer {second['collector_token']}"}
    assert client.post(f"{authorization_url}/revoke", headers=operator).status_code == 200
    assert (
        client.post(
            second_url,
            headers=second_collector,
            json={"dns_queries": [_dns_payload("DScope", "ok.lab", "NOERROR")]},
        ).status_code
        == 403
    )


def test_edr_signals_correlate_with_alerts_elevate_confidence_and_enforce_cidr_scope(
    client: TestClient,
    sensor: tuple[dict[str, str], str, str, dict],  # noqa: F811
) -> None:
    operator, _, _, source = sensor
    asset_id = client.get("/api/v1/assets", headers=operator).json()[0]["id"]
    analyze_url = f"/api/v1/telemetry/sources/{source['id']}/traffic-analyses"
    collector = {"Authorization": f"Bearer {source['collector_token']}"}

    response = client.post(
        analyze_url,
        headers=collector,
        json={
            "connections": [
                _conn_payload(f"CE{p}", p, origin_ip="192.168.50.10")
                for p in (22, 80, 443, 8000, 8080)
            ],
            "dns_queries": [
                _dns_payload(f"DE{i}", f"missing-{i}.lab.internal", "NXDOMAIN", client_ip="192.168.50.15")
                for i in range(4)
            ],
            "tls_handshakes": [_tls_payload("TE1", _fp("ok-cert"), "CN=R10, O=Lab CA")],
            "edr_signals": [
                {
                    "uid": "EDR1",
                    "observed_at": BASE_TIME.isoformat(),
                    "host_ip": "192.168.50.10",
                    "source_type": "EDR",
                    "signal": "BEACONING_DETECTED",
                    "process_name": "python3",
                    "detail": "Conexao suspeita com Bearer secret-edr-token-123",
                },
                {
                    "uid": "EDR2",
                    "observed_at": BASE_TIME.isoformat(),
                    "host_ip": "192.168.50.99",
                    "source_type": "ANTIVIRUS",
                    "signal": "SUSPICIOUS_PROCESS",
                    "process_name": "curl",
                },
            ],
        },
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["coverage"] == {
        "observed_layers": ["CONNECTIONS", "DNS", "TLS", "EDR"],
        "missing_layers": [],
    }
    assert body["edr_count"] == 2
    assert len(body["edr_signals"]) == 2
    assert body["edr_signals"][0]["detail"] == "Conexao suspeita com Bearer [REDACTED_TOKEN]"

    alerts_by_rule = {item["rule_id"]: item for item in body["alerts"]}
    sweep = alerts_by_rule["CONNECTION_PORT_SWEEP"]
    assert sweep["confidence"] == "HIGH"
    assert sweep["severity"] == "HIGH"
    assert "Correlacionado com 1 sinal(is) de EDR no host" in sweep["explanation"]
    assert len(sweep["evidence"]["correlated_edr_signals"]) == 1
    assert sweep["evidence"]["correlated_edr_signals"][0]["uid"] == "EDR1"

    dns_alert = alerts_by_rule["DNS_NXDOMAIN_BURST"]
    assert dns_alert["confidence"] == "MEDIUM"
    assert "correlated_edr_signals" not in dns_alert["evidence"]

    stored = client.get(f"/api/v1/assets/{asset_id}/traffic-analyses/{body['id']}", headers=operator).json()
    assert len(stored["edr_signals"]) == 2

    out_of_scope_edr = client.post(
        analyze_url,
        headers=collector,
        json={
            "dns_queries": [_dns_payload("DOk", "ok.lab", "NOERROR")],
            "edr_signals": [
                {
                    "uid": "EDROut",
                    "observed_at": BASE_TIME.isoformat(),
                    "host_ip": "203.0.113.50",
                    "source_type": "EDR",
                    "signal": "SUSPICIOUS_PROCESS",
                    "process_name": "nc",
                }
            ],
        },
    )
    assert out_of_scope_edr.status_code == 422
