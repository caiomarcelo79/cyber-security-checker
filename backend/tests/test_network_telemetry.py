"""Integração de autorização, ingestão, deduplicação e retenção de conexões."""

from datetime import timedelta
from hashlib import sha256

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from test_ssh_audits import authorize_lab, create_lab_asset, register

from app.models.entities import TelemetryConnection, TelemetrySource, utcnow
from app.services.network_telemetry import purge_expired_connections


def connection(uid: str = "CLab1", origin_ip: str = "192.168.50.10") -> dict:
    return {
        "uid": uid,
        "observed_at": "2026-11-20T10:30:00Z",
        "origin_ip": origin_ip,
        "origin_port": 44731,
        "responder_ip": "198.51.100.20",
        "responder_port": 8000,
        "transport": "tcp",
        "origin_bytes": 100,
    }


@pytest.fixture
def sensor(client: TestClient) -> tuple[dict[str, str], str, str, dict]:
    operator = register(client, "telemetry-owner@lab.local")
    asset_url = create_lab_asset(client, operator)
    sources_url = f"{asset_url}/telemetry-sources"
    payload = {"name": "Sensor do laboratório", "network": "192.168.50.0/24"}
    assert client.post(sources_url, headers=operator, json=payload).status_code == 403
    authorization_url = authorize_lab(client, operator, asset_url)
    created = client.post(sources_url, headers=operator, json=payload)
    assert created.status_code == 201, created.text
    return operator, sources_url, authorization_url, created.json()


def collector_request(source: dict) -> tuple[str, dict[str, str]]:
    return (
        f"/api/v1/telemetry/sources/{source['id']}/connections",
        {"Authorization": f"Bearer {source['collector_token']}"},
    )


def test_source_credential_and_idempotent_import(
    client: TestClient, db_session: Session, sensor: tuple[dict[str, str], str, str, dict]
) -> None:
    operator, sources_url, _, source = sensor
    ingest_url, collector = collector_request(source)
    record = db_session.get(TelemetrySource, source["id"])
    assert record is not None
    assert record.token_hash == sha256(source["collector_token"].encode()).hexdigest()
    assert client.get(sources_url, headers=collector).status_code == 401
    assert client.post(ingest_url, headers=operator, json={"events": [connection()]}).status_code == 401
    status_url = ingest_url.removesuffix("/connections")
    assert client.get(status_url, headers=operator).status_code == 401
    assert client.get(status_url, headers=collector).json()["network"] == "192.168.50.0/24"

    first = client.post(ingest_url, headers=collector, json={"events": [connection(), connection()]})
    assert first.status_code == 200, first.text
    assert first.json() == {"inserted": 1, "duplicates": 1}
    replay = client.post(ingest_url, headers=collector, json={"events": [connection()]})
    assert replay.json() == {"inserted": 0, "duplicates": 1}

    listed = client.get(sources_url, headers=operator).json()
    assert len(listed) == 1 and listed[0]["connection_count"] == 1
    assert listed[0]["last_received_at"] and listed[0]["latest_observed_at"] == connection()["observed_at"]
    assert "collector_token" not in listed[0] and "token_hash" not in listed[0]
    assert client.get(status_url, headers=collector).json() == listed[0]


def test_rejects_invalid_and_out_of_scope_batches_atomically(
    client: TestClient, sensor: tuple[dict[str, str], str, str, dict]
) -> None:
    operator, sources_url, _, source = sensor
    url, collector = collector_request(source)
    unexpected = {**connection(), "payload": "sensitive-fixture"}
    response = client.post(url, headers=collector, json={"events": [unexpected]})
    assert response.status_code == 422 and "sensitive-fixture" not in response.text
    assert client.post(url, headers=collector, content=b"x" * (128 * 1024 + 1)).status_code == 413
    assert client.post(url, headers=collector, json={"events": [connection()] * 201}).status_code == 422
    out_of_scope = connection(uid="COut", origin_ip="203.0.113.20")
    assert client.post(url, headers=collector, json={"events": [connection(), out_of_scope]}).status_code == 422
    assert client.get(sources_url, headers=operator).json()[0]["connection_count"] == 0
    invalid_source = client.post(sources_url, headers=operator, json={"name": "Rede inteira", "network": "0.0.0.0/0"})
    assert invalid_source.status_code == 422


def test_source_isolation_revocation_and_expiration(
    client: TestClient, db_session: Session, sensor: tuple[dict[str, str], str, str, dict]
) -> None:
    operator, sources_url, _, source = sensor
    url, collector = collector_request(source)
    foreign = register(client, "telemetry-outsider@lab.local")
    assert client.get(sources_url, headers=foreign).status_code == 404
    assert client.delete(f"{sources_url}/{source['id']}", headers=foreign).status_code == 404

    second = client.post(
        sources_url, headers=operator, json={"name": "Outro sensor", "network": "192.168.50.0/24"}
    ).json()
    second_url, second_collector = collector_request(second)
    assert client.post(second_url, headers=collector, json={"events": [connection()]}).status_code == 401
    assert client.get(second_url.removesuffix("/connections"), headers=collector).status_code == 401
    assert client.post(second_url, headers=second_collector, json={"events": [connection()]}).status_code == 200
    assert client.post(url, headers=collector, json={"events": [connection()]}).json()["inserted"] == 1
    assert client.delete(f"{sources_url}/{source['id']}", headers=operator).status_code == 204
    assert client.post(url, headers=collector, json={"events": [connection()]}).status_code == 401
    assert client.get(url.removesuffix("/connections"), headers=collector).status_code == 401

    second_record = db_session.get(TelemetrySource, second["id"])
    assert second_record is not None
    second_record.expires_at = utcnow() - timedelta(seconds=1)
    db_session.commit()
    assert client.post(second_url, headers=second_collector, json={"events": [connection()]}).status_code == 401
    states = {item["id"]: item["status"] for item in client.get(sources_url, headers=operator).json()}
    assert states == {source["id"]: "REVOKED", second["id"]: "EXPIRED"}


def test_scope_revocation_and_retention(
    client: TestClient, db_session: Session, sensor: tuple[dict[str, str], str, str, dict]
) -> None:
    operator, sources_url, authorization_url, source = sensor
    url, collector = collector_request(source)
    assert client.post(url, headers=collector, json={"events": [connection("COld"), connection()]}).status_code == 200
    stored = db_session.get(TelemetryConnection, (source["id"], "COld"))
    assert stored is not None
    stored.received_at = utcnow() - timedelta(days=8)
    db_session.commit()
    assert purge_expired_connections(db_session) == 1
    assert client.get(sources_url, headers=operator).json()[0]["connection_count"] == 1
    assert client.post(f"{authorization_url}/revoke", headers=operator).status_code == 200
    assert client.post(url, headers=collector, json={"events": [connection("CNew")]}).status_code == 403
