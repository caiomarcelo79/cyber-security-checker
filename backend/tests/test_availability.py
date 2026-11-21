"""ExercÃ­cio de disponibilidade: regras puras e integraÃ§Ã£o com a API e as notificaÃ§Ãµes."""

from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from test_ssh_audits import authorize_lab, create_lab_asset, register

from app.models.entities import AvailabilityExercise
from app.services.availability_logic import (
    ExercisePlan,
    SampleView,
    analyze_samples,
    grade_exercise,
    summarize_samples,
)
from app.services.notification_service import NotificationService
from app.services.webhook_service import WebhookService

PLAN = ExercisePlan(threshold_ms=500, consecutive_samples=3, interval_ms=1000, normal_ms=5000, degraded_ms=5000)


def scripted(count: int = 14, *, degraded: range = range(5, 10), bad: str = "slow") -> list[SampleView]:
    samples = []
    for index in range(count):
        if index in degraded:
            samples.append(
                SampleView(index * 1000, 900.0, "OK") if bad == "slow" else SampleView(index * 1000, None, "TIMEOUT")
            )
        else:
            samples.append(SampleView(index * 1000, 40.0, "OK"))
    return samples


def grade(samples: list[SampleView]) -> str:
    return grade_exercise(samples, PLAN, analyze_samples(samples, PLAN))


def test_plan_expected_timeline() -> None:
    assert PLAN.expected_alert_ms == 8000
    assert PLAN.expected_recovery_ms == 13000
    assert PLAN.planned_duration_ms == 15000


@pytest.mark.parametrize("bad", ["slow", "timeout"])
def test_alert_opens_after_consecutive_violations_and_recovers(bad: str) -> None:
    analysis = analyze_samples(scripted(bad=bad), PLAN)
    assert analysis.first_violation_offset_ms == 5000
    assert analysis.alert_offset_ms == 7000
    assert analysis.recovery_start_offset_ms == 10000
    assert analysis.recovery_offset_ms == 12000
    assert analysis.state == "RECOVERED"
    assert grade(scripted(bad=bad)) == "PASSED"


def test_isolated_spike_does_not_open_alert() -> None:
    samples = scripted(degraded=range(5, 7))
    assert analyze_samples(samples, PLAN).alert_offset_ms is None
    assert grade(samples) == "FAILED"


def test_grading_never_passes_without_data_or_recovery() -> None:
    assert grade([]) == "INCONCLUSIVE"
    assert grade(scripted(count=9)) == "INCONCLUSIVE"
    assert grade(scripted(count=16, degraded=range(5, 16))) == "FAILED"
    assert grade([SampleView(i * 1000, None, "CONNECTION_ERROR") for i in range(14)]) == "EXECUTION_ERROR"
    assert grade(scripted(count=4)) == "INCONCLUSIVE"


def test_premature_alert_is_a_failure() -> None:
    assert grade(scripted(degraded=range(1, 10))) == "FAILED"


def sample(seq: int, latency: float | None = 40.0, outcome: str = "OK") -> dict[str, Any]:
    return {"seq": seq, "offset_ms": seq * 1000, "latency_ms": latency, "outcome": outcome, "http_status": 200}


PAYLOAD = {"threshold_ms": 500, "consecutive_samples": 3, "interval_ms": 1000, "normal_ms": 5000, "degraded_ms": 5000}


def test_exercise_publishes_alert_and_recovery_in_app_only(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    external: list[str] = []
    monkeypatch.setattr(NotificationService, "_deliver_email_if_eligible", lambda *a, **k: external.append("e"))
    monkeypatch.setattr(WebhookService, "dispatch_event_to_webhooks", lambda *a, **k: external.append("w"))
    owner = register(client, "avail-owner@lab.local")
    outsider = register(client, "avail-outsider@lab.local")
    asset_url = create_lab_asset(client, owner)
    endpoint = f"{asset_url}/availability-exercises"
    assert client.post(endpoint, headers=owner, json=PAYLOAD).status_code == 403
    authorize_lab(client, owner, asset_url)
    assert client.post(endpoint, headers=outsider, json=PAYLOAD).status_code == 404
    assert client.post(endpoint, headers=owner, json={**PAYLOAD, "interval_ms": 100}).status_code == 422
    assert client.post(endpoint, headers=owner, json={**PAYLOAD, "extra": 1}).status_code == 422

    created = client.post(endpoint, headers=owner, json=PAYLOAD)
    assert created.status_code == 201, created.text
    exercise = created.json()
    assert exercise["status"] == "RUNNING" and exercise["hostname"] == "lab-target"
    assert exercise["planned_duration_ms"] == 15000
    assert client.post(endpoint, headers=owner, json=PAYLOAD).status_code == 409
    url = f"{endpoint}/{exercise['id']}"
    assert client.get(url, headers=outsider).status_code == 404

    assert client.post(f"{url}/samples", headers=owner, json=sample(1)).status_code == 409
    assert client.post(f"{url}/samples", headers=owner, json={**sample(0), "outcome": "TIMEOUT"}).status_code == 422
    for seq in range(14):
        degraded = 5 <= seq < 10
        response = client.post(f"{url}/samples", headers=owner, json=sample(seq, 900.0 if degraded else 40.0))
        assert response.status_code == 201, response.text
        if seq == 6:
            assert response.json()["state"] == "NORMAL"
        if seq == 7:
            assert response.json()["state"] == "ALERT"
    assert client.post(f"{url}/samples", headers=owner, json=sample(14)).json()["state"] == "RECOVERED"

    finished = client.post(f"{url}/finish", headers=owner)
    assert finished.status_code == 200, finished.text
    body = finished.json()
    assert body["result"] == "PASSED" and body["status"] == "FINISHED"
    assert body["alert_publication_ms"] >= 0 and body["recovery_publication_ms"] >= 0
    assert len(body["samples"]) == 15
    observed = {event["event"]: event["observed_offset_ms"] for event in body["timeline"]}
    assert observed == {
        "DEGRADATION_START": 5000,
        "ALERT_OPENED": 7000,
        "RECOVERY_START": 10000,
        "RECOVERY_DETECTED": 12000,
    }
    assert client.post(f"{url}/finish", headers=owner).status_code == 409
    assert client.post(f"{url}/samples", headers=owner, json=sample(15)).status_code == 409

    items = client.get("/api/v1/automations/notifications", headers=owner).json()["items"]
    by_type = {item["event_type"]: item for item in items}
    assert by_type["AVAILABILITY_DEGRADATION_SIMULATED"]["severity"] == "HIGH"
    assert by_type["AVAILABILITY_RECOVERY_SIMULATED"]["severity"] == "INFO"
    assert len(items) == 2 and all(item["metadata_json"]["synthetic"] for item in items)
    assert client.get("/api/v1/automations/notifications", headers=outsider).json()["items"] == []
    assert client.get(endpoint, headers=owner).json()[0]["samples"] is None
    actions = [e["action"] for e in client.get("/api/v1/audit-logs", headers=owner).json()]
    assert "AVAILABILITY_EXERCISE_STARTED" in actions and "AVAILABILITY_EXERCISE_FINISHED" in actions
    assert external == []


def test_revoked_authorization_blocks_samples_and_stale_run_is_replaced(
    client: TestClient, db_session: Session
) -> None:
    owner = register(client, "avail-revoke@lab.local")
    asset_url = create_lab_asset(client, owner)
    authorization_url = authorize_lab(client, owner, asset_url)
    endpoint = f"{asset_url}/availability-exercises"
    first = client.post(endpoint, headers=owner, json=PAYLOAD).json()
    assert client.post(f"{authorization_url}/revoke", headers=owner).status_code == 200
    assert client.post(f"{endpoint}/{first['id']}/samples", headers=owner, json=sample(0)).status_code == 403
    assert client.post(f"{endpoint}/{first['id']}/finish", headers=owner).status_code == 403
    authorize_lab(client, owner, asset_url)

    record = db_session.get(AvailabilityExercise, first["id"])
    assert record is not None
    from datetime import timedelta

    record.started_at = record.started_at - timedelta(hours=1)
    db_session.commit()
    second = client.post(endpoint, headers=owner, json=PAYLOAD)
    assert second.status_code == 201
    stale = client.get(f"{endpoint}/{first['id']}", headers=owner).json()
    assert stale["status"] == "FINISHED" and stale["result"] == "EXECUTION_ERROR"


@pytest.mark.parametrize("scenario,http_status", [("ERRORS", 503), ("SATURATION", 429)])
def test_errors_and_saturation_scenarios_trigger_alert_and_summary(
    client: TestClient, scenario: str, http_status: int
) -> None:
    owner = register(client, f"avail-{scenario.lower()}@lab.local")
    asset_url = create_lab_asset(client, owner)
    authorize_lab(client, owner, asset_url)
    endpoint = f"{asset_url}/availability-exercises"

    created = client.post(endpoint, headers=owner, json={**PAYLOAD, "scenario": scenario})
    assert created.status_code == 201, created.text
    exercise = created.json()
    assert exercise["scenario"] == scenario
    url = f"{endpoint}/{exercise['id']}"

    for seq in range(15):
        degraded = 5 <= seq < 10
        resp = client.post(
            f"{url}/samples",
            headers=owner,
            json={
                "seq": seq,
                "offset_ms": seq * 1000,
                "latency_ms": 25.0,
                "outcome": "OK",
                "http_status": http_status if degraded else 200,
            },
        )
        assert resp.status_code == 201, resp.text
        if seq == 7:
            assert resp.json()["state"] == "ALERT"
        if seq == 12:
            assert resp.json()["state"] == "RECOVERED"

    finished = client.post(f"{url}/finish", headers=owner)
    assert finished.status_code == 200
    body = finished.json()
    assert body["result"] == "PASSED"
    assert body["scenario"] == scenario
    summary = body["metrics_summary"]
    assert summary["peak_latency_ms"] == 25.0
    assert summary["timeout_or_connection_error_count"] == 0
    if http_status == 503:
        assert summary["error_5xx_count"] == 5 and summary["rate_limited_429_count"] == 0
    else:
        assert summary["rate_limited_429_count"] == 5 and summary["error_5xx_count"] == 0


def test_edge_signals_correlate_with_exercise_and_enforce_limits(client: TestClient) -> None:
    owner = register(client, "avail-signals@lab.local")
    outsider = register(client, "avail-signals-other@lab.local")
    asset_url = create_lab_asset(client, owner)
    authorize_lab(client, owner, asset_url)
    endpoint = f"{asset_url}/availability-exercises"

    exercise = client.post(endpoint, headers=owner, json={**PAYLOAD, "scenario": "SATURATION"}).json()
    url = f"{endpoint}/{exercise['id']}"
    assert client.post(
        f"{url}/signals",
        headers=outsider,
        json={"source_type": "CDN", "signal": "RATE_LIMITED", "offset_ms": 5000, "http_status": 429},
    ).status_code == 404

    for source_type, signal_code, offset_ms, status_code in (
        ("FIREWALL", "MITIGATION_ACTIVE", 5000, 429),
        ("CDN", "RATE_LIMITED", 5500, 429),
        ("PROVIDER", "RECOVERED", 10000, 200),
    ):
        sig_resp = client.post(
            f"{url}/signals",
            headers=owner,
            json={
                "source_type": source_type,
                "signal": signal_code,
                "offset_ms": offset_ms,
                "http_status": status_code,
            },
        )
        assert sig_resp.status_code == 201, sig_resp.text

    detail = client.get(url, headers=owner).json()
    assert [(s["source_type"], s["signal"], s["offset_ms"]) for s in detail["signals"]] == [
        ("FIREWALL", "MITIGATION_ACTIVE", 5000),
        ("CDN", "RATE_LIMITED", 5500),
        ("PROVIDER", "RECOVERED", 10000),
    ]

    for idx in range(17):
        assert (
            client.post(
                f"{url}/signals",
                headers=owner,
                json={"source_type": "CDN", "signal": "SATURATION", "offset_ms": 6000 + idx},
            ).status_code
            == 201
        )
    assert (
        client.post(
            f"{url}/signals",
            headers=owner,
            json={"source_type": "CDN", "signal": "SATURATION", "offset_ms": 7000},
        ).status_code
        == 409
    )

    client.post(f"{url}/finish", headers=owner)
    assert (
        client.post(
            f"{url}/signals",
            headers=owner,
            json={"source_type": "CDN", "signal": "RECOVERED", "offset_ms": 11000},
        ).status_code
        == 409
    )

    summary = summarize_samples(
        [
            SampleView(0, 10.0, "OK", 200),
            SampleView(1000, 120.0, "OK", 503),
            SampleView(2000, 220.0, "OK", 429),
            SampleView(3000, None, "TIMEOUT", None),
        ]
    )
    assert summary.peak_latency_ms == 220.0
    assert summary.error_5xx_count == 1
    assert summary.rate_limited_429_count == 1
    assert summary.timeout_or_connection_error_count == 1
