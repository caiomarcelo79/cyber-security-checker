"""Integração local da auditoria de configuração do OpenSSH."""

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.entities import TargetAuthorization, utcnow
from app.services.notification_service import NotificationService
from app.services.webhook_service import WebhookService


def register(client: TestClient, email: str) -> dict[str, str]:
    response = client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "password": "LabAuditPassword!2026",
            "full_name": "Analista do laboratório",
            "organization_name": f"Laboratório {email.split('@')[0]}",
        },
    )
    assert response.status_code == 201, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def create_lab_asset(client: TestClient, headers: dict[str, str], hostname: str = "lab-target") -> str:
    response = client.post(
        "/api/v1/assets",
        headers=headers,
        json={
            "name": "OpenSSH de laboratório",
            "target_url": f"http://{hostname}",
            "asset_type": "DOMAIN",
            "environment": "LAB",
            "owner_name": "Equipe do laboratório",
            "owner_email": "ops@lab.local",
        },
    )
    assert response.status_code == 201, response.text
    return f"/api/v1/assets/{response.json()['id']}"


def authorize_lab(client: TestClient, headers: dict[str, str], asset_url: str) -> str:
    created = client.post(
        f"{asset_url}/authorizations", headers=headers, json={"method": "LAB_INTERNAL"}
    )
    assert created.status_code == 201, created.text
    authorization_url = f"{asset_url}/authorizations/{created.json()['id']}"
    verified = client.post(f"{authorization_url}/verify", headers=headers)
    assert verified.status_code == 200, verified.text
    return authorization_url


def test_ssh_audit_records_only_typed_evidence_and_isolates_organizations(
    client: TestClient,
) -> None:
    owner = register(client, "first@lab.local")
    outsider = register(client, "second@lab.local")
    asset_url = create_lab_asset(client, owner)
    endpoint = f"{asset_url}/ssh-audit"
    payload = {"hostname": "lab-target", "password_authentication": "disabled"}

    assert client.get(endpoint, headers=owner).json() is None
    assert client.get(f"{endpoint}/collection", headers=owner).status_code == 403
    assert client.post(endpoint, headers=owner, json=payload).status_code == 403

    authorization_url = authorize_lab(client, owner, asset_url)
    assert client.get(f"{endpoint}/collection", headers=owner).json() == {"hostname": "lab-target"}
    assert client.get(endpoint, headers=outsider).status_code == 404
    assert client.post(endpoint, headers=outsider, json=payload).status_code == 404
    assert client.post(endpoint, headers=owner, json={**payload, "hostname": "other.lab"}).status_code == 422
    assert client.post(endpoint, headers=owner, json={**payload, "raw_output": "raw"}).status_code == 422

    for observation, status in (
        ("disabled", "PASSED"),
        ("enabled", "VULNERABILITY"),
        ("unknown", "INCONCLUSIVE"),
        ("collection_error", "EXECUTION_ERROR"),
    ):
        saved = client.post(endpoint, headers=owner, json={**payload, "password_authentication": observation})
        assert saved.status_code == 201, saved.text
        result = saved.json()
        assert result["status"] == status
        assert result["password_authentication"] == observation
        assert set(result) == {
            "id",
            "status",
            "password_authentication",
            "permit_root_login",
            "permit_root_login_status",
            "created_at",
        }
        assert result["permit_root_login"] is None and result["permit_root_login_status"] is None
        assert client.get(endpoint, headers=owner).json() == result

    logs = client.get("/api/v1/audit-logs", headers=owner).json()
    audit_entries = [entry for entry in logs if entry["action"] == "SSH_AUDIT_RECORDED"]
    assert len(audit_entries) == 4

    assert client.post(f"{authorization_url}/revoke", headers=owner).status_code == 200
    assert client.get(f"{endpoint}/collection", headers=owner).status_code == 403
    assert client.post(endpoint, headers=owner, json=payload).status_code == 403
    assert client.get(endpoint, headers=owner).json()["status"] == "EXECUTION_ERROR"


@pytest.mark.parametrize("hostname,expires", [("lab-target", True), ("outside-list.lab", False)])
def test_ssh_audit_requires_explicit_host_and_unexpired_authorization(
    client: TestClient, db_session: Session, hostname: str, expires: bool
) -> None:
    owner = register(client, "scope@lab.local")
    asset_url = create_lab_asset(client, owner, hostname)
    authorization_url = authorize_lab(client, owner, asset_url)
    if expires:
        authorization = db_session.get(TargetAuthorization, authorization_url.rsplit("/", 1)[-1])
        assert authorization is not None
        authorization.expires_at = utcnow() - timedelta(seconds=1)
        db_session.commit()

    endpoint = f"{asset_url}/ssh-audit"
    assert client.get(f"{endpoint}/collection", headers=owner).status_code == 403
    denied = client.post(
        endpoint, headers=owner, json={"hostname": hostname, "password_authentication": "disabled"}
    )
    assert denied.status_code == 403
    assert client.get(endpoint, headers=owner).json() is None


def test_ssh_root_policy_requires_root_login_to_be_disabled(client: TestClient) -> None:
    owner = register(client, "root-policy@lab.local")
    asset_url = create_lab_asset(client, owner)
    authorize_lab(client, owner, asset_url)
    for observation, expected_status in (
        ("no", "PASSED"),
        ("yes", "VULNERABILITY"),
        ("prohibit-password", "VULNERABILITY"),
        ("forced-commands-only", "VULNERABILITY"),
        ("unknown", "INCONCLUSIVE"),
        ("collection_error", "EXECUTION_ERROR"),
    ):
        saved = client.post(
            f"{asset_url}/ssh-audit",
            headers=owner,
            json={
                "hostname": "lab-target",
                "password_authentication": "disabled",
                "permit_root_login": observation,
            },
        )
        assert saved.status_code == 201, saved.text
        assert saved.json()["permit_root_login"] == observation
        assert saved.json()["permit_root_login_status"] == expected_status


def test_ssh_alert_exercise_is_in_app_only_and_visible_to_the_requester(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    external_deliveries = []
    monkeypatch.setattr(
        NotificationService,
        "_deliver_email_if_eligible",
        lambda *args, **kwargs: external_deliveries.append("email"),
    )
    monkeypatch.setattr(
        WebhookService,
        "dispatch_event_to_webhooks",
        lambda *args, **kwargs: external_deliveries.append("webhook"),
    )
    owner = register(client, "alert-owner@lab.local")
    outsider = register(client, "alert-outsider@lab.local")
    asset_url = create_lab_asset(client, owner)
    endpoint = f"{asset_url}/ssh-audit/alert-exercise"
    assert client.post(endpoint, headers=owner).status_code == 403
    authorization_url = authorize_lab(client, owner, asset_url)

    result = client.post(endpoint, headers=owner)
    assert result.status_code == 201
    exercise = result.json()
    assert exercise["channel"] == "in_app"
    assert exercise["publication_ms"] >= 0
    notifications_url = "/api/v1/automations/notifications"
    notifications = client.get(notifications_url, headers=owner).json()["items"]
    assert len(notifications) == 1
    notification = notifications[0]
    assert notification["id"] == exercise["notification_id"]
    assert notification["event_type"] == "SSH_AUTH_FAILURE_SIMULATED"
    assert notification["metadata_json"]["synthetic"] is True
    assert client.get(notifications_url, headers=outsider).json()["items"] == []
    assert client.post(endpoint, headers=outsider).status_code == 404
    assert client.post(f"{authorization_url}/revoke", headers=owner).status_code == 200
    assert client.post(endpoint, headers=owner).status_code == 403
    assert external_deliveries == []
