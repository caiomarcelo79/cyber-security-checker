"""Testes automatizados da Fase 7: Automação, Agendamentos, Notificações, Webhooks, API Tokens e Templates (TM-019)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.security import create_access_token, hash_password
from app.models.entities import (
    Asset,
    Organization,
    OrganizationMembership,
    TargetAuthorization,
    User,
    utcnow,
)
from app.schemas.automations import (
    ApiTokenCreateRequest,
    NotificationPreferenceUpdateRequest,
    ScanScheduleCreateRequest,
    ScanScheduleUpdateRequest,
    ScanTemplateCreateRequest,
    WebhookEndpointCreateRequest,
)
from app.services.api_token_service import ApiTokenError, ApiTokenService
from app.services.email_adapter import EmailDeliveryAdapter
from app.services.notification_service import NotificationService
from app.services.scheduler_service import (
    CronSchedulerUtil,
    SchedulerService,
    ScheduleValidationError,
)
from app.services.template_service import (
    TemplateService,
    format_discord_message,
    format_slack_message,
)
from app.services.webhook_service import (
    WebhookService,
    WebhookValidationError,
)


def _setup_org_user(
    db: Session,
    org_name: str = "SecOps Lab Phase 7",
    role: str = "SECURITY_ANALYST",
) -> tuple[Organization, User, str]:
    org = Organization(name=org_name, slug=f"slug-{utcnow().timestamp()}")
    user = User(
        email=f"user_{utcnow().timestamp()}@secops7.local",
        hashed_password=hash_password("SecOpsPass123!"),
        full_name="Engenheiro DevSecOps",
    )
    db.add_all([org, user])
    db.flush()

    membership = OrganizationMembership(organization_id=org.id, user_id=user.id, role=role)
    db.add(membership)
    db.commit()

    token = create_access_token(
        user_id=user.id,
        email=user.email,
        organization_id=org.id,
        role=role,
    )
    return org, user, token


def _create_verified_asset(db: Session, org_id: str, host: str = "app.local") -> Asset:
    asset = Asset(
        organization_id=org_id,
        name=f"Ativo {host}",
        hostname=host,
        target_url=f"http://{host}",
        asset_type="WEB_APP",
        environment="PRODUCTION",
        owner_name="Security Team",
        owner_email="sec@team.local",
        authorization_status="VERIFIED",
    )
    db.add(asset)
    db.flush()

    auth = TargetAuthorization(
        organization_id=org_id,
        asset_id=asset.id,
        method="DOMAIN_DNS",
        verification_token="csc-verify-token-12345",
        status="VERIFIED",
        verified_at=utcnow(),
        expires_at=utcnow() + timedelta(days=365),
    )
    db.add(auth)
    db.commit()
    db.refresh(asset)
    return asset


# ============================================================================
# 1. CronSchedulerUtil e Timezones
# ============================================================================


def test_cron_scheduler_util_validations():
    assert CronSchedulerUtil.validate_cron("0 2 * * *") is True
    assert CronSchedulerUtil.validate_cron("*/15 * * * *") is True
    assert CronSchedulerUtil.validate_cron("invalid cron expr") is False

    assert CronSchedulerUtil.validate_timezone("America/Sao_Paulo") is True
    assert CronSchedulerUtil.validate_timezone("UTC") is True
    assert CronSchedulerUtil.validate_timezone("Mars/Olympus") is False

    cron_daily = CronSchedulerUtil.resolve_cron_for_frequency("DAILY", "")
    assert cron_daily == "0 2 * * *"

    cron_custom = CronSchedulerUtil.resolve_cron_for_frequency("CRON", "*/30 * * * *")
    assert cron_custom == "*/30 * * * *"

    with pytest.raises(ScheduleValidationError):
        CronSchedulerUtil.resolve_cron_for_frequency("CRON", "bad expr")


def test_cron_scheduler_next_run_calculation():
    next_run = CronSchedulerUtil.calculate_next_run(
        cron_expression="0 2 * * *",
        tz_name="America/Sao_Paulo",
    )
    assert isinstance(next_run, datetime)
    assert next_run.tzinfo is not None
    assert next_run > datetime.now(UTC)


# ============================================================================
# 2. SchedulerService e Ciclo de Vida de Agendamentos
# ============================================================================


def test_scheduler_service_crud_and_lifecycle(db_session: Session):
    db = db_session
    org, user, _ = _setup_org_user(db)
    asset = _create_verified_asset(db, org.id, "scan-target.local")

    service = SchedulerService()

    # Criação
    create_req = ScanScheduleCreateRequest(
        asset_id=asset.id,
        profile_type="QUICK",
        frequency="DAILY",
        timezone="America/Sao_Paulo",
        misfire_policy="SKIP",
    )
    schedule = service.create_schedule(db, org.id, user.id, create_req)
    assert schedule.id is not None
    assert schedule.status == "ACTIVE"
    assert schedule.is_active is True
    assert schedule.next_run_at is not None

    # Listagem
    listing = service.list_schedules(db, org.id)
    assert listing.total >= 1
    assert any(s.id == schedule.id for s in listing.items)

    # Pause e Resume
    paused = service.pause_schedule(db, org.id, schedule.id)
    assert paused is not None
    assert paused.status == "PAUSED"
    assert paused.is_active is False

    resumed = service.resume_schedule(db, org.id, schedule.id)
    assert resumed is not None
    assert resumed.status == "ACTIVE"
    assert resumed.is_active is True

    # Atualização
    update_req = ScanScheduleUpdateRequest(profile_type="FULL", frequency="WEEKLY")
    updated = service.update_schedule(db, org.id, schedule.id, update_req)
    assert updated is not None
    assert updated.profile_type == "FULL"
    assert updated.frequency == "WEEKLY"

    # Exclusão
    deleted = service.delete_schedule(db, org.id, schedule.id)
    assert deleted is True
    assert service.get_schedule(db, org.id, schedule.id) is None


def test_scheduler_rejects_unverified_asset(db_session: Session):
    db = db_session
    org, user, _ = _setup_org_user(db)
    unverified_asset = Asset(
        organization_id=org.id,
        name="Ativo Não Autorizado",
        hostname="unverified.local",
        target_url="http://unverified.local",
        asset_type="WEB_APP",
        environment="PRODUCTION",
        owner_name="Dev Team",
        owner_email="dev@team.local",
        authorization_status="PENDING",
    )
    db.add(unverified_asset)
    db.commit()

    service = SchedulerService()
    create_req = ScanScheduleCreateRequest(
        asset_id=unverified_asset.id,
        profile_type="QUICK",
        frequency="DAILY",
    )
    with pytest.raises((ScheduleValidationError, Exception)) as exc:
        service.create_schedule(db, org.id, user.id, create_req)
    assert "autoriza" in str(exc.value)


# ============================================================================
# 3. NotificationService e EmailDeliveryAdapter
# ============================================================================


def test_notification_service_and_email_delivery(db_session: Session):
    db = db_session
    org, user, _ = _setup_org_user(db)
    EmailDeliveryAdapter.clear_sent_buffer()

    email_adapter = EmailDeliveryAdapter()
    notif_svc = NotificationService(email_adapter=email_adapter)

    # Configura preferência para receber CRITICAL por email
    pref_update = NotificationPreferenceUpdateRequest(
        email_enabled=True,
        email_destination="soc-alerts@secops.local",
        min_severity="HIGH",
    )
    notif_svc.update_preferences(db, org.id, user.id, pref_update)

    # Dispara evento INFO -> Não deve disparar email
    notif_svc.dispatch_event(
        db=db,
        organization_id=org.id,
        user_id=user.id,
        event_type="scan.started",
        severity="INFO",
        title="Auditoria Iniciada",
        message="Auditoria rápida iniciada no ativo.",
        dedup_window_seconds=0,
    )
    assert len(EmailDeliveryAdapter.get_sent_buffer()) == 0

    # Dispara evento CRITICAL -> Deve gerar notificação in-app e email
    notif_svc.dispatch_event(
        db=db,
        organization_id=org.id,
        user_id=user.id,
        event_type="finding.created",
        severity="CRITICAL",
        title="Vulnerabilidade Crítica Detectada",
        message="Injeção SQL confirmada no parâmetro id.",
        link_url="https://secops.local/findings/123",
        dedup_window_seconds=0,
    )
    sent_emails = EmailDeliveryAdapter.get_sent_buffer()
    assert len(sent_emails) == 1
    assert sent_emails[0]["to"] == "soc-alerts@secops.local"
    assert "CRITICAL" in sent_emails[0]["subject"]

    # Consulta notificações in-app
    page = notif_svc.list_notifications(db, org.id, user_id=user.id)
    assert page.total >= 2
    assert page.unread_count >= 2

    # Marcar como lida
    marked = notif_svc.mark_as_read(db, org.id, mark_all=True, user_id=user.id)
    assert marked >= 2

    page_after = notif_svc.list_notifications(db, org.id, user_id=user.id, unread_only=True)
    assert page_after.unread_count == 0


# ============================================================================
# 4. WebhookService, Anti-SSRF e Assinatura HMAC-SHA256
# ============================================================================


def test_webhook_anti_ssrf_validation():
    service = WebhookService()

    # Rejeita host de metadados da nuvem
    with pytest.raises(WebhookValidationError) as exc:
        service._validate_webhook_url("https://169.254.169.254/webhook")
    assert "metadados de nuvem proibido" in str(exc.value)

    # Rejeita HTTP inseguro para domínios públicos
    with pytest.raises(WebhookValidationError) as exc:
        service._validate_webhook_url("http://example.com/webhook")
    assert "HTTPS" in str(exc.value)

    # Aceita URL de laboratório local autorizada se configurada
    valid_lab = service._validate_webhook_url("http://localhost-lab.internal/webhook")
    assert valid_lab == "http://localhost-lab.internal/webhook"


def test_webhook_crud_and_hmac_signature(db_session: Session):
    db = db_session
    org, user, _ = _setup_org_user(db)
    service = WebhookService()

    req = WebhookEndpointCreateRequest(
        url="http://localhost-lab.internal/events",
        description="SIEM de Teste",
        subscribed_events=["scan.completed", "finding.created"],
    )
    ep = service.create_endpoint(db, org.id, user.id, req)
    assert ep.id is not None
    assert ep.is_active is True
    assert ep.secret_token_prefix.startswith("whsec_")

    # Rotacionar segredo
    rotated = service.rotate_secret(db, org.id, ep.id)
    assert rotated is not None
    assert rotated.new_secret_token.startswith("whsec_")

    # Mock HTTP post para verificar montagem de headers e HMAC
    with patch("httpx.Client.post") as mock_post:
        mock_post.return_value.status_code = 200
        mock_post.return_value.text = '{"received": true}'

        test_resp = service.test_webhook(db, org.id, ep.id)
        assert test_resp.status == "DELIVERED"
        assert test_resp.status_code == 200

        # Verifica headers enviados
        _called_args, called_kwargs = mock_post.call_args
        headers = called_kwargs["headers"]
        assert "X-CSC-Signature" in headers
        assert "X-CSC-Timestamp" in headers
        assert headers["X-CSC-Signature"].startswith("sha256=")

    # Consulta histórico de entregas
    deliveries = service.list_deliveries(db, org.id, webhook_id=ep.id)
    assert deliveries.total >= 1
    assert deliveries.items[0].status == "DELIVERED"


# ============================================================================
# 5. ApiTokenService e Autenticação com Chave de API
# ============================================================================


def test_api_token_service_and_authentication(db_session: Session):
    db = db_session
    org, user, _ = _setup_org_user(db)
    service = ApiTokenService()

    # Criação de chave de API
    create_req = ApiTokenCreateRequest(
        name="Chave CI/CD GitHub Actions",
        scopes=["scans:read", "scans:write", "findings:read"],
        expires_in_days=30,
    )
    created = service.create_token(db, org.id, user.id, create_req)
    assert created.raw_api_token.startswith("csc_live_")
    assert created.token_prefix.startswith("csc_live_")

    # Autenticação com sucesso
    auth_result = service.authenticate_token(db, created.raw_api_token)
    assert auth_result is not None
    token_rec, auth_user, auth_org = auth_result
    assert token_rec.id == created.id
    assert auth_user.id == user.id
    assert auth_org.id == org.id
    assert token_rec.last_used_at is not None

    # Tentativa com token adulterado
    assert service.authenticate_token(db, created.raw_api_token + "tampered") is None

    # Revogação
    revoked = service.revoke_token(db, org.id, created.id)
    assert revoked is True

    # Autenticação após revogação deve falhar
    assert service.authenticate_token(db, created.raw_api_token) is None


def test_api_token_scope_validation(db_session: Session):
    db = db_session
    org, user, _ = _setup_org_user(db)
    service = ApiTokenService()

    with pytest.raises(ApiTokenError) as exc:
        service.create_token(
            db,
            org.id,
            user.id,
            ApiTokenCreateRequest(
                name="Chave Inválida",
                scopes=["invalid:permission"],
            ),
        )
    assert "Escopo inválido" in str(exc.value)


# ============================================================================
# 6. ScanTemplateService e Formatadores de Chat (Slack & Discord)
# ============================================================================


def test_template_service_and_seed_defaults(db_session: Session):
    db = db_session
    org, user, _ = _setup_org_user(db)
    svc = TemplateService()

    # Seed de templates padrão
    seeded = svc.seed_defaults(db, org.id, user.id)
    assert len(seeded) == 3
    assert any("OWASP Top 10" in s.name for s in seeded)
    assert any("APIs REST" in s.name for s in seeded)

    # Criação de template customizado
    custom = svc.create_template(
        db,
        org.id,
        user.id,
        ScanTemplateCreateRequest(
            name="Template Customizado",
            profile_type="FULL",
            enabled_modules=["ssl_tls", "cors"],
            parameters={"timeout": 30},
        ),
    )
    assert custom.id is not None
    assert custom.parameters == {"timeout": 30}

    # Formatador Slack
    slack_payload = format_slack_message(
        event_type="finding.created",
        severity="HIGH",
        title="XSS Refletido",
        message="Evidência encontrada em /search?q=...",
        link_url="https://csc.local/findings/456",
    )
    assert "attachments" in slack_payload
    assert slack_payload["attachments"][0]["color"] == "#FF5A1F"

    # Formatador Discord
    discord_payload = format_discord_message(
        event_type="scan.completed",
        severity="INFO",
        title="Auditoria Concluída",
        message="15 verificações executadas com sucesso.",
    )
    assert "embeds" in discord_payload
    assert len(discord_payload["embeds"]) == 1


# ============================================================================
# 7. Testes de Integração REST com TestClient
# ============================================================================


def test_api_routes_phase7_automations(client: TestClient, db_session: Session):
    db = db_session
    org, _user, token = _setup_org_user(db)
    asset = _create_verified_asset(db, org.id, "rest-api-test.local")
    headers = {"Authorization": f"Bearer {token}"}

    # 1. API: Criar Agendamento
    resp = client.post(
        "/api/v1/automations/schedules",
        json={
            "asset_id": asset.id,
            "profile_type": "QUICK",
            "frequency": "DAILY",
            "timezone": "UTC",
        },
        headers=headers,
    )
    assert resp.status_code == 201
    schedule_data = resp.json()
    schedule_id = schedule_data["id"]
    assert schedule_data["frequency"] == "DAILY"

    # Listar agendamentos
    resp = client.get("/api/v1/automations/schedules", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["total"] >= 1

    # Pausar agendamento
    resp = client.post(f"/api/v1/automations/schedules/{schedule_id}/pause", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "PAUSED"

    # 2. API: Notificações
    resp = client.get("/api/v1/automations/notifications", headers=headers)
    assert resp.status_code == 200

    resp = client.get("/api/v1/automations/notifications/preferences", headers=headers)
    assert resp.status_code == 200
    assert "email_enabled" in resp.json()

    # 3. API: Criar Chave de API
    resp = client.post(
        "/api/v1/automations/api-tokens",
        json={
            "name": "Integration Key",
            "scopes": ["scans:read", "findings:read"],
            "expires_in_days": 60,
        },
        headers=headers,
    )
    assert resp.status_code == 201
    token_data = resp.json()
    raw_api_key = token_data["raw_api_token"]
    assert raw_api_key.startswith("csc_live_")

    # 4. Acesso REST autenticado usando a própria Chave de API (Bearer csc_live_...)!
    api_token_headers = {"Authorization": f"Bearer {raw_api_key}"}
    resp_with_token = client.get("/api/v1/automations/schedules", headers=api_token_headers)
    assert resp_with_token.status_code == 200
    assert resp_with_token.json()["total"] >= 1

    # 5. API: Templates de Auditoria
    resp = client.post("/api/v1/automations/templates/seed", headers=headers)
    assert resp.status_code == 200
    assert len(resp.json()) >= 3

    resp = client.get("/api/v1/automations/templates", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["total"] >= 3
