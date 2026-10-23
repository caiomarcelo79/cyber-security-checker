"""Suíte de Testes de Integração End-to-End (E2E) da Fase 8 (TM-020).

Cobre os 5 fluxos fundamentais:
- Fluxo A: Usuário, RBAC, Ativos e Isolamento Multi-Organização
- Fluxo B: Orquestração de Auditorias, Scanners Seguros e Cancelamento
- Fluxo C: Ciclo de Vida de Vulnerabilidades, Sanitização, Triagem e Revalidação
- Fluxo D: Geração e Exportação de Relatórios com Controle de Acesso
- Fluxo E: Automações, Agendamentos, Notificações e Webhooks Assinados
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import timedelta
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient
from security_engine.core.contracts import Severity
from sqlalchemy.orm import Session

from app.core.security import create_access_token, hash_password
from app.models.entities import (
    Asset,
    FindingRecord,
    Organization,
    OrganizationMembership,
    Scan,
    ScanSchedule,
    TargetAuthorization,
    User,
    WebhookEndpointRecord,
    utcnow,
)
from app.services.notification_service import NotificationService
from app.services.scheduler_service import SchedulerService
from app.services.webhook_service import WebhookService


def _create_tenant(
    db: Session,
    org_name: str,
    slug: str,
    email: str,
    role: str = "ADMIN",
) -> tuple[Organization, User, str]:
    org = Organization(name=org_name, slug=slug)
    user = User(
        email=email,
        hashed_password=hash_password("StrongE2EPass2026!"),
        full_name=f"User {org_name}",
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


# ==============================================================================
# FLUXO A — Usuário, RBAC, Ativos e Isolamento Multi-Organização
# ==============================================================================
def test_flow_a_user_assets_and_multitenant_isolation(client: TestClient, db_session: Session) -> None:
    # 1. Registrar Org Alpha e Usuário Admin
    reg_alpha = client.post(
        "/api/v1/auth/register",
        json={
            "email": "admin@tenant-alpha.test",
            "password": "AlphaPassword123!",
            "full_name": "Admin Alpha",
            "organization_name": "Tenant Alpha Corp",
        },
    )
    assert reg_alpha.status_code == 201
    alpha_token = reg_alpha.json()["access_token"]
    alpha_org_id = reg_alpha.json()["active_organization"]["id"]

    # 2. Registrar Org Beta e Usuário Admin
    reg_beta = client.post(
        "/api/v1/auth/register",
        json={
            "email": "admin@tenant-beta.test",
            "password": "BetaPassword123!",
            "full_name": "Admin Beta",
            "organization_name": "Tenant Beta Corp",
        },
    )
    assert reg_beta.status_code == 201
    beta_token = reg_beta.json()["access_token"]
    beta_org_id = reg_beta.json()["active_organization"]["id"]
    assert alpha_org_id != beta_org_id

    # 3. Autenticação e Verificação de Sessão
    headers_alpha = {"Authorization": f"Bearer {alpha_token}"}
    headers_beta = {"Authorization": f"Bearer {beta_token}"}

    me_alpha = client.get("/api/v1/auth/me", headers=headers_alpha)
    assert me_alpha.status_code == 200
    assert me_alpha.json()["active_organization"]["id"] == alpha_org_id

    # 4. Cadastrar Ativo de Laboratório na Org Alpha
    asset_resp = client.post(
        "/api/v1/assets",
        headers=headers_alpha,
        json={
            "name": "Lab Target Alpha",
            "target_url": "http://lab-target",
            "asset_type": "WEB_APP",
            "environment": "LAB",
            "owner_name": "Admin Alpha",
            "owner_email": "admin@tenant-alpha.test",
        },
    )
    assert asset_resp.status_code == 201
    alpha_asset_id = asset_resp.json()["id"]

    # 5. Iniciar e Validar Autorização do Ativo (Modo Laboratório)
    auth_init = client.post(
        f"/api/v1/assets/{alpha_asset_id}/authorizations",
        headers=headers_alpha,
        json={
            "method": "LAB_INTERNAL",
            "scope_notes": "Ambiente de laboratório isolado para testes E2E.",
            "expires_in_days": 30,
        },
    )
    assert auth_init.status_code == 201
    auth_id = auth_init.json()["id"]

    verify_resp = client.post(
        f"/api/v1/assets/{alpha_asset_id}/authorizations/{auth_id}/verify",
        headers=headers_alpha,
    )
    assert verify_resp.status_code == 200
    assert verify_resp.json()["status"] == "VERIFIED"

    # 6. Testar Isolamento Multi-Organização
    # Org Beta NÃO PODE listar, visualizar, editar ou auditar ativo da Org Alpha
    beta_list = client.get("/api/v1/assets", headers=headers_beta)
    assert beta_list.status_code == 200
    assert all(a["id"] != alpha_asset_id for a in beta_list.json())

    beta_get = client.get(f"/api/v1/assets/{alpha_asset_id}", headers=headers_beta)
    assert beta_get.status_code == 404

    beta_scan = client.post(
        "/api/v1/scans",
        headers=headers_beta,
        json={"asset_id": alpha_asset_id, "profile_type": "QUICK"},
    )
    assert beta_scan.status_code == 404


# ==============================================================================
# FLUXO B — Auditorias, Scanners Seguros e Cancelamento Controlado
# ==============================================================================
def test_flow_b_scans_execution_and_cancellation(client: TestClient, db_session: Session) -> None:
    org, _user, token = _create_tenant(db_session, "Flow B Org", "flow-b-org", "flowb@test.local")
    headers = {"Authorization": f"Bearer {token}"}

    # Cadastrar e autorizar ativo
    asset = Asset(
        organization_id=org.id,
        name="Lab Web Target",
        target_url="http://lab-target",
        hostname="lab-target",
        asset_type="WEB_APP",
        environment="LAB",
        authorization_status="VERIFIED",
        owner_name="SecOps Team",
        owner_email="secops@test.local",
    )
    db_session.add(asset)
    db_session.flush()

    auth = TargetAuthorization(
        asset_id=asset.id,
        organization_id=org.id,
        method="LAB_INTERNAL",
        verification_token="csc-challenge-token",
        status="VERIFIED",
        verified_at=utcnow(),
        expires_at=utcnow() + timedelta(days=90),
    )
    db_session.add(auth)
    db_session.commit()

    # Criar Auditoria com Perfil Rápido e despacho assíncrono mockado
    with patch("workers.tasks.execute_scan_task.delay") as mock_celery:
        mock_celery.return_value = MagicMock(id="celery-mock-task-b")
        scan_resp = client.post(
            "/api/v1/scans",
            headers=headers,
            json={"asset_id": asset.id, "profile_type": "QUICK", "execute_synchronously": False},
        )
        assert scan_resp.status_code == 201
        scan_id = scan_resp.json()["id"]
        assert scan_resp.json()["status"] in {"QUEUED", "PENDING"}

        # Consultar status do scan
        get_scan = client.get(f"/api/v1/scans/{scan_id}", headers=headers)
        assert get_scan.status_code == 200
        assert get_scan.json()["id"] == scan_id

        # Testar Cancelamento Controlado
        cancel_resp = client.post(f"/api/v1/scans/{scan_id}/cancel", headers=headers)
        assert cancel_resp.status_code == 200
        assert cancel_resp.json()["status"] == "CANCELLED"

        # Verificar que o status persistido reflete o cancelamento
        updated_scan = client.get(f"/api/v1/scans/{scan_id}", headers=headers)
        assert updated_scan.json()["status"] == "CANCELLED"


# ==============================================================================
# FLUXO C — Vulnerabilidades, Sanitização de Evidências, Triagem e Revalidação
# ==============================================================================
def test_flow_c_vulnerability_lifecycle_sanitization_and_revalidation(
    client: TestClient, db_session: Session
) -> None:
    org, user, token = _create_tenant(db_session, "Flow C Org", "flow-c-org", "flowc@test.local")
    headers = {"Authorization": f"Bearer {token}"}

    asset = Asset(
        organization_id=org.id,
        name="Vuln Asset",
        target_url="http://lab-target",
        hostname="lab-target",
        asset_type="WEB_APP",
        environment="LAB",
        authorization_status="VERIFIED",
        owner_name="SecOps Team",
        owner_email="secops@test.local",
    )
    db_session.add(asset)
    db_session.flush()

    auth = TargetAuthorization(
        asset_id=asset.id,
        organization_id=org.id,
        method="LAB_INTERNAL",
        verification_token="csc-challenge-token",
        status="VERIFIED",
        verified_at=utcnow(),
        expires_at=utcnow() + timedelta(days=90),
    )
    db_session.add(auth)
    db_session.flush()

    scan = Scan(
        organization_id=org.id,
        asset_id=asset.id,
        initiated_by_user_id=user.id,
        profile_type="QUICK",
        status="COMPLETED",
        progress_percent=100,
        enabled_modules=["mod_a_recon_headers_tls"],
        total_checks_run=5,
    )
    db_session.add(scan)
    db_session.flush()

    # Registrar descoberta com evidência técnica sanitizada
    finding = FindingRecord(
        organization_id=org.id,
        asset_id=asset.id,
        scan_id=scan.id,
        fingerprint="flow-c-test-fingerprint-001",
        module_id="mod_a_recon_headers_tls",
        check_id="CHK-A01",
        title="Cabeçalho Strict-Transport-Security Ausente",
        description="O cabeçalho HSTS não está configurado na resposta HTTP.",
        category="NETWORK_SECURITY",
        result_classification="VULNERABILITY",
        severity=Severity.HIGH.value,
        confidence="CONFIRMED",
        cwe_ids=["CWE-319"],
        owasp_categories=["A05:2021-Security Misconfiguration"],
        affected_endpoint="http://lab-target",
        evidence={
            "url": "http://lab-target",
            "status_code": 200,
            "missing_headers": ["Strict-Transport-Security"],
            "redacted_auth": "[REDACTED]",
        },
        impact="Comunicação sem proteção TLS estrita pode ser interceptada.",
        reproduction_steps=["GET / HTTP/1.1", "Inspecionar cabeçalho Strict-Transport-Security"],
        remediation_data={"header": "Strict-Transport-Security: max-age=63072000; includeSubDomains"},
        treatment_status="OPEN",
        priority="HIGH",
        sla_deadline=utcnow() + timedelta(days=15),
    )
    db_session.add(finding)
    db_session.commit()

    # 1. Consultar finding via API
    list_findings = client.get("/api/v1/findings", headers=headers)
    assert list_findings.status_code == 200
    assert len(list_findings.json()) >= 1
    f_data = next(f for f in list_findings.json() if f["id"] == finding.id)
    assert f_data["treatment_status"] == "OPEN"
    assert f_data["evidence"]["redacted_auth"] == "[REDACTED]"

    # 2. Alterar Triagem para IN_ANALYSIS
    patch_triage = client.patch(
        f"/api/v1/findings/{finding.id}/status",
        headers=headers,
        json={"treatment_status": "IN_ANALYSIS", "triage_note": "Iniciando análise técnica da falha."},
    )
    assert patch_triage.status_code == 200
    assert patch_triage.json()["treatment_status"] == "IN_ANALYSIS"

    # 3. Marcar como WAITING_VALIDATION
    patch_resolved = client.patch(
        f"/api/v1/findings/{finding.id}/status",
        headers=headers,
        json={"treatment_status": "WAITING_VALIDATION", "triage_note": "HSTS configurado no proxy reverso."},
    )
    assert patch_resolved.status_code == 200
    assert patch_resolved.json()["treatment_status"] == "WAITING_VALIDATION"

    # 4. Executar Revalidação Técnica via API
    reval_resp = client.post(
        f"/api/v1/findings/{finding.id}/revalidate",
        headers=headers,
        json={"triage_note": "Revalidação técnica de correção"},
    )
    assert reval_resp.status_code == 200
    reval_data = reval_resp.json()
    assert reval_data["finding_id"] == finding.id
    assert "status" in reval_data


# ==============================================================================
# FLUXO D — Relatórios Profissionais (Técnico e Executivo) e Exportações
# ==============================================================================
def test_flow_d_reports_generation_and_export_permissions(
    client: TestClient, db_session: Session
) -> None:
    org_a, user_a, token_a = _create_tenant(db_session, "Flow D Org A", "flow-d-org-a", "report_a@test.local")
    _org_b, _user_b, token_b = _create_tenant(db_session, "Flow D Org B", "flow-d-org-b", "report_b@test.local")
    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}

    # Ativo e Scan na Org A
    asset = Asset(
        organization_id=org_a.id,
        name="Asset Report Target",
        target_url="http://lab-target",
        hostname="lab-target",
        asset_type="WEB_APP",
        environment="LAB",
        authorization_status="VERIFIED",
        owner_name="Admin A",
        owner_email="admin@a.local",
    )
    db_session.add(asset)
    db_session.flush()

    auth = TargetAuthorization(
        asset_id=asset.id,
        organization_id=org_a.id,
        method="LAB_INTERNAL",
        verification_token="csc-challenge-token-d",
        status="VERIFIED",
        verified_at=utcnow(),
        expires_at=utcnow() + timedelta(days=90),
    )
    db_session.add(auth)
    db_session.flush()

    scan = Scan(
        organization_id=org_a.id,
        asset_id=asset.id,
        initiated_by_user_id=user_a.id,
        profile_type="QUICK",
        status="COMPLETED",
        progress_percent=100,
        enabled_modules=["mod_a_recon_headers_tls"],
        total_checks_run=3,
    )
    db_session.add(scan)
    db_session.flush()

    finding = FindingRecord(
        organization_id=org_a.id,
        asset_id=asset.id,
        scan_id=scan.id,
        fingerprint="flow-d-test-fingerprint-001",
        module_id="mod_a_recon_headers_tls",
        check_id="CHK-E01",
        title="Cookie de Sessão sem Flag HttpOnly",
        description="Cookie vulnerável a vazamento via XSS.",
        category="SESSION_MANAGEMENT",
        result_classification="VULNERABILITY",
        severity="MEDIUM",
        confidence="CONFIRMED",
        cwe_ids=["CWE-1004"],
        owasp_categories=["A05:2021-Security Misconfiguration"],
        affected_endpoint="http://lab-target",
        evidence={"cookie": "session_id", "flags": []},
        impact="Exposição de credenciais de sessão.",
        reproduction_steps=["Inspecionar Set-Cookie"],
        remediation_data={"fix": "Adicionar HttpOnly"},
        treatment_status="OPEN",
    )
    db_session.add(finding)
    db_session.commit()

    # 1. Gerar Relatório Técnico em JSON
    rep_resp = client.post(
        "/api/v1/reports",
        headers=headers_a,
        json={
            "report_type": "TECHNICAL",
            "format": "JSON",
            "scan_id": scan.id,
            "title": "Relatório Técnico E2E",
        },
    )
    assert rep_resp.status_code == 201
    rep_data = rep_resp.json()
    report_id = rep_data["id"]
    assert rep_data["report_type"] == "TECHNICAL"
    assert rep_data["format"] == "JSON"

    # 2. Download do Relatório pela Org A
    dl_resp = client.get(f"/api/v1/reports/{report_id}/download", headers=headers_a)
    assert dl_resp.status_code == 200
    report_content = json.loads(dl_resp.text)
    assert report_content["title"] == "Relatório Técnico E2E"
    assert report_content["summary"]["total_findings"] >= 1

    # 3. Gerar Relatório Executivo em CSV
    csv_resp = client.post(
        "/api/v1/reports",
        headers=headers_a,
        json={
            "report_type": "EXECUTIVE",
            "format": "CSV",
            "scan_id": scan.id,
            "title": "Relatório Executivo E2E",
        },
    )
    assert csv_resp.status_code == 201
    csv_id = csv_resp.json()["id"]
    dl_csv = client.get(f"/api/v1/reports/{csv_id}/download", headers=headers_a)
    assert dl_csv.status_code == 200
    assert "Severidade" in dl_csv.text or "Titulo" in dl_csv.text or "CHK-E01" in dl_csv.text

    # 4. Controle de Acesso: Org B não tem permissão para baixar relatórios da Org A
    unauth_dl = client.get(f"/api/v1/reports/{report_id}/download", headers=headers_b)
    assert unauth_dl.status_code == 404


# ==============================================================================
# FLUXO E — Automações: Agendamento, Notificações e Webhooks Seguros
# ==============================================================================
def test_flow_e_automations_scheduler_notifications_and_webhooks(
    client: TestClient, db_session: Session
) -> None:
    org, _user, token = _create_tenant(db_session, "Flow E Org", "flow-e-org", "flowe@test.local")
    headers = {"Authorization": f"Bearer {token}"}

    # Ativo Autorizado
    asset = Asset(
        organization_id=org.id,
        name="Scheduled Target",
        target_url="http://lab-target",
        hostname="lab-target",
        asset_type="WEB_APP",
        environment="LAB",
        authorization_status="VERIFIED",
        owner_name="Admin E",
        owner_email="admin@e.local",
    )
    db_session.add(asset)
    db_session.flush()

    auth = TargetAuthorization(
        asset_id=asset.id,
        organization_id=org.id,
        method="LAB_INTERNAL",
        verification_token="csc-challenge-token",
        status="VERIFIED",
        verified_at=utcnow(),
        expires_at=utcnow() + timedelta(days=90),
    )
    db_session.add(auth)
    db_session.commit()

    # 1. Criar Agendamento de Auditoria
    sched_resp = client.post(
        "/api/v1/automations/schedules",
        headers=headers,
        json={
            "asset_id": asset.id,
            "profile_type": "QUICK",
            "frequency": "DAILY",
            "cron_expression": "0 2 * * *",
            "timezone": "UTC",
        },
    )
    assert sched_resp.status_code == 201
    sched_id = sched_resp.json()["id"]

    # Forçar agendamento para estar vencido (due)
    sched_db = db_session.get(ScanSchedule, sched_id)
    assert sched_db is not None
    sched_db.next_run_at = utcnow() - timedelta(minutes=5)
    db_session.commit()

    # 2. Processar Agendamentos Devidos com SchedulerService (Execução Controlada)
    with patch("workers.tasks.execute_scan_task.delay") as mock_celery:
        mock_celery.return_value = MagicMock(id="celery-mock-task-e")
        dispatched = SchedulerService.trigger_due_schedules(db_session)
        assert len(dispatched) >= 1
        assert mock_celery.called

    # 3. Criar Notificação In-App com Deduplicação
    notif_svc = NotificationService()
    n1 = notif_svc.dispatch_event(
        db=db_session,
        organization_id=org.id,
        event_type="scan.completed",
        severity="INFO",
        title="Auditoria Concluída com Sucesso",
        message="A auditoria agendada no ativo lab-target foi concluída.",
    )
    assert n1 is not None

    # Notificação idêntica dentro da janela de deduplicação retorna a existente (sem flood)
    n2 = notif_svc.dispatch_event(
        db=db_session,
        organization_id=org.id,
        event_type="scan.completed",
        severity="INFO",
        title="Auditoria Concluída com Sucesso",
        message="A auditoria agendada no ativo lab-target foi concluída.",
        dedup_window_seconds=600,
    )
    assert n2 is not None
    assert n2.id == n1.id

    # Consultar notificações via API
    notifs = client.get("/api/v1/automations/notifications", headers=headers)
    assert notifs.status_code == 200
    notif_page = notifs.json()
    items = notif_page["items"]
    assert len(items) >= 1
    assert items[0]["title"] == "Auditoria Concluída com Sucesso"

    # 4. Criar Endpoint de Webhook com Assinatura HMAC
    endpoint_resp = client.post(
        "/api/v1/automations/webhooks",
        headers=headers,
        json={
            "url": "http://lab-target/webhook-receiver",
            "description": "Lab Webhook Receiver",
            "subscribed_events": ["scan.completed"],
        },
    )
    assert endpoint_resp.status_code == 201
    endpoint_id = endpoint_resp.json()["id"]

    # Simular Disparo do Webhook e Validar Assinatura Criptográfica
    with patch("httpx.Client.post") as mock_http_post:
        mock_http_post.return_value.status_code = 200
        mock_http_post.return_value.text = "OK"

        webhook_svc = WebhookService()
        delivery_ids = webhook_svc.dispatch_event_to_webhooks(
            db=db_session,
            organization_id=org.id,
            event_type="scan.completed",
            payload={"scan_id": "test-scan-123", "status": "COMPLETED"},
        )
        assert len(delivery_ids) >= 1

        # Verificar cabeçalho HMAC na chamada HTTP mockada
        assert mock_http_post.called
        call_kwargs = mock_http_post.call_args[1]
        sent_headers = call_kwargs["headers"]
        assert "X-CSC-Signature" in sent_headers
        assert sent_headers["X-CSC-Event"] == "scan.completed"

        # Validar assinatura HMAC-SHA256 gerada
        body = call_kwargs["content"]
        timestamp = sent_headers["X-CSC-Timestamp"]
        endpoint_record = db_session.get(WebhookEndpointRecord, endpoint_id)
        assert endpoint_record is not None
        expected_sig_base = f"{timestamp}.{body.decode('utf-8')}"
        expected_sig_hash = hmac.new(
            endpoint_record.secret_token.encode("utf-8"),
            expected_sig_base.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        assert sent_headers["X-CSC-Signature"] == f"sha256={expected_sig_hash}"

    # Verificar Histórico de Entregas Persistido no Banco
    deliveries = client.get(
        f"/api/v1/automations/webhooks/deliveries?webhook_id={endpoint_id}",
        headers=headers,
    )
    assert deliveries.status_code == 200
    deliv_items = deliveries.json()["items"]
    assert len(deliv_items) >= 1
    assert deliv_items[0]["status_code"] == 200
