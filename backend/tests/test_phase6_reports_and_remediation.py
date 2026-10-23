"""Testes automatizados da Fase 6: Relatórios, Comparação de Auditorias e Revalidação (TM-018)."""

from __future__ import annotations

import json
from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.security import create_access_token, hash_password
from app.models.entities import (
    Asset,
    FindingRecord,
    Organization,
    OrganizationMembership,
    Scan,
    ScanCheckResultRecord,
    TargetAuthorization,
    User,
    utcnow,
)
from app.services.report_engine import sanitize_csv_cell


def _setup_org_and_user(
    db: Session,
    org_name: str = "SecOps Lab Fase 6",
    role: str = "SECURITY_ANALYST",
) -> tuple[Organization, User, str]:
    org = Organization(name=org_name, slug=f"slug-{utcnow().timestamp()}")
    user = User(
        email=f"user_{utcnow().timestamp()}@secops.local",
        hashed_password=hash_password("SecOpsPass123!"),
        full_name="Analista AppSec",
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


def test_sanitize_csv_cell_formula_injection() -> None:
    """Valida a mitigação de CSV Formula Injection (DDE) segundo as diretrizes de segurança."""
    assert sanitize_csv_cell("=1+1") == "'=1+1"
    assert sanitize_csv_cell("+cmd|' /C calc'!A0") == "'+cmd|' /C calc'!A0"
    assert sanitize_csv_cell("-5+2") == "'-5+2"
    assert sanitize_csv_cell("@SUM(A1:A10)") == "'@SUM(A1:A10)"
    assert sanitize_csv_cell("\tTAB") == "'\tTAB"
    assert sanitize_csv_cell("Texto Normal") == "Texto Normal"
    assert sanitize_csv_cell(123) == "123"
    assert sanitize_csv_cell(None) == ""


def test_reports_generation_all_formats_and_downloads(db_session: Session, client: TestClient) -> None:
    """Valida a geração real de relatórios nos formatos JSON, CSV, HTML e PDF com isolamento de tenant."""
    org, user, token = _setup_org_and_user(db_session, "Empresa Alpha Reports")

    asset = Asset(
        organization_id=org.id,
        name="Portal Alpha",
        target_url="https://alpha.secops.local",
        hostname="alpha.secops.local",
        asset_type="WEB_APP",
        environment="LAB",
        owner_name="Equipe Alpha",
        owner_email="alpha@secops.local",
        authorization_status="VERIFIED",
        risk_score=75,
    )
    db_session.add(asset)
    db_session.flush()

    auth = TargetAuthorization(
        asset_id=asset.id,
        organization_id=org.id,
        method="LAB_INTERNAL",
        verification_token="token_auth_alpha_123",
        status="VERIFIED",
    )
    db_session.add(auth)

    scan = Scan(
        organization_id=org.id,
        asset_id=asset.id,
        initiated_by_user_id=user.id,
        profile_type="QUICK",
        status="COMPLETED",
        progress_percent=100,
        enabled_modules=["mod_a_recon_headers_tls"],
        total_checks_run=8,
        findings_summary={"CRITICAL": 1, "HIGH": 1},
    )
    db_session.add(scan)
    db_session.flush()

    # Cria vulnerabilidade contendo tentativa de injeção de fórmula e script HTML para testar sanitização
    finding1 = FindingRecord(
        organization_id=org.id,
        asset_id=asset.id,
        scan_id=scan.id,
        fingerprint="fp_test_001_hsts",
        module_id="mod_a_recon_headers_tls",
        check_id="CHK-A02",
        title="=cmd|' /C calc'!A0 Header Inseguro",
        description="<script>alert('xss')</script> Descrição vulnerável",
        category="Configuração de Segurança",
        result_classification="VULNERABILITY",
        severity="CRITICAL",
        confidence="CERTAIN",
        affected_endpoint="https://alpha.secops.local/login",
        evidence={"observed_value": "missing"},
        impact="Exposição a ataques de Man-in-the-Middle",
        reproduction_steps=["GET https://alpha.secops.local/login"],
        remediation_data={"explanation": "Adicionar header HSTS com max-age"},
        treatment_status="OPEN",
        priority="P1",
        sla_deadline=utcnow() + timedelta(days=7),
    )
    finding2 = FindingRecord(
        organization_id=org.id,
        asset_id=asset.id,
        scan_id=scan.id,
        fingerprint="fp_test_002_csp",
        module_id="mod_a_recon_headers_tls",
        check_id="CHK-A04",
        title="Ausência de Content Security Policy",
        description="Diretivas CSP ausentes",
        category="Proteção contra Injeção de Código",
        result_classification="VULNERABILITY",
        severity="HIGH",
        confidence="FIRM",
        affected_endpoint="https://alpha.secops.local",
        evidence={"observed_value": "none"},
        impact="Possibilidade de ataques XSS",
        reproduction_steps=["GET https://alpha.secops.local"],
        remediation_data={"explanation": "Definir CSP restrito"},
        treatment_status="IN_PROGRESS",
        priority="P2",
    )
    db_session.add_all([finding1, finding2])
    db_session.commit()

    headers = {"Authorization": f"Bearer {token}"}

    # 1. Geração JSON
    resp_json = client.post(
        "/api/v1/reports",
        json={
            "report_type": "EXECUTIVE",
            "format": "JSON",
            "asset_id": asset.id,
            "title": "Relatório Executivo Alpha JSON",
        },
        headers=headers,
    )
    assert resp_json.status_code == 201, resp_json.text
    rep_json_data = resp_json.json()
    assert rep_json_data["status"] == "COMPLETED"
    assert rep_json_data["file_size_bytes"] > 0
    assert rep_json_data["summary_data"]["total_findings"] == 2
    download_token = rep_json_data["download_token"]

    # Download do arquivo JSON
    dl_json = client.get(f"/api/v1/reports/{rep_json_data['id']}/download", headers=headers)
    assert dl_json.status_code == 200
    assert dl_json.headers["content-type"].startswith("application/json")
    parsed_json = json.loads(dl_json.content.decode("utf-8"))
    assert parsed_json["organization_name"] == "Empresa Alpha Reports"
    assert len(parsed_json["findings"]) == 2

    # Download por token público autorizado
    token_dl = client.get(f"/api/v1/reports/download-by-token/{download_token}")
    assert token_dl.status_code == 200

    # 2. Geração CSV com validação anti-formula injection
    resp_csv = client.post(
        "/api/v1/reports",
        json={
            "report_type": "TECHNICAL",
            "format": "CSV",
            "asset_id": asset.id,
            "title": "Relatório Técnico Alpha CSV",
        },
        headers=headers,
    )
    assert resp_csv.status_code == 201
    rep_csv_data = resp_csv.json()
    dl_csv = client.get(f"/api/v1/reports/{rep_csv_data['id']}/download", headers=headers)
    assert dl_csv.status_code == 200
    csv_text = dl_csv.content.decode("utf-8-sig")
    assert "'=cmd|" in csv_text  # Verifica que o '=' foi prefixado com apóstrofo

    # 3. Geração HTML com sanitização de tags
    resp_html = client.post(
        "/api/v1/reports",
        json={
            "report_type": "TECHNICAL",
            "format": "HTML",
            "asset_id": asset.id,
            "title": "Relatório Técnico Alpha HTML",
        },
        headers=headers,
    )
    assert resp_html.status_code == 201
    rep_html_data = resp_html.json()
    dl_html = client.get(f"/api/v1/reports/{rep_html_data['id']}/download", headers=headers)
    assert dl_html.status_code == 200
    html_text = dl_html.content.decode("utf-8")
    assert "<script>alert" not in html_text
    assert "&lt;script&gt;alert" in html_text

    # 4. Geração PDF via ReportLab
    resp_pdf = client.post(
        "/api/v1/reports",
        json={
            "report_type": "EXECUTIVE",
            "format": "PDF",
            "asset_id": asset.id,
            "title": "Relatório Executivo Alpha PDF",
        },
        headers=headers,
    )
    assert resp_pdf.status_code == 201
    rep_pdf_data = resp_pdf.json()
    assert rep_pdf_data["file_size_bytes"] > 500
    dl_pdf = client.get(f"/api/v1/reports/{rep_pdf_data['id']}/download", headers=headers)
    assert dl_pdf.status_code == 200
    assert dl_pdf.headers["content-type"] == "application/pdf"
    assert dl_pdf.content.startswith(b"%PDF-")

    # 5. Listagem de relatórios com paginação
    list_resp = client.get("/api/v1/reports?limit=10", headers=headers)
    assert list_resp.status_code == 200
    page_data = list_resp.json()
    assert page_data["total"] >= 4
    assert len(page_data["items"]) >= 4

    # 6. Teste de isolamento multi-tenant: outra organização não pode acessar
    _, _, other_token = _setup_org_and_user(db_session, "Outra Org Invasora")
    other_headers = {"Authorization": f"Bearer {other_token}"}
    forb_resp = client.get(f"/api/v1/reports/{rep_pdf_data['id']}/download", headers=other_headers)
    assert forb_resp.status_code == 404


def test_scan_comparison_with_coverage_parity(db_session: Session, client: TestClient) -> None:
    """Valida o motor de comparação entre duas auditorias, distinguindo novas, persistentes, resolvidas e falhas de cobertura."""
    org, _user, token = _setup_org_and_user(db_session, "Empresa Comparação")
    headers = {"Authorization": f"Bearer {token}"}

    asset = Asset(
        organization_id=org.id,
        name="API Gateway Comparação",
        target_url="https://gateway.secops.local",
        hostname="gateway.secops.local",
        asset_type="REST_API",
        environment="LAB",
        owner_name="Equipe Gateway",
        owner_email="gateway@secops.local",
        authorization_status="VERIFIED",
    )
    db_session.add(asset)
    db_session.flush()

    # Auditoria A (Base): Módulos A e E
    scan_a = Scan(
        organization_id=org.id,
        asset_id=asset.id,
        profile_type="QUICK",
        status="COMPLETED",
        enabled_modules=["mod_a_recon_headers_tls", "mod_e_cookies_session"],
        total_checks_run=10,
    )
    db_session.add(scan_a)
    db_session.flush()

    # Falha 1 (HSTS) e Falha 2 (Cookie sem HttpOnly) em Scan A
    f1_a = FindingRecord(
        organization_id=org.id,
        asset_id=asset.id,
        scan_id=scan_a.id,
        fingerprint="fp_comp_hsts",
        module_id="mod_a_recon_headers_tls",
        check_id="CHK-A02",
        title="Ausência de HSTS",
        description="Falta de Strict-Transport-Security",
        category="Configuração",
        result_classification="VULNERABILITY",
        severity="HIGH",
        confidence="CERTAIN",
        affected_endpoint="https://gateway.secops.local",
        evidence={},
        impact="MitM",
        reproduction_steps=[],
        remediation_data={},
        treatment_status="OPEN",
    )
    f2_a = FindingRecord(
        organization_id=org.id,
        asset_id=asset.id,
        scan_id=scan_a.id,
        fingerprint="fp_comp_cookie",
        module_id="mod_e_cookies_session",
        check_id="CHK-E01",
        title="Cookie sem flag HttpOnly",
        description="Sessão acessível por JavaScript",
        category="Cookies e Sessão",
        result_classification="VULNERABILITY",
        severity="CRITICAL",
        confidence="CERTAIN",
        affected_endpoint="https://gateway.secops.local",
        evidence={},
        impact="Roubo de sessão",
        reproduction_steps=[],
        remediation_data={},
        treatment_status="OPEN",
    )
    db_session.add_all([f1_a, f2_a])

    # Auditoria B (Recente): Módulos A, E e C
    scan_b = Scan(
        organization_id=org.id,
        asset_id=asset.id,
        profile_type="STANDARD",
        status="COMPLETED",
        enabled_modules=["mod_a_recon_headers_tls", "mod_e_cookies_session", "mod_c_xss_safe"],
        total_checks_run=15,
    )
    db_session.add(scan_b)
    db_session.flush()

    # Em Scan B:
    # 1. HSTS persiste, mas com alteração de severidade
    f1_b = FindingRecord(
        organization_id=org.id,
        asset_id=asset.id,
        scan_id=scan_b.id,
        fingerprint="fp_comp_hsts",
        module_id="mod_a_recon_headers_tls",
        check_id="CHK-A02",
        title="Ausência de HSTS",
        description="Falta de Strict-Transport-Security",
        category="Configuração",
        result_classification="VULNERABILITY",
        severity="MEDIUM",  # Alterou de HIGH para MEDIUM
        confidence="CERTAIN",
        affected_endpoint="https://gateway.secops.local",
        evidence={},
        impact="MitM",
        reproduction_steps=[],
        remediation_data={},
        treatment_status="OPEN",
    )
    # 2. Nova vulnerabilidade de XSS detectada
    f3_b = FindingRecord(
        organization_id=org.id,
        asset_id=asset.id,
        scan_id=scan_b.id,
        fingerprint="fp_comp_xss",
        module_id="mod_c_xss_safe",
        check_id="CHK-C01",
        title="Reflexão de Parâmetros Insegura",
        description="Reflexão identificada",
        category="Injeção",
        result_classification="VULNERABILITY",
        severity="HIGH",
        confidence="FIRM",
        affected_endpoint="https://gateway.secops.local/search",
        evidence={},
        impact="XSS",
        reproduction_steps=[],
        remediation_data={},
        treatment_status="OPEN",
    )
    db_session.add_all([f1_b, f3_b])

    # Em Scan B, o teste CHK-E01 rodou e deu PASSED (comprovando resolução da falha f2_a!)
    chk_e01_passed = ScanCheckResultRecord(
        scan_id=scan_b.id,
        module_id="mod_e_cookies_session",
        check_id="CHK-E01",
        title="Verificação de Cookies HttpOnly",
        status="PASSED",
        duration_ms=45,
        summary="Todos os cookies de sessão apresentam HttpOnly",
        details={},
    )
    db_session.add(chk_e01_passed)
    db_session.commit()

    # Executa a comparação via API
    comp_resp = client.get(
        f"/api/v1/scans/{scan_a.id}/compare/{scan_b.id}",
        headers=headers,
    )
    assert comp_resp.status_code == 200, comp_resp.text
    comp_data = comp_resp.json()

    assert comp_data["total_findings_a"] == 2
    assert comp_data["total_findings_b"] == 2
    summary = comp_data["comparison_summary"]
    assert summary["new_count"] == 1
    assert summary["persistent_count"] == 1
    assert summary["confirmed_remediated_count"] == 1
    assert summary["severity_changes_count"] == 1

    assert comp_data["new_findings"][0]["fingerprint"] == "fp_comp_xss"
    assert comp_data["persistent_findings"][0]["fingerprint"] == "fp_comp_hsts"
    assert comp_data["confirmed_remediated"][0]["fingerprint"] == "fp_comp_cookie"
    assert comp_data["severity_changes"][0]["previous_severity"] == "HIGH"
    assert comp_data["severity_changes"][0]["current_severity"] == "MEDIUM"

    cov = comp_data["coverage_diff"]
    assert "mod_c_xss_safe" in cov["modules_added_in_b"]


def test_revalidation_and_lifecycle_transitions(db_session: Session, client: TestClient) -> None:
    """Valida o fluxo de triagem, SLA, justificativa de risco aceito e revalidação de vulnerabilidade."""
    org, _user, token = _setup_org_and_user(db_session, "Empresa Revalidação")
    headers = {"Authorization": f"Bearer {token}"}

    asset = Asset(
        organization_id=org.id,
        name="Serviço de Autenticação",
        target_url="http://127.0.0.1:9",
        hostname="127.0.0.1",
        asset_type="REST_API",
        environment="LAB",
        owner_name="Equipe Auth",
        owner_email="auth@secops.local",
        authorization_status="VERIFIED",
        risk_score=50,
    )
    db_session.add(asset)
    db_session.flush()

    auth = TargetAuthorization(
        asset_id=asset.id,
        organization_id=org.id,
        method="LAB_INTERNAL",
        verification_token="token_reval_123",
        status="VERIFIED",
    )
    db_session.add(auth)

    scan = Scan(
        organization_id=org.id,
        asset_id=asset.id,
        profile_type="QUICK",
        status="COMPLETED",
        enabled_modules=["mod_a_recon_headers_tls"],
    )
    db_session.add(scan)
    db_session.flush()

    finding = FindingRecord(
        organization_id=org.id,
        asset_id=asset.id,
        scan_id=scan.id,
        fingerprint="fp_reval_test_xfo",
        module_id="mod_a_recon_headers_tls",
        check_id="CHK-A05",
        title="Ausência de X-Frame-Options",
        description="Falta de cabeçalho anti-clickjacking",
        category="Configuração",
        result_classification="VULNERABILITY",
        severity="MEDIUM",
        confidence="CERTAIN",
        affected_endpoint="http://127.0.0.1:9",
        evidence={},
        impact="Clickjacking",
        reproduction_steps=[],
        remediation_data={},
        treatment_status="OPEN",
    )
    db_session.add(finding)
    db_session.commit()

    # 1. Atualização para ACCEPTED_RISK sem justificativa deve ser rejeitada com 422
    fail_risk = client.patch(
        f"/api/v1/findings/{finding.id}/status",
        json={"treatment_status": "ACCEPTED_RISK"},
        headers=headers,
    )
    assert fail_risk.status_code == 422

    # 2. Atualização para ACCEPTED_RISK com justificativa formal é aceita
    ok_risk = client.patch(
        f"/api/v1/findings/{finding.id}/status",
        json={
            "treatment_status": "ACCEPTED_RISK",
            "risk_acceptance_reason": "Serviço é exclusivamente consumido por backend interno via mTLS.",
            "priority": "P3",
        },
        headers=headers,
    )
    assert ok_risk.status_code == 200
    assert ok_risk.json()["treatment_status"] == "ACCEPTED_RISK"
    assert ok_risk.json()["risk_acceptance_reason"] is not None

    # 3. Transição para WAITING_VALIDATION
    prep_reval = client.patch(
        f"/api/v1/findings/{finding.id}/status",
        json={
            "treatment_status": "WAITING_VALIDATION",
            "triage_note": "Header X-Frame-Options: DENY adicionado no nginx de laboratório.",
        },
        headers=headers,
    )
    assert prep_reval.status_code == 200
    assert prep_reval.json()["treatment_status"] == "WAITING_VALIDATION"

    # 4. Solicitação de revalidação técnica
    reval_resp = client.post(
        f"/api/v1/findings/{finding.id}/revalidate",
        json={"triage_note": "Revalidação pós-deploy de correção"},
        headers=headers,
    )
    assert reval_resp.status_code == 200
    reval_data = reval_resp.json()
    assert reval_data["finding_id"] == finding.id
    assert "status" in reval_data

    # 5. Consulta evolução de métricas temporais da Fase 6
    evol_resp = client.get("/api/v1/dashboard/evolution?days=14", headers=headers)
    assert evol_resp.status_code == 200
    evol_data = evol_resp.json()
    assert evol_data["days"] == 14
    assert len(evol_data["points"]) == 14
    assert "total_active_unresolved" in evol_data
