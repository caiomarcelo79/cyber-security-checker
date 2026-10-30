"""Testes automatizados da exportação direta de PDF com medidas protetivas e diagnósticos operacionais."""

from __future__ import annotations

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


def _setup_scan_with_findings_and_errors(
    db: Session,
) -> tuple[str, str, str]:
    org = Organization(name="Org PDF Test", slug=f"org-pdf-{utcnow().timestamp()}")
    user = User(
        email=f"user_pdf_{utcnow().timestamp()}@secops.local",
        hashed_password=hash_password("SecOpsPass123!"),
        full_name="Analista Auditor",
    )
    db.add_all([org, user])
    db.flush()

    membership = OrganizationMembership(
        organization_id=org.id, user_id=user.id, role="SECURITY_ANALYST"
    )
    db.add(membership)

    asset = Asset(
        organization_id=org.id,
        name="Portal Financeiro Lab",
        target_url="https://financeiro.csc-lab.local",
        hostname="financeiro.csc-lab.local",
        asset_type="WEB_APP",
        environment="LAB",
        owner_name="DevSec",
        owner_email="devsec@csc-lab.local",
        authorization_status="VERIFIED",
        risk_score=78,
    )
    db.add(asset)
    db.flush()

    auth = TargetAuthorization(
        organization_id=org.id,
        asset_id=asset.id,
        verified_by_user_id=user.id,
        method="DNS_TXT",
        status="VERIFIED",
        verification_token="csc-verify-token-1234",
    )
    db.add(auth)

    scan = Scan(
        organization_id=org.id,
        asset_id=asset.id,
        initiated_by_user_id=user.id,
        profile_type="FULL",
        status="COMPLETED",
        total_checks_run=14,
        progress_percent=100,
        started_at=utcnow(),
        completed_at=utcnow(),
    )
    db.add(scan)
    db.flush()

    # Adiciona 1 falha de execução técnica (EXECUTION_ERROR)
    err_check = ScanCheckResultRecord(
        scan_id=scan.id,
        module_id="mod_f_dos_resilience_posture",
        check_id="CHK-F04",
        title="Inconsistência de Cabeçalhos HTTP (Request Smuggling)",
        status="EXECUTION_ERROR",
        summary="Conexão resetada pelo gateway durante canário não destrutivo.",
        duration_ms=45,
    )
    ok_check = ScanCheckResultRecord(
        scan_id=scan.id,
        module_id="mod_a_recon_headers_tls",
        check_id="CHK-A01",
        title="Disponibilidade HTTPS e HSTS",
        status="PASSED",
        summary="HSTS ativo com max-age adequado.",
        duration_ms=25,
    )
    db.add_all([err_check, ok_check])

    # Adiciona 1 finding com playbook completo de medidas protetivas
    finding = FindingRecord(
        organization_id=org.id,
        asset_id=asset.id,
        scan_id=scan.id,
        fingerprint=f"fp-b04-{utcnow().timestamp()}",
        module_id="mod_b_auth_login",
        check_id="CHK-B04",
        title="Transmissão Insegura de Credenciais via Query String",
        description="Parâmetros de login detectados na URL via método GET.",
        category="Autenticação e Proteção de Segredos",
        result_classification="VULNERABILITY",
        severity="HIGH",
        confidence="CERTAIN",
        affected_endpoint="https://financeiro.csc-lab.local/login?user=admin&password=REDACTED",
        impact="Vazamento de credenciais em logs e histórico do navegador.",
        treatment_status="OPEN",
        evidence={
            "observed_value": "Parâmetros sensíveis na URL: ['password']",
            "expected_baseline": "Submissão via corpo HTTP com método POST",
            "request_url": "https://financeiro.csc-lab.local/login",
        },
        remediation_data={
            "what_was_identified": "O endpoint de autenticação recebe credenciais via query string.",
            "why_it_is_dangerous": "URLs com senhas são armazenadas em histórico de navegadores, logs de proxy e servidores.",
            "how_it_was_detected": "Análise determinística de parâmetros sensíveis na URL durante requisição GET.",
            "how_to_fix": "Migrar a submissão de credenciais exclusivamente para o corpo HTTP com método POST.",
            "secure_examples": [
                {
                    "technology": "Python / FastAPI",
                    "code": "@app.post('/api/v1/auth/login')\ndef login(data: LoginSchema):\n    return auth_service.authenticate(data.user, data.password)",
                    "explanation": "Recebe as credenciais encapsuladas no corpo JSON sob TLS.",
                },
                {
                    "technology": "HTML Form",
                    "code": "<form method='POST' action='/api/v1/auth/login'>\n  <input type='password' name='password' />\n</form>",
                    "explanation": "Usa método POST para evitar que o navegador anexe os campos na URL.",
                },
            ],
            "how_to_validate": "Enviar requisição GET para o endpoint e verificar se o servidor retorna HTTP 405 Method Not Allowed.",
            "references": ["CWE-598", "OWASP ASVS 5.0 - V2.10.1"],
        },
    )
    db.add(finding)
    db.commit()

    token = create_access_token(
        user_id=user.id,
        email=user.email,
        organization_id=org.id,
        role="SECURITY_ANALYST",
    )
    return scan.id, org.id, token


def test_export_scan_pdf_direct_endpoint_success(db_session: Session, client: TestClient) -> None:
    scan_id, _org_id, token = _setup_scan_with_findings_and_errors(db_session)

    headers = {"Authorization": f"Bearer {token}"}
    resp = client.get(f"/api/v1/scans/{scan_id}/export-pdf", headers=headers)

    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert "attachment" in resp.headers.get("content-disposition", "")
    assert f"csc-auditoria-{scan_id[:8]}.pdf" in resp.headers.get("content-disposition", "")

    # Valida formato binário do PDF
    pdf_bytes = resp.content
    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 1000

    # Segunda chamada: deve ser idempotente e retornar o mesmo relatório armazenado
    resp2 = client.get(f"/api/v1/scans/{scan_id}/export-pdf", headers=headers)
    assert resp2.status_code == 200
    assert resp2.content == pdf_bytes


def test_export_scan_pdf_requires_valid_token_and_tenant_isolation(
    db_session: Session, client: TestClient
) -> None:
    scan_id, _org_id, _token_a = _setup_scan_with_findings_and_errors(db_session)

    # 1. Sem token -> 401 Unauthorized
    resp_no_auth = client.get(f"/api/v1/scans/{scan_id}/export-pdf")
    assert resp_no_auth.status_code == 401

    # 2. Outra organização (Org B) não pode exportar scan da Org A -> 404
    other_org = Organization(name="Outra Org", slug=f"other-{utcnow().timestamp()}")
    other_user = User(
        email=f"other_{utcnow().timestamp()}@secops.local",
        hashed_password=hash_password("Pass123!"),
        full_name="Outro Usuário",
    )
    db_session.add_all([other_org, other_user])
    db_session.flush()
    db_session.add(
        OrganizationMembership(
            organization_id=other_org.id, user_id=other_user.id, role="SECURITY_ANALYST"
        )
    )
    db_session.commit()

    token_b = create_access_token(
        user_id=other_user.id,
        email=other_user.email,
        organization_id=other_org.id,
        role="SECURITY_ANALYST",
    )
    resp_org_b = client.get(
        f"/api/v1/scans/{scan_id}/export-pdf",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert resp_org_b.status_code == 404
