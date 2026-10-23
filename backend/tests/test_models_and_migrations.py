"""Testes de integridade relacional dos modelos SQLAlchemy 2.0 e métricas reais (TM-007)."""

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.entities import Asset, FindingRecord, Organization, Scan, TargetAuthorization


def test_persisted_entities_reflect_in_real_dashboard_metrics(
    db_session: Session,
    client: TestClient,
) -> None:
    org = Organization(name="Laboratório Defensivo SecOps", slug="lab-secops")
    db_session.add(org)
    db_session.flush()

    asset = Asset(
        organization_id=org.id,
        name="Portal Homologação",
        target_url="https://homolog.secops.local",
        hostname="homolog.secops.local",
        asset_type="WEB_APP",
        environment="LAB",
        owner_name="Equipe AppSec",
        owner_email="appsec@secops.local",
        tags=["homolog", "web"],
        excluded_paths=["/logout"],
        authorization_status="VERIFIED",
        risk_score=45,
    )
    db_session.add(asset)
    db_session.flush()

    auth = TargetAuthorization(
        asset_id=asset.id,
        organization_id=org.id,
        method="LAB_INTERNAL",
        verification_token="cyber-sec-checker-verify=tok_123",
        status="VERIFIED",
    )
    db_session.add(auth)

    scan = Scan(
        organization_id=org.id,
        asset_id=asset.id,
        profile_type="QUICK",
        status="COMPLETED",
        progress_percent=100,
        enabled_modules=["mod_a_recon_headers_tls"],
        total_checks_run=5,
        findings_summary={"CRITICAL": 1, "MEDIUM": 1},
    )
    db_session.add(scan)
    db_session.flush()

    finding = FindingRecord(
        organization_id=org.id,
        asset_id=asset.id,
        scan_id=scan.id,
        fingerprint="fp_001_hsts",
        module_id="mod_a_recon_headers_tls",
        check_id="CHK-A02",
        title="Ausência de HSTS",
        description="Header Strict-Transport-Security ausente",
        category="Configuração de Segurança",
        result_classification="VULNERABILITY",
        severity="CRITICAL",
        confidence="CERTAIN",
        affected_endpoint="https://homolog.secops.local",
        evidence={"observed_value": "ausente"},
        impact="Downgrade de protocolo",
        reproduction_steps=["GET https://homolog.secops.local"],
        remediation_data={"remediation_id": "missing_hsts"},
        treatment_status="OPEN",
    )
    db_session.add(finding)
    db_session.commit()

    summary_resp = client.get("/api/v1/dashboard/summary")
    assert summary_resp.status_code == 200
    summary = summary_resp.json()
    assert summary["total_organizations"] == 1
    assert summary["total_assets"] == 1
    assert summary["verified_assets"] == 1
    assert summary["total_scans_executed"] == 1
    assert summary["open_vulnerabilities"] == 1
    assert summary["critical_vulnerabilities"] == 1
