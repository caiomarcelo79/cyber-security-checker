"""Testes de contratos de módulos, PluginRegistry, RiskEngine e RemediationEngine (TM-003)."""

import pytest
from security_engine.core.contracts import (
    CheckStatus,
    Confidence,
    EnvironmentType,
)
from security_engine.core.registry import PluginRegistry
from security_engine.core.remediation import RemediationEngine
from security_engine.core.risk import RiskEngine


def test_plugin_registry_discovers_all_eight_modules_and_toggles_state() -> None:
    registry = PluginRegistry(register_builtins=True)
    modules = registry.list_metadata(only_enabled=False)
    assert len(modules) == 8

    codes = {m.code for m in modules}
    assert codes == {
        "MÓDULO A",
        "MÓDULO B",
        "MÓDULO C",
        "MÓDULO D",
        "MÓDULO E",
        "MÓDULO F",
        "MÓDULO G",
        "MÓDULO H",
    }

    # Módulo D (SQLi controlado) é bloqueado em produção por padrão
    with pytest.raises(ValueError, match="não é permitido em alvos de PRODUÇÃO"):
        registry.validate_modules_for_environment(
            ["mod_d_sqli_indicators"],
            EnvironmentType.PRODUCTION,
        )

    # Em ambiente LAB ou STAGING é permitido
    validated = registry.validate_modules_for_environment(
        ["mod_d_sqli_indicators"],
        EnvironmentType.LAB,
    )
    assert validated == ["mod_d_sqli_indicators"]


def test_module_a_and_e_real_snapshot_inspection() -> None:
    registry = PluginRegistry(register_builtins=True)
    mod_a = registry.get_module("mod_a_recon_headers_tls")
    mod_e = registry.get_module("mod_e_cookies_session")

    insecure_headers = {
        "Server": "nginx/1.18.0",
        "X-Powered-By": "Express",
        "Set-Cookie": "sid=secret1234567890; Path=/",
    }

    res_a = mod_a.inspect_response_snapshot(
        target_url="https://lab.local/login",
        status_code=200,
        headers=insecure_headers,
    )
    assert len(res_a.checks) >= 6
    assert len(res_a.findings) == 6  # HSTS, CSP, XCTO, Clickjacking, Referrer/Permissions-Policy, Server Version

    res_e = mod_e.inspect_response_snapshot(
        target_url="https://lab.local/login",
        status_code=200,
        headers=insecure_headers,
    )
    assert len(res_e.findings) == 1
    cookie_finding = res_e.findings[0]
    assert "secret1234567890" not in (cookie_finding.evidence.observed_value or "")
    assert cookie_finding.remediation.what_was_identified
    assert len(cookie_finding.remediation.secure_examples) >= 2


def test_risk_engine_prevents_tentative_from_being_confirmed_vulnerability() -> None:
    adjusted = RiskEngine.validate_classification_consistency(
        CheckStatus.VULNERABILITY,
        Confidence.TENTATIVE,
    )
    assert adjusted == CheckStatus.POTENTIAL_VULNERABILITY

    guidance = RemediationEngine.get_guidance("missing_hsts")
    assert len(guidance.references) >= 3
    assert any(ex.technology == "Nginx" for ex in guidance.secure_examples)
