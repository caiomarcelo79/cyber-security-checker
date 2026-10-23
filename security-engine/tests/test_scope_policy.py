"""Testes unitários e de segurança do ScopePolicyValidator (TM-001)."""

import pytest
from security_engine.policies.scope_validator import (
    ScopePolicyValidator,
    ScopeViolationError,
)


def test_authorized_host_allowed_with_public_ip() -> None:
    validator = ScopePolicyValidator(
        authorized_hosts=["portal.empresa.com.br"],
        allow_subdomains=False,
        excluded_paths=["/logout", "/admin/delete"],
        block_private_networks=True,
    )
    decision = validator.validate_url(
        "https://portal.empresa.com.br/login",
        custom_resolver=["93.184.216.34"],
    )
    assert decision.allowed is True
    assert decision.hostname == "portal.empresa.com.br"
    assert decision.resolved_ips == ["93.184.216.34"]


def test_subdomain_blocked_by_default_when_not_explicitly_authorized() -> None:
    """Seção 12: A permissão para verificar um domínio não deve ser interpretada automaticamente
    como autorização para avaliar todos os seus subdomínios.
    """
    validator = ScopePolicyValidator(
        authorized_hosts=["empresa.com.br"],
        allow_subdomains=False,
    )
    with pytest.raises(ScopeViolationError, match="fora do escopo autorizado"):
        validator.validate_url("https://pagamentos.empresa.com.br/api")


def test_ssrf_blocks_loopback_and_private_rfc1918_ips() -> None:
    validator = ScopePolicyValidator(
        authorized_hosts=["alvo.interno.local", "127.0.0.1", "10.0.0.15", "192.168.1.20"],
        block_private_networks=True,
        allow_local_lab_targets=False,
    )
    for blocked_url in [
        "http://127.0.0.1:8080/admin",
        "http://10.0.0.15/internal",
        "http://192.168.1.20/config",
    ]:
        with pytest.raises(ScopeViolationError, match="Anti-SSRF"):
            validator.validate_url(blocked_url)

    with pytest.raises(ScopeViolationError, match="Anti-SSRF"):
        validator.validate_url(
            "https://alvo.interno.local/app",
            custom_resolver=["172.16.5.10"],
        )


def test_ssrf_always_blocks_cloud_metadata_even_in_lab_mode() -> None:
    validator = ScopePolicyValidator(
        authorized_hosts=["169.254.169.254", "metadata.google.internal"],
        block_private_networks=False,
        allow_local_lab_targets=True,
        lab_allowed_hosts=["169.254.169.254", "metadata.google.internal"],
    )
    with pytest.raises(ScopeViolationError, match="metadados de nuvem"):
        validator.validate_url("http://169.254.169.254/latest/meta-data/")

    with pytest.raises(ScopeViolationError, match="metadados de nuvem"):
        validator.validate_url("http://metadata.google.internal/computeMetadata/v1/")


def test_excluded_paths_and_out_of_scope_redirects_blocked() -> None:
    validator = ScopePolicyValidator(
        authorized_hosts=["app.empresa.com.br"],
        excluded_paths=["/logout", "/billing/destroy"],
    )
    with pytest.raises(ScopeViolationError, match="endpoints excluídos"):
        validator.validate_url("https://app.empresa.com.br/logout")

    with pytest.raises(ScopeViolationError, match="fora do escopo autorizado"):
        validator.validate_redirect_target(
            source_url="https://app.empresa.com.br/redirect",
            redirect_location="https://terceiro-nao-autorizado.com/login",
        )


def test_controlled_lab_target_allowed_only_when_explicitly_whitelisted() -> None:
    validator = ScopePolicyValidator(
        authorized_hosts=["lab-target"],
        block_private_networks=True,
        allow_local_lab_targets=True,
        lab_allowed_hosts=["lab-target"],
    )
    decision = validator.validate_url(
        "http://lab-target:8080/health",
        custom_resolver=["172.18.0.5"],
    )
    assert decision.allowed is True
    assert decision.hostname == "lab-target"
