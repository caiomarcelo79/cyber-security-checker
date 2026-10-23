"""Testes dos limites operacionais obrigatórios (ScanExecutionPolicy - TM-004)."""

from security_engine.policies.execution_policy import (
    HARD_CAP_MAX_CONCURRENCY,
    HARD_CAP_MAX_REDIRECTS,
    HARD_CAP_MAX_RPS,
    ScanExecutionPolicy,
    get_scan_profiles,
)


def test_mandatory_guardrails_cannot_be_disabled_or_exceeded() -> None:
    """Seção 12: Não permitir que um usuário desative completamente as proteções obrigatórias."""
    policy = ScanExecutionPolicy(
        max_requests_per_second=9999,
        max_concurrency=500,
        request_timeout_seconds=999,
        max_redirects=100,
        respect_http_429_and_503=False,
        abort_on_target_degradation=False,
        prevent_redirect_loops=False,
        excluded_endpoints=["logout", "/admin/drop"],
    )

    assert policy.max_requests_per_second == HARD_CAP_MAX_RPS
    assert policy.max_concurrency == HARD_CAP_MAX_CONCURRENCY
    assert policy.max_redirects == HARD_CAP_MAX_REDIRECTS
    assert policy.respect_http_429_and_503 is True
    assert policy.abort_on_target_degradation is True
    assert policy.prevent_redirect_loops is True
    assert "/logout" in policy.excluded_endpoints
    assert "/admin/drop" in policy.excluded_endpoints


def test_scan_profiles_catalog_completeness() -> None:
    profiles = get_scan_profiles()
    assert len(profiles) == 6
    for profile in profiles:
        assert profile.what_is_analyzed
        assert profile.what_is_not_analyzed
        assert profile.prerequisites
        assert profile.known_risks
        assert profile.enabled_modules
