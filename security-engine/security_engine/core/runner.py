"""Executor coordenado de módulos do Security Engine sobre snapshots reais HTTP/TLS."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from security_engine.core.contracts import (
    AssetType,
    CheckEvaluationResult,
    CheckStatus,
    EnvironmentType,
    HttpInspectionSnapshot,
    ModuleExecutionResult,
    NormalizedFinding,
)
from security_engine.core.http_client import (
    CircuitBreakerTrippedError,
    SafeHttpClientError,
    ScanCancelledError,
    ScopedSafeHttpClient,
)
from security_engine.core.registry import PluginRegistry, default_registry
from security_engine.core.risk import RiskEngine
from security_engine.policies.execution_policy import ScanExecutionPolicy
from security_engine.policies.scope_validator import (
    ScopePolicyValidator,
    ScopeViolationError,
)


@dataclass
class EngineExecutionSummary:
    """Resumo consolidado da execução de múltiplos módulos pelo SecurityEngineRunner."""

    final_status: str = "COMPLETED"
    snapshot: HttpInspectionSnapshot | None = None
    module_results: list[ModuleExecutionResult] = field(default_factory=list)
    completed_modules: list[str] = field(default_factory=list)
    failed_modules: list[str] = field(default_factory=list)
    all_checks: list[CheckEvaluationResult] = field(default_factory=list)
    all_findings: list[NormalizedFinding] = field(default_factory=list)
    total_requests: int = 0
    total_duration_ms: int = 0
    error_message: str | None = None


class SecurityEngineRunner:
    """Executa uma lista de módulos de segurança contra um ativo autorizado usando ScopedSafeHttpClient."""

    def __init__(
        self,
        scope_validator: ScopePolicyValidator,
        policy: ScanExecutionPolicy | None = None,
        registry: PluginRegistry | None = None,
        *,
        resolve_dns: bool = True,
        custom_resolver: list[str] | None = None,
        ca_bundle_path: str | None = None,
        http_redirect_probe_url: str | None = None,
    ) -> None:
        self.scope_validator = scope_validator
        self.policy = policy or ScanExecutionPolicy()
        self.registry = registry or default_registry
        self.resolve_dns = resolve_dns
        self.custom_resolver = custom_resolver
        self.ca_bundle_path = ca_bundle_path
        self.http_redirect_probe_url = http_redirect_probe_url

    def execute_modules(
        self,
        target_url: str,
        module_ids: list[str],
        *,
        asset_type: AssetType = AssetType.WEB_APP,
        environment: EnvironmentType = EnvironmentType.STAGING,
        is_cancelled: Callable[[], bool] | None = None,
        on_module_start: Callable[[str, int, int], None] | None = None,
        on_module_complete: Callable[[str, ModuleExecutionResult, int, int], None] | None = None,
    ) -> EngineExecutionSummary:
        """Coleta o snapshot HTTP/TLS seguro e executa sequencialmente cada módulo habilitado."""
        run_start = time.monotonic()
        summary = EngineExecutionSummary()

        validated_modules = self.registry.validate_modules_for_environment(module_ids, environment)
        http_client = ScopedSafeHttpClient(
            scope_validator=self.scope_validator,
            policy=self.policy,
            resolve_dns=self.resolve_dns,
            custom_resolver=self.custom_resolver,
            ca_bundle_path=self.ca_bundle_path,
        )

        try:
            snapshot = http_client.fetch_snapshot(
                target_url=target_url,
                asset_type=asset_type,
                environment=environment,
                is_cancelled=is_cancelled,
                inspect_tls=True,
                http_redirect_probe_url=self.http_redirect_probe_url,
            )
            summary.snapshot = snapshot
            summary.total_requests = snapshot.total_requests_made
        except ScanCancelledError as exc:
            summary.final_status = "CANCELLED"
            summary.error_message = str(exc)
            summary.total_duration_ms = int((time.monotonic() - run_start) * 1000)
            return summary
        except CircuitBreakerTrippedError as exc:
            summary.final_status = "ABORTED_TARGET_DEGRADED"
            summary.error_message = str(exc)
            summary.total_duration_ms = int((time.monotonic() - run_start) * 1000)
            return summary
        except (ScopeViolationError, SafeHttpClientError) as exc:
            summary.final_status = "FAILED"
            summary.error_message = str(exc)
            summary.total_duration_ms = int((time.monotonic() - run_start) * 1000)
            return summary

        if snapshot.connection_error and snapshot.status_code <= 0:
            summary.error_message = snapshot.connection_error

        total_mods = len(validated_modules)
        tls_dict: dict[str, Any] | None = (
            snapshot.tls_info.model_dump(mode="json") if snapshot.tls_info else None
        )
        redirect_dicts: list[dict[str, Any]] = [
            hop.model_dump(mode="json") for hop in snapshot.redirect_chain
        ]

        for idx, mod_id in enumerate(validated_modules, start=1):
            if is_cancelled and is_cancelled():
                summary.final_status = "CANCELLED"
                summary.error_message = "Auditoria cancelada pelo usuário durante a execução dos módulos."
                break

            if on_module_start:
                on_module_start(mod_id, idx, total_mods)

            mod_start = time.monotonic()
            module = self.registry.get_module(mod_id)

            try:
                mod_result = module.inspect_response_snapshot(
                    target_url=snapshot.final_url,
                    status_code=snapshot.status_code,
                    headers=snapshot.headers,
                    cookies=None,
                    tls_info=tls_dict,
                    body_excerpt=snapshot.body_excerpt,
                    is_Canceled=is_cancelled,
                    asset_type=asset_type,
                    redirect_chain=redirect_dicts,
                    raw_set_cookies=snapshot.raw_set_cookies,
                    http_to_https_redirected=snapshot.http_to_https_redirected,
                    initial_url=snapshot.initial_url,
                    http_client=http_client,
                )
                mod_result.duration_ms = max(1, int((time.monotonic() - mod_start) * 1000))

                # Garante consistência de severidade/confiança de todas as descobertas
                normalized_findings: list[NormalizedFinding] = []
                for finding in mod_result.findings:
                    normalized_findings.append(RiskEngine.validate_finding_consistency(finding))
                mod_result.findings = normalized_findings

                if mod_result.execution_errors > 0:
                    summary.failed_modules.append(mod_id)
                else:
                    summary.completed_modules.append(mod_id)
            except Exception as exc:  # noqa: BLE001
                duration_ms = max(1, int((time.monotonic() - mod_start) * 1000))
                err_check = CheckEvaluationResult(
                    check_id=f"{mod_id.upper()}-ERR",
                    module_id=mod_id,
                    title=f"Execução do módulo {module.metadata.name}",
                    status=CheckStatus.EXECUTION_ERROR,
                    duration_ms=duration_ms,
                    summary=f"Exceção interna durante execução do módulo: {exc}",
                )
                mod_result = ModuleExecutionResult(
                    module_id=mod_id,
                    checks=[err_check],
                    findings=[],
                    total_requests=0,
                    execution_errors=1,
                    duration_ms=duration_ms,
                )
                summary.failed_modules.append(mod_id)

            summary.module_results.append(mod_result)
            summary.all_checks.extend(mod_result.checks)
            summary.all_findings.extend(mod_result.findings)

            if on_module_complete:
                on_module_complete(mod_id, mod_result, idx, total_mods)

        summary.total_requests = http_client.total_requests_made
        if summary.final_status not in {"CANCELLED", "ABORTED_TARGET_DEGRADED", "FAILED"}:
            if summary.failed_modules and summary.completed_modules:
                summary.final_status = "PARTIALLY_COMPLETED"
            elif summary.failed_modules and not summary.completed_modules:
                summary.final_status = "FAILED"
                if not summary.error_message:
                    summary.error_message = (
                        f"Todos os módulos apresentaram erro operacional: {', '.join(summary.failed_modules)}"
                    )
            else:
                summary.final_status = "COMPLETED"

        summary.total_duration_ms = max(1, int((time.monotonic() - run_start) * 1000))
        return summary
