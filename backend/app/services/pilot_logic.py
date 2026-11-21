"""Regras puras de avaliação de ciclo de vida, prontidão e escopo do piloto (Fase 6)."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import ip_network
from typing import Literal

PILOT_STAGES: tuple[str, ...] = ("OWN_ENVIRONMENT", "AUTHORIZED_CLIENT")
PILOT_CAPABILITIES: tuple[str, ...] = (
    "TELEMETRY",
    "TRAFFIC_ANALYSIS",
    "AVAILABILITY",
    "SSH_AUDIT",
    "AI_TRIAGE",
)
CORE_TRAFFIC_LAYERS: tuple[str, ...] = ("CONNECTIONS", "DNS", "TLS", "EDR")

PilotStage = Literal["OWN_ENVIRONMENT", "AUTHORIZED_CLIENT"]
PilotStatus = Literal["ACTIVE", "PAUSED", "EXPIRED", "REVOKED"]
PilotCapability = Literal[
    "TELEMETRY",
    "TRAFFIC_ANALYSIS",
    "AVAILABILITY",
    "SSH_AUDIT",
    "AI_TRIAGE",
]
PilotReviewDecision = Literal["APPROVED_FOR_EXPANSION", "NEEDS_ADJUSTMENT"]
CollectorUpdateStatus = Literal["UP_TO_DATE", "UPDATE_AVAILABLE", "UNKNOWN"]


def as_utc(value: datetime) -> datetime:
    """Normaliza datetimes ingênuos (SQLite) para UTC consciente."""
    return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)


def effective_pilot_status(
    status: str,
    expires_at: datetime,
    paused_at: datetime | None,
    revoked_at: datetime | None,
    now: datetime,
) -> PilotStatus:
    """Deriva o estado efetivo do piloto considerando revogação, expiração e pausa."""
    if revoked_at is not None or status == "REVOKED":
        return "REVOKED"
    if as_utc(expires_at) <= as_utc(now) or status == "EXPIRED":
        return "EXPIRED"
    if paused_at is not None or status == "PAUSED":
        return "PAUSED"
    return "ACTIVE"


def cidr_within_allowed(candidate_cidr: str, allowed_cidrs: Sequence[str]) -> bool:
    """Verifica se um segmento CIDR está integralmente contido no escopo autorizado."""
    try:
        candidate = ip_network(candidate_cidr, strict=False)
    except ValueError:
        return False
    if candidate.prefixlen == 0:
        return False

    for raw in allowed_cidrs:
        try:
            allowed = ip_network(raw, strict=False)
        except ValueError:
            continue
        if allowed.prefixlen == 0:
            continue
        if candidate.version == allowed.version and candidate.subnet_of(allowed):
            return True
    return False


@dataclass(frozen=True, slots=True)
class SourceLifecycleInput:
    """Resumo mínimo de estado e atualização de uma fonte de telemetria."""

    status: str
    has_reception: bool
    update_status: str
    token_generation: int


@dataclass(frozen=True, slots=True)
class LifecycleChecklist:
    """Marcos operacionais obrigatórios do piloto (Fase 6)."""

    installation_demonstrated: bool
    pause_resume_demonstrated: bool
    update_demonstrated: bool
    revocation_demonstrated: bool
    recovery_demonstrated: bool
    all_demonstrated: bool


@dataclass(frozen=True, slots=True)
class CoverageSummary:
    """Resumo real de cobertura observada no piloto."""

    total_sources: int
    active_sources: int
    paused_sources: int
    revoked_sources: int
    up_to_date_sources: int
    traffic_runs_count: int
    observed_layers: tuple[str, ...]
    missing_layers: tuple[str, ...]
    layer_coverage_percent: float
    ssh_audits_count: int
    availability_exercises_total: int
    availability_exercises_passed: int


@dataclass(frozen=True, slots=True)
class LatencySummary:
    """Métricas reais de latência de telemetria e publicação de alertas."""

    telemetry_samples_count: int
    telemetry_avg_delay_seconds: float | None
    telemetry_max_delay_seconds: float | None
    availability_alert_pub_avg_ms: float | None
    availability_alert_pub_max_ms: int | None
    availability_recovery_pub_avg_ms: float | None
    availability_recovery_pub_max_ms: int | None


@dataclass(frozen=True, slots=True)
class FalsePositiveSummary:
    """Indicadores reais de falsos positivos, rotações benignas e triagem humana."""

    suspicious_alerts_total: int
    benign_tls_rotations_ignored: int
    triage_suggestions_total: int
    triage_approved_count: int
    triage_rejected_count: int
    triage_pending_count: int
    findings_total: int
    findings_false_positive_count: int
    findings_false_positive_rate_percent: float


@dataclass(frozen=True, slots=True)
class ReadinessEvaluation:
    """Consolidação completa de prontidão e revisão do piloto."""

    lifecycle: LifecycleChecklist
    coverage: CoverageSummary
    latency: LatencySummary
    false_positives: FalsePositiveSummary
    blocking_reasons: tuple[str, ...]
    ready_for_expansion_approval: bool


def evaluate_pilot_readiness(
    *,
    asset_authorization_valid: bool,
    pilot_status: PilotStatus,
    sources: Sequence[SourceLifecycleInput],
    audit_actions: set[str],
    traffic_runs_observed_layers: Sequence[Sequence[str]],
    benign_rotations_count: int,
    suspicious_alerts_total: int,
    ssh_audits_count: int,
    availability_exercises_total: int,
    availability_exercises_passed: int,
    telemetry_delays_seconds: Sequence[float],
    availability_alert_pub_ms: Sequence[int],
    availability_recovery_pub_ms: Sequence[int],
    triage_review_statuses: Sequence[str],
    findings_total: int,
    findings_false_positive_count: int,
) -> ReadinessEvaluation:
    """Calcula marcos operacionais, cobertura, latência, falsos positivos e pendências."""
    active_sources = sum(1 for s in sources if s.status == "ACTIVE")
    paused_sources = sum(1 for s in sources if s.status == "PAUSED")
    revoked_sources = sum(1 for s in sources if s.status == "REVOKED")
    up_to_date_sources = sum(1 for s in sources if s.update_status == "UP_TO_DATE")

    installation_demonstrated = any(s.has_reception for s in sources) or (
        bool(sources) and bool(traffic_runs_observed_layers)
    )
    pause_resume_demonstrated = (
        "TELEMETRY_SOURCE_PAUSED" in audit_actions
        and "TELEMETRY_SOURCE_RESUMED" in audit_actions
    )
    update_demonstrated = "TELEMETRY_SOURCE_UPDATED" in audit_actions
    revocation_demonstrated = "TELEMETRY_SOURCE_REVOKED" in audit_actions
    recovery_demonstrated = (
        "TELEMETRY_SOURCE_RECOVERED" in audit_actions
        and any(s.status == "ACTIVE" and (s.token_generation > 1 or s.has_reception) for s in sources)
    )
    all_demonstrated = all(
        (
            installation_demonstrated,
            pause_resume_demonstrated,
            update_demonstrated,
            revocation_demonstrated,
            recovery_demonstrated,
        )
    )
    lifecycle = LifecycleChecklist(
        installation_demonstrated=installation_demonstrated,
        pause_resume_demonstrated=pause_resume_demonstrated,
        update_demonstrated=update_demonstrated,
        revocation_demonstrated=revocation_demonstrated,
        recovery_demonstrated=recovery_demonstrated,
        all_demonstrated=all_demonstrated,
    )

    observed_set = {
        layer
        for layers in traffic_runs_observed_layers
        for layer in layers
        if layer in CORE_TRAFFIC_LAYERS
    }
    observed_layers = tuple(layer for layer in CORE_TRAFFIC_LAYERS if layer in observed_set)
    missing_layers = tuple(layer for layer in CORE_TRAFFIC_LAYERS if layer not in observed_set)
    layer_coverage_percent = round((len(observed_layers) / len(CORE_TRAFFIC_LAYERS)) * 100.0, 2)

    coverage = CoverageSummary(
        total_sources=len(sources),
        active_sources=active_sources,
        paused_sources=paused_sources,
        revoked_sources=revoked_sources,
        up_to_date_sources=up_to_date_sources,
        traffic_runs_count=len(traffic_runs_observed_layers),
        observed_layers=observed_layers,
        missing_layers=missing_layers,
        layer_coverage_percent=layer_coverage_percent,
        ssh_audits_count=ssh_audits_count,
        availability_exercises_total=availability_exercises_total,
        availability_exercises_passed=availability_exercises_passed,
    )

    clean_delays = [max(0.0, float(d)) for d in telemetry_delays_seconds]
    latency = LatencySummary(
        telemetry_samples_count=len(clean_delays),
        telemetry_avg_delay_seconds=(
            round(sum(clean_delays) / len(clean_delays), 3) if clean_delays else None
        ),
        telemetry_max_delay_seconds=(round(max(clean_delays), 3) if clean_delays else None),
        availability_alert_pub_avg_ms=(
            round(sum(availability_alert_pub_ms) / len(availability_alert_pub_ms), 2)
            if availability_alert_pub_ms
            else None
        ),
        availability_alert_pub_max_ms=(
            max(availability_alert_pub_ms) if availability_alert_pub_ms else None
        ),
        availability_recovery_pub_avg_ms=(
            round(sum(availability_recovery_pub_ms) / len(availability_recovery_pub_ms), 2)
            if availability_recovery_pub_ms
            else None
        ),
        availability_recovery_pub_max_ms=(
            max(availability_recovery_pub_ms) if availability_recovery_pub_ms else None
        ),
    )

    approved_count = sum(1 for st in triage_review_statuses if st == "APPROVED")
    rejected_count = sum(1 for st in triage_review_statuses if st == "REJECTED")
    pending_count = sum(1 for st in triage_review_statuses if st == "PENDING_REVIEW")
    fp_rate = (
        round((findings_false_positive_count / findings_total) * 100.0, 2)
        if findings_total > 0
        else 0.0
    )
    false_positives = FalsePositiveSummary(
        suspicious_alerts_total=suspicious_alerts_total,
        benign_tls_rotations_ignored=benign_rotations_count,
        triage_suggestions_total=len(triage_review_statuses),
        triage_approved_count=approved_count,
        triage_rejected_count=rejected_count,
        triage_pending_count=pending_count,
        findings_total=findings_total,
        findings_false_positive_count=findings_false_positive_count,
        findings_false_positive_rate_percent=fp_rate,
    )

    blocking: list[str] = []
    if not asset_authorization_valid:
        blocking.append("Autorização do ativo ausente, expirada ou revogada.")
    if pilot_status != "ACTIVE":
        blocking.append("A habilitação do piloto precisa estar com estado ACTIVE.")
    if not installation_demonstrated:
        blocking.append("Instalação e recepção de telemetria ainda não demonstradas.")
    if not pause_resume_demonstrated:
        blocking.append("Ciclo de pausa e retomada da fonte ainda não demonstrado.")
    if not update_demonstrated:
        blocking.append("Atualização de configuração ou versão do coletor ainda não demonstrada.")
    if not revocation_demonstrated:
        blocking.append("Revogação de credencial do coletor ainda não demonstrada.")
    if not recovery_demonstrated:
        blocking.append("Recuperação operacional com fonte ativa ainda não demonstrada.")
    if active_sources == 0:
        blocking.append("Nenhuma fonte de telemetria ativa no momento.")
    if layer_coverage_percent <= 0.0:
        blocking.append("Cobertura de camadas de tráfego zerada (execute ao menos uma análise).")

    return ReadinessEvaluation(
        lifecycle=lifecycle,
        coverage=coverage,
        latency=latency,
        false_positives=false_positives,
        blocking_reasons=tuple(blocking),
        ready_for_expansion_approval=len(blocking) == 0,
    )
