"""Regras determinísticas do exercício de disponibilidade em laboratório.

O exercício compara uma linha do tempo esperada (normal → degradação → recuperação)
com a observada a partir das amostras de latência. Nenhuma função aqui acessa banco,
rede ou relógio: o mesmo conjunto de amostras sempre produz o mesmo resultado.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

SampleOutcome = Literal["OK", "TIMEOUT", "CONNECTION_ERROR"]
ExerciseState = Literal["NORMAL", "ALERT", "RECOVERED"]
ExerciseResult = Literal["PASSED", "FAILED", "INCONCLUSIVE", "EXECUTION_ERROR"]
ExerciseScenario = Literal["LATENCY", "ERRORS", "SATURATION"]
EdgeSourceType = Literal["FIREWALL", "CDN", "PROVIDER"]
EdgeSignalCode = Literal["RATE_LIMITED", "UPSTREAM_ERROR", "SATURATION", "MITIGATION_ACTIVE", "RECOVERED"]


@dataclass(frozen=True)
class SampleView:
    offset_ms: int
    latency_ms: float | None
    outcome: SampleOutcome
    http_status: int | None = None


@dataclass(frozen=True)
class SampleSummary:
    peak_latency_ms: float | None
    error_5xx_count: int
    rate_limited_429_count: int
    timeout_or_connection_error_count: int


@dataclass(frozen=True)
class ExercisePlan:
    threshold_ms: int
    consecutive_samples: int
    interval_ms: int
    normal_ms: int
    degraded_ms: int

    @property
    def expected_alert_ms(self) -> int:
        return self.normal_ms + self.consecutive_samples * self.interval_ms

    @property
    def expected_recovery_start_ms(self) -> int:
        return self.normal_ms + self.degraded_ms

    @property
    def expected_recovery_ms(self) -> int:
        return self.expected_recovery_start_ms + self.consecutive_samples * self.interval_ms

    @property
    def planned_duration_ms(self) -> int:
        return self.expected_recovery_ms + 2 * self.interval_ms

    @property
    def tolerance_ms(self) -> int:
        return self.interval_ms


@dataclass(frozen=True)
class Analysis:
    state: ExerciseState
    first_violation_offset_ms: int | None
    alert_offset_ms: int | None
    recovery_start_offset_ms: int | None
    recovery_offset_ms: int | None


def is_violation(sample: SampleView, threshold_ms: int) -> bool:
    """Violação ocorre por falha de rede, erro 5xx/429 ou latência acima do limiar."""
    if sample.outcome != "OK" or sample.latency_ms is None:
        return True
    if sample.http_status is not None and (sample.http_status >= 500 or sample.http_status == 429):
        return True
    return sample.latency_ms > threshold_ms


def summarize_samples(samples: Sequence[SampleView]) -> SampleSummary:
    """Agrega pico de latência e contagens de erros HTTP, saturação e falhas de rede."""
    latencies = [s.latency_ms for s in samples if s.latency_ms is not None]
    return SampleSummary(
        peak_latency_ms=max(latencies) if latencies else None,
        error_5xx_count=sum(1 for s in samples if s.http_status is not None and s.http_status >= 500),
        rate_limited_429_count=sum(1 for s in samples if s.http_status == 429),
        timeout_or_connection_error_count=sum(1 for s in samples if s.outcome != "OK"),
    )


def analyze_samples(samples: Sequence[SampleView], plan: ExercisePlan) -> Analysis:
    """Aplica a regra de amostras consecutivas para abrir o alerta e registrar a recuperação."""
    n = plan.consecutive_samples
    state: ExerciseState = "NORMAL"
    violations = healthy = 0
    first_violation: int | None = None
    alert: int | None = None
    recovery_start: int | None = None
    recovery: int | None = None

    for sample in samples:
        violating = is_violation(sample, plan.threshold_ms)
        if violating and first_violation is None:
            first_violation = sample.offset_ms
        if state == "NORMAL":
            violations = violations + 1 if violating else 0
            if violations >= n:
                state, alert, healthy = "ALERT", sample.offset_ms, 0
        elif state == "ALERT":
            if violating:
                healthy = 0
                recovery_start = None
            else:
                if healthy == 0:
                    recovery_start = sample.offset_ms
                healthy += 1
                if healthy >= n:
                    state, recovery = "RECOVERED", sample.offset_ms

    return Analysis(state, first_violation, alert, recovery_start, recovery)


def grade_exercise(samples: Sequence[SampleView], plan: ExercisePlan, analysis: Analysis) -> ExerciseResult:
    """Classifica o exercício sem tratar falta de dados como aprovação."""
    if not samples:
        return "INCONCLUSIVE"
    baseline = [s for s in samples if s.offset_ms < plan.normal_ms]
    if not baseline:
        return "INCONCLUSIVE"
    if all(is_violation(s, plan.threshold_ms) for s in baseline):
        # O alvo já estava indisponível antes da degradação programada: falha do laboratório.
        return "EXECUTION_ERROR"

    tolerance = plan.tolerance_ms
    last_offset = samples[-1].offset_ms
    if analysis.alert_offset_ms is None:
        return "FAILED" if last_offset >= plan.expected_alert_ms + tolerance else "INCONCLUSIVE"
    if abs(analysis.alert_offset_ms - plan.expected_alert_ms) > tolerance:
        return "FAILED"
    if analysis.recovery_offset_ms is None:
        return "FAILED" if last_offset >= plan.expected_recovery_ms + tolerance else "INCONCLUSIVE"
    if abs(analysis.recovery_offset_ms - plan.expected_recovery_ms) > tolerance:
        return "FAILED"
    return "PASSED"
