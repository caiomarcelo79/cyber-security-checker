"""Contratos do exercício de disponibilidade em laboratório."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.services.availability_logic import (
    EdgeSignalCode,
    EdgeSourceType,
    ExerciseResult,
    ExerciseScenario,
    ExerciseState,
    SampleOutcome,
)

MAX_SAMPLES = 600
MAX_DURATION_MS = 900_000
MAX_SIGNALS = 20


class AvailabilityExerciseCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario: ExerciseScenario = "LATENCY"
    threshold_ms: int = Field(default=500, strict=True, ge=50, le=10_000)
    consecutive_samples: int = Field(default=3, strict=True, ge=2, le=10)
    interval_ms: int = Field(default=1000, strict=True, ge=500, le=10_000)
    normal_ms: int = Field(default=8000, strict=True, ge=1000, le=600_000)
    degraded_ms: int = Field(default=8000, strict=True, ge=1000, le=600_000)

    @model_validator(mode="after")
    def check_plan(self) -> "AvailabilityExerciseCreate":
        if self.normal_ms < 2 * self.interval_ms:
            raise ValueError("O período normal deve cobrir ao menos duas amostras.")
        if self.degraded_ms < (self.consecutive_samples + 1) * self.interval_ms:
            raise ValueError("O período degradado deve permitir abrir o alerta com folga.")
        duration = self.normal_ms + self.degraded_ms + (self.consecutive_samples * 2 + 2) * self.interval_ms
        if duration > MAX_DURATION_MS or duration // self.interval_ms + 1 > MAX_SAMPLES:
            raise ValueError("O exercício excede a duração ou o número máximo de amostras.")
        return self


class AvailabilitySampleCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    seq: int = Field(strict=True, ge=0, lt=MAX_SAMPLES)
    offset_ms: int = Field(strict=True, ge=0, le=MAX_DURATION_MS)
    latency_ms: float | None = Field(default=None, ge=0, le=600_000)
    outcome: SampleOutcome
    http_status: int | None = Field(default=None, strict=True, ge=100, le=599)

    @model_validator(mode="after")
    def check_outcome(self) -> "AvailabilitySampleCreate":
        if self.outcome == "OK" and self.latency_ms is None:
            raise ValueError("Amostras OK exigem a latência medida.")
        if self.outcome != "OK" and self.latency_ms is not None:
            raise ValueError("Timeouts e falhas de conexão não possuem latência.")
        return self


class AvailabilitySampleResponse(BaseModel):
    seq: int
    offset_ms: int
    latency_ms: float | None
    outcome: SampleOutcome
    http_status: int | None


class TimelineEvent(BaseModel):
    event: Literal["DEGRADATION_START", "ALERT_OPENED", "RECOVERY_START", "RECOVERY_DETECTED"]
    expected_offset_ms: int
    observed_offset_ms: int | None
    delta_ms: int | None


class AvailabilitySignalCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_type: EdgeSourceType
    signal: EdgeSignalCode
    offset_ms: int = Field(strict=True, ge=0, le=MAX_DURATION_MS)
    http_status: int | None = Field(default=None, strict=True, ge=100, le=599)


class AvailabilitySignalResponse(BaseModel):
    id: str
    source_type: EdgeSourceType
    signal: EdgeSignalCode
    offset_ms: int
    http_status: int | None
    created_at: datetime


class AvailabilityMetricsSummary(BaseModel):
    peak_latency_ms: float | None
    error_5xx_count: int
    rate_limited_429_count: int
    timeout_or_connection_error_count: int


class AvailabilityExerciseResponse(BaseModel):
    id: str
    status: Literal["RUNNING", "FINISHED"]
    scenario: ExerciseScenario = "LATENCY"
    state: ExerciseState
    result: ExerciseResult | None
    hostname: str
    threshold_ms: int
    consecutive_samples: int
    interval_ms: int
    normal_ms: int
    degraded_ms: int
    planned_duration_ms: int
    tolerance_ms: int
    sample_count: int
    metrics_summary: AvailabilityMetricsSummary
    timeline: list[TimelineEvent]
    signals: list[AvailabilitySignalResponse]
    alert_publication_ms: int | None
    recovery_publication_ms: int | None
    started_at: datetime
    finished_at: datetime | None
    samples: list[AvailabilitySampleResponse] | None = None
