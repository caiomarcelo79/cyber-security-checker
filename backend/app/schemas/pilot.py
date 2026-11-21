"""Contratos Pydantic para governança de piloto, prontidão e revisão de expansão (Fase 6)."""

from datetime import datetime
from ipaddress import IPv4Network, IPv6Network
from typing import Any
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyNetwork,
    field_validator,
    model_validator,
)

from app.services.pilot_logic import (
    PilotCapability,
    PilotReviewDecision,
    PilotStage,
    PilotStatus,
)


def _validate_cidr_list_before(value: object) -> object:
    if not isinstance(value, list):
        return value
    for item in value:
        if isinstance(item, str) and ("/" not in item or "%" in item):
            raise ValueError("Informe todos os segmentos no formato CIDR válido.")
    return value


def _require_non_default_cidrs(
    networks: list[IPv4Network | IPv6Network],
) -> list[IPv4Network | IPv6Network]:
    for net in networks:
        if net.prefixlen == 0:
            raise ValueError("Segmento /0 não é permitido no escopo do piloto.")
    return networks


class PilotEnrollmentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_id: UUID
    stage: PilotStage
    prerequisite_pilot_id: UUID | None = None
    allowed_cidrs: list[IPvAnyNetwork] = Field(min_length=1, max_length=20)
    enabled_capabilities: list[PilotCapability] = Field(min_length=1, max_length=5)
    max_sources: int = Field(default=2, strict=True, ge=1, le=20)
    expires_in_days: int = Field(default=30, strict=True, ge=1, le=90)
    scope_notes: str | None = Field(default=None, max_length=500)

    @field_validator("allowed_cidrs", mode="before")
    @classmethod
    def check_cidrs_before(cls, value: object) -> object:
        return _validate_cidr_list_before(value)

    @field_validator("allowed_cidrs")
    @classmethod
    def check_cidrs(
        cls, value: list[IPv4Network | IPv6Network]
    ) -> list[IPv4Network | IPv6Network]:
        return _require_non_default_cidrs(value)

    @field_validator("scope_notes", mode="before")
    @classmethod
    def clean_scope_notes(cls, value: object) -> object:
        if isinstance(value, str):
            stripped = value.strip()
            return stripped or None
        return value


class PilotEnrollmentUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed_cidrs: list[IPvAnyNetwork] | None = Field(default=None, min_length=1, max_length=20)
    enabled_capabilities: list[PilotCapability] | None = Field(
        default=None, min_length=1, max_length=5
    )
    max_sources: int | None = Field(default=None, strict=True, ge=1, le=20)
    scope_notes: str | None = Field(default=None, max_length=500)

    @field_validator("allowed_cidrs", mode="before")
    @classmethod
    def check_cidrs_before(cls, value: object) -> object:
        if value is None:
            return None
        return _validate_cidr_list_before(value)

    @field_validator("allowed_cidrs")
    @classmethod
    def check_cidrs(
        cls, value: list[IPv4Network | IPv6Network] | None
    ) -> list[IPv4Network | IPv6Network] | None:
        if value is None:
            return None
        return _require_non_default_cidrs(value)

    @field_validator("scope_notes", mode="before")
    @classmethod
    def clean_scope_notes(cls, value: object) -> object:
        if isinstance(value, str):
            stripped = value.strip()
            return stripped or None
        return value

    @model_validator(mode="after")
    def require_any_field(self) -> "PilotEnrollmentUpdate":
        if (
            self.allowed_cidrs is None
            and self.enabled_capabilities is None
            and self.max_sources is None
            and self.scope_notes is None
        ):
            raise ValueError("Informe ao menos um campo para atualizar o piloto.")
        return self


class PilotReviewCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: PilotReviewDecision
    coverage_ok: bool
    latency_ok: bool
    false_positives_ok: bool
    notes: str | None = Field(default=None, max_length=500)

    @field_validator("notes", mode="before")
    @classmethod
    def clean_notes(cls, value: object) -> object:
        if isinstance(value, str):
            stripped = value.strip()
            return stripped or None
        return value


class PilotReviewResponse(BaseModel):
    id: str
    pilot_id: str
    organization_id: str
    decision: PilotReviewDecision
    coverage_ok: bool
    latency_ok: bool
    false_positives_ok: bool
    reviewer_user_id: str | None
    notes: str | None
    metrics_snapshot: dict[str, Any]
    created_at: datetime


class PilotLifecycleChecklistResponse(BaseModel):
    installation_demonstrated: bool
    pause_resume_demonstrated: bool
    update_demonstrated: bool
    revocation_demonstrated: bool
    recovery_demonstrated: bool
    all_demonstrated: bool


class PilotCoverageResponse(BaseModel):
    total_sources: int
    active_sources: int
    paused_sources: int
    revoked_sources: int
    up_to_date_sources: int
    traffic_runs_count: int
    observed_layers: list[str]
    missing_layers: list[str]
    layer_coverage_percent: float
    ssh_audits_count: int
    availability_exercises_total: int
    availability_exercises_passed: int


class PilotLatencyResponse(BaseModel):
    telemetry_samples_count: int
    telemetry_avg_delay_seconds: float | None
    telemetry_max_delay_seconds: float | None
    availability_alert_pub_avg_ms: float | None
    availability_alert_pub_max_ms: int | None
    availability_recovery_pub_avg_ms: float | None
    availability_recovery_pub_max_ms: int | None


class PilotFalsePositiveResponse(BaseModel):
    suspicious_alerts_total: int
    benign_tls_rotations_ignored: int
    triage_suggestions_total: int
    triage_approved_count: int
    triage_rejected_count: int
    triage_pending_count: int
    findings_total: int
    findings_false_positive_count: int
    findings_false_positive_rate_percent: float


class PilotReadinessResponse(BaseModel):
    pilot_id: str
    asset_id: str
    stage: PilotStage
    status: PilotStatus
    lifecycle: PilotLifecycleChecklistResponse
    coverage: PilotCoverageResponse
    latency: PilotLatencyResponse
    false_positives: PilotFalsePositiveResponse
    blocking_reasons: list[str]
    ready_for_expansion_approval: bool
    latest_review: PilotReviewResponse | None = None


class PilotEnrollmentResponse(BaseModel):
    id: str
    organization_id: str
    asset_id: str
    asset_name: str
    asset_environment: str
    asset_hostname: str
    stage: PilotStage
    status: PilotStatus
    prerequisite_pilot_id: str | None
    allowed_cidrs: list[str]
    enabled_capabilities: list[str]
    max_sources: int
    scope_notes: str | None
    expires_at: datetime
    paused_at: datetime | None
    revoked_at: datetime | None
    created_by_user_id: str | None
    created_at: datetime
    updated_at: datetime | None
    latest_review_decision: PilotReviewDecision | None = None
