"""Contratos Pydantic para sugestões revisáveis de triagem assistida (Fase 5)."""

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, StringConstraints, field_validator

from app.services.ai_triage_logic import (
    AiAvailabilityStatus,
    RecommendedAction,
    TriageGenerationMode,
    TriageReviewStatus,
    TriageTargetType,
)

TriageReviewDecision = Literal["APPROVED", "REJECTED"]


class AiTriageReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: TriageReviewDecision
    reviewer_notes: Annotated[str, StringConstraints(max_length=1000)] | None = None

    @field_validator("reviewer_notes", mode="before")
    @classmethod
    def normalize_notes(cls, value: object) -> object:
        if isinstance(value, str):
            return value.strip() or None
        return value


class EvidenceCitationResponse(BaseModel):
    field: str
    value_excerpt: str


class AiTriageSuggestionResponse(BaseModel):
    id: str
    organization_id: str
    asset_id: str
    target_type: TriageTargetType
    traffic_alert_id: str | None = None
    finding_id: str | None = None
    generation_mode: TriageGenerationMode
    ai_status: AiAvailabilityStatus
    model_name: str
    summary: str
    explanation: str
    recommended_action: RecommendedAction
    remediation_steps: list[str]
    evidence_citations: list[EvidenceCitationResponse]
    sanitized_evidence_hash: str
    review_status: TriageReviewStatus
    requires_analyst_review: bool
    reviewer_user_id: str | None = None
    reviewer_notes: str | None = None
    reviewed_at: datetime | None = None
    created_at: datetime
