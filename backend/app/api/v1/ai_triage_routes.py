"""Rotas para geração e consulta de sugestões revisáveis de triagem assistida (Fase 5)."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends

from app.api.deps import AuthenticatedPrincipal, DbSessionDep, require_minimum_role
from app.core.security import UserRole
from app.schemas.ai_triage import AiTriageReviewRequest, AiTriageSuggestionResponse
from app.services.ai_triage_service import (
    generate_finding_suggestion,
    generate_traffic_alert_suggestion,
    get_finding_suggestion,
    get_traffic_alert_suggestion,
    review_triage_suggestion,
)

router = APIRouter(prefix="/api/v1", tags=["Triagem assistida por IA"])
ViewerDep = Annotated[AuthenticatedPrincipal, Depends(require_minimum_role(UserRole.VIEWER))]
AnalystDep = Annotated[AuthenticatedPrincipal, Depends(require_minimum_role(UserRole.SECURITY_ANALYST))]


@router.post(
    "/assets/{asset_id}/traffic-analyses/{run_id}/alerts/{alert_id}/triage-suggestion",
    response_model=AiTriageSuggestionResponse,
    status_code=201,
)
def create_traffic_alert_triage_suggestion(
    asset_id: UUID,
    run_id: UUID,
    alert_id: UUID,
    db: DbSessionDep,
    principal: AnalystDep,
) -> AiTriageSuggestionResponse:
    return generate_traffic_alert_suggestion(
        db, principal, str(asset_id), str(run_id), str(alert_id)
    )


@router.get(
    "/assets/{asset_id}/traffic-analyses/{run_id}/alerts/{alert_id}/triage-suggestion",
    response_model=AiTriageSuggestionResponse | None,
)
def read_traffic_alert_triage_suggestion(
    asset_id: UUID,
    run_id: UUID,
    alert_id: UUID,
    db: DbSessionDep,
    principal: ViewerDep,
) -> AiTriageSuggestionResponse | None:
    return get_traffic_alert_suggestion(
        db, principal.organization.id, str(asset_id), str(run_id), str(alert_id)
    )


@router.post(
    "/findings/{finding_id}/triage-suggestion",
    response_model=AiTriageSuggestionResponse,
    status_code=201,
)
def create_finding_triage_suggestion(
    finding_id: UUID,
    db: DbSessionDep,
    principal: AnalystDep,
) -> AiTriageSuggestionResponse:
    return generate_finding_suggestion(db, principal, str(finding_id))


@router.get(
    "/findings/{finding_id}/triage-suggestion",
    response_model=AiTriageSuggestionResponse | None,
)
def read_finding_triage_suggestion(
    finding_id: UUID,
    db: DbSessionDep,
    principal: ViewerDep,
) -> AiTriageSuggestionResponse | None:
    return get_finding_suggestion(db, principal.organization.id, str(finding_id))


@router.patch(
    "/triage-suggestions/{suggestion_id}/review",
    response_model=AiTriageSuggestionResponse,
)
def submit_triage_review(
    suggestion_id: UUID,
    payload: AiTriageReviewRequest,
    db: DbSessionDep,
    principal: AnalystDep,
) -> AiTriageSuggestionResponse:
    return review_triage_suggestion(db, principal, str(suggestion_id), payload)
