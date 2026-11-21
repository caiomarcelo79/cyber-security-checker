"""Rotas REST v1 para governança do piloto em ambiente próprio e expansão controlada (Fase 6)."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException

from app.api.deps import AuthenticatedPrincipal, DbSessionDep, require_minimum_role
from app.core.security import UserRole
from app.schemas.pilot import (
    PilotEnrollmentCreate,
    PilotEnrollmentResponse,
    PilotEnrollmentUpdate,
    PilotReadinessResponse,
    PilotReviewCreate,
    PilotReviewResponse,
)
from app.services.pilot_service import (
    create_pilot_enrollment,
    get_pilot_enrollment,
    get_pilot_readiness,
    list_pilot_enrollments,
    list_pilot_reviews,
    pause_pilot_enrollment,
    record_pilot_review,
    resume_pilot_enrollment,
    revoke_pilot_enrollment,
    update_pilot_enrollment,
)

router = APIRouter(prefix="/api/v1/pilots", tags=["Piloto e expansão"])
ViewerDep = Annotated[AuthenticatedPrincipal, Depends(require_minimum_role(UserRole.VIEWER))]
AnalystDep = Annotated[
    AuthenticatedPrincipal, Depends(require_minimum_role(UserRole.SECURITY_ANALYST))
]


def _require_user_session(principal: AuthenticatedPrincipal) -> None:
    if principal.api_token_scopes is not None:
        raise HTTPException(403, "A gestão do piloto requer uma sessão de usuário.")


@router.get("", response_model=list[PilotEnrollmentResponse])
def get_pilots(db: DbSessionDep, principal: ViewerDep) -> list[PilotEnrollmentResponse]:
    _require_user_session(principal)
    return list_pilot_enrollments(db, principal.organization.id)


@router.post("", response_model=PilotEnrollmentResponse, status_code=201)
def post_pilot(
    payload: PilotEnrollmentCreate, db: DbSessionDep, principal: AnalystDep
) -> PilotEnrollmentResponse:
    _require_user_session(principal)
    return create_pilot_enrollment(db, principal, payload)


@router.get("/{pilot_id}", response_model=PilotEnrollmentResponse)
def get_pilot(
    pilot_id: UUID, db: DbSessionDep, principal: ViewerDep
) -> PilotEnrollmentResponse:
    _require_user_session(principal)
    return get_pilot_enrollment(db, principal.organization.id, str(pilot_id))


@router.patch("/{pilot_id}", response_model=PilotEnrollmentResponse)
def patch_pilot(
    pilot_id: UUID,
    payload: PilotEnrollmentUpdate,
    db: DbSessionDep,
    principal: AnalystDep,
) -> PilotEnrollmentResponse:
    _require_user_session(principal)
    return update_pilot_enrollment(db, principal, str(pilot_id), payload)


@router.post("/{pilot_id}/pause", response_model=PilotEnrollmentResponse)
def post_pause_pilot(
    pilot_id: UUID, db: DbSessionDep, principal: AnalystDep
) -> PilotEnrollmentResponse:
    _require_user_session(principal)
    return pause_pilot_enrollment(db, principal, str(pilot_id))


@router.post("/{pilot_id}/resume", response_model=PilotEnrollmentResponse)
def post_resume_pilot(
    pilot_id: UUID, db: DbSessionDep, principal: AnalystDep
) -> PilotEnrollmentResponse:
    _require_user_session(principal)
    return resume_pilot_enrollment(db, principal, str(pilot_id))


@router.post("/{pilot_id}/revoke", response_model=PilotEnrollmentResponse)
def post_revoke_pilot(
    pilot_id: UUID, db: DbSessionDep, principal: AnalystDep
) -> PilotEnrollmentResponse:
    _require_user_session(principal)
    return revoke_pilot_enrollment(db, principal, str(pilot_id))


@router.get("/{pilot_id}/readiness", response_model=PilotReadinessResponse)
def get_readiness(
    pilot_id: UUID, db: DbSessionDep, principal: ViewerDep
) -> PilotReadinessResponse:
    _require_user_session(principal)
    return get_pilot_readiness(db, principal.organization.id, str(pilot_id))


@router.post("/{pilot_id}/reviews", response_model=PilotReviewResponse, status_code=201)
def post_review(
    pilot_id: UUID,
    payload: PilotReviewCreate,
    db: DbSessionDep,
    principal: AnalystDep,
) -> PilotReviewResponse:
    _require_user_session(principal)
    return record_pilot_review(db, principal, str(pilot_id), payload)


@router.get("/{pilot_id}/reviews", response_model=list[PilotReviewResponse])
def get_reviews(
    pilot_id: UUID, db: DbSessionDep, principal: ViewerDep
) -> list[PilotReviewResponse]:
    _require_user_session(principal)
    return list_pilot_reviews(db, principal.organization.id, str(pilot_id))
