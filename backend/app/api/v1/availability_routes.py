"""Rotas do exercício de disponibilidade dos ativos de laboratório."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException

from app.api.deps import AuthenticatedPrincipal, DbSessionDep, require_minimum_role
from app.core.security import UserRole
from app.schemas.availability import (
    AvailabilityExerciseCreate,
    AvailabilityExerciseResponse,
    AvailabilitySampleCreate,
    AvailabilitySignalCreate,
)
from app.services.availability_service import (
    finish_exercise,
    get_asset_exercise,
    list_asset_exercises,
    record_sample,
    record_signal,
    start_exercise,
)

router = APIRouter(prefix="/api/v1/assets/{asset_id}/availability-exercises", tags=["Disponibilidade"])
ViewerDep = Annotated[AuthenticatedPrincipal, Depends(require_minimum_role(UserRole.VIEWER))]
AnalystDep = Annotated[AuthenticatedPrincipal, Depends(require_minimum_role(UserRole.SECURITY_ANALYST))]


def _require_user_session(principal: AuthenticatedPrincipal) -> None:
    if principal.api_token_scopes is not None:
        raise HTTPException(403, "O exercício de disponibilidade requer uma sessão de usuário.")


@router.get("", response_model=list[AvailabilityExerciseResponse])
def list_exercises(
    asset_id: UUID, db: DbSessionDep, principal: ViewerDep
) -> list[AvailabilityExerciseResponse]:
    _require_user_session(principal)
    return list_asset_exercises(db, principal.organization.id, str(asset_id))


@router.post("", response_model=AvailabilityExerciseResponse, status_code=201)
def create_exercise(
    asset_id: UUID, payload: AvailabilityExerciseCreate, db: DbSessionDep, principal: AnalystDep
) -> AvailabilityExerciseResponse:
    _require_user_session(principal)
    return start_exercise(db, principal, str(asset_id), payload)


@router.get("/{exercise_id}", response_model=AvailabilityExerciseResponse)
def get_exercise(
    asset_id: UUID, exercise_id: UUID, db: DbSessionDep, principal: ViewerDep
) -> AvailabilityExerciseResponse:
    _require_user_session(principal)
    return get_asset_exercise(db, principal.organization.id, str(asset_id), str(exercise_id))


@router.post("/{exercise_id}/samples", response_model=AvailabilityExerciseResponse, status_code=201)
def submit_sample(
    asset_id: UUID,
    exercise_id: UUID,
    payload: AvailabilitySampleCreate,
    db: DbSessionDep,
    principal: AnalystDep,
) -> AvailabilityExerciseResponse:
    _require_user_session(principal)
    return record_sample(db, principal, str(asset_id), str(exercise_id), payload)


@router.post("/{exercise_id}/signals", response_model=AvailabilityExerciseResponse, status_code=201)
def submit_signal(
    asset_id: UUID,
    exercise_id: UUID,
    payload: AvailabilitySignalCreate,
    db: DbSessionDep,
    principal: AnalystDep,
) -> AvailabilityExerciseResponse:
    _require_user_session(principal)
    return record_signal(db, principal, str(asset_id), str(exercise_id), payload)


@router.post("/{exercise_id}/finish", response_model=AvailabilityExerciseResponse)
def finish(
    asset_id: UUID, exercise_id: UUID, db: DbSessionDep, principal: AnalystDep
) -> AvailabilityExerciseResponse:
    _require_user_session(principal)
    return finish_exercise(db, principal, str(asset_id), str(exercise_id))
