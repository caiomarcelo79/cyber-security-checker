"""Rotas de auditoria SSH para os ativos da organização ativa."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException

from app.api.deps import AuthenticatedPrincipal, DbSessionDep, require_minimum_role
from app.core.security import UserRole
from app.schemas.ssh_audits import (
    SshAlertExerciseResponse,
    SshAuditCollection,
    SshAuditCreate,
    SshAuditResponse,
)
from app.services.lab_authorization import require_authorized_operational_asset
from app.services.ssh_audit_service import latest_ssh_audit, record_ssh_audit, run_ssh_alert_exercise

router = APIRouter(prefix="/api/v1/assets/{asset_id}/ssh-audit", tags=["Auditoria SSH"])
ViewerDep = Annotated[AuthenticatedPrincipal, Depends(require_minimum_role(UserRole.VIEWER))]
AnalystDep = Annotated[AuthenticatedPrincipal, Depends(require_minimum_role(UserRole.SECURITY_ANALYST))]


def _require_user_session(principal: AuthenticatedPrincipal) -> None:
    if principal.api_token_scopes is not None:
        raise HTTPException(403, "A auditoria SSH requer uma sessão de usuário.")


@router.get("", response_model=SshAuditResponse | None)
def get_latest(asset_id: UUID, db: DbSessionDep, principal: ViewerDep) -> SshAuditResponse | None:
    _require_user_session(principal)
    return latest_ssh_audit(db, principal.organization.id, str(asset_id))


@router.get("/collection", response_model=SshAuditCollection)
def get_collection(asset_id: UUID, db: DbSessionDep, principal: AnalystDep) -> SshAuditCollection:
    _require_user_session(principal)
    asset, _ = require_authorized_operational_asset(
        db, principal.organization.id, str(asset_id), capability="SSH_AUDIT"
    )
    return SshAuditCollection(hostname=asset.hostname)


@router.post("", response_model=SshAuditResponse, status_code=201)
def submit(
    asset_id: UUID, payload: SshAuditCreate, db: DbSessionDep, principal: AnalystDep
) -> SshAuditResponse:
    _require_user_session(principal)
    return record_ssh_audit(db, principal, str(asset_id), payload)


@router.post("/alert-exercise", response_model=SshAlertExerciseResponse, status_code=201)
def create_alert_exercise(asset_id: UUID, db: DbSessionDep, principal: AnalystDep) -> SshAlertExerciseResponse:
    _require_user_session(principal)
    return run_ssh_alert_exercise(db, principal, str(asset_id))
