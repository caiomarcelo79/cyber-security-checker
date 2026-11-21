"""Valida o escopo do laboratório e classifica evidências de SSH."""

from datetime import UTC, datetime
from typing import cast

from fastapi import HTTPException
from security_engine.core.contracts import CheckStatus
from sqlalchemy.orm import Session

from app.api.deps import AuthenticatedPrincipal
from app.models.entities import SshAudit, utcnow
from app.repositories.ssh_audits import find_latest_ssh_audit, insert_ssh_audit
from app.schemas.ssh_audits import (
    PasswordAuthentication,
    PermitRootLogin,
    SshAlertExerciseResponse,
    SshAuditCreate,
    SshAuditResponse,
)
from app.services.asset_service import AssetAuthorizationService
from app.services.audit_service import AuditLogService
from app.services.lab_authorization import require_authorized_operational_asset
from app.services.notification_service import NotificationService

PASSWORD_AUTHENTICATION_STATUS: dict[PasswordAuthentication, CheckStatus] = {
    "disabled": CheckStatus.PASSED,
    "enabled": CheckStatus.VULNERABILITY,
    "unknown": CheckStatus.INCONCLUSIVE,
    "collection_error": CheckStatus.EXECUTION_ERROR,
}

PERMIT_ROOT_LOGIN_STATUS: dict[PermitRootLogin, CheckStatus] = {
    "no": CheckStatus.PASSED,
    "yes": CheckStatus.VULNERABILITY,
    "prohibit-password": CheckStatus.VULNERABILITY,
    "forced-commands-only": CheckStatus.VULNERABILITY,
    "unknown": CheckStatus.INCONCLUSIVE,
    "collection_error": CheckStatus.EXECUTION_ERROR,
}

SSH_ALERT_EXERCISE_EVENT = "SSH_AUTH_FAILURE_SIMULATED"


def _as_utc(timestamp: datetime) -> datetime:
    return timestamp.astimezone(UTC) if timestamp.tzinfo else timestamp.replace(tzinfo=UTC)


def _response(audit: SshAudit) -> SshAuditResponse:
    observation = cast(PasswordAuthentication, audit.password_authentication)
    root_observation = cast(PermitRootLogin | None, audit.permit_root_login)
    return SshAuditResponse(
        id=audit.id,
        status=PASSWORD_AUTHENTICATION_STATUS[observation],
        password_authentication=observation,
        permit_root_login=root_observation,
        permit_root_login_status=PERMIT_ROOT_LOGIN_STATUS[root_observation] if root_observation else None,
        created_at=_as_utc(audit.created_at),
    )


def latest_ssh_audit(db: Session, organization_id: str, asset_id: str) -> SshAuditResponse | None:
    asset = AssetAuthorizationService.get_asset_or_404(db, organization_id, asset_id)
    audit = find_latest_ssh_audit(db, asset.id)
    return _response(audit) if audit is not None else None


def record_ssh_audit(
    db: Session, principal: AuthenticatedPrincipal, asset_id: str, payload: SshAuditCreate
) -> SshAuditResponse:
    asset, _ = require_authorized_operational_asset(
        db, principal.organization.id, asset_id, capability="SSH_AUDIT", lock_authorization=True
    )
    if payload.hostname.lower() != asset.hostname.lower():
        raise HTTPException(422, "O hostname da coleta deve corresponder ao ativo autorizado.")

    audit = insert_ssh_audit(db, asset.id, payload.password_authentication, payload.permit_root_login)
    result = _response(audit)
    AuditLogService.record(
        db,
        action="SSH_AUDIT_RECORDED",
        resource_type="ssh_audit",
        resource_id=audit.id,
        organization_id=principal.organization.id,
        user_id=principal.user.id,
        ip_address=principal.client_ip,
        metadata={
            "asset_id": asset.id,
            "status": result.status.value,
            "permit_root_login_status": result.permit_root_login_status,
        },
    )
    db.commit()
    return result


def run_ssh_alert_exercise(
    db: Session, principal: AuthenticatedPrincipal, asset_id: str
) -> SshAlertExerciseResponse:
    asset, _ = require_authorized_operational_asset(
        db, principal.organization.id, asset_id, capability="SSH_AUDIT", lock_authorization=True
    )
    event_created_at = utcnow()
    metadata = {"asset_id": asset.id, "synthetic": True, "event_created_at": event_created_at.isoformat()}
    AuditLogService.record(
        db,
        action=SSH_ALERT_EXERCISE_EVENT,
        resource_type="asset",
        resource_id=asset.id,
        organization_id=principal.organization.id,
        user_id=principal.user.id,
        ip_address=principal.client_ip,
        metadata=metadata,
    )
    notification = NotificationService().dispatch_event(
        db=db,
        organization_id=principal.organization.id,
        user_id=principal.user.id,
        event_type=SSH_ALERT_EXERCISE_EVENT,
        severity="INFO",
        title="[Exercício] Falha sintética de autenticação SSH",
        message="O fluxo de notificação do laboratório recebeu um evento sintético de autenticação.",
        metadata_json=metadata,
        dedup_window_seconds=0,
        publish_external=False,
    )
    if notification is None:
        raise HTTPException(500, "Não foi possível publicar a notificação do exercício.")
    elapsed = _as_utc(notification.created_at) - event_created_at
    return SshAlertExerciseResponse(
        notification_id=notification.id, publication_ms=max(0, int(elapsed.total_seconds() * 1000))
    )
