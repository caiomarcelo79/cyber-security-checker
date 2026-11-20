"""Autorização compartilhada para evidências de laboratório recebidas pela API."""

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.entities import Asset, TargetAuthorization, utcnow
from app.services.asset_service import AssetAuthorizationService


def require_authorized_lab_asset(
    db: Session, organization_id: str, asset_id: str, *, lock_authorization: bool = False
) -> Asset:
    asset = AssetAuthorizationService.get_asset_or_404(db, organization_id, asset_id)
    settings = get_settings()
    if (
        settings.is_production
        or not settings.allow_local_lab_targets
        or asset.environment != "LAB"
        or asset.hostname not in settings.parsed_lab_allowed_hosts
    ):
        raise HTTPException(403, "Operação disponível somente para hosts da lista do laboratório.")

    authorization = (
        select(TargetAuthorization.id)
        .where(
            TargetAuthorization.asset_id == asset.id,
            TargetAuthorization.organization_id == organization_id,
            TargetAuthorization.method == "LAB_INTERNAL",
            TargetAuthorization.status == "VERIFIED",
            TargetAuthorization.verified_at.is_not(None),
            TargetAuthorization.expires_at > utcnow(),
        )
        .order_by(TargetAuthorization.expires_at.desc(), TargetAuthorization.id)
        .limit(1)
    )
    if lock_authorization:
        authorization = authorization.with_for_update()
    if asset.authorization_status != "VERIFIED" or db.scalar(authorization) is None:
        raise HTTPException(403, "O ativo precisa de autorização de laboratório válida.")
    return asset
