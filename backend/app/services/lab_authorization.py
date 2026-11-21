"""Autorização compartilhada para evidências de laboratório e pilotos controlados."""

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.entities import Asset, PilotEnrollment, TargetAuthorization, utcnow
from app.services.asset_service import AssetAuthorizationService
from app.services.pilot_logic import effective_pilot_status


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


def require_authorized_operational_asset(
    db: Session,
    organization_id: str,
    asset_id: str,
    *,
    capability: str,
    lock_authorization: bool = False,
) -> tuple[Asset, PilotEnrollment | None]:
    """Valida ativo de laboratório ou cliente autorizado em piloto vigente para a capacidade."""
    asset = AssetAuthorizationService.get_asset_or_404(db, organization_id, asset_id)
    settings = get_settings()
    now = utcnow()

    enrollment = db.scalar(
        select(PilotEnrollment)
        .where(
            PilotEnrollment.organization_id == organization_id,
            PilotEnrollment.asset_id == asset.id,
        )
        .order_by(PilotEnrollment.created_at.desc(), PilotEnrollment.id.desc())
        .limit(1)
    )

    is_lab_host = (
        not settings.is_production
        and settings.allow_local_lab_targets
        and asset.environment == "LAB"
        and asset.hostname in settings.parsed_lab_allowed_hosts
    )

    if is_lab_host and (enrollment is None or enrollment.stage == "OWN_ENVIRONMENT"):
        if enrollment is not None:
            pilot_status = effective_pilot_status(
                enrollment.status,
                enrollment.expires_at,
                enrollment.paused_at,
                enrollment.revoked_at,
                now,
            )
            if pilot_status != "ACTIVE":
                raise HTTPException(
                    403,
                    "A habilitação do piloto para este ativo está pausada, expirada ou revogada.",
                )
            if capability not in (enrollment.enabled_capabilities or []):
                raise HTTPException(
                    403,
                    f"A capacidade '{capability}' não faz parte do escopo deste piloto.",
                )

        lab_asset = require_authorized_lab_asset(
            db, organization_id, asset_id, lock_authorization=lock_authorization
        )
        return lab_asset, enrollment

    if enrollment is None or enrollment.stage != "AUTHORIZED_CLIENT":
        raise HTTPException(
            403,
            "Operação disponível somente para laboratório autorizado ou cliente em piloto habilitado.",
        )

    pilot_status = effective_pilot_status(
        enrollment.status,
        enrollment.expires_at,
        enrollment.paused_at,
        enrollment.revoked_at,
        now,
    )
    if pilot_status != "ACTIVE":
        raise HTTPException(
            403,
            "A habilitação do piloto do cliente está pausada, expirada ou revogada.",
        )
    if capability not in (enrollment.enabled_capabilities or []):
        raise HTTPException(
            403,
            f"A capacidade '{capability}' não faz parte do escopo autorizado deste piloto.",
        )

    authorization = (
        select(TargetAuthorization.id)
        .where(
            TargetAuthorization.asset_id == asset.id,
            TargetAuthorization.organization_id == organization_id,
            TargetAuthorization.method.in_(("DNS_TXT", "HTTP_WELL_KNOWN")),
            TargetAuthorization.status == "VERIFIED",
            TargetAuthorization.verified_at.is_not(None),
            TargetAuthorization.expires_at > now,
        )
        .order_by(TargetAuthorization.expires_at.desc(), TargetAuthorization.id)
        .limit(1)
    )
    if lock_authorization:
        authorization = authorization.with_for_update()
    if asset.authorization_status != "VERIFIED" or db.scalar(authorization) is None:
        raise HTTPException(
            403,
            "O ativo do cliente precisa de autorização DNS_TXT ou HTTP_WELL_KNOWN vigente.",
        )
    return asset, enrollment
