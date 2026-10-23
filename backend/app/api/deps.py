"""DependÃªncias FastAPI de autenticaÃ§Ã£o JWT/Cookie e autorizaÃ§Ã£o RBAC multi-organizaÃ§Ã£o (Fase 2)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated

from fastapi import Cookie, Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import AUTH_COOKIE_NAME, UserRole, decode_access_token, has_minimum_role
from app.models.entities import Organization, OrganizationMembership, RevokedToken, User

DbSessionDep = Annotated[Session, Depends(get_db)]


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    """Contexto verificado do usuÃ¡rio autenticado e da organizaÃ§Ã£o ativa."""

    user: User
    organization: Organization
    role: UserRole
    client_ip: str | None
    api_token_scopes: list[str] | None = None


def extract_client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded and get_settings().trust_forwarded_for:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return None


def _enforce_cookie_csrf(request: Request) -> None:
    """Defesa em profundidade: requisiÃ§Ãµes mutÃ¡veis por cookie exigem Origin permitida (quando enviada)."""
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return
    origin = request.headers.get("origin")
    if origin and origin not in get_settings().cors_origins:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Origem nÃ£o permitida para requisiÃ§Ã£o autenticada por cookie.",
        )


def get_current_principal(
    request: Request,
    db: DbSessionDep,
    authorization: Annotated[str | None, Header()] = None,
    cookie_token: Annotated[str | None, Cookie(alias=AUTH_COOKIE_NAME)] = None,
) -> AuthenticatedPrincipal:
    """Extrai e valida o JWT ou Chave de API do cabeÃ§alho Authorization Bearer ou cookie HttpOnly."""
    raw_token: str | None = None
    if authorization and authorization.lower().startswith("bearer "):
        raw_token = authorization.split(" ", 1)[1].strip()
    elif cookie_token:
        raw_token = cookie_token.strip()
        _enforce_cookie_csrf(request)

    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="NÃ£o autenticado. ForneÃ§a um token Bearer ou cookie de sessÃ£o vÃ¡lido.",
        )

    # Suporte a Chaves de API para integraÃ§Ãµes de terceiros (Fase 7)
    if raw_token.startswith("csc_live_"):
        from app.services.api_token_service import ApiTokenService

        token_service = ApiTokenService()
        auth_result = token_service.authenticate_token(db=db, raw_token=raw_token)
        if not auth_result:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Chave de API invÃ¡lida, revogada ou expirada.",
            )

        api_token_rec, user, organization = auth_result
        membership = db.scalar(
            select(OrganizationMembership).where(
                OrganizationMembership.user_id == user.id,
                OrganizationMembership.organization_id == organization.id,
            )
        )
        if membership is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="VÃ­nculo do proprietÃ¡rio da chave com a organizaÃ§Ã£o foi revogado.",
            )

        return AuthenticatedPrincipal(
            user=user,
            organization=organization,
            role=UserRole(membership.role),
            client_ip=extract_client_ip(request),
            api_token_scopes=api_token_rec.scopes,
        )

    try:
        payload = decode_access_token(raw_token)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        ) from exc

    jti = str(payload.get("jti", ""))
    if jti and db.get(RevokedToken, jti) is not None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="SessÃ£o encerrada. FaÃ§a login novamente.",
        )

    user_id = str(payload.get("sub", ""))
    org_id = str(payload.get("org_id", ""))

    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="UsuÃ¡rio nÃ£o encontrado ou conta desativada.",
        )

    organization = db.get(Organization, org_id)
    if organization is None or not organization.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="OrganizaÃ§Ã£o ativa nÃ£o encontrada ou desativada.",
        )

    membership = db.scalar(
        select(OrganizationMembership).where(
            OrganizationMembership.user_id == user.id,
            OrganizationMembership.organization_id == organization.id,
        )
    )
    if membership is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="VÃ­nculo com a organizaÃ§Ã£o foi revogado ou nÃ£o existe.",
        )

    return AuthenticatedPrincipal(
        user=user,
        organization=organization,
        role=UserRole(membership.role),
        client_ip=extract_client_ip(request),
    )


def get_optional_principal(
    request: Request,
    db: DbSessionDep,
    authorization: Annotated[str | None, Header()] = None,
    cookie_token: Annotated[str | None, Cookie(alias=AUTH_COOKIE_NAME)] = None,
) -> AuthenticatedPrincipal | None:
    """Resolve o contexto do usuÃ¡rio autenticado quando presente, ou retorna None sem erro."""
    try:
        return get_current_principal(
            request=request,
            db=db,
            authorization=authorization,
            cookie_token=cookie_token,
        )
    except HTTPException:
        return None


def require_minimum_role(
    minimum_role: UserRole,
) -> Callable[[AuthenticatedPrincipal], AuthenticatedPrincipal]:
    """Cria dependÃªncia FastAPI que exige um papel mÃ­nimo RBAC na organizaÃ§Ã£o ativa."""

    def _dependency(
        principal: Annotated[AuthenticatedPrincipal, Depends(get_current_principal)],
    ) -> AuthenticatedPrincipal:
        if not has_minimum_role(principal.role, minimum_role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"PermissÃ£o insuficiente. Seu papel atual Ã© '{principal.role.value}', "
                    f"mas esta operaÃ§Ã£o requer no mÃ­nimo '{minimum_role.value}'."
                ),
            )
        return principal

    return _dependency
