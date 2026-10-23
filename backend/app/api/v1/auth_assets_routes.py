"""Rotas REST v1 de Autenticação, Organizações, RBAC, Ativos, Comprovação de Autorização e AuditLog (Fase 2)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, Response, status
from sqlalchemy.orm import Session

from app.api.deps import (
    AUTH_COOKIE_NAME,
    AuthenticatedPrincipal,
    extract_client_ip,
    get_current_principal,
    require_minimum_role,
)
from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import UserRole
from app.schemas.auth_assets import (
    AssetCreateRequest,
    AssetResponse,
    AssetUpdateRequest,
    AuditLogResponse,
    AuthorizationInitiateRequest,
    AuthSessionResponse,
    OrganizationCreateRequest,
    OrganizationMemberAddRequest,
    OrganizationMemberResponse,
    OrganizationPublicResponse,
    SwitchOrganizationRequest,
    TargetAuthorizationResponse,
    UserLoginRequest,
    UserRegisterRequest,
)
from app.services.asset_service import AssetAuthorizationService
from app.services.audit_service import AuditLogService
from app.services.auth_service import AuthOrganizationService

router = APIRouter(prefix="/api/v1", tags=["phase2-auth-assets"])

DbSessionDep = Annotated[Session, Depends(get_db)]
ViewerPrincipalDep = Annotated[AuthenticatedPrincipal, Depends(require_minimum_role(UserRole.VIEWER))]
AnalystPrincipalDep = Annotated[
    AuthenticatedPrincipal, Depends(require_minimum_role(UserRole.SECURITY_ANALYST))
]
AdminPrincipalDep = Annotated[AuthenticatedPrincipal, Depends(require_minimum_role(UserRole.ADMIN))]


def _set_auth_cookie(response: Response, access_token: str) -> None:
    settings = get_settings()
    is_prod = settings.app_env.lower() == "production"
    response.set_cookie(
        key=AUTH_COOKIE_NAME,
        value=access_token,
        httponly=True,
        secure=is_prod,
        samesite="lax",
        max_age=settings.access_token_expire_minutes * 60,
        path="/",
    )


@router.post(
    "/auth/register",
    response_model=AuthSessionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Registra novo usuário, cria organização inicial e inicia sessão autenticada",
)
def register_user(
    payload: UserRegisterRequest,
    request: Request,
    response: Response,
    db: DbSessionDep,
) -> AuthSessionResponse:
    session_data = AuthOrganizationService.register_user_and_organization(
        db=db,
        payload=payload,
        ip_address=extract_client_ip(request),
    )
    _set_auth_cookie(response, session_data.access_token)
    return session_data


@router.post(
    "/auth/login",
    response_model=AuthSessionResponse,
    summary="Autentica usuário e emite JWT + Cookie HttpOnly",
)
def login_user(
    payload: UserLoginRequest,
    request: Request,
    response: Response,
    db: DbSessionDep,
) -> AuthSessionResponse:
    session_data = AuthOrganizationService.authenticate_user(
        db=db,
        payload=payload,
        ip_address=extract_client_ip(request),
    )
    _set_auth_cookie(response, session_data.access_token)
    return session_data


@router.post(
    "/auth/logout",
    summary="Encerra sessão limpando o cookie HttpOnly e registrando evento de auditoria",
)
def logout_user(
    request: Request,
    response: Response,
    db: DbSessionDep,
    principal: Annotated[AuthenticatedPrincipal, Depends(get_current_principal)],
) -> dict[str, str]:
    AuthOrganizationService.revoke_request_token(db=db, request=request, user_id=principal.user.id)
    AuditLogService.record(
        db=db,
        action="USER_LOGOUT",
        resource_type="auth",
        resource_id=principal.user.id,
        organization_id=principal.organization.id,
        user_id=principal.user.id,
        ip_address=principal.client_ip,
        commit=True,
    )
    response.delete_cookie(key=AUTH_COOKIE_NAME, path="/")
    return {"status": "LOGGED_OUT"}


@router.get(
    "/auth/me",
    response_model=AuthSessionResponse,
    summary="Retorna dados do usuário autenticado, organização ativa e papéis RBAC",
)
def get_me(
    db: DbSessionDep,
    principal: Annotated[AuthenticatedPrincipal, Depends(get_current_principal)],
) -> AuthSessionResponse:
    return AuthOrganizationService.build_session_response(
        db=db,
        user=principal.user,
        active_organization=principal.organization,
        active_role=principal.role,
    )


@router.post(
    "/auth/switch-organization",
    response_model=AuthSessionResponse,
    summary="Alterna a organização ativa na sessão do usuário autenticado",
)
def switch_active_organization(
    payload: SwitchOrganizationRequest,
    response: Response,
    db: DbSessionDep,
    principal: Annotated[AuthenticatedPrincipal, Depends(get_current_principal)],
) -> AuthSessionResponse:
    session_data = AuthOrganizationService.switch_organization(
        db=db,
        user=principal.user,
        target_organization_id=payload.organization_id,
        ip_address=principal.client_ip,
    )
    _set_auth_cookie(response, session_data.access_token)
    return session_data


@router.post(
    "/organizations",
    response_model=OrganizationPublicResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Cria uma nova organização vinculando o usuário criador como ADMIN",
)
def create_organization(
    payload: OrganizationCreateRequest,
    db: DbSessionDep,
    principal: Annotated[AuthenticatedPrincipal, Depends(get_current_principal)],
) -> OrganizationPublicResponse:
    return AuthOrganizationService.create_organization_for_user(
        db=db,
        user=principal.user,
        payload=payload,
        ip_address=principal.client_ip,
    )


@router.get(
    "/organizations/members",
    response_model=list[OrganizationMemberResponse],
    summary="Lista os membros e papéis RBAC da organização ativa",
)
def list_organization_members(
    db: DbSessionDep,
    principal: ViewerPrincipalDep,
) -> list[OrganizationMemberResponse]:
    return AuthOrganizationService.list_organization_members(
        db=db,
        organization_id=principal.organization.id,
    )


@router.post(
    "/organizations/members",
    response_model=OrganizationMemberResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Adiciona ou atualiza o papel RBAC de um membro na organização ativa (Restrito a ADMIN)",
)
def add_or_update_organization_member(
    payload: OrganizationMemberAddRequest,
    db: DbSessionDep,
    principal: AdminPrincipalDep,
) -> OrganizationMemberResponse:
    return AuthOrganizationService.add_or_update_member(
        db=db,
        organization_id=principal.organization.id,
        actor_user_id=principal.user.id,
        payload=payload,
        ip_address=principal.client_ip,
    )


@router.get(
    "/assets",
    response_model=list[AssetResponse],
    summary="Lista todos os sistemas/ativos pertencentes à organização ativa",
)
def list_assets(
    db: DbSessionDep,
    principal: ViewerPrincipalDep,
) -> list[AssetResponse]:
    return AssetAuthorizationService.list_assets(
        db=db,
        organization_id=principal.organization.id,
    )


@router.post(
    "/assets",
    response_model=AssetResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Cadastra um novo ativo na organização ativa (Requer SECURITY_ANALYST ou ADMIN)",
)
def create_asset(
    payload: AssetCreateRequest,
    db: DbSessionDep,
    principal: AnalystPrincipalDep,
) -> AssetResponse:
    return AssetAuthorizationService.create_asset(
        db=db,
        organization_id=principal.organization.id,
        user_id=principal.user.id,
        payload=payload,
        ip_address=principal.client_ip,
    )


@router.get(
    "/assets/{asset_id}",
    response_model=AssetResponse,
    summary="Obtém detalhes de um ativo específico da organização ativa",
)
def get_asset(
    asset_id: str,
    db: DbSessionDep,
    principal: ViewerPrincipalDep,
) -> AssetResponse:
    asset = AssetAuthorizationService.get_asset_or_404(
        db=db,
        organization_id=principal.organization.id,
        asset_id=asset_id,
    )
    return AssetAuthorizationService._to_asset_response(asset)


@router.patch(
    "/assets/{asset_id}",
    response_model=AssetResponse,
    summary="Atualiza metadados de um ativo da organização ativa (Requer SECURITY_ANALYST ou ADMIN)",
)
def update_asset(
    asset_id: str,
    payload: AssetUpdateRequest,
    db: DbSessionDep,
    principal: AnalystPrincipalDep,
) -> AssetResponse:
    return AssetAuthorizationService.update_asset(
        db=db,
        organization_id=principal.organization.id,
        user_id=principal.user.id,
        asset_id=asset_id,
        payload=payload,
        ip_address=principal.client_ip,
    )


@router.delete(
    "/assets/{asset_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remove um ativo da organização ativa (Restrito a ADMIN)",
)
def delete_asset(
    asset_id: str,
    db: DbSessionDep,
    principal: AdminPrincipalDep,
) -> Response:
    AssetAuthorizationService.delete_asset(
        db=db,
        organization_id=principal.organization.id,
        user_id=principal.user.id,
        asset_id=asset_id,
        ip_address=principal.client_ip,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/assets/{asset_id}/authorizations",
    response_model=TargetAuthorizationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Inicia um desafio de comprovação de autorização do alvo (DNS_TXT, HTTP_WELL_KNOWN, LAB_INTERNAL)",
)
def initiate_asset_authorization(
    asset_id: str,
    payload: AuthorizationInitiateRequest,
    db: DbSessionDep,
    principal: AnalystPrincipalDep,
) -> TargetAuthorizationResponse:
    return AssetAuthorizationService.initiate_authorization(
        db=db,
        organization_id=principal.organization.id,
        user_id=principal.user.id,
        asset_id=asset_id,
        payload=payload,
        ip_address=principal.client_ip,
    )


@router.get(
    "/assets/{asset_id}/authorizations",
    response_model=list[TargetAuthorizationResponse],
    summary="Lista os desafios e registros de autorização de um ativo",
)
def list_asset_authorizations(
    asset_id: str,
    db: DbSessionDep,
    principal: ViewerPrincipalDep,
) -> list[TargetAuthorizationResponse]:
    return AssetAuthorizationService.list_authorizations(
        db=db,
        organization_id=principal.organization.id,
        asset_id=asset_id,
    )


@router.post(
    "/assets/{asset_id}/authorizations/{auth_id}/verify",
    response_model=TargetAuthorizationResponse,
    summary="Executa a verificação técnica da comprovação de autorização do alvo",
)
def verify_asset_authorization(
    asset_id: str,
    auth_id: str,
    db: DbSessionDep,
    principal: AnalystPrincipalDep,
) -> TargetAuthorizationResponse:
    return AssetAuthorizationService.verify_authorization(
        db=db,
        organization_id=principal.organization.id,
        user_id=principal.user.id,
        asset_id=asset_id,
        authorization_id=auth_id,
        ip_address=principal.client_ip,
    )


@router.post(
    "/assets/{asset_id}/authorizations/{auth_id}/revoke",
    response_model=TargetAuthorizationResponse,
    summary="Revoga formalmente uma autorização de ativo (Requer SECURITY_ANALYST ou ADMIN)",
)
def revoke_asset_authorization(
    asset_id: str,
    auth_id: str,
    db: DbSessionDep,
    principal: AnalystPrincipalDep,
) -> TargetAuthorizationResponse:
    return AssetAuthorizationService.revoke_authorization(
        db=db,
        organization_id=principal.organization.id,
        user_id=principal.user.id,
        asset_id=asset_id,
        authorization_id=auth_id,
        ip_address=principal.client_ip,
    )


@router.get(
    "/audit-logs",
    response_model=list[AuditLogResponse],
    summary="Consulta a trilha de auditoria da organização ativa (Requer SECURITY_ANALYST ou ADMIN)",
)
def list_organization_audit_logs(
    db: DbSessionDep,
    principal: AnalystPrincipalDep,
    limit: int = Query(default=100, ge=1, le=500),
) -> list[AuditLogResponse]:
    return AuditLogService.list_organization_logs(
        db=db,
        organization_id=principal.organization.id,
        limit=limit,
    )
