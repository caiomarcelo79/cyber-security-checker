"""Rotas REST v1 para Automações, Agendamentos, Notificações, Webhooks, API Tokens e Templates (Fase 7)."""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import (
    AuthenticatedPrincipal,
    require_minimum_role,
)
from app.core.database import get_db
from app.core.security import UserRole
from app.schemas.automations import (
    ApiTokenCreatedResponse,
    ApiTokenCreateRequest,
    ApiTokenPageResponse,
    NotificationPageResponse,
    NotificationPreferenceResponse,
    NotificationPreferenceUpdateRequest,
    ScanScheduleCreateRequest,
    ScanSchedulePageResponse,
    ScanScheduleResponse,
    ScanScheduleUpdateRequest,
    ScanTemplateCreateRequest,
    ScanTemplatePageResponse,
    ScanTemplateResponse,
    ScanTemplateUpdateRequest,
    WebhookDeliveryPageResponse,
    WebhookEndpointCreateRequest,
    WebhookEndpointResponse,
    WebhookEndpointSecretRotateResponse,
    WebhookEndpointUpdateRequest,
    WebhookTestResponse,
)
from app.services.api_token_service import ApiTokenError, ApiTokenService
from app.services.notification_service import NotificationService
from app.services.scheduler_service import SchedulerService, ScheduleValidationError
from app.services.template_service import TemplateService
from app.services.webhook_service import WebhookService, WebhookValidationError

logger = logging.getLogger("cyber_security_checker.automation_routes")

router = APIRouter(prefix="/api/v1/automations", tags=["phase7-automations"])

DbSessionDep = Annotated[Session, Depends(get_db)]
ViewerDep = Annotated[AuthenticatedPrincipal, Depends(require_minimum_role(UserRole.VIEWER))]
SecurityAnalystDep = Annotated[
    AuthenticatedPrincipal, Depends(require_minimum_role(UserRole.SECURITY_ANALYST))
]


# ============================================================================
# Agendamentos de Auditorias (Schedules)
# ============================================================================


@router.post(
    "/schedules",
    response_model=ScanScheduleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Criar novo agendamento de auditoria",
)
def create_schedule(
    req: ScanScheduleCreateRequest,
    principal: SecurityAnalystDep,
    db: DbSessionDep,
) -> ScanScheduleResponse:
    service = SchedulerService()
    try:
        return service.create_schedule(
            db=db,
            organization_id=principal.organization.id,
            user_id=principal.user.id,
            req=req,
        )
    except ScheduleValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.get(
    "/schedules",
    response_model=ScanSchedulePageResponse,
    summary="Listar agendamentos de auditorias da organização",
)
def list_schedules(
    principal: ViewerDep,
    db: DbSessionDep,
    asset_id: str | None = Query(default=None, description="Filtrar por ativo"),
    status_filter: str | None = Query(default=None, alias="status", description="Filtrar por status"),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> ScanSchedulePageResponse:
    service = SchedulerService()
    return service.list_schedules(
        db=db,
        organization_id=principal.organization.id,
        asset_id=asset_id,
        status=status_filter,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/schedules/{schedule_id}",
    response_model=ScanScheduleResponse,
    summary="Obter detalhes de um agendamento",
)
def get_schedule(
    schedule_id: str,
    principal: ViewerDep,
    db: DbSessionDep,
) -> ScanScheduleResponse:
    service = SchedulerService()
    item = service.get_schedule(
        db=db,
        organization_id=principal.organization.id,
        schedule_id=schedule_id,
    )
    if not item:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agendamento '{schedule_id}' não encontrado na organização ativa.",
        )
    return item


@router.patch(
    "/schedules/{schedule_id}",
    response_model=ScanScheduleResponse,
    summary="Atualizar parâmetros ou frequência do agendamento",
)
def update_schedule(
    schedule_id: str,
    req: ScanScheduleUpdateRequest,
    principal: SecurityAnalystDep,
    db: DbSessionDep,
) -> ScanScheduleResponse:
    service = SchedulerService()
    try:
        item = service.update_schedule(
            db=db,
            organization_id=principal.organization.id,
            schedule_id=schedule_id,
            req=req,
        )
    except ScheduleValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    if not item:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agendamento '{schedule_id}' não encontrado para atualização.",
        )
    return item


@router.delete(
    "/schedules/{schedule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Excluir agendamento de auditoria",
)
def delete_schedule(
    schedule_id: str,
    principal: SecurityAnalystDep,
    db: DbSessionDep,
) -> None:
    service = SchedulerService()
    success = service.delete_schedule(
        db=db,
        organization_id=principal.organization.id,
        schedule_id=schedule_id,
    )
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agendamento '{schedule_id}' não encontrado para exclusão.",
        )


@router.post(
    "/schedules/{schedule_id}/pause",
    response_model=ScanScheduleResponse,
    summary="Pausar agendamento de auditoria",
)
def pause_schedule(
    schedule_id: str,
    principal: SecurityAnalystDep,
    db: DbSessionDep,
) -> ScanScheduleResponse:
    service = SchedulerService()
    item = service.pause_schedule(
        db=db,
        organization_id=principal.organization.id,
        schedule_id=schedule_id,
    )
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agendamento não encontrado.")
    return item


@router.post(
    "/schedules/{schedule_id}/resume",
    response_model=ScanScheduleResponse,
    summary="Retomar agendamento de auditoria pausado",
)
def resume_schedule(
    schedule_id: str,
    principal: SecurityAnalystDep,
    db: DbSessionDep,
) -> ScanScheduleResponse:
    service = SchedulerService()
    item = service.resume_schedule(
        db=db,
        organization_id=principal.organization.id,
        schedule_id=schedule_id,
    )
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agendamento não encontrado.")
    return item


@router.post(
    "/schedules/trigger-due",
    summary="Disparar verificação de agendamentos pendentes",
)
def trigger_due_schedules(
    principal: SecurityAnalystDep,
    db: DbSessionDep,
) -> dict[str, list[str]]:
    service = SchedulerService()
    triggered_scans = service.trigger_due_schedules(db=db)
    return {"triggered_scan_ids": triggered_scans}


# ============================================================================
# Notificações e Preferências
# ============================================================================


@router.get(
    "/notifications",
    response_model=NotificationPageResponse,
    summary="Listar notificações in-app da organização",
)
def list_notifications(
    principal: ViewerDep,
    db: DbSessionDep,
    unread_only: bool = Query(default=False),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> NotificationPageResponse:
    service = NotificationService()
    return service.list_notifications(
        db=db,
        organization_id=principal.organization.id,
        user_id=principal.user.id,
        unread_only=unread_only,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/notifications/{notification_id}/read",
    summary="Marcar notificação específica como lida",
)
def mark_notification_read(
    notification_id: str,
    principal: ViewerDep,
    db: DbSessionDep,
) -> dict[str, int]:
    service = NotificationService()
    count = service.mark_as_read(
        db=db,
        organization_id=principal.organization.id,
        notification_id=notification_id,
        user_id=principal.user.id,
    )
    return {"updated": count}


@router.post(
    "/notifications/read-all",
    summary="Marcar todas as notificações como lidas",
)
def mark_all_notifications_read(
    principal: ViewerDep,
    db: DbSessionDep,
) -> dict[str, int]:
    service = NotificationService()
    count = service.mark_as_read(
        db=db,
        organization_id=principal.organization.id,
        mark_all=True,
        user_id=principal.user.id,
    )
    return {"updated": count}


@router.get(
    "/notifications/preferences",
    response_model=NotificationPreferenceResponse,
    summary="Obter preferências de notificações do usuário",
)
def get_notification_preferences(
    principal: ViewerDep,
    db: DbSessionDep,
) -> NotificationPreferenceResponse:
    service = NotificationService()
    return service.get_preferences(
        db=db,
        organization_id=principal.organization.id,
        user_id=principal.user.id,
    )


@router.put(
    "/notifications/preferences",
    response_model=NotificationPreferenceResponse,
    summary="Atualizar preferências de notificações do usuário",
)
def update_notification_preferences(
    req: NotificationPreferenceUpdateRequest,
    principal: ViewerDep,
    db: DbSessionDep,
) -> NotificationPreferenceResponse:
    service = NotificationService()
    return service.update_preferences(
        db=db,
        organization_id=principal.organization.id,
        user_id=principal.user.id,
        req=req,
    )


# ============================================================================
# Webhooks
# ============================================================================


@router.post(
    "/webhooks",
    response_model=WebhookEndpointResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Cadastrar endpoint de webhook com validação anti-SSRF",
)
def create_webhook(
    req: WebhookEndpointCreateRequest,
    principal: SecurityAnalystDep,
    db: DbSessionDep,
) -> WebhookEndpointResponse:
    service = WebhookService()
    try:
        return service.create_endpoint(
            db=db,
            organization_id=principal.organization.id,
            user_id=principal.user.id,
            req=req,
        )
    except WebhookValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.get(
    "/webhooks",
    response_model=list[WebhookEndpointResponse],
    summary="Listar endpoints de webhook da organização",
)
def list_webhooks(
    principal: ViewerDep,
    db: DbSessionDep,
) -> list[WebhookEndpointResponse]:
    service = WebhookService()
    return service.list_endpoints(
        db=db,
        organization_id=principal.organization.id,
    )


@router.get(
    "/webhooks/deliveries",
    response_model=WebhookDeliveryPageResponse,
    summary="Listar histórico de entregas de webhooks",
)
def list_webhook_deliveries(
    principal: ViewerDep,
    db: DbSessionDep,
    webhook_id: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> WebhookDeliveryPageResponse:
    service = WebhookService()
    return service.list_deliveries(
        db=db,
        organization_id=principal.organization.id,
        webhook_id=webhook_id,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/webhooks/{webhook_id}",
    response_model=WebhookEndpointResponse,
    summary="Obter detalhes de endpoint de webhook",
)
def get_webhook(
    webhook_id: str,
    principal: ViewerDep,
    db: DbSessionDep,
) -> WebhookEndpointResponse:
    service = WebhookService()
    ep = service.get_endpoint(
        db=db,
        organization_id=principal.organization.id,
        webhook_id=webhook_id,
    )
    if not ep:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook não encontrado.")
    return ep


@router.patch(
    "/webhooks/{webhook_id}",
    response_model=WebhookEndpointResponse,
    summary="Atualizar configurações de endpoint de webhook",
)
def update_webhook(
    webhook_id: str,
    req: WebhookEndpointUpdateRequest,
    principal: SecurityAnalystDep,
    db: DbSessionDep,
) -> WebhookEndpointResponse:
    service = WebhookService()
    try:
        ep = service.update_endpoint(
            db=db,
            organization_id=principal.organization.id,
            webhook_id=webhook_id,
            req=req,
        )
    except WebhookValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    if not ep:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook não encontrado.")
    return ep


@router.delete(
    "/webhooks/{webhook_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remover endpoint de webhook",
)
def delete_webhook(
    webhook_id: str,
    principal: SecurityAnalystDep,
    db: DbSessionDep,
) -> None:
    service = WebhookService()
    if not service.delete_endpoint(
        db=db,
        organization_id=principal.organization.id,
        webhook_id=webhook_id,
    ):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook não encontrado.")


@router.post(
    "/webhooks/{webhook_id}/rotate-secret",
    response_model=WebhookEndpointSecretRotateResponse,
    summary="Rotacionar chave secreta HMAC do webhook",
)
def rotate_webhook_secret(
    webhook_id: str,
    principal: SecurityAnalystDep,
    db: DbSessionDep,
) -> WebhookEndpointSecretRotateResponse:
    service = WebhookService()
    resp = service.rotate_secret(
        db=db,
        organization_id=principal.organization.id,
        webhook_id=webhook_id,
    )
    if not resp:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook não encontrado.")
    return resp


@router.post(
    "/webhooks/{webhook_id}/test",
    response_model=WebhookTestResponse,
    summary="Disparar evento de teste imediato para o webhook",
)
def test_webhook(
    webhook_id: str,
    principal: SecurityAnalystDep,
    db: DbSessionDep,
) -> WebhookTestResponse:
    service = WebhookService()
    return service.test_webhook(
        db=db,
        organization_id=principal.organization.id,
        webhook_id=webhook_id,
    )


# ============================================================================
# Chaves de API (API Tokens)
# ============================================================================


@router.post(
    "/api-tokens",
    response_model=ApiTokenCreatedResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Criar nova chave de API com escopos limitados",
)
def create_api_token(
    req: ApiTokenCreateRequest,
    principal: SecurityAnalystDep,
    db: DbSessionDep,
) -> ApiTokenCreatedResponse:
    service = ApiTokenService()
    try:
        return service.create_token(
            db=db,
            organization_id=principal.organization.id,
            user_id=principal.user.id,
            req=req,
        )
    except ApiTokenError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.get(
    "/api-tokens",
    response_model=ApiTokenPageResponse,
    summary="Listar chaves de API da organização",
)
def list_api_tokens(
    principal: ViewerDep,
    db: DbSessionDep,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> ApiTokenPageResponse:
    service = ApiTokenService()
    return service.list_tokens(
        db=db,
        organization_id=principal.organization.id,
        limit=limit,
        offset=offset,
    )


@router.delete(
    "/api-tokens/{token_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revogar chave de API",
)
def revoke_api_token(
    token_id: str,
    principal: SecurityAnalystDep,
    db: DbSessionDep,
) -> None:
    service = ApiTokenService()
    if not service.revoke_token(
        db=db,
        organization_id=principal.organization.id,
        token_id=token_id,
    ):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Chave de API não encontrada.")


# ============================================================================
# Templates de Auditoria
# ============================================================================


@router.post(
    "/templates",
    response_model=ScanTemplateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Criar template reutilizável de auditoria",
)
def create_template(
    req: ScanTemplateCreateRequest,
    principal: SecurityAnalystDep,
    db: DbSessionDep,
) -> ScanTemplateResponse:
    service = TemplateService()
    return service.create_template(
        db=db,
        organization_id=principal.organization.id,
        user_id=principal.user.id,
        req=req,
    )


@router.get(
    "/templates",
    response_model=ScanTemplatePageResponse,
    summary="Listar templates de auditoria",
)
def list_templates(
    principal: ViewerDep,
    db: DbSessionDep,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> ScanTemplatePageResponse:
    service = TemplateService()
    return service.list_templates(
        db=db,
        organization_id=principal.organization.id,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/templates/seed",
    response_model=list[ScanTemplateResponse],
    summary="Inicializar templates padrão se vazios",
)
def seed_templates(
    principal: SecurityAnalystDep,
    db: DbSessionDep,
) -> list[ScanTemplateResponse]:
    service = TemplateService()
    return service.seed_defaults(
        db=db,
        organization_id=principal.organization.id,
        user_id=principal.user.id,
    )


@router.get(
    "/templates/{template_id}",
    response_model=ScanTemplateResponse,
    summary="Obter detalhes de um template",
)
def get_template(
    template_id: str,
    principal: ViewerDep,
    db: DbSessionDep,
) -> ScanTemplateResponse:
    service = TemplateService()
    t = service.get_template(
        db=db,
        organization_id=principal.organization.id,
        template_id=template_id,
    )
    if not t:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Template não encontrado.")
    return t


@router.patch(
    "/templates/{template_id}",
    response_model=ScanTemplateResponse,
    summary="Atualizar template de auditoria",
)
def update_template(
    template_id: str,
    req: ScanTemplateUpdateRequest,
    principal: SecurityAnalystDep,
    db: DbSessionDep,
) -> ScanTemplateResponse:
    service = TemplateService()
    t = service.update_template(
        db=db,
        organization_id=principal.organization.id,
        template_id=template_id,
        req=req,
    )
    if not t:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Template não encontrado.")
    return t


@router.delete(
    "/templates/{template_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remover template de auditoria",
)
def delete_template(
    template_id: str,
    principal: SecurityAnalystDep,
    db: DbSessionDep,
) -> None:
    service = TemplateService()
    if not service.delete_template(
        db=db,
        organization_id=principal.organization.id,
        template_id=template_id,
    ):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Template não encontrado.")
