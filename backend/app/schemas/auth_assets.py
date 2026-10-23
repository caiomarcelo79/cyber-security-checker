"""Esquemas Pydantic v2 para Autenticação, Organizações, RBAC, Ativos, Autorizações e AuditLog (Fase 2)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from app.core.security import UserRole

AssetTypeLiteral = Literal["WEB_APP", "REST_API", "GRAPHQL_API", "DOMAIN"]
EnvironmentLiteral = Literal["PRODUCTION", "STAGING", "DEVELOPMENT", "LAB"]
AuthorizationMethodLiteral = Literal["DNS_TXT", "HTTP_WELL_KNOWN", "LAB_INTERNAL"]
AuthorizationStatusLiteral = Literal["PENDING", "VERIFIED", "EXPIRED", "REVOKED"]


class UserRegisterRequest(BaseModel):
    """Dados para registro inicial de usuário e criação de sua organização."""

    email: str = Field(..., min_length=5, max_length=255)
    password: str = Field(..., min_length=8, max_length=128)
    full_name: str = Field(..., min_length=2, max_length=160)
    organization_name: str = Field(..., min_length=2, max_length=160)
    organization_slug: str | None = Field(default=None, max_length=120)

    @field_validator("email")
    @classmethod
    def validate_email_format(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if "@" not in cleaned or "." not in cleaned.split("@")[-1]:
            raise ValueError("Informe um endereço de e-mail válido.")
        return cleaned


class UserLoginRequest(BaseModel):
    """Credenciais de login e organização opcional."""

    email: str = Field(..., min_length=5, max_length=255)
    password: str = Field(..., min_length=8, max_length=128)
    organization_id: str | None = None

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return value.strip().lower()


class SwitchOrganizationRequest(BaseModel):
    """Solicitação para alternar o contexto da organização ativa na sessão."""

    organization_id: str


class UserPublicResponse(BaseModel):
    """Representação pública segura de um usuário (sem hash de senha)."""

    id: str
    email: str
    full_name: str
    is_active: bool
    created_at: datetime


class OrganizationPublicResponse(BaseModel):
    """Representação de uma organização."""

    id: str
    name: str
    slug: str
    is_active: bool
    created_at: datetime


class MembershipSummary(BaseModel):
    """Resumo do vínculo de um usuário com uma organização."""

    organization_id: str
    organization_name: str
    organization_slug: str
    role: UserRole


class AuthSessionResponse(BaseModel):
    """Resposta completa de sessão autenticada com JWT e contexto multi-organização."""

    access_token: str
    token_type: str = "bearer"
    expires_in_minutes: int
    user: UserPublicResponse
    active_organization: OrganizationPublicResponse
    active_role: UserRole
    memberships: list[MembershipSummary]


class OrganizationCreateRequest(BaseModel):
    """Criação de nova organização pelo usuário autenticado."""

    name: str = Field(..., min_length=2, max_length=160)
    slug: str | None = Field(default=None, max_length=120)


class OrganizationMemberAddRequest(BaseModel):
    """Adição ou atualização de membro em uma organização pelo ADMIN."""

    email: str = Field(..., min_length=5, max_length=255)
    full_name: str = Field(default="Novo Integrante", min_length=2, max_length=160)
    password: str | None = Field(
        default=None,
        description="Obrigatório apenas se o usuário ainda não existir na plataforma",
    )
    role: UserRole = Field(default=UserRole.VIEWER)

    @field_validator("email")
    @classmethod
    def normalize_member_email(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if "@" not in cleaned:
            raise ValueError("E-mail inválido.")
        return cleaned


class OrganizationMemberResponse(BaseModel):
    """Dados de membro vinculado à organização."""

    membership_id: str
    organization_id: str
    user_id: str
    email: str
    full_name: str
    role: UserRole
    created_at: datetime


class AssetCreateRequest(BaseModel):
    """Cadastro de sistema, domínio, aplicação web ou API na organização ativa."""

    name: str = Field(..., min_length=2, max_length=180)
    target_url: str = Field(..., min_length=7, max_length=512)
    asset_type: AssetTypeLiteral = "WEB_APP"
    environment: EnvironmentLiteral = "STAGING"
    owner_name: str = Field(..., min_length=2, max_length=160)
    owner_email: str = Field(..., min_length=5, max_length=255)
    tags: list[str] = Field(default_factory=list)
    excluded_paths: list[str] = Field(default_factory=lambda: ["/logout", "/delete"])


class AssetUpdateRequest(BaseModel):
    """Atualização parcial de metadados de um ativo da organização."""

    name: str | None = Field(default=None, min_length=2, max_length=180)
    environment: EnvironmentLiteral | None = None
    owner_name: str | None = Field(default=None, min_length=2, max_length=160)
    owner_email: str | None = Field(default=None, min_length=5, max_length=255)
    tags: list[str] | None = None
    excluded_paths: list[str] | None = None


class AssetResponse(BaseModel):
    """Representação completa de um ativo cadastrado."""

    id: str
    organization_id: str
    name: str
    target_url: str
    hostname: str
    asset_type: str
    environment: str
    owner_name: str
    owner_email: str
    tags: list[str]
    excluded_paths: list[str]
    risk_score: int
    authorization_status: str
    created_at: datetime
    updated_at: datetime


class AuthorizationInitiateRequest(BaseModel):
    """Inicia um desafio de comprovação de controle/autorização para o ativo."""

    method: AuthorizationMethodLiteral
    scope_notes: str | None = Field(
        default=None,
        max_length=1000,
        description="Observações formais de escopo, janela e documento de autorização",
    )
    expires_in_days: int = Field(default=90, ge=1, le=365)


class AuthorizationVerifyRequest(BaseModel):
    """Parâmetros opcionais para execução da verificação de autorização."""

    notes: str | None = None


class TargetAuthorizationResponse(BaseModel):
    """Registro de comprovação de autorização de um ativo com instruções passo a passo."""

    id: str
    asset_id: str
    organization_id: str
    method: str
    verification_token: str
    status: str
    verified_by_user_id: str | None
    scope_notes: str | None
    instructions: dict[str, str]
    verified_at: datetime | None
    expires_at: datetime | None
    created_at: datetime


class AuditLogResponse(BaseModel):
    """Registro imutável da trilha de auditoria interna."""

    id: str
    organization_id: str | None
    user_id: str | None
    action: str
    resource_type: str
    resource_id: str | None
    ip_address: str | None
    metadata_json: dict[str, Any]
    created_at: datetime
