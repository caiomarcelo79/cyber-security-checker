"""Serviço de Autenticação, Organizações e Controle de Acesso Baseado em Papéis (RBAC - Fase 2)."""

from __future__ import annotations

import re
import secrets
from datetime import UTC, datetime, timedelta

from fastapi import HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.security import (
    AUTH_COOKIE_NAME,
    UserRole,
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)
from app.models.entities import AuditLog, Organization, OrganizationMembership, RevokedToken, User
from app.schemas.auth_assets import (
    AuthSessionResponse,
    MembershipSummary,
    OrganizationCreateRequest,
    OrganizationMemberAddRequest,
    OrganizationMemberResponse,
    OrganizationPublicResponse,
    UserLoginRequest,
    UserPublicResponse,
    UserRegisterRequest,
)
from app.services.audit_service import AuditLogService


def slugify_org_name(raw_name: str) -> str:
    cleaned = re.sub(r"[^a-z0-9]+", "-", raw_name.strip().lower()).strip("-")
    return cleaned or f"org-{secrets.token_hex(4)}"


_DUMMY_PASSWORD_HASH = hash_password("timing-equalizer-not-a-real-password")


class AuthOrganizationService:
    """Gerencia ciclo de vida de autenticação, organizações e membros com isolamento por tenant."""

    @staticmethod
    def _ensure_unique_slug(db: Session, desired_slug: str) -> str:
        base_slug = slugify_org_name(desired_slug)
        candidate = base_slug
        counter = 1
        while db.scalar(select(Organization).where(Organization.slug == candidate)) is not None:
            counter += 1
            candidate = f"{base_slug}-{counter}"
        return candidate

    @classmethod
    def register_user_and_organization(
        cls,
        db: Session,
        payload: UserRegisterRequest,
        ip_address: str | None = None,
    ) -> AuthSessionResponse:
        existing_user = db.scalar(select(User).where(User.email == payload.email))
        if existing_user is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Já existe um usuário cadastrado com este endereço de e-mail.",
            )

        org_slug = cls._ensure_unique_slug(db, payload.organization_slug or payload.organization_name)
        organization = Organization(
            name=payload.organization_name.strip(),
            slug=org_slug,
            is_active=True,
        )
        db.add(organization)
        db.flush()

        user = User(
            email=payload.email,
            hashed_password=hash_password(payload.password),
            full_name=payload.full_name.strip(),
            is_active=True,
        )
        db.add(user)
        db.flush()

        membership = OrganizationMembership(
            organization_id=organization.id,
            user_id=user.id,
            role=UserRole.ADMIN.value,
        )
        db.add(membership)
        db.flush()

        AuditLogService.record(
            db=db,
            action="USER_REGISTERED",
            resource_type="user",
            resource_id=user.id,
            organization_id=organization.id,
            user_id=user.id,
            ip_address=ip_address,
            metadata={"email": user.email, "organization_slug": organization.slug},
        )
        AuditLogService.record(
            db=db,
            action="ORG_CREATED",
            resource_type="organization",
            resource_id=organization.id,
            organization_id=organization.id,
            user_id=user.id,
            ip_address=ip_address,
            metadata={"name": organization.name, "slug": organization.slug},
        )
        db.commit()
        db.refresh(user)
        db.refresh(organization)

        return cls.build_session_response(
            db=db,
            user=user,
            active_organization=organization,
            active_role=UserRole.ADMIN,
        )

    @classmethod
    def _enforce_login_rate_limit(cls, db: Session, email: str, ip_address: str | None) -> None:
        """Limite proporcional por janela deslizante (sem bloqueio permanente de conta)."""
        settings = get_settings()
        since = datetime.now(UTC) - timedelta(minutes=settings.login_failure_window_minutes)
        base = select(AuditLog).where(
            AuditLog.action == "USER_LOGIN_FAILED", AuditLog.created_at >= since
        )
        too_many = False
        if ip_address:
            ip_count = db.scalar(
                select(func.count()).select_from(base.where(AuditLog.ip_address == ip_address).subquery())
            )
            too_many = (ip_count or 0) >= settings.login_max_failures_per_ip
        if not too_many:
            recent = db.scalars(base.order_by(AuditLog.created_at.desc()).limit(500)).all()
            email_count = sum(
                1 for r in recent if (r.metadata_json or {}).get("attempted_email") == email
            )
            too_many = email_count >= settings.login_max_failures_per_email
        if too_many:
            AuditLogService.record(
                db=db,
                action="USER_LOGIN_RATE_LIMITED",
                resource_type="auth",
                ip_address=ip_address,
                metadata={"attempted_email": email},
                commit=True,
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Muitas tentativas de login. Aguarde alguns minutos e tente novamente.",
                headers={"Retry-After": str(settings.login_failure_window_minutes * 60)},
            )

    @classmethod
    def revoke_request_token(cls, db: Session, request: Request, user_id: str) -> None:
        """Revoga o JWT da requisição atual (logout efetivo até a expiração natural)."""
        auth = request.headers.get("authorization", "")
        raw = auth.split(" ", 1)[1].strip() if auth.lower().startswith("bearer ") else None
        raw = raw or request.cookies.get(AUTH_COOKIE_NAME)
        if not raw or raw.startswith("csc_live_"):
            return
        try:
            payload = decode_access_token(raw)
        except ValueError:
            return
        jti = str(payload.get("jti", ""))
        if jti and db.get(RevokedToken, jti) is None:
            db.add(
                RevokedToken(
                    jti=jti,
                    user_id=user_id,
                    expires_at=datetime.fromtimestamp(int(payload["exp"]), UTC),
                )
            )
            db.commit()

    @classmethod
    def authenticate_user(
        cls,
        db: Session,
        payload: UserLoginRequest,
        ip_address: str | None = None,
    ) -> AuthSessionResponse:
        cls._enforce_login_rate_limit(db, payload.email, ip_address)
        user = db.scalar(select(User).where(User.email == payload.email))
        if user is None:
            # Equaliza o tempo de resposta para evitar enumeração de usuários por timing.
            verify_password(payload.password, _DUMMY_PASSWORD_HASH)
        if (
            user is None
            or not user.is_active
            or not verify_password(payload.password, user.hashed_password)
        ):
            AuditLogService.record(
                db=db,
                action="USER_LOGIN_FAILED",
                resource_type="auth",
                ip_address=ip_address,
                metadata={"attempted_email": payload.email},
                commit=True,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Credenciais inválidas ou conta inativa.",
            )

        memberships = db.scalars(
            select(OrganizationMembership).where(OrganizationMembership.user_id == user.id)
        ).all()
        if not memberships:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Usuário não possui vínculo ativo com nenhuma organização.",
            )

        selected_membership: OrganizationMembership | None = None
        if payload.organization_id:
            for m in memberships:
                if m.organization_id == payload.organization_id:
                    selected_membership = m
                    break
            if selected_membership is None:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Usuário não pertence à organização solicitada.",
                )
        else:
            selected_membership = memberships[0]

        organization = db.get(Organization, selected_membership.organization_id)
        if organization is None or not organization.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Organização selecionada está inativa ou não encontrada.",
            )

        AuditLogService.record(
            db=db,
            action="USER_LOGIN",
            resource_type="auth",
            resource_id=user.id,
            organization_id=organization.id,
            user_id=user.id,
            ip_address=ip_address,
            metadata={"role": selected_membership.role},
            commit=True,
        )

        return cls.build_session_response(
            db=db,
            user=user,
            active_organization=organization,
            active_role=UserRole(selected_membership.role),
        )

    @classmethod
    def switch_organization(
        cls,
        db: Session,
        user: User,
        target_organization_id: str,
        ip_address: str | None = None,
    ) -> AuthSessionResponse:
        membership = db.scalar(
            select(OrganizationMembership).where(
                OrganizationMembership.user_id == user.id,
                OrganizationMembership.organization_id == target_organization_id,
            )
        )
        if membership is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Acesso negado: você não pertence a esta organização.",
            )

        organization = db.get(Organization, target_organization_id)
        if organization is None or not organization.is_active:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organização não encontrada ou inativa.",
            )

        AuditLogService.record(
            db=db,
            action="USER_SWITCHED_ORG",
            resource_type="organization",
            resource_id=organization.id,
            organization_id=organization.id,
            user_id=user.id,
            ip_address=ip_address,
            metadata={"role": membership.role},
            commit=True,
        )

        return cls.build_session_response(
            db=db,
            user=user,
            active_organization=organization,
            active_role=UserRole(membership.role),
        )

    @staticmethod
    def build_session_response(
        db: Session,
        user: User,
        active_organization: Organization,
        active_role: UserRole,
    ) -> AuthSessionResponse:
        settings = get_settings()
        rows = db.execute(
            select(OrganizationMembership, Organization)
            .join(Organization, OrganizationMembership.organization_id == Organization.id)
            .where(OrganizationMembership.user_id == user.id, Organization.is_active.is_(True))
        ).all()

        membership_summaries = [
            MembershipSummary(
                organization_id=org.id,
                organization_name=org.name,
                organization_slug=org.slug,
                role=UserRole(mem.role),
            )
            for mem, org in rows
        ]

        token = create_access_token(
            user_id=user.id,
            email=user.email,
            organization_id=active_organization.id,
            role=active_role.value,
        )

        return AuthSessionResponse(
            access_token=token,
            token_type="bearer",
            expires_in_minutes=settings.access_token_expire_minutes,
            user=UserPublicResponse(
                id=user.id,
                email=user.email,
                full_name=user.full_name,
                is_active=user.is_active,
                created_at=user.created_at,
            ),
            active_organization=OrganizationPublicResponse(
                id=active_organization.id,
                name=active_organization.name,
                slug=active_organization.slug,
                is_active=active_organization.is_active,
                created_at=active_organization.created_at,
            ),
            active_role=active_role,
            memberships=membership_summaries,
        )

    @classmethod
    def create_organization_for_user(
        cls,
        db: Session,
        user: User,
        payload: OrganizationCreateRequest,
        ip_address: str | None = None,
    ) -> OrganizationPublicResponse:
        slug = cls._ensure_unique_slug(db, payload.slug or payload.name)
        org = Organization(name=payload.name.strip(), slug=slug, is_active=True)
        db.add(org)
        db.flush()

        mem = OrganizationMembership(
            organization_id=org.id,
            user_id=user.id,
            role=UserRole.ADMIN.value,
        )
        db.add(mem)
        AuditLogService.record(
            db=db,
            action="ORG_CREATED",
            resource_type="organization",
            resource_id=org.id,
            organization_id=org.id,
            user_id=user.id,
            ip_address=ip_address,
            metadata={"name": org.name, "slug": org.slug},
        )
        db.commit()
        db.refresh(org)
        return OrganizationPublicResponse(
            id=org.id,
            name=org.name,
            slug=org.slug,
            is_active=org.is_active,
            created_at=org.created_at,
        )

    @staticmethod
    def list_organization_members(
        db: Session,
        organization_id: str,
    ) -> list[OrganizationMemberResponse]:
        rows = db.execute(
            select(OrganizationMembership, User)
            .join(User, OrganizationMembership.user_id == User.id)
            .where(OrganizationMembership.organization_id == organization_id)
        ).all()

        return [
            OrganizationMemberResponse(
                membership_id=mem.id,
                organization_id=mem.organization_id,
                user_id=usr.id,
                email=usr.email,
                full_name=usr.full_name,
                role=UserRole(mem.role),
                created_at=mem.created_at,
            )
            for mem, usr in rows
        ]

    @staticmethod
    def add_or_update_member(
        db: Session,
        organization_id: str,
        actor_user_id: str,
        payload: OrganizationMemberAddRequest,
        ip_address: str | None = None,
    ) -> OrganizationMemberResponse:
        target_user = db.scalar(select(User).where(User.email == payload.email))
        if target_user is None:
            if not payload.password or len(payload.password) < 8:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Para cadastrar um novo usuário na plataforma, forneça uma senha de no mínimo 8 caracteres.",
                )
            target_user = User(
                email=payload.email,
                hashed_password=hash_password(payload.password),
                full_name=payload.full_name.strip(),
                is_active=True,
            )
            db.add(target_user)
            db.flush()

        membership = db.scalar(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id == organization_id,
                OrganizationMembership.user_id == target_user.id,
            )
        )
        if membership is None:
            membership = OrganizationMembership(
                organization_id=organization_id,
                user_id=target_user.id,
                role=payload.role.value,
            )
            db.add(membership)
        else:
            membership.role = payload.role.value

        AuditLogService.record(
            db=db,
            action="MEMBER_ADDED_OR_UPDATED",
            resource_type="organization_membership",
            resource_id=target_user.id,
            organization_id=organization_id,
            user_id=actor_user_id,
            ip_address=ip_address,
            metadata={"member_email": target_user.email, "assigned_role": payload.role.value},
        )
        db.commit()
        db.refresh(membership)

        return OrganizationMemberResponse(
            membership_id=membership.id,
            organization_id=membership.organization_id,
            user_id=target_user.id,
            email=target_user.email,
            full_name=target_user.full_name,
            role=UserRole(membership.role),
            created_at=membership.created_at,
        )
