"""Serviço de gerenciamento e validação de chaves de API para integrações de terceiros (Fase 7).

Gera tokens seguros, persiste apenas o hash SHA-256 no banco de dados e valida
escopos e datas de expiração nas requisições autenticadas.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.models.entities import ApiTokenRecord, Organization, User
from app.schemas.automations import (
    VALID_API_SCOPES,
    ApiTokenCreatedResponse,
    ApiTokenCreateRequest,
    ApiTokenPageResponse,
    ApiTokenResponse,
)

logger = logging.getLogger("cyber_security_checker.api_token_service")


class ApiTokenError(ValueError):
    """Erro em operações de chave de API."""


class ApiTokenService:
    """Gerencia ciclo de vida, hashing e validação de chaves de API."""

    TOKEN_PREFIX = "csc_live_"

    @staticmethod
    def _hash_token(raw_token: str) -> str:
        """Gera o hash SHA-256 do segredo da chave de API."""
        return hashlib.sha256(raw_token.strip().encode("utf-8")).hexdigest()

    def create_token(
        self,
        db: Session,
        organization_id: str,
        user_id: str,
        req: ApiTokenCreateRequest,
    ) -> ApiTokenCreatedResponse:
        """Cria uma nova chave de API, salvando apenas seu hash SHA-256 e retornando o segredo uma única vez."""
        # Validação de escopos
        for sc in req.scopes:
            if sc not in VALID_API_SCOPES:
                raise ApiTokenError(
                    f"Escopo inválido: '{sc}'. Escopos válidos: {sorted(VALID_API_SCOPES)}"
                )

        # Gera token criptograficamente seguro
        random_part = secrets.token_urlsafe(32)
        raw_token = f"{self.TOKEN_PREFIX}{random_part}"
        token_prefix = raw_token[:12]
        token_hash = self._hash_token(raw_token)

        expires_at: datetime | None = None
        if req.expires_in_days:
            expires_at = datetime.now(UTC) + timedelta(days=req.expires_in_days)

        now = datetime.now(UTC)
        record = ApiTokenRecord(
            organization_id=organization_id,
            user_id=user_id,
            name=req.name.strip(),
            token_prefix=token_prefix,
            token_hash=token_hash,
            scopes=req.scopes,
            expires_at=expires_at,
            is_revoked=False,
            created_at=now,
        )
        db.add(record)
        db.commit()
        db.refresh(record)

        logger.info(
            "Chave de API criada: id=%s org=%s user=%s prefix=%s escopos=%s",
            record.id,
            organization_id,
            user_id,
            token_prefix,
            req.scopes,
        )

        return ApiTokenCreatedResponse(
            id=record.id,
            name=record.name,
            token_prefix=token_prefix,
            raw_api_token=raw_token,
            scopes=record.scopes,
            expires_at=record.expires_at,
            created_at=record.created_at,
        )

    def list_tokens(
        self,
        db: Session,
        organization_id: str,
        limit: int = 50,
        offset: int = 0,
    ) -> ApiTokenPageResponse:
        """Lista chaves de API da organização."""
        total = (
            db.scalar(
                select(func.count(ApiTokenRecord.id)).where(
                    ApiTokenRecord.organization_id == organization_id
                )
            )
            or 0
        )

        query = (
            select(ApiTokenRecord)
            .where(ApiTokenRecord.organization_id == organization_id)
            .order_by(desc(ApiTokenRecord.created_at))
            .limit(limit)
            .offset(offset)
        )
        records = db.execute(query).scalars().all()

        items = [
            ApiTokenResponse(
                id=t.id,
                organization_id=t.organization_id,
                user_id=t.user_id,
                name=t.name,
                token_prefix=t.token_prefix,
                scopes=t.scopes or [],
                expires_at=t.expires_at,
                last_used_at=t.last_used_at,
                is_revoked=t.is_revoked,
                created_at=t.created_at,
            )
            for t in records
        ]

        return ApiTokenPageResponse(
            items=items,
            total=total,
            limit=limit,
            offset=offset,
        )

    def revoke_token(
        self,
        db: Session,
        organization_id: str,
        token_id: str,
    ) -> bool:
        """Revoga uma chave de API."""
        token = db.get(ApiTokenRecord, token_id)
        if not token or token.organization_id != organization_id:
            return False

        token.is_revoked = True
        db.commit()
        logger.info("Chave de API revogada: id=%s org=%s", token_id, organization_id)
        return True

    def authenticate_token(
        self,
        db: Session,
        raw_token: str,
    ) -> tuple[ApiTokenRecord, User, Organization] | None:
        """Autentica uma requisição com chave de API.

        Verifica o hash SHA-256, se a chave não foi revogada e se não expirou.
        Atualiza o campo `last_used_at`.
        """
        if not raw_token or not raw_token.startswith(self.TOKEN_PREFIX):
            return None

        token_hash = self._hash_token(raw_token)
        token = (
            db.execute(select(ApiTokenRecord).where(ApiTokenRecord.token_hash == token_hash))
            .scalars()
            .first()
        )

        if not token:
            return None

        if token.is_revoked:
            logger.warning("Tentativa de uso de chave revogada: id=%s", token.id)
            return None

        now = datetime.now(UTC)
        if token.expires_at:
            exp = token.expires_at
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=UTC)
            if exp < now:
                logger.warning("Tentativa de uso de chave expirada: id=%s", token.id)
                return None

        user = db.get(User, token.user_id)
        organization = db.get(Organization, token.organization_id)
        if not user or not organization or not user.is_active or not organization.is_active:
            return None

        token.last_used_at = now
        db.commit()

        return token, user, organization
