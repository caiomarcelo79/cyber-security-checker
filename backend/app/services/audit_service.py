"""Serviço de registro e consulta da trilha de auditoria interna (AuditLog - Seção 5 e Seção 12)."""

from __future__ import annotations

from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.models.entities import AuditLog
from app.schemas.auth_assets import AuditLogResponse


class AuditLogService:
    """Registra eventos relevantes executados por usuários e componentes do sistema."""

    @staticmethod
    def record(
        db: Session,
        action: str,
        resource_type: str,
        resource_id: str | None = None,
        organization_id: str | None = None,
        user_id: str | None = None,
        ip_address: str | None = None,
        metadata: dict[str, Any] | None = None,
        commit: bool = False,
    ) -> AuditLog:
        entry = AuditLog(
            organization_id=organization_id,
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            ip_address=ip_address,
            metadata_json=metadata or {},
        )
        db.add(entry)
        if commit:
            db.commit()
            db.refresh(entry)
        else:
            db.flush()
        return entry

    @staticmethod
    def list_organization_logs(
        db: Session,
        organization_id: str,
        limit: int = 100,
    ) -> list[AuditLogResponse]:
        stmt = (
            select(AuditLog)
            .where(AuditLog.organization_id == organization_id)
            .order_by(desc(AuditLog.created_at))
            .limit(max(1, min(limit, 500)))
        )
        rows = db.scalars(stmt).all()
        return [
            AuditLogResponse(
                id=row.id,
                organization_id=row.organization_id,
                user_id=row.user_id,
                action=row.action,
                resource_type=row.resource_type,
                resource_id=row.resource_id,
                ip_address=row.ip_address,
                metadata_json=row.metadata_json,
                created_at=row.created_at,
            )
            for row in rows
        ]
