"""Serviço de gerenciamento de notificações, alertas e preferências (Fase 7).

Gerencia notificações in-app persistentes no PostgreSQL, envio de emails
através do EmailDeliveryAdapter e despacho de eventos para webhooks externos.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import desc, func, select, update
from sqlalchemy.orm import Session

from app.models.entities import NotificationPreferenceRecord, NotificationRecord, User
from app.schemas.automations import (
    NotificationPageResponse,
    NotificationPreferenceResponse,
    NotificationPreferenceUpdateRequest,
    NotificationResponse,
)
from app.services.email_adapter import EmailDeliveryAdapter

logger = logging.getLogger("cyber_security_checker.notification_service")

SEVERITY_LEVELS: dict[str, int] = {
    "INFO": 1,
    "LOW": 2,
    "MEDIUM": 3,
    "HIGH": 4,
    "CRITICAL": 5,
}


class NotificationService:
    """Gerencia notificações in-app, preferências e despacho de alertas."""

    def __init__(self, email_adapter: EmailDeliveryAdapter | None = None) -> None:
        self.email_adapter = email_adapter or EmailDeliveryAdapter()

    def dispatch_event(
        self,
        db: Session,
        organization_id: str,
        event_type: str,
        severity: str,
        title: str,
        message: str,
        link_url: str | None = None,
        user_id: str | None = None,
        metadata_json: dict[str, Any] | None = None,
        dedup_window_seconds: int = 60,
    ) -> NotificationRecord | None:
        """Registra uma notificação in-app e dispara canais configurados (email, webhooks).

        Aplica janela de deduplicação opcional para evitar spam de alertas idênticos.
        """
        severity_norm = severity.upper()
        if severity_norm not in SEVERITY_LEVELS:
            severity_norm = "INFO"

        meta = metadata_json or {}
        now = datetime.now(UTC)

        # 1. Deduplicação
        if dedup_window_seconds > 0:
            threshold = now - timedelta(seconds=dedup_window_seconds)
            existing = (
                db.execute(
                    select(NotificationRecord).where(
                        NotificationRecord.organization_id == organization_id,
                        NotificationRecord.event_type == event_type,
                        NotificationRecord.title == title,
                        NotificationRecord.created_at >= threshold,
                    )
                )
                .scalars()
                .first()
            )

            if existing:
                logger.debug(
                    "Notificação suprimida por deduplicação (evento: %s, titulo: %s)",
                    event_type,
                    title,
                )
                return existing

        # 2. Persistir notificação in-app
        notification = NotificationRecord(
            organization_id=organization_id,
            user_id=user_id,
            event_type=event_type,
            severity=severity_norm,
            title=title,
            message=message,
            link_url=link_url,
            metadata_json=meta,
            created_at=now,
        )
        db.add(notification)
        db.commit()
        db.refresh(notification)

        logger.info(
            "Notificação in-app criada: id=%s org=%s evento=%s severidade=%s",
            notification.id,
            organization_id,
            event_type,
            severity_norm,
        )

        # 3. Notificação por Email baseada em preferências
        self._deliver_email_if_eligible(
            db=db,
            organization_id=organization_id,
            user_id=user_id,
            event_type=event_type,
            severity=severity_norm,
            title=title,
            message=message,
            link_url=link_url,
        )

        # 4. Despacho para Webhooks da organização
        try:
            from app.services.webhook_service import WebhookService

            webhook_svc = WebhookService()
            webhook_svc.dispatch_event_to_webhooks(
                db=db,
                organization_id=organization_id,
                event_type=event_type,
                payload={
                    "notification_id": notification.id,
                    "event_type": event_type,
                    "severity": severity_norm,
                    "title": title,
                    "message": message,
                    "link_url": link_url,
                    "timestamp": now.isoformat(),
                    "metadata": meta,
                },
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Falha ao despachar evento para webhooks: %s", exc)

        return notification

    def _deliver_email_if_eligible(
        self,
        db: Session,
        organization_id: str,
        user_id: str | None,
        event_type: str,
        severity: str,
        title: str,
        message: str,
        link_url: str | None = None,
    ) -> None:
        """Verifica preferências e despacha email caso as condições sejam atendidas."""
        # Se user_id fornecido, busca preferência do usuário; senão, busca preferências da org
        query = select(NotificationPreferenceRecord).where(
            NotificationPreferenceRecord.organization_id == organization_id,
            NotificationPreferenceRecord.email_enabled.is_(True),
        )
        if user_id:
            query = query.where(NotificationPreferenceRecord.user_id == user_id)

        prefs = db.execute(query).scalars().all()
        event_level = SEVERITY_LEVELS.get(severity, 1)

        for pref in prefs:
            min_lvl = SEVERITY_LEVELS.get(pref.min_severity.upper(), 3)
            if event_level < min_lvl:
                continue

            # Se o usuário especificou eventos inscritos e este evento não está na lista
            if pref.subscribed_events and event_type not in pref.subscribed_events:
                continue

            destination_email = pref.email_destination
            if not destination_email:
                user = db.get(User, pref.user_id)
                if user and user.email:
                    destination_email = user.email

            if destination_email:
                body_text = f"{title}\n\nSeveridade: {severity}\n\n{message}"
                if link_url:
                    body_text += f"\n\nAcesse: {link_url}"

                body_html = (
                    f"<h3>{title}</h3><p><strong>Severidade:</strong> {severity}</p><p>{message}</p>"
                )
                if link_url:
                    body_html += f'<p><a href="{link_url}">Visualizar na Plataforma</a></p>'

                self.email_adapter.send_alert(
                    to_email=destination_email,
                    subject=f"[{severity}] {title}",
                    body_text=body_text,
                    body_html=body_html,
                )

    def list_notifications(
        self,
        db: Session,
        organization_id: str,
        user_id: str | None = None,
        unread_only: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> NotificationPageResponse:
        """Lista notificações da organização/usuário com filtros e paginação."""
        filters = [NotificationRecord.organization_id == organization_id]
        if user_id:
            filters.append(
                (NotificationRecord.user_id == user_id) | (NotificationRecord.user_id.is_(None))
            )
        if unread_only:
            filters.append(NotificationRecord.read_at.is_(None))

        total_stmt = select(func.count(NotificationRecord.id)).where(*filters)
        total = db.scalar(total_stmt) or 0

        unread_filters = [
            NotificationRecord.organization_id == organization_id,
            NotificationRecord.read_at.is_(None),
        ]
        if user_id:
            unread_filters.append(
                (NotificationRecord.user_id == user_id) | (NotificationRecord.user_id.is_(None))
            )
        unread_count = db.scalar(select(func.count(NotificationRecord.id)).where(*unread_filters)) or 0

        query = (
            select(NotificationRecord)
            .where(*filters)
            .order_by(desc(NotificationRecord.created_at))
            .limit(limit)
            .offset(offset)
        )
        records = db.execute(query).scalars().all()

        items = [
            NotificationResponse(
                id=n.id,
                organization_id=n.organization_id,
                user_id=n.user_id,
                event_type=n.event_type,
                severity=n.severity,
                title=n.title,
                message=n.message,
                link_url=n.link_url,
                read_at=n.read_at,
                metadata_json=n.metadata_json or {},
                created_at=n.created_at,
            )
            for n in records
        ]

        return NotificationPageResponse(
            items=items,
            total=total,
            unread_count=unread_count,
            limit=limit,
            offset=offset,
        )

    def mark_as_read(
        self,
        db: Session,
        organization_id: str,
        notification_id: str | None = None,
        mark_all: bool = False,
        user_id: str | None = None,
    ) -> int:
        """Marca notificações como lidas."""
        now = datetime.now(UTC)
        if mark_all:
            stmt = update(NotificationRecord).where(
                NotificationRecord.organization_id == organization_id,
                NotificationRecord.read_at.is_(None),
            )
            if user_id:
                stmt = stmt.where(
                    (NotificationRecord.user_id == user_id) | (NotificationRecord.user_id.is_(None))
                )
            result = db.execute(stmt.values(read_at=now))
            db.commit()
            return result.rowcount or 0

        if not notification_id:
            return 0

        notification = db.get(NotificationRecord, notification_id)
        if not notification or notification.organization_id != organization_id:
            return 0

        notification.read_at = now
        db.commit()
        return 1

    def get_preferences(
        self,
        db: Session,
        organization_id: str,
        user_id: str,
    ) -> NotificationPreferenceResponse:
        """Retorna ou inicializa as preferências de notificação do usuário."""
        pref = (
            db.execute(
                select(NotificationPreferenceRecord).where(
                    NotificationPreferenceRecord.organization_id == organization_id,
                    NotificationPreferenceRecord.user_id == user_id,
                )
            )
            .scalars()
            .first()
        )

        if not pref:
            pref = NotificationPreferenceRecord(
                organization_id=organization_id,
                user_id=user_id,
                email_enabled=False,
                email_destination=None,
                channels=["IN_APP"],
                min_severity="MEDIUM",
                subscribed_events=[
                    "scan.completed",
                    "scan.failed",
                    "finding.created",
                    "finding.reopened",
                    "schedule.failed_auth",
                ],
            )
            db.add(pref)
            db.commit()
            db.refresh(pref)

        return NotificationPreferenceResponse(
            id=pref.id,
            organization_id=pref.organization_id,
            user_id=pref.user_id,
            email_enabled=pref.email_enabled,
            email_destination=pref.email_destination,
            channels=pref.channels or ["IN_APP"],
            min_severity=pref.min_severity,
            subscribed_events=pref.subscribed_events or [],
            updated_at=pref.updated_at,
        )

    def update_preferences(
        self,
        db: Session,
        organization_id: str,
        user_id: str,
        req: NotificationPreferenceUpdateRequest,
    ) -> NotificationPreferenceResponse:
        """Atualiza preferências de notificação do usuário."""
        # Garante existência
        _ = self.get_preferences(db, organization_id, user_id)

        pref = (
            db.execute(
                select(NotificationPreferenceRecord).where(
                    NotificationPreferenceRecord.organization_id == organization_id,
                    NotificationPreferenceRecord.user_id == user_id,
                )
            )
            .scalars()
            .one()
        )

        if req.email_enabled is not None:
            pref.email_enabled = req.email_enabled
        if req.email_destination is not None:
            pref.email_destination = req.email_destination
        if req.channels is not None:
            pref.channels = req.channels
        if req.min_severity is not None:
            pref.min_severity = req.min_severity.upper()
        if req.subscribed_events is not None:
            pref.subscribed_events = req.subscribed_events

        pref.updated_at = datetime.now(UTC)
        db.commit()
        db.refresh(pref)

        return NotificationPreferenceResponse(
            id=pref.id,
            organization_id=pref.organization_id,
            user_id=pref.user_id,
            email_enabled=pref.email_enabled,
            email_destination=pref.email_destination,
            channels=pref.channels,
            min_severity=pref.min_severity,
            subscribed_events=pref.subscribed_events,
            updated_at=pref.updated_at,
        )
