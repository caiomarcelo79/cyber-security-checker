"""Serviço de templates de auditoria e formatadores de notificação para plataformas de chat (Fase 7).

Gerencia templates reutilizáveis de auditoria com parâmetros pré-configurados e
provê adaptadores para formatação de alertas em Slack, Discord e Microsoft Teams.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.models.entities import ScanTemplateRecord
from app.schemas.automations import (
    ScanTemplateCreateRequest,
    ScanTemplatePageResponse,
    ScanTemplateResponse,
    ScanTemplateUpdateRequest,
)

logger = logging.getLogger("cyber_security_checker.template_service")


class TemplateService:
    """Gerencia templates reutilizáveis de auditorias de segurança."""

    def create_template(
        self,
        db: Session,
        organization_id: str,
        user_id: str | None,
        req: ScanTemplateCreateRequest,
    ) -> ScanTemplateResponse:
        """Cria um novo template de auditoria."""
        template = ScanTemplateRecord(
            organization_id=organization_id,
            name=req.name.strip(),
            description=req.description,
            profile_type=req.profile_type,
            enabled_modules=req.enabled_modules,
            parameters=req.parameters,
            environment_type=req.environment_type,
            created_by_user_id=user_id,
            created_at=datetime.now(UTC),
        )
        db.add(template)
        db.commit()
        db.refresh(template)

        logger.info(
            "Template de auditoria criado: id=%s org=%s nome='%s'",
            template.id,
            organization_id,
            template.name,
        )
        return self._to_response(template)

    def list_templates(
        self,
        db: Session,
        organization_id: str,
        limit: int = 50,
        offset: int = 0,
    ) -> ScanTemplatePageResponse:
        """Lista templates da organização com paginação."""
        total = (
            db.scalar(
                select(func.count(ScanTemplateRecord.id)).where(
                    ScanTemplateRecord.organization_id == organization_id
                )
            )
            or 0
        )

        query = (
            select(ScanTemplateRecord)
            .where(ScanTemplateRecord.organization_id == organization_id)
            .order_by(desc(ScanTemplateRecord.created_at))
            .limit(limit)
            .offset(offset)
        )
        records = db.execute(query).scalars().all()

        items = [self._to_response(t) for t in records]
        return ScanTemplatePageResponse(
            items=items,
            total=total,
            limit=limit,
            offset=offset,
        )

    def get_template(
        self,
        db: Session,
        organization_id: str,
        template_id: str,
    ) -> ScanTemplateResponse | None:
        """Busca template por ID."""
        t = db.get(ScanTemplateRecord, template_id)
        if not t or t.organization_id != organization_id:
            return None
        return self._to_response(t)

    def update_template(
        self,
        db: Session,
        organization_id: str,
        template_id: str,
        req: ScanTemplateUpdateRequest,
    ) -> ScanTemplateResponse | None:
        """Atualiza campos de um template de auditoria."""
        t = db.get(ScanTemplateRecord, template_id)
        if not t or t.organization_id != organization_id:
            return None

        if req.name is not None:
            t.name = req.name.strip()
        if req.description is not None:
            t.description = req.description
        if req.profile_type is not None:
            t.profile_type = req.profile_type
        if req.enabled_modules is not None:
            t.enabled_modules = req.enabled_modules
        if req.parameters is not None:
            t.parameters = req.parameters
        if req.environment_type is not None:
            t.environment_type = req.environment_type

        t.updated_at = datetime.now(UTC)
        db.commit()
        db.refresh(t)
        return self._to_response(t)

    def delete_template(
        self,
        db: Session,
        organization_id: str,
        template_id: str,
    ) -> bool:
        """Remove um template de auditoria."""
        t = db.get(ScanTemplateRecord, template_id)
        if not t or t.organization_id != organization_id:
            return False

        db.delete(t)
        db.commit()
        return True

    def seed_defaults(
        self,
        db: Session,
        organization_id: str,
        user_id: str | None = None,
    ) -> list[ScanTemplateResponse]:
        """Cria templates padrões da indústria se a organização ainda não possuir nenhum."""
        existing_count = (
            db.scalar(
                select(func.count(ScanTemplateRecord.id)).where(
                    ScanTemplateRecord.organization_id == organization_id
                )
            )
            or 0
        )

        if existing_count > 0:
            return self.list_templates(db, organization_id).items

        defaults = [
            ScanTemplateCreateRequest(
                name="Auditoria Rápida de Perímetro",
                description="Verificação passiva e rápida de cabeçalhos HTTP, certificados SSL/TLS e exposição de portas.",
                profile_type="QUICK",
                enabled_modules=["security_headers", "ssl_tls", "dns_sec"],
                parameters={"follow_redirects": True, "max_depth": 1},
                environment_type="PRODUCTION",
            ),
            ScanTemplateCreateRequest(
                name="Auditoria OWASP Top 10 Web",
                description="Auditoria abrangente para vulnerabilidades comuns em aplicações web (injeções, CORS, CSRF, XSS e vazamentos).",
                profile_type="FULL",
                enabled_modules=[
                    "security_headers",
                    "ssl_tls",
                    "cors",
                    "csrf",
                    "sqli_detection",
                    "xss_detection",
                ],
                parameters={"follow_redirects": True, "max_depth": 3, "timeout_seconds": 15},
                environment_type="STAGING",
            ),
            ScanTemplateCreateRequest(
                name="Auditoria de Segurança de APIs REST",
                description="Verificação especializada para endpoints de API (autenticação, rate limiting, JWT e exposição de dados).",
                profile_type="API",
                enabled_modules=["api_security", "jwt_analyzer", "rate_limit_probe", "sensitive_files"],
                parameters={"treat_401_as_safe": True},
                environment_type="PRODUCTION",
            ),
        ]

        created: list[ScanTemplateResponse] = []
        for d in defaults:
            created.append(self.create_template(db, organization_id, user_id, d))

        return created

    def _to_response(self, t: ScanTemplateRecord) -> ScanTemplateResponse:
        return ScanTemplateResponse(
            id=t.id,
            organization_id=t.organization_id,
            name=t.name,
            description=t.description,
            profile_type=t.profile_type,
            enabled_modules=t.enabled_modules or [],
            parameters=t.parameters or {},
            environment_type=t.environment_type,
            created_by_user_id=t.created_by_user_id,
            created_at=t.created_at,
            updated_at=t.updated_at,
        )


# ============================================================================
# Adaptadores e Formatadores de Alertas para Canais de Chat Externos
# ============================================================================

SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "#E02424",  # Vermelho escuro
    "HIGH": "#FF5A1F",  # Laranja forte
    "MEDIUM": "#E3A008",  # Amarelo/âmbar
    "LOW": "#3F83F8",  # Azul
    "INFO": "#0E9F6E",  # Verde
}


def format_slack_message(
    event_type: str,
    severity: str,
    title: str,
    message: str,
    link_url: str | None = None,
) -> dict[str, Any]:
    """Formata payload em formato Block Kit e Attachments para Webhooks do Slack."""
    color = SEVERITY_COLORS.get(severity.upper(), "#3F83F8")
    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"🛡️ CSC Alerta: [{severity}] {title}"[:150],
                "emoji": True,
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Evento:* `{event_type}`\n*Detalhes:* {message}",
            },
        },
    ]

    if link_url:
        blocks.append(
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Visualizar na Plataforma"},
                        "url": link_url,
                        "style": "primary",
                    }
                ],
            }
        )

    return {
        "text": f"CSC Alerta: [{severity}] {title}",
        "attachments": [
            {
                "color": color,
                "blocks": blocks,
            }
        ],
    }


def format_discord_message(
    event_type: str,
    severity: str,
    title: str,
    message: str,
    link_url: str | None = None,
) -> dict[str, Any]:
    """Formata payload com Embed rich para Webhooks do Discord."""
    color_hex = SEVERITY_COLORS.get(severity.upper(), "#3F83F8").lstrip("#")
    color_int = int(color_hex, 16)

    embed: dict[str, Any] = {
        "title": f"🛡️ [{severity}] {title}"[:256],
        "description": message[:2048],
        "color": color_int,
        "fields": [
            {"name": "Tipo do Evento", "value": f"`{event_type}`", "inline": True},
            {"name": "Severidade", "value": f"**{severity}**", "inline": True},
        ],
        "timestamp": datetime.now(UTC).isoformat(),
        "footer": {"text": "Cyber Security Checker"},
    }

    if link_url:
        embed["url"] = link_url

    return {
        "username": "Cyber Security Checker",
        "embeds": [embed],
    }
