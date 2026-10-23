"""Adaptador de entrega de emails para notificações da plataforma (Fase 7).

Suporta envio SMTP com TLS e modo desenvolvimento/teste local com captura em memória.
"""

from __future__ import annotations

import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, ClassVar

from app.core.config import get_settings

logger = logging.getLogger("cyber_security_checker.email_adapter")


class EmailDeliveryAdapter:
    """Adaptador para envio de alertas por correio eletrônico."""

    _dev_sent_buffer: ClassVar[list[dict[str, Any]]] = []

    def __init__(self) -> None:
        self.settings = get_settings()

    def send_alert(
        self,
        to_email: str,
        subject: str,
        body_text: str,
        body_html: str | None = None,
    ) -> bool:
        """Envia email para o destinatário especificado.

        Em ambiente de teste/desenvolvimento (com smtp_enabled=False), armazena
        no buffer em memória para inspeção e teste automatizado.
        """
        if not to_email or "@" not in to_email:
            logger.warning("Destinatário inválido para envio de email: %s", to_email)
            return False

        if not self.settings.smtp_enabled:
            logger.info(
                "[DEV MODE] Email simulado para %s: Assunto='%s'",
                to_email,
                subject,
            )
            EmailDeliveryAdapter._dev_sent_buffer.append(
                {
                    "to": to_email,
                    "subject": subject,
                    "body_text": body_text,
                    "body_html": body_html,
                    "from": self.settings.smtp_from,
                }
            )
            if len(EmailDeliveryAdapter._dev_sent_buffer) > 200:
                EmailDeliveryAdapter._dev_sent_buffer.pop(0)
            return True

        # Envio real via SMTP
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[CSC Security] {subject}"
            msg["From"] = self.settings.smtp_from
            msg["To"] = to_email

            part1 = MIMEText(body_text, "plain", "utf-8")
            msg.attach(part1)

            if body_html:
                part2 = MIMEText(body_html, "html", "utf-8")
                msg.attach(part2)

            with smtplib.SMTP(self.settings.smtp_host, self.settings.smtp_port, timeout=10) as server:
                if self.settings.smtp_use_tls:
                    server.starttls()
                if self.settings.smtp_user and self.settings.smtp_password:
                    server.login(self.settings.smtp_user, self.settings.smtp_password)
                server.sendmail(self.settings.smtp_from, [to_email], msg.as_string())

            logger.info("Email enviado com sucesso para %s", to_email)
            return True
        except Exception:
            logger.exception("Falha ao enviar email para %s via SMTP", to_email)
            return False

    @classmethod
    def get_sent_buffer(cls) -> list[dict[str, Any]]:
        """Retorna histórico de emails capturados em memória (modo dev/testes)."""
        return list(cls._dev_sent_buffer)

    @classmethod
    def clear_sent_buffer(cls) -> None:
        """Limpa histórico em memória."""
        cls._dev_sent_buffer.clear()
