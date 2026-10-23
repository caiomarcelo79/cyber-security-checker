"""Serviço de gerenciamento de Webhooks, despacho seguro e assinaturas HMAC (Fase 7).

Inclui validação anti-SSRF de URLs receptoras, assinatura criptográfica HMAC-SHA256,
registro de entregas e retentativas com backoff exponencial.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import socket
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlparse

import httpx
from security_engine.policies.scope_validator import (
    CLOUD_METADATA_HOSTS,
    CLOUD_METADATA_IPS,
    ScopePolicyValidator,
)
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.entities import WebhookDeliveryRecord, WebhookEndpointRecord
from app.schemas.automations import (
    WebhookDeliveryPageResponse,
    WebhookDeliveryResponse,
    WebhookEndpointCreateRequest,
    WebhookEndpointResponse,
    WebhookEndpointSecretRotateResponse,
    WebhookEndpointUpdateRequest,
    WebhookTestResponse,
)

logger = logging.getLogger("cyber_security_checker.webhook_service")


class WebhookValidationError(ValueError):
    """Exceção levantada quando uma URL de webhook viola regras de segurança."""


class WebhookService:
    """Gerencia endpoints e entregas de webhooks."""

    def __init__(self) -> None:
        self.settings = get_settings()

    def _validate_webhook_url(self, url: str) -> str:
        """Valida que a URL é válida, utiliza HTTPS e previne SSRF contra redes privadas."""
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.hostname:
            raise WebhookValidationError("URL do webhook inválida. Forneça uma URL absoluta completa.")

        host = parsed.hostname.lower()

        # Metadados de nuvem bloqueados incondicionalmente
        if host in CLOUD_METADATA_HOSTS:
            raise WebhookValidationError("Host de metadados de nuvem proibido para webhooks.")

        is_lab_allowed = (
            self.settings.allow_local_lab_targets and host in self.settings.parsed_lab_allowed_hosts
        )

        # HTTPS obrigatório, exceto em hosts de laboratório autorizados
        if parsed.scheme.lower() != "https" and not is_lab_allowed:
            raise WebhookValidationError("URLs de webhook devem utilizar o protocolo seguro HTTPS.")

        # Resolução DNS e validação anti-SSRF dos endereços IP
        try:
            addr_info = socket.getaddrinfo(
                host, parsed.port or (443 if parsed.scheme == "https" else 80)
            )
            resolved_ips = {item[4][0] for item in addr_info}
        except socket.gaierror as exc:
            if is_lab_allowed:
                resolved_ips = {"127.0.0.1"}
            else:
                raise WebhookValidationError(
                    f"Não foi possível resolver o hostname '{host}': {exc}"
                ) from exc

        for ip in resolved_ips:
            if ip in CLOUD_METADATA_IPS:
                raise WebhookValidationError("Endereço IP de metadados de nuvem proibido para webhooks.")

            if (
                self.settings.block_private_networks
                and ScopePolicyValidator.is_private_or_reserved_ip(ip)
                and not is_lab_allowed
            ):
                raise WebhookValidationError(
                    f"Endereço IP de rede privada/interna ({ip}) não autorizado para destino de webhook."
                )

        return url

    def create_endpoint(
        self,
        db: Session,
        organization_id: str,
        user_id: str,
        req: WebhookEndpointCreateRequest,
    ) -> WebhookEndpointResponse:
        """Cria e cadastra um novo endpoint de webhook com segredo HMAC seguro."""
        clean_url = self._validate_webhook_url(req.url)
        secret_token = f"whsec_{secrets.token_hex(28)}"

        endpoint = WebhookEndpointRecord(
            organization_id=organization_id,
            url=clean_url,
            description=req.description,
            secret_token=secret_token,
            subscribed_events=req.subscribed_events,
            is_active=True,
            consecutive_failures=0,
            created_by_user_id=user_id,
        )
        db.add(endpoint)
        db.commit()
        db.refresh(endpoint)

        logger.info(
            "Webhook criado: id=%s org=%s url=%s eventos=%s",
            endpoint.id,
            organization_id,
            clean_url,
            req.subscribed_events,
        )

        return self._to_response(endpoint)

    def list_endpoints(
        self,
        db: Session,
        organization_id: str,
    ) -> list[WebhookEndpointResponse]:
        """Lista todos os endpoints de webhook da organização."""
        query = (
            select(WebhookEndpointRecord)
            .where(WebhookEndpointRecord.organization_id == organization_id)
            .order_by(desc(WebhookEndpointRecord.created_at))
        )
        endpoints = db.execute(query).scalars().all()
        return [self._to_response(ep) for ep in endpoints]

    def get_endpoint(
        self,
        db: Session,
        organization_id: str,
        webhook_id: str,
    ) -> WebhookEndpointResponse | None:
        """Busca um endpoint específico por ID."""
        ep = db.get(WebhookEndpointRecord, webhook_id)
        if not ep or ep.organization_id != organization_id:
            return None
        return self._to_response(ep)

    def update_endpoint(
        self,
        db: Session,
        organization_id: str,
        webhook_id: str,
        req: WebhookEndpointUpdateRequest,
    ) -> WebhookEndpointResponse | None:
        """Atualiza configuração de um webhook."""
        ep = db.get(WebhookEndpointRecord, webhook_id)
        if not ep or ep.organization_id != organization_id:
            return None

        if req.url is not None:
            ep.url = self._validate_webhook_url(req.url)
        if req.description is not None:
            ep.description = req.description
        if req.subscribed_events is not None:
            ep.subscribed_events = req.subscribed_events
        if req.is_active is not None:
            ep.is_active = req.is_active
            if req.is_active:
                ep.consecutive_failures = 0

        ep.updated_at = datetime.now(UTC)
        db.commit()
        db.refresh(ep)
        return self._to_response(ep)

    def delete_endpoint(
        self,
        db: Session,
        organization_id: str,
        webhook_id: str,
    ) -> bool:
        """Remove um endpoint de webhook."""
        ep = db.get(WebhookEndpointRecord, webhook_id)
        if not ep or ep.organization_id != organization_id:
            return False

        db.delete(ep)
        db.commit()
        return True

    def rotate_secret(
        self,
        db: Session,
        organization_id: str,
        webhook_id: str,
    ) -> WebhookEndpointSecretRotateResponse | None:
        """Rotaciona o segredo HMAC e o retorna uma única vez."""
        ep = db.get(WebhookEndpointRecord, webhook_id)
        if not ep or ep.organization_id != organization_id:
            return None

        new_secret = f"whsec_{secrets.token_hex(28)}"
        ep.secret_token = new_secret
        ep.updated_at = datetime.now(UTC)
        db.commit()

        return WebhookEndpointSecretRotateResponse(
            id=ep.id,
            new_secret_token=new_secret,
            message="Novo segredo HMAC gerado com sucesso. Atualize seu receptor imediatamente.",
        )

    def dispatch_event_to_webhooks(
        self,
        db: Session,
        organization_id: str,
        event_type: str,
        payload: dict[str, Any],
    ) -> list[str]:
        """Localiza endpoints ativos inscritos no evento e despacha a entrega."""
        query = select(WebhookEndpointRecord).where(
            WebhookEndpointRecord.organization_id == organization_id,
            WebhookEndpointRecord.is_active.is_(True),
        )
        endpoints = db.execute(query).scalars().all()
        delivery_ids: list[str] = []

        for ep in endpoints:
            # Verifica se está inscrito
            if (
                ep.subscribed_events
                and event_type not in ep.subscribed_events
                and "*" not in ep.subscribed_events
            ):
                continue

            delivery_id = self.deliver_payload(
                db=db,
                endpoint=ep,
                event_type=event_type,
                payload=payload,
            )
            delivery_ids.append(delivery_id)

        return delivery_ids

    def deliver_payload(
        self,
        db: Session,
        endpoint: WebhookEndpointRecord,
        event_type: str,
        payload: dict[str, Any],
    ) -> str:
        """Executa a entrega HTTP do webhook, computando assinatura HMAC-SHA256 e gravando auditoria."""
        event_id = str(uuid.uuid4())
        timestamp_sec = int(time.time())

        # Formata corpo canônico JSON
        canonical_body = json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
        signature_base = f"{timestamp_sec}.{canonical_body}"
        signature_hash = hmac.new(
            endpoint.secret_token.encode("utf-8"),
            signature_base.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "CyberSecurityChecker-Webhook/1.0",
            "X-CSC-Event": event_type,
            "X-CSC-Delivery": str(uuid.uuid4()),
            "X-CSC-Timestamp": str(timestamp_sec),
            "X-CSC-Signature": f"sha256={signature_hash}",
        }

        # Cria registro de entrega
        delivery = WebhookDeliveryRecord(
            webhook_id=endpoint.id,
            organization_id=endpoint.organization_id,
            event_type=event_type,
            event_id=event_id,
            payload=payload,
            status="PENDING",
            attempt_count=1,
            created_at=datetime.now(UTC),
        )
        db.add(delivery)
        db.commit()
        db.refresh(delivery)

        # Envia requisição HTTP
        start_time = time.perf_counter()
        try:
            with httpx.Client(timeout=self.settings.webhook_delivery_timeout_sec) as client:
                resp = client.post(
                    endpoint.url,
                    content=canonical_body.encode("utf-8"),
                    headers=headers,
                )
            duration_ms = int((time.perf_counter() - start_time) * 1000)

            delivery.duration_ms = duration_ms
            delivery.status_code = resp.status_code
            delivery.response_body = resp.text[:1000] if resp.text else ""

            if 200 <= resp.status_code < 300:
                delivery.status = "DELIVERED"
                endpoint.consecutive_failures = 0
            else:
                delivery.status = "FAILED"
                delivery.error_message = f"Resposta HTTP inválida ({resp.status_code})"
                self._handle_delivery_failure(endpoint, delivery)

        except Exception as exc:  # noqa: BLE001
            duration_ms = int((time.perf_counter() - start_time) * 1000)
            delivery.duration_ms = duration_ms
            delivery.status = "FAILED"
            delivery.error_message = f"Erro na conexão de rede: {exc}"
            self._handle_delivery_failure(endpoint, delivery)

        db.commit()
        return delivery.id

    def _handle_delivery_failure(
        self,
        endpoint: WebhookEndpointRecord,
        delivery: WebhookDeliveryRecord,
    ) -> None:
        """Incrementa falhas consecutivas e calcula próxima retentativa com backoff exponencial."""
        endpoint.consecutive_failures += 1
        max_retries = self.settings.webhook_max_retries

        if delivery.attempt_count < max_retries:
            # Backoff exponencial: 2^(attempt) * 15 segundos
            delay_sec = (2**delivery.attempt_count) * 15
            delivery.next_retry_at = datetime.now(UTC) + timedelta(seconds=delay_sec)
        else:
            delivery.next_retry_at = None

        # Desativação de segurança após 10 falhas consecutivas
        if endpoint.consecutive_failures >= 10:
            endpoint.is_active = False
            logger.warning(
                "Webhook endpoint %s auto-desativado após 10 falhas consecutivas.",
                endpoint.id,
            )

    def test_webhook(
        self,
        db: Session,
        organization_id: str,
        webhook_id: str,
    ) -> WebhookTestResponse:
        """Dispara um evento de teste imediato para validar conectividade e assinatura."""
        ep = db.get(WebhookEndpointRecord, webhook_id)
        if not ep or ep.organization_id != organization_id:
            return WebhookTestResponse(
                status="ERROR",
                message="Endpoint de webhook não encontrado.",
            )

        test_payload = {
            "test": True,
            "message": "Teste de conectividade do Cyber Security Checker.",
            "timestamp": datetime.now(UTC).isoformat(),
        }

        delivery_id = self.deliver_payload(
            db=db,
            endpoint=ep,
            event_type="webhook.test",
            payload=test_payload,
        )

        delivery = db.get(WebhookDeliveryRecord, delivery_id)
        if not delivery:
            return WebhookTestResponse(status="ERROR", message="Falha ao rastrear entrega de teste.")

        return WebhookTestResponse(
            status=delivery.status,
            status_code=delivery.status_code,
            response_summary=delivery.response_body[:200]
            if delivery.response_body
            else delivery.error_message,
            duration_ms=delivery.duration_ms,
            message="Entrega de teste concluída com sucesso."
            if delivery.status == "DELIVERED"
            else f"Falha na entrega de teste: {delivery.error_message}",
        )

    def list_deliveries(
        self,
        db: Session,
        organization_id: str,
        webhook_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> WebhookDeliveryPageResponse:
        """Lista o histórico de entregas de webhook com paginação."""
        filters = [WebhookDeliveryRecord.organization_id == organization_id]
        if webhook_id:
            filters.append(WebhookDeliveryRecord.webhook_id == webhook_id)

        total = db.scalar(select(func.count(WebhookDeliveryRecord.id)).where(*filters)) or 0
        query = (
            select(WebhookDeliveryRecord)
            .where(*filters)
            .order_by(desc(WebhookDeliveryRecord.created_at))
            .limit(limit)
            .offset(offset)
        )
        records = db.execute(query).scalars().all()

        items = [
            WebhookDeliveryResponse(
                id=d.id,
                webhook_id=d.webhook_id,
                organization_id=d.organization_id,
                event_type=d.event_type,
                event_id=d.event_id,
                payload=d.payload or {},
                status=d.status,
                status_code=d.status_code,
                response_body=d.response_body,
                duration_ms=d.duration_ms,
                attempt_count=d.attempt_count,
                next_retry_at=d.next_retry_at,
                error_message=d.error_message,
                created_at=d.created_at,
            )
            for d in records
        ]

        return WebhookDeliveryPageResponse(
            items=items,
            total=total,
            limit=limit,
            offset=offset,
        )

    def _to_response(self, ep: WebhookEndpointRecord) -> WebhookEndpointResponse:
        prefix = ep.secret_token[:10] if ep.secret_token else "whsec_..."
        return WebhookEndpointResponse(
            id=ep.id,
            organization_id=ep.organization_id,
            url=ep.url,
            description=ep.description,
            secret_token_prefix=f"{prefix}***",
            subscribed_events=ep.subscribed_events or [],
            is_active=ep.is_active,
            consecutive_failures=ep.consecutive_failures,
            created_at=ep.created_at,
            updated_at=ep.updated_at,
        )
