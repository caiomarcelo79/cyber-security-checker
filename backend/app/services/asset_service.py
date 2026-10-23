"""Serviço de gestão de Ativos (Assets) e Comprovação de Autorização (TargetAuthorization - Fase 2)."""

from __future__ import annotations

import socket
import struct
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from urllib.parse import urlparse

import httpx
from fastapi import HTTPException, status
from security_engine.policies.scope_validator import (
    CLOUD_METADATA_HOSTS,
    CLOUD_METADATA_IPS,
    ScopePolicyValidator,
    ScopeViolationError,
)
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.security import generate_target_verification_token
from app.models.entities import Asset, TargetAuthorization
from app.schemas.auth_assets import (
    AssetCreateRequest,
    AssetResponse,
    AssetUpdateRequest,
    AuthorizationInitiateRequest,
    TargetAuthorizationResponse,
)
from app.services.audit_service import AuditLogService

DnsTxtResolverCallable = Callable[[str], list[str]]


def query_dns_txt_records_udp(
    qname: str, nameserver: str = "127.0.0.53", timeout: float = 2.5
) -> list[str]:
    """Consulta registros DNS TXT via pacote DNS padrão (RFC 1035) sem dependências binárias externas."""
    tx_id = 0x4353
    flags = 0x0100  # Standard query, recursion desired
    header = struct.pack("!HHHHHH", tx_id, flags, 1, 0, 0, 0)
    qname_bytes = (
        b"".join(
            bytes([len(label)]) + label.encode("ascii") for label in qname.strip(".").split(".") if label
        )
        + b"\x00"
    )
    question = qname_bytes + struct.pack("!HH", 16, 1)  # QTYPE=16 (TXT), QCLASS=1 (IN)
    packet = header + question

    records: list[str] = []
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, (nameserver, 53))
            data, _ = sock.recvfrom(2048)

        if len(data) < 12:
            return []
        _, _, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])
        offset = 12

        for _ in range(qdcount):
            while offset < len(data) and data[offset] != 0:
                if (data[offset] & 0xC0) == 0xC0:
                    offset += 2
                    break
                offset += 1 + data[offset]
            else:
                offset += 1
            offset += 4

        for _ in range(ancount):
            if offset >= len(data):
                break
            if (data[offset] & 0xC0) == 0xC0:
                offset += 2
            else:
                while offset < len(data) and data[offset] != 0:
                    offset += 1 + data[offset]
                offset += 1
            if offset + 10 > len(data):
                break
            rtype, _, _, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
            offset += 10
            rdata = data[offset : offset + rdlength]
            offset += rdlength
            if rtype == 16 and len(rdata) > 0:
                pos = 0
                txt_parts: list[str] = []
                while pos < len(rdata):
                    slen = rdata[pos]
                    pos += 1
                    txt_parts.append(rdata[pos : pos + slen].decode("utf-8", errors="ignore"))
                    pos += slen
                records.append("".join(txt_parts))
    except OSError:
        return []
    return records


class AssetAuthorizationService:
    """Gerencia ativos por organização e valida comprovantes técnicos de autorização de escopo."""

    @staticmethod
    def _extract_and_validate_target(target_url: str) -> tuple[str, str]:
        parsed = urlparse(target_url.strip())
        if parsed.scheme.lower() not in {"http", "https"}:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="A URL do ativo deve utilizar o esquema http:// ou https://.",
            )
        if not parsed.hostname:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="A URL informada não possui um hostname válido.",
            )
        if parsed.username or parsed.password:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Credenciais embutidas na URL são proibidas por segurança.",
            )

        hostname = parsed.hostname.lower()
        if hostname in CLOUD_METADATA_HOSTS or hostname in CLOUD_METADATA_IPS:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Bloqueio crítico Anti-SSRF: host de metadados proibido ({hostname}).",
            )

        path = parsed.path or "/"
        normalized_url = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{path}"
        return normalized_url, hostname

    @staticmethod
    def _to_asset_response(asset: Asset) -> AssetResponse:
        return AssetResponse(
            id=asset.id,
            organization_id=asset.organization_id,
            name=asset.name,
            target_url=asset.target_url,
            hostname=asset.hostname,
            asset_type=asset.asset_type,
            environment=asset.environment,
            owner_name=asset.owner_name,
            owner_email=asset.owner_email,
            tags=list(asset.tags or []),
            excluded_paths=list(asset.excluded_paths or []),
            risk_score=asset.risk_score,
            authorization_status=asset.authorization_status,
            created_at=asset.created_at,
            updated_at=asset.updated_at,
        )

    @staticmethod
    def _build_authorization_instructions(asset: Asset, method: str, token: str) -> dict[str, str]:
        parsed = urlparse(asset.target_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if method == "DNS_TXT":
            return {
                "record_type": "TXT",
                "record_host": f"_cybersecuritychecker.{asset.hostname}",
                "record_value": token,
                "summary": (
                    f"Publique um registro DNS TXT em '_cybersecuritychecker.{asset.hostname}' "
                    f"(ou na raiz '{asset.hostname}') contendo exatamente o valor '{token}'."
                ),
            }
        if method == "HTTP_WELL_KNOWN":
            well_known_url = f"{origin}/.well-known/cyber-security-checker.txt"
            return {
                "http_method": "GET",
                "well_known_url": well_known_url,
                "expected_content": token,
                "summary": (
                    f"Disponibilize um arquivo de texto em '{well_known_url}' "
                    f"respondendo HTTP 200 com o conteúdo '{token}'."
                ),
            }
        return {
            "lab_environment": asset.environment,
            "hostname": asset.hostname,
            "expected_token": token,
            "summary": (
                f"Autorização de laboratório local controlado para '{asset.hostname}' "
                "restrita a ambientes LAB/DEVELOPMENT e hosts permitidos na política."
            ),
        }

    @classmethod
    def _to_authorization_response(
        cls,
        auth: TargetAuthorization,
        asset: Asset,
    ) -> TargetAuthorizationResponse:
        return TargetAuthorizationResponse(
            id=auth.id,
            asset_id=auth.asset_id,
            organization_id=auth.organization_id,
            method=auth.method,
            verification_token=auth.verification_token,
            status=auth.status,
            verified_by_user_id=auth.verified_by_user_id,
            scope_notes=auth.scope_notes,
            instructions=cls._build_authorization_instructions(
                asset=asset,
                method=auth.method,
                token=auth.verification_token,
            ),
            verified_at=auth.verified_at,
            expires_at=auth.expires_at,
            created_at=auth.created_at,
        )

    @classmethod
    def create_asset(
        cls,
        db: Session,
        organization_id: str,
        user_id: str,
        payload: AssetCreateRequest,
        ip_address: str | None = None,
    ) -> AssetResponse:
        normalized_url, hostname = cls._extract_and_validate_target(payload.target_url)

        clean_exclusions: list[str] = []
        for path in payload.excluded_paths:
            p = path.strip()
            if p:
                clean_exclusions.append(p if p.startswith("/") else f"/{p}")

        asset = Asset(
            organization_id=organization_id,
            name=payload.name.strip(),
            target_url=normalized_url,
            hostname=hostname,
            asset_type=payload.asset_type,
            environment=payload.environment,
            owner_name=payload.owner_name.strip(),
            owner_email=payload.owner_email.strip().lower(),
            tags=[t.strip() for t in payload.tags if t.strip()],
            excluded_paths=clean_exclusions or ["/logout", "/delete"],
            risk_score=0,
            authorization_status="PENDING",
        )
        db.add(asset)
        db.flush()

        AuditLogService.record(
            db=db,
            action="ASSET_CREATED",
            resource_type="asset",
            resource_id=asset.id,
            organization_id=organization_id,
            user_id=user_id,
            ip_address=ip_address,
            metadata={
                "name": asset.name,
                "target_url": asset.target_url,
                "hostname": asset.hostname,
                "environment": asset.environment,
            },
        )
        db.commit()
        db.refresh(asset)
        return cls._to_asset_response(asset)

    @classmethod
    def list_assets(cls, db: Session, organization_id: str) -> list[AssetResponse]:
        stmt = (
            select(Asset)
            .where(Asset.organization_id == organization_id)
            .order_by(desc(Asset.created_at))
        )
        rows = db.scalars(stmt).all()
        return [cls._to_asset_response(row) for row in rows]

    @staticmethod
    def get_asset_or_404(db: Session, organization_id: str, asset_id: str) -> Asset:
        asset = db.scalar(
            select(Asset).where(Asset.id == asset_id, Asset.organization_id == organization_id)
        )
        if asset is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Ativo não encontrado na organização ativa.",
            )
        return asset

    @classmethod
    def update_asset(
        cls,
        db: Session,
        organization_id: str,
        user_id: str,
        asset_id: str,
        payload: AssetUpdateRequest,
        ip_address: str | None = None,
    ) -> AssetResponse:
        asset = cls.get_asset_or_404(db, organization_id, asset_id)
        if payload.name is not None:
            asset.name = payload.name.strip()
        if payload.environment is not None:
            asset.environment = payload.environment
        if payload.owner_name is not None:
            asset.owner_name = payload.owner_name.strip()
        if payload.owner_email is not None:
            asset.owner_email = payload.owner_email.strip().lower()
        if payload.tags is not None:
            asset.tags = [t.strip() for t in payload.tags if t.strip()]
        if payload.excluded_paths is not None:
            asset.excluded_paths = [
                p.strip() if p.strip().startswith("/") else f"/{p.strip()}"
                for p in payload.excluded_paths
                if p.strip()
            ]

        AuditLogService.record(
            db=db,
            action="ASSET_UPDATED",
            resource_type="asset",
            resource_id=asset.id,
            organization_id=organization_id,
            user_id=user_id,
            ip_address=ip_address,
            metadata={"name": asset.name, "environment": asset.environment},
        )
        db.commit()
        db.refresh(asset)
        return cls._to_asset_response(asset)

    @classmethod
    def delete_asset(
        cls,
        db: Session,
        organization_id: str,
        user_id: str,
        asset_id: str,
        ip_address: str | None = None,
    ) -> None:
        asset = cls.get_asset_or_404(db, organization_id, asset_id)
        hostname = asset.hostname
        db.delete(asset)
        AuditLogService.record(
            db=db,
            action="ASSET_DELETED",
            resource_type="asset",
            resource_id=asset_id,
            organization_id=organization_id,
            user_id=user_id,
            ip_address=ip_address,
            metadata={"hostname": hostname},
        )
        db.commit()

    @classmethod
    def initiate_authorization(
        cls,
        db: Session,
        organization_id: str,
        user_id: str,
        asset_id: str,
        payload: AuthorizationInitiateRequest,
        ip_address: str | None = None,
    ) -> TargetAuthorizationResponse:
        asset = cls.get_asset_or_404(db, organization_id, asset_id)
        token = generate_target_verification_token(
            organization_id=organization_id,
            asset_id=asset.id,
            hostname=asset.hostname,
        )
        expires_at = datetime.now(UTC) + timedelta(days=payload.expires_in_days)

        auth = TargetAuthorization(
            asset_id=asset.id,
            organization_id=organization_id,
            method=payload.method,
            verification_token=token,
            status="PENDING",
            scope_notes=payload.scope_notes,
            expires_at=expires_at,
        )
        db.add(auth)
        db.flush()

        AuditLogService.record(
            db=db,
            action="AUTH_CHALLENGE_CREATED",
            resource_type="target_authorization",
            resource_id=auth.id,
            organization_id=organization_id,
            user_id=user_id,
            ip_address=ip_address,
            metadata={
                "asset_id": asset.id,
                "hostname": asset.hostname,
                "method": auth.method,
            },
        )
        db.commit()
        db.refresh(auth)
        return cls._to_authorization_response(auth, asset)

    @classmethod
    def list_authorizations(
        cls,
        db: Session,
        organization_id: str,
        asset_id: str,
    ) -> list[TargetAuthorizationResponse]:
        asset = cls.get_asset_or_404(db, organization_id, asset_id)
        stmt = (
            select(TargetAuthorization)
            .where(
                TargetAuthorization.asset_id == asset.id,
                TargetAuthorization.organization_id == organization_id,
            )
            .order_by(desc(TargetAuthorization.created_at))
        )
        rows = db.scalars(stmt).all()
        return [cls._to_authorization_response(row, asset) for row in rows]

    @classmethod
    def verify_authorization(
        cls,
        db: Session,
        organization_id: str,
        user_id: str,
        asset_id: str,
        authorization_id: str,
        ip_address: str | None = None,
        dns_txt_resolver: DnsTxtResolverCallable | None = None,
        http_transport: httpx.BaseTransport | None = None,
    ) -> TargetAuthorizationResponse:
        settings = get_settings()
        asset = cls.get_asset_or_404(db, organization_id, asset_id)
        auth = db.scalar(
            select(TargetAuthorization).where(
                TargetAuthorization.id == authorization_id,
                TargetAuthorization.asset_id == asset.id,
                TargetAuthorization.organization_id == organization_id,
            )
        )
        if auth is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Desafio de autorização não encontrado para este ativo.",
            )

        if auth.status == "REVOKED":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Esta autorização foi revogada. Inicie um novo desafio.",
            )

        now = datetime.now(UTC)
        if auth.expires_at and auth.expires_at.replace(tzinfo=UTC) < now:
            auth.status = "EXPIRED"
            asset.authorization_status = "EXPIRED"
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="O prazo deste desafio de autorização expirou.",
            )

        verified_ok = False
        failure_reason = ""

        if auth.method == "DNS_TXT":
            resolver = dns_txt_resolver or query_dns_txt_records_udp
            candidate_hosts = [
                f"_cybersecuritychecker.{asset.hostname}",
                asset.hostname,
            ]
            collected_txt: list[str] = []
            for qhost in candidate_hosts:
                collected_txt.extend(resolver(qhost))

            if any(auth.verification_token in txt for txt in collected_txt):
                verified_ok = True
            else:
                failure_reason = (
                    f"Token '{auth.verification_token}' não encontrado nos registros DNS TXT de "
                    f"'_cybersecuritychecker.{asset.hostname}' ou '{asset.hostname}'."
                )

        elif auth.method == "HTTP_WELL_KNOWN":
            parsed = urlparse(asset.target_url)
            well_known_url = f"{parsed.scheme}://{parsed.netloc}/.well-known/cyber-security-checker.txt"
            validator = ScopePolicyValidator(
                authorized_hosts=[asset.hostname],
                allow_subdomains=False,
                block_private_networks=settings.block_private_networks,
                allow_local_lab_targets=settings.allow_local_lab_targets,
                lab_allowed_hosts=settings.parsed_lab_allowed_hosts,
            )
            try:
                validator.validate_url(well_known_url, resolve_dns=False)
                with httpx.Client(
                    transport=http_transport,
                    follow_redirects=False,
                    timeout=5.0,
                ) as http_client:
                    resp = http_client.get(well_known_url)
                    if resp.status_code == 200 and auth.verification_token in resp.text:
                        verified_ok = True
                    else:
                        failure_reason = (
                            f"Endpoint '{well_known_url}' respondeu HTTP {resp.status_code} "
                            "sem conter o token de verificação esperado."
                        )
            except (ScopeViolationError, httpx.HTTPError) as exc:
                failure_reason = f"Falha ao validar arquivo HTTP Well-Known: {exc}"

        elif auth.method == "LAB_INTERNAL":
            allowed_lab_hosts = set(settings.parsed_lab_allowed_hosts)
            is_lab_domain = (
                asset.hostname in allowed_lab_hosts
                or asset.hostname.endswith(".local")
                or asset.hostname.endswith(".internal")
                or asset.hostname.endswith(".lab")
            )
            if (
                settings.allow_local_lab_targets
                and asset.environment in {"LAB", "DEVELOPMENT"}
                and is_lab_domain
            ):
                verified_ok = True
            else:
                failure_reason = (
                    "O método LAB_INTERNAL é exclusivo para ativos com ambiente LAB/DEVELOPMENT "
                    "e hostnames pertencentes ao laboratório local isolado (.local, .internal, .lab ou whitelist)."
                )
        else:
            failure_reason = f"Método de autorização desconhecido: {auth.method}"

        if not verified_ok:
            AuditLogService.record(
                db=db,
                action="AUTH_CHALLENGE_FAILED",
                resource_type="target_authorization",
                resource_id=auth.id,
                organization_id=organization_id,
                user_id=user_id,
                ip_address=ip_address,
                metadata={
                    "asset_id": asset.id,
                    "hostname": asset.hostname,
                    "method": auth.method,
                    "reason": failure_reason,
                },
                commit=True,
            )
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=failure_reason,
            )

        auth.status = "VERIFIED"
        auth.verified_at = now
        auth.verified_by_user_id = user_id
        asset.authorization_status = "VERIFIED"

        AuditLogService.record(
            db=db,
            action="AUTH_CHALLENGE_VERIFIED",
            resource_type="target_authorization",
            resource_id=auth.id,
            organization_id=organization_id,
            user_id=user_id,
            ip_address=ip_address,
            metadata={
                "asset_id": asset.id,
                "hostname": asset.hostname,
                "method": auth.method,
            },
        )
        db.commit()
        db.refresh(auth)
        db.refresh(asset)
        return cls._to_authorization_response(auth, asset)

    @classmethod
    def revoke_authorization(
        cls,
        db: Session,
        organization_id: str,
        user_id: str,
        asset_id: str,
        authorization_id: str,
        ip_address: str | None = None,
    ) -> TargetAuthorizationResponse:
        asset = cls.get_asset_or_404(db, organization_id, asset_id)
        auth = db.scalar(
            select(TargetAuthorization).where(
                TargetAuthorization.id == authorization_id,
                TargetAuthorization.asset_id == asset.id,
                TargetAuthorization.organization_id == organization_id,
            )
        )
        if auth is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Registro de autorização não encontrado.",
            )

        auth.status = "REVOKED"
        other_verified = db.scalar(
            select(TargetAuthorization).where(
                TargetAuthorization.asset_id == asset.id,
                TargetAuthorization.organization_id == organization_id,
                TargetAuthorization.status == "VERIFIED",
                TargetAuthorization.id != auth.id,
            )
        )
        if other_verified is None:
            asset.authorization_status = "REVOKED"

        AuditLogService.record(
            db=db,
            action="AUTH_REVOKED",
            resource_type="target_authorization",
            resource_id=auth.id,
            organization_id=organization_id,
            user_id=user_id,
            ip_address=ip_address,
            metadata={"asset_id": asset.id, "hostname": asset.hostname},
        )
        db.commit()
        db.refresh(auth)
        return cls._to_authorization_response(auth, asset)
