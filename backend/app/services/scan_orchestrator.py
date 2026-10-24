"""Orquestrador de Auditorias (ScanOrchestrator) com controle de escopo, fila, progresso e cancelamento (Fase 3)."""

from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime
from typing import Any

import redis
from fastapi import HTTPException, status
from security_engine.core.contracts import (
    AssetType,
    EnvironmentType,
    ModuleExecutionResult,
    NormalizedFinding,
    ScanProfileType,
)
from security_engine.core.registry import default_registry
from security_engine.core.risk import RiskEngine
from security_engine.core.runner import SecurityEngineRunner
from security_engine.policies.execution_policy import (
    SCAN_PROFILES_CATALOG,
    ScanExecutionPolicy,
)
from security_engine.policies.scope_validator import ScopePolicyValidator, ScopeViolationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.entities import (
    Asset,
    FindingRecord,
    Scan,
    ScanCheckResultRecord,
    TargetAuthorization,
    utcnow,
)
from app.schemas.scans import (
    FindingResponse,
    FindingTriageUpdateRequest,
    ScanCheckResultResponse,
    ScanCreateRequest,
    ScanDetailedResultsResponse,
    ScanProgressResponse,
    ScanResponse,
)
from app.services.audit_service import AuditLogService

logger = logging.getLogger(__name__)

ACTIVE_SCAN_STATUSES = {"PENDING", "QUEUED", "RUNNING"}
TERMINAL_SCAN_STATUSES = {
    "COMPLETED",
    "PARTIALLY_COMPLETED",
    "FAILED",
    "CANCELLED",
    "ABORTED_TARGET_DEGRADED",
}
VALID_TREATMENT_STATUSES = {
    "OPEN",
    "IN_ANALYSIS",
    "IN_PROGRESS",
    "WAITING_VALIDATION",
    "RESOLVED_VERIFIED",
    "FALSE_POSITIVE",
    "ACCEPTED_RISK",
    "REOPENED",
    "MITIGATED",  # Preservado para retrocompatibilidade
}
ACTIVE_FINDING_STATUSES = {
    "OPEN",
    "IN_ANALYSIS",
    "IN_PROGRESS",
    "WAITING_VALIDATION",
    "REOPENED",
}
MAX_ACTIVE_SCANS_PER_ORG = 5


class ScanOrchestrator:
    """Coordena o ciclo de vida completo de auditorias de segurança autorizadas."""

    @staticmethod
    def _set_redis_cancel_flag(scan_id: str) -> None:
        settings = get_settings()
        try:
            client = redis.Redis.from_url(settings.redis_url, socket_connect_timeout=1, socket_timeout=1)
            client.set(f"csc:scan:cancel:{scan_id}", "1", ex=3600)
        except (redis.RedisError, OSError, ValueError) as exc:
            logger.debug("Redis indisponível ao gravar flag de cancelamento (%s): %s", scan_id, exc)

    @staticmethod
    def _is_redis_cancel_flagged(scan_id: str) -> bool:
        settings = get_settings()
        try:
            client = redis.Redis.from_url(settings.redis_url, socket_connect_timeout=1, socket_timeout=1)
            return bool(client.get(f"csc:scan:cancel:{scan_id}"))
        except (redis.RedisError, OSError, ValueError):
            return False

    @staticmethod
    def _compute_elapsed_seconds(scan: Scan) -> float:
        if not scan.started_at:
            return 0.0
        start_dt = (
            scan.started_at
            if scan.started_at.tzinfo is not None
            else scan.started_at.replace(tzinfo=UTC)
        )
        end_dt = (
            (
                scan.completed_at
                if scan.completed_at.tzinfo is not None
                else scan.completed_at.replace(tzinfo=UTC)
            )
            if scan.completed_at
            else datetime.now(UTC)
        )
        return round(max(0.0, (end_dt - start_dt).total_seconds()), 2)

    @classmethod
    def _to_scan_response(cls, scan: Scan, asset: Asset | None = None) -> ScanResponse:
        target_asset = asset or scan.asset
        snapshot = scan.policy_snapshot or {}
        completed_mods = list(snapshot.get("completed_modules", []))
        failed_mods = list(snapshot.get("failed_modules", []))
        return ScanResponse(
            id=scan.id,
            organization_id=scan.organization_id,
            asset_id=scan.asset_id,
            asset_name=target_asset.name if target_asset else None,
            target_url=target_asset.target_url if target_asset else None,
            initiated_by_user_id=scan.initiated_by_user_id,
            profile_type=scan.profile_type,
            status=scan.status,
            progress_percent=scan.progress_percent,
            current_module=scan.current_module,
            enabled_modules=list(scan.enabled_modules or []),
            completed_modules=completed_mods,
            failed_modules=failed_mods,
            policy_snapshot=snapshot,
            total_checks_run=scan.total_checks_run,
            findings_summary=dict(scan.findings_summary or {}),
            elapsed_seconds=cls._compute_elapsed_seconds(scan),
            error_message=scan.error_message,
            celery_task_id=scan.celery_task_id,
            started_at=scan.started_at,
            completed_at=scan.completed_at,
            created_at=scan.created_at,
        )

    @classmethod
    def _to_progress_response(cls, scan: Scan) -> ScanProgressResponse:
        snapshot = scan.policy_snapshot or {}
        return ScanProgressResponse(
            scan_id=scan.id,
            asset_id=scan.asset_id,
            status=scan.status,
            progress_percent=scan.progress_percent,
            current_module=scan.current_module,
            enabled_modules=list(scan.enabled_modules or []),
            completed_modules=list(snapshot.get("completed_modules", [])),
            failed_modules=list(snapshot.get("failed_modules", [])),
            total_checks_run=scan.total_checks_run,
            findings_summary=dict(scan.findings_summary or {}),
            elapsed_seconds=cls._compute_elapsed_seconds(scan),
            error_message=scan.error_message,
            started_at=scan.started_at,
            completed_at=scan.completed_at,
        )

    @staticmethod
    def _to_check_response(rec: ScanCheckResultRecord) -> ScanCheckResultResponse:
        return ScanCheckResultResponse(
            id=rec.id,
            scan_id=rec.scan_id,
            module_id=rec.module_id,
            check_id=rec.check_id,
            title=rec.title,
            status=rec.status,
            duration_ms=rec.duration_ms,
            summary=rec.summary,
            details=dict(rec.details or {}),
            created_at=rec.created_at,
        )

    @staticmethod
    def _to_finding_response(rec: FindingRecord, asset: Asset | None = None) -> FindingResponse:
        target_asset = asset or rec.asset
        rem_data = dict(rec.remediation_data or {})
        triage_note = rem_data.get("triage_note")
        return FindingResponse(
            id=rec.id,
            organization_id=rec.organization_id,
            asset_id=rec.asset_id,
            asset_name=target_asset.name if target_asset else None,
            scan_id=rec.scan_id,
            fingerprint=rec.fingerprint,
            module_id=rec.module_id,
            check_id=rec.check_id,
            title=rec.title,
            description=rec.description,
            category=rec.category,
            result_classification=rec.result_classification,
            severity=rec.severity,
            confidence=rec.confidence,
            cvss_v4_vector=rec.cvss_v4_vector,
            cvss_v4_score=rec.cvss_v4_score,
            cwe_ids=list(rec.cwe_ids or []),
            owasp_categories=list(rec.owasp_categories or []),
            affected_endpoint=rec.affected_endpoint,
            evidence=dict(rec.evidence or {}),
            impact=rec.impact,
            reproduction_steps=list(rec.reproduction_steps or []),
            remediation_data=rem_data,
            treatment_status=rec.treatment_status,
            triage_note=str(triage_note) if triage_note else None,
            assigned_to_user_id=rec.assigned_to_user_id,
            priority=getattr(rec, "priority", "MEDIUM") or "MEDIUM",
            sla_deadline=getattr(rec, "sla_deadline", None),
            revalidation_scan_id=getattr(rec, "revalidation_scan_id", None),
            risk_acceptance_reason=getattr(rec, "risk_acceptance_reason", None),
            first_detected_at=rec.first_detected_at,
            last_confirmed_at=rec.last_confirmed_at,
            resolved_at=rec.resolved_at,
        )

    @classmethod
    def recalculate_asset_risk_score(cls, db: Session, asset: Asset) -> int:
        """Recalcula o risk_score do ativo com base nas vulnerabilidades abertas deduplicadas por fingerprint."""
        open_records = list(
            db.scalars(
                select(FindingRecord)
                .where(
                    FindingRecord.asset_id == asset.id,
                    FindingRecord.organization_id == asset.organization_id,
                    FindingRecord.treatment_status.in_(list(ACTIVE_FINDING_STATUSES)),
                )
                .order_by(FindingRecord.last_confirmed_at.desc())
            ).all()
        )
        seen_fps: set[str] = set()
        tuples: list[tuple[str, str, str]] = []
        for fnd in open_records:
            if fnd.fingerprint not in seen_fps:
                seen_fps.add(fnd.fingerprint)
                tuples.append((fnd.severity, fnd.confidence, fnd.result_classification))
        new_score = RiskEngine.calculate_risk_score_from_records(tuples)
        asset.risk_score = new_score
        return new_score

    @staticmethod
    def _verify_asset_authorization_gate(
        db: Session,
        asset: Asset,
        user_id: str | None,
        ip_address: str | None,
    ) -> None:
        """Verifica de forma inviolável se o ativo possui autorização VERIFIED e vigente."""
        if asset.authorization_status != "VERIFIED":
            AuditLogService.record(
                db=db,
                action="SCAN_BLOCKED_UNVERIFIED_ASSET",
                resource_type="asset",
                resource_id=asset.id,
                organization_id=asset.organization_id,
                user_id=user_id,
                ip_address=ip_address,
                metadata={
                    "authorization_status": asset.authorization_status,
                    "target_url": asset.target_url,
                },
                commit=True,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Execução bloqueada: o ativo '{asset.name}' ({asset.hostname}) possui status de "
                    f"autorização '{asset.authorization_status}'. É obrigatório comprovar autorização "
                    "(VERIFIED) antes de iniciar qualquer auditoria."
                ),
            )

        # Confirma que existe um registro TargetAuthorization VERIFIED e não expirado
        latest_auth = db.scalar(
            select(TargetAuthorization)
            .where(
                TargetAuthorization.asset_id == asset.id,
                TargetAuthorization.organization_id == asset.organization_id,
                TargetAuthorization.status == "VERIFIED",
            )
            .order_by(TargetAuthorization.verified_at.desc())
        )
        now = utcnow()
        if not latest_auth:
            asset.authorization_status = "PENDING"
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Nenhum comprovante de autorização VERIFIED encontrado para este ativo.",
            )

        if latest_auth.expires_at is not None:
            exp_dt = (
                latest_auth.expires_at
                if latest_auth.expires_at.tzinfo is not None
                else latest_auth.expires_at.replace(tzinfo=UTC)
            )
            if exp_dt <= now:
                latest_auth.status = "EXPIRED"
                asset.authorization_status = "EXPIRED"
                db.commit()
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="O comprovante de autorização deste ativo expirou. Renove a verificação antes de auditar.",
                )

    @classmethod
    def build_scope_validator_for_asset(cls, asset: Asset) -> ScopePolicyValidator:
        """Constrói o ScopePolicyValidator configurado para o ativo e ambiente."""
        settings = get_settings()
        lab_hosts = set(settings.parsed_lab_allowed_hosts)
        if settings.allow_local_lab_targets and asset.environment == "LAB":
            # Permite que servidores locais de laboratório explicitamente cadastrados como LAB sejam auditados
            lab_hosts.add(asset.hostname.lower())

        return ScopePolicyValidator(
            authorized_hosts=[asset.hostname],
            allow_subdomains=False,
            excluded_paths=list(asset.excluded_paths or []),
            block_private_networks=settings.block_private_networks,
            allow_local_lab_targets=settings.allow_local_lab_targets,
            lab_allowed_hosts=list(lab_hosts),
        )

    @classmethod
    def create_scan(
        cls,
        db: Session,
        organization_id: str,
        asset_id: str,
        user_id: str,
        profile_type: str = "QUICK",
        enabled_modules: list[str] | None = None,
        schedule_id: str | None = None,
        execute_synchronously: bool = False,
    ) -> Scan:
        """Cria e enfileira uma auditoria programaticamente (usado pelo scheduler de automações)."""
        payload = ScanCreateRequest(
            asset_id=asset_id,
            profile_type=profile_type,
            enabled_modules=enabled_modules,
            execute_synchronously=execute_synchronously,
        )
        resp = cls.create_and_dispatch_scan(
            db=db,
            organization_id=organization_id,
            user_id=user_id,
            payload=payload,
            ip_address="127.0.0.1",
        )
        scan = db.scalar(select(Scan).where(Scan.id == resp.id))
        if scan is None:
            raise RuntimeError(f"Falha ao recuperar auditoria criada {resp.id}")
        if schedule_id:
            scan.schedule_id = schedule_id
            db.commit()
            db.refresh(scan)
        return scan

    @classmethod
    def create_and_dispatch_scan(
        cls,
        db: Session,
        organization_id: str,
        user_id: str,
        payload: ScanCreateRequest,
        ip_address: str | None = None,
    ) -> ScanResponse:
        """Valida autorização, escopo, limites e cria uma auditoria, despachando-a ao worker."""
        asset = db.scalar(
            select(Asset).where(
                Asset.id == payload.asset_id,
                Asset.organization_id == organization_id,
            )
        )
        if not asset:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Ativo não encontrado na organização ativa.",
            )

        # 1. Gatekeeper de autorização
        cls._verify_asset_authorization_gate(db=db, asset=asset, user_id=user_id, ip_address=ip_address)

        # 2. Idempotência: evita duplicar scan ativo com a mesma idempotency_key
        if payload.idempotency_key:
            existing_scans = list(
                db.scalars(
                    select(Scan).where(
                        Scan.organization_id == organization_id,
                        Scan.asset_id == asset.id,
                        Scan.status.in_(ACTIVE_SCAN_STATUSES),
                    )
                ).all()
            )
            for active_scan in existing_scans:
                if (active_scan.policy_snapshot or {}).get("idempotency_key") == payload.idempotency_key:
                    return cls._to_scan_response(active_scan, asset)

        # 3. Controle de concorrência por organização
        active_org_scans_count = len(
            list(
                db.scalars(
                    select(Scan.id).where(
                        Scan.organization_id == organization_id,
                        Scan.status.in_(ACTIVE_SCAN_STATUSES),
                    )
                ).all()
            )
        )
        if active_org_scans_count >= MAX_ACTIVE_SCANS_PER_ORG:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Limite de {MAX_ACTIVE_SCANS_PER_ORG} auditorias simultâneas por organização atingido.",
            )

        # 4. Validação de perfil e ambiente
        try:
            profile_enum = ScanProfileType(payload.profile_type.upper().strip())
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Perfil de auditoria inválido: '{payload.profile_type}'.",
            ) from exc

        profile_desc = SCAN_PROFILES_CATALOG[profile_enum]
        env_enum = EnvironmentType(asset.environment)
        if env_enum == EnvironmentType.PRODUCTION and not profile_desc.allowed_in_production:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"O perfil '{profile_desc.name}' não é permitido em ativos classificados como PRODUCTION."
                ),
            )

        requested_modules = (
            payload.enabled_modules
            if payload.enabled_modules is not None
            else list(profile_desc.enabled_modules)
        )
        if not requested_modules:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Ao menos um módulo de verificação deve ser selecionado.",
            )

        try:
            validated_modules = default_registry.validate_modules_for_environment(
                requested_modules,
                env_enum,
            )
        except (KeyError, ValueError) as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=str(exc),
            ) from exc

        # 5. Validação prévia de escopo e Anti-SSRF
        scope_validator = cls.build_scope_validator_for_asset(asset)
        try:
            scope_validator.validate_url(asset.target_url, resolve_dns=False)
        except ScopeViolationError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Violação de escopo / Anti-SSRF na URL do ativo: {exc}",
            ) from exc

        # 6. Construção da política de execução com guardrails intransponíveis
        merged_excluded = list(
            set((asset.excluded_paths or []) + ["/logout", "/signout", "/delete", "/reset"])
        )
        exec_policy = ScanExecutionPolicy(
            max_requests_per_second=payload.max_requests_per_second or profile_desc.default_max_rps,
            max_concurrency=payload.max_concurrency or profile_desc.default_max_concurrency,
            request_timeout_seconds=payload.request_timeout_seconds or 10,
            global_timeout_seconds=profile_desc.default_timeout_seconds,
            max_redirects=payload.max_redirects if payload.max_redirects is not None else 5,
            excluded_endpoints=merged_excluded,
        )

        policy_snapshot: dict[str, Any] = exec_policy.model_dump(mode="json")
        policy_snapshot["completed_modules"] = []
        policy_snapshot["failed_modules"] = []
        if payload.idempotency_key:
            policy_snapshot["idempotency_key"] = payload.idempotency_key

        scan = Scan(
            organization_id=organization_id,
            asset_id=asset.id,
            initiated_by_user_id=user_id,
            profile_type=profile_enum.value,
            status="PENDING",
            progress_percent=0,
            current_module=None,
            enabled_modules=validated_modules,
            policy_snapshot=policy_snapshot,
            total_checks_run=0,
            findings_summary={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        )
        db.add(scan)
        db.flush()

        AuditLogService.record(
            db=db,
            action="SCAN_CREATED",
            resource_type="scan",
            resource_id=scan.id,
            organization_id=organization_id,
            user_id=user_id,
            ip_address=ip_address,
            metadata={
                "asset_id": asset.id,
                "profile_type": scan.profile_type,
                "enabled_modules": validated_modules,
            },
            commit=False,
        )

        scan.status = "QUEUED"
        db.commit()
        db.refresh(scan)

        if payload.execute_synchronously:
            cls.execute_scan_by_id(db=db, scan_id=scan.id)
            db.refresh(scan)
            return cls._to_scan_response(scan, asset)

        # Enfileira no Celery
        try:
            from workers.tasks import execute_scan_task

            async_res = execute_scan_task.delay(scan.id)
            scan.celery_task_id = str(async_res.id)
            db.commit()
            db.refresh(scan)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Broker Celery indisponível ao enfileirar scan %s (%s); executando fallback síncrono.",
                scan.id,
                exc,
            )
            cls.execute_scan_by_id(db=db, scan_id=scan.id)
            db.refresh(scan)

        return cls._to_scan_response(scan, asset)

    @classmethod
    def execute_scan_by_id(
        cls,
        db: Session,
        scan_id: str,
        *,
        ca_bundle_path: str | None = None,
        http_redirect_probe_url: str | None = None,
        resolve_dns: bool = True,
        custom_resolver: list[str] | None = None,
    ) -> Scan:
        """Executa de forma determinística e idempotente uma auditoria persistindo resultados incrementais."""
        scan = db.scalar(select(Scan).where(Scan.id == scan_id))
        if not scan:
            raise ValueError(f"Scan '{scan_id}' não encontrado.")

        # Idempotência: se o scan já está em estado terminal, não reexecuta
        if scan.status in TERMINAL_SCAN_STATUSES:
            return scan

        asset = db.scalar(select(Asset).where(Asset.id == scan.asset_id))
        if not asset or asset.authorization_status != "VERIFIED":
            scan.status = "FAILED"
            scan.error_message = "Ativo ausente ou sem autorização VERIFIED no momento da execução."
            scan.completed_at = utcnow()
            db.commit()
            return scan

        # Verifica se já foi cancelado enquanto estava na fila
        if cls._is_redis_cancel_flagged(scan.id) or scan.status == "CANCELLED":
            scan.status = "CANCELLED"
            scan.completed_at = utcnow()
            db.commit()
            return scan

        scan.status = "RUNNING"
        scan.started_at = utcnow()
        scan.progress_percent = 5
        db.commit()

        policy_data = dict(scan.policy_snapshot or {})
        exec_policy = ScanExecutionPolicy(
            max_requests_per_second=int(policy_data.get("max_requests_per_second", 5)),
            max_concurrency=int(policy_data.get("max_concurrency", 3)),
            request_timeout_seconds=int(policy_data.get("request_timeout_seconds", 10)),
            global_timeout_seconds=int(policy_data.get("global_timeout_seconds", 600)),
            max_crawl_depth=int(policy_data.get("max_crawl_depth", 2)),
            max_redirects=int(policy_data.get("max_redirects", 5)),
            max_response_body_bytes=int(policy_data.get("max_response_body_bytes", 2 * 1024 * 1024)),
            excluded_endpoints=list(policy_data.get("excluded_endpoints", [])),
            circuit_breaker_error_threshold=int(policy_data.get("circuit_breaker_error_threshold", 5)),
        )

        scope_validator = cls.build_scope_validator_for_asset(asset)
        runner = SecurityEngineRunner(
            scope_validator=scope_validator,
            policy=exec_policy,
            registry=default_registry,
            resolve_dns=resolve_dns,
            custom_resolver=custom_resolver,
            ca_bundle_path=ca_bundle_path,
            http_redirect_probe_url=http_redirect_probe_url,
        )

        def _is_cancelled() -> bool:
            if cls._is_redis_cancel_flagged(scan.id):
                return True
            db.expire(scan, ["status"])
            current_status = db.scalar(select(Scan.status).where(Scan.id == scan.id))
            return current_status == "CANCELLED"

        completed_modules: list[str] = []
        failed_modules: list[str] = []
        severity_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        collected_domain_findings: list[NormalizedFinding] = []
        total_checks = 0

        def _on_module_start(mod_id: str, idx: int, total: int) -> None:
            scan.current_module = mod_id
            scan.progress_percent = min(95, int(((idx - 1) / max(1, total)) * 85) + 10)
            db.commit()

        def _on_module_complete(
            mod_id: str,
            mod_result: ModuleExecutionResult,
            idx: int,
            total: int,
        ) -> None:
            nonlocal total_checks
            for chk in mod_result.checks:
                total_checks += 1
                db.add(
                    ScanCheckResultRecord(
                        scan_id=scan.id,
                        module_id=chk.module_id,
                        check_id=chk.check_id,
                        title=chk.title,
                        status=chk.status.value,
                        duration_ms=chk.duration_ms,
                        summary=chk.summary,
                        details=chk.details,
                    )
                )

            for fnd in mod_result.findings:
                collected_domain_findings.append(fnd)
                sev_key = fnd.severity.value
                severity_counts[sev_key] = severity_counts.get(sev_key, 0) + 1

                safe_fp = str(fnd.fingerprint or "").strip()
                if len(safe_fp) > 64:
                    safe_fp = hashlib.sha256(safe_fp.encode("utf-8")).hexdigest()[:32]
                elif not safe_fp:
                    safe_fp = hashlib.sha256(
                        f"{asset.hostname}|{fnd.module_id}|{fnd.check_id}|{fnd.endpoint}".encode()
                    ).hexdigest()[:32]

                # Verifica se já houve detecção prévia do mesmo fingerprint neste ativo
                prior_finding = db.scalar(
                    select(FindingRecord)
                    .where(
                        FindingRecord.asset_id == asset.id,
                        FindingRecord.organization_id == scan.organization_id,
                        FindingRecord.fingerprint == safe_fp,
                    )
                    .order_by(FindingRecord.last_confirmed_at.desc())
                )
                first_seen = prior_finding.first_detected_at if prior_finding else utcnow()
                # Estado administrativo herdado da detecção anterior; correções reincidentes reabrem.
                inherited_status = "OPEN"
                inherited_assignee = None
                inherited_rem: dict[str, Any] = {}
                if prior_finding is not None:
                    inherited_assignee = prior_finding.assigned_to_user_id
                    if prior_finding.treatment_status in {
                        "IN_PROGRESS",
                        "FALSE_POSITIVE",
                        "ACCEPTED_RISK",
                    }:
                        inherited_status = prior_finding.treatment_status
                        prior_note = (prior_finding.remediation_data or {}).get("triage_note")
                        if prior_note:
                            inherited_rem["triage_note"] = prior_note

                db.add(
                    FindingRecord(
                        organization_id=scan.organization_id,
                        asset_id=asset.id,
                        scan_id=scan.id,
                        fingerprint=safe_fp,
                        module_id=fnd.module_id,
                        check_id=fnd.check_id,
                        title=fnd.title,
                        description=fnd.description,
                        category=fnd.category,
                        result_classification=fnd.result_classification.value,
                        severity=fnd.severity.value,
                        confidence=fnd.confidence.value,
                        cvss_v4_vector=fnd.cvss_v4_vector,
                        cvss_v4_score=fnd.cvss_v4_score,
                        cwe_ids=fnd.cwe_ids,
                        owasp_categories=fnd.owasp_references,
                        affected_endpoint=fnd.endpoint,
                        evidence=fnd.evidence.model_dump(mode="json"),
                        impact=fnd.impact,
                        reproduction_steps=fnd.safe_reproduction_steps,
                        remediation_data={**fnd.remediation.model_dump(mode="json"), **inherited_rem},
                        treatment_status=inherited_status,
                        assigned_to_user_id=inherited_assignee,
                        first_detected_at=first_seen,
                        last_confirmed_at=utcnow(),
                    )
                )

            if mod_result.execution_errors > 0:
                failed_modules.append(mod_id)
            else:
                completed_modules.append(mod_id)

            updated_snapshot = dict(scan.policy_snapshot or {})
            updated_snapshot["completed_modules"] = list(completed_modules)
            updated_snapshot["failed_modules"] = list(failed_modules)
            scan.policy_snapshot = updated_snapshot
            scan.total_checks_run = total_checks
            scan.findings_summary = dict(severity_counts)
            scan.progress_percent = min(98, int((idx / max(1, total)) * 90) + 8)
            db.commit()

        summary = runner.execute_modules(
            target_url=asset.target_url,
            module_ids=list(scan.enabled_modules or []),
            asset_type=AssetType(asset.asset_type),
            environment=EnvironmentType(asset.environment),
            is_cancelled=_is_cancelled,
            on_module_start=_on_module_start,
            on_module_complete=_on_module_complete,
        )

        final_snapshot = dict(scan.policy_snapshot or {})
        final_snapshot["completed_modules"] = list(summary.completed_modules)
        final_snapshot["failed_modules"] = list(summary.failed_modules)
        final_snapshot["total_http_requests"] = summary.total_requests
        final_snapshot["total_duration_ms"] = summary.total_duration_ms
        if summary.snapshot:
            final_snapshot["final_url"] = summary.snapshot.final_url
            final_snapshot["http_status_code"] = summary.snapshot.status_code
            final_snapshot["redirect_hops"] = len(summary.snapshot.redirect_chain)

        scan.policy_snapshot = final_snapshot
        scan.current_module = None
        scan.status = summary.final_status
        scan.error_message = summary.error_message
        scan.completed_at = utcnow()
        if summary.final_status in {"COMPLETED", "PARTIALLY_COMPLETED"}:
            scan.progress_percent = 100
            cls.recalculate_asset_risk_score(db, asset)

        AuditLogService.record(
            db=db,
            action=f"SCAN_{summary.final_status}",
            resource_type="scan",
            resource_id=scan.id,
            organization_id=scan.organization_id,
            user_id=scan.initiated_by_user_id,
            metadata={
                "asset_id": asset.id,
                "status": summary.final_status,
                "total_checks_run": scan.total_checks_run,
                "findings_summary": scan.findings_summary,
                "risk_score": asset.risk_score,
            },
            commit=False,
        )
        db.commit()
        db.refresh(scan)
        return scan

    @classmethod
    def cancel_scan(
        cls,
        db: Session,
        organization_id: str,
        user_id: str,
        scan_id: str,
        ip_address: str | None = None,
    ) -> ScanResponse:
        """Solicita o cancelamento cooperativo e imediato de uma auditoria em fila ou em execução."""
        scan = db.scalar(
            select(Scan).where(
                Scan.id == scan_id,
                Scan.organization_id == organization_id,
            )
        )
        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Auditoria não encontrada na organização ativa.",
            )

        if scan.status in TERMINAL_SCAN_STATUSES:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Não é possível cancelar uma auditoria que já está no estado '{scan.status}'.",
            )

        cls._set_redis_cancel_flag(scan.id)

        if scan.celery_task_id:
            try:
                from workers.celery_app import celery_app

                celery_app.control.revoke(scan.celery_task_id, terminate=False)
            except Exception as exc:  # noqa: BLE001
                logger.debug("Falha ao revogar task Celery %s: %s", scan.celery_task_id, exc)

        scan.status = "CANCELLED"
        scan.current_module = None
        scan.error_message = "Auditoria cancelada manualmente pelo usuário."
        scan.completed_at = utcnow()

        AuditLogService.record(
            db=db,
            action="SCAN_CANCELLED",
            resource_type="scan",
            resource_id=scan.id,
            organization_id=organization_id,
            user_id=user_id,
            ip_address=ip_address,
            metadata={"asset_id": scan.asset_id},
            commit=False,
        )
        db.commit()
        db.refresh(scan)
        return cls._to_scan_response(scan)

    @classmethod
    def list_scans(
        cls,
        db: Session,
        organization_id: str,
        asset_id: str | None = None,
        limit: int = 50,
    ) -> list[ScanResponse]:
        stmt = select(Scan).where(Scan.organization_id == organization_id)
        if asset_id:
            stmt = stmt.where(Scan.asset_id == asset_id)
        stmt = stmt.order_by(Scan.created_at.desc()).limit(limit)
        scans = list(db.scalars(stmt).all())
        return [cls._to_scan_response(s) for s in scans]

    @classmethod
    def get_scan_or_404(
        cls,
        db: Session,
        organization_id: str,
        scan_id: str,
    ) -> Scan:
        scan = db.scalar(
            select(Scan).where(
                Scan.id == scan_id,
                Scan.organization_id == organization_id,
            )
        )
        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Auditoria não encontrada na organização ativa.",
            )
        return scan

    @classmethod
    def get_scan_progress(
        cls,
        db: Session,
        organization_id: str,
        scan_id: str,
    ) -> ScanProgressResponse:
        scan = cls.get_scan_or_404(db=db, organization_id=organization_id, scan_id=scan_id)
        return cls._to_progress_response(scan)

    @classmethod
    def get_scan_detailed_results(
        cls,
        db: Session,
        organization_id: str,
        scan_id: str,
    ) -> ScanDetailedResultsResponse:
        scan = cls.get_scan_or_404(db=db, organization_id=organization_id, scan_id=scan_id)
        checks = list(
            db.scalars(
                select(ScanCheckResultRecord)
                .where(ScanCheckResultRecord.scan_id == scan.id)
                .order_by(ScanCheckResultRecord.created_at.asc())
            ).all()
        )
        findings = list(
            db.scalars(
                select(FindingRecord)
                .where(
                    FindingRecord.scan_id == scan.id,
                    FindingRecord.organization_id == organization_id,
                )
                .order_by(FindingRecord.first_detected_at.asc())
            ).all()
        )
        return ScanDetailedResultsResponse(
            scan=cls._to_scan_response(scan),
            checks=[cls._to_check_response(c) for c in checks],
            findings=[cls._to_finding_response(f) for f in findings],
        )

    @classmethod
    def list_organization_findings(
        cls,
        db: Session,
        organization_id: str,
        *,
        asset_id: str | None = None,
        scan_id: str | None = None,
        severity: str | None = None,
        treatment_status: str | None = None,
        confidence: str | None = None,
        cwe_id: str | None = None,
        owasp_category: str | None = None,
        search: str | None = None,
    ) -> list[FindingResponse]:
        stmt = select(FindingRecord).where(FindingRecord.organization_id == organization_id)
        if asset_id:
            stmt = stmt.where(FindingRecord.asset_id == asset_id)
        if scan_id:
            stmt = stmt.where(FindingRecord.scan_id == scan_id)
        if severity:
            stmt = stmt.where(FindingRecord.severity == severity.upper().strip())
        if treatment_status:
            stmt = stmt.where(FindingRecord.treatment_status == treatment_status.upper().strip())
        if confidence:
            stmt = stmt.where(FindingRecord.confidence == confidence.upper().strip())
        stmt = stmt.order_by(FindingRecord.last_confirmed_at.desc())
        records = list(db.scalars(stmt).all())

        # Filtros adicionais em memória para listas JSON (CWE / OWASP) e busca textual
        if cwe_id:
            norm_cwe = cwe_id.upper().strip()
            records = [r for r in records if any(norm_cwe in str(c).upper() for c in (r.cwe_ids or []))]
        if owasp_category:
            norm_owasp = owasp_category.lower().strip()
            records = [
                r
                for r in records
                if any(norm_owasp in str(ow).lower() for ow in (r.owasp_categories or []))
            ]
        if search:
            q = search.lower().strip()
            records = [
                r
                for r in records
                if q in r.title.lower()
                or q in r.description.lower()
                or q in r.check_id.lower()
                or q in r.affected_endpoint.lower()
            ]
        return [cls._to_finding_response(r) for r in records]

    @classmethod
    def get_finding_or_404(
        cls,
        db: Session,
        organization_id: str,
        finding_id: str,
    ) -> FindingRecord:
        finding = db.scalar(
            select(FindingRecord).where(
                FindingRecord.id == finding_id,
                FindingRecord.organization_id == organization_id,
            )
        )
        if not finding:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Vulnerabilidade não encontrada na organização ativa.",
            )
        return finding

    @classmethod
    def update_finding_status(
        cls,
        db: Session,
        organization_id: str,
        user_id: str,
        finding_id: str,
        payload: FindingTriageUpdateRequest,
        ip_address: str | None = None,
    ) -> FindingResponse:
        """Atualiza o status de tratamento (triagem) de uma vulnerabilidade e recalcula o risk_score do ativo."""
        finding = cls.get_finding_or_404(db=db, organization_id=organization_id, finding_id=finding_id)
        new_status = payload.treatment_status.upper().strip()
        if new_status not in VALID_TREATMENT_STATUSES:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=(
                    f"Status de tratamento inválido: '{payload.treatment_status}'. "
                    f"Valores permitidos: {sorted(VALID_TREATMENT_STATUSES)}"
                ),
            )

        previous_status = finding.treatment_status
        finding.treatment_status = new_status
        if payload.assigned_to_user_id is not None:
            finding.assigned_to_user_id = payload.assigned_to_user_id
        if payload.priority is not None:
            finding.priority = payload.priority.upper().strip()
        if payload.sla_deadline is not None:
            finding.sla_deadline = payload.sla_deadline
        if payload.risk_acceptance_reason is not None:
            finding.risk_acceptance_reason = payload.risk_acceptance_reason.strip()

        if new_status == "ACCEPTED_RISK" and not (
            finding.risk_acceptance_reason
            or (payload.risk_acceptance_reason and payload.risk_acceptance_reason.strip())
        ):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Justificativa formal é obrigatória para aceitação de risco.",
            )

        rem_data = dict(finding.remediation_data or {})
        if payload.triage_note is not None:
            rem_data["triage_note"] = payload.triage_note.strip()
        rem_data["last_triaged_by"] = user_id
        rem_data["last_triaged_at"] = utcnow().isoformat()
        finding.remediation_data = rem_data

        if new_status in {"MITIGATED", "RESOLVED_VERIFIED", "FALSE_POSITIVE", "ACCEPTED_RISK"}:
            finding.resolved_at = utcnow()
        else:
            finding.resolved_at = None

        db.flush()

        asset = db.scalar(select(Asset).where(Asset.id == finding.asset_id))
        updated_risk_score = 0
        if asset:
            updated_risk_score = cls.recalculate_asset_risk_score(db, asset)

        AuditLogService.record(
            db=db,
            action="FINDING_STATUS_UPDATED",
            resource_type="finding",
            resource_id=finding.id,
            organization_id=organization_id,
            user_id=user_id,
            ip_address=ip_address,
            metadata={
                "asset_id": finding.asset_id,
                "check_id": finding.check_id,
                "previous_status": previous_status,
                "new_status": new_status,
                "triage_note": payload.triage_note,
                "updated_asset_risk_score": updated_risk_score,
            },
            commit=False,
        )
        db.commit()
        db.refresh(finding)
        return cls._to_finding_response(finding, asset)

    @classmethod
    def recover_interrupted_scans(cls, db: Session, organization_id: str | None = None) -> int:
        """Recupera auditorias interrompidas por queda de worker que excederam o timeout global."""
        stmt = select(Scan).where(Scan.status.in_({"RUNNING", "QUEUED"}))
        if organization_id:
            stmt = stmt.where(Scan.organization_id == organization_id)
        candidates = list(db.scalars(stmt).all())
        now = utcnow()
        recovered = 0
        for scan in candidates:
            ref_time = scan.started_at or scan.created_at
            ref_dt = ref_time if ref_time.tzinfo is not None else ref_time.replace(tzinfo=UTC)
            global_timeout = int((scan.policy_snapshot or {}).get("global_timeout_seconds", 600))
            if (now - ref_dt).total_seconds() > global_timeout:
                completed_mods = (scan.policy_snapshot or {}).get("completed_modules", [])
                scan.status = "PARTIALLY_COMPLETED" if completed_mods else "FAILED"
                scan.current_module = None
                scan.error_message = f"Execução interrompida por timeout operacional ({global_timeout}s) ou reinicialização do worker."
                scan.completed_at = now
                recovered += 1
        if recovered > 0:
            db.commit()
        return recovered
