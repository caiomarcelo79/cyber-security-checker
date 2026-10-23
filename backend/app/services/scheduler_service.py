"""Serviço de agendamento e execução periódica de auditorias de segurança (Fase 7)."""

from __future__ import annotations

import logging
import zoneinfo
from datetime import UTC, datetime
from typing import Any

from croniter import croniter
from fastapi import HTTPException, status
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.models.entities import Asset, AuditLog, Scan, ScanSchedule
from app.schemas.automations import (
    ScanScheduleCreateRequest,
    ScanSchedulePageResponse,
    ScanScheduleResponse,
    ScanScheduleUpdateRequest,
)
from app.services.scan_orchestrator import ScanOrchestrator

logger = logging.getLogger(__name__)

STANDARD_FREQUENCY_CRONS = {
    "DAILY": "0 2 * * *",  # Todo dia às 02:00
    "WEEKLY": "0 2 * * 1",  # Toda segunda-feira às 02:00
    "MONTHLY": "0 2 1 * *",  # Todo dia 1º às 02:00
}

VALID_FREQUENCIES = {"ONCE", "DAILY", "WEEKLY", "MONTHLY", "CRON"}
VALID_SCHEDULE_STATUSES = {"ACTIVE", "PAUSED", "COMPLETED", "FAILED_AUTH"}


class ScheduleValidationError(ValueError):
    """Exceção levantada quando parâmetros do agendamento são inválidos."""


def utcnow() -> datetime:
    return datetime.now(UTC)


class CronSchedulerUtil:
    """Validador e calculador de próximas execuções de auditorias com fuso horário."""

    @staticmethod
    def validate_cron(expression: str) -> bool:
        """Verifica se a expressão cron possui 5 campos válidos."""
        try:
            return croniter.is_valid(expression.strip())
        except Exception:  # noqa: BLE001
            return False

    @staticmethod
    def validate_timezone(tz_name: str) -> bool:
        """Verifica se o fuso horário IANA é válido."""
        try:
            zoneinfo.ZoneInfo(tz_name.strip())
            return True
        except Exception:  # noqa: BLE001
            return False

    @staticmethod
    def resolve_cron_for_frequency(frequency: str, custom_cron: str = "") -> str:
        """Resolve a expressão cron correspondente à frequência."""
        freq = frequency.upper().strip()
        if freq in STANDARD_FREQUENCY_CRONS:
            return STANDARD_FREQUENCY_CRONS[freq]
        if freq == "CRON":
            if not CronSchedulerUtil.validate_cron(custom_cron):
                raise ScheduleValidationError(f"Expressão cron inválida: '{custom_cron}'.")
            return custom_cron.strip()
        if freq == "ONCE":
            return "@once"
        raise ScheduleValidationError(f"Frequência inválida: '{frequency}'.")

    @classmethod
    def calculate_next_run(
        cls,
        cron_expression: str,
        tz_name: str = "UTC",
        base_time: datetime | None = None,
    ) -> datetime:
        """Calcula próxima execução a partir de uma expressão cron e fuso horário."""
        return cls.compute_next_run(
            frequency="CRON",
            cron_expression=cron_expression,
            tz_name=tz_name,
            base_time=base_time,
        )

    @classmethod
    def compute_next_run(
        cls,
        frequency: str,
        cron_expression: str,
        tz_name: str,
        base_time: datetime | None = None,
    ) -> datetime:
        """Calcula o próximo instante de execução em UTC respeitando o fuso horário configurado."""
        freq = frequency.upper().strip()
        base = base_time or utcnow()

        # Resolução do fuso horário
        try:
            tz = zoneinfo.ZoneInfo(tz_name.strip() if tz_name else "UTC")
        except Exception:  # noqa: BLE001
            tz = UTC

        # Converte base para o fuso local do agendamento
        local_base = base.astimezone(tz)

        if freq in STANDARD_FREQUENCY_CRONS:
            cron_expr = STANDARD_FREQUENCY_CRONS[freq]
        elif freq == "CRON":
            cron_expr = cron_expression.strip()
            if not cls.validate_cron(cron_expr):
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"Expressão cron inválida: '{cron_expr}'. Utilize formato de 5 campos (min hora dia mês dow).",
                )
        else:
            # ONCE ou desconhecido
            return base

        it = croniter(cron_expr, local_base)
        next_local = it.get_next(datetime)
        return next_local.astimezone(UTC)


class SchedulerService:
    """Gerenciamento de regras de agendamento de auditorias autorizadas."""

    @classmethod
    def create_schedule(
        cls,
        db: Session,
        organization_id: str,
        user_id: str,
        payload: ScanScheduleCreateRequest | None = None,
        req: ScanScheduleCreateRequest | None = None,
    ) -> ScanScheduleResponse:
        """Cadastra um novo agendamento recorrente para um ativo autorizado."""
        data = payload or req
        if not data:
            raise ScheduleValidationError("Payload de agendamento é obrigatório.")
        payload = data
        # 1. Valida existência do ativo no tenant
        asset = db.scalar(
            select(Asset).where(
                Asset.id == payload.asset_id,
                Asset.organization_id == organization_id,
            )
        )
        if not asset:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Ativo não encontrado ou não pertence a esta organização.",
            )

        # 2. Valida autorização prévia
        if asset.authorization_status != "VERIFIED":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Agendamento não permitido: o ativo não possui comprovação de autorização válida.",
            )

        freq = payload.frequency.upper().strip()
        if freq not in VALID_FREQUENCIES:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Frequência inválida. Valores aceitos: {sorted(VALID_FREQUENCIES)}",
            )

        cron_expr = payload.cron_expression.strip()
        if freq == "CRON" and not CronSchedulerUtil.validate_cron(cron_expr):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Expressão cron inválida: '{cron_expr}'.",
            )
        elif freq in STANDARD_FREQUENCY_CRONS:
            cron_expr = STANDARD_FREQUENCY_CRONS[freq]

        tz_name = payload.timezone.strip() if payload.timezone else "UTC"
        try:
            zoneinfo.ZoneInfo(tz_name)
        except Exception:  # noqa: BLE001
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Fuso horário inválido: '{tz_name}'. Utilize nomes IANA como 'UTC' ou 'America/Sao_Paulo'.",
            )

        next_run = CronSchedulerUtil.compute_next_run(
            frequency=freq,
            cron_expression=cron_expr,
            tz_name=tz_name,
            base_time=utcnow(),
        )

        schedule = ScanSchedule(
            organization_id=organization_id,
            asset_id=asset.id,
            profile_type=payload.profile_type.upper().strip(),
            enabled_modules=payload.enabled_modules,
            frequency=freq,
            cron_expression=cron_expr,
            timezone=tz_name,
            status="ACTIVE",
            is_active=True,
            misfire_policy=payload.misfire_policy.upper().strip(),
            consecutive_failures=0,
            next_run_at=next_run,
            created_by_user_id=user_id,
            created_at=utcnow(),
        )
        db.add(schedule)
        db.flush()

        audit = AuditLog(
            organization_id=organization_id,
            user_id=user_id,
            action="SCHEDULE_CREATED",
            resource_type="scan_schedule",
            resource_id=schedule.id,
            metadata_json={
                "asset_id": asset.id,
                "frequency": freq,
                "cron_expression": cron_expr,
                "next_run_at": next_run.isoformat(),
            },
        )
        db.add(audit)
        db.commit()
        db.refresh(schedule)

        return cls._to_response(schedule, asset_name=asset.name)

    @classmethod
    def list_schedules(
        cls,
        db: Session,
        organization_id: str,
        asset_id: str | None = None,
        status_filter: str | None = None,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> ScanSchedulePageResponse:
        """Lista agendamentos de auditoria com paginação no servidor."""
        st_filter = status_filter or status
        stmt = (
            select(ScanSchedule, Asset.name.label("asset_name"))
            .outerjoin(Asset, ScanSchedule.asset_id == Asset.id)
            .where(ScanSchedule.organization_id == organization_id)
        )
        if asset_id:
            stmt = stmt.where(ScanSchedule.asset_id == asset_id)
        if st_filter:
            stmt = stmt.where(ScanSchedule.status == st_filter.upper().strip())

        total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
        rows = db.execute(stmt.order_by(desc(ScanSchedule.created_at)).limit(limit).offset(offset)).all()

        items = [cls._to_response(row[0], asset_name=row[1]) for row in rows]
        return ScanSchedulePageResponse(items=items, total=total, limit=limit, offset=offset)

    @classmethod
    def get_schedule(
        cls, db: Session, organization_id: str, schedule_id: str
    ) -> ScanScheduleResponse | None:
        """Consulta detalhes de um agendamento específico."""
        row = db.execute(
            select(ScanSchedule, Asset.name.label("asset_name"))
            .outerjoin(Asset, ScanSchedule.asset_id == Asset.id)
            .where(ScanSchedule.id == schedule_id, ScanSchedule.organization_id == organization_id)
        ).first()
        if not row:
            return None
        return cls._to_response(row[0], asset_name=row[1])

    @classmethod
    def update_schedule(
        cls,
        db: Session,
        organization_id: str,
        schedule_id: str,
        payload: ScanScheduleUpdateRequest | None = None,
        req: ScanScheduleUpdateRequest | None = None,
        user_id: str | None = None,
    ) -> ScanScheduleResponse:
        """Atualiza parâmetros de um agendamento existente."""
        data = payload or req
        if not data:
            raise ScheduleValidationError("Payload de atualização é obrigatório.")
        payload = data
        schedule = db.scalar(
            select(ScanSchedule).where(
                ScanSchedule.id == schedule_id,
                ScanSchedule.organization_id == organization_id,
            )
        )
        if not schedule:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Agendamento não encontrado."
            )

        if payload.profile_type is not None:
            schedule.profile_type = payload.profile_type.upper().strip()
        if payload.enabled_modules is not None:
            schedule.enabled_modules = payload.enabled_modules
        if payload.timezone is not None:
            tz = payload.timezone.strip()
            try:
                zoneinfo.ZoneInfo(tz)
                schedule.timezone = tz
            except Exception:  # noqa: BLE001
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"Fuso horário inválido: '{tz}'",
                )

        if payload.frequency is not None:
            freq = payload.frequency.upper().strip()
            if freq not in VALID_FREQUENCIES:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Frequência inválida."
                )
            schedule.frequency = freq
            if freq in STANDARD_FREQUENCY_CRONS:
                schedule.cron_expression = STANDARD_FREQUENCY_CRONS[freq]

        if payload.cron_expression is not None:
            expr = payload.cron_expression.strip()
            if not CronSchedulerUtil.validate_cron(expr):
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Expressão cron inválida."
                )
            schedule.cron_expression = expr

        if payload.status is not None:
            st = payload.status.upper().strip()
            if st in VALID_SCHEDULE_STATUSES:
                schedule.status = st
                schedule.is_active = st == "ACTIVE"

        if payload.misfire_policy is not None:
            schedule.misfire_policy = payload.misfire_policy.upper().strip()

        # Recalcula próximo disparo caso ativo
        if schedule.is_active and schedule.status == "ACTIVE":
            schedule.next_run_at = CronSchedulerUtil.compute_next_run(
                frequency=schedule.frequency,
                cron_expression=schedule.cron_expression,
                tz_name=schedule.timezone,
                base_time=utcnow(),
            )

        schedule.updated_at = utcnow()
        db.commit()
        db.refresh(schedule)

        asset = db.scalar(select(Asset).where(Asset.id == schedule.asset_id))
        return cls._to_response(schedule, asset_name=asset.name if asset else None)

    @classmethod
    def pause_schedule(
        cls,
        db: Session,
        organization_id: str,
        schedule_id: str,
        user_id: str | None = None,
    ) -> ScanScheduleResponse:
        """Pausa um agendamento ativo."""
        schedule = db.scalar(
            select(ScanSchedule).where(
                ScanSchedule.id == schedule_id,
                ScanSchedule.organization_id == organization_id,
            )
        )
        if not schedule:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Agendamento não encontrado."
            )

        schedule.status = "PAUSED"
        schedule.is_active = False
        schedule.updated_at = utcnow()
        db.commit()
        db.refresh(schedule)
        asset = db.scalar(select(Asset).where(Asset.id == schedule.asset_id))
        return cls._to_response(schedule, asset_name=asset.name if asset else None)

    @classmethod
    def resume_schedule(
        cls,
        db: Session,
        organization_id: str,
        schedule_id: str,
        user_id: str | None = None,
    ) -> ScanScheduleResponse:
        """Retoma um agendamento pausado ou que falhou por autorização."""
        schedule = db.scalar(
            select(ScanSchedule).where(
                ScanSchedule.id == schedule_id,
                ScanSchedule.organization_id == organization_id,
            )
        )
        if not schedule:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Agendamento não encontrado."
            )

        asset = db.scalar(select(Asset).where(Asset.id == schedule.asset_id))
        if not asset or asset.authorization_status != "VERIFIED":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Não é possível retomar o agendamento: o ativo não possui autorização verificada.",
            )

        schedule.status = "ACTIVE"
        schedule.is_active = True
        schedule.consecutive_failures = 0
        schedule.next_run_at = CronSchedulerUtil.compute_next_run(
            frequency=schedule.frequency,
            cron_expression=schedule.cron_expression,
            tz_name=schedule.timezone,
            base_time=utcnow(),
        )
        schedule.updated_at = utcnow()
        db.commit()
        db.refresh(schedule)
        return cls._to_response(schedule, asset_name=asset.name)

    @classmethod
    def delete_schedule(
        cls,
        db: Session,
        organization_id: str,
        schedule_id: str,
        user_id: str | None = None,
    ) -> bool:
        """Exclui um agendamento."""
        schedule = db.scalar(
            select(ScanSchedule).where(
                ScanSchedule.id == schedule_id,
                ScanSchedule.organization_id == organization_id,
            )
        )
        if not schedule:
            return False

        db.delete(schedule)
        if user_id:
            audit = AuditLog(
                organization_id=organization_id,
                user_id=user_id,
                action="SCHEDULE_DELETED",
                resource_type="scan_schedule",
                resource_id=schedule_id,
                metadata_json={"asset_id": schedule.asset_id},
            )
            db.add(audit)
        db.commit()
        return True

    @classmethod
    def trigger_due_schedules(cls, db: Session) -> list[dict[str, Any]]:
        """Verifica e dispara auditorias com next_run_at expirado (usado pelo Celery Beat ou scheduler assíncrono)."""
        now = utcnow()
        # Busca agendamentos ativos vencidos
        stmt = (
            select(ScanSchedule)
            .where(
                ScanSchedule.is_active.is_(True),
                ScanSchedule.status == "ACTIVE",
                ScanSchedule.next_run_at <= now,
            )
            .with_for_update(skip_locked=True)
        )
        schedules = db.execute(stmt).scalars().all()
        dispatched_results: list[dict[str, Any]] = []

        from app.services.notification_service import NotificationService

        for sched in schedules:
            asset = db.scalar(select(Asset).where(Asset.id == sched.asset_id))
            if not asset or asset.authorization_status != "VERIFIED":
                # Alvo sem autorização válida: PAUSA agendamento e gera alerta de segurança
                sched.status = "FAILED_AUTH"
                sched.is_active = False
                sched.consecutive_failures += 1
                sched.updated_at = utcnow()
                db.flush()

                NotificationService().dispatch_event(
                    db=db,
                    organization_id=sched.organization_id,
                    event_type="schedule.failed",
                    severity="HIGH",
                    title="Agendamento Bloqueado: Autorização do Ativo Não Verificada",
                    message=(
                        f"O agendamento de auditoria para o ativo '{asset.name if asset else sched.asset_id}' "
                        f"foi interrompido pois o ativo não possui comprovação de autorização válida."
                    ),
                    metadata_json={"schedule_id": sched.id, "asset_id": sched.asset_id},
                )
                dispatched_results.append(
                    {
                        "schedule_id": sched.id,
                        "status": "BLOCKED_AUTH",
                        "reason": "Asset authorization is not VERIFIED",
                    }
                )
                continue

            # Valida concorrência: existe scan em andamento para o mesmo ativo?
            active_scan = db.scalar(
                select(Scan).where(
                    Scan.asset_id == sched.asset_id,
                    Scan.status.in_(["PENDING", "QUEUED", "RUNNING"]),
                )
            )
            if active_scan and sched.misfire_policy == "SKIP":
                # Concorrência detectada: se misfire_policy == "SKIP", pula este ciclo
                sched.next_run_at = CronSchedulerUtil.compute_next_run(
                    frequency=sched.frequency,
                    cron_expression=sched.cron_expression,
                    tz_name=sched.timezone,
                    base_time=now,
                )
                sched.updated_at = now
                db.flush()
                dispatched_results.append(
                    {
                        "schedule_id": sched.id,
                        "status": "SKIPPED_CONCURRENT",
                        "active_scan_id": active_scan.id,
                    }
                )
                continue

            # Cria a auditoria real
            try:
                scan = ScanOrchestrator.create_scan(
                    db=db,
                    organization_id=sched.organization_id,
                    asset_id=sched.asset_id,
                    user_id=sched.created_by_user_id or "system-scheduler",
                    profile_type=sched.profile_type,
                    enabled_modules=sched.enabled_modules if sched.enabled_modules else None,
                )
                scan.schedule_id = sched.id
                sched.last_scan_id = scan.id
                sched.last_run_at = now
                sched.consecutive_failures = 0

                # Próxima execução
                if sched.frequency == "ONCE":
                    sched.status = "COMPLETED"
                    sched.is_active = False
                    sched.next_run_at = None
                else:
                    sched.next_run_at = CronSchedulerUtil.compute_next_run(
                        frequency=sched.frequency,
                        cron_expression=sched.cron_expression,
                        tz_name=sched.timezone,
                        base_time=now,
                    )

                sched.updated_at = now
                db.flush()

                # Dispara notificação de início
                NotificationService().dispatch_event(
                    db=db,
                    organization_id=sched.organization_id,
                    event_type="scan.started",
                    severity="INFO",
                    title="Auditoria Recorrente Iniciada",
                    message=f"Auditoria programada disparada com sucesso para o ativo '{asset.name}'.",
                    link_url=f"/scans/{scan.id}",
                    metadata_json={"scan_id": scan.id, "schedule_id": sched.id, "asset_id": asset.id},
                )

                dispatched_results.append(
                    {
                        "schedule_id": sched.id,
                        "status": "DISPATCHED",
                        "scan_id": scan.id,
                    }
                )
            except Exception as e:
                logger.exception("Falha ao disparar auditoria para agendamento %s", sched.id)
                sched.consecutive_failures += 1
                sched.updated_at = now
                dispatched_results.append(
                    {
                        "schedule_id": sched.id,
                        "status": "ERROR",
                        "error": str(e),
                    }
                )

        db.commit()
        return dispatched_results

    @classmethod
    def _to_response(cls, s: ScanSchedule, asset_name: str | None = None) -> ScanScheduleResponse:
        return ScanScheduleResponse(
            id=s.id,
            organization_id=s.organization_id,
            asset_id=s.asset_id,
            asset_name=asset_name,
            profile_type=s.profile_type,
            enabled_modules=s.enabled_modules or [],
            frequency=s.frequency,
            cron_expression=s.cron_expression,
            timezone=s.timezone,
            status=s.status,
            is_active=s.is_active,
            misfire_policy=s.misfire_policy,
            consecutive_failures=s.consecutive_failures,
            last_run_at=s.last_run_at,
            next_run_at=s.next_run_at,
            last_scan_id=s.last_scan_id,
            created_by_user_id=s.created_by_user_id,
            created_at=s.created_at,
            updated_at=s.updated_at,
        )
