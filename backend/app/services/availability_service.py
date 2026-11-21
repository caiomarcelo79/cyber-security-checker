"""Orquestra o exercício de disponibilidade: amostras, alertas e classificação."""

from datetime import UTC, datetime, timedelta
from typing import cast

from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.deps import AuthenticatedPrincipal
from app.models.entities import (
    Asset,
    AvailabilityExercise,
    AvailabilitySample,
    AvailabilitySignal,
    utcnow,
)
from app.repositories.availability import (
    find_exercise,
    find_running_exercises,
    list_exercises,
    list_samples,
    list_signals,
)
from app.schemas.availability import (
    MAX_SIGNALS,
    AvailabilityExerciseCreate,
    AvailabilityExerciseResponse,
    AvailabilityMetricsSummary,
    AvailabilitySampleCreate,
    AvailabilitySampleResponse,
    AvailabilitySignalCreate,
    AvailabilitySignalResponse,
    TimelineEvent,
)
from app.services.asset_service import AssetAuthorizationService
from app.services.audit_service import AuditLogService
from app.services.availability_logic import (
    Analysis,
    EdgeSignalCode,
    EdgeSourceType,
    ExercisePlan,
    ExerciseResult,
    ExerciseScenario,
    SampleOutcome,
    SampleView,
    analyze_samples,
    grade_exercise,
    summarize_samples,
)
from app.services.lab_authorization import require_authorized_operational_asset
from app.services.notification_service import NotificationService

ALERT_EVENT = "AVAILABILITY_DEGRADATION_SIMULATED"
RECOVERY_EVENT = "AVAILABILITY_RECOVERY_SIMULATED"
STALE_AFTER = timedelta(minutes=20)


def _as_utc(timestamp: datetime) -> datetime:
    return timestamp.astimezone(UTC) if timestamp.tzinfo else timestamp.replace(tzinfo=UTC)


def _plan(exercise: AvailabilityExercise) -> ExercisePlan:
    return ExercisePlan(
        threshold_ms=exercise.threshold_ms,
        consecutive_samples=exercise.consecutive_samples,
        interval_ms=exercise.interval_ms,
        normal_ms=exercise.normal_ms,
        degraded_ms=exercise.degraded_ms,
    )


def _views(samples: list[AvailabilitySample]) -> list[SampleView]:
    return [
        SampleView(s.offset_ms, s.latency_ms, cast(SampleOutcome, s.outcome), s.http_status)
        for s in samples
    ]


def _timeline(plan: ExercisePlan, analysis: Analysis) -> list[TimelineEvent]:
    pairs = (
        ("DEGRADATION_START", plan.normal_ms, analysis.first_violation_offset_ms),
        ("ALERT_OPENED", plan.expected_alert_ms, analysis.alert_offset_ms),
        ("RECOVERY_START", plan.expected_recovery_start_ms, analysis.recovery_start_offset_ms),
        ("RECOVERY_DETECTED", plan.expected_recovery_ms, analysis.recovery_offset_ms),
    )
    return [
        TimelineEvent(
            event=event,  # type: ignore[arg-type]
            expected_offset_ms=expected,
            observed_offset_ms=observed,
            delta_ms=None if observed is None else observed - expected,
        )
        for event, expected, observed in pairs
    ]


def _response(
    exercise: AvailabilityExercise,
    asset: Asset,
    samples: list[AvailabilitySample],
    signals: list[AvailabilitySignal],
    *,
    detail: bool,
) -> AvailabilityExerciseResponse:
    plan = _plan(exercise)
    views = _views(samples)
    analysis = analyze_samples(views, plan)
    summary = summarize_samples(views)
    return AvailabilityExerciseResponse(
        id=exercise.id,
        status=cast("str", exercise.status),  # type: ignore[arg-type]
        scenario=cast(ExerciseScenario, exercise.scenario),
        state=analysis.state,
        result=cast("ExerciseResult | None", exercise.result),
        hostname=asset.hostname,
        threshold_ms=plan.threshold_ms,
        consecutive_samples=plan.consecutive_samples,
        interval_ms=plan.interval_ms,
        normal_ms=plan.normal_ms,
        degraded_ms=plan.degraded_ms,
        planned_duration_ms=plan.planned_duration_ms,
        tolerance_ms=plan.tolerance_ms,
        sample_count=len(samples),
        metrics_summary=AvailabilityMetricsSummary(
            peak_latency_ms=summary.peak_latency_ms,
            error_5xx_count=summary.error_5xx_count,
            rate_limited_429_count=summary.rate_limited_429_count,
            timeout_or_connection_error_count=summary.timeout_or_connection_error_count,
        ),
        timeline=_timeline(plan, analysis),
        signals=[
            AvailabilitySignalResponse(
                id=sig.id,
                source_type=cast(EdgeSourceType, sig.source_type),
                signal=cast(EdgeSignalCode, sig.signal),
                offset_ms=sig.offset_ms,
                http_status=sig.http_status,
                created_at=_as_utc(sig.created_at),
            )
            for sig in signals
        ],
        alert_publication_ms=exercise.alert_publication_ms,
        recovery_publication_ms=exercise.recovery_publication_ms,
        started_at=_as_utc(exercise.started_at),
        finished_at=_as_utc(exercise.finished_at) if exercise.finished_at else None,
        samples=(
            [
                AvailabilitySampleResponse(
                    seq=s.seq,
                    offset_ms=s.offset_ms,
                    latency_ms=s.latency_ms,
                    outcome=cast(SampleOutcome, s.outcome),
                    http_status=s.http_status,
                )
                for s in samples
            ]
            if detail
            else None
        ),
    )


def _get_exercise(db: Session, asset: Asset, exercise_id: str) -> AvailabilityExercise:
    exercise = find_exercise(db, asset.id, exercise_id)
    if exercise is None:
        raise HTTPException(404, "Exercício de disponibilidade não encontrado.")
    return exercise


def list_asset_exercises(
    db: Session, organization_id: str, asset_id: str
) -> list[AvailabilityExerciseResponse]:
    asset = AssetAuthorizationService.get_asset_or_404(db, organization_id, asset_id)
    return [
        _response(e, asset, list_samples(db, e.id), list_signals(db, e.id), detail=False)
        for e in list_exercises(db, asset.id)
    ]


def get_asset_exercise(
    db: Session, organization_id: str, asset_id: str, exercise_id: str
) -> AvailabilityExerciseResponse:
    asset = AssetAuthorizationService.get_asset_or_404(db, organization_id, asset_id)
    exercise = _get_exercise(db, asset, exercise_id)
    return _response(exercise, asset, list_samples(db, exercise.id), list_signals(db, exercise.id), detail=True)


def _require_availability_asset(
    db: Session, organization_id: str, asset_id: str
) -> Asset:
    asset, _ = require_authorized_operational_asset(
        db, organization_id, asset_id, capability="AVAILABILITY", lock_authorization=True
    )
    if asset.environment == "PRODUCTION":
        raise HTTPException(
            403,
            "Exercícios sintéticos de disponibilidade não são permitidos em ativos de produção.",
        )
    return asset


def start_exercise(
    db: Session, principal: AuthenticatedPrincipal, asset_id: str, payload: AvailabilityExerciseCreate
) -> AvailabilityExerciseResponse:
    asset = _require_availability_asset(db, principal.organization.id, asset_id)
    now = utcnow()
    for running in find_running_exercises(db, asset.id):
        if now - _as_utc(running.started_at) < STALE_AFTER:
            raise HTTPException(409, "Já existe um exercício de disponibilidade em andamento para este ativo.")
        running.status, running.result, running.finished_at = "FINISHED", "EXECUTION_ERROR", now

    exercise = AvailabilityExercise(
        asset_id=asset.id, created_by_user_id=principal.user.id, started_at=now, **payload.model_dump()
    )
    db.add(exercise)
    db.flush()
    AuditLogService.record(
        db,
        action="AVAILABILITY_EXERCISE_STARTED",
        resource_type="availability_exercise",
        resource_id=exercise.id,
        organization_id=principal.organization.id,
        user_id=principal.user.id,
        ip_address=principal.client_ip,
        metadata={"asset_id": asset.id, **payload.model_dump()},
    )
    db.commit()
    return _response(exercise, asset, [], [], detail=False)


def _publish(
    db: Session,
    exercise: AvailabilityExercise,
    organization_id: str,
    *,
    event_type: str,
    severity: str,
    title: str,
    message: str,
    received_at: datetime,
    offset_ms: int,
) -> tuple[str, int]:
    notification = NotificationService().dispatch_event(
        db=db,
        organization_id=organization_id,
        user_id=exercise.created_by_user_id,
        event_type=event_type,
        severity=severity,
        title=title,
        message=message,
        metadata_json={
            "exercise_id": exercise.id,
            "asset_id": exercise.asset_id,
            "synthetic": True,
            "offset_ms": offset_ms,
        },
        dedup_window_seconds=0,
        publish_external=False,
    )
    if notification is None:
        raise HTTPException(500, "Não foi possível publicar a notificação do exercício.")
    elapsed = _as_utc(notification.created_at) - received_at
    return notification.id, max(0, int(elapsed.total_seconds() * 1000))


def record_sample(
    db: Session,
    principal: AuthenticatedPrincipal,
    asset_id: str,
    exercise_id: str,
    payload: AvailabilitySampleCreate,
) -> AvailabilityExerciseResponse:
    received_at = utcnow()
    asset = _require_availability_asset(db, principal.organization.id, asset_id)
    exercise = _get_exercise(db, asset, exercise_id)
    if exercise.created_by_user_id != principal.user.id:
        raise HTTPException(403, "Somente quem iniciou o exercício pode enviar amostras.")
    if exercise.status != "RUNNING":
        raise HTTPException(409, "O exercício já foi encerrado.")

    existing = list_samples(db, exercise.id)
    if payload.seq != len(existing):
        raise HTTPException(409, "Sequência de amostra inesperada.")
    if existing and payload.offset_ms < existing[-1].offset_ms:
        raise HTTPException(422, "O deslocamento da amostra não pode retroceder.")

    sample = AvailabilitySample(exercise_id=exercise.id, **payload.model_dump())
    db.add(sample)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "Amostra duplicada.") from exc
    samples = [*existing, sample]

    plan = _plan(exercise)
    analysis = analyze_samples(_views(samples), plan)
    if analysis.alert_offset_ms is not None and exercise.alert_notification_id is None:
        exercise.alert_notification_id, exercise.alert_publication_ms = _publish(
            db,
            exercise,
            principal.organization.id,
            event_type=ALERT_EVENT,
            severity="HIGH",
            title="[Exercício] Degradação sintética de disponibilidade",
            message=(
                f"{plan.consecutive_samples} amostras consecutivas violaram o cenário {exercise.scenario} "
                f"(limiar {plan.threshold_ms} ms) em {asset.hostname}."
            ),
            received_at=received_at,
            offset_ms=analysis.alert_offset_ms,
        )
    if analysis.recovery_offset_ms is not None and exercise.recovery_notification_id is None:
        exercise.recovery_notification_id, exercise.recovery_publication_ms = _publish(
            db,
            exercise,
            principal.organization.id,
            event_type=RECOVERY_EVENT,
            severity="INFO",
            title="[Exercício] Recuperação sintética de disponibilidade",
            message=(
                f"{plan.consecutive_samples} amostras consecutivas dentro do limiar de "
                f"{plan.threshold_ms} ms em {asset.hostname}."
            ),
            received_at=received_at,
            offset_ms=analysis.recovery_offset_ms,
        )
    signals = list_signals(db, exercise.id)
    db.commit()
    return _response(exercise, asset, samples, signals, detail=False)


def record_signal(
    db: Session,
    principal: AuthenticatedPrincipal,
    asset_id: str,
    exercise_id: str,
    payload: AvailabilitySignalCreate,
) -> AvailabilityExerciseResponse:
    asset = _require_availability_asset(db, principal.organization.id, asset_id)
    exercise = _get_exercise(db, asset, exercise_id)
    if exercise.created_by_user_id != principal.user.id:
        raise HTTPException(403, "Somente quem iniciou o exercício pode registrar sinais.")
    if exercise.status != "RUNNING":
        raise HTTPException(409, "O exercício já foi encerrado.")

    existing_signals = list_signals(db, exercise.id)
    if len(existing_signals) >= MAX_SIGNALS:
        raise HTTPException(409, "Limite máximo de sinais atingido para este exercício.")

    signal = AvailabilitySignal(exercise_id=exercise.id, **payload.model_dump())
    db.add(signal)
    db.flush()
    AuditLogService.record(
        db,
        action="AVAILABILITY_SIGNAL_RECORDED",
        resource_type="availability_signal",
        resource_id=signal.id,
        organization_id=principal.organization.id,
        user_id=principal.user.id,
        ip_address=principal.client_ip,
        metadata={"asset_id": asset.id, "exercise_id": exercise.id, **payload.model_dump()},
    )
    samples = list_samples(db, exercise.id)
    db.commit()
    return _response(exercise, asset, samples, [*existing_signals, signal], detail=False)


def finish_exercise(
    db: Session, principal: AuthenticatedPrincipal, asset_id: str, exercise_id: str
) -> AvailabilityExerciseResponse:
    asset = _require_availability_asset(db, principal.organization.id, asset_id)
    exercise = _get_exercise(db, asset, exercise_id)
    if exercise.created_by_user_id != principal.user.id:
        raise HTTPException(403, "Somente quem iniciou o exercício pode encerrá-lo.")
    if exercise.status != "RUNNING":
        raise HTTPException(409, "O exercício já foi encerrado.")

    samples = list_samples(db, exercise.id)
    signals = list_signals(db, exercise.id)
    plan = _plan(exercise)
    analysis = analyze_samples(_views(samples), plan)
    exercise.result = grade_exercise(_views(samples), plan, analysis)
    exercise.status = "FINISHED"
    exercise.finished_at = utcnow()
    AuditLogService.record(
        db,
        action="AVAILABILITY_EXERCISE_FINISHED",
        resource_type="availability_exercise",
        resource_id=exercise.id,
        organization_id=principal.organization.id,
        user_id=principal.user.id,
        ip_address=principal.client_ip,
        metadata={"asset_id": asset.id, "result": exercise.result, "sample_count": len(samples)},
    )
    db.commit()
    return _response(exercise, asset, samples, signals, detail=True)
