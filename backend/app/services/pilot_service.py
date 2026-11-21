"""Serviço de governança de piloto em ambiente próprio e expansão controlada para clientes."""

from __future__ import annotations

from datetime import timedelta
from typing import cast

from fastapi import HTTPException
from security_engine.core.evidence import EvidenceManager
from sqlalchemy.orm import Session

from app.api.deps import AuthenticatedPrincipal
from app.core.security import UserRole
from app.models.entities import Asset, PilotEnrollment, PilotReview, utcnow
from app.repositories.pilot import (
    count_asset_current_findings,
    count_asset_ssh_audits,
    find_pilot_with_asset,
    find_user_membership_in_org,
    has_valid_authorization_for_method,
    list_asset_availability_exercises,
    list_asset_enrollments,
    list_asset_telemetry_sources,
    list_asset_traffic_runs,
    list_asset_triage_statuses,
    list_pilots_with_assets,
    list_reviews_for_pilots,
    list_source_connection_timestamps,
    list_source_lifecycle_audit_actions,
)
from app.schemas.pilot import (
    PilotCoverageResponse,
    PilotEnrollmentCreate,
    PilotEnrollmentResponse,
    PilotEnrollmentUpdate,
    PilotFalsePositiveResponse,
    PilotLatencyResponse,
    PilotLifecycleChecklistResponse,
    PilotReadinessResponse,
    PilotReviewCreate,
    PilotReviewResponse,
)
from app.services.asset_service import AssetAuthorizationService
from app.services.audit_service import AuditLogService
from app.services.lab_authorization import require_authorized_lab_asset
from app.services.network_telemetry import _collector_status, _update_status
from app.services.pilot_logic import (
    PilotReviewDecision,
    PilotStage,
    SourceLifecycleInput,
    as_utc,
    cidr_within_allowed,
    effective_pilot_status,
    evaluate_pilot_readiness,
)

CLIENT_AUTH_METHODS: tuple[str, ...] = ("DNS_TXT", "HTTP_WELL_KNOWN")
LAB_AUTH_METHODS: tuple[str, ...] = ("LAB_INTERNAL",)


def _clean_text(value: str | None, max_chars: int = 500) -> str | None:
    if value is None:
        return None
    cleaned, _ = EvidenceManager.sanitize_text_snippet(value, max_chars=max_chars)
    return cleaned if cleaned else None


def _review_response(review: PilotReview) -> PilotReviewResponse:
    return PilotReviewResponse(
        id=review.id,
        pilot_id=review.pilot_id,
        organization_id=review.organization_id,
        decision=cast(PilotReviewDecision, review.decision),
        coverage_ok=review.coverage_ok,
        latency_ok=review.latency_ok,
        false_positives_ok=review.false_positives_ok,
        reviewer_user_id=review.reviewer_user_id,
        notes=review.notes,
        metrics_snapshot=dict(review.metrics_snapshot or {}),
        created_at=as_utc(review.created_at),
    )


def _enrollment_response(
    enrollment: PilotEnrollment,
    asset: Asset,
    latest_review: PilotReview | None = None,
) -> PilotEnrollmentResponse:
    now = utcnow()
    return PilotEnrollmentResponse(
        id=enrollment.id,
        organization_id=enrollment.organization_id,
        asset_id=enrollment.asset_id,
        asset_name=asset.name,
        asset_environment=asset.environment,
        asset_hostname=asset.hostname,
        stage=cast(PilotStage, enrollment.stage),
        status=effective_pilot_status(
            enrollment.status,
            enrollment.expires_at,
            enrollment.paused_at,
            enrollment.revoked_at,
            now,
        ),
        prerequisite_pilot_id=enrollment.prerequisite_pilot_id,
        allowed_cidrs=list(enrollment.allowed_cidrs or []),
        enabled_capabilities=list(enrollment.enabled_capabilities or []),
        max_sources=enrollment.max_sources,
        scope_notes=enrollment.scope_notes,
        expires_at=as_utc(enrollment.expires_at),
        paused_at=as_utc(enrollment.paused_at) if enrollment.paused_at else None,
        revoked_at=as_utc(enrollment.revoked_at) if enrollment.revoked_at else None,
        created_by_user_id=enrollment.created_by_user_id,
        created_at=as_utc(enrollment.created_at),
        updated_at=as_utc(enrollment.updated_at) if enrollment.updated_at else None,
        latest_review_decision=(
            cast(PilotReviewDecision, latest_review.decision) if latest_review else None
        ),
    )


def create_pilot_enrollment(
    db: Session, principal: AuthenticatedPrincipal, payload: PilotEnrollmentCreate
) -> PilotEnrollmentResponse:
    now = utcnow()
    asset_id = str(payload.asset_id)
    existing = list_asset_enrollments(db, principal.organization.id, asset_id)
    for item in existing:
        if (
            effective_pilot_status(
                item.status, item.expires_at, item.paused_at, item.revoked_at, now
            )
            in {"ACTIVE", "PAUSED"}
        ):
            raise HTTPException(
                409, "Já existe uma habilitação de piloto ativa ou pausada para este ativo."
            )

    allowed_cidrs = list(dict.fromkeys(str(net) for net in payload.allowed_cidrs))
    enabled_capabilities = list(dict.fromkeys(payload.enabled_capabilities))
    prereq_id: str | None = None

    if payload.stage == "OWN_ENVIRONMENT":
        asset = require_authorized_lab_asset(
            db, principal.organization.id, asset_id, lock_authorization=True
        )
    else:
        if principal.role != UserRole.ADMIN:
            raise HTTPException(
                403,
                "A habilitação de piloto para cliente autorizado requer perfil ADMIN.",
            )
        if payload.prerequisite_pilot_id is None:
            raise HTTPException(
                422,
                "Informe o piloto pré-requisito aprovado em ambiente próprio para habilitar cliente.",
            )
        prereq_id = str(payload.prerequisite_pilot_id)
        prereq = db.get(PilotEnrollment, prereq_id)
        if prereq is None or prereq.stage != "OWN_ENVIRONMENT":
            raise HTTPException(
                422, "Piloto pré-requisito em ambiente próprio não encontrado."
            )
        membership = find_user_membership_in_org(
            db, principal.user.id, prereq.organization_id
        )
        if membership is None or membership.role not in {
            UserRole.ADMIN.value,
            UserRole.SECURITY_ANALYST.value,
        }:
            raise HTTPException(
                403,
                "Sem permissão na organização do piloto pré-requisito para promover a expansão.",
            )
        prereq_reviews = list_reviews_for_pilots(db, [prereq.id]).get(prereq.id, [])
        if (
            not prereq_reviews
            or prereq_reviews[0].decision != "APPROVED_FOR_EXPANSION"
        ):
            raise HTTPException(
                422,
                "O piloto em ambiente próprio precisa de revisão aprovada (APPROVED_FOR_EXPANSION) antes de habilitar cliente.",
            )

        asset = AssetAuthorizationService.get_asset_or_404(
            db, principal.organization.id, asset_id
        )
        if asset.authorization_status != "VERIFIED" or not has_valid_authorization_for_method(
            db, principal.organization.id, asset.id, CLIENT_AUTH_METHODS, now
        ):
            raise HTTPException(
                403,
                "O ativo do cliente precisa de comprovação de autorização DNS_TXT ou HTTP_WELL_KNOWN vigente.",
            )
        if asset.environment == "PRODUCTION" and "AVAILABILITY" in enabled_capabilities:
            raise HTTPException(
                422,
                "A capacidade AVAILABILITY não pode ser habilitada para ativos de produção.",
            )

    enrollment = PilotEnrollment(
        organization_id=principal.organization.id,
        asset_id=asset.id,
        stage=payload.stage,
        status="ACTIVE",
        prerequisite_pilot_id=prereq_id,
        allowed_cidrs=allowed_cidrs,
        enabled_capabilities=enabled_capabilities,
        max_sources=payload.max_sources,
        scope_notes=_clean_text(payload.scope_notes, 500),
        expires_at=now + timedelta(days=payload.expires_in_days),
        created_by_user_id=principal.user.id,
        updated_at=now,
    )
    db.add(enrollment)
    db.flush()
    AuditLogService.record(
        db,
        action="PILOT_ENROLLMENT_CREATED",
        resource_type="pilot_enrollment",
        resource_id=enrollment.id,
        organization_id=principal.organization.id,
        user_id=principal.user.id,
        ip_address=principal.client_ip,
        metadata={
            "asset_id": asset.id,
            "stage": enrollment.stage,
            "allowed_cidrs": allowed_cidrs,
            "enabled_capabilities": enabled_capabilities,
            "max_sources": enrollment.max_sources,
            "prerequisite_pilot_id": prereq_id,
        },
    )
    response = _enrollment_response(enrollment, asset)
    db.commit()
    return response


def list_pilot_enrollments(
    db: Session, organization_id: str
) -> list[PilotEnrollmentResponse]:
    rows = list_pilots_with_assets(db, organization_id)
    reviews_map = list_reviews_for_pilots(db, [pilot.id for pilot, _ in rows])
    return [
        _enrollment_response(
            pilot, asset, (reviews_map.get(pilot.id) or [None])[0]
        )
        for pilot, asset in rows
    ]


def get_pilot_enrollment(
    db: Session, organization_id: str, pilot_id: str
) -> PilotEnrollmentResponse:
    found = find_pilot_with_asset(db, organization_id, pilot_id)
    if found is None:
        raise HTTPException(404, "Habilitação de piloto não encontrada.")
    pilot, asset = found
    reviews = list_reviews_for_pilots(db, [pilot.id]).get(pilot.id, [])
    return _enrollment_response(pilot, asset, reviews[0] if reviews else None)


def update_pilot_enrollment(
    db: Session,
    principal: AuthenticatedPrincipal,
    pilot_id: str,
    payload: PilotEnrollmentUpdate,
) -> PilotEnrollmentResponse:
    found = find_pilot_with_asset(db, principal.organization.id, pilot_id, lock=True)
    if found is None:
        raise HTTPException(404, "Habilitação de piloto não encontrada.")
    pilot, asset = found
    now = utcnow()
    current_status = effective_pilot_status(
        pilot.status, pilot.expires_at, pilot.paused_at, pilot.revoked_at, now
    )
    if current_status in {"REVOKED", "EXPIRED"}:
        raise HTTPException(409, "Não é possível atualizar um piloto revogado ou expirado.")

    sources = list_asset_telemetry_sources(db, asset.id)
    active_sources = [
        src for src in sources if _collector_status(src, now) in {"ACTIVE", "PAUSED"}
    ]

    if payload.allowed_cidrs is not None:
        new_cidrs = list(dict.fromkeys(str(net) for net in payload.allowed_cidrs))
        for src in active_sources:
            if not cidr_within_allowed(src.network, new_cidrs):
                raise HTTPException(
                    409,
                    "Os novos segmentos CIDR incompatibilizam uma fonte de telemetria ativa ou pausada.",
                )
        pilot.allowed_cidrs = new_cidrs

    if payload.max_sources is not None:
        if len(active_sources) > payload.max_sources:
            raise HTTPException(
                409,
                "O limite max_sources não pode ser menor que o total de fontes ativas ou pausadas.",
            )
        pilot.max_sources = payload.max_sources

    if payload.enabled_capabilities is not None:
        new_caps = list(dict.fromkeys(payload.enabled_capabilities))
        if asset.environment == "PRODUCTION" and "AVAILABILITY" in new_caps:
            raise HTTPException(
                422,
                "A capacidade AVAILABILITY não pode ser habilitada para ativos de produção.",
            )
        pilot.enabled_capabilities = new_caps

    if payload.scope_notes is not None:
        pilot.scope_notes = _clean_text(payload.scope_notes, 500)

    pilot.updated_at = now
    AuditLogService.record(
        db,
        action="PILOT_ENROLLMENT_UPDATED",
        resource_type="pilot_enrollment",
        resource_id=pilot.id,
        organization_id=principal.organization.id,
        user_id=principal.user.id,
        ip_address=principal.client_ip,
        metadata={
            "asset_id": asset.id,
            "allowed_cidrs": pilot.allowed_cidrs,
            "enabled_capabilities": pilot.enabled_capabilities,
            "max_sources": pilot.max_sources,
        },
    )
    reviews = list_reviews_for_pilots(db, [pilot.id]).get(pilot.id, [])
    response = _enrollment_response(pilot, asset, reviews[0] if reviews else None)
    db.commit()
    return response


def pause_pilot_enrollment(
    db: Session, principal: AuthenticatedPrincipal, pilot_id: str
) -> PilotEnrollmentResponse:
    found = find_pilot_with_asset(db, principal.organization.id, pilot_id, lock=True)
    if found is None:
        raise HTTPException(404, "Habilitação de piloto não encontrada.")
    pilot, asset = found
    now = utcnow()
    current_status = effective_pilot_status(
        pilot.status, pilot.expires_at, pilot.paused_at, pilot.revoked_at, now
    )
    if current_status in {"REVOKED", "EXPIRED"}:
        raise HTTPException(409, "Não é possível pausar um piloto revogado ou expirado.")
    if current_status != "PAUSED":
        pilot.status = "PAUSED"
        pilot.paused_at = now
        pilot.updated_at = now
        AuditLogService.record(
            db,
            action="PILOT_ENROLLMENT_PAUSED",
            resource_type="pilot_enrollment",
            resource_id=pilot.id,
            organization_id=principal.organization.id,
            user_id=principal.user.id,
            ip_address=principal.client_ip,
            metadata={"asset_id": asset.id},
        )
    reviews = list_reviews_for_pilots(db, [pilot.id]).get(pilot.id, [])
    response = _enrollment_response(pilot, asset, reviews[0] if reviews else None)
    db.commit()
    return response


def resume_pilot_enrollment(
    db: Session, principal: AuthenticatedPrincipal, pilot_id: str
) -> PilotEnrollmentResponse:
    found = find_pilot_with_asset(db, principal.organization.id, pilot_id, lock=True)
    if found is None:
        raise HTTPException(404, "Habilitação de piloto não encontrada.")
    pilot, asset = found
    now = utcnow()
    current_status = effective_pilot_status(
        pilot.status, pilot.expires_at, pilot.paused_at, pilot.revoked_at, now
    )
    if current_status in {"REVOKED", "EXPIRED"}:
        raise HTTPException(409, "Não é possível retomar um piloto revogado ou expirado.")

    methods = (
        LAB_AUTH_METHODS if pilot.stage == "OWN_ENVIRONMENT" else CLIENT_AUTH_METHODS
    )
    if asset.authorization_status != "VERIFIED" or not has_valid_authorization_for_method(
        db, principal.organization.id, asset.id, methods, now
    ):
        raise HTTPException(
            403,
            "Não é possível retomar o piloto sem autorização vigente do ativo.",
        )

    if current_status == "PAUSED":
        pilot.status = "ACTIVE"
        pilot.paused_at = None
        pilot.updated_at = now
        AuditLogService.record(
            db,
            action="PILOT_ENROLLMENT_RESUMED",
            resource_type="pilot_enrollment",
            resource_id=pilot.id,
            organization_id=principal.organization.id,
            user_id=principal.user.id,
            ip_address=principal.client_ip,
            metadata={"asset_id": asset.id},
        )
    reviews = list_reviews_for_pilots(db, [pilot.id]).get(pilot.id, [])
    response = _enrollment_response(pilot, asset, reviews[0] if reviews else None)
    db.commit()
    return response


def revoke_pilot_enrollment(
    db: Session, principal: AuthenticatedPrincipal, pilot_id: str
) -> PilotEnrollmentResponse:
    found = find_pilot_with_asset(db, principal.organization.id, pilot_id, lock=True)
    if found is None:
        raise HTTPException(404, "Habilitação de piloto não encontrada.")
    pilot, asset = found
    now = utcnow()
    if pilot.revoked_at is None:
        pilot.status = "REVOKED"
        pilot.revoked_at = now
        pilot.updated_at = now
        AuditLogService.record(
            db,
            action="PILOT_ENROLLMENT_REVOKED",
            resource_type="pilot_enrollment",
            resource_id=pilot.id,
            organization_id=principal.organization.id,
            user_id=principal.user.id,
            ip_address=principal.client_ip,
            metadata={"asset_id": asset.id},
        )
    reviews = list_reviews_for_pilots(db, [pilot.id]).get(pilot.id, [])
    response = _enrollment_response(pilot, asset, reviews[0] if reviews else None)
    db.commit()
    return response


def get_pilot_readiness(
    db: Session, organization_id: str, pilot_id: str
) -> PilotReadinessResponse:
    found = find_pilot_with_asset(db, organization_id, pilot_id)
    if found is None:
        raise HTTPException(404, "Habilitação de piloto não encontrada.")
    pilot, asset = found
    now = utcnow()

    pilot_status = effective_pilot_status(
        pilot.status, pilot.expires_at, pilot.paused_at, pilot.revoked_at, now
    )
    methods = (
        LAB_AUTH_METHODS if pilot.stage == "OWN_ENVIRONMENT" else CLIENT_AUTH_METHODS
    )
    auth_valid = (
        asset.authorization_status == "VERIFIED"
        and has_valid_authorization_for_method(db, organization_id, asset.id, methods, now)
    )

    sources = list_asset_telemetry_sources(db, asset.id)
    source_ids = [src.id for src in sources]
    source_inputs = [
        SourceLifecycleInput(
            status=_collector_status(src, now),
            has_reception=src.last_received_at is not None,
            update_status=_update_status(src),
            token_generation=src.token_generation,
        )
        for src in sources
    ]
    audit_actions = list_source_lifecycle_audit_actions(db, organization_id, source_ids)

    runs = list_asset_traffic_runs(db, asset.id)
    observed_layers_per_run = [list(r.observed_layers or []) for r in runs]
    benign_rotations_count = sum(r.benign_rotations_count for r in runs)
    suspicious_alerts_total = sum(r.alerts_count for r in runs)

    timestamps = list_source_connection_timestamps(db, source_ids)
    telemetry_delays = [
        (as_utc(received_at) - as_utc(observed_at)).total_seconds()
        for observed_at, received_at in timestamps
    ]

    exercises = list_asset_availability_exercises(db, asset.id)
    exercises_passed = sum(1 for ex in exercises if ex.result == "PASSED")
    alert_pub_ms = [
        ex.alert_publication_ms for ex in exercises if ex.alert_publication_ms is not None
    ]
    recovery_pub_ms = [
        ex.recovery_publication_ms
        for ex in exercises
        if ex.recovery_publication_ms is not None
    ]

    ssh_audits_count = count_asset_ssh_audits(db, asset.id)
    triage_statuses = list_asset_triage_statuses(db, organization_id, asset.id)
    findings_total, findings_fp = count_asset_current_findings(
        db, organization_id, asset.id
    )

    evaluation = evaluate_pilot_readiness(
        asset_authorization_valid=auth_valid,
        pilot_status=pilot_status,
        sources=source_inputs,
        audit_actions=audit_actions,
        traffic_runs_observed_layers=observed_layers_per_run,
        benign_rotations_count=benign_rotations_count,
        suspicious_alerts_total=suspicious_alerts_total,
        ssh_audits_count=ssh_audits_count,
        availability_exercises_total=len(exercises),
        availability_exercises_passed=exercises_passed,
        telemetry_delays_seconds=telemetry_delays,
        availability_alert_pub_ms=alert_pub_ms,
        availability_recovery_pub_ms=recovery_pub_ms,
        triage_review_statuses=triage_statuses,
        findings_total=findings_total,
        findings_false_positive_count=findings_fp,
    )

    reviews = list_reviews_for_pilots(db, [pilot.id]).get(pilot.id, [])
    return PilotReadinessResponse(
        pilot_id=pilot.id,
        asset_id=asset.id,
        stage=cast(PilotStage, pilot.stage),
        status=pilot_status,
        lifecycle=PilotLifecycleChecklistResponse(
            installation_demonstrated=evaluation.lifecycle.installation_demonstrated,
            pause_resume_demonstrated=evaluation.lifecycle.pause_resume_demonstrated,
            update_demonstrated=evaluation.lifecycle.update_demonstrated,
            revocation_demonstrated=evaluation.lifecycle.revocation_demonstrated,
            recovery_demonstrated=evaluation.lifecycle.recovery_demonstrated,
            all_demonstrated=evaluation.lifecycle.all_demonstrated,
        ),
        coverage=PilotCoverageResponse(
            total_sources=evaluation.coverage.total_sources,
            active_sources=evaluation.coverage.active_sources,
            paused_sources=evaluation.coverage.paused_sources,
            revoked_sources=evaluation.coverage.revoked_sources,
            up_to_date_sources=evaluation.coverage.up_to_date_sources,
            traffic_runs_count=evaluation.coverage.traffic_runs_count,
            observed_layers=list(evaluation.coverage.observed_layers),
            missing_layers=list(evaluation.coverage.missing_layers),
            layer_coverage_percent=evaluation.coverage.layer_coverage_percent,
            ssh_audits_count=evaluation.coverage.ssh_audits_count,
            availability_exercises_total=evaluation.coverage.availability_exercises_total,
            availability_exercises_passed=evaluation.coverage.availability_exercises_passed,
        ),
        latency=PilotLatencyResponse(
            telemetry_samples_count=evaluation.latency.telemetry_samples_count,
            telemetry_avg_delay_seconds=evaluation.latency.telemetry_avg_delay_seconds,
            telemetry_max_delay_seconds=evaluation.latency.telemetry_max_delay_seconds,
            availability_alert_pub_avg_ms=evaluation.latency.availability_alert_pub_avg_ms,
            availability_alert_pub_max_ms=evaluation.latency.availability_alert_pub_max_ms,
            availability_recovery_pub_avg_ms=evaluation.latency.availability_recovery_pub_avg_ms,
            availability_recovery_pub_max_ms=evaluation.latency.availability_recovery_pub_max_ms,
        ),
        false_positives=PilotFalsePositiveResponse(
            suspicious_alerts_total=evaluation.false_positives.suspicious_alerts_total,
            benign_tls_rotations_ignored=evaluation.false_positives.benign_tls_rotations_ignored,
            triage_suggestions_total=evaluation.false_positives.triage_suggestions_total,
            triage_approved_count=evaluation.false_positives.triage_approved_count,
            triage_rejected_count=evaluation.false_positives.triage_rejected_count,
            triage_pending_count=evaluation.false_positives.triage_pending_count,
            findings_total=evaluation.false_positives.findings_total,
            findings_false_positive_count=evaluation.false_positives.findings_false_positive_count,
            findings_false_positive_rate_percent=evaluation.false_positives.findings_false_positive_rate_percent,
        ),
        blocking_reasons=list(evaluation.blocking_reasons),
        ready_for_expansion_approval=evaluation.ready_for_expansion_approval,
        latest_review=_review_response(reviews[0]) if reviews else None,
    )


def record_pilot_review(
    db: Session,
    principal: AuthenticatedPrincipal,
    pilot_id: str,
    payload: PilotReviewCreate,
) -> PilotReviewResponse:
    readiness = get_pilot_readiness(db, principal.organization.id, pilot_id)
    if payload.decision == "APPROVED_FOR_EXPANSION":
        if not readiness.ready_for_expansion_approval:
            raise HTTPException(
                422,
                "Piloto não atende aos critérios de prontidão: "
                + " | ".join(readiness.blocking_reasons),
            )
        if not (
            payload.coverage_ok
            and payload.latency_ok
            and payload.false_positives_ok
        ):
            raise HTTPException(
                422,
                "A aprovação requer confirmação explícita de cobertura, latência e falsos positivos.",
            )

    review = PilotReview(
        pilot_id=pilot_id,
        organization_id=principal.organization.id,
        decision=payload.decision,
        coverage_ok=payload.coverage_ok,
        latency_ok=payload.latency_ok,
        false_positives_ok=payload.false_positives_ok,
        reviewer_user_id=principal.user.id,
        notes=_clean_text(payload.notes, 500),
        metrics_snapshot=readiness.model_dump(mode="json", exclude={"latest_review"}),
    )
    db.add(review)
    db.flush()
    AuditLogService.record(
        db,
        action="PILOT_REVIEW_RECORDED",
        resource_type="pilot_review",
        resource_id=review.id,
        organization_id=principal.organization.id,
        user_id=principal.user.id,
        ip_address=principal.client_ip,
        metadata={
            "pilot_id": pilot_id,
            "decision": review.decision,
            "coverage_ok": review.coverage_ok,
            "latency_ok": review.latency_ok,
            "false_positives_ok": review.false_positives_ok,
        },
    )
    response = _review_response(review)
    db.commit()
    return response


def list_pilot_reviews(
    db: Session, organization_id: str, pilot_id: str
) -> list[PilotReviewResponse]:
    found = find_pilot_with_asset(db, organization_id, pilot_id)
    if found is None:
        raise HTTPException(404, "Habilitação de piloto não encontrada.")
    reviews = list_reviews_for_pilots(db, [pilot_id]).get(pilot_id, [])
    return [_review_response(review) for review in reviews]
