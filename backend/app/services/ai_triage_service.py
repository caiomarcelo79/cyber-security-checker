"""Serviço de triagem assistida por IA sobre evidências sanitizadas com fallback resiliente."""

from __future__ import annotations

import logging
from ipaddress import ip_address
from typing import Any, cast
from urllib.parse import urlparse

import httpx
from fastapi import HTTPException
from security_engine.core.evidence import EvidenceManager
from security_engine.policies.scope_validator import CLOUD_METADATA_HOSTS, CLOUD_METADATA_IPS
from sqlalchemy.orm import Session

from app.api.deps import AuthenticatedPrincipal
from app.core.config import get_settings
from app.models.entities import (
    AiTriageSuggestion,
    FindingRecord,
    SuspiciousTrafficAlert,
    TrafficAnalysisRun,
    utcnow,
)
from app.repositories.ai_triage import (
    find_scoped_finding,
    find_scoped_suggestion,
    find_scoped_traffic_alert,
    get_latest_suggestion_for_alert,
    get_latest_suggestion_for_finding,
)
from app.schemas.ai_triage import (
    AiTriageReviewRequest,
    AiTriageSuggestionResponse,
    EvidenceCitationResponse,
)
from app.services.ai_triage_logic import (
    DETERMINISTIC_MODEL_NAME,
    AiAvailabilityStatus,
    GeneratedTriageDraft,
    RecommendedAction,
    TriageContext,
    TriageGenerationMode,
    TriageReviewStatus,
    TriageTargetType,
    build_deterministic_suggestion,
    compute_evidence_hash,
    sanitize_evidence_payload,
    validate_grounded_draft,
)
from app.services.audit_service import AuditLogService
from app.services.suspicious_traffic_logic import as_utc

logger = logging.getLogger(__name__)


def _is_safe_provider_url(endpoint_url: str) -> bool:
    parsed = urlparse(endpoint_url.strip())
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return False
    host = parsed.hostname.lower()
    if host in CLOUD_METADATA_HOSTS or host in CLOUD_METADATA_IPS:
        return False
    try:
        ip_val = ip_address(host)
    except ValueError:
        return True
    return not ip_val.is_link_local and not ip_val.is_multicast


def invoke_ai_provider(ctx: TriageContext) -> tuple[dict[str, Any] | None, AiAvailabilityStatus, str]:
    """Consulta provedor de IA opcional enviando apenas contexto e evidência já sanitizados."""
    settings = get_settings()
    endpoint = settings.ai_triage_endpoint_url.strip()
    if not settings.ai_triage_enabled or not endpoint:
        return None, "UNCONFIGURED", DETERMINISTIC_MODEL_NAME

    model_name = settings.ai_triage_model.strip() or "ai-provider"
    if not _is_safe_provider_url(endpoint):
        logger.warning("Endpoint de triagem IA bloqueado pela política de destino: %s", endpoint)
        return None, "UNAVAILABLE", model_name

    evidence_hash = compute_evidence_hash(ctx.sanitized_evidence)
    payload = {
        "model": model_name,
        "target_type": ctx.target_type,
        "rule_or_check_id": ctx.rule_or_check_id,
        "category": ctx.category,
        "title": ctx.title,
        "severity": ctx.severity,
        "confidence": ctx.confidence,
        "description": ctx.description_or_explanation,
        "sanitized_evidence": ctx.sanitized_evidence,
        "evidence_hash": evidence_hash,
        "observed_layers": list(ctx.observed_layers),
        "missing_layers": list(ctx.missing_layers),
        "remediation_hint_steps": list(ctx.remediation_hint_steps),
    }
    headers = {"Content-Type": "application/json"}
    if settings.ai_triage_api_key.strip():
        headers["Authorization"] = f"Bearer {settings.ai_triage_api_key.strip()}"

    try:
        response = httpx.post(
            endpoint,
            json=payload,
            headers=headers,
            timeout=settings.ai_triage_timeout_seconds,
            follow_redirects=False,
        )
        if response.status_code >= 400:
            logger.warning("Provedor de IA respondeu HTTP %s; acionando fallback.", response.status_code)
            return None, "UNAVAILABLE", model_name
        data = response.json()
        if not isinstance(data, dict):
            return None, "INVALID_OUTPUT_FALLBACK", model_name
        return data, "AVAILABLE", str(data.get("model_name") or model_name)
    except (httpx.HTTPError, ValueError, TypeError) as exc:
        logger.warning("Provedor de IA indisponível (%s); acionando fallback determinístico.", exc)
        return None, "UNAVAILABLE", model_name


def _generate_draft(ctx: TriageContext) -> GeneratedTriageDraft:
    evidence_hash = compute_evidence_hash(ctx.sanitized_evidence)
    raw_ai, ai_status, model_name = invoke_ai_provider(ctx)
    if raw_ai is not None:
        grounded = validate_grounded_draft(
            raw_ai,
            ctx.sanitized_evidence,
            model_name=model_name,
            evidence_hash=evidence_hash,
        )
        if grounded is not None:
            return grounded
        ai_status = "INVALID_OUTPUT_FALLBACK"
    return build_deterministic_suggestion(ctx, ai_status=ai_status)


def _to_response(record: AiTriageSuggestion) -> AiTriageSuggestionResponse:
    return AiTriageSuggestionResponse(
        id=record.id,
        organization_id=record.organization_id,
        asset_id=record.asset_id,
        target_type=cast(TriageTargetType, record.target_type),
        traffic_alert_id=record.traffic_alert_id,
        finding_id=record.finding_id,
        generation_mode=cast(TriageGenerationMode, record.generation_mode),
        ai_status=cast(AiAvailabilityStatus, record.ai_status),
        model_name=record.model_name,
        summary=record.summary,
        explanation=record.explanation,
        recommended_action=cast(RecommendedAction, record.recommended_action),
        remediation_steps=list(record.remediation_steps or []),
        evidence_citations=[
            EvidenceCitationResponse(field=item["field"], value_excerpt=item["value_excerpt"])
            for item in (record.evidence_citations or [])
        ],
        sanitized_evidence_hash=record.sanitized_evidence_hash,
        review_status=cast(TriageReviewStatus, record.review_status),
        requires_analyst_review=record.review_status == "PENDING_REVIEW",
        reviewer_user_id=record.reviewer_user_id,
        reviewer_notes=record.reviewer_notes,
        reviewed_at=as_utc(record.reviewed_at) if record.reviewed_at else None,
        created_at=as_utc(record.created_at),
    )


def _persist_suggestion(
    db: Session,
    principal: AuthenticatedPrincipal,
    *,
    asset_id: str,
    target_type: TriageTargetType,
    draft: GeneratedTriageDraft,
    traffic_alert_id: str | None = None,
    finding_id: str | None = None,
) -> AiTriageSuggestionResponse:
    record = AiTriageSuggestion(
        organization_id=principal.organization.id,
        asset_id=asset_id,
        target_type=target_type,
        traffic_alert_id=traffic_alert_id,
        finding_id=finding_id,
        generation_mode=draft.generation_mode,
        ai_status=draft.ai_status,
        model_name=draft.model_name,
        summary=draft.summary,
        explanation=draft.explanation,
        recommended_action=draft.recommended_action,
        remediation_steps=list(draft.remediation_steps),
        evidence_citations=[
            {"field": cit.field, "value_excerpt": cit.value_excerpt}
            for cit in draft.evidence_citations
        ],
        sanitized_evidence_hash=draft.sanitized_evidence_hash,
        review_status="PENDING_REVIEW",
        created_at=utcnow(),
    )
    db.add(record)
    db.flush()
    AuditLogService.record(
        db,
        action="AI_TRIAGE_SUGGESTION_GENERATED",
        resource_type="ai_triage_suggestion",
        resource_id=record.id,
        organization_id=principal.organization.id,
        user_id=principal.user.id,
        ip_address=principal.client_ip,
        metadata={
            "asset_id": asset_id,
            "target_type": target_type,
            "traffic_alert_id": traffic_alert_id,
            "finding_id": finding_id,
            "generation_mode": draft.generation_mode,
            "ai_status": draft.ai_status,
            "citations_count": len(draft.evidence_citations),
        },
    )
    db.commit()
    return _to_response(record)


def _context_from_traffic_alert(alert: SuspiciousTrafficAlert, run: TrafficAnalysisRun) -> TriageContext:
    return TriageContext(
        target_type="TRAFFIC_ALERT",
        rule_or_check_id=alert.rule_id,
        category=alert.category,
        title=alert.title,
        severity=alert.severity,
        confidence=alert.confidence,
        description_or_explanation=alert.explanation,
        sanitized_evidence=sanitize_evidence_payload(alert.evidence or {}),
        observed_layers=tuple(alert.observed_layers or run.observed_layers or ()),
        missing_layers=tuple(alert.missing_layers or run.missing_layers or ()),
    )


def _context_from_finding(finding: FindingRecord) -> TriageContext:
    rem_data = finding.remediation_data or {}
    hint_steps: list[str] = []
    for key in ("how_to_fix", "how_to_validate"):
        val = rem_data.get(key)
        if isinstance(val, str) and val.strip():
            hint_steps.append(val.strip())
    return TriageContext(
        target_type="FINDING",
        rule_or_check_id=finding.check_id,
        category=finding.category,
        title=finding.title,
        severity=finding.severity,
        confidence=finding.confidence,
        description_or_explanation=finding.description,
        sanitized_evidence=sanitize_evidence_payload(finding.evidence or {}),
        remediation_hint_title=finding.category,
        remediation_hint_steps=tuple(hint_steps),
        is_potential_finding=finding.result_classification == "POTENTIAL_VULNERABILITY",
    )


def generate_traffic_alert_suggestion(
    db: Session,
    principal: AuthenticatedPrincipal,
    asset_id: str,
    run_id: str,
    alert_id: str,
) -> AiTriageSuggestionResponse:
    found = find_scoped_traffic_alert(db, principal.organization.id, asset_id, run_id, alert_id)
    if found is None:
        raise HTTPException(404, "Alerta de tráfego suspeito não encontrado.")
    alert, run = found
    draft = _generate_draft(_context_from_traffic_alert(alert, run))
    return _persist_suggestion(
        db,
        principal,
        asset_id=run.asset_id,
        target_type="TRAFFIC_ALERT",
        draft=draft,
        traffic_alert_id=alert.id,
    )


def get_traffic_alert_suggestion(
    db: Session,
    organization_id: str,
    asset_id: str,
    run_id: str,
    alert_id: str,
) -> AiTriageSuggestionResponse | None:
    found = find_scoped_traffic_alert(db, organization_id, asset_id, run_id, alert_id)
    if found is None:
        raise HTTPException(404, "Alerta de tráfego suspeito não encontrado.")
    alert, _ = found
    latest = get_latest_suggestion_for_alert(db, organization_id, alert.id)
    return _to_response(latest) if latest is not None else None


def generate_finding_suggestion(
    db: Session,
    principal: AuthenticatedPrincipal,
    finding_id: str,
) -> AiTriageSuggestionResponse:
    finding = find_scoped_finding(db, principal.organization.id, finding_id)
    if finding is None:
        raise HTTPException(404, "Vulnerabilidade não encontrada na organização ativa.")
    draft = _generate_draft(_context_from_finding(finding))
    return _persist_suggestion(
        db,
        principal,
        asset_id=finding.asset_id,
        target_type="FINDING",
        draft=draft,
        finding_id=finding.id,
    )


def get_finding_suggestion(
    db: Session,
    organization_id: str,
    finding_id: str,
) -> AiTriageSuggestionResponse | None:
    finding = find_scoped_finding(db, organization_id, finding_id)
    if finding is None:
        raise HTTPException(404, "Vulnerabilidade não encontrada na organização ativa.")
    latest = get_latest_suggestion_for_finding(db, organization_id, finding.id)
    return _to_response(latest) if latest is not None else None


def review_triage_suggestion(
    db: Session,
    principal: AuthenticatedPrincipal,
    suggestion_id: str,
    payload: AiTriageReviewRequest,
) -> AiTriageSuggestionResponse:
    record = find_scoped_suggestion(db, principal.organization.id, suggestion_id)
    if record is None:
        raise HTTPException(404, "Sugestão de triagem assistida não encontrada.")

    clean_notes: str | None = None
    if payload.reviewer_notes is not None:
        cleaned, _ = EvidenceManager.sanitize_text_snippet(payload.reviewer_notes, max_chars=1000)
        clean_notes = (cleaned or "").strip() or None

    record.review_status = payload.decision
    record.reviewer_user_id = principal.user.id
    record.reviewer_notes = clean_notes
    record.reviewed_at = utcnow()
    db.flush()
    AuditLogService.record(
        db,
        action="AI_TRIAGE_SUGGESTION_REVIEWED",
        resource_type="ai_triage_suggestion",
        resource_id=record.id,
        organization_id=principal.organization.id,
        user_id=principal.user.id,
        ip_address=principal.client_ip,
        metadata={
            "decision": payload.decision,
            "target_type": record.target_type,
            "asset_id": record.asset_id,
            "traffic_alert_id": record.traffic_alert_id,
            "finding_id": record.finding_id,
        },
    )
    db.commit()
    return _to_response(record)
