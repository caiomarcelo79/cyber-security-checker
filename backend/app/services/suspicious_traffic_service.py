"""Serviço de ingestão e análise explicável de tráfego suspeito em laboratório."""

from ipaddress import ip_network
from typing import Any, cast

from fastapi import HTTPException
from security_engine.core.evidence import SENSITIVE_HEADER_NAMES, SENSITIVE_QUERY_KEYS, EvidenceManager
from sqlalchemy.orm import Session

from app.models.entities import (
    Asset,
    SuspiciousTrafficAlert,
    TelemetryConnection,
    TelemetryTlsBaseline,
    TrafficAnalysisRun,
    TrafficEdrSignal,
    TrafficTlsDecision,
    utcnow,
)
from app.repositories.network_telemetry import existing_uids
from app.repositories.suspicious_traffic import (
    find_analysis_run,
    list_analysis_runs,
    list_run_alerts,
    list_run_edr_signals,
    list_run_tls_decisions,
    load_tls_baselines,
)
from app.schemas.suspicious_traffic import (
    SuspiciousTrafficAlertResponse,
    TrafficAnalysisBatch,
    TrafficAnalysisRunResponse,
    TrafficCoverageResponse,
    TrafficEdrSignalResponse,
    TrafficTlsDecisionResponse,
)
from app.services.asset_service import AssetAuthorizationService
from app.services.audit_service import AuditLogService
from app.services.network_telemetry import require_collector_source
from app.services.suspicious_traffic_logic import (
    AlertCategory,
    AlertConfidence,
    AlertSeverity,
    ConnectionEvent,
    DnsEvent,
    EdrSignalCode,
    EdrSignalEvent,
    EdrSourceType,
    TlsBaselineState,
    TlsDecisionOutcome,
    TlsEvent,
    as_utc,
    evaluate_traffic_batch,
)


def _sanitize_value(value: Any) -> Any:
    if isinstance(value, str):
        cleaned, _ = EvidenceManager.sanitize_text_snippet(value, max_chars=512)
        return cleaned if cleaned is not None else ""
    if isinstance(value, list):
        return [_sanitize_value(item) for item in value]
    if isinstance(value, dict):
        return _sanitize_evidence(value)
    return value


def _sanitize_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    sanitized: dict[str, Any] = {}
    for key, val in evidence.items():
        lower_key = str(key).lower().strip()
        if lower_key in SENSITIVE_QUERY_KEYS or lower_key in SENSITIVE_HEADER_NAMES:
            sanitized[key] = "[REDACTED]"
        else:
            sanitized[key] = _sanitize_value(val)
    return sanitized


def _clean_text(value: str | None, max_chars: int) -> str | None:
    if value is None:
        return None
    cleaned, _ = EvidenceManager.sanitize_text_snippet(value, max_chars=max_chars)
    return cleaned if cleaned is not None else ""


def _validate_batch_scope(network_cidr: str, batch: TrafficAnalysisBatch) -> None:
    network = ip_network(network_cidr)
    for conn in batch.connections:
        if conn.origin_ip not in network and conn.responder_ip not in network:
            raise HTTPException(422, "O lote contém conexão fora do segmento autorizado.")
    for dns in batch.dns_queries:
        if dns.client_ip not in network and dns.responder_ip not in network:
            raise HTTPException(422, "O lote contém consulta DNS fora do segmento autorizado.")
    for tls in batch.tls_handshakes:
        if tls.client_ip not in network and tls.responder_ip not in network:
            raise HTTPException(422, "O lote contém handshake TLS fora do segmento autorizado.")
    for edr in batch.edr_signals:
        if edr.host_ip not in network:
            raise HTTPException(422, "O lote contém sinal de AV/EDR fora do segmento autorizado.")


def _to_run_response(
    run: TrafficAnalysisRun,
    source_name: str,
    alerts: list[SuspiciousTrafficAlert],
    decisions: list[TrafficTlsDecision],
    edr_signals: list[TrafficEdrSignal],
) -> TrafficAnalysisRunResponse:
    return TrafficAnalysisRunResponse(
        id=run.id,
        asset_id=run.asset_id,
        source_id=run.source_id,
        source_name=source_name,
        coverage=TrafficCoverageResponse(
            observed_layers=list(run.observed_layers or []),
            missing_layers=list(run.missing_layers or []),
        ),
        connection_count=run.connection_count,
        dns_count=run.dns_count,
        tls_count=run.tls_count,
        edr_count=run.edr_count,
        alerts_count=run.alerts_count,
        benign_rotations_count=run.benign_rotations_count,
        alerts=[
            SuspiciousTrafficAlertResponse(
                id=alert.id,
                rule_id=alert.rule_id,
                category=cast(AlertCategory, alert.category),
                severity=cast(AlertSeverity, alert.severity),
                confidence=cast(AlertConfidence, alert.confidence),
                title=alert.title,
                explanation=alert.explanation,
                evidence=dict(alert.evidence or {}),
                observed_layers=list(alert.observed_layers or []),
                missing_layers=list(alert.missing_layers or []),
                created_at=as_utc(alert.created_at),
            )
            for alert in alerts
        ],
        tls_decisions=[
            TrafficTlsDecisionResponse(
                id=dec.id,
                uid=dec.uid,
                server_name=dec.server_name,
                responder_ip=dec.responder_ip,
                responder_port=dec.responder_port,
                outcome=cast(TlsDecisionOutcome, dec.outcome),
                observed_cert_sha256=dec.observed_cert_sha256,
                previous_cert_sha256=dec.previous_cert_sha256,
                observed_issuer=dec.observed_issuer,
                previous_issuer=dec.previous_issuer,
                reason=dec.reason,
                observed_at=as_utc(dec.observed_at),
            )
            for dec in decisions
        ],
        edr_signals=[
            TrafficEdrSignalResponse(
                id=sig.id,
                uid=sig.uid,
                host_ip=sig.host_ip,
                source_type=cast(EdrSourceType, sig.source_type),
                signal=cast(EdrSignalCode, sig.signal),
                process_name=sig.process_name,
                detail=sig.detail,
                observed_at=as_utc(sig.observed_at),
            )
            for sig in edr_signals
        ],
        created_at=as_utc(run.created_at),
    )


def analyze_traffic_batch(
    db: Session, source_id: str, token: str, batch: TrafficAnalysisBatch
) -> TrafficAnalysisRunResponse:
    source = require_collector_source(
        db, source_id, token, lock=True, capability="TRAFFIC_ANALYSIS"
    )
    _validate_batch_scope(source.network, batch)
    now = utcnow()
    asset = db.get(Asset, source.asset_id)
    if asset is None:
        raise HTTPException(404, "Ativo da fonte não encontrado.")

    if batch.connections:
        known_uids = existing_uids(db, source.id, [ev.uid for ev in batch.connections])
        for ev in batch.connections:
            if ev.uid in known_uids:
                continue
            known_uids.add(ev.uid)
            db.add(
                TelemetryConnection(
                    source_id=source.id,
                    received_at=now,
                    **ev.model_dump(mode="json", exclude={"observed_at"}),
                    observed_at=ev.observed_at,
                )
            )
    source.last_received_at = now

    baseline_rows = load_tls_baselines(db, source.id)
    baseline_states = {
        key: TlsBaselineState(
            server_name=row.server_name,
            responder_ip=row.responder_ip,
            responder_port=row.responder_port,
            cert_sha256=row.cert_sha256,
            subject=row.subject,
            issuer=row.issuer,
            not_before=as_utc(row.not_before),
            not_after=as_utc(row.not_after),
        )
        for key, row in baseline_rows.items()
    }

    conn_events = [
        ConnectionEvent(
            uid=c.uid,
            observed_at=as_utc(c.observed_at),
            origin_ip=str(c.origin_ip),
            origin_port=c.origin_port,
            responder_ip=str(c.responder_ip),
            responder_port=c.responder_port,
            transport=c.transport,
        )
        for c in batch.connections
    ]
    dns_events = [
        DnsEvent(
            uid=d.uid,
            observed_at=as_utc(d.observed_at),
            client_ip=str(d.client_ip),
            responder_ip=str(d.responder_ip),
            query=d.query,
            qtype=d.qtype,
            rcode=d.rcode,
        )
        for d in batch.dns_queries
    ]
    tls_events = [
        TlsEvent(
            uid=t.uid,
            observed_at=as_utc(t.observed_at),
            client_ip=str(t.client_ip),
            responder_ip=str(t.responder_ip),
            responder_port=t.responder_port,
            server_name=t.server_name,
            cert_sha256=t.cert_sha256,
            subject=t.subject,
            issuer=t.issuer,
            validation_status=t.validation_status,
            self_signed=t.self_signed,
            not_before=as_utc(t.not_before),
            not_after=as_utc(t.not_after),
        )
        for t in batch.tls_handshakes
    ]

    edr_events = [
        EdrSignalEvent(
            uid=e.uid,
            observed_at=as_utc(e.observed_at),
            host_ip=str(e.host_ip),
            source_type=e.source_type,
            signal=e.signal,
            process_name=_clean_text(e.process_name, 120) or "",
            detail=_clean_text(e.detail, 255),
        )
        for e in batch.edr_signals
    ]

    evaluation = evaluate_traffic_batch(
        connections=conn_events,
        dns_queries=dns_events,
        tls_handshakes=tls_events,
        existing_baselines=baseline_states,
        edr_signals=edr_events,
    )

    seen_tls_keys = {
        (t.server_name.lower(), t.responder_ip, t.responder_port) for t in tls_events
    }
    rotations_by_key: dict[tuple[str, str, int], int] = {}
    for dec in evaluation.tls_decisions:
        if dec.outcome == "BENIGN_ROTATION":
            key = (dec.server_name, dec.responder_ip, dec.responder_port)
            rotations_by_key[key] = rotations_by_key.get(key, 0) + 1

    for key, state in evaluation.updated_baselines.items():
        if key in baseline_rows:
            row = baseline_rows[key]
            if key in seen_tls_keys:
                row.last_seen_at = now
            if row.cert_sha256 != state.cert_sha256:
                row.cert_sha256 = state.cert_sha256
                row.subject = state.subject
                row.issuer = state.issuer
                row.not_before = state.not_before
                row.not_after = state.not_after
                row.rotation_count += rotations_by_key.get(key, 0)
        else:
            db.add(
                TelemetryTlsBaseline(
                    source_id=source.id,
                    server_name=state.server_name,
                    responder_ip=state.responder_ip,
                    responder_port=state.responder_port,
                    cert_sha256=state.cert_sha256,
                    subject=state.subject,
                    issuer=state.issuer,
                    not_before=state.not_before,
                    not_after=state.not_after,
                    rotation_count=rotations_by_key.get(key, 0),
                    first_seen_at=now,
                    last_seen_at=now,
                )
            )

    run = TrafficAnalysisRun(
        asset_id=source.asset_id,
        source_id=source.id,
        observed_layers=list(evaluation.observed_layers),
        missing_layers=list(evaluation.missing_layers),
        connection_count=len(conn_events),
        dns_count=len(dns_events),
        tls_count=len(tls_events),
        edr_count=len(edr_events),
        alerts_count=len(evaluation.alerts),
        benign_rotations_count=evaluation.benign_rotations_count,
        created_at=now,
    )
    db.add(run)
    db.flush()

    alert_rows = [
        SuspiciousTrafficAlert(
            run_id=run.id,
            rule_id=alert.rule_id,
            category=alert.category,
            severity=alert.severity,
            confidence=alert.confidence,
            title=alert.title,
            explanation=alert.explanation,
            evidence=_sanitize_evidence(alert.evidence),
            observed_layers=list(evaluation.observed_layers),
            missing_layers=list(evaluation.missing_layers),
            created_at=now,
        )
        for alert in evaluation.alerts
    ]
    for alert_row in alert_rows:
        db.add(alert_row)

    decision_rows = [
        TrafficTlsDecision(
            run_id=run.id,
            uid=dec.uid,
            server_name=dec.server_name,
            responder_ip=dec.responder_ip,
            responder_port=dec.responder_port,
            outcome=dec.outcome,
            observed_cert_sha256=dec.observed_cert_sha256,
            previous_cert_sha256=dec.previous_cert_sha256,
            observed_issuer=dec.observed_issuer,
            previous_issuer=dec.previous_issuer,
            reason=dec.reason,
            observed_at=dec.observed_at,
        )
        for dec in evaluation.tls_decisions
    ]
    for decision_row in decision_rows:
        db.add(decision_row)

    edr_rows = [
        TrafficEdrSignal(
            run_id=run.id,
            uid=ev.uid,
            host_ip=ev.host_ip,
            source_type=ev.source_type,
            signal=ev.signal,
            process_name=ev.process_name,
            detail=ev.detail,
            observed_at=ev.observed_at,
        )
        for ev in edr_events
    ]
    for edr_row in edr_rows:
        db.add(edr_row)

    db.flush()
    AuditLogService.record(
        db,
        action="TRAFFIC_ANALYSIS_EXECUTED",
        resource_type="traffic_analysis_run",
        resource_id=run.id,
        organization_id=asset.organization_id,
        user_id=None,
        metadata={
            "asset_id": asset.id,
            "source_id": source.id,
            "observed_layers": list(evaluation.observed_layers),
            "edr_count": len(edr_rows),
            "alerts_count": len(alert_rows),
            "benign_rotations_count": evaluation.benign_rotations_count,
        },
    )
    db.commit()
    return _to_run_response(run, source.name, alert_rows, decision_rows, edr_rows)


def list_asset_traffic_analyses(
    db: Session, organization_id: str, asset_id: str
) -> list[TrafficAnalysisRunResponse]:
    asset = AssetAuthorizationService.get_asset_or_404(db, organization_id, asset_id)
    runs = list_analysis_runs(db, asset.id)
    run_ids = [run.id for run, _ in runs]
    alerts_map = list_run_alerts(db, run_ids)
    decisions_map = list_run_tls_decisions(db, run_ids)
    edr_map = list_run_edr_signals(db, run_ids)
    return [
        _to_run_response(
            run,
            source_name,
            alerts_map.get(run.id, []),
            decisions_map.get(run.id, []),
            edr_map.get(run.id, []),
        )
        for run, source_name in runs
    ]


def get_asset_traffic_analysis(
    db: Session, organization_id: str, asset_id: str, run_id: str
) -> TrafficAnalysisRunResponse:
    asset = AssetAuthorizationService.get_asset_or_404(db, organization_id, asset_id)
    found = find_analysis_run(db, asset.id, run_id)
    if found is None:
        raise HTTPException(404, "Análise de tráfego não encontrada.")
    run, source_name = found
    alerts_map = list_run_alerts(db, [run.id])
    decisions_map = list_run_tls_decisions(db, [run.id])
    edr_map = list_run_edr_signals(db, [run.id])
    return _to_run_response(
        run,
        source_name,
        alerts_map.get(run.id, []),
        decisions_map.get(run.id, []),
        edr_map.get(run.id, []),
    )
