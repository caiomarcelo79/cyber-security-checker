"""Regras determinísticas e explicáveis para detecção de tráfego suspeito em laboratório."""

from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Any, Literal

CORE_LAYERS: tuple[str, ...] = ("CONNECTIONS", "DNS", "TLS", "EDR")

AlertConfidence = Literal["HIGH", "MEDIUM", "LOW"]
AlertSeverity = Literal["HIGH", "MEDIUM", "LOW"]
AlertCategory = Literal["CONNECTIONS", "DNS", "TLS"]
EdrSourceType = Literal["ANTIVIRUS", "EDR"]
EdrSignalCode = Literal[
    "SUSPICIOUS_PROCESS",
    "UNTRUSTED_ROOT_CA",
    "BEACONING_DETECTED",
    "MALWARE_QUARANTINED",
]
TlsDecisionOutcome = Literal[
    "BASELINE_ESTABLISHED",
    "UNCHANGED",
    "BENIGN_ROTATION",
    "INTERCEPTION_ALERT",
]

PORT_SWEEP_MIN_PORTS = 5
PORT_SWEEP_HIGH_PORTS = 8
REPEATED_BURST_MIN_CONNECTIONS = 10
REPEATED_BURST_HIGH_CONNECTIONS = 20
DNS_NXDOMAIN_MIN_COUNT = 4
DNS_NXDOMAIN_HIGH_COUNT = 6
DNS_HIGH_ENTROPY_MIN_LABEL_LEN = 24
DNS_HIGH_ENTROPY_MIN_BITS = 3.8

_ISSUER_ORG_PATTERN = re.compile(r"(?:^|[,/]\s*)O\s*=\s*([^,/]+)", re.IGNORECASE)
_ISSUER_CN_PATTERN = re.compile(r"(?:^|[,/]\s*)CN\s*=\s*([^,/]+)", re.IGNORECASE)


def as_utc(value: datetime) -> datetime:
    """Normaliza datas ingênuas ou com fuso para UTC."""
    return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)


@dataclass(frozen=True)
class ConnectionEvent:
    uid: str
    observed_at: datetime
    origin_ip: str
    origin_port: int
    responder_ip: str
    responder_port: int
    transport: str


@dataclass(frozen=True)
class DnsEvent:
    uid: str
    observed_at: datetime
    client_ip: str
    responder_ip: str
    query: str
    qtype: str
    rcode: str


@dataclass(frozen=True)
class TlsEvent:
    uid: str
    observed_at: datetime
    client_ip: str
    responder_ip: str
    responder_port: int
    server_name: str
    cert_sha256: str
    subject: str
    issuer: str
    validation_status: str
    self_signed: bool
    not_before: datetime
    not_after: datetime


@dataclass(frozen=True)
class TlsBaselineState:
    server_name: str
    responder_ip: str
    responder_port: int
    cert_sha256: str
    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime


@dataclass(frozen=True)
class EdrSignalEvent:
    uid: str
    observed_at: datetime
    host_ip: str
    source_type: EdrSourceType
    signal: EdrSignalCode
    process_name: str
    detail: str | None = None


@dataclass(frozen=True)
class DetectedAlert:
    rule_id: str
    category: AlertCategory
    severity: AlertSeverity
    confidence: AlertConfidence
    title: str
    explanation: str
    evidence: dict[str, Any]


@dataclass(frozen=True)
class TlsDecisionRecord:
    uid: str
    server_name: str
    responder_ip: str
    responder_port: int
    outcome: TlsDecisionOutcome
    observed_cert_sha256: str
    previous_cert_sha256: str | None
    observed_issuer: str
    previous_issuer: str | None
    reason: str
    observed_at: datetime


@dataclass(frozen=True)
class TrafficEvaluationResult:
    observed_layers: tuple[str, ...]
    missing_layers: tuple[str, ...]
    alerts: tuple[DetectedAlert, ...]
    tls_decisions: tuple[TlsDecisionRecord, ...]
    updated_baselines: dict[tuple[str, str, int], TlsBaselineState]
    benign_rotations_count: int


def shannon_entropy(text: str) -> float:
    """Calcula a entropia de Shannon em bits por caractere."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def candidate_subdomain_label(query: str) -> str:
    """Extrai o maior rótulo de subdomínio em minúsculas candidato a DGA ou tunelamento."""
    cleaned = query.strip().rstrip(".").lower()
    if not cleaned:
        return ""
    labels = [part for part in cleaned.split(".") if part]
    if not labels:
        return ""
    candidates = labels[:-2] if len(labels) >= 3 else labels[:1]
    return max(candidates, key=lambda item: (len(item), shannon_entropy(item)))


def issuer_organization(issuer: str) -> str:
    """Extrai a organização emissora (ou CN) normalizada para comparar continuidade da CA."""
    raw = issuer.strip()
    if not raw:
        return ""
    org_match = _ISSUER_ORG_PATTERN.search(raw)
    if org_match:
        return org_match.group(1).strip().strip('"').lower()
    cn_match = _ISSUER_CN_PATTERN.search(raw)
    if cn_match:
        return cn_match.group(1).strip().strip('"').lower()
    return raw.lower()


def compute_coverage(
    has_connections: bool,
    has_dns: bool,
    has_tls: bool,
    has_edr: bool = False,
) -> tuple[list[str], list[str]]:
    """Retorna (camadas_observadas, camadas_ausentes) preservando a ordem canônica."""
    presence = {
        "CONNECTIONS": has_connections,
        "DNS": has_dns,
        "TLS": has_tls,
        "EDR": has_edr,
    }
    observed = [layer for layer in CORE_LAYERS if presence[layer]]
    missing = [layer for layer in CORE_LAYERS if not presence[layer]]
    return observed, missing


def evaluate_connections(connections: Sequence[ConnectionEvent]) -> list[DetectedAlert]:
    """Detecta varredura horizontal/vertical de portas e rajadas repetitivas de conexão."""
    alerts: list[DetectedAlert] = []
    sweep_groups: dict[tuple[str, str], dict[int, list[str]]] = defaultdict(lambda: defaultdict(list))
    burst_groups: dict[tuple[str, str, int, str], list[str]] = defaultdict(list)

    for event in connections:
        sweep_groups[(event.origin_ip, event.responder_ip)][event.responder_port].append(event.uid)
        burst_key = (
            event.origin_ip,
            event.responder_ip,
            event.responder_port,
            event.transport,
        )
        burst_groups[burst_key].append(event.uid)

    for origin_ip, responder_ip in sorted(sweep_groups):
        ports_map = sweep_groups[(origin_ip, responder_ip)]
        distinct_ports = sorted(ports_map)
        if len(distinct_ports) < PORT_SWEEP_MIN_PORTS:
            continue
        is_high = len(distinct_ports) >= PORT_SWEEP_HIGH_PORTS
        sample_uids: list[str] = []
        for port in distinct_ports:
            sample_uids.extend(ports_map[port])
        alerts.append(
            DetectedAlert(
                rule_id="CONNECTION_PORT_SWEEP",
                category="CONNECTIONS",
                severity="HIGH" if is_high else "MEDIUM",
                confidence="HIGH" if is_high else "MEDIUM",
                title=f"Varredura de portas detectada de {origin_ip} para {responder_ip}",
                explanation=(
                    f"O host {origin_ip} iniciou conexões para {len(distinct_ports)} portas distintas "
                    f"em {responder_ip} na janela analisada (limiar mínimo: {PORT_SWEEP_MIN_PORTS})."
                ),
                evidence={
                    "origin_ip": origin_ip,
                    "responder_ip": responder_ip,
                    "distinct_ports_count": len(distinct_ports),
                    "sampled_ports": distinct_ports[:15],
                    "sample_uids": sample_uids[:10],
                },
            )
        )

    for burst_key in sorted(burst_groups):
        origin_ip, responder_ip, responder_port, transport = burst_key
        uids = burst_groups[burst_key]
        if len(uids) < REPEATED_BURST_MIN_CONNECTIONS:
            continue
        is_high = len(uids) >= REPEATED_BURST_HIGH_CONNECTIONS
        alerts.append(
            DetectedAlert(
                rule_id="CONNECTION_REPEATED_BURST",
                category="CONNECTIONS",
                severity="MEDIUM",
                confidence="HIGH" if is_high else "MEDIUM",
                title=(
                    f"Rajada repetitiva de conexões ({transport.upper()}/{responder_port}) "
                    f"de {origin_ip}"
                ),
                explanation=(
                    f"Foram observadas {len(uids)} conexões consecutivas de {origin_ip} para "
                    f"{responder_ip}:{responder_port}/{transport} na mesma janela "
                    f"(limiar: {REPEATED_BURST_MIN_CONNECTIONS})."
                ),
                evidence={
                    "origin_ip": origin_ip,
                    "responder_ip": responder_ip,
                    "responder_port": responder_port,
                    "transport": transport,
                    "connection_count": len(uids),
                    "sample_uids": uids[:10],
                },
            )
        )

    return alerts


def evaluate_dns(dns_queries: Sequence[DnsEvent]) -> list[DetectedAlert]:
    """Detecta rajadas de NXDOMAIN e consultas com subdomínio de alta entropia (DGA/tunelamento)."""
    alerts: list[DetectedAlert] = []
    nxdomain_by_client: dict[str, list[DnsEvent]] = defaultdict(list)
    entropy_by_client: dict[str, list[tuple[DnsEvent, str, float]]] = defaultdict(list)

    for event in dns_queries:
        if event.rcode.strip().upper() == "NXDOMAIN":
            nxdomain_by_client[event.client_ip].append(event)
        label = candidate_subdomain_label(event.query)
        if len(label) >= DNS_HIGH_ENTROPY_MIN_LABEL_LEN:
            bits = shannon_entropy(label)
            if bits >= DNS_HIGH_ENTROPY_MIN_BITS:
                entropy_by_client[event.client_ip].append((event, label, bits))

    nxdomain_burst_clients: set[str] = set()
    for client_ip in sorted(nxdomain_by_client):
        events = nxdomain_by_client[client_ip]
        if len(events) < DNS_NXDOMAIN_MIN_COUNT:
            continue
        nxdomain_burst_clients.add(client_ip)
        is_high = len(events) >= DNS_NXDOMAIN_HIGH_COUNT
        sampled_queries = list(dict.fromkeys(ev.query for ev in events))[:10]
        alerts.append(
            DetectedAlert(
                rule_id="DNS_NXDOMAIN_BURST",
                category="DNS",
                severity="MEDIUM",
                confidence="HIGH" if is_high else "MEDIUM",
                title=f"Rajada de respostas NXDOMAIN originada em {client_ip}",
                explanation=(
                    f"O cliente {client_ip} acumulou {len(events)} consultas DNS com resposta "
                    f"NXDOMAIN na janela observada (limiar: {DNS_NXDOMAIN_MIN_COUNT})."
                ),
                evidence={
                    "client_ip": client_ip,
                    "nxdomain_count": len(events),
                    "sampled_queries": sampled_queries,
                    "sample_uids": [ev.uid for ev in events[:10]],
                },
            )
        )

    for client_ip in sorted(entropy_by_client):
        matches = entropy_by_client[client_ip]
        has_nxdomain = client_ip in nxdomain_burst_clients or any(
            ev.rcode.strip().upper() == "NXDOMAIN" for ev, _, _ in matches
        )
        is_high = has_nxdomain or len(matches) >= 2
        max_entropy = round(max(bits for _, _, bits in matches), 2)
        max_length = max(len(label) for _, label, _ in matches)
        sampled_queries = list(dict.fromkeys(ev.query for ev, _, _ in matches))[:10]
        alerts.append(
            DetectedAlert(
                rule_id="DNS_HIGH_ENTROPY_QUERY",
                category="DNS",
                severity="HIGH" if is_high else "MEDIUM",
                confidence="HIGH" if is_high else "MEDIUM",
                title=f"Subdomínio DNS de alta entropia detectado em {client_ip}",
                explanation=(
                    f"O cliente {client_ip} realizou {len(matches)} consulta(s) com rótulo de "
                    f"{max_length} caracteres e entropia máxima de {max_entropy} bits/caractere "
                    f"(limiar >= {DNS_HIGH_ENTROPY_MIN_LABEL_LEN} chars e {DNS_HIGH_ENTROPY_MIN_BITS} bits)."
                ),
                evidence={
                    "client_ip": client_ip,
                    "suspicious_query_count": len(matches),
                    "max_entropy_bits": max_entropy,
                    "max_label_length": max_length,
                    "combined_with_nxdomain": has_nxdomain,
                    "sampled_queries": sampled_queries,
                    "sample_uids": [ev.uid for ev, _, _ in matches[:10]],
                },
            )
        )

    return alerts


def _cert_unhealthy_reasons(event: TlsEvent) -> list[str]:
    reasons: list[str] = []
    if event.self_signed:
        reasons.append("self_signed_certificate")
    if event.validation_status.strip().lower() != "ok":
        reasons.append("validation_failed")
    observed_at = as_utc(event.observed_at)
    not_before = as_utc(event.not_before)
    not_after = as_utc(event.not_after)
    if not_before >= not_after or not (not_before <= observed_at <= not_after):
        reasons.append("outside_validity_window")
    return reasons


def evaluate_tls(
    tls_events: Sequence[TlsEvent],
    existing_baselines: Mapping[tuple[str, str, int], TlsBaselineState],
) -> tuple[list[DetectedAlert], list[TlsDecisionRecord], dict[tuple[str, str, int], TlsBaselineState], int]:
    """Avalia identidade TLS distinguindo rotação legítima de possível interceptação."""
    baselines = dict(existing_baselines)
    alerts: list[DetectedAlert] = []
    decisions: list[TlsDecisionRecord] = []
    benign_rotations_count = 0

    for event in sorted(tls_events, key=lambda item: (as_utc(item.observed_at), item.uid)):
        server_key = event.server_name.strip().lower()
        target_key = (server_key, event.responder_ip, event.responder_port)
        current = baselines.get(target_key)
        observed_fp = event.cert_sha256.strip().lower()
        observed_at = as_utc(event.observed_at)
        not_before = as_utc(event.not_before)
        not_after = as_utc(event.not_after)
        base_reasons = _cert_unhealthy_reasons(event)
        healthy = not base_reasons

        if current is None:
            if healthy:
                baselines[target_key] = TlsBaselineState(
                    server_name=server_key,
                    responder_ip=event.responder_ip,
                    responder_port=event.responder_port,
                    cert_sha256=observed_fp,
                    subject=event.subject,
                    issuer=event.issuer,
                    not_before=not_before,
                    not_after=not_after,
                )
                decisions.append(
                    TlsDecisionRecord(
                        uid=event.uid,
                        server_name=server_key,
                        responder_ip=event.responder_ip,
                        responder_port=event.responder_port,
                        outcome="BASELINE_ESTABLISHED",
                        observed_cert_sha256=observed_fp,
                        previous_cert_sha256=None,
                        observed_issuer=event.issuer,
                        previous_issuer=None,
                        reason="trusted_initial_certificate",
                        observed_at=observed_at,
                    )
                )
                continue

            reason_text = ",".join(base_reasons)
            decisions.append(
                TlsDecisionRecord(
                    uid=event.uid,
                    server_name=server_key,
                    responder_ip=event.responder_ip,
                    responder_port=event.responder_port,
                    outcome="INTERCEPTION_ALERT",
                    observed_cert_sha256=observed_fp,
                    previous_cert_sha256=None,
                    observed_issuer=event.issuer,
                    previous_issuer=None,
                    reason=reason_text,
                    observed_at=observed_at,
                )
            )
            alerts.append(
                DetectedAlert(
                    rule_id="TLS_POSSIBLE_INTERCEPTION",
                    category="TLS",
                    severity="HIGH" if event.self_signed else "MEDIUM",
                    confidence="MEDIUM",
                    title=f"Identidade TLS suspeita sem baseline prévio para {server_key}",
                    explanation=(
                        f"O handshake para {server_key} ({event.responder_ip}:{event.responder_port}) "
                        f"apresentou certificado não confiável ({reason_text})."
                    ),
                    evidence={
                        "uid": event.uid,
                        "client_ip": event.client_ip,
                        "server_name": server_key,
                        "responder_ip": event.responder_ip,
                        "responder_port": event.responder_port,
                        "previous_cert_sha256": None,
                        "observed_cert_sha256": observed_fp,
                        "previous_issuer": None,
                        "observed_issuer": event.issuer,
                        "observed_subject": event.subject,
                        "validation_status": event.validation_status,
                        "self_signed": event.self_signed,
                        "reasons": base_reasons,
                    },
                )
            )
            continue

        if observed_fp == current.cert_sha256:
            if healthy:
                decisions.append(
                    TlsDecisionRecord(
                        uid=event.uid,
                        server_name=server_key,
                        responder_ip=event.responder_ip,
                        responder_port=event.responder_port,
                        outcome="UNCHANGED",
                        observed_cert_sha256=observed_fp,
                        previous_cert_sha256=current.cert_sha256,
                        observed_issuer=event.issuer,
                        previous_issuer=current.issuer,
                        reason="certificate_matches_baseline",
                        observed_at=observed_at,
                    )
                )
                continue

            reason_text = ",".join(base_reasons)
            decisions.append(
                TlsDecisionRecord(
                    uid=event.uid,
                    server_name=server_key,
                    responder_ip=event.responder_ip,
                    responder_port=event.responder_port,
                    outcome="INTERCEPTION_ALERT",
                    observed_cert_sha256=observed_fp,
                    previous_cert_sha256=current.cert_sha256,
                    observed_issuer=event.issuer,
                    previous_issuer=current.issuer,
                    reason=reason_text,
                    observed_at=observed_at,
                )
            )
            alerts.append(
                DetectedAlert(
                    rule_id="TLS_POSSIBLE_INTERCEPTION",
                    category="TLS",
                    severity="HIGH" if event.self_signed else "MEDIUM",
                    confidence="MEDIUM",
                    title=f"Falha de validação TLS persistente em {server_key}",
                    explanation=(
                        f"O certificado de {server_key} falhou na validação ({reason_text}) "
                        f"apesar de manter a impressão digital {observed_fp[:12]}."
                    ),
                    evidence={
                        "uid": event.uid,
                        "client_ip": event.client_ip,
                        "server_name": server_key,
                        "responder_ip": event.responder_ip,
                        "responder_port": event.responder_port,
                        "previous_cert_sha256": current.cert_sha256,
                        "observed_cert_sha256": observed_fp,
                        "previous_issuer": current.issuer,
                        "observed_issuer": event.issuer,
                        "observed_subject": event.subject,
                        "validation_status": event.validation_status,
                        "self_signed": event.self_signed,
                        "reasons": base_reasons,
                    },
                )
            )
            continue

        same_ca_org = bool(
            issuer_organization(event.issuer)
            and issuer_organization(event.issuer) == issuer_organization(current.issuer)
        )
        validity_non_regressive = not_after >= as_utc(current.not_after)

        if healthy and same_ca_org and validity_non_regressive:
            benign_rotations_count += 1
            decisions.append(
                TlsDecisionRecord(
                    uid=event.uid,
                    server_name=server_key,
                    responder_ip=event.responder_ip,
                    responder_port=event.responder_port,
                    outcome="BENIGN_ROTATION",
                    observed_cert_sha256=observed_fp,
                    previous_cert_sha256=current.cert_sha256,
                    observed_issuer=event.issuer,
                    previous_issuer=current.issuer,
                    reason="valid_renewal_same_ca",
                    observed_at=observed_at,
                )
            )
            baselines[target_key] = TlsBaselineState(
                server_name=server_key,
                responder_ip=event.responder_ip,
                responder_port=event.responder_port,
                cert_sha256=observed_fp,
                subject=event.subject,
                issuer=event.issuer,
                not_before=not_before,
                not_after=not_after,
            )
            continue

        interception_reasons = list(base_reasons)
        if not same_ca_org:
            interception_reasons.append("unexpected_issuer_change")
        if not validity_non_regressive:
            interception_reasons.append("validity_regression")

        reason_text = ",".join(interception_reasons)
        confidence: AlertConfidence = (
            "HIGH"
            if (event.self_signed or event.validation_status.strip().lower() != "ok")
            else "MEDIUM"
        )
        decisions.append(
            TlsDecisionRecord(
                uid=event.uid,
                server_name=server_key,
                responder_ip=event.responder_ip,
                responder_port=event.responder_port,
                outcome="INTERCEPTION_ALERT",
                observed_cert_sha256=observed_fp,
                previous_cert_sha256=current.cert_sha256,
                observed_issuer=event.issuer,
                previous_issuer=current.issuer,
                reason=reason_text,
                observed_at=observed_at,
            )
        )
        alerts.append(
            DetectedAlert(
                rule_id="TLS_POSSIBLE_INTERCEPTION",
                category="TLS",
                severity="HIGH",
                confidence=confidence,
                title=f"Possível interceptação TLS detectada para {server_key}",
                explanation=(
                    f"Substituição anômala de certificado em {server_key} "
                    f"({event.responder_ip}:{event.responder_port}): baseline emitido por "
                    f"'{current.issuer}' ({current.cert_sha256[:12]}) alterado para "
                    f"'{event.issuer}' ({observed_fp[:12]}), motivos: {reason_text}."
                ),
                evidence={
                    "uid": event.uid,
                    "client_ip": event.client_ip,
                    "server_name": server_key,
                    "responder_ip": event.responder_ip,
                    "responder_port": event.responder_port,
                    "previous_cert_sha256": current.cert_sha256,
                    "observed_cert_sha256": observed_fp,
                    "previous_issuer": current.issuer,
                    "observed_issuer": event.issuer,
                    "observed_subject": event.subject,
                    "validation_status": event.validation_status,
                    "self_signed": event.self_signed,
                    "reasons": interception_reasons,
                },
            )
        )

    return alerts, decisions, baselines, benign_rotations_count


def _alert_host_ips(alert: DetectedAlert) -> list[str]:
    if alert.category == "CONNECTIONS":
        candidates = [alert.evidence.get("origin_ip")]
    elif alert.category == "DNS":
        candidates = [alert.evidence.get("client_ip")]
    else:
        candidates = [alert.evidence.get("client_ip"), alert.evidence.get("responder_ip")]
    return list(dict.fromkeys(str(ip) for ip in candidates if isinstance(ip, str) and ip))


def correlate_alerts_with_edr(
    alerts: Sequence[DetectedAlert],
    edr_signals: Sequence[EdrSignalEvent],
) -> list[DetectedAlert]:
    """Correlaciona alertas de rede/DNS/TLS com sinais de AV/EDR no mesmo host_ip."""
    if not edr_signals:
        return list(alerts)

    by_host: dict[str, list[EdrSignalEvent]] = defaultdict(list)
    for signal in edr_signals:
        by_host[signal.host_ip].append(signal)

    correlated: list[DetectedAlert] = []
    for alert in alerts:
        matched: list[EdrSignalEvent] = []
        seen_uids: set[str] = set()
        for host_ip in _alert_host_ips(alert):
            for sig in by_host.get(host_ip, ()):
                if sig.uid not in seen_uids:
                    seen_uids.add(sig.uid)
                    matched.append(sig)
        if not matched:
            correlated.append(alert)
            continue

        sources = ", ".join(sorted({sig.source_type for sig in matched}))
        signals = ", ".join(dict.fromkeys(f"{sig.signal} ({sig.process_name})" for sig in matched))
        evidence = {
            **alert.evidence,
            "correlated_edr_signals": [
                {
                    "uid": sig.uid,
                    "host_ip": sig.host_ip,
                    "source_type": sig.source_type,
                    "signal": sig.signal,
                    "process_name": sig.process_name,
                }
                for sig in matched
            ],
        }
        correlated.append(
            replace(
                alert,
                confidence="HIGH",
                severity="HIGH",
                explanation=(
                    f"{alert.explanation} Correlacionado com {len(matched)} sinal(is) "
                    f"de {sources} no host ({signals})."
                ),
                evidence=evidence,
            )
        )
    return correlated


def evaluate_traffic_batch(
    *,
    connections: Sequence[ConnectionEvent],
    dns_queries: Sequence[DnsEvent],
    tls_handshakes: Sequence[TlsEvent],
    existing_baselines: Mapping[tuple[str, str, int], TlsBaselineState],
    edr_signals: Sequence[EdrSignalEvent] = (),
) -> TrafficEvaluationResult:
    """Executa todas as famílias de detecção explicáveis e consolida cobertura."""
    observed, missing = compute_coverage(
        has_connections=len(connections) > 0,
        has_dns=len(dns_queries) > 0,
        has_tls=len(tls_handshakes) > 0,
        has_edr=len(edr_signals) > 0,
    )
    conn_alerts = evaluate_connections(connections)
    dns_alerts = evaluate_dns(dns_queries)
    tls_alerts, tls_decisions, updated_baselines, benign_rotations_count = evaluate_tls(
        tls_handshakes, existing_baselines
    )
    alerts = correlate_alerts_with_edr([*conn_alerts, *dns_alerts, *tls_alerts], edr_signals)
    return TrafficEvaluationResult(
        observed_layers=tuple(observed),
        missing_layers=tuple(missing),
        alerts=tuple(alerts),
        tls_decisions=tuple(tls_decisions),
        updated_baselines=updated_baselines,
        benign_rotations_count=benign_rotations_count,
    )
