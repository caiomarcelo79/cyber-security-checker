"""Regras determinísticas, citação de evidências e fallback resiliente para triagem assistida."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

from security_engine.core.evidence import SENSITIVE_HEADER_NAMES, SENSITIVE_QUERY_KEYS, EvidenceManager

TriageTargetType = Literal["TRAFFIC_ALERT", "FINDING"]
TriageGenerationMode = Literal["AI_PROVIDER", "DETERMINISTIC_FALLBACK"]
AiAvailabilityStatus = Literal[
    "AVAILABLE",
    "UNAVAILABLE",
    "UNCONFIGURED",
    "INVALID_OUTPUT_FALLBACK",
]
RecommendedAction = Literal["INVESTIGATE", "CONTAIN", "REMEDIATE", "VERIFY_CHANGE"]
TriageReviewStatus = Literal["PENDING_REVIEW", "APPROVED", "REJECTED"]

VALID_ACTIONS: tuple[RecommendedAction, ...] = (
    "INVESTIGATE",
    "CONTAIN",
    "REMEDIATE",
    "VERIFY_CHANGE",
)
DETERMINISTIC_MODEL_NAME = "csc-deterministic-triage-v1"

_PRIORITY_EVIDENCE_KEYS: tuple[str, ...] = (
    "request_method",
    "request_url",
    "response_status_code",
    "observed_value",
    "expected_baseline",
    "origin_ip",
    "client_ip",
    "server_name",
    "responder_ip",
    "responder_port",
    "distinct_ports_count",
    "connection_count",
    "nxdomain_count",
    "suspicious_query_count",
    "max_entropy_bits",
    "previous_cert_sha256",
    "observed_cert_sha256",
    "previous_issuer",
    "observed_issuer",
    "correlated_edr_signals",
    "reasons",
    "technical_notes",
)

_LEVEL_LABELS: dict[str, str] = {
    "CRITICAL": "Crítica",
    "HIGH": "Alta",
    "MEDIUM": "Média",
    "LOW": "Baixa",
    "INFO": "Informativa",
    "CERTAIN": "Certa",
    "FIRM": "Firme",
    "TENTATIVE": "Tentativa",
}

_TRAFFIC_PLAYBOOKS: dict[str, tuple[RecommendedAction, tuple[str, ...]]] = {
    "CONNECTION_PORT_SWEEP": (
        "CONTAIN",
        (
            "Validar se o host de origem possui autorização administrativa para sondagem de portas.",
            "Inspecionar processos ativos e conexões recentes no host de origem via endpoint/EDR.",
            "Restringir portas expostas e regras de firewall entre a origem e o destino afetado.",
            "Reprocessar logs de conexão após a contenção para confirmar cessação da varredura.",
        ),
    ),
    "CONNECTION_REPEATED_BURST": (
        "INVESTIGATE",
        (
            "Identificar o serviço ou processo responsável pela rajada repetitiva na porta de destino.",
            "Conferir se o comportamento decorre de tarefa programada legítima ou tentativa de beaconing.",
            "Aplicar limitação de taxa ou bloqueio seletivo caso a origem não seja esperada.",
        ),
    ),
    "DNS_NXDOMAIN_BURST": (
        "INVESTIGATE",
        (
            "Inspecionar os domínios inexistentes consultados pelo cliente no log do resolvedor DNS.",
            "Verificar configurações antigas de serviço ou possível geração algorítmica de domínios (DGA).",
            "Correlacionar o cliente com telemetria de antivírus/EDR antes de isolar o endpoint.",
        ),
    ),
    "DNS_HIGH_ENTROPY_QUERY": (
        "CONTAIN",
        (
            "Avaliar os rótulos de subdomínio de alta entropia contra indícios de tunelamento DNS ou exfiltração.",
            "Bloquear temporariamente o domínio pai suspeito no resolvedor recursivo e monitorar recorrência.",
            "Inspecionar o processo emissor no host de origem para descartar comprometimento.",
        ),
    ),
    "TLS_POSSIBLE_INTERCEPTION": (
        "CONTAIN",
        (
            "Comparar a impressão digital SHA-256 e o emissor observados com o certificado autorizado do serviço.",
            "Verificar se há proxy corporativo não autorizado ou interceptação TLS no caminho de rede.",
            "Auditar o armazenamento de autoridades certificadoras confiáveis no cliente afetado.",
            "Confirmar restauração do certificado esperado em nova análise de handshakes TLS.",
        ),
    ),
}


@dataclass(frozen=True)
class EvidenceCitation:
    field: str
    value_excerpt: str


@dataclass(frozen=True)
class TriageContext:
    target_type: TriageTargetType
    rule_or_check_id: str
    category: str
    title: str
    severity: str
    confidence: str
    description_or_explanation: str
    sanitized_evidence: dict[str, Any]
    remediation_hint_title: str | None = None
    remediation_hint_steps: tuple[str, ...] = ()
    observed_layers: tuple[str, ...] = ()
    missing_layers: tuple[str, ...] = ()
    is_potential_finding: bool = False


@dataclass(frozen=True)
class GeneratedTriageDraft:
    generation_mode: TriageGenerationMode
    ai_status: AiAvailabilityStatus
    model_name: str
    summary: str
    explanation: str
    recommended_action: RecommendedAction
    remediation_steps: tuple[str, ...]
    evidence_citations: tuple[EvidenceCitation, ...]
    sanitized_evidence_hash: str


def _sanitize_value(value: Any) -> Any:
    if isinstance(value, str):
        cleaned, _ = EvidenceManager.sanitize_text_snippet(value, max_chars=512)
        return cleaned if cleaned is not None else ""
    if isinstance(value, list):
        return [_sanitize_value(item) for item in value]
    if isinstance(value, dict):
        return sanitize_evidence_payload(value)
    return value


def sanitize_evidence_payload(evidence: Mapping[str, Any]) -> dict[str, Any]:
    """Aplica sanitização recursiva sobre qualquer dicionário de evidências."""
    sanitized: dict[str, Any] = {}
    for key, val in evidence.items():
        lower_key = str(key).lower().strip()
        if lower_key in SENSITIVE_QUERY_KEYS or lower_key in SENSITIVE_HEADER_NAMES:
            sanitized[str(key)] = "[REDACTED]"
        else:
            sanitized[str(key)] = _sanitize_value(val)
    return sanitized


def compute_evidence_hash(sanitized_evidence: Mapping[str, Any]) -> str:
    """Calcula hash SHA-256 determinístico da evidência sanitizada."""
    canonical = json.dumps(sanitized_evidence, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _format_evidence_value(value: Any, max_len: int = 140) -> str:
    if isinstance(value, str):
        text = " ".join(value.split())
    elif isinstance(value, bool | int | float):
        text = str(value)
    else:
        text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if len(text) > max_len:
        return f"{text[: max_len - 3]}..."
    return text


def _is_meaningful(key: str, value: Any) -> bool:
    if key == "redacted_fields_count":
        return False
    return value not in (None, "", [], {})


def extract_evidence_citations(
    sanitized_evidence: Mapping[str, Any],
    max_citations: int = 6,
) -> list[EvidenceCitation]:
    """Extrai citações verificáveis diretamente dos campos não vazios da evidência."""
    ordered_keys: list[str] = []
    seen: set[str] = set()
    for key in _PRIORITY_EVIDENCE_KEYS:
        if key in sanitized_evidence and _is_meaningful(key, sanitized_evidence[key]):
            ordered_keys.append(key)
            seen.add(key)
    for key in sorted(sanitized_evidence):
        if key not in seen and _is_meaningful(key, sanitized_evidence[key]):
            ordered_keys.append(key)

    citations: list[EvidenceCitation] = []
    for key in ordered_keys[:max_citations]:
        excerpt = _format_evidence_value(sanitized_evidence[key])
        if excerpt:
            citations.append(EvidenceCitation(field=str(key), value_excerpt=excerpt))
    return citations


def _clean_text(text: str, max_chars: int) -> str:
    cleaned, _ = EvidenceManager.sanitize_text_snippet(text.strip(), max_chars=max_chars)
    return (cleaned or "").strip()


def _value_matches_evidence(actual_value: Any, excerpt: str) -> bool:
    needle = excerpt.rstrip(".").strip().lower()
    if not needle:
        return False
    actual_serialized = _format_evidence_value(actual_value, max_len=2048).lower()
    return needle in actual_serialized


def validate_grounded_draft(
    raw: Mapping[str, Any],
    sanitized_evidence: Mapping[str, Any],
    model_name: str,
    evidence_hash: str,
) -> GeneratedTriageDraft | None:
    """Valida se a sugestão retornada por IA cita corretamente a evidência sanitizada."""
    summary = raw.get("summary")
    explanation = raw.get("explanation")
    action = raw.get("recommended_action")
    steps = raw.get("remediation_steps")
    raw_citations = raw.get("evidence_citations")

    if (
        not isinstance(summary, str)
        or not summary.strip()
        or not isinstance(explanation, str)
        or not explanation.strip()
        or not isinstance(action, str)
        or action not in VALID_ACTIONS
        or not isinstance(steps, list)
        or not steps
        or not isinstance(raw_citations, list)
        or not raw_citations
    ):
        return None

    clean_steps = [
        _clean_text(step, 320)
        for step in steps[:8]
        if isinstance(step, str) and step.strip()
    ]
    if not clean_steps:
        return None

    validated_citations: list[EvidenceCitation] = []
    for item in raw_citations[:8]:
        if not isinstance(item, Mapping):
            return None
        field = item.get("field")
        excerpt = item.get("value_excerpt")
        if not isinstance(field, str) or not isinstance(excerpt, str):
            return None
        if field not in sanitized_evidence or not _is_meaningful(field, sanitized_evidence[field]):
            return None
        if not _value_matches_evidence(sanitized_evidence[field], excerpt):
            return None
        clean_excerpt = _clean_text(excerpt, 160)
        if not clean_excerpt:
            return None
        validated_citations.append(EvidenceCitation(field=field, value_excerpt=clean_excerpt))

    if not validated_citations:
        return None

    clean_summary = _clean_text(summary, 900)
    clean_explanation = _clean_text(explanation, 1600)
    lowered_summary = clean_summary.lower()
    summary_cites_evidence = any(
        cit.field.lower() in lowered_summary
        or cit.value_excerpt.rstrip(".").lower() in lowered_summary
        for cit in validated_citations
    )
    if not summary_cites_evidence:
        return None

    return GeneratedTriageDraft(
        generation_mode="AI_PROVIDER",
        ai_status="AVAILABLE",
        model_name=_clean_text(model_name, 120) or "ai-provider",
        summary=clean_summary,
        explanation=clean_explanation,
        recommended_action=action,  # type: ignore[arg-type]
        remediation_steps=tuple(clean_steps),
        evidence_citations=tuple(validated_citations),
        sanitized_evidence_hash=evidence_hash,
    )


def build_deterministic_suggestion(
    ctx: TriageContext,
    *,
    ai_status: AiAvailabilityStatus = "UNCONFIGURED",
) -> GeneratedTriageDraft:
    """Sintetiza resumo, explicação e correção determinísticos citando a evidência sanitizada."""
    evidence_hash = compute_evidence_hash(ctx.sanitized_evidence)
    citations = extract_evidence_citations(ctx.sanitized_evidence)
    sev_label = _LEVEL_LABELS.get(ctx.severity.upper(), ctx.severity)
    conf_label = _LEVEL_LABELS.get(ctx.confidence.upper(), ctx.confidence)

    if citations:
        ev_refs = "; ".join(f"{cit.field}={cit.value_excerpt}" for cit in citations[:4])
    else:
        ev_refs = "sem atributos adicionais registrados na evidência"

    raw_summary = (
        f"[{sev_label} | Confiança {conf_label}] {ctx.title} ({ctx.rule_or_check_id}). "
        f"Evidências sanitizadas observadas: {ev_refs}."
    )

    coverage_note = ""
    if ctx.observed_layers or ctx.missing_layers:
        observed_txt = ", ".join(ctx.observed_layers) if ctx.observed_layers else "nenhuma"
        missing_txt = ", ".join(ctx.missing_layers) if ctx.missing_layers else "nenhuma"
        coverage_note = f" Cobertura observada: {observed_txt} (ausente: {missing_txt})."

    raw_explanation = (
        f"{ctx.description_or_explanation.strip()}{coverage_note} "
        f"Classificação atribuída: severidade {sev_label} com confiança {conf_label}."
    )

    if ctx.target_type == "TRAFFIC_ALERT":
        action, default_steps = _TRAFFIC_PLAYBOOKS.get(
            ctx.rule_or_check_id,
            (
                "INVESTIGATE",
                (
                    "Revisar os campos citados na evidência sanitizada e validar legitimidade do fluxo.",
                    "Correlacionar eventos de rede/DNS/TLS com logs do sistema ou EDR do ativo.",
                    "Executar nova coleta controlada após aplicação de medidas corretivas.",
                ),
            ),
        )
        steps = list(default_steps)
    else:
        action = (
            "INVESTIGATE"
            if (ctx.is_potential_finding or ctx.confidence.upper() == "TENTATIVE")
            else "REMEDIATE"
        )
        steps = [s.strip() for s in ctx.remediation_hint_steps if isinstance(s, str) and s.strip()][:6]
        if not steps:
            hint_prefix = f"{ctx.remediation_hint_title}: " if ctx.remediation_hint_title else ""
            steps = [
                f"{hint_prefix}Reproduzir o achado {ctx.rule_or_check_id} usando as evidências citadas.",
                "Aplicar a correção recomendada na camada afetada e restringir exposição desnecessária.",
                "Executar revalidação técnica direcionada no ativo após o ajuste.",
            ]

    return GeneratedTriageDraft(
        generation_mode="DETERMINISTIC_FALLBACK",
        ai_status=ai_status,
        model_name=DETERMINISTIC_MODEL_NAME,
        summary=_clean_text(raw_summary, 900),
        explanation=_clean_text(raw_explanation, 1600),
        recommended_action=action,
        remediation_steps=tuple(_clean_text(step, 320) for step in steps),
        evidence_citations=tuple(citations),
        sanitized_evidence_hash=evidence_hash,
    )
