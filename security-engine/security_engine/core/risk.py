"""Motor de classificação de risco e cálculo de indicadores de postura (RiskEngine - Seção 5 e Seção 9)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from security_engine.core.contracts import (
    CheckStatus,
    Confidence,
    NormalizedFinding,
    Severity,
)

SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.CRITICAL: 25.0,
    Severity.HIGH: 14.0,
    Severity.MEDIUM: 6.0,
    Severity.LOW: 2.0,
    Severity.INFO: 0.25,
}

CONFIDENCE_MULTIPLIERS: dict[Confidence, float] = {
    Confidence.CERTAIN: 1.0,
    Confidence.FIRM: 0.8,
    Confidence.TENTATIVE: 0.45,
}


@dataclass(frozen=True)
class RiskPostureSummary:
    """Resumo calculado de risco de uma execução ou ativo."""

    risk_score: int  # 0 (sem risco identificado) a 100 (risco crítico máximo)
    risk_grade: str  # A, B, C, D, F
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    confirmed_vulnerabilities: int
    potential_vulnerabilities: int


class RiskEngine:
    """Classifica descobertas, gera fingerprints determinísticos e calcula indicadores de risco."""

    @staticmethod
    def compute_finding_fingerprint(
        asset_hostname: str,
        module_id: str,
        check_id: str,
        endpoint: str,
        discriminator: str = "",
    ) -> str:
        """Gera hash SHA-256 canônico para rastrear a mesma vulnerabilidade entre múltiplas execuções."""
        raw = f"{asset_hostname.lower().strip()}|{module_id.strip()}|{check_id.strip()}|{endpoint.strip()}|{discriminator.strip()}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]

    @staticmethod
    def validate_classification_consistency(
        classification: CheckStatus,
        confidence: Confidence,
    ) -> CheckStatus:
        """Garante a regra da Seção 3: 'Não apresente um resultado como vulnerabilidade confirmada
        quando o teste produzir apenas um indício.'
        """
        if classification not in {CheckStatus.VULNERABILITY, CheckStatus.POTENTIAL_VULNERABILITY}:
            raise ValueError(
                f"Apenas VULNERABILITY ou POTENTIAL_VULNERABILITY podem gerar um Finding. Recebido: {classification}"
            )
        if confidence == Confidence.TENTATIVE and classification == CheckStatus.VULNERABILITY:
            return CheckStatus.POTENTIAL_VULNERABILITY
        return classification

    @classmethod
    def validate_finding_consistency(cls, finding: NormalizedFinding) -> NormalizedFinding:
        """Valida e ajusta a classificação de uma descoberta de acordo com o nível de confiança."""
        adjusted = cls.validate_classification_consistency(
            finding.result_classification,
            finding.confidence,
        )
        if adjusted != finding.result_classification:
            finding.result_classification = adjusted
        return finding

    @classmethod
    def calculate_asset_risk_score(cls, findings: list[NormalizedFinding]) -> int:
        """Retorna a pontuação consolidada de risco do ativo (0 a 100)."""
        return cls.calculate_posture_summary(findings).risk_score

    @classmethod
    def calculate_risk_score_from_records(
        cls,
        records: list[tuple[str, str, str]],
    ) -> int:
        """Calcula o score de risco (0-100) a partir de tuplas (severity, confidence, result_classification)."""
        has_critical = False
        weighted_sum = 0.0
        for sev_str, conf_str, class_str in records:
            try:
                sev = Severity(sev_str)
            except ValueError:
                sev = Severity.LOW
            try:
                conf = Confidence(conf_str)
            except ValueError:
                conf = Confidence.FIRM
            if sev == Severity.CRITICAL:
                has_critical = True
            classification_factor = 1.0 if class_str == CheckStatus.VULNERABILITY.value else 0.65
            weighted_sum += SEVERITY_WEIGHTS[sev] * CONFIDENCE_MULTIPLIERS[conf] * classification_factor

        score = min(100, round(weighted_sum))
        if has_critical:
            score = max(score, 75)
        return score

    @classmethod
    def calculate_posture_summary(cls, findings: list[NormalizedFinding]) -> RiskPostureSummary:
        """Calcula o score de risco (0-100) e distribuição por severidade a partir de descobertas reais."""
        counts: dict[Severity, int] = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 0,
            Severity.MEDIUM: 0,
            Severity.LOW: 0,
            Severity.INFO: 0,
        }
        confirmed_count = 0
        potential_count = 0
        weighted_sum = 0.0

        for item in findings:
            counts[item.severity] = counts.get(item.severity, 0) + 1
            if item.result_classification == CheckStatus.VULNERABILITY:
                confirmed_count += 1
                classification_factor = 1.0
            else:
                potential_count += 1
                classification_factor = 0.65

            base_weight = SEVERITY_WEIGHTS[item.severity]
            conf_mult = CONFIDENCE_MULTIPLIERS[item.confidence]
            weighted_sum += base_weight * conf_mult * classification_factor

        score = min(100, round(weighted_sum))
        if counts[Severity.CRITICAL] > 0:
            score = max(score, 75)

        if score == 0:
            grade = "A"
        elif score < 20:
            grade = "B"
        elif score < 45:
            grade = "C"
        elif score < 75:
            grade = "D"
        else:
            grade = "F"

        return RiskPostureSummary(
            risk_score=score,
            risk_grade=grade,
            critical_count=counts[Severity.CRITICAL],
            high_count=counts[Severity.HIGH],
            medium_count=counts[Severity.MEDIUM],
            low_count=counts[Severity.LOW],
            info_count=counts[Severity.INFO],
            confirmed_vulnerabilities=confirmed_count,
            potential_vulnerabilities=potential_count,
        )
