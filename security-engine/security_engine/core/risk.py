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
from security_engine.core.evidence import EvidenceManager

SEVERITY_CVSS_V4_FALLBACK: dict[Severity, tuple[str, float]] = {
    Severity.CRITICAL: ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3),
    Severity.HIGH: ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N", 8.2),
    Severity.MEDIUM: ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N", 5.3),
    Severity.LOW: ("CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", 3.1),
    Severity.INFO: ("CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0.0),
}

CHECK_CVSS_V4_CATALOG: dict[str, tuple[str, float]] = {
    # Módulo A — Recon, TLS, Headers, DNS, SRI
    "CHK-A01": ("CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N", 7.7),
    "CHK-A02": ("CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N", 4.8),
    "CHK-A03": ("CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N", 4.3),
    "CHK-A04": ("CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:P/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N", 2.7),
    "CHK-A05": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N", 3.9),
    "CHK-A06": ("CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", 2.7),
    "CHK-A07": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", 3.7),
    "CHK-A08": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", 5.3),
    "CHK-A09": ("CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N", 7.1),
    "CHK-A10": ("CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N", 8.2),
    "CHK-A11": ("CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", 7.4),
    "CHK-A12": ("CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:P/VC:N/VI:L/VA:N/SC:L/SI:L/SA:N", 3.5),
    "CHK-A13": ("CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N", 3.7),
    # Módulo B — Autenticação e Segredos no Cliente
    "CHK-B01": ("CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N", 9.1),
    "CHK-B02": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", 3.9),
    "CHK-B03": ("CVSS:4.0/AV:L/AC:H/AT:P/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", 2.9),
    "CHK-B04": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", 7.5),
    "CHK-B05": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N", 7.8),
    # Módulo C — XSS e SSTI
    "CHK-C01": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:H/SI:H/SA:N", 7.1),
    "CHK-C02": ("CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N", 5.8),
    "CHK-C03": ("CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N", 4.3),
    "CHK-C04": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:H/SI:H/SA:N", 7.3),
    "CHK-C05": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3),
    # Módulo D — SQLi, Command Injection, NoSQL/LDAP/XPath
    "CHK-D01": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N", 7.8),
    "CHK-D02": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N", 8.7),
    "CHK-D03": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.5),
    "CHK-D04": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N", 8.7),
    "CHK-D05": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N", 8.2),
    # Módulo E — Cookies, Prefixos, Entropia e Desserialização
    "CHK-E01": ("CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N", 5.3),
    "CHK-E02": ("CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N", 5.1),
    "CHK-E03": ("CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N", 3.5),
    "CHK-E04": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 8.8),
    # Módulo F — Resiliência DoS, Smuggling e Cache Poisoning
    "CHK-F01": ("CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N", 1.8),
    "CHK-F02": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N", 3.7),
    "CHK-F03": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N", 3.9),
    "CHK-F04": ("CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N", 7.4),
    "CHK-F05": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:H/VA:N/SC:L/SI:L/SA:N", 7.2),
    # Módulo G — APIs REST & GraphQL, CORS, JWT, BOPLA
    "CHK-G01": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N", 7.7),
    "CHK-G02": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", 3.7),
    "CHK-G03": ("CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", 3.4),
    "CHK-G04": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", 5.3),
    "CHK-G05": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N", 8.9),
    "CHK-G06": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", 7.8),
    "CHK-G07": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:L/SC:N/SI:N/SA:N", 5.3),
    # Módulo H — Arquivos Sensíveis, LFI, SSRF, Host Header, Source Maps
    "CHK-H01": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", 9.1),
    "CHK-H02": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", 5.3),
    "CHK-H03": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N", 5.1),
    "CHK-H04": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N", 5.4),
    "CHK-H05": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", 9.1),
    "CHK-H06": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:H/SI:N/SA:N", 8.2),
    "CHK-H07": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N", 7.9),
    "CHK-H08": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N", 7.1),
    "CHK-H09": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", 3.7),
}

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
        """Valida classificação, garante sanitização de evidências e enriquece vetores CVSS v4.0."""
        adjusted = cls.validate_classification_consistency(
            finding.result_classification,
            finding.confidence,
        )
        if adjusted != finding.result_classification:
            finding.result_classification = adjusted

        finding.evidence = EvidenceManager.ensure_sanitized(finding.evidence)

        if finding.cvss_v4_vector is None or finding.cvss_v4_score is None:
            catalog_entry = CHECK_CVSS_V4_CATALOG.get(finding.check_id)
            if catalog_entry is not None:
                vector, base_score = catalog_entry
                if finding.result_classification == CheckStatus.POTENTIAL_VULNERABILITY:
                    score = round(base_score * 0.85, 1)
                else:
                    score = base_score
            else:
                vector, score = SEVERITY_CVSS_V4_FALLBACK[finding.severity]

            if finding.cvss_v4_vector is None:
                finding.cvss_v4_vector = vector
            if finding.cvss_v4_score is None:
                finding.cvss_v4_score = score

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
