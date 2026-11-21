"""Lógica pura e determinística das 7 ferramentas defensivas do Console SOC.

Todas as rotinas operam estritamente em modo defensivo, passivo ou estático,
sem execução de payloads, sem geração de tráfego ofensivo e sem persistência
de segredos em texto claro.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import math
import re
import secrets
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import unquote, urlparse

from security_engine.core.evidence import EvidenceManager

from app.schemas.security_tools import (
    DdosAnalyzeRequest,
    DdosAnalyzeResponse,
    DdosAnomaly,
    DdosIpMetric,
    DdosMitigationSnippet,
    FirewallAnalyzeRequest,
    FirewallAnalyzeResponse,
    FirewallFinding,
    FirewallParsedRule,
    FirewallSimulationResult,
    ForensicsAnalyzeRequest,
    ForensicsAnalyzeResponse,
    ForensicsHashes,
    ForensicsIocs,
    ForensicsJwtInspection,
    ForensicsTimelineSummary,
    MalwareAnalyzeRequest,
    MalwareAnalyzeResponse,
    MalwareDeobfuscationItem,
    MalwareSignatureHit,
    PasswordAnalyzeResponse,
    PasswordComplianceCheck,
    PasswordGenerateRequest,
    PasswordGenerateResponse,
    PentestPhase,
    PentestPlanResponse,
    PentestStepItem,
    WifiAnalyzeRequest,
    WifiAnalyzeResponse,
    WifiConnectedInterface,
    WifiFinding,
    WifiNetworkAssessment,
    WifiNetworkInput,
)

# ---------------------------------------------------------------------------
# 1. Pentest Assistant (OWASP WSTG guiado e integrado ao catálogo CHK-*)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _WstgStepSpec:
    step_id: str
    wstg_ref: str
    title: str
    objective: str
    safe_technique: str
    mapped_checks: tuple[str, ...]
    allowed_in_production: bool
    asset_types: tuple[str, ...] = ("WEB_APP", "REST_API", "GRAPHQL_API", "DOMAIN")


@dataclass(frozen=True)
class _WstgPhaseSpec:
    phase_number: int
    name: str
    description: str
    steps: tuple[_WstgStepSpec, ...]


_PENTEST_PHASES: tuple[_WstgPhaseSpec, ...] = (
    _WstgPhaseSpec(
        phase_number=1,
        name="1. Reconhecimento e Superfície de Ataque",
        description=(
            "Mapeamento passivo de tecnologia exposta, artefatos de build, "
            "interfaces administrativas e registros DNS."
        ),
        steps=(
            _WstgStepSpec(
                step_id="PT-01",
                wstg_ref="WSTG-INFO-02 / WSTG-INFO-08",
                title="Fingerprinting de servidor, frameworks e erros verbosos",
                objective="Identificar banners Server/X-Powered-By e stack traces que facilitem ataques.",
                safe_technique="Inspecionar cabeçalhos HTTP passivos e respostas 404/500 sem fuzzing destrutivo.",
                mapped_checks=("CHK-A07", "CHK-A08"),
                allowed_in_production=True,
            ),
            _WstgStepSpec(
                step_id="PT-02",
                wstg_ref="WSTG-CONF-04 / WSTG-CONF-05",
                title="Exposição de arquivos sensíveis, source maps e painéis debug",
                objective="Garantir que .env, .git, .js.map, /actuator e /admin não estejam acessíveis.",
                safe_technique="Validar caminhos conhecidos com verificação anti-Soft-404 de SPA.",
                mapped_checks=("CHK-H01", "CHK-H07", "CHK-H09"),
                allowed_in_production=True,
            ),
            _WstgStepSpec(
                step_id="PT-03",
                wstg_ref="WSTG-INFO-04",
                title="Auditoria de registros DNS, SPF e DMARC",
                objective="Prevenir spoofing de domínio verificando políticas TXT de e-mail.",
                safe_technique="Consulta passiva DNS TXT (RFC 1035) para SPF (-all) e DMARC (p=reject/quarantine).",
                mapped_checks=("CHK-A12",),
                allowed_in_production=True,
            ),
        ),
    ),
    _WstgPhaseSpec(
        phase_number=2,
        name="2. Criptografia, Transporte e Cabeçalhos HTTP",
        description="Validação de TLS, certificados X.509 e políticas defensivas do navegador.",
        steps=(
            _WstgStepSpec(
                step_id="PT-04",
                wstg_ref="WSTG-CRYP-01 / WSTG-CRYP-03",
                title="Força TLS, validade de certificado e redirecionamento HTTPS",
                objective="Confirmar TLS 1.2+, cifras fortes, cadeia válida e ausência de downgrade HTTP.",
                safe_technique="Handshake TLS passivo e checagem de salto HTTP -> HTTPS.",
                mapped_checks=("CHK-A01", "CHK-A09", "CHK-A10", "CHK-A11"),
                allowed_in_production=True,
            ),
            _WstgStepSpec(
                step_id="PT-05",
                wstg_ref="WSTG-CONF-07 / WSTG-CLNT-09",
                title="Cabeçalhos de segurança (HSTS, CSP, Clickjacking, SRI)",
                objective="Validar defesa em profundidade contra XSS, sniffing e clickjacking.",
                safe_technique="Analisar diretivas CSP (unsafe-inline, frame-ancestors), HSTS e atributos SRI.",
                mapped_checks=("CHK-A02", "CHK-A03", "CHK-A04", "CHK-A05", "CHK-A06", "CHK-A13"),
                allowed_in_production=True,
            ),
        ),
    ),
    _WstgPhaseSpec(
        phase_number=3,
        name="3. Autenticação, Sessão e Tokens",
        description="Revisão de fluxos de login, atributos de cookies, CSRF e segregação de credenciais.",
        steps=(
            _WstgStepSpec(
                step_id="PT-06",
                wstg_ref="WSTG-ATHN-01 / WSTG-ATHN-04",
                title="Transporte de login, enumeração de contas e segredos no cliente",
                objective="Evitar credenciais via GET/HTTP, cache em auth e segredos hardcoded no JS.",
                safe_technique="Inspeção de formulários HTML, respostas de erro de login e bundles JS.",
                mapped_checks=("CHK-B01", "CHK-B02", "CHK-B03", "CHK-B04", "CHK-B05"),
                allowed_in_production=True,
                asset_types=("WEB_APP", "REST_API", "GRAPHQL_API"),
            ),
            _WstgStepSpec(
                step_id="PT-07",
                wstg_ref="WSTG-SESS-02 / WSTG-SESS-05",
                title="Segurança de cookies, prefixos __Host- e proteção anti-CSRF",
                objective="Assegurar HttpOnly, Secure, SameSite, entropia adequada e tokens anti-CSRF.",
                safe_technique="Auditar cabeçalhos Set-Cookie e formulários POST que dependam de sessão.",
                mapped_checks=("CHK-E01", "CHK-E02", "CHK-E03", "CHK-E04", "CHK-H04"),
                allowed_in_production=True,
                asset_types=("WEB_APP", "REST_API", "GRAPHQL_API"),
            ),
        ),
    ),
    _WstgPhaseSpec(
        phase_number=4,
        name="4. Validação de Entrada e Testes Controlados de Injeção",
        description=(
            "Verificações de XSS, SSTI, SQLi diferencial, Command Injection, LFI e SSRF "
            "sob limites estritos de laboratório/homologação."
        ),
        steps=(
            _WstgStepSpec(
                step_id="PT-08",
                wstg_ref="WSTG-INPV-01 / WSTG-CLNT-02",
                title="Reflexão XSS segura, DOM sinks e Template Injection (SSTI)",
                objective="Verificar sanitização contextual sem execução de scripts maliciosos.",
                safe_technique="Enviar marcadores alfanuméricos inofensivos e inspecionar sinks DOM/CSP.",
                mapped_checks=("CHK-C01", "CHK-C02", "CHK-C03", "CHK-C05"),
                allowed_in_production=True,
                asset_types=("WEB_APP", "REST_API", "GRAPHQL_API"),
            ),
            _WstgStepSpec(
                step_id="PT-09",
                wstg_ref="WSTG-INPV-05 / WSTG-INPV-12 / WSTG-ATHZ-01",
                title="Fuzzing contextual, SQLi diferencial, OS Command, LFI e SSRF",
                objective="Validar parametrização de queries, chamadas ao SO, paths de arquivo e URLs.",
                safe_technique=(
                    "Executar apenas em LAB/STAGING com canários não destrutivos e análise diferencial."
                ),
                mapped_checks=("CHK-C04", "CHK-D01", "CHK-D02", "CHK-D03", "CHK-D04", "CHK-D05", "CHK-H05", "CHK-H06"),
                allowed_in_production=False,
                asset_types=("WEB_APP", "REST_API", "GRAPHQL_API"),
            ),
        ),
    ),
    _WstgPhaseSpec(
        phase_number=5,
        name="5. Segurança de APIs, CORS, JWT e Controle de Acesso",
        description="Auditoria de CORS, exposição OpenAPI/GraphQL, JWT e redirecionamentos.",
        steps=(
            _WstgStepSpec(
                step_id="PT-10",
                wstg_ref="WSTG-CLNT-07 / WSTG-CONF-06 / WSTG-APIT-01",
                title="CORS com credenciais, métodos TRACE/Verb Tampering e esquema API",
                objective="Impedir leitura cross-origin indevida, introspecção pública e exposição BOPLA.",
                safe_technique="Testar Origin canário controlado, OPTIONS/TRACE e endpoints /openapi.json /graphql.",
                mapped_checks=("CHK-G01", "CHK-G02", "CHK-G03", "CHK-G04", "CHK-G06", "CHK-G07"),
                allowed_in_production=True,
                asset_types=("WEB_APP", "REST_API", "GRAPHQL_API"),
            ),
            _WstgStepSpec(
                step_id="PT-11",
                wstg_ref="WSTG-SESS-10 / WSTG-CLNT-04",
                title="Configuração de JWT, Open Redirect e Host Header Injection",
                objective="Mitigar alg:none, chaves HMAC fracas, redirecionamentos abertos e reset poisoning.",
                safe_technique="Validar tokens observados e testar canários de redirect/Host sem alterar dados.",
                mapped_checks=("CHK-G05", "CHK-H03", "CHK-H08"),
                allowed_in_production=True,
            ),
        ),
    ),
    _WstgPhaseSpec(
        phase_number=6,
        name="6. Resiliência, Cache e Proteção Anti-Abuso",
        description="Avaliação passiva de WAF/CDN, Rate Limiting, Request Smuggling e Cache Poisoning.",
        steps=(
            _WstgStepSpec(
                step_id="PT-12",
                wstg_ref="WSTG-CONF-06 / WSTG-BUSL-07",
                title="Postura anti-DoS, Rate Limiting, HTTP Desync e Cache Poisoning",
                objective="Confirmar presença de CDN/WAF, cabeçalhos RateLimit-* e isolamento de cache.",
                safe_technique="Inspeção passiva de cabeçalhos de borda e canários seguros não chaveados.",
                mapped_checks=("CHK-F01", "CHK-F02", "CHK-F03", "CHK-F04", "CHK-F05", "CHK-H02"),
                allowed_in_production=True,
            ),
        ),
    ),
)


def build_pentest_plan(
    *,
    target_name: str,
    asset_type: str,
    environment: str,
    authorization_status: str,
    passed_checks: set[str] | None = None,
    finding_checks_count: dict[str, int] | None = None,
) -> PentestPlanResponse:
    """Constrói plano guiado OWASP WSTG correlacionado com checks e guarda de ambiente."""
    passed = passed_checks or set()
    finding_counts = finding_checks_count or {}
    phases: list[PentestPhase] = []
    total_steps = 0
    covered_steps = 0
    total_findings = 0

    for phase_spec in _PENTEST_PHASES:
        step_items: list[PentestStepItem] = []
        for step in phase_spec.steps:
            if asset_type not in step.asset_types:
                continue

            related_findings = sum(finding_counts.get(chk, 0) for chk in step.mapped_checks)
            total_findings += related_findings

            if environment == "PRODUCTION" and not step.allowed_in_production:
                status = "BLOCKED_IN_PRODUCTION"
            elif related_findings > 0:
                status = "COVERED_WITH_FINDINGS"
                covered_steps += 1
            elif any(chk in passed for chk in step.mapped_checks):
                status = "COVERED_PASSED"
                covered_steps += 1
            else:
                status = "NOT_YET_RUN"

            total_steps += 1
            step_items.append(
                PentestStepItem(
                    step_id=step.step_id,
                    wstg_ref=step.wstg_ref,
                    title=step.title,
                    objective=step.objective,
                    safe_technique=step.safe_technique,
                    mapped_checks=list(step.mapped_checks),
                    allowed_in_production=step.allowed_in_production,
                    automated_status=status,
                    related_findings_count=related_findings,
                )
            )

        if step_items:
            phases.append(
                PentestPhase(
                    phase_number=phase_spec.phase_number,
                    name=phase_spec.name,
                    description=phase_spec.description,
                    steps=step_items,
                )
            )

    warnings: list[str] = []
    if authorization_status == "MANUAL_UNVERIFIED":
        warnings.append(
            "Modo de planejamento manual: cadastre o ativo e valide a autorização formal "
            "(DNS_TXT, HTTP_WELL_KNOWN ou LAB_INTERNAL) antes de executar testes ativos."
        )
    elif authorization_status != "VERIFIED":
        warnings.append(
            f"Autorização do ativo está '{authorization_status}'. "
            "Auditorias ativas permanecem bloqueadas até comprovação VERIFIED."
        )
    if environment == "PRODUCTION":
        warnings.append(
            "Ambiente PRODUCTION: etapas de injeção/fuzzing profundo permanecem bloqueadas "
            "pelo guardrail ético."
        )

    return PentestPlanResponse(
        target_name=target_name,
        asset_type=asset_type,
        environment=environment,
        authorization_status=authorization_status,
        authorization_warning=" ".join(warnings) if warnings else None,
        total_steps=total_steps,
        automated_covered_steps=covered_steps,
        open_findings_count=total_findings,
        phases=phases,
    )


# ---------------------------------------------------------------------------
# 2. Password Tools (Geração CSPRNG + Análise de Entropia e Conformidade)
# ---------------------------------------------------------------------------

_DICEWARE_WORDS: tuple[str, ...] = (
    "abacaxi", "albatroz", "amendoa", "ancora", "antena", "aquario", "arenito", "arvoredo",
    "asteroide", "atletico", "aurora", "azulejo", "bambuzal", "bandeira", "barometro", "basalto",
    "bateria", "bergamota", "biblioteca", "bicicleta", "bussola", "cacau", "cachoeira", "caderno",
    "cafeeiro", "caldeira", "camaleao", "camelia", "caminhao", "campina", "canario", "candelabro",
    "canela", "canhao", "canoagem", "capivara", "caravela", "carvalho", "cascata", "castanha",
    "catavento", "catedral", "cavaleiro", "cedro", "centauro", "ceramica", "cereal", "cerejeira",
    "chamine", "chapada", "ciclone", "cilindro", "cinamomo", "cinturao", "cipreste", "ciranda",
    "cisterna", "cidadela", "clarinete", "coentro", "colibri", "colina", "cometa", "compasso",
    "concha", "condor", "coniferas", "constante", "contorno", "coralina", "cordilheira", "coruja",
    "cosmonauta", "cratera", "cristal", "croissant", "cruzeiro", "cupuacu", "damasco", "delfim",
    "deserto", "diamante", "dinamo", "dossel", "dragao", "eclipse", "edredom", "elefante",
    "emblema", "esmeralda", "espiral", "estacao", "estrelado", "estuario", "eucalipto", "falcao",
    "farol", "ferrovia", "figueira", "filigrana", "floresta", "foguete", "formiga", "fortaleza",
    "fragata", "framboesa", "galaxia", "garoa", "gavioes", "geleira", "girassol", "granito",
    "gravidade", "guaranas", "harpa", "horizonte", "hortela", "iceberg", "iguana", "imbuia",
    "imperio", "indigo", "infinito", "ipe", "iris", "jabuti", "jacaranda", "jade",
    "jaguar", "jasmim", "jequitiba", "juriti", "labirinto", "laguna", "lampada", "laranjeira",
    "latitudes", "lavanda", "legenda", "leopardo", "libelula", "limoeiro", "linterna", "litoral",
)

_COMMON_WEAK_PASSWORDS: frozenset[str] = frozenset(
    {
        "123456", "12345678", "123456789", "1234567890", "password", "password123",
        "admin", "admin123", "administrator", "root", "toor", "qwerty", "qwerty123",
        "abc123", "senha", "senha123", "mudar123", "changeme", "letmein", "welcome",
        "1q2w3e4r", "111111", "000000", "passw0rd", "p@ssw0rd", "iloveyou", "secret",
        "test", "teste123", "guest", "oracle", "postgres", "master", "default",
    }
)

_KEYBOARD_SEQUENCES: tuple[str, ...] = (
    "0123456789",
    "9876543210",
    "abcdefghijklmnopqrstuvwxyz",
    "zyxwvutsrqponmlkjihgfedcba",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
)

_AMBIGUOUS_CHARS = set("0Oo1lI|")
_SYMBOLS_POOL = "!@#$%^&*()-_=+[]{}:;,.?/~"


def _shannon_entropy_per_char(text: str) -> float:
    if not text:
        return 0.0
    total = len(text)
    counts = Counter(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _format_crack_time_pt(seconds: float) -> str:
    if seconds < 1:
        return "menos de 1 segundo"
    if seconds < 60:
        return f"~{int(seconds)} segundos"
    minutes = seconds / 60
    if minutes < 60:
        return f"~{int(minutes)} minutos"
    hours = minutes / 60
    if hours < 24:
        return f"~{int(hours)} horas"
    days = hours / 24
    if days < 365:
        return f"~{int(days)} dias"
    years = days / 365.25
    if years < 1000:
        return f"~{int(years)} anos"
    if years < 1_000_000:
        return f"~{int(years / 1000)} mil anos"
    return "milhões de anos / séculos"


def _strength_label_from_entropy(bits: float) -> str:
    if bits < 40:
        return "Fraca"
    if bits < 60:
        return "Moderada"
    if bits < 80:
        return "Forte"
    return "Muito Forte"


def generate_password(req: PasswordGenerateRequest) -> PasswordGenerateResponse:
    """Gera senha aleatória ou passphrase usando CSPRNG (`secrets`)."""
    sys_rand = secrets.SystemRandom()

    if req.mode == "PASSPHRASE":
        words = [secrets.choice(_DICEWARE_WORDS) for _ in range(req.word_count)]
        if req.include_number:
            idx = secrets.randbelow(len(words))
            words[idx] = f"{words[idx]}{secrets.randbelow(90) + 10}"
        generated = req.separator.join(words)
        entropy = round(
            req.word_count * math.log2(len(_DICEWARE_WORDS)) + (math.log2(90 * req.word_count) if req.include_number else 0.0),
            2,
        )
        return PasswordGenerateResponse(
            generated=generated,
            mode=req.mode,
            length=len(generated),
            entropy_bits=entropy,
            strength_label=_strength_label_from_entropy(entropy),
        )

    pools: list[str] = []
    if req.include_uppercase:
        pools.append("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    if req.include_lowercase:
        pools.append("abcdefghijklmnopqrstuvwxyz")
    if req.include_digits:
        pools.append("0123456789")
    if req.include_symbols:
        pools.append(_SYMBOLS_POOL)

    if req.exclude_ambiguous:
        pools = ["".join(ch for ch in p if ch not in _AMBIGUOUS_CHARS) for p in pools]
        pools = [p for p in pools if p]

    if not pools:
        raise ValueError("Selecione ao menos um conjunto de caracteres para gerar a senha.")

    combined = "".join(pools)
    chars: list[str] = []
    if req.length >= len(pools):
        for pool in pools:
            chars.append(secrets.choice(pool))
    while len(chars) < req.length:
        chars.append(secrets.choice(combined))
    sys_rand.shuffle(chars)
    generated = "".join(chars[: req.length])

    entropy = round(req.length * math.log2(len(combined)), 2)
    return PasswordGenerateResponse(
        generated=generated,
        mode=req.mode,
        length=len(generated),
        entropy_bits=entropy,
        strength_label=_strength_label_from_entropy(entropy),
    )


def analyze_password(password: str) -> PasswordAnalyzeResponse:
    """Analisa entropia, padrões previsíveis, tempo de quebra e conformidade NIST/OWASP."""
    length = len(password)
    has_lower = any("a" <= c <= "z" for c in password)
    has_upper = any("A" <= c <= "Z" for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() and ord(c) < 128 for c in password)
    has_unicode = any(ord(c) >= 128 for c in password)

    pool_size = (
        (26 if has_lower else 0)
        + (26 if has_upper else 0)
        + (10 if has_digit else 0)
        + (32 if has_symbol else 0)
        + (64 if has_unicode else 0)
    )
    pool_size = max(pool_size, 1)

    keyspace_entropy = round(length * math.log2(pool_size), 2)
    shannon_total = round(_shannon_entropy_per_char(password) * length, 2)

    lowered = password.lower()
    patterns: list[str] = []
    penalty = 0.0

    if lowered in _COMMON_WEAK_PASSWORDS or any(w in lowered and len(w) >= 5 for w in _COMMON_WEAK_PASSWORDS):
        patterns.append("Contém senha comum ou palavra frequentemente vazada em dicionários.")
        penalty += 45.0

    if any(seq[i : i + 4] in lowered for seq in _KEYBOARD_SEQUENCES for i in range(len(seq) - 3)):
        patterns.append("Sequência previsível de teclado ou alfanumérica detectada.")
        penalty += 22.0

    if re.search(r"(.)\1{2,}", password):
        patterns.append("Repetição consecutiva do mesmo caractere (3 ou mais vezes).")
        penalty += 18.0

    if re.search(r"(19\d{2}|20[0-3]\d)", password):
        patterns.append("Padrão de ano calendário detectado (ex.: 1990–2039).")
        penalty += 10.0

    char_classes = sum([has_lower, has_upper, has_digit, has_symbol or has_unicode])
    if char_classes <= 1:
        patterns.append("Uso de apenas uma classe de caracteres reduz drasticamente o espaço de busca.")
        penalty += 18.0

    if length < 12:
        patterns.append("Comprimento inferior a 12 caracteres (abaixo da recomendação moderna).")
        penalty += max(0.0, (12 - length) * 4.0)

    effective_bits = max(1.0, min(keyspace_entropy, shannon_total + 12.0) - (penalty * 0.65))
    raw_score = min(100.0, max(0.0, (effective_bits / 90.0) * 100.0 - (penalty * 0.4)))
    if lowered in _COMMON_WEAK_PASSWORDS:
        raw_score = min(raw_score, 12.0)
    score = round(raw_score)

    if score < 25:
        classification = "CRITICAL_WEAK"
    elif score < 45:
        classification = "WEAK"
    elif score < 68:
        classification = "FAIR"
    elif score < 85:
        classification = "STRONG"
    else:
        classification = "VERY_STRONG"

    guesses = 2.0 ** min(effective_bits, 100.0)
    crack_slow = _format_crack_time_pt(guesses / 10_000.0)
    crack_fast = _format_crack_time_pt(guesses / 10_000_000_000.0)

    compliance_checks = [
        PasswordComplianceCheck(
            standard="NIST SP 800-63B (Comprimento mínimo >= 8; recomendado >= 12)",
            passed=length >= 8,
            detail=f"Comprimento atual: {length} caracteres."
            + (" Recomendável ampliar para 12+." if 8 <= length < 12 else ""),
        ),
        PasswordComplianceCheck(
            standard="NIST SP 800-63B (Bloqueio contra dicionário e sequências)",
            passed=not any("comum" in p or "Sequência" in p for p in patterns),
            detail="Nenhum termo comum ou sequência trivial identificado."
            if not any("comum" in p or "Sequência" in p for p in patterns)
            else "Contém padrões fáceis de adivinhar por dicionário.",
        ),
        PasswordComplianceCheck(
            standard="OWASP ASVS V2.1 (Entropia efetiva >= 60 bits e diversidade)",
            passed=effective_bits >= 60.0 and char_classes >= 3,
            detail=f"Entropia de espaço={keyspace_entropy} bits, classes={char_classes}/4.",
        ),
        PasswordComplianceCheck(
            standard="OWASP ASVS V2.1 (Ausência de repetições consecutivas)",
            passed=not re.search(r"(.)\1{2,}", password),
            detail="Sem sequências repetitivas de caracteres."
            if not re.search(r"(.)\1{2,}", password)
            else "Há caracteres repetidos em sequência.",
        ),
    ]

    recommendations: list[str] = []
    if length < 14:
        recommendations.append("Utilize pelo menos 14 a 16 caracteres ou uma passphrase de 5+ palavras.")
    if char_classes < 3:
        recommendations.append("Combine letras maiúsculas, minúsculas, números e símbolos não previsíveis.")
    if patterns:
        recommendations.append("Substitua sequências de teclado, datas e palavras conhecidas por aleatoriedade real.")
    if not recommendations:
        recommendations.append("Senha aderente às recomendações; habilite MFA e armazene apenas com Argon2id.")

    return PasswordAnalyzeResponse(
        length=length,
        score=score,
        classification=classification,
        pool_size=pool_size,
        keyspace_entropy_bits=keyspace_entropy,
        shannon_entropy_bits=shannon_total,
        crack_time_offline_slow=crack_slow,
        crack_time_offline_fast=crack_fast,
        detected_patterns=patterns,
        compliance_checks=compliance_checks,
        recommendations=recommendations,
    )


# ---------------------------------------------------------------------------
# 3. Forensics (Hashes, Extração/Defang de IOCs, Timeline, JWT e Segredos)
# ---------------------------------------------------------------------------

_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_IPV6_RE = re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4}\b")
_URL_RE = re.compile(r"\bhttps?://[^\s\"'<>)\]]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,15}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]{1,63}\.)+(?:[a-zA-Z]{2,12})\b")
_HASH_HEX_RE = re.compile(r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_JWT_TOKEN_RE = re.compile(
    r"\b(eyJ[A-Za-z0-9_-]{4,})\.(eyJ[A-Za-z0-9_-]{4,})\.([A-Za-z0-9_-]*)(?![A-Za-z0-9_-])"
)
_ISO_TS_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b")
_CLF_TS_RE = re.compile(r"\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4})\]")
_HTTP_LOG_STATUS_RE = re.compile(r'"\s+([1-5]\d{2})\s+(?:\d+|-)')
_AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_PRIV_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")
_GH_TOKEN_RE = re.compile(r"\b(?:ghp|gho|ghu|ghs)_[A-Za-z0-9]{20,}\b")
_CSC_TOKEN_RE = re.compile(r"\bcsc_live_[A-Za-z0-9_-]{12,}\b")


def _compute_hashes(raw_bytes: bytes) -> ForensicsHashes:
    return ForensicsHashes(
        md5=hashlib.md5(raw_bytes).hexdigest(),
        sha1=hashlib.sha1(raw_bytes).hexdigest(),
        sha256=hashlib.sha256(raw_bytes).hexdigest(),
        sha512=hashlib.sha512(raw_bytes).hexdigest(),
    )


def _defang_value(value: str, enabled: bool) -> str:
    if not enabled:
        return value
    out = re.sub(r"^https://", "hxxps://", value, flags=re.IGNORECASE)
    out = re.sub(r"^http://", "hxxp://", out, flags=re.IGNORECASE)
    return out.replace(".", "[.]")


def _decode_jwt_segment(segment: str) -> dict[str, object] | None:
    try:
        padded = segment + "=" * (-len(segment) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        parsed = json.loads(decoded.decode("utf-8"))
        return parsed if isinstance(parsed, dict) else None
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def _sanitize_jwt_claims(claims: dict[str, object]) -> dict[str, object]:
    sensitive_keys = {"password", "secret", "token", "refresh_token", "api_key", "ssn", "cpf"}
    sanitized: dict[str, object] = {}
    for k, v in claims.items():
        if k.lower() in sensitive_keys:
            sanitized[k] = "[REDACTED]"
        elif isinstance(v, str):
            clean, _ = EvidenceManager.sanitize_text_snippet(v, max_chars=256)
            sanitized[k] = clean or ""
        else:
            sanitized[k] = v
    return sanitized


_INTERNAL_IPV4_NETS: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),
    ipaddress.IPv4Network("100.64.0.0/10"),
    ipaddress.IPv4Network("0.0.0.0/8"),
)


def analyze_forensics(req: ForensicsAnalyzeRequest) -> ForensicsAnalyzeResponse:
    """Executa análise forense estática: hashes, IOCs, linha do tempo, JWT e segredos."""
    raw_bytes = req.content.encode("utf-8", errors="replace")
    hashes = _compute_hashes(raw_bytes)
    entropy = round(_shannon_entropy_per_char(req.content), 3)
    line_count = len(req.content.splitlines()) or 1

    pub_v4: set[str] = set()
    priv_v4: set[str] = set()
    for candidate in _IPV4_RE.findall(req.content):
        try:
            addr = ipaddress.IPv4Address(candidate)
        except ValueError:
            continue
        formatted = _defang_value(str(addr), req.defang_iocs)
        if any(addr in net for net in _INTERNAL_IPV4_NETS) or addr.is_multicast:
            priv_v4.add(formatted)
        else:
            pub_v4.add(formatted)

    ipv6_set: set[str] = set()
    for candidate in _IPV6_RE.findall(req.content):
        if re.fullmatch(r"\d{2}:\d{2}:\d{2}", candidate):
            continue
        try:
            addr6 = ipaddress.IPv6Address(candidate)
            ipv6_set.add(str(addr6))
        except ValueError:
            continue

    raw_urls = _URL_RE.findall(req.content)
    urls_clean: set[str] = set()
    for u in raw_urls:
        clean_u, _ = EvidenceManager.sanitize_url(u.rstrip(".,;"))
        urls_clean.add(_defang_value(clean_u, req.defang_iocs))

    emails = sorted(set(_EMAIL_RE.findall(req.content)))[:40]
    domains: set[str] = set()
    for d in _DOMAIN_RE.findall(req.content):
        if not _IPV4_RE.fullmatch(d) and not re.fullmatch(
            r".*\.(?:log|txt|py|js|ts|json|exe|dll|sh|ps1)", d, re.IGNORECASE
        ):
            domains.add(_defang_value(d.lower(), req.defang_iocs))

    hashes_found = sorted(set(_HASH_HEX_RE.findall(req.content)))[:40]
    cves = sorted({c.upper() for c in _CVE_RE.findall(req.content)})[:40]

    # Timeline & HTTP Status histogram
    timestamps: list[str] = _ISO_TS_RE.findall(req.content)
    timestamps.extend(_CLF_TS_RE.findall(req.content))
    status_counter = Counter(_HTTP_LOG_STATUS_RE.findall(req.content))
    timeline = ForensicsTimelineSummary(
        events_detected=len(timestamps),
        first_timestamp=timestamps[0] if timestamps else None,
        last_timestamp=timestamps[-1] if timestamps else None,
        http_status_counts=dict(sorted(status_counter.items())),
    )

    # JWT passive forensic inspection
    jwt_match = _JWT_TOKEN_RE.search(req.content)
    jwt_info = ForensicsJwtInspection(detected=False, warnings=[])
    if jwt_match:
        header = _decode_jwt_segment(jwt_match.group(1))
        payload = _decode_jwt_segment(jwt_match.group(2))
        sig = jwt_match.group(3)
        jwt_warnings: list[str] = []
        if header is not None:
            alg = str(header.get("alg", "")).lower()
            if alg == "none" or not sig:
                jwt_warnings.append("Token JWT sem assinatura ou com algoritmo 'none' (risco crítico).")
            if alg.startswith("hs"):
                jwt_warnings.append("JWT usa assinatura simétrica HMAC (validar segredo forte no servidor).")
        if payload is not None:
            if "exp" not in payload:
                jwt_warnings.append("Token JWT sem claim 'exp' (não expira automaticamente).")
            elif isinstance(payload.get("exp"), (int, float)):
                exp_ts = float(payload["exp"])
                if exp_ts < datetime.now(UTC).timestamp():
                    jwt_warnings.append("Token JWT já está expirado conforme claim 'exp'.")
        jwt_info = ForensicsJwtInspection(
            detected=True,
            header=header,
            payload_sanitized=_sanitize_jwt_claims(payload) if payload else None,
            warnings=jwt_warnings,
        )

    # Secret leak warnings (sempre mascarados)
    secret_warnings: list[str] = []
    if _AWS_KEY_RE.search(req.content):
        secret_warnings.append("Possível AWS Access Key ID detectada (AKIA...[REDACTED]).")
    if _PRIV_KEY_RE.search(req.content):
        secret_warnings.append("Bloco de chave privada PEM/OpenSSH detectado no artefato.")
    if _GH_TOKEN_RE.search(req.content) or _CSC_TOKEN_RE.search(req.content):
        secret_warnings.append("Token de API ou GitHub detectado no conteúdo (revogar se exposto).")
    if re.search(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}", req.content):
        secret_warnings.append("Cabeçalho Authorization Bearer exposto no artefato analisado.")
    if jwt_match:
        secret_warnings.append("Token JWT identificado no conteúdo (evitar persistência em logs).")

    iocs = ForensicsIocs(
        ipv4_public=sorted(pub_v4)[:50],
        ipv4_private=sorted(priv_v4)[:50],
        ipv6=sorted(ipv6_set)[:30],
        domains=sorted(domains)[:50],
        urls=sorted(urls_clean)[:50],
        emails=emails,
        hashes=hashes_found,
        cves=cves,
    )

    total_iocs = (
        len(iocs.ipv4_public)
        + len(iocs.ipv4_private)
        + len(iocs.domains)
        + len(iocs.urls)
        + len(iocs.hashes)
        + len(iocs.cves)
    )
    summary = (
        f"Artefato '{req.artifact_name or 'evidencia.txt'}' ({len(raw_bytes)} bytes, {line_count} linhas): "
        f"{total_iocs} IOC(s) extraído(s), {timeline.events_detected} timestamp(s) e "
        f"{len(secret_warnings)} alerta(s) de exposição de credenciais."
    )

    return ForensicsAnalyzeResponse(
        artifact_name=req.artifact_name or "evidencia.txt",
        size_bytes=len(raw_bytes),
        line_count=line_count,
        shannon_entropy=entropy,
        hashes=hashes,
        iocs=iocs,
        timeline=timeline,
        jwt_inspection=jwt_info,
        secret_leak_warnings=secret_warnings,
        summary=summary,
    )


# ---------------------------------------------------------------------------
# 4. Firewall Tester (Auditoria Estática de Regras & Simulação de Pacote)
# ---------------------------------------------------------------------------

_CRITICAL_EXPOSED_PORTS: dict[int, str] = {
    22: "SSH",
    23: "Telnet (texto claro)",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL/MariaDB",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    9200: "Elasticsearch",
    27017: "MongoDB",
}
_CLEARTEXT_PORTS: set[int] = {21, 23, 80}


def _normalize_cidr(raw: str) -> str:
    cleaned = raw.strip().lower()
    if cleaned in {"any", "*", "anywhere", "0.0.0.0/0", "::/0"}:
        return "::/0" if cleaned == "::/0" else "0.0.0.0/0"
    if "/" not in cleaned:
        try:
            addr = ipaddress.ip_address(cleaned)
            return f"{addr}/32" if addr.version == 4 else f"{addr}/128"
        except ValueError:
            return raw.strip()
    try:
        return str(ipaddress.ip_network(cleaned, strict=False))
    except ValueError:
        return raw.strip()


def _parse_ports_set(port_spec: str) -> tuple[bool, set[int]]:
    spec = port_spec.strip().upper()
    if spec in {"ANY", "*"}:
        return True, set()
    ports: set[int] = set()
    for part in spec.split(","):
        token = part.strip().split("/")[0]
        if "-" in token or ":" in token:
            sep = "-" if "-" in token else ":"
            bounds = token.split(sep, 1)
            if bounds[0].isdigit() and bounds[1].isdigit():
                lo, hi = int(bounds[0]), int(bounds[1])
                if 1 <= lo <= hi <= 65535 and (hi - lo) <= 1024:
                    ports.update(range(lo, hi + 1))
        elif token.isdigit():
            val = int(token)
            if 1 <= val <= 65535:
                ports.add(val)
    return False, ports


def _parse_single_firewall_line(
    line_num: int, line: str
) -> tuple[FirewallParsedRule | None, bool, bool]:
    """Interpreta regra iptables/UFW/genérica.

    Retorna (regra_sequencial, is_catchall_deny_rule, is_default_policy_directive).
    """
    stripped = line.strip()
    lower = stripped.lower()

    # Diretiva de política padrão (não deve sombrear regras explícitas abaixo dela)
    if re.search(r"iptables\s+-p\s+input\s+(drop|reject)", lower) or re.search(
        r"^(?:ufw\s+)?default\s+deny(?:\s+incoming)?\b", lower
    ):
        return None, False, True

    # iptables -A INPUT -p tcp -s 10.0.0.0/8 --dport 22 -j ACCEPT
    if "-a " in lower or "iptables" in lower:
        action_m = re.search(r"-j\s+(accept|drop|reject|deny)", lower)
        if action_m:
            action: str = "ALLOW" if action_m.group(1) == "accept" else "DENY"
            proto_m = re.search(r"(?:-p|--protocol)\s+(tcp|udp|icmp|all|any)", lower)
            src_m = re.search(r"(?:-s|--source)\s+(\S+)", lower)
            dport_m = re.search(r"(?:--dport|--dports)\s+(\S+)", lower)
            proto = proto_m.group(1).upper() if proto_m else "ANY"
            if proto == "ALL":
                proto = "ANY"
            src = _normalize_cidr(src_m.group(1) if src_m else "0.0.0.0/0")
            port = (dport_m.group(1) if dport_m else "ANY").upper()
            is_def = (
                action == "DENY"
                and proto == "ANY"
                and src in {"0.0.0.0/0", "::/0"}
                and port == "ANY"
            )
            return (
                FirewallParsedRule(
                    line_number=line_num,
                    raw=stripped,
                    action=action,  # type: ignore[arg-type]
                    protocol=proto,
                    source_cidr=src,
                    port_spec=port,
                ),
                is_def,
                False,
            )

    # UFW ou formato genérico: ALLOW TCP 0.0.0.0/0 22 | ufw allow 443/tcp
    if lower.startswith("ufw ") or re.match(r"^(allow|deny|drop|reject)\s+", lower):
        ufw_body = re.sub(r"^ufw\s+", "", lower)
        act_m = re.match(r"^(allow|deny|drop|reject)\b", ufw_body)
        if act_m:
            action = "ALLOW" if act_m.group(1) == "allow" else "DENY"
            src_m = re.search(r"\bfrom\s+(\S+)", ufw_body)
            port_m = re.search(r"\bport\s+(\S+)", ufw_body)
            proto_m = re.search(r"\bproto\s+(tcp|udp|icmp|any)", ufw_body)
            simple_port_m = re.search(r"\b(\d{1,5}(?::\d{1,5})?)/(tcp|udp)\b", ufw_body)
            simple_num_m = re.search(r"^(?:allow|deny|drop|reject)\s+(?:in\s+)?(\d{1,5})\b", ufw_body)

            tokens = stripped.split()
            if (
                not lower.startswith("ufw ")
                and len(tokens) >= 4
                and tokens[0].upper() in {"ALLOW", "DENY", "DROP", "REJECT"}
                and "from" not in ufw_body
                and "port" not in ufw_body
            ):
                action = "ALLOW" if tokens[0].upper() == "ALLOW" else "DENY"
                proto = tokens[1].upper()
                src = _normalize_cidr(tokens[2])
                port = tokens[3].upper()
            else:
                src = _normalize_cidr(src_m.group(1) if src_m else "0.0.0.0/0")
                if simple_port_m:
                    port = simple_port_m.group(1)
                    proto = simple_port_m.group(2).upper()
                elif port_m:
                    port = port_m.group(1).upper()
                    proto = proto_m.group(1).upper() if proto_m else "ANY"
                elif simple_num_m:
                    port = simple_num_m.group(1)
                    proto = proto_m.group(1).upper() if proto_m else "ANY"
                else:
                    proto = proto_m.group(1).upper() if proto_m else "ANY"
                    port = "ANY"

            is_def = (
                action == "DENY"
                and proto == "ANY"
                and src in {"0.0.0.0/0", "::/0"}
                and port == "ANY"
            )
            return (
                FirewallParsedRule(
                    line_number=line_num,
                    raw=stripped,
                    action=action,  # type: ignore[arg-type]
                    protocol=proto,
                    source_cidr=src,
                    port_spec=port,
                ),
                is_def,
                False,
            )

    return None, False, False


def _cidr_covers(outer: str, inner: str) -> bool:
    if outer in {"0.0.0.0/0", "::/0"} and outer == inner:
        return True
    try:
        net_outer = ipaddress.ip_network(outer, strict=False)
        net_inner = ipaddress.ip_network(inner, strict=False)
    except ValueError:
        return outer == inner
    if net_outer.version != net_inner.version:
        return False
    return net_inner.subnet_of(net_outer)  # type: ignore[arg-type]


def analyze_firewall_rules(req: FirewallAnalyzeRequest) -> FirewallAnalyzeResponse:
    """Audita regras de firewall quanto a exposição, sombreamento, default-deny e simula pacote."""
    parsed_rules: list[FirewallParsedRule] = []
    unparsed_lines: list[int] = []
    findings: list[FirewallFinding] = []
    has_default_deny = False

    for idx, line in enumerate(req.rules_text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";", "//")):
            continue
        rule, is_def, is_default_policy = _parse_single_firewall_line(idx, stripped)
        if is_default_policy:
            has_default_deny = True
            continue
        if rule is None:
            unparsed_lines.append(idx)
            continue
        parsed_rules.append(rule)
        if is_def:
            has_default_deny = True

    for rule in parsed_rules:
        is_any_src = rule.source_cidr in {"0.0.0.0/0", "::/0"}
        is_any_port, ports = _parse_ports_set(rule.port_spec)

        if rule.action == "ALLOW" and is_any_src and is_any_port:
            findings.append(
                FirewallFinding(
                    severity="CRITICAL",
                    line_number=rule.line_number,
                    title="Regra permissiva irrestrita (ALLOW ANY ANY)",
                    description=f"Linha {rule.line_number} permite todo tráfego de qualquer origem.",
                    cwe_id="CWE-284",
                    remediation="Restrinja protocolo, porta de destino e blocos CIDR de origem específicos.",
                )
            )
        elif rule.action == "ALLOW" and is_any_src:
            exposed_admin = [p for p in sorted(ports) if p in _CRITICAL_EXPOSED_PORTS]
            if exposed_admin:
                names = ", ".join(f"{p} ({_CRITICAL_EXPOSED_PORTS[p]})" for p in exposed_admin)
                findings.append(
                    FirewallFinding(
                        severity="CRITICAL",
                        line_number=rule.line_number,
                        title="Serviço administrativo ou banco de dados exposto à internet (0.0.0.0/0)",
                        description=f"Linha {rule.line_number} libera {names} para qualquer endereço IP.",
                        cwe_id="CWE-284",
                        remediation="Restrinja o acesso a VPN/bastion corporativo ou IPs administrativos autorizados.",
                    )
                )
            elif any(p in _CLEARTEXT_PORTS for p in ports):
                findings.append(
                    FirewallFinding(
                        severity="HIGH",
                        line_number=rule.line_number,
                        title="Porta de protocolo em texto claro aberta publicamente",
                        description=f"Linha {rule.line_number} expõe porta {rule.port_spec} para {rule.source_cidr}.",
                        cwe_id="CWE-319",
                        remediation="Migre para HTTPS/TLS (443) ou SFTP/SSH restrito por origem.",
                    )
                )

    # Detecção de regras sombreadas (shadowing)
    for i, earlier in enumerate(parsed_rules):
        e_any_port, e_ports = _parse_ports_set(earlier.port_spec)
        for later in parsed_rules[i + 1 :]:
            if earlier.protocol not in {"ANY", later.protocol}:
                continue
            if not _cidr_covers(earlier.source_cidr, later.source_cidr):
                continue
            l_any_port, l_ports = _parse_ports_set(later.port_spec)
            port_covered = e_any_port or (not l_any_port and bool(l_ports) and l_ports.issubset(e_ports))
            if port_covered:
                findings.append(
                    FirewallFinding(
                        severity="MEDIUM",
                        line_number=later.line_number,
                        title=f"Regra sombreada pela linha {earlier.line_number}",
                        description=(
                            f"A regra na linha {later.line_number} nunca será avaliada porque a linha "
                            f"{earlier.line_number} ({earlier.action} {earlier.source_cidr} {earlier.port_spec}) "
                            "já cobre todo o tráfego correspondente."
                        ),
                        cwe_id="CWE-670",
                        remediation="Reordene regras específicas antes das regras amplas ou remova redundâncias.",
                    )
                )
                break

    if not has_default_deny:
        findings.append(
            FirewallFinding(
                severity="HIGH",
                line_number=None,
                title="Ausência de política explícita Default-Deny",
                description="O conjunto de regras não encerra com bloqueio padrão (DROP/DENY ANY).",
                cwe_id="CWE-1188",
                remediation="Adicione política padrão 'DROP' no chain INPUT ou 'ufw default deny incoming'.",
            )
        )

    score = 100
    penalties = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 5, "INFO": 0}
    for f in findings:
        score -= penalties.get(f.severity, 0)
    if not parsed_rules and not has_default_deny:
        score = 0
    score = max(0, min(100, score))

    simulation: FirewallSimulationResult | None = None
    if req.test_packet is not None:
        pkt = req.test_packet
        try:
            pkt_ip = ipaddress.ip_address(pkt.source_ip.strip())
        except ValueError:
            simulation = FirewallSimulationResult(
                verdict="DEFAULT_IMPLICIT",
                explanation=f"Endereço IP de origem inválido para simulação: {pkt.source_ip}",
            )
        else:
            matched: FirewallParsedRule | None = None
            for rule in parsed_rules:
                if rule.protocol not in {"ANY", pkt.protocol}:
                    continue
                try:
                    net = ipaddress.ip_network(rule.source_cidr, strict=False)
                except ValueError:
                    continue
                if pkt_ip.version != net.version or pkt_ip not in net:
                    continue
                any_p, ports = _parse_ports_set(rule.port_spec)
                if not any_p and pkt.destination_port not in ports:
                    continue
                matched = rule
                break

            if matched:
                simulation = FirewallSimulationResult(
                    verdict=matched.action,
                    matched_line=matched.line_number,
                    matched_rule=matched.raw,
                    explanation=(
                        f"Pacote {pkt.protocol} de {pkt.source_ip} para porta {pkt.destination_port} "
                        f"correspondeu à regra da linha {matched.line_number} ({matched.action})."
                    ),
                )
            elif has_default_deny:
                simulation = FirewallSimulationResult(
                    verdict="DENY",
                    explanation=(
                        f"Nenhuma regra explícita liberou {pkt.protocol} {pkt.source_ip}:"
                        f"{pkt.destination_port}; bloqueado pela política padrão Default-Deny."
                    ),
                )
            else:
                simulation = FirewallSimulationResult(
                    verdict="DEFAULT_IMPLICIT",
                    explanation=(
                        f"Nenhuma regra explícita correspondeu a {pkt.protocol} {pkt.source_ip}:"
                        f"{pkt.destination_port}; recomenda-se política implícita DENY."
                    ),
                )

    return FirewallAnalyzeResponse(
        total_rules_parsed=len(parsed_rules),
        unparsed_lines=unparsed_lines,
        posture_score=score,
        has_default_deny=has_default_deny,
        parsed_rules=parsed_rules,
        findings=findings,
        simulation=simulation,
    )


# ---------------------------------------------------------------------------
# 5. Malware Analysis (Análise Estática, Desofuscação Segura e MITRE ATT&CK)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _StaticMalwareRule:
    rule_id: str
    name: str
    severity: str
    mitre_attack: str
    pattern: re.Pattern[str]
    description: str


_MALWARE_RULES: tuple[_StaticMalwareRule, ...] = (
    _StaticMalwareRule(
        rule_id="MAL-001",
        name="Download Cradle PowerShell com IEX / Net.WebClient",
        severity="CRITICAL",
        mitre_attack="T1059.001",
        pattern=re.compile(
            r"(?i)(?:invoke-expression|\biex\b).*(?:downloadstring|invoke-webrequest|webclient|irm\b)"
            r"|(?:net\.webclient).*(?:downloadstring|downloadfile)"
        ),
        description="Padrão típico de download e execução em memória via PowerShell.",
    ),
    _StaticMalwareRule(
        rule_id="MAL-002",
        name="PowerShell com Comando Codificado (-EncodedCommand / -enc)",
        severity="HIGH",
        mitre_attack="T1059.001 / T1027",
        pattern=re.compile(r"(?i)powershell(?:\.exe)?\s+.*-(?:e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}"),
        description="Invocação de PowerShell ofuscada por parâmetro Base64 UTF-16LE.",
    ),
    _StaticMalwareRule(
        rule_id="MAL-003",
        name="Indicador de Reverse Shell (/dev/tcp, nc -e, bash -i)",
        severity="CRITICAL",
        mitre_attack="T1059.004",
        pattern=re.compile(r"(?i)(?:/dev/tcp/|bash\s+-i\s+>&|\bnc\b\s+.*-e\s+/bin/|mkfifo\s+/tmp/)"),
        description="Comando de redirecionamento de shell interativo para host remoto.",
    ),
    _StaticMalwareRule(
        rule_id="MAL-004",
        name="Execução Direta via Pipe de Download (curl/wget | sh/bash)",
        severity="HIGH",
        mitre_attack="T1105",
        pattern=re.compile(r"(?i)(?:curl|wget)\s+[^\n|]+\|\s*(?:sh|bash|python3?|perl)"),
        description="Execução imediata de script remoto sem verificação de integridade.",
    ),
    _StaticMalwareRule(
        rule_id="MAL-005",
        name="Exclusão de Shadow Copies / Backup (Indicador Ransomware)",
        severity="CRITICAL",
        mitre_attack="T1490",
        pattern=re.compile(r"(?i)(?:vssadmin\s+delete\s+shadows|wbadmin\s+delete\s+catalog|bcdedit.*recoveryenabled\s+no)"),
        description="Tentativa de inviabilizar restauração do sistema operacional.",
    ),
    _StaticMalwareRule(
        rule_id="MAL-006",
        name="Webshell PHP com Execução de Entrada do Usuário",
        severity="CRITICAL",
        mitre_attack="T1505.003",
        pattern=re.compile(r"(?i)(?:eval|system|shell_exec|passthru|exec)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)"),
        description="Webshell PHP permitindo execução remota de comandos via parâmetros HTTP.",
    ),
    _StaticMalwareRule(
        rule_id="MAL-007",
        name="Desofuscação Dinâmica em JavaScript (eval / Function(atob))",
        severity="HIGH",
        mitre_attack="T1027",
        pattern=re.compile(r"(?i)(?:eval|new\s+Function)\s*\(\s*(?:atob|unescape|decodeURIComponent)\s*\("),
        description="Execução dinâmica de código decodificado em runtime.",
    ),
    _StaticMalwareRule(
        rule_id="MAL-008",
        name="Persistência em Registro Windows (Run / RunOnce) ou Crontab",
        severity="MEDIUM",
        mitre_attack="T1547.001 / T1053",
        pattern=re.compile(r"(?i)(?:CurrentVersion\\Run(?:Once)?|/etc/cron|crontab\s+-|schtasks\s+/create)"),
        description="Mecanismo de persistência automática após reinicialização ou agendamento.",
    ),
    _StaticMalwareRule(
        rule_id="MAL-009",
        name="Sondagem de Endpoint de Metadados Cloud (169.254.169.254)",
        severity="HIGH",
        mitre_attack="T1552.005",
        pattern=re.compile(r"169\.254\.169\.254"),
        description="Referência a serviço de metadados de nuvem (SSRF / roubo de credenciais IAM).",
    ),
    _StaticMalwareRule(
        rule_id="MAL-010",
        name="Execução Python Dinâmica Ofuscada (exec(base64.b64decode))",
        severity="HIGH",
        mitre_attack="T1059.006 / T1027",
        pattern=re.compile(r"(?i)(?:exec|eval)\s*\(\s*(?:base64\.b64decode|codecs\.decode|zlib\.decompress)"),
        description="Carregamento ofuscado de payload Python em memória.",
    ),
)

_B64_BLOB_RE = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{24,}={0,2})(?![A-Za-z0-9+/=])")
_PS_ENC_RE = re.compile(r"(?i)-(?:e|enc|encodedcommand)\s+([A-Za-z0-9+/]{16,}={0,2})")


def _guess_file_type(raw_bytes: bytes) -> str:
    if raw_bytes.startswith(b"MZ"):
        return "Executável Windows PE/COFF (MZ)"
    if raw_bytes.startswith(b"\x7fELF"):
        return "Binário Linux ELF"
    if raw_bytes.startswith(b"%PDF"):
        return "Documento PDF"
    if raw_bytes.startswith(b"PK\x03\x04"):
        return "Arquivo Compactado ZIP / Office OpenXML"
    if raw_bytes.startswith(b"#!"):
        return "Script Executável Unix (Shebang #!)"
    return "Texto / Script / Payload"


def _byte_shannon_entropy(raw_bytes: bytes) -> float:
    if not raw_bytes:
        return 0.0
    total = len(raw_bytes)
    counts = Counter(raw_bytes)
    return round(-sum((c / total) * math.log2(c / total) for c in counts.values()), 3)


def analyze_malware_static(req: MalwareAnalyzeRequest) -> MalwareAnalyzeResponse:
    """Inspeciona payloads estaticamente sem execução, com desofuscação segura."""
    if req.input_encoding == "BASE64":
        try:
            raw_bytes = base64.b64decode(req.payload.strip(), validate=True)
        except Exception as exc:
            raise ValueError("Payload Base64 inválido para decodificação estática.") from exc
    elif req.input_encoding == "HEX":
        try:
            raw_bytes = bytes.fromhex(re.sub(r"\s+", "", req.payload))
        except ValueError as exc:
            raise ValueError("Payload Hexadecimal inválido para decodificação estática.") from exc
    else:
        raw_bytes = req.payload.encode("utf-8", errors="replace")

    hashes = _compute_hashes(raw_bytes)
    entropy = _byte_shannon_entropy(raw_bytes)
    file_type = _guess_file_type(raw_bytes)
    text_view = raw_bytes.decode("utf-8", errors="replace")

    deobfuscated: list[MalwareDeobfuscationItem] = []
    combined_analysis_texts = [text_view]

    # PowerShell UTF-16LE -EncodedCommand
    for m in _PS_ENC_RE.finditer(text_view):
        try:
            decoded_bytes = base64.b64decode(m.group(1))
        except (ValueError, binascii.Error):
            decoded_bytes = b""
        if decoded_bytes:
            decoded_str = decoded_bytes.decode("utf-16-le", errors="ignore").strip("\x00")
            if decoded_str and sum(ch.isprintable() for ch in decoded_str) / max(len(decoded_str), 1) > 0.7:
                safe_preview, _ = EvidenceManager.sanitize_text_snippet(decoded_str, max_chars=400)
                deobfuscated.append(
                    MalwareDeobfuscationItem(
                        encoding="PowerShell UTF-16LE Base64",
                        decoded_preview=safe_preview or "",
                    )
                )
                combined_analysis_texts.append(decoded_str)

    # Generic Base64 blobs
    for m in _B64_BLOB_RE.finditer(text_view):
        if len(deobfuscated) >= 5:
            break
        blob = m.group(1)
        try:
            decoded_bytes = base64.b64decode(blob, validate=True)
        except (ValueError, binascii.Error):
            decoded_bytes = b""
        if decoded_bytes:
            decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
            if (
                len(decoded_str) >= 12
                and sum(ch.isprintable() or ch in "\r\n\t" for ch in decoded_str) / len(decoded_str) > 0.85
            ):
                safe_preview, _ = EvidenceManager.sanitize_text_snippet(decoded_str, max_chars=400)
                if not any(d.decoded_preview == safe_preview for d in deobfuscated):
                    deobfuscated.append(
                        MalwareDeobfuscationItem(
                            encoding="Base64 UTF-8",
                            decoded_preview=safe_preview or "",
                        )
                    )
                    combined_analysis_texts.append(decoded_str)

    # URL encoding preview if present
    if "%" in text_view and re.search(r"%[0-9A-Fa-f]{2}", text_view):
        unquoted = unquote(text_view)
        if unquoted != text_view:
            safe_preview, _ = EvidenceManager.sanitize_text_snippet(unquoted, max_chars=400)
            deobfuscated.append(
                MalwareDeobfuscationItem(encoding="URL-Decoded", decoded_preview=safe_preview or "")
            )
            combined_analysis_texts.append(unquoted)

    search_corpus = "\n".join(combined_analysis_texts)
    hits: list[MalwareSignatureHit] = []
    for rule in _MALWARE_RULES:
        match = rule.pattern.search(search_corpus)
        if match:
            excerpt, _ = EvidenceManager.sanitize_text_snippet(match.group(0), max_chars=180)
            hits.append(
                MalwareSignatureHit(
                    rule_id=rule.rule_id,
                    name=rule.name,
                    severity=rule.severity,  # type: ignore[arg-type]
                    mitre_attack=rule.mitre_attack,
                    matched_excerpt=excerpt or "",
                    description=rule.description,
                )
            )

    urls = sorted({_defang_value(u.rstrip(".,;"), True) for u in _URL_RE.findall(search_corpus)})[:30]
    ips = sorted({_defang_value(ip, True) for ip in _IPV4_RE.findall(search_corpus)})[:30]

    severity_weights = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 15, "LOW": 5}
    risk_score = sum(severity_weights.get(h.severity, 0) for h in hits)
    high_entropy_warning = entropy >= 7.0
    if high_entropy_warning:
        risk_score += 20
    if deobfuscated and hits:
        risk_score += 10
    risk_score = min(100, risk_score)

    if risk_score >= 55 or any(h.severity == "CRITICAL" for h in hits):
        verdict = "HIGH_RISK_MALICIOUS_INDICATORS"
    elif risk_score >= 20 or hits or high_entropy_warning:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN_NO_INDICATORS"

    recommendations: list[str] = []
    if hits or high_entropy_warning:
        recommendations.extend(
            [
                "Não execute o artefato fora de sandbox isolada e sem rede de produção.",
                "Bloqueie os hashes (SHA-256) e URLs/IPs extraídos no EDR, proxy e firewall.",
                "Verifique processos filhos, tarefas agendadas e chaves de persistência no host afetado.",
            ]
        )
    else:
        recommendations.append(
            "Nenhum indicador estático malicioso detectado; mantenha validação por EDR e assinatura digital."
        )

    return MalwareAnalyzeResponse(
        filename=req.filename or "amostra.bin",
        size_bytes=len(raw_bytes),
        file_type_guess=file_type,
        hashes=hashes,
        shannon_entropy=entropy,
        high_entropy_warning=high_entropy_warning,
        risk_score=risk_score,
        verdict=verdict,
        signature_hits=hits,
        deobfuscated_previews=deobfuscated,
        extracted_urls=urls,
        extracted_ips=ips,
        containment_recommendations=recommendations,
    )


# ---------------------------------------------------------------------------
# 6. WiFi Auditor (Auditoria Passiva de Saída netsh / nmcli / Configs AP)
# ---------------------------------------------------------------------------

_DEFAULT_SSID_PREFIXES = ("tp-link", "netgear", "d-link", "dlink", "linksys", "vivo-", "claro_", "oi_")


def _band_from_channel(channel: int | None) -> str | None:
    if channel is None:
        return None
    if 1 <= channel <= 14:
        return "2.4 GHz"
    if 32 <= channel <= 177:
        return "5 GHz"
    if channel > 177:
        return "6 GHz"
    return None


def _parse_netsh_interface_output(raw: str | None) -> WifiConnectedInterface | None:
    """Extrai dados da interface Wi-Fi conectada de `netsh wlan show interfaces` (PT-BR/EN)."""
    if not raw or not raw.strip():
        return None

    data: dict[str, str] = {}
    for line in raw.splitlines():
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        k = key.strip().lower()
        v = val.strip()
        if not v:
            continue
        if k in {"nome", "name"} and "interface_name" not in data:
            data["interface_name"] = v
        elif k in {"descrição", "descricao", "description"}:
            data["adapter_description"] = v
        elif k in {"estado", "state"}:
            data["state"] = v
        elif k == "ssid":
            data["ssid"] = v
        elif k == "bssid":
            data["bssid"] = v
        elif k in {"tipo de rádio", "tipo de radio", "radio type"}:
            data["radio_type"] = v
        elif k in {"autenticação", "autenticacao", "authentication"}:
            data["authentication"] = v
        elif k in {"codificação", "codificacao", "criptografia", "cipher", "encryption"}:
            data["encryption"] = v
        elif k in {"canal", "channel"} and v.isdigit():
            data["channel"] = v
        elif k in {"sinal", "signal"}:
            sig_m = re.match(r"(\d{1,3})\s*%", v)
            if sig_m:
                data["signal_percent"] = sig_m.group(1)
        elif k.startswith(("taxa de recepção", "taxa de recepcao", "receive rate")):
            data["receive_rate_mbps"] = v
        elif k.startswith(("taxa de transmissão", "taxa de transmissao", "transmit rate")):
            data["transmit_rate_mbps"] = v

    if not data:
        return None

    return WifiConnectedInterface(
        interface_name=data.get("interface_name"),
        adapter_description=data.get("adapter_description"),
        state=data.get("state"),
        ssid=data.get("ssid"),
        bssid=data.get("bssid"),
        radio_type=data.get("radio_type"),
        authentication=data.get("authentication"),
        encryption=data.get("encryption"),
        channel=int(data["channel"]) if "channel" in data else None,
        signal_percent=min(100, int(data["signal_percent"])) if "signal_percent" in data else None,
        receive_rate_mbps=data.get("receive_rate_mbps"),
        transmit_rate_mbps=data.get("transmit_rate_mbps"),
    )


def _parse_netsh_output(raw: str) -> list[WifiNetworkInput]:
    """Extrai redes de `netsh wlan show networks mode=bssid` em PT-BR ou EN."""
    networks: list[WifiNetworkInput] = []
    current_ssid: str | None = None
    current_auth = "Desconhecida"
    current_enc = ""
    current_bssid: str | None = None
    current_radio: str | None = None
    current_signal: int | None = None
    current_channel: int | None = None
    bssid_count_for_ssid = 0

    def _flush_bssid() -> None:
        nonlocal current_bssid, current_radio, current_signal, current_channel, bssid_count_for_ssid
        if current_ssid is not None and current_bssid is not None:
            networks.append(
                WifiNetworkInput(
                    ssid=current_ssid,
                    bssid=current_bssid,
                    authentication=current_auth,
                    encryption=current_enc,
                    radio_type=current_radio,
                    channel=current_channel,
                    signal_percent=current_signal,
                )
            )
            bssid_count_for_ssid += 1
            current_bssid = None
            current_radio = None
            current_signal = None
            current_channel = None

    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        ssid_m = re.match(r"^SSID\s+\d+\s*:\s*(.*)$", stripped, re.IGNORECASE)
        if ssid_m:
            _flush_bssid()
            if current_ssid is not None and bssid_count_for_ssid == 0:
                networks.append(
                    WifiNetworkInput(
                        ssid=current_ssid,
                        authentication=current_auth,
                        encryption=current_enc,
                    )
                )
            current_ssid = ssid_m.group(1).strip() or "<SSID Oculto>"
            current_auth = "Desconhecida"
            current_enc = ""
            bssid_count_for_ssid = 0
            continue

        auth_m = re.match(r"^(?:Autentica[çc][ãa]o|Authentication)\s*:\s*(.+)$", stripped, re.IGNORECASE)
        if auth_m:
            current_auth = auth_m.group(1).strip()
            continue

        enc_m = re.match(r"^(?:Criptografia|Encryption)\s*:\s*(.+)$", stripped, re.IGNORECASE)
        if enc_m:
            current_enc = enc_m.group(1).strip()
            continue

        bssid_m = re.match(r"^BSSID\s+\d+\s*:\s*([0-9a-fA-F:.-]+)$", stripped, re.IGNORECASE)
        if bssid_m:
            _flush_bssid()
            current_bssid = bssid_m.group(1).strip()
            continue

        radio_m = re.match(r"^(?:Tipo de r[áa]dio|Radio type)\s*:\s*(.+)$", stripped, re.IGNORECASE)
        if radio_m:
            current_radio = radio_m.group(1).strip()
            continue

        sig_m = re.match(r"^(?:Sinal|Signal)\s*:\s*(\d{1,3})\s*%$", stripped, re.IGNORECASE)
        if sig_m:
            current_signal = min(100, max(0, int(sig_m.group(1))))
            continue

        chan_m = re.match(r"^(?:Canal|Channel)\s*:\s*(\d{1,3})$", stripped, re.IGNORECASE)
        if chan_m:
            val = int(chan_m.group(1))
            if 1 <= val <= 200:
                current_channel = val

    _flush_bssid()
    if current_ssid is not None and bssid_count_for_ssid == 0:
        networks.append(
            WifiNetworkInput(ssid=current_ssid, authentication=current_auth, encryption=current_enc)
        )
    return networks


def _parse_nmcli_output(raw: str) -> list[WifiNetworkInput]:
    """Extrai redes de `nmcli -t -f SSID,BSSID,CHAN,SIGNAL,SECURITY dev wifi`."""
    networks: list[WifiNetworkInput] = []
    for line in raw.splitlines():
        if ":" not in line or line.strip().lower().startswith("ssid"):
            continue
        # nmcli -t escapes ':' inside BSSID as '\:'
        parts = re.split(r"(?<!\\):", line.strip())
        if len(parts) >= 5:
            ssid = parts[0].strip() or "<SSID Oculto>"
            bssid = parts[1].replace("\\:", ":").strip() or None
            chan = int(parts[2]) if parts[2].strip().isdigit() else None
            sig = int(parts[3]) if parts[3].strip().isdigit() else None
            sec = parts[4].strip() or "Open"
            networks.append(
                WifiNetworkInput(
                    ssid=ssid,
                    bssid=bssid,
                    authentication=sec,
                    encryption="CCMP" if "WPA" in sec.upper() else "",
                    channel=chan if chan and 1 <= chan <= 200 else None,
                    signal_percent=min(100, sig) if sig is not None else None,
                )
            )
    return networks


def analyze_wifi_audit(req: WifiAnalyzeRequest) -> WifiAnalyzeResponse:
    """Audita configurações e varreduras passivas de redes Wi-Fi."""
    all_networks = list(req.networks)
    if req.raw_scan_output and req.raw_scan_output.strip():
        netsh_nets = _parse_netsh_output(req.raw_scan_output)
        if netsh_nets:
            all_networks.extend(netsh_nets)
        else:
            all_networks.extend(_parse_nmcli_output(req.raw_scan_output))

    connected_iface = _parse_netsh_interface_output(req.connected_interface_output)
    findings: list[WifiFinding] = []
    assessments: list[WifiNetworkAssessment] = []
    profiles_by_ssid: dict[str, set[tuple[str, str]]] = defaultdict(set)
    hidden_ssid_reported = False

    for net in all_networks:
        auth_up = net.authentication.upper()
        enc_up = net.encryption.upper()
        profiles_by_ssid[net.ssid].add((auth_up, enc_up))
        issues = 0
        grade = "A"

        if (
            any(tok in auth_up for tok in ("OPEN", "ABERTA", "ABRIR", "NONE", "--"))
            or "NONE" in enc_up
            or "NENHUM" in enc_up
        ):
            issues += 1
            grade = "F"
            findings.append(
                WifiFinding(
                    severity="CRITICAL",
                    ssid=net.ssid,
                    bssid=net.bssid,
                    title="Rede sem fio aberta (sem criptografia)",
                    description=f"O SSID '{net.ssid}' transmite tráfego sem criptografia de enlace.",
                    cwe_id="CWE-319",
                    remediation="Habilite WPA3-Personal/Enterprise ou no mínimo WPA2-AES (CCMP).",
                )
            )
        elif "WEP" in auth_up or "WEP" in enc_up:
            issues += 1
            grade = "F"
            findings.append(
                WifiFinding(
                    severity="CRITICAL",
                    ssid=net.ssid,
                    bssid=net.bssid,
                    title="Protocolo WEP obsoleto e quebrável em minutos",
                    description=f"O SSID '{net.ssid}' utiliza WEP, vulnerável a recuperação passiva de chave.",
                    cwe_id="CWE-327",
                    remediation="Desative WEP imediatamente e migre para WPA2-AES (CCMP) ou WPA3-SAE.",
                )
            )
        elif "TKIP" in enc_up or re.search(r"\bWPA\b(?!2|3)", auth_up):
            issues += 1
            grade = "D"
            findings.append(
                WifiFinding(
                    severity="HIGH",
                    ssid=net.ssid,
                    bssid=net.bssid,
                    title="Criptografia legada WPA1 / TKIP habilitada",
                    description=f"O SSID '{net.ssid}' aceita TKIP/WPA1 com fraquezas criptográficas conhecidas.",
                    cwe_id="CWE-327",
                    remediation="Configure o AP exclusivamente para WPA2-AES (CCMP) ou WPA3-SAE.",
                )
            )
        elif "WPA3" in auth_up or "SAE" in auth_up or "ENTERPRISE" in auth_up or "802.1X" in auth_up:
            grade = "A"
        else:
            grade = "B"

        if net.wps_enabled:
            issues += 1
            if grade in {"A", "B"}:
                grade = "C"
            findings.append(
                WifiFinding(
                    severity="HIGH",
                    ssid=net.ssid,
                    bssid=net.bssid,
                    title="WPS (Wi-Fi Protected Setup) habilitado",
                    description=f"O AP '{net.ssid}' anuncia WPS ativo, exposto a ataques Pixie Dust / PIN.",
                    cwe_id="CWE-307",
                    remediation="Desative o WPS completamente na interface administrativa do Access Point.",
                )
            )

        if net.pmf_enabled is False and grade not in {"F", "D"}:
            issues += 1
            if grade == "A":
                grade = "B"
            findings.append(
                WifiFinding(
                    severity="MEDIUM",
                    ssid=net.ssid,
                    bssid=net.bssid,
                    title="Protected Management Frames (802.11w / PMF) desabilitado",
                    description=f"Sem PMF, clientes do SSID '{net.ssid}' ficam expostos a frames de desautenticação forjados.",
                    cwe_id="CWE-345",
                    remediation="Ative 802.11w (PMF) como obrigatório (WPA3) ou opcional (WPA2).",
                )
            )

        if net.channel is not None and 1 <= net.channel <= 14 and net.channel not in {1, 6, 11}:
            issues += 1
            findings.append(
                WifiFinding(
                    severity="LOW",
                    ssid=net.ssid,
                    bssid=net.bssid,
                    title="Canal 2.4 GHz sobreposto (fora de 1, 6 ou 11)",
                    description=f"O canal {net.channel} sofre interferência de canais adjacentes em 2.4 GHz.",
                    cwe_id="CWE-664",
                    remediation="Utilize exclusivamente os canais não sobrepostos 1, 6 ou 11 em 2.4 GHz.",
                )
            )

        if net.ssid.lower().startswith(_DEFAULT_SSID_PREFIXES):
            issues += 1
            findings.append(
                WifiFinding(
                    severity="INFO",
                    ssid=net.ssid,
                    bssid=net.bssid,
                    title="SSID padrão de fabricante detectado",
                    description=f"O nome '{net.ssid}' sugere configuração de fábrica, facilitando enumeração de roteador.",
                    cwe_id="CWE-1188",
                    remediation="Altere o SSID para identificador corporativo que não exponha modelo/operadora.",
                )
            )

        if net.ssid == "<SSID Oculto>" and not hidden_ssid_reported:
            hidden_ssid_reported = True
            issues += 1
            findings.append(
                WifiFinding(
                    severity="INFO",
                    ssid=net.ssid,
                    bssid=net.bssid,
                    title="SSID oculto detectado na varredura",
                    description=(
                        "Redes com broadcast de SSID oculto ainda expõem o nome em quadros "
                        "Probe Request/Response e não substituem criptografia forte."
                    ),
                    cwe_id="CWE-656",
                    remediation="Mantenha WPA2-AES/WPA3 com senha forte; não confie em ocultação de SSID.",
                )
            )

        assessments.append(
            WifiNetworkAssessment(
                ssid=net.ssid,
                bssid=net.bssid,
                security_grade=grade,  # type: ignore[arg-type]
                authentication=net.authentication,
                encryption=net.encryption or "N/D",
                radio_type=net.radio_type,
                band=_band_from_channel(net.channel),
                channel=net.channel,
                signal_percent=net.signal_percent,
                issues_count=issues,
            )
        )

    evil_twin_suspected = False
    for ssid, profiles in profiles_by_ssid.items():
        if len(profiles) > 1 and ssid != "<SSID Oculto>":
            evil_twin_suspected = True
            findings.append(
                WifiFinding(
                    severity="HIGH",
                    ssid=ssid,
                    bssid=None,
                    title="Possível Evil Twin / Divergência de segurança no mesmo SSID",
                    description=(
                        f"O SSID '{ssid}' aparece com perfis conflitantes de autenticação/criptografia "
                        f"({len(profiles)} variações distintas), podendo indicar ponto de acesso falso."
                    ),
                    cwe_id="CWE-290",
                    remediation="Inspecione os BSSIDs autorizados no inventário WLC e ative detecção de Rogue AP.",
                )
            )

    grade_scores = {"A": 100, "B": 82, "C": 62, "D": 35, "F": 10}
    if assessments:
        overall = round(sum(grade_scores[a.security_grade] for a in assessments) / len(assessments))
        if evil_twin_suspected:
            overall = max(0, overall - 15)
    else:
        overall = 0

    checklist = [
        "Padronizar redes corporativas com WPA3-Enterprise (802.1X/RADIUS) ou WPA3-SAE.",
        "Desabilitar WPS, WEP, WPA1 e TKIP em todos os pontos de acesso.",
        "Habilitar 802.11w (PMF) para mitigar ataques de desautenticação.",
        "Segregar rede de visitantes em VLAN isolada com Client Isolation ativo.",
    ]

    return WifiAnalyzeResponse(
        total_networks=len(assessments),
        overall_score=overall,
        evil_twin_suspected=evil_twin_suspected,
        connected_interface=connected_iface,
        assessments=assessments,
        findings=findings,
        hardening_checklist=checklist,
    )


# ---------------------------------------------------------------------------
# 7. DDoS Analyzer (Análise Defensiva de Logs, Postura e Snippets Mitigadores)
# ---------------------------------------------------------------------------

_CLF_LOG_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<target>\S+)\s+[^"]*"\s+(?P<status>\d{3})\s+\S+(?:\s+"[^"]*"\s+"(?P<ua>[^"]*)")?'
)


def _parse_clf_timestamp_second(ts_raw: str) -> str:
    # Ex: 20/Nov/2026:12:00:01 +0000 -> 20/Nov/2026:12:00:01
    return ts_raw.strip().split(" ")[0]


def analyze_ddos_defense(
    req: DdosAnalyzeRequest,
    asset_module_f_context: list[str] | None = None,
) -> DdosAnalyzeResponse:
    """Analisa logs de acesso e postura de borda para diagnosticar e mitigar DDoS."""
    ip_counts: Counter[str] = Counter()
    ip_errors: Counter[str] = Counter()
    sec_counts: Counter[str] = Counter()
    path_counts: Counter[str] = Counter()
    path_queries: dict[str, set[str]] = defaultdict(set)
    ua_counts: Counter[str] = Counter()
    total = 0
    total_sat_errors = 0

    if req.access_logs:
        for line in req.access_logs.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            m = _CLF_LOG_RE.match(stripped)
            if not m:
                continue
            total += 1
            ip = m.group("ip")
            sec_key = _parse_clf_timestamp_second(m.group("ts"))
            target = m.group("target")
            status_code = int(m.group("status"))
            ua = (m.group("ua") or "").strip()

            parsed_target = urlparse(target)
            base_path = parsed_target.path or "/"
            ip_counts[ip] += 1
            sec_counts[sec_key] += 1
            path_counts[base_path] += 1
            if parsed_target.query:
                path_queries[base_path].add(parsed_target.query)
            ua_counts[ua] += 1

            if status_code in {408, 429, 499, 502, 503, 504}:
                total_sat_errors += 1
                ip_errors[ip] += 1

    unique_ips = len(ip_counts)
    peak_rps = float(max(sec_counts.values())) if sec_counts else 0.0
    avg_rps = (total / len(sec_counts)) if sec_counts else 0.0
    err_rate = round((total_sat_errors / total) * 100.0, 2) if total else 0.0

    top_ips: list[DdosIpMetric] = []
    for ip, count in ip_counts.most_common(10):
        share = round((count / total) * 100.0, 2) if total else 0.0
        ip_err = round((ip_errors[ip] / count) * 100.0, 2) if count else 0.0
        top_ips.append(
            DdosIpMetric(
                ip=ip,
                request_count=count,
                share_percent=share,
                error_rate_percent=ip_err,
            )
        )

    top_paths = [
        {
            "path": p,
            "count": c,
            "unique_query_variants": len(path_queries[p]),
        }
        for p, c in path_counts.most_common(10)
    ]

    anomalies: list[DdosAnomaly] = []
    if top_ips and top_ips[0].share_percent >= 25.0 and top_ips[0].request_count >= 10:
        lead = top_ips[0]
        sev = "CRITICAL" if lead.share_percent >= 50.0 else "HIGH"
        anomalies.append(
            DdosAnomaly(
                severity=sev,
                anomaly_type="SINGLE_IP_CONCENTRATION",
                title=f"Alta concentração de tráfego originada no IP {lead.ip}",
                description=(
                    f"Um único IP concentrou {lead.share_percent}% do volume analisado "
                    f"({lead.request_count} requisições)."
                ),
                evidence=f"ip={lead.ip} requests={lead.request_count} share={lead.share_percent}%",
            )
        )

    if peak_rps >= 20.0 or (avg_rps > 0 and peak_rps >= max(10.0, avg_rps * 4.0)):
        anomalies.append(
            DdosAnomaly(
                severity="HIGH",
                anomaly_type="TRAFFIC_BURST_PEAK",
                title="Pico abrupto de requisições por segundo (RPS)",
                description=f"Pico observado de {peak_rps:.1f} req/s contra média de {avg_rps:.1f} req/s.",
                evidence=f"peak_rps={peak_rps:.1f} avg_rps={avg_rps:.1f} total={total}",
            )
        )

    if err_rate >= 20.0 and total >= 5:
        anomalies.append(
            DdosAnomaly(
                severity="CRITICAL",
                anomaly_type="ORIGIN_SATURATION",
                title="Saturação do serviço (HTTP 429/5xx/408 elevado)",
                description=f"{err_rate}% das requisições resultaram em saturação ou timeout.",
                evidence=f"saturation_errors={total_sat_errors}/{total} ({err_rate}%)",
            )
        )

    for p, queries in path_queries.items():
        if len(queries) >= 8:
            anomalies.append(
                DdosAnomaly(
                    severity="HIGH",
                    anomaly_type="L7_CACHE_BUSTING",
                    title=f"Possível ataque L7 Cache-Busting em {p}",
                    description=(
                        f"Detectadas {len(queries)} query strings distintas sobre o mesmo endpoint "
                        "para contornar cache de borda."
                    ),
                    evidence=f"path={p} unique_queries={len(queries)}",
                )
            )

    if ua_counts and total >= 15:
        top_ua, top_ua_count = ua_counts.most_common(1)[0]
        ua_share = (top_ua_count / total) * 100.0
        if (top_ua == "" or top_ua == "-" or "curl" in top_ua.lower() or "python" in top_ua.lower()) and ua_share >= 50.0:
            safe_ua, _ = EvidenceManager.sanitize_text_snippet(top_ua or "<vazio>", max_chars=80)
            anomalies.append(
                DdosAnomaly(
                    severity="MEDIUM",
                    anomaly_type="BOT_USER_AGENT_ANOMALY",
                    title="Predomínio de User-Agent automatizado ou ausente",
                    description=f"{ua_share:.1f}% das requisições compartilham User-Agent suspeito.",
                    evidence=f"user_agent={safe_ua} count={top_ua_count}/{total}",
                )
            )

    posture = req.posture
    resilience_score = (
        (30 if posture.has_cdn_waf else 0)
        + (25 if posture.has_rate_limiting else 0)
        + (15 if posture.has_syn_cookies else 0)
        + (15 if posture.has_upstream_timeouts else 0)
        + (15 if posture.has_autoscaling_or_anycast else 0)
    )
    if err_rate >= 20.0:
        resilience_score = max(0, resilience_score - 20)
    if any(a.severity == "CRITICAL" for a in anomalies) and not posture.has_rate_limiting:
        resilience_score = max(0, resilience_score - 15)

    if resilience_score < 35 or any(a.severity == "CRITICAL" for a in anomalies):
        risk_level = "CRITICAL"
    elif resilience_score < 60 or len(anomalies) >= 2:
        risk_level = "HIGH"
    elif resilience_score < 85 or anomalies:
        risk_level = "MODERATE"
    else:
        risk_level = "LOW"

    snippets = [
        DdosMitigationSnippet(
            platform="Nginx",
            title="Rate Limiting por IP, limite de conexões e timeouts anti-Slowloris",
            code=(
                "limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;\n"
                "limit_conn_zone $binary_remote_addr zone=conn_limit:10m;\n"
                "server {\n"
                "    client_body_timeout 10s;\n"
                "    client_header_timeout 10s;\n"
                "    limit_req zone=api_limit burst=20 nodelay;\n"
                "    limit_conn conn_limit 15;\n"
                "    limit_req_status 429;\n"
                "}"
            ),
        ),
        DdosMitigationSnippet(
            platform="Cloudflare WAF",
            title="Regra de desafio/bloqueio para rajadas L7 e Cache-Busting",
            code=(
                "(http.request.uri.path in {\"/login\" \"/api/v1/search\"} and "
                "cf.threat_score gt 15) or (http.user_agent eq \"\")"
            ),
        ),
        DdosMitigationSnippet(
            platform="Linux sysctl / nftables",
            title="Proteção contra SYN Flood no kernel",
            code=(
                "sysctl -w net.ipv4.tcp_syncookies=1\n"
                "sysctl -w net.ipv4.tcp_max_syn_backlog=4096\n"
                "sysctl -w net.ipv4.tcp_synack_retries=2"
            ),
        ),
    ]

    return DdosAnalyzeResponse(
        total_requests_parsed=total,
        unique_ips=unique_ips,
        peak_rps=round(peak_rps, 2),
        error_5xx_429_rate_percent=err_rate,
        resilience_score=resilience_score,
        risk_level=risk_level,
        top_ips=top_ips,
        top_paths=top_paths,
        anomalies=anomalies,
        asset_module_f_context=asset_module_f_context or [],
        mitigation_snippets=snippets,
    )
