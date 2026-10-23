"""Gerenciador e sanitizador de evidências técnicas (EvidenceManager - Seção 5 e Seção 12)."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from security_engine.core.contracts import SanitizedEvidence

SENSITIVE_HEADER_NAMES = {
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
    "x-access-token",
    "api-key",
    "client-secret",
    "x-csrf-token",
}

SENSITIVE_QUERY_KEYS = {
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "client_secret",
    "session_id",
}

JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
BEARER_PATTERN = re.compile(r"(?i)\b(Bearer|Basic|Token)\s+([A-Za-z0-9._~+/=-]{6,})")
JSON_SECRET_PATTERN = re.compile(
    r'(?i)("(?:password|passwd|secret|token|access_token|refresh_token|api_key|client_secret)"\s*:\s*)"([^"]+)"'
)

MAX_EVIDENCE_EXCERPT_CHARS = 2048


class EvidenceManager:
    """Registra e sanitiza evidências técnicas garantindo que segredos e valores de cookies
    sensíveis nunca sejam armazenados em texto puro (Seção 6 - Módulo E e Seção 12).
    """

    @staticmethod
    def mask_secret_value(raw_value: str, visible_prefix: int = 4) -> str:
        """Mascara um valor sensível preservando apenas um prefixo curto ou metadado de comprimento."""
        cleaned = raw_value.strip()
        if not cleaned:
            return "[REDACTED]"
        if len(cleaned) <= visible_prefix * 2:
            return f"[REDACTED:len={len(cleaned)}]"
        return f"{cleaned[:visible_prefix]}...[REDACTED:len={len(cleaned)}]"

    @classmethod
    def sanitize_set_cookie_header(cls, set_cookie_raw: str) -> str:
        """Sanitiza um cabeçalho Set-Cookie ocultando o valor do cookie mas preservando todas as flags
        (HttpOnly, Secure, SameSite, Path, Domain, Max-Age, Expires) para auditoria técnica.
        """
        parts = [p.strip() for p in set_cookie_raw.split(";") if p.strip()]
        if not parts:
            return "[REDACTED_COOKIE]"

        first_part = parts[0]
        if "=" in first_part:
            cookie_name, cookie_val = first_part.split("=", 1)
            sanitized_first = f"{cookie_name.strip()}={cls.mask_secret_value(cookie_val, visible_prefix=2)}"
        else:
            sanitized_first = cls.mask_secret_value(first_part, visible_prefix=2)

        attributes = parts[1:]
        if attributes:
            return "; ".join([sanitized_first, *attributes])
        return sanitized_first

    @classmethod
    def sanitize_cookie_request_header(cls, cookie_raw: str) -> str:
        """Sanitiza o cabeçalho Cookie de requisição."""
        pairs = [p.strip() for p in cookie_raw.split(";") if p.strip()]
        sanitized_pairs: list[str] = []
        for pair in pairs:
            if "=" in pair:
                name, val = pair.split("=", 1)
                sanitized_pairs.append(f"{name.strip()}={cls.mask_secret_value(val, visible_prefix=2)}")
            else:
                sanitized_pairs.append("[REDACTED]")
        return "; ".join(sanitized_pairs)

    @classmethod
    def sanitize_url(cls, url: str) -> tuple[str, int]:
        """Sanitiza credenciais ou parâmetros sensíveis na query string de uma URL."""
        if not url:
            return "", 0

        redactions = 0
        parsed = urlparse(url)
        netloc = parsed.netloc
        if "@" in netloc:
            _, host_part = netloc.rsplit("@", 1)
            netloc = f"[REDACTED_CREDENTIALS]@{host_part}"
            redactions += 1

        query_items = parse_qsl(parsed.query, keep_blank_values=True)
        sanitized_query: list[tuple[str, str]] = []
        for k, v in query_items:
            if k.lower() in SENSITIVE_QUERY_KEYS or JWT_PATTERN.search(v):
                sanitized_query.append((k, "[REDACTED]"))
                redactions += 1
            else:
                sanitized_query.append((k, v))

        new_url = urlunparse(
            (
                parsed.scheme,
                netloc,
                parsed.path,
                parsed.params,
                urlencode(sanitized_query),
                parsed.fragment,
            )
        )
        return new_url, redactions

    @classmethod
    def sanitize_headers(cls, headers: dict[str, str] | None) -> tuple[dict[str, str], int]:
        """Sanitiza cabeçalhos HTTP de requisição ou resposta."""
        if not headers:
            return {}, 0

        sanitized: dict[str, str] = {}
        redacted_count = 0

        for key, value in headers.items():
            lower_key = key.lower().strip()
            if lower_key in SENSITIVE_HEADER_NAMES:
                match = BEARER_PATTERN.match(value.strip())
                if match:
                    scheme = match.group(1)
                    token = match.group(2)
                    sanitized[key] = f"{scheme} {cls.mask_secret_value(token, visible_prefix=4)}"
                else:
                    sanitized[key] = cls.mask_secret_value(value, visible_prefix=3)
                redacted_count += 1
            elif lower_key == "set-cookie":
                sanitized[key] = cls.sanitize_set_cookie_header(value)
                redacted_count += 1
            elif lower_key == "cookie":
                sanitized[key] = cls.sanitize_cookie_request_header(value)
                redacted_count += 1
            else:
                cleaned_val, c = cls.sanitize_text_snippet(value, max_chars=512)
                sanitized[key] = cleaned_val
                redacted_count += c

        return sanitized, redacted_count

    @classmethod
    def sanitize_text_snippet(
        cls,
        text: str | None,
        max_chars: int = MAX_EVIDENCE_EXCERPT_CHARS,
    ) -> tuple[str | None, int]:
        """Remove tokens JWT, cabeçalhos Bearer e segredos JSON de trechos de texto e aplica limite de tamanho."""
        if text is None:
            return None, 0

        redactions = 0

        def _replace_jwt(match: re.Match[str]) -> str:
            nonlocal redactions
            redactions += 1
            token = match.group(0)
            return f"{token[:10]}...[REDACTED_JWT]"

        def _replace_bearer(match: re.Match[str]) -> str:
            nonlocal redactions
            redactions += 1
            return f"{match.group(1)} [REDACTED_TOKEN]"

        def _replace_json_secret(match: re.Match[str]) -> str:
            nonlocal redactions
            redactions += 1
            return f'{match.group(1)}"[REDACTED_SECRET]"'

        sanitized = JWT_PATTERN.sub(_replace_jwt, text)
        sanitized = BEARER_PATTERN.sub(_replace_bearer, sanitized)
        sanitized = JSON_SECRET_PATTERN.sub(_replace_json_secret, sanitized)

        if len(sanitized) > max_chars:
            sanitized = f"{sanitized[:max_chars]}... [TRUNCATED at {max_chars} chars]"

        return sanitized, redactions

    @classmethod
    def build_sanitized_evidence(
        cls,
        request_method: str | None = None,
        request_url: str | None = None,
        request_headers: dict[str, str] | None = None,
        response_status_code: int | None = None,
        response_headers: dict[str, str] | None = None,
        response_body_excerpt: str | None = None,
        observed_value: str | None = None,
        expected_baseline: str | None = None,
        technical_notes: list[str] | None = None,
    ) -> SanitizedEvidence:
        """Constrói um objeto SanitizedEvidence garantindo sanitização completa de todos os campos."""
        total_redactions = 0

        clean_url: str | None = None
        if request_url:
            clean_url, c_url = cls.sanitize_url(request_url)
            total_redactions += c_url

        clean_req_headers, c_req = cls.sanitize_headers(request_headers)
        total_redactions += c_req

        clean_resp_headers, c_resp = cls.sanitize_headers(response_headers)
        total_redactions += c_resp

        clean_body, c_body = cls.sanitize_text_snippet(response_body_excerpt)
        total_redactions += c_body

        clean_observed, c_obs = cls.sanitize_text_snippet(observed_value, max_chars=512)
        total_redactions += c_obs

        return SanitizedEvidence(
            request_method=request_method,
            request_url=clean_url,
            request_headers=clean_req_headers,
            response_status_code=response_status_code,
            response_headers=clean_resp_headers,
            response_body_Excerpt=clean_body,
            observed_value=clean_observed,
            expected_baseline=expected_baseline,
            technical_notes=technical_notes or [],
            redacted_fields_count=total_redactions,
        )
