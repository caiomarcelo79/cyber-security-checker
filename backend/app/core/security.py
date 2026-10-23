"""Utilitários criptográficos de autenticação, senhas, JWT, RBAC e tokens de verificação (Fase 2)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any
from uuid import uuid4

from app.core.config import get_settings


class UserRole(str, Enum):
    """Papéis RBAC suportados por organização (Seção 13)."""

    ADMIN = "ADMIN"
    SECURITY_ANALYST = "SECURITY_ANALYST"
    DEVELOPER = "DEVELOPER"
    VIEWER = "VIEWER"


ROLE_PRIVILEGE_RANK: dict[UserRole, int] = {
    UserRole.VIEWER: 10,
    UserRole.DEVELOPER: 20,
    UserRole.SECURITY_ANALYST: 30,
    UserRole.ADMIN: 40,
}


AUTH_COOKIE_NAME = "csc_access_token"


def has_minimum_role(user_role: str | UserRole, minimum_role: UserRole) -> bool:
    """Verifica se o papel do usuário na organização satisfaz o privilégio mínimo exigido."""
    try:
        resolved_role = UserRole(user_role)
    except ValueError:
        return False
    return ROLE_PRIVILEGE_RANK.get(resolved_role, 0) >= ROLE_PRIVILEGE_RANK[minimum_role]


def hash_password(plain_password: str) -> str:
    """Gera hash seguro de senha utilizando scrypt com salt aleatório de 16 bytes."""
    if not plain_password or len(plain_password) < 8:
        raise ValueError("A senha deve possuir no mínimo 8 caracteres.")
    salt = secrets.token_bytes(16)
    n_param, r_param, p_param = 16384, 8, 1
    derived = hashlib.scrypt(
        plain_password.encode("utf-8"),
        salt=salt,
        n=n_param,
        r=r_param,
        p=p_param,
        dklen=64,
    )
    salt_b64 = base64.urlsafe_b64encode(salt).decode("ascii")
    hash_b64 = base64.urlsafe_b64encode(derived).decode("ascii")
    return f"scrypt${n_param}${r_param}${p_param}${salt_b64}${hash_b64}"


def verify_password(plain_password: str, stored_hash: str) -> bool:
    """Valida senha em tempo constante contra o hash armazenado."""
    try:
        parts = stored_hash.split("$")
        if len(parts) != 6 or parts[0] != "scrypt":
            return False
        n_param = int(parts[1])
        r_param = int(parts[2])
        p_param = int(parts[3])
        salt = base64.urlsafe_b64decode(parts[4].encode("ascii"))
        expected_key = base64.urlsafe_b64decode(parts[5].encode("ascii"))
        candidate_key = hashlib.scrypt(
            plain_password.encode("utf-8"),
            salt=salt,
            n=n_param,
            r=r_param,
            p=p_param,
            dklen=len(expected_key),
        )
        return hmac.compare_digest(candidate_key, expected_key)
    except (ValueError, TypeError):
        return False


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + padding).encode("ascii"))


def create_access_token(
    user_id: str,
    email: str,
    organization_id: str,
    role: str,
    expires_delta: timedelta | None = None,
) -> str:
    """Cria um JSON Web Token (JWT RFC 7519) assinado com HMAC-SHA256."""
    settings = get_settings()
    now = datetime.now(UTC)
    expire = now + (expires_delta or timedelta(minutes=settings.access_token_expire_minutes))

    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": user_id,
        "email": email,
        "org_id": organization_id,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "jti": str(uuid4()),
    }

    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = hmac.new(
        settings.secret_key.encode("utf-8"),
        signing_input,
        hashlib.sha256,
    ).digest()
    signature_b64 = _b64url_encode(signature)
    return f"{header_b64}.{payload_b64}.{signature_b64}"


def decode_access_token(token: str) -> dict[str, Any]:
    """Valida a assinatura HMAC-SHA256 e a expiração de um JWT."""
    settings = get_settings()
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Formato de token JWT inválido.")

    header_b64, payload_b64, signature_b64 = parts
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    expected_sig = hmac.new(
        settings.secret_key.encode("utf-8"),
        signing_input,
        hashlib.sha256,
    ).digest()

    try:
        provided_sig = _b64url_decode(signature_b64)
    except Exception as exc:
        raise ValueError("Assinatura de token malformada.") from exc

    if not hmac.compare_digest(provided_sig, expected_sig):
        raise ValueError("Assinatura do token JWT inválida.")

    try:
        payload: dict[str, Any] = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    except Exception as exc:
        raise ValueError("Payload do token JWT inválido.") from exc

    exp = payload.get("exp")
    if not isinstance(exp, int) or datetime.now(UTC).timestamp() >= exp:
        raise ValueError("Token JWT expirado.")

    return payload


def generate_target_verification_token(organization_id: str, asset_id: str, hostname: str) -> str:
    """Gera token criptográfico determinístico + nonce para comprovação de domínio/sistema."""
    settings = get_settings()
    nonce = secrets.token_hex(12)
    message = f"{organization_id}:{asset_id}:{hostname.lower()}:{nonce}".encode()
    digest = hmac.new(settings.secret_key.encode("utf-8"), message, hashlib.sha256).hexdigest()[:36]
    return f"cyber-sec-checker-verify={digest}"
