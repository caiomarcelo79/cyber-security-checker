"""Testes unitários de sanitização de evidências e proteção de segredos (TM-002)."""

from security_engine.core.evidence import EvidenceManager


def test_masks_authorization_cookie_and_api_key_headers() -> None:
    raw_headers = {
        "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "X-API-Key": "sk-live-998877665544332211",
        "Set-Cookie": "session_id=super_secret_session_value_999; Path=/; HttpOnly; Secure; SameSite=Lax",
        "Content-Type": "application/json",
    }
    evidence = EvidenceManager.build_sanitized_evidence(
        request_method="GET",
        request_url="https://app.exemplo.local/api/profile?access_token=my_secret_token_123&page=1",
        request_headers=raw_headers,
        response_status_code=200,
        response_headers={"Set-Cookie": raw_headers["Set-Cookie"]},
        response_body_excerpt='{"user": "alice", "password": "PlainTextPassword!23", "status": "ok"}',
    )

    assert "super_secret_session_value_999" not in str(evidence.model_dump())
    assert "sk-live-998877665544332211" not in str(evidence.model_dump())
    assert "PlainTextPassword!23" not in (evidence.response_body_Excerpt or "")
    assert "my_secret_token_123" not in (evidence.request_url or "")

    # Confirma que flags do Set-Cookie foram preservadas para análise do Módulo E
    sanitized_cookie = evidence.response_headers["Set-Cookie"]
    assert "HttpOnly" in sanitized_cookie
    assert "Secure" in sanitized_cookie
    assert "SameSite=Lax" in sanitized_cookie
    assert "[REDACTED" in sanitized_cookie
    assert evidence.redacted_fields_count >= 4
