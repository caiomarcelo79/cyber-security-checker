"""Testes reais de integração dos Scanners Passivos (HTTP/HTTPS, TLS, Headers, Cookies, Info Disclosure) e ScopedSafeHttpClient (Fase 3)."""

from __future__ import annotations

import ipaddress
import ssl
import tempfile
import threading
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from security_engine.core.contracts import (
    AssetType,
    CheckStatus,
    EnvironmentType,
)
from security_engine.core.http_client import (
    CircuitBreakerTrippedError,
    RedirectLoopError,
    ScanCancelledError,
    ScopedSafeHttpClient,
)
from security_engine.core.runner import SecurityEngineRunner
from security_engine.modules.builtin_modules import (
    ModuleAReconHeadersTLS,
    ModuleECookiesAndSession,
)
from security_engine.policies.execution_policy import ScanExecutionPolicy
from security_engine.policies.scope_validator import (
    ScopePolicyValidator,
    ScopeViolationError,
)


def _generate_x509_cert_files(
    directory: Path,
    *,
    common_name: str = "127.0.0.1",
    san_dns: list[str] | None = None,
    san_ips: list[str] | None = None,
    valid_days_offset_start: int = -1,
    valid_days_offset_end: int = 365,
) -> tuple[Path, Path]:
    """Gera par chave privada + certificado X.509 em PEM para o servidor TLS de laboratório."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "BR"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CyberSecurityChecker Lab"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )
    now = datetime.now(UTC)
    san_entries: list[x509.GeneralName] = []
    for d in san_dns or []:
        san_entries.append(x509.DNSName(d))
    for ip_s in san_ips or []:
        san_entries.append(x509.IPAddress(ipaddress.ip_address(ip_s)))

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + timedelta(days=valid_days_offset_start))
        .not_valid_after(now + timedelta(days=valid_days_offset_end))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    )
    if san_entries:
        builder = builder.add_extension(x509.SubjectAlternativeName(san_entries), critical=False)

    cert = builder.sign(key, hashes.SHA256())

    cert_path = directory / "cert.pem"
    key_path = directory / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


@contextmanager
def run_local_lab_server(
    handler_cls: type[BaseHTTPRequestHandler],
    *,
    ssl_context: ssl.SSLContext | None = None,
) -> Generator[tuple[str, int], None, None]:
    """Inicia um servidor HTTP/HTTPS efêmero em 127.0.0.1 para testes de laboratório."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    if ssl_context is not None:
        server.socket = ssl_context.wrap_socket(server.socket, server_side=True)
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield "127.0.0.1", port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


def _make_lab_validator(extra_hosts: list[str] | None = None) -> ScopePolicyValidator:
    hosts = ["127.0.0.1", "localhost", *(extra_hosts or [])]
    return ScopePolicyValidator(
        authorized_hosts=hosts,
        allow_subdomains=False,
        excluded_paths=["/logout", "/admin-secret"],
        block_private_networks=True,
        allow_local_lab_targets=True,
        lab_allowed_hosts=hosts,
    )


def test_http_to_https_redirect_and_tls_valid_cert_inspection() -> None:
    """Valida redirecionamento HTTP -> HTTPS, inspeção de certificado TLS válido e Security Headers."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        cert_path, key_path = _generate_x509_cert_files(
            tmp_path,
            common_name="127.0.0.1",
            san_ips=["127.0.0.1"],
            san_dns=["localhost"],
        )
        server_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ssl.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))

        class SecureHttpsHandler(BaseHTTPRequestHandler):
            def version_string(self) -> str:
                return "SecureGateway"

            def log_message(self, format: str, *args: Any) -> None:
                return

            def do_GET(self) -> None:
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
                self.send_header(
                    "Content-Security-Policy",
                    "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'",
                )
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
                self.send_header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
                self.send_header(
                    "Set-Cookie",
                    "__Host-csc_sid=top_secret_session_value_998877; Secure; HttpOnly; SameSite=Strict; Path=/",
                )
                self.end_headers()
                self.wfile.write(b"<html><body> Portal Seguro </body></html>")

        with run_local_lab_server(SecureHttpsHandler, ssl_context=server_ssl) as (_, https_port):

            class RedirectHttpHandler(BaseHTTPRequestHandler):
                def log_message(self, format: str, *args: Any) -> None:
                    return

                def do_GET(self) -> None:
                    self.send_response(301)
                    self.send_header("Location", f"https://127.0.0.1:{https_port}/app")
                    self.end_headers()

            with run_local_lab_server(RedirectHttpHandler) as (_, http_port):
                validator = _make_lab_validator()
                runner = SecurityEngineRunner(
                    scope_validator=validator,
                    policy=ScanExecutionPolicy(max_requests_per_second=20),
                    ca_bundle_path=str(cert_path),
                )
                summary = runner.execute_modules(
                    target_url=f"http://127.0.0.1:{http_port}/",
                    module_ids=["mod_a_recon_headers_tls", "mod_e_cookies_session"],
                    asset_type=AssetType.WEB_APP,
                    environment=EnvironmentType.LAB,
                )

                assert summary.final_status == "COMPLETED"
                assert summary.snapshot is not None
                assert summary.snapshot.http_to_https_redirected is True
                assert len(summary.snapshot.redirect_chain) == 1
                assert summary.snapshot.redirect_chain[0].scheme_upgraded is True
                assert summary.snapshot.tls_info is not None
                assert summary.snapshot.tls_info.trusted_chain is True
                assert summary.snapshot.tls_info.hostname_matched is True
                assert summary.snapshot.tls_info.is_expired is False
                assert summary.all_findings == []
                assert all(c.status == CheckStatus.PASSED for c in summary.all_checks)


def test_expired_and_untrusted_tls_certificates_and_weak_headers() -> None:
    """Valida detecção de certificado TLS expirado/autoassinado, CSP fraco, cookies incompatíveis e stack trace."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        # Certificado expirado e com hostname divergente
        cert_path, key_path = _generate_x509_cert_files(
            tmp_path,
            common_name="outro-dominio.lab",
            san_dns=["outro-dominio.lab"],
            valid_days_offset_start=-60,
            valid_days_offset_end=-5,
        )
        server_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ssl.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))

        class VulnerableLabHandler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                return

            def do_GET(self) -> None:
                self.send_response(500)
                self.send_header("Content-Type", "text/html")
                self.send_header("Server", "Apache/2.4.49 (Unix)")
                self.send_header("X-Powered-By", "PHP/8.1.2")
                self.send_header("Strict-Transport-Security", "max-age=60")
                self.send_header(
                    "Content-Security-Policy",
                    "default-src * 'unsafe-inline' 'unsafe-eval'",
                )
                self.send_header(
                    "Set-Cookie",
                    "auth_token=super_sensitive_jwt_secret_12345; SameSite=None; Domain=.127.0.0.1; Max-Age=99999999",
                )
                self.end_headers()
                self.wfile.write(
                    b"<html><body>Traceback (most recent call last):\n  File 'app.py', line 42</body></html>"
                )

        with run_local_lab_server(VulnerableLabHandler, ssl_context=server_ssl) as (_, https_port):
            validator = _make_lab_validator()
            runner = SecurityEngineRunner(
                scope_validator=validator,
                policy=ScanExecutionPolicy(max_requests_per_second=20),
            )
            summary = runner.execute_modules(
                target_url=f"https://127.0.0.1:{https_port}/debug",
                module_ids=["mod_a_recon_headers_tls", "mod_e_cookies_session"],
                asset_type=AssetType.WEB_APP,
                environment=EnvironmentType.LAB,
            )

            assert summary.final_status == "COMPLETED"
            check_map = {c.check_id: c.status for c in summary.all_checks}
            assert check_map["CHK-A02"] == CheckStatus.POTENTIAL_VULNERABILITY  # HSTS max-age curto
            assert check_map["CHK-A03"] == CheckStatus.POTENTIAL_VULNERABILITY  # CSP unsafe-inline/eval
            assert check_map["CHK-A04"] == CheckStatus.VULNERABILITY  # Missing nosniff
            assert check_map["CHK-A05"] == CheckStatus.VULNERABILITY  # Missing Clickjacking
            assert check_map["CHK-A07"] == CheckStatus.VULNERABILITY  # Server version
            assert check_map["CHK-A08"] == CheckStatus.VULNERABILITY  # Stack trace in body
            assert check_map["CHK-A09"] == CheckStatus.VULNERABILITY  # Expired TLS cert
            assert check_map["CHK-A10"] == CheckStatus.VULNERABILITY  # Self-signed + hostname mismatch
            assert check_map["CHK-E01"] == CheckStatus.VULNERABILITY  # Missing Secure + HttpOnly
            assert check_map["CHK-E02"] == CheckStatus.VULNERABILITY  # SameSite=None without Secure

            # Garante que o segredo do cookie foi mascarado em todas as evidências
            for finding in summary.all_findings:
                assert "super_sensitive_jwt_secret_12345" not in (finding.evidence.observed_value or "")
                for h_val in finding.evidence.response_headers.values():
                    assert "super_sensitive_jwt_secret_12345" not in h_val


def test_api_context_does_not_false_positive_browser_html_headers() -> None:
    """Garante que ativos REST_API retornando JSON não geram falsos positivos de CSP/Clickjacking HTML."""
    mod_a = ModuleAReconHeadersTLS()
    res = mod_a.inspect_response_snapshot(
        target_url="https://api.lab.local/v1/items",
        status_code=200,
        headers={
            "Content-Type": "application/json",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Content-Type-Options": "nosniff",
        },
        asset_type=AssetType.REST_API,
    )
    check_map = {c.check_id: c.status for c in res.checks}
    assert check_map["CHK-A01"] == CheckStatus.PASSED
    assert check_map["CHK-A02"] == CheckStatus.PASSED
    assert check_map["CHK-A03"] == CheckStatus.NOT_APPLICABLE
    assert check_map["CHK-A04"] == CheckStatus.PASSED
    assert check_map["CHK-A05"] == CheckStatus.NOT_APPLICABLE
    assert check_map["CHK-A06"] == CheckStatus.NOT_APPLICABLE
    assert len(res.findings) == 0


def test_ssrf_out_of_scope_redirect_and_circuit_breaker_and_cancellation() -> None:
    """Valida bloqueio de redirecionamento para fora do escopo/metadados, circuit breaker e cancelamento."""

    class MaliciousRedirectAndDegradedHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def do_GET(self) -> None:
            if self.path == "/redirect-aws-metadata":
                self.send_response(302)
                self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
                self.end_headers()
            elif self.path == "/redirect-external":
                self.send_response(302)
                self.send_header("Location", "https://nao-autorizado.externo.org/login")
                self.end_headers()
            elif self.path == "/loop":
                self.send_response(302)
                self.send_header("Location", "/loop")
                self.end_headers()
            elif self.path == "/degraded":
                self.send_response(503)
                self.end_headers()
            elif self.path == "/huge":
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"A" * 16384)

    with run_local_lab_server(MaliciousRedirectAndDegradedHandler) as (_, port):
        validator = _make_lab_validator()
        policy = ScanExecutionPolicy(
            max_requests_per_second=20,
            max_response_body_bytes=4096,
            circuit_breaker_error_threshold=2,
        )
        client = ScopedSafeHttpClient(scope_validator=validator, policy=policy)

        # 1. Redirecionamento para metadados de nuvem (169.254.169.254) é bloqueado
        with pytest.raises(ScopeViolationError, match="169.254.169.254"):
            client.fetch_snapshot(f"http://127.0.0.1:{port}/redirect-aws-metadata")

        # 2. Redirecionamento para domínio externo não autorizado é bloqueado
        with pytest.raises(ScopeViolationError, match="fora do escopo"):
            client.fetch_snapshot(f"http://127.0.0.1:{port}/redirect-external")

        # 3. Loop de redirecionamento é detectado e interrompido
        with pytest.raises(RedirectLoopError, match="Loop de redirecionamento"):
            client.fetch_snapshot(f"http://127.0.0.1:{port}/loop")

        # 4. Resposta gigante é truncada no limite max_response_body_bytes
        snap = client.fetch_snapshot(f"http://127.0.0.1:{port}/huge")
        assert snap.body_truncated is True

        # 5. Circuit breaker interrompe após 2 respostas HTTP 503 consecutivas
        client.fetch_snapshot(f"http://127.0.0.1:{port}/degraded")
        with pytest.raises(CircuitBreakerTrippedError, match="Circuit breaker acionado"):
            client.fetch_snapshot(f"http://127.0.0.1:{port}/degraded")

        # 6. Cancelamento cooperativo
        with pytest.raises(ScanCancelledError):
            client.fetch_snapshot(
                f"http://127.0.0.1:{port}/huge",
                is_cancelled=lambda: True,
            )


def test_execution_error_when_target_is_unreachable() -> None:
    """Garante que falha técnica de conexão gera EXECUTION_ERROR e jamais é tratada como PASSED."""
    mod_a = ModuleAReconHeadersTLS()
    mod_e = ModuleECookiesAndSession()

    res_a = mod_a.inspect_response_snapshot(
        target_url="https://127.0.0.1:59999/",
        status_code=0,
        headers={},
    )
    assert res_a.execution_errors == 1
    assert res_a.checks[0].status == CheckStatus.EXECUTION_ERROR

    res_e = mod_e.inspect_response_snapshot(
        target_url="https://127.0.0.1:59999/",
        status_code=0,
        headers={},
    )
    assert res_e.execution_errors == 1
    assert res_e.checks[0].status == CheckStatus.EXECUTION_ERROR
