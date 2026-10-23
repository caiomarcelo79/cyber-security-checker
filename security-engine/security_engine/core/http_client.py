"""Cliente HTTP/TLS centralizado e seguro com proteção Anti-SSRF, Rate Limiting e Circuit Breaker."""

from __future__ import annotations

import ipaddress
import socket
import ssl
import struct
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

import httpx
from cryptography import x509
from cryptography.x509.oid import NameOID

from security_engine.core.contracts import (
    AssetType,
    EnvironmentType,
    HttpInspectionSnapshot,
    RedirectHop,
    TlsInspectionDetail,
)
from security_engine.policies.execution_policy import ScanExecutionPolicy
from security_engine.policies.scope_validator import (
    ScopePolicyValidator,
    ScopeViolationError,
)

SCANNER_USER_AGENT = "CyberSecurityChecker-Engine/1.0 (+Authorized-Defensive-Audit)"


class SafeHttpClientError(RuntimeError):
    """Erro base operacional do cliente HTTP seguro."""


class ScanCancelledError(SafeHttpClientError):
    """Levantada quando a execução é cancelada cooperativamente pelo usuário ou sistema."""


class CircuitBreakerTrippedError(SafeHttpClientError):
    """Levantada quando o alvo apresenta degradação contínua (429/503/Timeouts consecutivos)."""


class RedirectLoopError(SafeHttpClientError):
    """Levantada quando um loop de redirecionamentos HTTP é detectado."""


class MaxRedirectsExceededError(SafeHttpClientError):
    """Levantada quando o número de redirecionamentos excede o limite da política."""


@dataclass
class SafeProbeResult:
    """Resultado estruturado de uma requisição de teste pontual segura."""

    status_code: int
    headers: dict[str, str]
    body: str
    elapsed_ms: int
    url: str
    error: str | None = None


def _match_hostname_pattern(hostname: str, pattern: str) -> bool:
    """Verifica correspondência RFC 6125 entre um hostname e um padrão DNS/SAN (incluindo wildcard)."""
    host = hostname.strip().lower().rstrip(".")
    pat = pattern.strip().lower().rstrip(".")
    if not host or not pat:
        return False
    if host == pat:
        return True
    if pat.startswith("*."):
        suffix = pat[2:]
        if "." in suffix and host.endswith(f".{suffix}"):
            prefix = host[: -(len(suffix) + 1)]
            return "." not in prefix and len(prefix) > 0
    return False


class ScopedSafeHttpClient:
    """Cliente HTTP/TLS defensivo que impõe validação de escopo, limites de taxa e circuit breaker."""

    def __init__(
        self,
        scope_validator: ScopePolicyValidator,
        policy: ScanExecutionPolicy | None = None,
        *,
        resolve_dns: bool = True,
        custom_resolver: list[str] | None = None,
        verify_tls_in_http_client: bool = False,
        ca_bundle_path: str | None = None,
        http_transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.scope_validator = scope_validator
        self.policy = policy or ScanExecutionPolicy()
        self.resolve_dns = resolve_dns
        self.custom_resolver = custom_resolver
        self.verify_tls_in_http_client = verify_tls_in_http_client
        self.ca_bundle_path = ca_bundle_path
        self.http_transport = http_transport

        self._rate_lock = threading.Lock()
        self._last_request_ts: float = 0.0
        self._semaphore = threading.BoundedSemaphore(self.policy.max_concurrency)
        self._consecutive_degradation_errors: int = 0
        self._total_requests_made: int = 0
        self._session_started_monotonic: float = time.monotonic()

    @property
    def total_requests_made(self) -> int:
        return self._total_requests_made

    @property
    def consecutive_degradation_errors(self) -> int:
        return self._consecutive_degradation_errors

    def _check_cancellation_and_global_timeout(
        self,
        is_cancelled: Callable[[], bool] | None = None,
    ) -> None:
        if is_cancelled and is_cancelled():
            raise ScanCancelledError("Auditoria cancelada cooperativamente durante a execução.")
        elapsed = time.monotonic() - self._session_started_monotonic
        if elapsed > self.policy.global_timeout_seconds:
            raise SafeHttpClientError(
                f"Timeout global da auditoria excedido ({self.policy.global_timeout_seconds}s)."
            )

    def _acquire_rate_slot(self) -> None:
        min_interval = 1.0 / float(max(1, self.policy.max_requests_per_second))
        with self._rate_lock:
            now = time.monotonic()
            if self._last_request_ts > 0.0:
                wait_seconds = min_interval - (now - self._last_request_ts)
                if wait_seconds > 0:
                    time.sleep(wait_seconds)
            self._last_request_ts = time.monotonic()

    def _record_degradation_signal(self, reason: str) -> None:
        self._consecutive_degradation_errors += 1
        if (
            self.policy.abort_on_target_degradation
            and self._consecutive_degradation_errors >= self.policy.circuit_breaker_error_threshold
        ):
            raise CircuitBreakerTrippedError(
                f"Circuit breaker acionado após {self._consecutive_degradation_errors} falhas/sinais "
                f"de degradação consecutivos ({reason})."
            )

    def _reset_degradation_signal(self) -> None:
        self._consecutive_degradation_errors = 0

    def inspect_tls_endpoint(self, url: str) -> TlsInspectionDetail:
        """Executa inspeção não invasiva do certificado X.509 e versão TLS negociada."""
        parsed = urlparse(url)
        if parsed.scheme.lower() != "https":
            return TlsInspectionDetail(enabled=False)

        # Valida escopo e Anti-SSRF antes de abrir socket TLS
        self.scope_validator.validate_url(
            url,
            resolve_dns=self.resolve_dns,
            custom_resolver=self.custom_resolver,
        )

        hostname = parsed.hostname or ""
        port = parsed.port or 443
        detail = TlsInspectionDetail(enabled=True)

        # 1. Tentativa de validação completa da cadeia de confiança e hostname
        try:
            verified_ctx = ssl.create_default_context(cafile=self.ca_bundle_path)
            verified_ctx.check_hostname = True
            verified_ctx.verify_mode = ssl.CERT_REQUIRED
            with (
                socket.create_connection(
                    (hostname, port), timeout=self.policy.request_timeout_seconds
                ) as sock,
                verified_ctx.wrap_socket(sock, server_hostname=hostname) as ssock,
            ):
                detail.handshake_succeeded = True
                detail.trusted_chain = True
                detail.hostname_matched = True
                detail.negotiated_version = ssock.version()
                cipher = ssock.cipher()
                if cipher:
                    detail.cipher_suite = cipher[0]
        except ssl.SSLCertVerificationError as verify_exc:
            detail.verification_error = str(verify_exc)
            detail.trusted_chain = False
        except ssl.SSLError as ssl_exc:
            detail.verification_error = f"SSLError: {ssl_exc}"
        except OSError as conn_exc:
            detail.connection_error = f"Falha de conexão TCP/TLS: {conn_exc}"
            return detail

        # 2. Extração determinística dos metadados do certificado X.509 em formato DER
        try:
            diag_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            diag_ctx.check_hostname = False
            diag_ctx.verify_mode = ssl.CERT_NONE
            with (
                socket.create_connection(
                    (hostname, port), timeout=self.policy.request_timeout_seconds
                ) as sock,
                diag_ctx.wrap_socket(sock, server_hostname=hostname) as ssock,
            ):
                detail.handshake_succeeded = True
                if not detail.negotiated_version:
                    detail.negotiated_version = ssock.version()
                if not detail.cipher_suite:
                    cipher = ssock.cipher()
                    if cipher:
                        detail.cipher_suite = cipher[0]

                der_bytes = ssock.getpeercert(binary_form=True)
                if der_bytes:
                    cert = x509.load_der_x509_certificate(der_bytes)
                    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                    if cn_attrs:
                        detail.subject_cn = str(cn_attrs[0].value)

                    issuer_attrs = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
                    if issuer_attrs:
                        detail.issuer_cn = str(issuer_attrs[0].value)

                    detail.is_self_signed = cert.subject == cert.issuer

                    not_before_dt = cert.not_valid_before_utc
                    not_after_dt = cert.not_valid_after_utc
                    detail.not_before = not_before_dt.isoformat()
                    detail.not_after = not_after_dt.isoformat()

                    now_utc = datetime.now(UTC)
                    delta = not_after_dt - now_utc
                    detail.days_until_expiration = int(delta.total_seconds() // 86400)
                    detail.is_expired = now_utc > not_after_dt or now_utc < not_before_dt

                    san_names: list[str] = []
                    try:
                        san_ext = cert.extensions.get_extension_for_class(
                            x509.SubjectAlternativeName
                        )
                        for dns_name in san_ext.value.get_values_for_type(x509.DNSName):
                            san_names.append(str(dns_name))
                        for ip_val in san_ext.value.get_values_for_type(x509.IPAddress):
                            san_names.append(str(ip_val))
                    except x509.ExtensionNotFound:
                        pass
                    detail.san_dns_names = san_names

                    # Verifica correspondência de hostname contra SANs ou Subject CN
                    candidates = san_names if san_names else ([detail.subject_cn] if detail.subject_cn else [])
                    matched = False
                    for candidate in candidates:
                        if not candidate:
                            continue
                        try:
                            if ipaddress.ip_address(hostname) == ipaddress.ip_address(candidate):
                                matched = True
                                break
                        except ValueError:
                            if _match_hostname_pattern(hostname, candidate):
                                matched = True
                                break
                    detail.hostname_matched = matched

                if detail.negotiated_version in {"TLSv1", "TLSv1.0", "TLSv1.1"}:
                    detail.weak_protocols_accepted.append(detail.negotiated_version)
        except OSError as exc:
            if not detail.handshake_succeeded:
                detail.connection_error = f"Erro ao inspecionar certificado TLS: {exc}"

        return detail

    def fetch_snapshot(
        self,
        target_url: str,
        *,
        asset_type: AssetType = AssetType.WEB_APP,
        environment: EnvironmentType = EnvironmentType.STAGING,
        is_cancelled: Callable[[], bool] | None = None,
        inspect_tls: bool = True,
        http_redirect_probe_url: str | None = None,
    ) -> HttpInspectionSnapshot:
        """Executa requisição HTTP/HTTPS controlada com validação de escopo em cada hop e coleta snapshot."""
        start_ts = time.monotonic()
        self._check_cancellation_and_global_timeout(is_cancelled)

        # Validação obrigatória do URL inicial antes de qualquer conexão
        initial_decision = self.scope_validator.validate_url(
            target_url,
            resolve_dns=self.resolve_dns,
            custom_resolver=self.custom_resolver,
        )
        current_url = initial_decision.normalized_url
        visited_urls: set[str] = {current_url}
        redirect_chain: list[RedirectHop] = []
        collected_set_cookies: list[str] = []

        verify_param: ssl.SSLContext | bool = (
            ssl.create_default_context(cafile=self.ca_bundle_path)
            if self.ca_bundle_path
            else self.verify_tls_in_http_client
        )

        final_status_code = 0
        final_headers: dict[str, str] = {}
        body_excerpt = ""
        body_truncated = False

        with httpx.Client(
            follow_redirects=False,
            timeout=httpx.Timeout(self.policy.request_timeout_seconds),
            verify=verify_param,
            headers={"User-Agent": SCANNER_USER_AGENT},
            transport=self.http_transport,
        ) as client:
            step = 0
            while True:
                self._check_cancellation_and_global_timeout(is_cancelled)
                self._acquire_rate_slot()

                with self._semaphore:
                    self._total_requests_made += 1
                    try:
                        with client.stream("GET", current_url) as response:
                            final_status_code = response.status_code
                            final_headers = dict(response.headers.items())
                            hop_cookies = response.headers.get_list("set-cookie")
                            for c_val in hop_cookies:
                                if c_val not in collected_set_cookies:
                                    collected_set_cookies.append(c_val)

                            if final_status_code in {429, 503}:
                                self._record_degradation_signal(f"HTTP {final_status_code}")
                            else:
                                self._reset_degradation_signal()

                            # Verifica redirecionamentos 3xx com Location
                            location = response.headers.get("location")
                            if final_status_code in {301, 302, 303, 307, 308} and location:
                                step += 1
                                if step > self.policy.max_redirects:
                                    raise MaxRedirectsExceededError(
                                        f"Limite máximo de redirecionamentos ({self.policy.max_redirects}) excedido."
                                    )

                                # Valida o destino do redirecionamento contra escopo e Anti-SSRF
                                redirect_decision = self.scope_validator.validate_redirect_target(
                                    current_url,
                                    location,
                                    resolve_dns=self.resolve_dns,
                                    custom_resolver=self.custom_resolver,
                                )
                                next_url = redirect_decision.normalized_url
                                src_scheme = urlparse(current_url).scheme.lower()
                                dst_scheme = urlparse(next_url).scheme.lower()

                                redirect_chain.append(
                                    RedirectHop(
                                        step=step,
                                        source_url=current_url,
                                        status_code=final_status_code,
                                        target_url=next_url,
                                        scheme_upgraded=(src_scheme == "http" and dst_scheme == "https"),
                                        scheme_downgraded=(src_scheme == "https" and dst_scheme == "http"),
                                    )
                                )

                                if self.policy.prevent_redirect_loops and next_url in visited_urls:
                                    raise RedirectLoopError(
                                        f"Loop de redirecionamento detectado para '{next_url}'."
                                    )
                                visited_urls.add(next_url)
                                current_url = next_url
                                continue

                            # Lê o corpo da resposta respeitando max_response_body_bytes
                            chunks: list[bytes] = []
                            bytes_read = 0
                            for chunk in response.iter_bytes(chunk_size=8192):
                                if bytes_read + len(chunk) > self.policy.max_response_body_bytes:
                                    remaining = max(0, self.policy.max_response_body_bytes - bytes_read)
                                    if remaining > 0:
                                        chunks.append(chunk[:remaining])
                                    body_truncated = True
                                    break
                                chunks.append(chunk)
                                bytes_read += len(chunk)

                            raw_body = b"".join(chunks)
                            body_excerpt = raw_body.decode("utf-8", errors="replace")[:4096]
                            break

                    except (ScopeViolationError, ScanCancelledError, CircuitBreakerTrippedError, RedirectLoopError, MaxRedirectsExceededError):
                        raise
                    except httpx.TimeoutException as exc:
                        self._record_degradation_signal("Timeout HTTP")
                        return HttpInspectionSnapshot(
                            initial_url=initial_decision.normalized_url,
                            final_url=current_url,
                            status_code=0,
                            redirect_chain=redirect_chain,
                            raw_set_cookies=collected_set_cookies,
                            elapsed_ms=int((time.monotonic() - start_ts) * 1000),
                            total_requests_made=self._total_requests_made,
                            asset_type=asset_type,
                            environment=environment,
                            connection_error=f"Timeout ao conectar em {current_url}: {exc}",
                        )
                    except httpx.HTTPError as exc:
                        self._record_degradation_signal("Erro de transporte HTTP")
                        return HttpInspectionSnapshot(
                            initial_url=initial_decision.normalized_url,
                            final_url=current_url,
                            status_code=0,
                            redirect_chain=redirect_chain,
                            raw_set_cookies=collected_set_cookies,
                            elapsed_ms=int((time.monotonic() - start_ts) * 1000),
                            total_requests_made=self._total_requests_made,
                            asset_type=asset_type,
                            environment=environment,
                            connection_error=f"Falha de comunicação HTTP com {current_url}: {exc}",
                        )

            # Verifica se houve redirecionamento HTTP -> HTTPS na cadeia principal ou em probe auxiliar
            http_to_https_redirected: bool | None = None
            http_probe_status: int | None = None

            if any(hop.scheme_upgraded for hop in redirect_chain):
                http_to_https_redirected = True
            elif urlparse(initial_decision.normalized_url).scheme.lower() == "http":
                http_to_https_redirected = urlparse(current_url).scheme.lower() == "https"
            elif http_redirect_probe_url:
                try:
                    probe_decision = self.scope_validator.validate_url(
                        http_redirect_probe_url,
                        resolve_dns=self.resolve_dns,
                        custom_resolver=self.custom_resolver,
                    )
                    self._acquire_rate_slot()
                    with self._semaphore:
                        self._total_requests_made += 1
                        probe_resp = client.get(probe_decision.normalized_url)
                        http_probe_status = probe_resp.status_code
                        loc = probe_resp.headers.get("location", "")
                        http_to_https_redirected = (
                            probe_resp.status_code in {301, 302, 307, 308}
                            and loc.strip().lower().startswith("https://")
                        )
                except (ScopeViolationError, httpx.HTTPError, OSError):
                    http_to_https_redirected = None

        tls_detail: TlsInspectionDetail | None = None
        if inspect_tls and urlparse(current_url).scheme.lower() == "https" and self.http_transport is None:
            tls_detail = self.inspect_tls_endpoint(current_url)

        elapsed_ms = int((time.monotonic() - start_ts) * 1000)
        return HttpInspectionSnapshot(
            initial_url=initial_decision.normalized_url,
            final_url=current_url,
            status_code=final_status_code,
            headers=final_headers,
            raw_set_cookies=collected_set_cookies,
            redirect_chain=redirect_chain,
            http_to_https_redirected=http_to_https_redirected,
            http_probe_status_code=http_probe_status,
            tls_info=tls_detail,
            body_excerpt=body_excerpt,
            body_truncated=body_truncated,
            elapsed_ms=elapsed_ms,
            total_requests_made=self._total_requests_made,
            asset_type=asset_type,
            environment=environment,
            connection_error=None,
        )

    def probe(
        self,
        target_url: str,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        data: Any = None,
        params: dict[str, str] | None = None,
        is_cancelled: Callable[[], bool] | None = None,
        max_bytes: int = 65536,
    ) -> SafeProbeResult | None:
        """Executa uma requisição HTTP pontual com validação estrita anti-SSRF, rate limiting e circuit breaker."""
        start_ts = time.monotonic()
        self._check_cancellation_and_global_timeout(is_cancelled)

        decision = self.scope_validator.validate_url(
            target_url,
            resolve_dns=self.resolve_dns,
            custom_resolver=self.custom_resolver,
        )
        norm_url = decision.normalized_url

        self._acquire_rate_slot()
        with self._semaphore:
            self._total_requests_made += 1
            verify_param: ssl.SSLContext | bool = (
                ssl.create_default_context(cafile=self.ca_bundle_path)
                if self.ca_bundle_path
                else self.verify_tls_in_http_client
            )
            req_headers = {"User-Agent": SCANNER_USER_AGENT}
            if headers:
                req_headers.update(headers)

            try:
                with httpx.Client(
                    follow_redirects=False,
                    timeout=httpx.Timeout(min(self.policy.request_timeout_seconds, 10)),
                    verify=verify_param,
                    transport=self.http_transport,
                ) as client:
                    resp = client.request(
                        method,
                        norm_url,
                        headers=req_headers,
                        data=data,
                        params=params,
                    )
                    if resp.status_code in {429, 503}:
                        self._record_degradation_signal(f"HTTP {resp.status_code}")
                    else:
                        self._reset_degradation_signal()

                    body_str = resp.text[:max_bytes]
                    elapsed = int((time.monotonic() - start_ts) * 1000)
                    return SafeProbeResult(
                        status_code=resp.status_code,
                        headers=dict(resp.headers.items()),
                        body=body_str,
                        elapsed_ms=elapsed,
                        url=str(resp.url),
                    )
            except (ScopeViolationError, ScanCancelledError, CircuitBreakerTrippedError):
                raise
            except httpx.TimeoutException:
                self._record_degradation_signal("Timeout HTTP na probe")
                return None
            except (httpx.HTTPError, OSError):
                self._record_degradation_signal("Falha de conexão na probe")
                return None

    @staticmethod
    def query_dns_txt_records(
        qname: str,
        nameserver: str = "8.8.8.8",
        timeout: float = 2.0,
        resolver_fn: Callable[[str], list[str]] | None = None,
    ) -> list[str]:
        """Consulta registros DNS TXT (RFC 1035) de forma determinística sem dependências externas."""
        if resolver_fn:
            return resolver_fn(qname)
        tx_id = 0x4353
        flags = 0x0100  # Recursion desired
        header = struct.pack("!HHHHHH", tx_id, flags, 1, 0, 0, 0)
        qname_bytes = b"".join(
            bytes([len(p)]) + p.encode("ascii") for p in qname.strip(".").split(".") if p
        ) + b"\x00"
        qtype_txt = 16
        qclass_in = 1
        question = qname_bytes + struct.pack("!HH", qtype_txt, qclass_in)
        packet = header + question

        txt_records: list[str] = []
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(packet, (nameserver, 53))
                data, _ = sock.recvfrom(4096)
                if len(data) < 12:
                    return []
                _, resp_flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])
                if (resp_flags & 0x000F) != 0:
                    return []
                offset = 12
                for _ in range(qdcount):
                    while offset < len(data) and data[offset] != 0:
                        offset += 1 + data[offset]
                    offset += 5  # null byte + type + class
                for _ in range(ancount):
                    if offset >= len(data):
                        break
                    if (data[offset] & 0xC0) == 0xC0:
                        offset += 2
                    else:
                        while offset < len(data) and data[offset] != 0:
                            offset += 1 + data[offset]
                        offset += 1
                    if offset + 10 > len(data):
                        break
                    rtype, _, _, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
                    offset += 10
                    rdata = data[offset : offset + rdlength]
                    offset += rdlength
                    if rtype == 16:  # TXT
                        txt_offset = 0
                        chunks: list[str] = []
                        while txt_offset < len(rdata):
                            chunk_len = rdata[txt_offset]
                            txt_offset += 1
                            chunk_bytes = rdata[txt_offset : txt_offset + chunk_len]
                            chunks.append(chunk_bytes.decode("utf-8", errors="replace"))
                            txt_offset += chunk_len
                        if chunks:
                            txt_records.append("".join(chunks))
        except (OSError, UnicodeDecodeError, struct.error):
            return []
        return txt_records
