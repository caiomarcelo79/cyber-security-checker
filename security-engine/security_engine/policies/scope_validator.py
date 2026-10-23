"""Validador de escopo, prevenção de SSRF e revalidação de destinos (Seção 12)."""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urlparse


class ScopeViolationError(ValueError):
    """Exceção lançada quando um destino viola o escopo autorizado ou as proteções anti-SSRF."""


# Redes reservadas/privadas bloqueadas por padrão para prevenir SSRF
BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # Cloud Metadata Services (AWS/GCP/Azure 169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
]

# Endereços de metadados de nuvem que NUNCA podem ser acessados, mesmo em modo laboratório
CLOUD_METADATA_IPS = {
    "169.254.169.254",
    "169.254.170.2",
    "fd00:ec2::254",
}

CLOUD_METADATA_HOSTS = {
    "metadata.google.internal",
    "metadata",
    "instance-data",
}


@dataclass(frozen=True)
class ScopeDecision:
    """Resultado auditável de uma validação de escopo."""

    allowed: bool
    normalized_url: str
    hostname: str
    resolved_ips: list[str] = field(default_factory=list)
    reason: str = "OK"


class ScopePolicyValidator:
    """Valida URLs, escopo de domínio, caminhos excluídos e endereços IP (Anti-SSRF).

    Regra fundamental (Seção 12):
    - A permissão para verificar um domínio não autoriza automaticamente todos os seus subdomínios,
      provedores ou serviços externos.
    - Bloqueia destinos fora do escopo, inclusive redirecionamentos.
    - Previne SSRF protegendo redes internas, metadados de nuvem e infraestrutura local.
    """

    def __init__(
        self,
        authorized_hosts: set[str] | list[str],
        allow_subdomains: bool = False,
        excluded_paths: list[str] | None = None,
        block_private_networks: bool = True,
        allow_local_lab_targets: bool = False,
        lab_allowed_hosts: set[str] | list[str] | None = None,
    ) -> None:
        self.authorized_hosts = {h.strip().lower() for h in authorized_hosts if h.strip()}
        self.allow_subdomains = allow_subdomains
        self.excluded_paths = [
            p.strip() if p.strip().startswith("/") else f"/{p.strip()}"
            for p in (excluded_paths or [])
            if p.strip()
        ]
        self.block_private_networks = block_private_networks
        self.allow_local_lab_targets = allow_local_lab_targets
        self.lab_allowed_hosts = {
            h.strip().lower() for h in (lab_allowed_hosts or []) if h.strip()
        }

    @staticmethod
    def is_private_or_reserved_ip(ip_str: str) -> bool:
        """Verifica se um endereço IPv4 ou IPv6 pertence a redes internas, loopback ou reservadas."""
        addr = ipaddress.ip_address(ip_str)
        if addr.version == 6 and addr.ipv4_mapped is not None:
            addr = addr.ipv4_mapped
        if (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_unspecified
        ):
            return True
        return any(addr in net for net in BLOCKED_NETWORKS if addr.version == net.version)

    def _is_host_in_authorized_scope(self, hostname: str) -> bool:
        host = hostname.lower()
        if host in self.authorized_hosts:
            return True
        if self.allow_local_lab_targets and host in self.lab_allowed_hosts and host in self.authorized_hosts:
            return True
        if self.allow_subdomains:
            for auth_host in self.authorized_hosts:
                if host.endswith(f".{auth_host}"):
                    return True
        return False

    def _is_path_excluded(self, path: str) -> bool:
        normalized_path = path or "/"
        for excluded in self.excluded_paths:
            if normalized_path == excluded or normalized_path.startswith(f"{excluded}/"):
                return True
        return False

    def validate_ip_address(self, ip_str: str, hostname: str) -> None:
        """Valida se o endereço IP resolvido é seguro contra SSRF."""
        if ip_str in CLOUD_METADATA_IPS:
            raise ScopeViolationError(
                f"Bloqueio crítico Anti-SSRF: endereço de metadados de nuvem proibido ({ip_str})."
            )

        if self.is_private_or_reserved_ip(ip_str):
            is_explicit_lab_host = (
                self.allow_local_lab_targets and hostname.lower() in self.lab_allowed_hosts
            )
            if self.block_private_networks and not is_explicit_lab_host:
                raise ScopeViolationError(
                    f"Bloqueio Anti-SSRF: endereço interno/reservado '{ip_str}' para o host '{hostname}' "
                    "não é permitido fora do laboratório isolado autorizado."
                )

    def validate_url(
        self,
        url: str,
        resolve_dns: bool = False,
        custom_resolver: list[str] | None = None,
    ) -> ScopeDecision:
        """Valida esquema, host, escopo autorizado, caminhos excluídos e IPs (opcionalmente via DNS)."""
        if not url or not isinstance(url, str):
            raise ScopeViolationError("URL inválida ou vazia.")

        parsed = urlparse(url.strip())
        if parsed.scheme.lower() not in {"http", "https"}:
            raise ScopeViolationError(
                f"Esquema de URL não permitido: '{parsed.scheme}'. Apenas http e https são aceitos."
            )

        if not parsed.hostname:
            raise ScopeViolationError("URL não contém um hostname válido.")

        if parsed.username or parsed.password:
            raise ScopeViolationError(
                "Credenciais embutidas na URL (user:pass@host) são proibidas por segurança."
            )

        hostname = parsed.hostname.lower()
        if hostname in CLOUD_METADATA_HOSTS:
            raise ScopeViolationError(
                f"Bloqueio crítico Anti-SSRF: host de metadados de nuvem proibido ({hostname})."
            )

        # Verifica se o próprio hostname já é um literal IP
        literal_ip: str | None = None
        try:
            ipaddress.ip_address(hostname)
            literal_ip = hostname
        except ValueError:
            literal_ip = None

        if literal_ip is not None:
            self.validate_ip_address(literal_ip, hostname)

        if not self._is_host_in_authorized_scope(hostname):
            raise ScopeViolationError(
                f"Host '{hostname}' está fora do escopo autorizado ({sorted(self.authorized_hosts)})."
            )

        path = parsed.path or "/"
        if self._is_path_excluded(path):
            raise ScopeViolationError(
                f"Caminho '{path}' pertence à lista de endpoints excluídos da auditoria."
            )

        resolved_ips: list[str] = []
        if literal_ip is not None:
            resolved_ips = [literal_ip]
        elif custom_resolver is not None:
            for ip_item in custom_resolver:
                self.validate_ip_address(ip_item, hostname)
                resolved_ips.append(ip_item)
        elif resolve_dns:
            try:
                addr_info = socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
                seen: set[str] = set()
                for entry in addr_info:
                    ip_candidate = str(entry[4][0])
                    if ip_candidate not in seen:
                        seen.add(ip_candidate)
                        self.validate_ip_address(ip_candidate, hostname)
                        resolved_ips.append(ip_candidate)
            except socket.gaierror as exc:
                raise ScopeViolationError(
                    f"Falha ao resolver DNS do host autorizado '{hostname}': {exc}"
                ) from exc

        normalized_url = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{path}"
        if parsed.query:
            normalized_url = f"{normalized_url}?{parsed.query}"

        return ScopeDecision(
            allowed=True,
            normalized_url=normalized_url,
            hostname=hostname,
            resolved_ips=resolved_ips,
            reason="URL dentro do escopo autorizado e aprovada nas verificações Anti-SSRF.",
        )

    def validate_redirect_target(
        self,
        source_url: str,
        redirect_location: str,
        resolve_dns: bool = False,
        custom_resolver: list[str] | None = None,
    ) -> ScopeDecision:
        """Valida o destino de um redirecionamento HTTP (bloqueando desvios para fora do escopo)."""
        from urllib.parse import urljoin

        resolved_target = urljoin(source_url, redirect_location)
        return self.validate_url(
            resolved_target,
            resolve_dns=resolve_dns,
            custom_resolver=custom_resolver,
        )
