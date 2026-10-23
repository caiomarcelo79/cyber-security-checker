"""Contratos de adaptadores opcionais para ferramentas externas (OWASP ZAP, Playwright, TLS)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class AdapterHealthStatus:
    """Estado de disponibilidade de um adaptador externo opcional."""

    adapter_id: str
    name: str
    optional: bool
    available: bool
    details: str


class ExternalToolAdapter(ABC):
    """Interface base para adaptadores opcionais de ferramentas externas (Seção 4).

    Regra: As ferramentas externas devem ser opcionais e isoladas por adaptadores,
    sem comprometer o funcionamento do sistema caso alguma não esteja disponível.
    """

    @property
    @abstractmethod
    def adapter_id(self) -> str:
        """Identificador único do adaptador."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Nome legível da integração externa."""

    @abstractmethod
    def check_availability(self) -> AdapterHealthStatus:
        """Verifica de forma segura se a ferramenta externa está acessível."""


class OwaspZapOptionalAdapter(ExternalToolAdapter):
    """Adaptador opcional para integração futura via API com OWASP ZAP."""

    def __init__(self, zap_api_url: str | None = None) -> None:
        self.zap_api_url = zap_api_url

    @property
    def adapter_id(self) -> str:
        return "adapter_owasp_zap"

    @property
    def name(self) -> str:
        return "OWASP ZAP Daemon API (Opcional)"

    def check_availability(self) -> AdapterHealthStatus:
        if not self.zap_api_url:
            return AdapterHealthStatus(
                adapter_id=self.adapter_id,
                name=self.name,
                optional=True,
                available=False,
                details="Não configurado (operação 100% funcional via detectores nativos do security-engine).",
            )
        return AdapterHealthStatus(
            adapter_id=self.adapter_id,
            name=self.name,
            optional=True,
            available=True,
            details=f"Endpoint ZAP configurado em {self.zap_api_url}",
        )
