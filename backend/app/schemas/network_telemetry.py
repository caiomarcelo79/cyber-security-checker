"""Contratos de inscrição da fonte e importação de conexões."""

from datetime import datetime
from ipaddress import IPv4Network, IPv6Network
from typing import Annotated, Literal

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    IPvAnyNetwork,
    StringConstraints,
    field_validator,
)

MAX_CONNECTIONS_PER_BATCH = 200
Port = Annotated[int, Field(strict=True, ge=0, le=65535)]
ByteCount = Annotated[int, Field(strict=True, ge=0, le=(1 << 63) - 1)]


class TelemetrySourceCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=2, max_length=100)]
    network: IPvAnyNetwork
    expires_in_days: int = Field(default=30, strict=True, ge=1, le=90)

    @field_validator("network", mode="before")
    @classmethod
    def validate_network_text(cls, value: object) -> str:
        if not isinstance(value, str) or "/" not in value or "%" in value:
            raise ValueError("Informe um segmento específico no formato CIDR.")
        return value

    @field_validator("network")
    @classmethod
    def require_segment(cls, value: IPv4Network | IPv6Network) -> IPv4Network | IPv6Network:
        if value.prefixlen == 0:
            raise ValueError("Informe um segmento específico no formato CIDR.")
        return value


class TelemetrySourceResponse(BaseModel):
    id: str
    name: str
    network: str
    status: Literal["ACTIVE", "EXPIRED", "REVOKED"]
    expires_at: datetime
    last_received_at: datetime | None
    latest_observed_at: datetime | None
    connection_count: int


class TelemetrySourceCreated(TelemetrySourceResponse):
    collector_token: str


class ConnectionObservation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    uid: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9]+$")
    observed_at: AwareDatetime
    origin_ip: IPvAnyAddress
    origin_port: Port
    responder_ip: IPvAnyAddress
    responder_port: Port
    transport: Literal["tcp", "udp", "icmp"]
    origin_bytes: ByteCount | None = None
    responder_bytes: ByteCount | None = None

    @field_validator("origin_ip", "responder_ip", mode="before")
    @classmethod
    def validate_address(cls, value: object) -> str:
        if not isinstance(value, str) or "%" in value:
            raise ValueError("Informe um endereço IP textual sem identificador de interface.")
        return value


class ConnectionBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: list[ConnectionObservation] = Field(min_length=1, max_length=MAX_CONNECTIONS_PER_BATCH)


class ConnectionImportResult(BaseModel):
    inserted: int
    duplicates: int
