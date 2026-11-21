"""Contratos Pydantic para análise explicável de tráfego suspeito em laboratório."""

from datetime import datetime
from typing import Annotated, Any

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    StringConstraints,
    field_validator,
    model_validator,
)

from app.schemas.network_telemetry import ConnectionObservation, Port
from app.services.suspicious_traffic_logic import (
    AlertCategory,
    AlertConfidence,
    AlertSeverity,
    EdrSignalCode,
    EdrSourceType,
    TlsDecisionOutcome,
)

MAX_DNS_PER_BATCH = 200
MAX_TLS_PER_BATCH = 100
MAX_EDR_PER_BATCH = 100
UidStr = Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9]+$")]
TrimmedText255 = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=255)]


class DnsObservation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    uid: UidStr
    observed_at: AwareDatetime
    client_ip: IPvAnyAddress
    responder_ip: IPvAnyAddress
    query: TrimmedText255
    qtype: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=24)] = "A"
    rcode: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=32)]

    @field_validator("client_ip", "responder_ip", mode="before")
    @classmethod
    def validate_address(cls, value: object) -> str:
        if not isinstance(value, str) or "%" in value:
            raise ValueError("Informe um endereço IP textual sem identificador de interface.")
        return value


class TlsObservation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    uid: UidStr
    observed_at: AwareDatetime
    client_ip: IPvAnyAddress
    responder_ip: IPvAnyAddress
    responder_port: Port
    server_name: TrimmedText255
    cert_sha256: Annotated[
        str,
        StringConstraints(strip_whitespace=True, pattern=r"^[0-9a-fA-F]{64}$"),
    ]
    subject: TrimmedText255
    issuer: TrimmedText255
    validation_status: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=64)]
    self_signed: bool
    not_before: AwareDatetime
    not_after: AwareDatetime

    @field_validator("client_ip", "responder_ip", mode="before")
    @classmethod
    def validate_address(cls, value: object) -> str:
        if not isinstance(value, str) or "%" in value:
            raise ValueError("Informe um endereço IP textual sem identificador de interface.")
        return value

    @field_validator("cert_sha256", mode="after")
    @classmethod
    def normalize_fingerprint(cls, value: str) -> str:
        return value.lower()


class EdrSignalObservation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    uid: UidStr
    observed_at: AwareDatetime
    host_ip: IPvAnyAddress
    source_type: EdrSourceType
    signal: EdrSignalCode
    process_name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=120)]
    detail: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=255)] | None = None

    @field_validator("host_ip", mode="before")
    @classmethod
    def validate_address(cls, value: object) -> str:
        if not isinstance(value, str) or "%" in value:
            raise ValueError("Informe um endereço IP textual sem identificador de interface.")
        return value


class TrafficAnalysisBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    connections: list[ConnectionObservation] = Field(default_factory=list, max_length=200)
    dns_queries: list[DnsObservation] = Field(default_factory=list, max_length=MAX_DNS_PER_BATCH)
    tls_handshakes: list[TlsObservation] = Field(default_factory=list, max_length=MAX_TLS_PER_BATCH)
    edr_signals: list[EdrSignalObservation] = Field(default_factory=list, max_length=MAX_EDR_PER_BATCH)

    @model_validator(mode="after")
    def require_at_least_one_event(self) -> "TrafficAnalysisBatch":
        if not (self.connections or self.dns_queries or self.tls_handshakes):
            raise ValueError("Envie ao menos uma observação de conexão, DNS ou TLS.")
        return self


class TrafficCoverageResponse(BaseModel):
    observed_layers: list[str]
    missing_layers: list[str]


class SuspiciousTrafficAlertResponse(BaseModel):
    id: str
    rule_id: str
    category: AlertCategory
    severity: AlertSeverity
    confidence: AlertConfidence
    title: str
    explanation: str
    evidence: dict[str, Any]
    observed_layers: list[str]
    missing_layers: list[str]
    created_at: datetime


class TrafficTlsDecisionResponse(BaseModel):
    id: str
    uid: str
    server_name: str
    responder_ip: str
    responder_port: int
    outcome: TlsDecisionOutcome
    observed_cert_sha256: str
    previous_cert_sha256: str | None
    observed_issuer: str
    previous_issuer: str | None
    reason: str
    observed_at: datetime


class TrafficEdrSignalResponse(BaseModel):
    id: str
    uid: str
    host_ip: str
    source_type: EdrSourceType
    signal: EdrSignalCode
    process_name: str
    detail: str | None
    observed_at: datetime


class TrafficAnalysisRunResponse(BaseModel):
    id: str
    asset_id: str
    source_id: str
    source_name: str
    coverage: TrafficCoverageResponse
    connection_count: int
    dns_count: int
    tls_count: int
    edr_count: int = 0
    alerts_count: int
    benign_rotations_count: int
    alerts: list[SuspiciousTrafficAlertResponse]
    tls_decisions: list[TrafficTlsDecisionResponse]
    edr_signals: list[TrafficEdrSignalResponse] = Field(default_factory=list)
    created_at: datetime
