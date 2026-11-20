"""Contrato de evidência estruturada para auditorias SSH locais."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from security_engine.core.contracts import CheckStatus

PasswordAuthentication = Literal["enabled", "disabled", "unknown", "collection_error"]
PermitRootLogin = Literal[
    "yes", "no", "prohibit-password", "forced-commands-only", "unknown", "collection_error"
]


class SshAuditCollection(BaseModel):
    hostname: str


class SshAuditCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hostname: str = Field(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9.-]+$")
    password_authentication: PasswordAuthentication
    permit_root_login: PermitRootLogin | None = None


class SshAuditResponse(BaseModel):
    id: str
    status: CheckStatus
    password_authentication: PasswordAuthentication
    permit_root_login: PermitRootLogin | None
    permit_root_login_status: CheckStatus | None
    created_at: datetime


class SshAlertExerciseResponse(BaseModel):
    notification_id: str
    channel: Literal["in_app"] = "in_app"
    publication_ms: int
