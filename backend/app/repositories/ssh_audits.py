"""Consultas de auditorias SSH vinculadas ao ativo."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.entities import SshAudit
from app.schemas.ssh_audits import PasswordAuthentication, PermitRootLogin


def find_latest_ssh_audit(db: Session, asset_id: str) -> SshAudit | None:
    return db.scalar(
        select(SshAudit)
        .where(SshAudit.asset_id == asset_id)
        .order_by(SshAudit.created_at.desc(), SshAudit.id.desc())
        .limit(1)
    )


def insert_ssh_audit(
    db: Session,
    asset_id: str,
    password_authentication: PasswordAuthentication,
    permit_root_login: PermitRootLogin | None,
) -> SshAudit:
    audit = SshAudit(
        asset_id=asset_id,
        password_authentication=password_authentication,
        permit_root_login=permit_root_login,
    )
    db.add(audit)
    db.flush()
    return audit
