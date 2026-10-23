"""Gerenciamento de conexão SQLAlchemy 2.0, sessões e diagnóstico do banco de dados."""

from __future__ import annotations

import time
from collections.abc import Generator
from typing import Any

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import get_settings


class Base(DeclarativeBase):
    """Classe base declarativa do SQLAlchemy 2.0 para todas as entidades ORM."""


def build_engine(database_url: str | None = None) -> Engine:
    """Cria engine SQLAlchemy compatível com PostgreSQL (produção/docker) ou SQLite (testes locais)."""
    settings = get_settings()
    url = database_url or settings.database_url
    connect_args: dict[str, Any] = {}
    if url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
        return create_engine(url, connect_args=connect_args, future=True)
    return create_engine(
        url,
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=10,
        future=True,
    )


engine = build_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


def get_db() -> Generator[Session, None, None]:
    """Dependência FastAPI que fornece uma sessão transacional isolada por requisição."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def check_database_health(db: Session) -> dict[str, Any]:
    """Executa uma consulta leve ('SELECT 1') para aferir conectividade e latência do banco."""
    started = time.perf_counter()
    try:
        db.execute(text("SELECT 1"))
        latency_ms = round((time.perf_counter() - started) * 1000, 2)
        return {
            "status": "UP",
            "latency_ms": latency_ms,
            "dialect": db.bind.dialect.name if db.bind is not None else "unknown",
        }
    except SQLAlchemyError as exc:
        latency_ms = round((time.perf_counter() - started) * 1000, 2)
        return {
            "status": "DOWN",
            "latency_ms": latency_ms,
            "error": str(exc),
        }


def get_stream_session_factory() -> sessionmaker[Session]:
    """Fábrica de sessões independentes para fluxos SSE de longa duração (sobrescrevível em testes)."""
    return SessionLocal
