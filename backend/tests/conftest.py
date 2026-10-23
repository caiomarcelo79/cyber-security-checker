"""Fixtures compartilhadas para os testes automatizados do Backend."""

from __future__ import annotations

from collections.abc import Generator
from contextlib import nullcontext

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base, get_db, get_stream_session_factory
from app.main import app


@pytest.fixture()
def db_session() -> Generator[Session, None, None]:
    """Cria um banco relacional isolado em memória para cada teste."""
    test_engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(bind=test_engine)
    TestingSessionLocal = sessionmaker(
        bind=test_engine, autoflush=False, autocommit=False, expire_on_commit=False
    )
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=test_engine)


@pytest.fixture()
def client(db_session: Session) -> Generator[TestClient, None, None]:
    """TestClient FastAPI com dependência de banco apontando para a sessão isolada do teste."""

    def _override_get_db() -> Generator[Session, None, None]:
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_stream_session_factory] = lambda: lambda: nullcontext(db_session)
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
