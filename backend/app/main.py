"""Aplicação principal FastAPI do cyber-security-checker."""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.auth_assets_routes import router as auth_assets_router
from app.api.v1.automation_routes import router as automation_router
from app.api.v1.report_routes import router as report_router
from app.api.v1.routes import router as v1_router
from app.api.v1.scan_routes import router as scan_router
from app.core.config import get_settings
from app.core.logging import configure_logging


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncGenerator[None, None]:
    settings = get_settings()
    configure_logging(settings.log_level)
    problems = settings.validate_production_safety()
    if problems:
        raise RuntimeError("Configuração insegura para produção: " + " | ".join(problems))
    yield


def create_app() -> FastAPI:
    """Factory da aplicação FastAPI com cabeçalhos de segurança e rotas versionadas."""
    settings = get_settings()
    application = FastAPI(
        title="Cyber-Security-Checker API",
        description=(
            "API de gerenciamento de vulnerabilidades, validação de escopo, orquestração de auditorias "
            "e recomendações técnicas de correção."
        ),
        version=settings.app_version,
        lifespan=lifespan,
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )

    @application.middleware("http")
    async def security_headers_middleware(request: Request, call_next) -> Response:
        correlation_id = request.headers.get("X-Request-ID", "")[:64] or uuid.uuid4().hex
        response: Response = await call_next(request)
        response.headers["X-Request-ID"] = correlation_id
        if get_settings().is_production:
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        if request.url.path.startswith("/api/"):
            response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Cache-Control"] = "no-store"
        return response

    application.include_router(v1_router)
    application.include_router(auth_assets_router)
    application.include_router(scan_router)
    application.include_router(report_router)
    application.include_router(automation_router)
    return application


app = create_app()
