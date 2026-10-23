"""Serviço de diagnóstico da plataforma, verificação de subsistemas e consulta ao security-engine."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any

import redis
from security_engine.adapters.base import OwaspZapOptionalAdapter
from security_engine.core.registry import default_registry
from security_engine.policies.execution_policy import get_scan_profiles
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import check_database_health
from app.repositories.metrics_repo import MetricsRepository
from app.schemas.system import ComponentHealth, SystemStatusResponse


class SystemService:
    """Fornece diagnósticos técnicos reais dos componentes da plataforma."""

    @staticmethod
    def check_redis_health(redis_url: str | None = None) -> ComponentHealth:
        settings = get_settings()
        url = redis_url or settings.redis_url
        started = time.perf_counter()
        try:
            client = redis.Redis.from_url(
                url,
                socket_connect_timeout=1.5,
                socket_timeout=1.5,
                decode_responses=True,
            )
            pong = client.ping()
            latency_ms = round((time.perf_counter() - started) * 1000, 2)
            client.close()
            return ComponentHealth(
                name="Redis Broker & Cache",
                status="UP" if pong else "DEGRADED",
                latency_ms=latency_ms,
                details={"broker_configured": True},
            )
        except (redis.RedisError, OSError, ValueError) as exc:
            latency_ms = round((time.perf_counter() - started) * 1000, 2)
            return ComponentHealth(
                name="Redis Broker & Cache",
                status="DOWN",
                latency_ms=latency_ms,
                details={"error": str(exc)},
            )

    @staticmethod
    def check_security_engine_health() -> ComponentHealth:
        started = time.perf_counter()
        modules = default_registry.list_metadata(only_enabled=False)
        enabled_modules = default_registry.list_metadata(only_enabled=True)
        profiles = get_scan_profiles()
        zap_adapter = OwaspZapOptionalAdapter().check_availability()
        latency_ms = round((time.perf_counter() - started) * 1000, 2)
        return ComponentHealth(
            name="Security Engine & Plugin Registry",
            status="UP" if len(modules) >= 8 else "DEGRADED",
            latency_ms=latency_ms,
            details={
                "total_modules": len(modules),
                "enabled_modules": len(enabled_modules),
                "scan_profiles": len(profiles),
                "optional_adapters": [
                    {
                        "id": zap_adapter.adapter_id,
                        "name": zap_adapter.name,
                        "optional": zap_adapter.optional,
                        "available": zap_adapter.available,
                    }
                ],
            },
        )

    @classmethod
    def get_system_status(
        cls,
        db: Session,
        skip_external_redis: bool = False,
        organization_id: str | None = None,
    ) -> SystemStatusResponse:
        settings = get_settings()
        db_info = check_database_health(db)
        db_health = ComponentHealth(
            name="PostgreSQL Database",
            status=db_info["status"],
            latency_ms=db_info.get("latency_ms"),
            details={k: v for k, v in db_info.items() if k not in {"status", "latency_ms"}},
        )

        if skip_external_redis:
            redis_health = ComponentHealth(
                name="Redis Broker & Cache",
                status="UP",
                latency_ms=0.5,
                details={"mode": "local_test_bypass"},
            )
        else:
            redis_health = cls.check_redis_health()

        engine_health = cls.check_security_engine_health()
        metrics = MetricsRepository.get_platform_metrics(db, organization_id=organization_id)

        overall_status = "UP"
        if db_health.status == "DOWN" or engine_health.status == "DOWN":
            overall_status = "DEGRADED"

        return SystemStatusResponse(
            status=overall_status,
            app_name=settings.app_name,
            version=settings.app_version,
            environment=settings.app_env,
            current_phase="FASE 4 — Dashboard SOC, Triagem de Vulnerabilidades e Base de Correção",
            timestamp=datetime.now(UTC),
            components={
                "database": db_health,
                "redis": redis_health,
                "security_engine": engine_health,
            },
            registered_modules_count=len(default_registry.list_metadata(only_enabled=False)),
            available_profiles_count=len(get_scan_profiles()),
            metrics=metrics,
        )

    @staticmethod
    def list_modules_catalog() -> list[dict[str, Any]]:
        modules = default_registry.list_metadata(only_enabled=False)
        return [m.model_dump() for m in modules]

    @staticmethod
    def list_profiles_catalog() -> list[dict[str, Any]]:
        profiles = get_scan_profiles()
        return [p.model_dump() for p in profiles]
