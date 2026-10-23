"""Tarefas assíncronas executadas pelos Workers Celery."""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from security_engine.core.registry import default_registry
from security_engine.policies.execution_policy import ScanExecutionPolicy

from workers.celery_app import celery_app

BACKEND_PATH = Path(__file__).resolve().parent.parent / "backend"
if str(BACKEND_PATH) not in sys.path:
    sys.path.insert(0, str(BACKEND_PATH))


@celery_app.task(name="workers.tasks.ping_worker")
def ping_worker() -> dict[str, Any]:
    """Tarefa de diagnóstico para confirmar prontidão do worker e carregamento do security-engine."""
    modules = default_registry.list_metadata(only_enabled=False)
    return {
        "status": "READY",
        "worker": "cyber_security_checker_worker",
        "loaded_modules_count": len(modules),
        "timestamp": datetime.now(UTC).isoformat(),
    }


@celery_app.task(name="workers.tasks.evaluate_snapshot_task")
def evaluate_snapshot_task(
    module_id: str,
    target_url: str,
    status_code: int,
    headers: dict[str, str],
) -> dict[str, Any]:
    """Executa de forma isolada a inspeção de um módulo do security-engine sobre um snapshot HTTP."""
    policy = ScanExecutionPolicy()
    module = default_registry.get_module(module_id)
    result = module.inspect_response_snapshot(
        target_url=target_url,
        status_code=status_code,
        headers=headers,
    )
    return {
        "module_id": result.module_id,
        "policy_applied_max_rps": policy.max_requests_per_second,
        "checks_count": len(result.checks),
        "findings_count": len(result.findings),
        "result": result.model_dump(mode="json"),
    }


@celery_app.task(
    name="workers.tasks.execute_scan_task",
    bind=True,
    max_retries=0,  # Política defensiva: não repete automaticamente auditorias sem verificação explícita
)
def execute_scan_task(self: Any, scan_id: str) -> dict[str, Any]:
    """Executa uma auditoria completa via ScanOrchestrator com persistência incremental e idempotência."""
    from app.core.database import SessionLocal
    from app.services.scan_orchestrator import ScanOrchestrator

    with SessionLocal() as db:
        scan = ScanOrchestrator.execute_scan_by_id(db=db, scan_id=scan_id)
        return {
            "scan_id": scan.id,
            "status": scan.status,
            "progress_percent": scan.progress_percent,
            "total_checks_run": scan.total_checks_run,
            "findings_summary": dict(scan.findings_summary or {}),
        }


@celery_app.task(name="workers.tasks.process_due_schedules_task")
def process_due_schedules_task() -> dict[str, Any]:
    """Processa periodicamente agendamentos vencidos e enfileira auditorias recorrentes."""
    from app.core.database import SessionLocal
    from app.services.scheduler_service import SchedulerService

    with SessionLocal() as db:
        dispatched = SchedulerService.trigger_due_schedules(db)
        return {
            "processed_at": datetime.now(UTC).isoformat(),
            "triggered_scans_count": len(dispatched),
            "dispatched": dispatched,
        }


