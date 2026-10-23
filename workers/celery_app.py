"""Configuração da instância Celery conectada ao Redis e integrada ao security-engine."""

from __future__ import annotations

import os

from celery import Celery

BROKER_URL = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")
RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/1")

celery_app = Celery(
    "cyber_security_checker_worker",
    broker=BROKER_URL,
    backend=RESULT_BACKEND,
    include=["workers.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3660,
    task_soft_time_limit=3600,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    beat_schedule={
        "process-due-schedules-every-minute": {
            "task": "workers.tasks.process_due_schedules_task",
            "schedule": 60.0,
        },
    },
)
