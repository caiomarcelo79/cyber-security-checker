"""Testes das tarefas assíncronas dos Workers Celery integradas ao security-engine (TM-008)."""

from workers.tasks import evaluate_snapshot_task, ping_worker, process_due_schedules_task


def test_worker_ping_and_snapshot_evaluation_tasks() -> None:
    ping_res = ping_worker()
    assert ping_res["status"] == "READY"
    assert ping_res["loaded_modules_count"] == 8

    eval_res = evaluate_snapshot_task(
        module_id="mod_a_recon_headers_tls",
        target_url="https://lab-target.internal/app",
        status_code=200,
        headers={"Server": "Apache/2.4.49"},
    )
    assert eval_res["module_id"] == "mod_a_recon_headers_tls"
    assert eval_res["checks_count"] >= 5
    assert eval_res["findings_count"] >= 4


def test_process_due_schedules_periodic_task() -> None:
    res = process_due_schedules_task()
    assert "processed_at" in res
    assert "triggered_scans_count" in res
    assert isinstance(res["dispatched"], list)


