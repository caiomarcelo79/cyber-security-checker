"""Testes para a CLI operacional scripts/pilot_lifecycle.py (Fase 6)."""

from __future__ import annotations

import io
import os
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pilot_lifecycle


class PilotLifecycleCliTests(unittest.TestCase):
    def test_heartbeat_subcommand_confirms_version_and_config(self) -> None:
        source_id = str(uuid4())

        class StubCollectorApi:
            def __init__(self, api_url: str, sid: object, token: str) -> None:
                self.api_url = api_url
                self.sid = sid
                self.token = token

            def status(self) -> dict:
                return {"network": "192.168.50.0/24", "config_version": 3}

            def heartbeat(
                self, collector_version: str = "1.1.0", applied_config_version: int | None = None
            ) -> dict:
                return {
                    "id": str(self.sid),
                    "network": "192.168.50.0/24",
                    "status": "ACTIVE",
                    "collector_version": collector_version,
                    "applied_config_version": applied_config_version,
                    "update_status": "UP_TO_DATE",
                }

        buf = io.StringIO()
        with (
            patch.dict(os.environ, {"CSC_COLLECTOR_TOKEN": "csc_sensor_test"}, clear=False),
            patch.object(pilot_lifecycle, "CollectorApi", StubCollectorApi),
            patch.object(
                sys,
                "argv",
                [
                    "pilot_lifecycle.py",
                    "heartbeat",
                    "--api-url",
                    "http://127.0.0.1:8000",
                    "--source-id",
                    source_id,
                    "--collector-version",
                    "1.1.0",
                ],
            ),
            redirect_stdout(buf),
        ):
            rc = pilot_lifecycle.main()
        self.assertEqual(rc, 0)
        output = buf.getvalue()
        self.assertIn("config_v=3", output)
        self.assertIn("update_status=UP_TO_DATE", output)

    def test_readiness_subcommand_prints_checklist_and_blocking_reasons(self) -> None:
        pilot_id = str(uuid4())

        class StubPilotSessionApi:
            def __init__(self, api_url: str, token: str) -> None:
                self.api_url = api_url
                self.token = token

            def get_readiness(self, pid: object) -> dict:
                return {
                    "pilot_id": str(pid),
                    "stage": "OWN_ENVIRONMENT",
                    "status": "ACTIVE",
                    "lifecycle": {
                        "installation_demonstrated": True,
                        "pause_resume_demonstrated": True,
                        "update_demonstrated": True,
                        "revocation_demonstrated": True,
                        "recovery_demonstrated": True,
                        "all_demonstrated": True,
                    },
                    "coverage": {
                        "observed_layers": ["CONNECTIONS", "DNS", "TLS", "EDR"],
                        "layer_coverage_percent": 100.0,
                        "active_sources": 1,
                        "total_sources": 1,
                    },
                    "latency": {
                        "telemetry_samples_count": 4,
                        "telemetry_avg_delay_seconds": 1.25,
                        "availability_alert_pub_avg_ms": 14.0,
                    },
                    "false_positives": {
                        "suspicious_alerts_total": 1,
                        "benign_tls_rotations_ignored": 1,
                        "findings_false_positive_rate_percent": 0.0,
                    },
                    "blocking_reasons": [],
                    "ready_for_expansion_approval": True,
                }

        buf = io.StringIO()
        with (
            patch.dict(os.environ, {"CSC_SESSION_TOKEN": "jwt-test"}, clear=False),
            patch.object(pilot_lifecycle, "PilotSessionApi", StubPilotSessionApi),
            patch.object(
                sys,
                "argv",
                [
                    "pilot_lifecycle.py",
                    "readiness",
                    "--api-url",
                    "http://127.0.0.1:8000",
                    "--pilot-id",
                    pilot_id,
                ],
            ),
            redirect_stdout(buf),
        ):
            rc = pilot_lifecycle.main()
        self.assertEqual(rc, 0)
        output = buf.getvalue()
        self.assertIn("[OK] Recuperacao", output)
        self.assertIn("camadas=CONNECTIONS,DNS,TLS,EDR (100.0%)", output)
        self.assertIn("Pronto para revisao de expansao: SIM", output)

    def test_missing_tokens_return_exit_code_2(self) -> None:
        env_clean = {
            k: v
            for k, v in os.environ.items()
            if k not in {"CSC_COLLECTOR_TOKEN", "CSC_SESSION_TOKEN"}
        }
        with (
            patch.dict(os.environ, env_clean, clear=True),
            patch.object(
                sys,
                "argv",
                [
                    "pilot_lifecycle.py",
                    "readiness",
                    "--api-url",
                    "http://127.0.0.1:8000",
                    "--pilot-id",
                    str(uuid4()),
                ],
            ),
        ):
            rc = pilot_lifecycle.main()
        self.assertEqual(rc, 2)
