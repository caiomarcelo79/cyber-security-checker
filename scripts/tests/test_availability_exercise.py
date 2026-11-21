"""Testes locais do servidor de laboratório, medição de latência e fluxo probe."""

import argparse
import io
import os
import sys
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch
from uuid import UUID

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from _local_api import local_api_opener
from availability_exercise import (
    make_server,
    measure,
    run_probe,
    scripted_delay_ms,
    scripted_response,
)


def make_probe_args(
    target_url: str,
    *,
    normal_ms: int = 1000,
    degraded_ms: int = 1500,
    scenario: str = "LATENCY",
    edge_source: str | None = None,
) -> argparse.Namespace:
    return argparse.Namespace(
        api_url="http://127.0.0.1:8000",
        asset_id=UUID("11111111-1111-1111-1111-111111111111"),
        target_url=target_url,
        threshold_ms=200,
        consecutive_samples=3,
        interval_ms=500,
        normal_ms=normal_ms,
        degraded_ms=degraded_ms,
        scenario=scenario,
        edge_source=edge_source,
    )


class ScriptedDelayTest(unittest.TestCase):
    def test_delay_only_inside_degraded_window(self) -> None:
        self.assertEqual(scripted_delay_ms(0, 1000, 2000, 800), 0)
        self.assertEqual(scripted_delay_ms(999, 1000, 2000, 800), 0)
        self.assertEqual(scripted_delay_ms(1000, 1000, 2000, 800), 800)
        self.assertEqual(scripted_delay_ms(2999, 1000, 2000, 800), 800)
        self.assertEqual(scripted_delay_ms(3000, 1000, 2000, 800), 0)

    def test_scripted_response_scenarios(self) -> None:
        self.assertEqual(scripted_response(1500, 1000, 2000, 400, "LATENCY"), (400, 200))
        self.assertEqual(scripted_response(1500, 1000, 2000, 400, "ERRORS"), (0, 503))
        self.assertEqual(scripted_response(1500, 1000, 2000, 400, "SATURATION"), (400, 429))
        self.assertEqual(scripted_response(3500, 1000, 2000, 400, "SATURATION"), (0, 200))


class LabServerTest(unittest.TestCase):
    def test_probe_measures_real_latency(self) -> None:
        server = make_server("127.0.0.1", 0, normal_ms=0, degraded_ms=60_000, degraded_delay_ms=300)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        opener = local_api_opener()
        try:
            slow = measure(opener, f"http://127.0.0.1:{port}/")
            self.assertEqual(slow["outcome"], "OK")
            self.assertEqual(slow["http_status"], 200)
            self.assertGreaterEqual(slow["latency_ms"], 290)
        finally:
            server.shutdown()
            server.server_close()

    def test_normal_phase_is_fast(self) -> None:
        server = make_server("127.0.0.1", 0, normal_ms=60_000, degraded_ms=1000, degraded_delay_ms=300)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            fast = measure(local_api_opener(), f"http://127.0.0.1:{server.server_address[1]}/")
            self.assertEqual(fast["outcome"], "OK")
            self.assertLess(fast["latency_ms"], 250)
        finally:
            server.shutdown()
            server.server_close()


class RunProbeTest(unittest.TestCase):
    def test_requires_session_token(self) -> None:
        args = make_probe_args("http://127.0.0.1:8081/")
        with patch.dict(os.environ, {"CSC_SESSION_TOKEN": ""}), redirect_stderr(io.StringIO()):
            code = run_probe(args)
        self.assertEqual(code, 2)

    def test_rejects_mismatched_hostname_and_finishes_exercise(self) -> None:
        calls: list[tuple[str, dict | None]] = []

        def fake_api_call(_opener, url: str, _headers: dict[str, str], body: dict | None = None) -> dict:
            calls.append((url, body))
            if url.endswith("/availability-exercises"):
                return {
                    "id": "ex-mismatch",
                    "hostname": "lab-target",
                    "interval_ms": 500,
                    "planned_duration_ms": 3000,
                }
            return {"status": "FINISHED"}

        args = make_probe_args("http://127.0.0.1:8081/")
        with (
            patch.dict(os.environ, {"CSC_SESSION_TOKEN": "token-ok"}),
            patch("availability_exercise.api_call", side_effect=fake_api_call),
            redirect_stderr(io.StringIO()),
        ):
            code = run_probe(args)

        self.assertEqual(code, 1)
        self.assertEqual(len(calls), 2)
        self.assertTrue(calls[1][0].endswith("/availability-exercises/ex-mismatch/finish"))

    def test_full_probe_cycle_against_lab_server(self) -> None:
        server = make_server("127.0.0.1", 0, normal_ms=1000, degraded_ms=1500, degraded_delay_ms=350)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        port = server.server_address[1]
        samples: list[dict] = []

        def fake_api_call(_opener, url: str, _headers: dict[str, str], body: dict | None = None) -> dict:
            if url.endswith("/availability-exercises"):
                return {
                    "id": "ex-full",
                    "hostname": "127.0.0.1",
                    "interval_ms": 500,
                    "planned_duration_ms": 5000,
                }
            if url.endswith("/samples"):
                assert body is not None
                samples.append(body)
                return {"state": "NORMAL"}
            if url.endswith("/finish"):
                return {
                    "result": "PASSED",
                    "timeline": [
                        {
                            "event": "DEGRADATION_START",
                            "expected_offset_ms": 1000,
                            "observed_offset_ms": 1000,
                            "delta_ms": 0,
                        },
                        {
                            "event": "ALERT_OPENED",
                            "expected_offset_ms": 2500,
                            "observed_offset_ms": 2000,
                            "delta_ms": -500,
                        },
                        {
                            "event": "RECOVERY_START",
                            "expected_offset_ms": 2500,
                            "observed_offset_ms": 2500,
                            "delta_ms": 0,
                        },
                        {
                            "event": "RECOVERY_DETECTED",
                            "expected_offset_ms": 4000,
                            "observed_offset_ms": 3500,
                            "delta_ms": -500,
                        },
                    ],
                    "alert_publication_ms": 5,
                    "recovery_publication_ms": 4,
                }
            raise AssertionError(f"URL inesperada: {url}")

        args = make_probe_args(f"http://127.0.0.1:{port}/")
        try:
            with (
                patch.dict(os.environ, {"CSC_SESSION_TOKEN": "token-ok"}),
                patch("availability_exercise.api_call", side_effect=fake_api_call),
                redirect_stdout(io.StringIO()),
            ):
                code = run_probe(args)
        finally:
            server.shutdown()
            server.server_close()

        self.assertEqual(code, 0)
        self.assertGreaterEqual(len(samples), 8)
        self.assertEqual([s["seq"] for s in samples], list(range(len(samples))))
        self.assertTrue(all(s["outcome"] == "OK" and s["http_status"] == 200 for s in samples))
        self.assertTrue(any(s["latency_ms"] >= 300 for s in samples))
        self.assertTrue(any(s["latency_ms"] < 200 for s in samples))

    def test_saturation_server_and_edge_signals(self) -> None:
        err_server = make_server("127.0.0.1", 0, normal_ms=0, degraded_ms=60_000, degraded_delay_ms=0, scenario="ERRORS")
        threading.Thread(target=err_server.serve_forever, daemon=True).start()
        try:
            err_sample = measure(local_api_opener(), f"http://127.0.0.1:{err_server.server_address[1]}/")
            self.assertEqual(err_sample["outcome"], "OK")
            self.assertEqual(err_sample["http_status"], 503)
        finally:
            err_server.shutdown()
            err_server.server_close()

        sat_server = make_server(
            "127.0.0.1", 0, normal_ms=1000, degraded_ms=1500, degraded_delay_ms=250, scenario="SATURATION"
        )
        threading.Thread(target=sat_server.serve_forever, daemon=True).start()
        port = sat_server.server_address[1]
        samples: list[dict] = []
        signals: list[dict] = []

        def fake_api_call(_opener, url: str, _headers: dict[str, str], body: dict | None = None) -> dict:
            if url.endswith("/availability-exercises"):
                self.assertEqual(body["scenario"], "SATURATION")
                return {
                    "id": "ex-sat",
                    "hostname": "127.0.0.1",
                    "interval_ms": 500,
                    "planned_duration_ms": 5000,
                }
            if url.endswith("/samples"):
                assert body is not None
                samples.append(body)
                return {"state": "RECOVERED" if body["seq"] >= 7 else "NORMAL"}
            if url.endswith("/signals"):
                assert body is not None
                signals.append(body)
                return {"id": "ex-sat"}
            if url.endswith("/finish"):
                return {
                    "result": "PASSED",
                    "timeline": [],
                    "alert_publication_ms": 5,
                    "recovery_publication_ms": 4,
                }
            raise AssertionError(f"URL inesperada: {url}")

        args = make_probe_args(f"http://127.0.0.1:{port}/", scenario="SATURATION", edge_source="CDN")
        try:
            with (
                patch.dict(os.environ, {"CSC_SESSION_TOKEN": "token-ok"}),
                patch("availability_exercise.api_call", side_effect=fake_api_call),
                redirect_stdout(io.StringIO()),
            ):
                code = run_probe(args)
        finally:
            sat_server.shutdown()
            sat_server.server_close()

        self.assertEqual(code, 0)
        self.assertTrue(any(s["http_status"] == 429 for s in samples))
        self.assertEqual([(s["source_type"], s["signal"]) for s in signals], [("CDN", "RATE_LIMITED"), ("CDN", "RECOVERED")])


if __name__ == "__main__":
    unittest.main()
