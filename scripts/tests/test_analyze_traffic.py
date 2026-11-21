"""Testes locais para a CLI de análise explicável de tráfego (scripts/analyze_traffic.py)."""

from __future__ import annotations

import json
import os
import sys
import threading
import unittest
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import analyze_traffic


def _jsonl(path: Path, records: list[dict]) -> Path:
    content = "\n".join(json.dumps(item) for item in records) + "\n"
    path.write_text(content, encoding="utf-8")
    return path


class AnalyzeTrafficTests(unittest.TestCase):
    def test_parses_zeek_dns_and_ssl_lines_including_cert_chain_fps(self) -> None:
        fp = sha256(b"cert").hexdigest()
        dns_line = json.dumps(
            {
                "ts": 1795172400.5,
                "uid": "CDns1",
                "id.orig_h": "192.168.50.10",
                "id.resp_h": "192.168.50.2",
                "query": "missing.lab.internal",
                "qtype_name": "A",
                "rcode": 3,
            }
        ).encode("utf-8")
        dns = analyze_traffic.dns_metadata_from_line(dns_line)
        self.assertEqual(dns["rcode"], "NXDOMAIN")
        self.assertEqual(dns["qtype"], "A")

        ssl_line = json.dumps(
            {
                "ts": 1795172401.0,
                "uid": "CTls1",
                "id.orig_h": "192.168.50.10",
                "id.resp_h": "198.51.100.30",
                "id.resp_p": 443,
                "server_name": "api.lab.internal",
                "cert_chain_fps": [fp],
                "subject": "CN=api.lab.internal",
                "issuer": "CN=R10, O=Let's Encrypt, C=US",
                "validation_status": "ok",
                "not_before": 1795000000,
                "not_after": 1802000000,
            }
        ).encode("utf-8")
        ssl = analyze_traffic.ssl_metadata_from_line(ssl_line)
        self.assertEqual(ssl["cert_sha256"], fp)
        self.assertFalse(ssl["self_signed"])

        edr_line = json.dumps(
            {
                "ts": 1795172401.5,
                "uid": "CEdr1",
                "host_ip": "192.168.50.10",
                "source_type": "edr",
                "signal": "beaconing_detected",
                "process_name": "python3",
                "detail": "Conexao periodica para C2",
            }
        ).encode("utf-8")
        edr = analyze_traffic.edr_metadata_from_line(edr_line)
        self.assertEqual(edr["source_type"], "EDR")
        self.assertEqual(edr["signal"], "BEACONING_DETECTED")
        self.assertEqual(edr["process_name"], "python3")

        with self.assertRaises(ValueError):
            analyze_traffic.edr_metadata_from_line(
                json.dumps(
                    {
                        "ts": 1795172401.5,
                        "uid": "CEdrBad",
                        "host_ip": "192.168.50.10",
                        "source_type": "SIEM",
                        "signal": "BEACONING_DETECTED",
                        "process_name": "python3",
                    }
                ).encode("utf-8")
            )

    def test_rejects_oversized_line_invalid_sha256_and_batch_limit(self) -> None:
        with TemporaryDirectory() as tmp:
            folder = Path(tmp)
            bad_ssl = _jsonl(
                folder / "ssl.log",
                [
                    {
                        "ts": 1795172401.0,
                        "uid": "Bad1",
                        "id.orig_h": "192.168.50.10",
                        "id.resp_h": "198.51.100.30",
                        "id.resp_p": 443,
                        "server_name": "api.lab.internal",
                        "cert_sha256": "invalid-sha",
                        "subject": "CN=api",
                        "issuer": "CN=CA",
                        "validation_status": "ok",
                        "not_before": 1795000000,
                        "not_after": 1802000000,
                    }
                ],
            )
            with self.assertRaises(ValueError):
                analyze_traffic.read_jsonl_events(
                    bad_ssl, analyze_traffic.ssl_metadata_from_line, label="ssl.log", limit=10
                )

            many_dns = _jsonl(
                folder / "dns.log",
                [
                    {
                        "ts": 1795172400.0 + idx,
                        "uid": f"D{idx}",
                        "id.orig_h": "192.168.50.10",
                        "id.resp_h": "192.168.50.2",
                        "query": "a.lab.internal",
                        "rcode_name": "NOERROR",
                    }
                    for idx in range(5)
                ],
            )
            with self.assertRaises(ValueError):
                analyze_traffic.read_jsonl_events(
                    many_dns, analyze_traffic.dns_metadata_from_line, label="dns.log", limit=4
                )

    def test_cli_submits_logs_to_api_and_prints_explanation_and_coverage(self) -> None:
        received: list[dict] = []
        fp = sha256(b"trusted").hexdigest()
        source_id = "11111111-1111-4111-8111-111111111111"

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                received.append(json.loads(self.rfile.read(length).decode("utf-8")))
                response = json.dumps(
                    {
                        "id": "run-1",
                        "asset_id": "asset-1",
                        "source_id": source_id,
                        "source_name": "Zeek Lab",
                        "coverage": {
                            "observed_layers": ["CONNECTIONS", "DNS", "TLS", "EDR"],
                            "missing_layers": [],
                        },
                        "connection_count": 1,
                        "dns_count": 1,
                        "tls_count": 1,
                        "edr_count": 1,
                        "alerts_count": 1,
                        "benign_rotations_count": 1,
                        "edr_signals": [
                            {
                                "id": "edr-1",
                                "uid": "CEdr1",
                                "host_ip": "192.168.50.10",
                                "source_type": "EDR",
                                "signal": "BEACONING_DETECTED",
                                "process_name": "python3",
                                "detail": "Beaconing",
                                "observed_at": "2026-11-20T12:00:00Z",
                            }
                        ],
                        "tls_decisions": [
                            {
                                "id": "dec-1",
                                "uid": "CTls1",
                                "server_name": "api.lab.internal",
                                "responder_ip": "198.51.100.30",
                                "responder_port": 443,
                                "outcome": "BENIGN_ROTATION",
                                "observed_cert_sha256": fp,
                                "previous_cert_sha256": sha256(b"old").hexdigest(),
                                "observed_issuer": "O=Let's Encrypt",
                                "previous_issuer": "O=Let's Encrypt",
                                "reason": "valid_renewal_same_ca",
                                "observed_at": "2026-11-20T12:00:00Z",
                            }
                        ],
                        "alerts": [
                            {
                                "id": "alert-1",
                                "rule_id": "DNS_NXDOMAIN_BURST",
                                "category": "DNS",
                                "severity": "MEDIUM",
                                "confidence": "MEDIUM",
                                "title": "Rajada NXDOMAIN",
                                "explanation": "4 consultas NXDOMAIN em sequência.",
                                "evidence": {"client_ip": "192.168.50.10", "nxdomain_count": 4},
                                "observed_layers": ["CONNECTIONS", "DNS", "TLS"],
                                "missing_layers": [],
                                "created_at": "2026-11-20T12:00:01Z",
                            }
                        ],
                        "created_at": "2026-11-20T12:00:01Z",
                    }
                ).encode("utf-8")
                self.send_response(201)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

            def log_message(self, format: str, *args: object) -> None:
                return

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(lambda: (server.shutdown(), server.server_close()))

        with TemporaryDirectory() as tmp:
            folder = Path(tmp)
            conn_log = _jsonl(
                folder / "conn.log",
                [
                    {
                        "ts": 1795172400.0,
                        "uid": "CConn1",
                        "id.orig_h": "192.168.50.10",
                        "id.orig_p": 50000,
                        "id.resp_h": "198.51.100.30",
                        "id.resp_p": 443,
                        "proto": "tcp",
                    }
                ],
            )
            dns_log = _jsonl(
                folder / "dns.log",
                [
                    {
                        "ts": 1795172400.0,
                        "uid": "CDns1",
                        "id.orig_h": "192.168.50.10",
                        "id.resp_h": "192.168.50.2",
                        "query": "miss.lab.internal",
                        "qtype_name": "A",
                        "rcode_name": "NXDOMAIN",
                    }
                ],
            )
            ssl_log = _jsonl(
                folder / "ssl.log",
                [
                    {
                        "ts": 1795172400.0,
                        "uid": "CTls1",
                        "id.orig_h": "192.168.50.10",
                        "id.resp_h": "198.51.100.30",
                        "id.resp_p": 443,
                        "server_name": "api.lab.internal",
                        "cert_sha256": fp,
                        "subject": "CN=api.lab.internal",
                        "issuer": "O=Let's Encrypt",
                        "validation_status": "ok",
                        "self_signed": False,
                        "not_before": "2026-11-10T00:00:00+00:00",
                        "not_after": "2027-02-01T00:00:00+00:00",
                    }
                ],
            )
            edr_log = _jsonl(
                folder / "edr.log",
                [
                    {
                        "ts": 1795172400.0,
                        "uid": "CEdr1",
                        "host_ip": "192.168.50.10",
                        "source_type": "EDR",
                        "signal": "BEACONING_DETECTED",
                        "process_name": "python3",
                    }
                ],
            )
            argv = [
                "analyze_traffic.py",
                "--api-url",
                f"http://127.0.0.1:{server.server_port}",
                "--source-id",
                source_id,
                "--conn-log",
                str(conn_log),
                "--dns-log",
                str(dns_log),
                "--ssl-log",
                str(ssl_log),
                "--edr-log",
                str(edr_log),
            ]
            with (
                patch.dict(os.environ, {"CSC_COLLECTOR_TOKEN": "csc_sensor_" + "a" * 43}),
                patch.object(sys, "argv", argv),
            ):
                exit_code = analyze_traffic.main()

        self.assertEqual(exit_code, 0)
        self.assertEqual(len(received), 1)
        self.assertEqual(len(received[0]["connections"]), 1)
        self.assertEqual(len(received[0]["dns_queries"]), 1)
        self.assertEqual(len(received[0]["tls_handshakes"]), 1)
        self.assertEqual(len(received[0]["edr_signals"]), 1)


if __name__ == "__main__":
    unittest.main()
