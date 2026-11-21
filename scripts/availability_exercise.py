"""Servidor de laboratório e sonda do exercício de disponibilidade.

Subcomandos:
  serve  Servidor HTTP com roteiro determinístico de atraso (normal → degradado → normal).
         O relógio do roteiro começa na primeira requisição recebida.
  probe  Mede a latência real do servidor no hostname do ativo autorizado e envia cada
         amostra à API, que avalia o limiar e publica os alertas.

Nenhuma carga é gerada: a sonda faz uma requisição GET por intervalo (mínimo de 500 ms).
"""

import argparse
import json
import os
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request
from uuid import UUID

from _local_api import api_base_url, local_api_opener

PROBE_TIMEOUT_S = 2.0
SCENARIOS = ("LATENCY", "ERRORS", "SATURATION")
EDGE_SOURCES = ("FIREWALL", "CDN", "PROVIDER")


def scripted_response(
    elapsed_ms: float,
    normal_ms: int,
    degraded_ms: int,
    degraded_delay_ms: int,
    scenario: str = "LATENCY",
) -> tuple[int, int]:
    """Retorna (atraso_ms, http_status) imposto pelo roteiro no instante informado."""
    if not (normal_ms <= elapsed_ms < normal_ms + degraded_ms):
        return 0, 200
    if scenario == "ERRORS":
        return 0, 503
    if scenario == "SATURATION":
        return degraded_delay_ms, 429
    return degraded_delay_ms, 200


def scripted_delay_ms(elapsed_ms: float, normal_ms: int, degraded_ms: int, degraded_delay_ms: int) -> int:
    """Atraso imposto pelo roteiro no instante informado (ms desde a primeira requisição)."""
    return scripted_response(elapsed_ms, normal_ms, degraded_ms, degraded_delay_ms)[0]


def make_server(
    host: str,
    port: int,
    normal_ms: int,
    degraded_ms: int,
    degraded_delay_ms: int,
    scenario: str = "LATENCY",
) -> ThreadingHTTPServer:
    clock: dict[str, float] = {}
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            with lock:
                started = clock.setdefault("start", time.monotonic())
            elapsed_ms = (time.monotonic() - started) * 1000
            delay, status = scripted_response(
                elapsed_ms, normal_ms, degraded_ms, degraded_delay_ms, scenario
            )
            if delay:
                time.sleep(delay / 1000)
            body = b"ok" if status == 200 else f"degraded:{status}".encode("ascii")
            self.send_response(status)
            self.send_header("Content-Type", "text/plain")
            if status == 429:
                self.send_header("Retry-After", "1")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            return

    return ThreadingHTTPServer((host, port), Handler)


def measure(opener, url: str) -> dict[str, object]:
    started = time.perf_counter()
    try:
        with opener.open(Request(url), timeout=PROBE_TIMEOUT_S) as response:
            response.read(1024)
            status = response.status
    except HTTPError as exc:
        try:
            exc.read(1024)
        finally:
            exc.close()
        status = exc.code
    except TimeoutError:
        return {"latency_ms": None, "outcome": "TIMEOUT", "http_status": None}
    except (URLError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        outcome = "TIMEOUT" if isinstance(reason, (TimeoutError, socket.timeout)) else "CONNECTION_ERROR"
        return {"latency_ms": None, "outcome": outcome, "http_status": None}
    latency = round((time.perf_counter() - started) * 1000, 1)
    return {"latency_ms": latency, "outcome": "OK", "http_status": status}


def api_call(opener, url: str, headers: dict[str, str], body: dict | None = None) -> dict:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = Request(url, headers=headers, data=data, method="POST")
    with opener.open(request, timeout=10) as response:
        return json.load(response)


def run_probe(args: argparse.Namespace) -> int:
    token = os.environ.get("CSC_SESSION_TOKEN", "").strip()
    if not token:
        print("Defina CSC_SESSION_TOKEN com um token de sessão válido.", file=sys.stderr)
        return 2
    target = urlsplit(args.target_url)
    if target.scheme not in {"http", "https"} or not target.hostname or target.username or target.password:
        print("Informe uma URL de alvo http(s) sem credenciais.", file=sys.stderr)
        return 2

    scenario = getattr(args, "scenario", "LATENCY")
    edge_source = getattr(args, "edge_source", None)
    endpoint = f"{args.api_url}/api/v1/assets/{args.asset_id}/availability-exercises"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    opener = local_api_opener()
    exercise_id = None
    try:
        exercise = api_call(
            opener,
            endpoint,
            headers,
            {
                "scenario": scenario,
                "threshold_ms": args.threshold_ms,
                "consecutive_samples": args.consecutive_samples,
                "interval_ms": args.interval_ms,
                "normal_ms": args.normal_ms,
                "degraded_ms": args.degraded_ms,
            },
        )
        exercise_id = exercise["id"]
        if target.hostname.lower() != exercise["hostname"].lower():
            print("O alvo deve usar o hostname do ativo autorizado.", file=sys.stderr)
            api_call(opener, f"{endpoint}/{exercise_id}/finish", headers)
            return 1

        interval_s = exercise["interval_ms"] / 1000
        planned_ms = exercise["planned_duration_ms"]
        origin = time.monotonic()
        seq = 0
        degraded_signal_sent = False
        recovered_signal_sent = False
        while True:
            offset_ms = int((time.monotonic() - origin) * 1000)
            sample = {"seq": seq, "offset_ms": offset_ms, **measure(opener, args.target_url)}
            state = api_call(opener, f"{endpoint}/{exercise_id}/samples", headers, sample)
            http_status = sample["http_status"]
            latency_ms = sample["latency_ms"]
            is_bad = (
                sample["outcome"] != "OK"
                or (isinstance(http_status, int) and (http_status >= 500 or http_status == 429))
                or (isinstance(latency_ms, (int, float)) and latency_ms > args.threshold_ms)
            )
            if edge_source and is_bad and not degraded_signal_sent:
                signal_code = (
                    "UPSTREAM_ERROR"
                    if scenario == "ERRORS"
                    else "RATE_LIMITED"
                    if scenario == "SATURATION"
                    else "MITIGATION_ACTIVE"
                )
                api_call(
                    opener,
                    f"{endpoint}/{exercise_id}/signals",
                    headers,
                    {
                        "source_type": edge_source,
                        "signal": signal_code,
                        "offset_ms": offset_ms,
                        "http_status": http_status,
                    },
                )
                degraded_signal_sent = True
            if edge_source and state["state"] == "RECOVERED" and not recovered_signal_sent:
                api_call(
                    opener,
                    f"{endpoint}/{exercise_id}/signals",
                    headers,
                    {
                        "source_type": edge_source,
                        "signal": "RECOVERED",
                        "offset_ms": offset_ms,
                        "http_status": http_status,
                    },
                )
                recovered_signal_sent = True
            print(
                f"#{seq} {offset_ms} ms {sample['outcome']} HTTP {http_status} "
                f"{latency_ms} ms estado {state['state']}"
            )
            seq += 1
            if offset_ms >= planned_ms:
                break
            time.sleep(max(0.0, origin + seq * interval_s - time.monotonic()))

        result = api_call(opener, f"{endpoint}/{exercise_id}/finish", headers)
        print(f"Resultado: {result['result']}")
        for event in result["timeline"]:
            print(
                f"  {event['event']}: esperado {event['expected_offset_ms']} ms, "
                f"observado {event['observed_offset_ms']} ms, diferença {event['delta_ms']} ms"
            )
        print(
            f"Publicação: alerta {result['alert_publication_ms']} ms, "
            f"recuperação {result['recovery_publication_ms']} ms"
        )
        return 0 if result["result"] == "PASSED" else 1
    except HTTPError as exc:
        print(f"A API recusou a operação (HTTP {exc.code}).", file=sys.stderr)
    except (URLError, OSError, KeyError, TypeError, ValueError):
        print("Falha na comunicação com a API do exercício de disponibilidade.", file=sys.stderr)
    if exercise_id is not None:
        try:
            api_call(opener, f"{endpoint}/{exercise_id}/finish", headers)
        except (HTTPError, URLError, OSError, ValueError):
            pass
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="Inicia o servidor de laboratório com roteiro de atraso.")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8081)
    serve.add_argument("--normal-ms", type=int, default=8000)
    serve.add_argument("--degraded-ms", type=int, default=8000)
    serve.add_argument("--degraded-delay-ms", type=int, default=800)
    serve.add_argument("--scenario", choices=SCENARIOS, default="LATENCY")

    probe = sub.add_parser("probe", help="Mede o servidor e envia as amostras à API.")
    probe.add_argument("--api-url", type=api_base_url, required=True)
    probe.add_argument("--asset-id", type=UUID, required=True)
    probe.add_argument("--target-url", required=True)
    probe.add_argument("--threshold-ms", type=int, default=500)
    probe.add_argument("--consecutive-samples", type=int, default=3)
    probe.add_argument("--interval-ms", type=int, default=1000)
    probe.add_argument("--normal-ms", type=int, default=8000)
    probe.add_argument("--degraded-ms", type=int, default=8000)
    probe.add_argument("--scenario", choices=SCENARIOS, default="LATENCY")
    probe.add_argument("--edge-source", choices=EDGE_SOURCES, default=None)

    args = parser.parse_args()
    if args.command == "serve":
        server = make_server(
            args.host,
            args.port,
            args.normal_ms,
            args.degraded_ms,
            args.degraded_delay_ms,
            args.scenario,
        )
        print(f"Servidor de laboratório em http://{args.host}:{args.port} (Ctrl+C encerra).")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            server.shutdown()
        return 0
    return run_probe(args)


if __name__ == "__main__":
    raise SystemExit(main())
