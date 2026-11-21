"""Analisa logs JSONL de laboratório (Zeek conn.log, dns.log e ssl.log) via API."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request
from uuid import UUID

from _local_api import api_base_url, local_api_opener
from import_zeek import (
    MAX_LINE_BYTES,
    UID_PATTERN,
    address,
    integer_value,
    metadata_from_line,
)

MAX_CONNECTIONS = 200
MAX_DNS = 200
MAX_TLS = 100
MAX_EDR = 100
EDR_SOURCE_TYPES = ("ANTIVIRUS", "EDR")
EDR_SIGNAL_CODES = (
    "SUSPICIOUS_PROCESS",
    "UNTRUSTED_ROOT_CA",
    "BEACONING_DETECTED",
    "MALWARE_QUARANTINED",
)
SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")
DNS_RCODES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


class TrafficAnalysisApi:
    """Cliente da instalação para o endpoint de análise explicável de tráfego."""

    def __init__(self, api_url: str, source_id: UUID, token: str) -> None:
        self.endpoint = f"{api_url}/api/v1/telemetry/sources/{source_id}/traffic-analyses"
        self.headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        self.opener = local_api_opener()

    def analyze(self, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        request = Request(self.endpoint, data=body, headers=self.headers, method="POST")
        with self.opener.open(request, timeout=20) as response:
            result = json.load(response)
        if not isinstance(result, dict) or not isinstance(result.get("coverage"), dict):
            raise TypeError("A API não retornou um resultado de análise válido.")
        return result


def _iso_timestamp(value: object) -> str:
    if type(value) in (int, float):
        return datetime.fromtimestamp(float(value), tz=UTC).isoformat()
    if isinstance(value, str) and value.strip():
        parsed = datetime.fromisoformat(value.strip())
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC).isoformat()
    raise ValueError("Timestamp inválido no registro.")


def _valid_uid(value: object) -> str:
    if not isinstance(value, str) or UID_PATTERN.fullmatch(value) is None:
        raise ValueError("Identificador uid inválido.")
    return value


def _non_empty_text(value: object, field_name: str, max_len: int = 255) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Campo '{field_name}' ausente ou vazio.")
    text = value.strip()
    if len(text) > max_len:
        raise ValueError(f"Campo '{field_name}' excedeu {max_len} caracteres.")
    return text


def dns_metadata_from_line(line: bytes) -> dict[str, Any]:
    data = json.loads(line)
    if not isinstance(data, dict):
        raise TypeError("Objeto JSON esperado.")
    qtype_raw = data.get("qtype_name") or data.get("qtype") or "A"
    qtype = str(qtype_raw).strip() or "A"
    rcode_raw = data.get("rcode_name")
    if rcode_raw is None:
        raw_code = data.get("rcode")
        if type(raw_code) is int:
            rcode_raw = DNS_RCODES.get(raw_code, str(raw_code))
        else:
            rcode_raw = raw_code
    return {
        "uid": _valid_uid(data["uid"]),
        "observed_at": _iso_timestamp(data["ts"]),
        "client_ip": address(data["id.orig_h"]),
        "responder_ip": address(data["id.resp_h"]),
        "query": _non_empty_text(data["query"], "query"),
        "qtype": qtype[:24],
        "rcode": _non_empty_text(rcode_raw, "rcode", max_len=32).upper(),
    }


def ssl_metadata_from_line(line: bytes) -> dict[str, Any]:
    data = json.loads(line)
    if not isinstance(data, dict):
        raise TypeError("Objeto JSON esperado.")
    cert_fp = data.get("cert_sha256")
    if cert_fp is None and isinstance(data.get("cert_chain_fps"), list) and data["cert_chain_fps"]:
        cert_fp = data["cert_chain_fps"][0]
    if not isinstance(cert_fp, str) or SHA256_PATTERN.fullmatch(cert_fp.strip()) is None:
        raise ValueError("Impressão digital SHA-256 do certificado inválida.")

    validation_status = _non_empty_text(data.get("validation_status"), "validation_status", max_len=64)
    self_signed_raw = data.get("self_signed")
    if type(self_signed_raw) is bool:
        self_signed = self_signed_raw
    else:
        self_signed = "self signed" in validation_status.lower() or "self-signed" in validation_status.lower()

    return {
        "uid": _valid_uid(data["uid"]),
        "observed_at": _iso_timestamp(data["ts"]),
        "client_ip": address(data["id.orig_h"]),
        "responder_ip": address(data["id.resp_h"]),
        "responder_port": integer_value(data["id.resp_p"], 65535),
        "server_name": _non_empty_text(data.get("server_name"), "server_name"),
        "cert_sha256": cert_fp.strip().lower(),
        "subject": _non_empty_text(data.get("subject"), "subject"),
        "issuer": _non_empty_text(data.get("issuer"), "issuer"),
        "validation_status": validation_status,
        "self_signed": self_signed,
        "not_before": _iso_timestamp(data["not_before"]),
        "not_after": _iso_timestamp(data["not_after"]),
    }


def edr_metadata_from_line(line: bytes) -> dict[str, Any]:
    data = json.loads(line)
    if not isinstance(data, dict):
        raise TypeError("Objeto JSON esperado.")
    source_type = _non_empty_text(data.get("source_type"), "source_type", max_len=16).upper()
    if source_type not in EDR_SOURCE_TYPES:
        raise ValueError("source_type inválido (use ANTIVIRUS ou EDR).")
    signal = _non_empty_text(data.get("signal"), "signal", max_len=32).upper()
    if signal not in EDR_SIGNAL_CODES:
        raise ValueError("Código de sinal AV/EDR inválido.")
    raw_host = data.get("host_ip", data.get("id.orig_h"))
    raw_ts = data.get("ts", data.get("observed_at"))
    detail_raw = data.get("detail")
    detail = _non_empty_text(detail_raw, "detail", max_len=255) if detail_raw is not None else None
    return {
        "uid": _valid_uid(data["uid"]),
        "observed_at": _iso_timestamp(raw_ts),
        "host_ip": address(raw_host),
        "source_type": source_type,
        "signal": signal,
        "process_name": _non_empty_text(data.get("process_name"), "process_name", max_len=120),
        "detail": detail,
    }


def read_jsonl_events(
    path: Path,
    parser: Callable[[bytes], dict[str, Any]],
    *,
    label: str,
    limit: int,
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with path.open("rb") as source:
        for line_number, line in enumerate(iter(lambda: source.readline(MAX_LINE_BYTES + 1), b""), 1):
            if len(line) > MAX_LINE_BYTES:
                raise ValueError(f"{label}: linha {line_number} excedeu 64 KiB.")
            if not line.strip():
                continue
            try:
                events.append(parser(line))
            except (ValueError, TypeError, KeyError, OverflowError, OSError) as exc:
                raise ValueError(f"{label}: linha {line_number} incompatível ({exc}).") from exc
            if len(events) > limit:
                raise ValueError(f"{label}: limite de {limit} registros por lote excedido.")
    return events


def format_report(result: dict[str, Any]) -> str:
    coverage = result.get("coverage") or {}
    observed = ", ".join(coverage.get("observed_layers") or []) or "nenhuma"
    missing = ", ".join(coverage.get("missing_layers") or []) or "nenhuma"
    lines = [
        f"Análise concluída (run={result.get('id')}) | Fonte: {result.get('source_name')}",
        f"Cobertura observada: {observed} | Ausente: {missing}",
        (
            f"Eventos analisados: {result.get('connection_count', 0)} conexões, "
            f"{result.get('dns_count', 0)} DNS, {result.get('tls_count', 0)} TLS, "
            f"{result.get('edr_count', 0)} AV/EDR | "
            f"Rotações legítimas: {result.get('benign_rotations_count', 0)} | "
            f"Alertas: {result.get('alerts_count', 0)}"
        ),
    ]
    for sig in result.get("edr_signals") or []:
        lines.append(
            f"  [AV/EDR:{sig['source_type']}:{sig['signal']}] {sig['host_ip']} "
            f"processo={sig['process_name']}"
        )
    for decision in result.get("tls_decisions") or []:
        lines.append(
            f"  [TLS:{decision['outcome']}] {decision['server_name']} "
            f"({decision['responder_ip']}:{decision['responder_port']}) "
            f"cert={str(decision['observed_cert_sha256'])[:12]} motivo={decision['reason']}"
        )
    for alert in result.get("alerts") or []:
        lines.append(
            f"  [{alert['severity']}|confiança={alert['confidence']}] "
            f"{alert['rule_id']} — {alert['title']}"
        )
        lines.append(f"    Explicação: {alert['explanation']}")
        lines.append(f"    Evidência: {json.dumps(alert['evidence'], ensure_ascii=False)}")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-url", type=api_base_url, required=True)
    parser.add_argument("--source-id", type=UUID, required=True)
    parser.add_argument("--conn-log", type=Path, default=None)
    parser.add_argument("--dns-log", type=Path, default=None)
    parser.add_argument("--ssl-log", type=Path, default=None)
    parser.add_argument("--edr-log", type=Path, default=None)
    args = parser.parse_args()

    if not (args.conn_log or args.dns_log or args.ssl_log):
        parser.error("Informe ao menos --conn-log, --dns-log ou --ssl-log.")

    token = os.environ.get("CSC_COLLECTOR_TOKEN", "").strip()
    if not token:
        parser.error("Defina CSC_COLLECTOR_TOKEN com a credencial da instalação.")

    try:
        connections = (
            read_jsonl_events(args.conn_log, metadata_from_line, label="conn.log", limit=MAX_CONNECTIONS)
            if args.conn_log
            else []
        )
        dns_queries = (
            read_jsonl_events(args.dns_log, dns_metadata_from_line, label="dns.log", limit=MAX_DNS)
            if args.dns_log
            else []
        )
        tls_handshakes = (
            read_jsonl_events(args.ssl_log, ssl_metadata_from_line, label="ssl.log", limit=MAX_TLS)
            if args.ssl_log
            else []
        )
        edr_signals = (
            read_jsonl_events(args.edr_log, edr_metadata_from_line, label="edr.log", limit=MAX_EDR)
            if args.edr_log
            else []
        )
        if not (connections or dns_queries or tls_handshakes):
            print("Os arquivos informados não contêm registros para análise.", file=sys.stderr)
            return 1

        api = TrafficAnalysisApi(args.api_url, args.source_id, token)
        result = api.analyze(
            {
                "connections": connections,
                "dns_queries": dns_queries,
                "tls_handshakes": tls_handshakes,
                "edr_signals": edr_signals,
            }
        )
    except HTTPError as exc:
        print(f"A API recusou a análise de tráfego (HTTP {exc.code}).", file=sys.stderr)
        return 1
    except (URLError, OSError, KeyError, TypeError):
        print("Falha ao ler os arquivos ou comunicar com a API de tráfego.", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"Análise interrompida. {exc}", file=sys.stderr)
        return 1

    print(format_report(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
