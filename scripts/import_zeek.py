"""Importa metadados do arquivo conn.log JSON do Zeek de laboratório."""

import argparse
import json
import os
import re
import sys
from collections.abc import Iterator
from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request
from uuid import UUID

from _local_api import api_base_url, local_api_opener

BATCH_SIZE = 200
COLLECTOR_VERSION = "1.1.0"
MAX_LINE_BYTES = 64 * 1024
MAX_BYTE_COUNT = (1 << 63) - 1
UID_PATTERN = re.compile(r"[A-Za-z0-9]{1,64}")
MetadataValue = str | int | None
ConnectionMetadata = dict[str, MetadataValue]


class CollectorApi:
    """Acesso da instalação às duas operações autorizadas pela API."""

    def __init__(self, api_url: str, source_id: UUID, token: str) -> None:
        self.endpoint = f"{api_url}/api/v1/telemetry/sources/{source_id}"
        self.headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        self.opener = local_api_opener()

    def status(self) -> dict:
        with self.opener.open(Request(self.endpoint, headers=self.headers), timeout=10) as response:
            result = json.load(response)
        if not isinstance(result, dict) or not isinstance(result.get("network"), str):
            raise TypeError("A API não retornou um estado de fonte válido.")
        return result

    def heartbeat(
        self,
        collector_version: str = COLLECTOR_VERSION,
        applied_config_version: int | None = None,
    ) -> dict:
        payload: dict[str, object] = {"collector_version": collector_version}
        if applied_config_version is not None:
            payload["applied_config_version"] = applied_config_version
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        request = Request(f"{self.endpoint}/heartbeat", data=body, headers=self.headers, method="POST")
        with self.opener.open(request, timeout=10) as response:
            result = json.load(response)
        if not isinstance(result, dict) or not isinstance(result.get("network"), str):
            raise TypeError("A API não retornou um estado de fonte válido após heartbeat.")
        return result

    def submit(self, batch: list[ConnectionMetadata]) -> tuple[int, int]:
        body = json.dumps({"events": batch}, separators=(",", ":")).encode("utf-8")
        request = Request(f"{self.endpoint}/connections", data=body, headers=self.headers, method="POST")
        with self.opener.open(request, timeout=15) as response:
            result = json.load(response)
        if not isinstance(result, dict):
            raise TypeError("A API não confirmou o lote de telemetria.")
        inserted = result.get("inserted")
        duplicates = result.get("duplicates")
        if (
            type(inserted) is not int or type(duplicates) is not int
            or inserted < 0 or duplicates < 0 or inserted + duplicates != len(batch)
        ):
            raise ValueError("A API não confirmou todo o lote de telemetria.")
        return inserted, duplicates


def integer_value(value: object, maximum: int) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("Valor inteiro fora do intervalo.")
    return value


def address(value: object) -> str:
    if not isinstance(value, str) or "%" in value:
        raise ValueError("Endereço inválido.")
    return str(ip_address(value))


def metadata_from_line(line: bytes) -> ConnectionMetadata:
    data = json.loads(line)
    if not isinstance(data, dict):
        raise TypeError("Objeto JSON esperado.")
    uid = data["uid"]
    timestamp = data["ts"]
    transport = data["proto"]
    if (
        not isinstance(uid, str)
        or UID_PATTERN.fullmatch(uid) is None
        or type(timestamp) not in (int, float)
        or not isinstance(transport, str)
        or transport not in ("tcp", "udp", "icmp")
    ):
        raise ValueError("Identificação da conexão inválida.")
    origin_bytes = data.get("orig_bytes")
    responder_bytes = data.get("resp_bytes")
    return {
        "uid": uid,
        "observed_at": datetime.fromtimestamp(timestamp, tz=UTC).isoformat(),
        "origin_ip": address(data["id.orig_h"]),
        "origin_port": integer_value(data["id.orig_p"], 65535),
        "responder_ip": address(data["id.resp_h"]),
        "responder_port": integer_value(data["id.resp_p"], 65535),
        "transport": transport,
        "origin_bytes": integer_value(origin_bytes, MAX_BYTE_COUNT) if origin_bytes is not None else None,
        "responder_bytes": integer_value(responder_bytes, MAX_BYTE_COUNT) if responder_bytes is not None else None,
    }


def event_batches(path: Path) -> Iterator[list[ConnectionMetadata]]:
    with path.open("rb") as source:
        batch = []
        for line_number, line in enumerate(iter(lambda: source.readline(MAX_LINE_BYTES + 1), b""), 1):
            if len(line) > MAX_LINE_BYTES:
                raise ValueError(f"Linha {line_number} excedeu 64 KiB.")
            if not line.strip():
                continue
            try:
                batch.append(metadata_from_line(line))
            except (ValueError, TypeError, KeyError, OverflowError, OSError) as exc:
                raise ValueError(f"Linha {line_number} incompatível com conn.log JSON do Zeek.") from exc
            if len(batch) == BATCH_SIZE:
                yield batch
                batch = []
        if batch:
            yield batch


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-url", type=api_base_url, required=True)
    parser.add_argument("--source-id", type=UUID, required=True)
    parser.add_argument("conn_log", type=Path)
    args = parser.parse_args()
    token = os.environ.get("CSC_COLLECTOR_TOKEN", "").strip()
    if not token:
        parser.error("Defina CSC_COLLECTOR_TOKEN com a credencial da instalação.")

    api = CollectorApi(args.api_url, args.source_id, token)
    inserted = duplicates = 0
    try:
        for batch in event_batches(args.conn_log):
            new_count, duplicate_count = api.submit(batch)
            inserted += new_count
            duplicates += duplicate_count
    except HTTPError as exc:
        print(f"A API recusou o lote (HTTP {exc.code}).", file=sys.stderr)
        return 1
    except (URLError, OSError, KeyError, TypeError):
        print("Falha ao ler o arquivo ou comunicar com a API de telemetria.", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"Importação interrompida. {exc}", file=sys.stderr)
        return 1

    print(f"Importação concluída. {inserted} novas conexões e {duplicates} duplicadas.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
