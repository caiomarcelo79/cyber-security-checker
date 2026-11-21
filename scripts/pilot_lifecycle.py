"""Ferramenta CLI operacional para heartbeat do coletor e consulta de prontidão do piloto."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request
from uuid import UUID

from _local_api import api_base_url, local_api_opener
from import_zeek import COLLECTOR_VERSION, CollectorApi


class PilotSessionApi:
    """Cliente autenticado por sessão do analista para consultar prontidão do piloto."""

    def __init__(self, api_url: str, token: str) -> None:
        self.api_url = api_url
        self.headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        self.opener = local_api_opener()

    def get_readiness(self, pilot_id: UUID) -> dict[str, Any]:
        url = f"{self.api_url}/api/v1/pilots/{pilot_id}/readiness"
        with self.opener.open(Request(url, headers=self.headers), timeout=15) as response:
            result = json.load(response)
        if not isinstance(result, dict) or "lifecycle" not in result:
            raise TypeError("A API não retornou um relatório de prontidão válido.")
        return result


def _run_heartbeat(args: argparse.Namespace) -> int:
    token = os.environ.get("CSC_COLLECTOR_TOKEN", "").strip()
    if not token:
        print("Defina CSC_COLLECTOR_TOKEN com a credencial da instalação.", file=sys.stderr)
        return 2
    api = CollectorApi(args.api_url, args.source_id, token)
    try:
        config_version = args.config_version
        if config_version is None:
            current = api.status()
            config_version = current.get("config_version")
        updated = api.heartbeat(
            collector_version=args.collector_version,
            applied_config_version=config_version if type(config_version) is int else None,
        )
    except HTTPError as exc:
        print(f"A API recusou o heartbeat (HTTP {exc.code}).", file=sys.stderr)
        return 1
    except (URLError, OSError, TypeError, ValueError) as exc:
        print(f"Falha ao enviar heartbeat do coletor: {exc}", file=sys.stderr)
        return 1

    print(
        f"Heartbeat confirmado: fonte={updated['id']} status={updated['status']} "
        f"versao={updated.get('collector_version')} config_v={updated.get('applied_config_version')} "
        f"update_status={updated.get('update_status')}"
    )
    return 0


def _mark(flag: bool) -> str:
    return "[OK]" if flag else "[PENDENTE]"


def _run_readiness(args: argparse.Namespace) -> int:
    token = os.environ.get("CSC_SESSION_TOKEN", "").strip()
    if not token:
        print("Defina CSC_SESSION_TOKEN com o token JWT da sessão do analista.", file=sys.stderr)
        return 2
    api = PilotSessionApi(args.api_url, token)
    try:
        data = api.get_readiness(args.pilot_id)
    except HTTPError as exc:
        print(f"A API recusou a consulta de prontidão (HTTP {exc.code}).", file=sys.stderr)
        return 1
    except (URLError, OSError, TypeError, ValueError) as exc:
        print(f"Falha ao consultar prontidão do piloto: {exc}", file=sys.stderr)
        return 1

    lifecycle = data["lifecycle"]
    coverage = data["coverage"]
    latency = data["latency"]
    fp = data["false_positives"]

    print(f"Piloto {data['pilot_id']} · estagio={data['stage']} status={data['status']}")
    print("Marcos operacionais:")
    print(f"  {_mark(lifecycle['installation_demonstrated'])} Instalacao e recepcao")
    print(f"  {_mark(lifecycle['pause_resume_demonstrated'])} Pausa e retomada")
    print(f"  {_mark(lifecycle['update_demonstrated'])} Atualizacao")
    print(f"  {_mark(lifecycle['revocation_demonstrated'])} Revogacao")
    print(f"  {_mark(lifecycle['recovery_demonstrated'])} Recuperacao")
    print(
        f"Cobertura: camadas={','.join(coverage['observed_layers']) or 'nenhuma'} "
        f"({coverage['layer_coverage_percent']}%) · fontes_ativas={coverage['active_sources']}/{coverage['total_sources']}"
    )
    print(
        f"Latencia: amostras_telemetria={latency['telemetry_samples_count']} "
        f"atraso_medio_s={latency['telemetry_avg_delay_seconds']} "
        f"alerta_disp_medio_ms={latency['availability_alert_pub_avg_ms']}"
    )
    print(
        f"Falsos positivos: alertas_trafego={fp['suspicious_alerts_total']} "
        f"rotacoes_tls_benignas={fp['benign_tls_rotations_ignored']} "
        f"taxa_fp_findings={fp['findings_false_positive_rate_percent']}%"
    )
    ready = "SIM" if data["ready_for_expansion_approval"] else "NAO"
    print(f"Pronto para revisao de expansao: {ready}")
    for reason in data.get("blocking_reasons") or []:
        print(f"  - Bloqueio: {reason}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    hb = sub.add_parser("heartbeat", help="Confirma versão e configuração aplicada pela instalação.")
    hb.add_argument("--api-url", type=api_base_url, required=True)
    hb.add_argument("--source-id", type=UUID, required=True)
    hb.add_argument("--collector-version", default=COLLECTOR_VERSION)
    hb.add_argument("--config-version", type=int, default=None)

    rd = sub.add_parser("readiness", help="Exibe prontidão, cobertura, latência e falsos positivos do piloto.")
    rd.add_argument("--api-url", type=api_base_url, required=True)
    rd.add_argument("--pilot-id", type=UUID, required=True)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "heartbeat":
        return _run_heartbeat(args)
    return _run_readiness(args)


if __name__ == "__main__":
    raise SystemExit(main())
