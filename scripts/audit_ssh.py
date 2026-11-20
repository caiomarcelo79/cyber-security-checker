"""Lê diretivas efetivas do OpenSSH local e envia as observações à API do laboratório."""

import argparse
import json
import os
import socket
import subprocess
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request
from uuid import UUID

from _local_api import api_base_url, local_api_opener


def observe_ssh_configuration() -> dict[str, str]:
    try:
        result = subprocess.run(
            ["/usr/sbin/sshd", "-T"],
            capture_output=True,
            text=True,
            errors="replace",
            check=True,
            timeout=10,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError):
        return {"password_authentication": "collection_error", "permit_root_login": "collection_error"}

    observations = {"password_authentication": "unknown", "permit_root_login": "unknown"}
    password_values = {"yes": "enabled", "no": "disabled"}
    root_values = {
        "yes": "yes",
        "no": "no",
        "prohibit-password": "prohibit-password",
        "without-password": "prohibit-password",
        "forced-commands-only": "forced-commands-only",
    }
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) != 2:
            continue
        directive, value = fields
        if directive == "passwordauthentication":
            observations["password_authentication"] = password_values.get(value, "unknown")
        elif directive == "permitrootlogin":
            observations["permit_root_login"] = root_values.get(value, "unknown")
    return observations


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-url", type=api_base_url, required=True)
    parser.add_argument("--asset-id", type=UUID, required=True)
    parser.add_argument(
        "--test-alert", action="store_true", help="Publica um alerta de autenticação sintético no Console."
    )
    args = parser.parse_args()

    token = os.environ.get("CSC_SSH_SESSION_TOKEN", "").strip()
    if not token:
        parser.error("Defina CSC_SSH_SESSION_TOKEN com um token de sessão válido.")

    endpoint = f"{args.api_url}/api/v1/assets/{args.asset_id}/ssh-audit"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    opener = local_api_opener()
    try:
        if args.test_alert:
            request = Request(f"{endpoint}/alert-exercise", headers=headers, method="POST")
            with opener.open(request, timeout=10) as response:
                result = json.load(response)
            print(f"Notificação de exercício publicada no Console em {result['publication_ms']} ms.")
            return 0

        with opener.open(Request(f"{endpoint}/collection", headers=headers), timeout=10) as response:
            authorized_hostname = json.load(response)["hostname"]
        hostname = socket.gethostname()
        if not isinstance(authorized_hostname, str) or hostname.lower() != authorized_hostname.lower():
            print("O hostname local não corresponde ao ativo autorizado.", file=sys.stderr)
            return 1

        observations = observe_ssh_configuration()
        data = json.dumps({"hostname": hostname, **observations}).encode("utf-8")
        request = Request(endpoint, headers=headers, data=data, method="POST")
        with opener.open(request, timeout=10) as response:
            result = json.load(response)
        print(
            f"Auditoria SSH registrada. Senha {result['status']}. "
            f"Acesso de root {result['permit_root_login_status']}."
        )
        return 1 if "collection_error" in observations.values() else 0
    except HTTPError as exc:
        print(f"A API recusou a operação (HTTP {exc.code}).", file=sys.stderr)
    except (URLError, OSError, KeyError, TypeError, ValueError):
        print("Falha na comunicação com a API de auditoria SSH.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
