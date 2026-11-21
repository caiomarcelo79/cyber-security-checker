"""Sensor local passivo de Wi-Fi em loopback (127.0.0.1) para o Console SOC.

Permite que o navegador acesse leituras reais e passivas do adaptador Wi-Fi
do host (Windows `netsh` ou Linux `nmcli`) mesmo quando o backend/frontend
estiverem executando em containers Docker isolados.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import platform
import shutil
import subprocess
import time
from ctypes import wintypes
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ALLOWED_CORS_ORIGINS: frozenset[str] = frozenset(
    {
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    }
)


def decode_os_output(raw: bytes) -> str:
    """Decodifica saída de comandos do SO preservando acentuação PT-BR."""
    for enc in ("utf-8", "cp850", "cp1252", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def _trigger_windows_wlan_refresh() -> None:
    """Solicita atualização da lista de beacons ao serviço WLAN AutoConfig do Windows."""
    try:
        wlanapi = getattr(ctypes, "windll", None)
        if wlanapi is None:
            return
        wlan = wlanapi.wlanapi
        negotiated = wintypes.DWORD()
        handle = wintypes.HANDLE()
        if wlan.WlanOpenHandle(2, None, ctypes.byref(negotiated), ctypes.byref(handle)) != 0:
            return
        p_list = ctypes.c_void_p()
        try:
            if wlan.WlanEnumInterfaces(handle, None, ctypes.byref(p_list)) == 0 and p_list.value:
                count = ctypes.c_uint32.from_address(p_list.value).value
                if count >= 1:
                    guid = (ctypes.c_ubyte * 16).from_address(p_list.value + 8)
                    if wlan.WlanScan(handle, ctypes.byref(guid), None, None, None) == 0:
                        time.sleep(1.5)
        finally:
            if p_list.value:
                wlan.WlanFreeMemory(p_list)
            wlan.WlanCloseHandle(handle, None)
    except (OSError, AttributeError, ValueError):
        return


def capture_wifi_scan() -> dict[str, object]:
    """Executa leitura somente-leitura da placa Wi-Fi local (sem pacotes ofensivos)."""
    system_name = platform.system()
    captured_at = datetime.now(UTC).isoformat()

    if system_name == "Windows":
        netsh_exe = shutil.which("netsh")
        if not netsh_exe:
            return {
                "available": False,
                "host_os": system_name,
                "tool": "none",
                "captured_at": captured_at,
                "error": "Utilitário netsh não encontrado no PATH do Windows.",
            }

        _trigger_windows_wlan_refresh()
        nets_proc = subprocess.run(
            [netsh_exe, "wlan", "show", "networks", "mode=bssid"],
            capture_output=True,
            timeout=8,
            check=False,
        )
        iface_proc = subprocess.run(
            [netsh_exe, "wlan", "show", "interfaces"],
            capture_output=True,
            timeout=8,
            check=False,
        )
        raw_scan = decode_os_output(nets_proc.stdout or b"")
        raw_iface = decode_os_output(iface_proc.stdout or b"")
        if nets_proc.returncode != 0 or not raw_scan.strip():
            err_detail = decode_os_output(nets_proc.stderr or nets_proc.stdout or b"").strip()
            return {
                "available": False,
                "host_os": system_name,
                "tool": "netsh",
                "captured_at": captured_at,
                "error": err_detail or "Adaptador Wi-Fi indisponível ou desligado.",
            }
        return {
            "available": True,
            "host_os": system_name,
            "tool": "netsh",
            "captured_at": captured_at,
            "raw_scan_output": raw_scan,
            "connected_interface_output": raw_iface or None,
        }

    if system_name == "Linux":
        nmcli_exe = shutil.which("nmcli")
        if not nmcli_exe:
            return {
                "available": False,
                "host_os": system_name,
                "tool": "none",
                "captured_at": captured_at,
                "error": "Utilitário nmcli não encontrado no Linux.",
            }
        proc = subprocess.run(
            [nmcli_exe, "-t", "-f", "SSID,BSSID,CHAN,SIGNAL,SECURITY", "dev", "wifi", "list"],
            capture_output=True,
            timeout=8,
            check=False,
        )
        raw_scan = decode_os_output(proc.stdout or b"")
        if proc.returncode != 0 or not raw_scan.strip():
            err_detail = decode_os_output(proc.stderr or proc.stdout or b"").strip()
            return {
                "available": False,
                "host_os": system_name,
                "tool": "nmcli",
                "captured_at": captured_at,
                "error": err_detail or "Nenhuma rede retornada pelo nmcli.",
            }
        return {
            "available": True,
            "host_os": system_name,
            "tool": "nmcli",
            "captured_at": captured_at,
            "raw_scan_output": raw_scan,
            "connected_interface_output": None,
        }

    return {
        "available": False,
        "host_os": system_name,
        "tool": "unsupported",
        "captured_at": captured_at,
        "error": f"Sistema operacional '{system_name}' não suportado pelo sensor local.",
    }


class WifiSensorHandler(BaseHTTPRequestHandler):
    """Servidor HTTP local restrito a loopback (127.0.0.1)."""

    def log_message(self, format: str, *args: object) -> None:
        return

    def _write_cors_headers(self) -> None:
        origin = self.headers.get("Origin", "")
        if origin in ALLOWED_CORS_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _send_json(self, status_code: int, payload: dict[str, object]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self._write_cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self._write_cors_headers()
        self.end_headers()

    def do_GET(self) -> None:
        if self.path == "/health":
            tool = "netsh" if platform.system() == "Windows" else "nmcli"
            self._send_json(
                200,
                {
                    "status": "UP",
                    "host_os": platform.system(),
                    "tool": tool,
                    "timestamp": datetime.now(UTC).isoformat(),
                },
            )
            return

        if self.path == "/scan":
            payload = capture_wifi_scan()
            status_code = 200 if payload.get("available") else 503
            self._send_json(status_code, payload)
            return

        self._send_json(404, {"detail": "Rota não encontrada no sensor local Wi-Fi."})


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sensor local passivo de Wi-Fi (127.0.0.1) para Cyber-Security-Checker."
    )
    parser.add_argument("--port", type=int, default=8765, help="Porta loopback (padrão: 8765)")
    parser.add_argument(
        "--once",
        action="store_true",
        help="Executa uma captura única em JSON e encerra.",
    )
    args = parser.parse_args()

    if args.once:
        print(json.dumps(capture_wifi_scan(), ensure_ascii=False, indent=2))
        return

    server = ThreadingHTTPServer(("127.0.0.1", args.port), WifiSensorHandler)
    print(f"Sensor local Wi-Fi ativo em http://127.0.0.1:{args.port} (somente loopback)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
