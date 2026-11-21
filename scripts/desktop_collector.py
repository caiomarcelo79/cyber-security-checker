"""Piloto desktop para publicar metadados de um conn.log do Zeek autorizado."""

import argparse
import os
import tkinter as tk
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from queue import Empty, Queue
from threading import Event, Thread
from time import monotonic
from tkinter import filedialog, ttk
from urllib.error import HTTPError, URLError
from uuid import UUID

from _local_api import api_base_url
from import_zeek import COLLECTOR_VERSION, CollectorApi
from zeek_file_collector import ZeekFileCollector, state_path

POLL_SECONDS = 2
RETRY_SECONDS = 5
STATUS_SECONDS = 15


@dataclass(frozen=True)
class CollectorUpdate:
    message: str = ""
    source: dict | None = None
    finished: bool = False


def collect(
    api: CollectorApi,
    log: Path,
    checkpoint: Path,
    paused: Event,
    stopped: Event,
    updates: Queue[CollectorUpdate],
) -> None:
    next_status = 0.0
    poll_seconds = POLL_SECONDS
    applied_config_version: int | None = None
    try:
        with ZeekFileCollector(log, checkpoint) as collector:
            while not stopped.is_set():
                if paused.is_set():
                    updates.put(CollectorUpdate("Coleta pausada."))
                    while paused.is_set() and not stopped.wait(0.2):
                        pass
                    continue
                try:
                    if monotonic() >= next_status:
                        source = api.status()
                        interval = source.get("poll_interval_seconds")
                        if type(interval) is int and 1 <= interval <= 300:
                            poll_seconds = interval
                        config_version = source.get("config_version")
                        config_updated = False
                        if type(config_version) is int and config_version != applied_config_version:
                            applied_config_version = config_version
                            if hasattr(api, "heartbeat"):
                                source = api.heartbeat(COLLECTOR_VERSION, config_version)
                            updates.put(
                                CollectorUpdate(
                                    f"Configuração v{config_version} aplicada (coletor {COLLECTOR_VERSION}).",
                                    source,
                                )
                            )
                            config_updated = True
                        if source.get("status") == "PAUSED":
                            updates.put(
                                CollectorUpdate("Coleta pausada pelo Console. Aguardando retomada.", source)
                            )
                            next_status = monotonic() + poll_seconds
                            stopped.wait(poll_seconds)
                            continue
                        if not config_updated:
                            updates.put(CollectorUpdate("Fonte conectada.", source))
                        next_status = monotonic() + STATUS_SECONDS
                    inserted, duplicates = collector.sync_once(api.submit)
                    if inserted or duplicates:
                        updates.put(
                            CollectorUpdate(
                                f"Lote confirmado. {inserted} novas conexões e {duplicates} duplicadas.",
                                api.status(),
                            )
                        )
                        next_status = monotonic() + STATUS_SECONDS
                        continue
                except HTTPError as exc:
                    if exc.code == 409:
                        updates.put(
                            CollectorUpdate("Coleta pausada pelo servidor. Nova verificação em 5 segundos.")
                        )
                        next_status = 0
                        stopped.wait(RETRY_SECONDS)
                        continue
                    if exc.code in {408, 429} or exc.code >= 500:
                        updates.put(CollectorUpdate("API temporariamente indisponível. Nova tentativa em 5 segundos."))
                        next_status = 0
                        stopped.wait(RETRY_SECONDS)
                        continue
                    messages = {
                        401: "Credencial da instalação inválida, expirada ou revogada.",
                        403: "Autorização do ativo, piloto ou laboratório indisponível.",
                        422: "A API recusou o lote. Confira se o arquivo corresponde ao segmento autorizado.",
                    }
                    updates.put(CollectorUpdate(messages.get(exc.code, f"A API recusou a operação (HTTP {exc.code}).")))
                    break
                except (URLError, TimeoutError):
                    updates.put(CollectorUpdate("Sem conexão com a API. Nova tentativa em 5 segundos."))
                    next_status = 0
                    stopped.wait(RETRY_SECONDS)
                    continue
                except FileNotFoundError:
                    updates.put(CollectorUpdate("Aguardando o arquivo de log."))
                except OSError:
                    updates.put(CollectorUpdate("Falha ao ler o log ou salvar a posição local."))
                    break
                except (TypeError, ValueError) as exc:
                    updates.put(CollectorUpdate(str(exc)))
                    break
                stopped.wait(poll_seconds)
    finally:
        updates.put(CollectorUpdate("Coleta encerrada." if stopped.is_set() else "", finished=True))


def display_times(source: dict) -> tuple[str, str]:
    received = source.get("last_received_at")
    observed = source.get("latest_observed_at")
    if not isinstance(received, str):
        return "Aguardando dados", "—"
    try:
        received_time = datetime.fromisoformat(received)
        last_send = received_time.astimezone().strftime("%d/%m/%Y %H:%M:%S")
        if isinstance(observed, str):
            delay_seconds = (received_time - datetime.fromisoformat(observed)).total_seconds()
            if delay_seconds >= 0:
                return last_send, f"{delay_seconds:,.0f} s"
        return last_send, "—"
    except (TypeError, ValueError):
        return "Indisponível", "—"


def checkpoint_directory() -> Path:
    if os.name == "nt":
        folder = Path(os.environ.get("LOCALAPPDATA", str(Path.home())))
    else:
        folder = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local" / "state")))
    return folder / "cyber-security-checker" / "collector"


class CollectorWindow:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.updates: Queue[CollectorUpdate] = Queue()
        self.paused = Event()
        self.stopped = Event()
        self.thread: Thread | None = None
        self.api_origin = tk.StringVar(value="http://127.0.0.1:8000")
        self.source_id = tk.StringVar()
        self.token = tk.StringVar(value=os.environ.get("CSC_COLLECTOR_TOKEN", ""))
        self.log_path = tk.StringVar()
        self.message = tk.StringVar(value="Informe a fonte cadastrada no Console e selecione o conn.log.")
        self.source_summary = tk.StringVar(value="—")
        self.last_send = tk.StringVar(value="—")
        self.delay = tk.StringVar(value="—")

        root.title("Coletor de rede · Cyber Security Checker")
        root.columnconfigure(0, weight=1)
        panel = ttk.Frame(root, padding=20)
        panel.grid(row=0, column=0, sticky="nsew")
        panel.columnconfigure(1, weight=1)
        root.minsize(560, 345)

        self.entries = []
        for row, (label, value) in enumerate(
            (
                ("Origem da API", self.api_origin),
                ("Identificador da fonte", self.source_id),
                ("Credencial da fonte", self.token),
                ("Arquivo conn.log", self.log_path),
            )
        ):
            ttk.Label(panel, text=label).grid(row=row, column=0, sticky="w", pady=4, padx=(0, 10))
            entry = ttk.Entry(panel, textvariable=value, show="*" if value is self.token else "")
            entry.grid(row=row, column=1, sticky="ew", pady=4)
            self.entries.append(entry)
        self.browse_button = ttk.Button(panel, text="Procurar", command=self._browse)
        self.browse_button.grid(row=3, column=2, padx=(6, 0))

        controls = ttk.Frame(panel)
        controls.grid(row=4, column=0, columnspan=3, sticky="w", pady=12)
        self.start_button = ttk.Button(controls, text="Iniciar", command=self._start)
        self.start_button.pack(side="left")
        self.pause_button = ttk.Button(controls, text="Pausar", command=self._toggle_pause, state="disabled")
        self.pause_button.pack(side="left", padx=6)
        self.stop_button = ttk.Button(controls, text="Parar", command=self._stop, state="disabled")
        self.stop_button.pack(side="left")

        for row, (label, value) in enumerate(
            (("Fonte e segmento", self.source_summary), ("Último envio", self.last_send), ("Atraso do evento", self.delay)),
            start=5,
        ):
            ttk.Label(panel, text=label).grid(row=row, column=0, sticky="w", pady=4)
            ttk.Label(panel, textvariable=value).grid(row=row, column=1, columnspan=2, sticky="w")
        ttk.Separator(panel).grid(row=8, column=0, columnspan=3, sticky="ew", pady=10)
        ttk.Label(panel, textvariable=self.message, wraplength=500).grid(row=9, column=0, columnspan=3, sticky="w")
        root.protocol("WM_DELETE_WINDOW", self._close)
        root.after(100, self._read_updates)

    def _browse(self) -> None:
        selected = filedialog.askopenfilename(parent=self.root, filetypes=[("Logs Zeek", "*.log"), ("Arquivos", "*")])
        if selected:
            self.log_path.set(selected)

    def _start(self) -> None:
        try:
            api = api_base_url(self.api_origin.get().strip())
            identifier = UUID(self.source_id.get().strip())
            token = self.token.get().strip()
            path = self.log_path.get().strip()
            if not token or not path:
                raise ValueError("Informe a credencial e o caminho do log.")
            log = Path(path).absolute()
            position = state_path(checkpoint_directory(), api, str(identifier), log)
        except (argparse.ArgumentTypeError, OSError, ValueError):
            self.message.set("Confira a origem da API, o identificador, a credencial e o caminho do log.")
            return
        self.paused.clear()
        self.stopped.clear()
        self._set_active(True)
        self.source_summary.set("—")
        self.last_send.set("—")
        self.delay.set("—")
        self.message.set("Conectando à API.")
        self.thread = Thread(
            target=collect,
            args=(CollectorApi(api, identifier, token), log, position, self.paused, self.stopped, self.updates),
            daemon=True,
        )
        self.thread.start()

    def _toggle_pause(self) -> None:
        if self.paused.is_set():
            self.paused.clear()
            self.message.set("Retomando a coleta.")
            self.pause_button.configure(text="Pausar")
        else:
            self.paused.set()
            self.message.set("Pausando após o lote em andamento.")
            self.pause_button.configure(text="Retomar")

    def _stop(self) -> None:
        self.stopped.set()
        self.stop_button.configure(state="disabled")
        self.pause_button.configure(state="disabled")
        self.message.set("Encerrando a coleta.")

    def _set_active(self, active: bool) -> None:
        for entry in self.entries:
            entry.configure(state="disabled" if active else "normal")
        self.browse_button.configure(state="disabled" if active else "normal")
        self.start_button.configure(state="disabled" if active else "normal")
        self.pause_button.configure(state="normal" if active else "disabled", text="Pausar")
        self.stop_button.configure(state="normal" if active else "disabled")

    def _read_updates(self) -> None:
        try:
            while True:
                update = self.updates.get_nowait()
                if update.message:
                    self.message.set(update.message)
                if update.source:
                    source = update.source
                    version_info = ""
                    if type(source.get("config_version")) is int:
                        version_info = f" · v{source['config_version']}"
                    if isinstance(source.get("collector_version"), str):
                        version_info += f" ({source['collector_version']})"
                    self.source_summary.set(f"{source.get('name', 'Zeek')} · {source['network']}{version_info}")
                    last_send, delay = display_times(source)
                    self.last_send.set(last_send)
                    self.delay.set(delay)
                if update.finished:
                    self._set_active(False)
        except Empty:
            self.root.after(100, self._read_updates)

    def _close(self) -> None:
        self.stopped.set()
        self.root.destroy()


def main() -> None:
    root = tk.Tk()
    CollectorWindow(root)
    root.mainloop()


if __name__ == "__main__":
    main()
