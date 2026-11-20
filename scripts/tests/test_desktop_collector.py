"""Valida pausa, reconexão e revogação no controlador desktop."""

import sys
import unittest
from pathlib import Path
from queue import Queue
from tempfile import TemporaryDirectory
from threading import Event, Thread
from unittest.mock import patch
from urllib.error import HTTPError, URLError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:
    from desktop_collector import CollectorUpdate, collect, display_times
except ModuleNotFoundError as exc:
    if exc.name not in {"tkinter", "_tkinter"}:
        raise
    raise unittest.SkipTest("Python sem Tkinter.") from exc

from test_zeek_file_collector import zeek_line


class LocalApi:
    def __init__(self):
        self.attempts = 0
        self.confirmed = Event()

    def status(self):
        return {"name": "Sensor local", "network": "192.168.50.0/24"}

    def submit(self, batch):
        self.attempts += 1
        if self.attempts == 1:
            raise URLError("offline")
        self.confirmed.set()
        return len(batch), 0


class DesktopTests(unittest.TestCase):
    @patch("desktop_collector.RETRY_SECONDS", 0.01)
    @patch("desktop_collector.POLL_SECONDS", 0.01)
    def test_pauses_without_reading_and_retries_after_resume(self):
        with TemporaryDirectory() as directory:
            log = Path(directory) / "conn.log"
            log.write_bytes(zeek_line("CFirst"))
            checkpoint = Path(directory) / "state.json"
            paused, stopped = Event(), Event()
            paused.set()
            updates: Queue[CollectorUpdate] = Queue()
            api = LocalApi()
            worker = Thread(target=collect, args=(api, log, checkpoint, paused, stopped, updates))
            worker.start()
            try:
                self.assertIn("pausada", updates.get(timeout=3).message)
                self.assertEqual(api.attempts, 0)
                self.assertFalse(checkpoint.exists())
                paused.clear()
                self.assertTrue(api.confirmed.wait(3))
            finally:
                stopped.set()
                worker.join(3)
            self.assertFalse(worker.is_alive())
            self.assertEqual(api.attempts, 2)
            self.assertTrue(checkpoint.exists())

    def test_rejects_revoked_credentials_before_reading(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            updates: Queue[CollectorUpdate] = Queue()
            api = LocalApi()
            with patch.object(api, "status", side_effect=HTTPError("http://127.0.0.1", 401, "", {}, None)):
                collect(api, root / "conn.log", root / "state.json", Event(), Event(), updates)
            self.assertIn("revogada", updates.get_nowait().message)
            self.assertTrue(updates.get_nowait().finished)
            self.assertEqual(api.attempts, 0)

    def test_displays_delay_only_for_ordered_timestamps(self):
        source = {"latest_observed_at": "2026-11-20T12:00:00Z", "last_received_at": "2026-11-20T12:00:08Z"}
        self.assertEqual(display_times(source)[1], "8 s")
        source["last_received_at"] = "2026-11-20T11:00:00Z"
        self.assertEqual(display_times(source)[1], "—")
