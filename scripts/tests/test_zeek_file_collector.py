"""Testes locais para a posição confirmada do aplicativo desktop."""

import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.error import URLError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from zeek_file_collector import ZeekFileCollector, read_position, state_path


def zeek_line(uid: str) -> bytes:
    record = {
        "ts": 1795172400.5,
        "uid": uid,
        "id.orig_h": "192.168.50.10",
        "id.orig_p": 54000,
        "id.resp_h": "192.168.50.20",
        "id.resp_p": 9100,
        "proto": "udp",
        "unrelated": "discarded",
    }
    return (json.dumps(record) + "\n").encode("utf-8")


class ZeekFileCollectorTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.folder = Path(directory.name)
        self.log = self.folder / "conn.log"
        self.checkpoint = self.folder / "state.json"
        self.uids = []

    def accept(self, batch):
        self.uids.extend(entry["uid"] for entry in batch)
        self.assertTrue(all("unrelated" not in entry for entry in batch))
        return len(batch), 0

    def test_retries_unacknowledged_batch_and_resumes_after_restart(self):
        first = zeek_line("COne")
        self.log.write_bytes(first)

        def offline(_batch):
            raise URLError("fixture offline")

        with ZeekFileCollector(self.log, self.checkpoint) as follower:
            with self.assertRaises(URLError):
                follower.sync_once(offline)
            self.assertFalse(self.checkpoint.exists())
            self.assertEqual(follower.sync_once(self.accept), (1, 0))
        self.assertEqual(read_position(self.checkpoint).offset, len(first))

        with self.log.open("ab") as writer:
            writer.write(zeek_line("CTwo"))
        with ZeekFileCollector(self.log, self.checkpoint) as follower:
            self.assertEqual(follower.sync_once(self.accept), (1, 0))
            self.assertEqual(follower.sync_once(self.accept), (0, 0))
        self.assertEqual(self.uids, ["COne", "CTwo"])

    def test_rotates_after_draining_a_previously_open_log(self):
        self.log.write_bytes(zeek_line("CBefore"))
        rotated = self.folder / "conn-old.log"
        with ZeekFileCollector(self.log, self.checkpoint) as follower:
            follower.sync_once(self.accept)
            self.log.rename(rotated)
            with rotated.open("ab") as writer:
                writer.write(zeek_line("CBacklog"))
            self.log.write_bytes(zeek_line("CAfter"))
            follower.sync_once(self.accept)
            follower.sync_once(self.accept)
        self.assertEqual(self.uids, ["CBefore", "CBacklog", "CAfter"])

    def test_log_truncation_or_in_place_rewrite_resets_position(self):
        self.log.write_bytes(zeek_line("CBefore"))
        with ZeekFileCollector(self.log, self.checkpoint) as follower:
            follower.sync_once(self.accept)
            self.log.write_bytes(zeek_line("CDifferent") + zeek_line("CMore"))
            follower.sync_once(self.accept)
        self.assertEqual(self.uids, ["CBefore", "CDifferent", "CMore"])

    def test_waits_for_a_complete_record_and_recovers_from_invalid_state(self):
        line = zeek_line("CWait")
        self.checkpoint.write_text("incomplete", encoding="utf-8")
        self.log.write_bytes(line[:-1])
        with ZeekFileCollector(self.log, self.checkpoint) as follower:
            self.assertEqual(follower.sync_once(self.accept), (0, 0))
            with self.log.open("ab") as writer:
                writer.write(b"\n")
            self.assertEqual(follower.sync_once(self.accept), (1, 0))
        self.assertEqual(self.uids, ["CWait"])

    def test_state_identity_depends_on_installation_api_and_path(self):
        first = state_path(self.folder, "http://127.0.0.1:8000", "one", self.log)
        second = state_path(self.folder, "http://127.0.0.1:8000", "two", self.log)
        self.assertNotEqual(first, second)
        self.assertEqual(first.parent, self.folder)
        self.assertNotIn(str(self.log), first.name)
