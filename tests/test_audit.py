"""Audit log tests (spec item 3c)."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from firmware.audit import AuditLog
from firmware.util import now_iso, sha256_file


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="f1-test-audit-")
        self.path = Path(self.tmp) / "logs" / "campaign.jsonl"

    def test_fields_present_on_every_action(self):
        log = AuditLog(self.path)
        log.start(mode="dry-run", campaign_id="c1", campaign_sha256="SHA", targets=["192.0.2.0/24"])
        log.action(mode="dry-run", campaign_id="c1", campaign_sha256="SHA",
                   phase="recon", plugin="recon-echo", target="192.0.2.1",
                   action="banner grab", executed=False)
        log.end(status="completed", campaign_id="c1", campaign_sha256="SHA")
        entries = log.read_entries()
        self.assertEqual(len(entries), 3)
        action = entries[1]
        for key in ("ts", "phase", "plugin", "target", "campaign_sha256", "executed"):
            self.assertIn(key, action)
        self.assertTrue(action["ts"])
        self.assertEqual(action["campaign_sha256"], "SHA")
        self.assertEqual(action["phase"], "recon")

    def test_appends_multiple_runs_in_order(self):
        log = AuditLog(self.path)
        log.start(mode="execute", campaign_id="a", campaign_sha256="1", targets=[])
        log.start(mode="execute", campaign_id="b", campaign_sha256="2", targets=[])
        entries = log.read_entries()
        self.assertEqual([e["campaign_id"] for e in entries], ["a", "b"])

    def test_abort_entry_carries_reason(self):
        log = AuditLog(self.path)
        log.abort(reason="approval_gate", campaign_id="c", campaign_sha256="S",
                  phase="post", plugin="post-echo")
        entries = log.read_entries()
        self.assertEqual(entries[0]["event"], "abort")
        self.assertEqual(entries[0]["reason"], "approval_gate")

    def test_sha256_matches_file(self):
        f = Path(self.tmp) / "camp.yaml"
        f.write_bytes(b"id: x\nname: y\n")
        expected = hashlib.sha256(b"id: x\nname: y\n").hexdigest()
        self.assertEqual(sha256_file(f), expected)

    def test_timestamp_is_iso(self):
        self.assertIn("T", now_iso())

    def test_empty_log_reads_empty(self):
        self.assertEqual(AuditLog(Path(self.tmp) / "nope.jsonl").read_entries(), [])


if __name__ == "__main__":
    unittest.main()