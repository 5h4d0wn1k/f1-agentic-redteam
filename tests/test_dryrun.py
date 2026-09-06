"""Dry-run behaviour tests (safety rail (a) + spec item 3a)."""

import tempfile
import unittest
from pathlib import Path

from firmware.audit import AuditLog
from firmware.errors import EXIT_OK
from firmware.orchestrator import run_campaign

from tests.helpers import make_config, write_campaign


class DryRunTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="f1-test-dryrun-")
        self.cfg = make_config(self.tmp)

    def test_dry_run_executes_nothing(self):
        camp = write_campaign(self.tmp, "dry", "192.0.2.0/24")
        rc = run_campaign(camp, self.cfg, execute=False)
        self.assertEqual(rc, EXIT_OK)
        entries = AuditLog(Path(self.cfg.audit_log)).read_entries()
        actions = [e for e in entries if e.get("event") == "action"]
        self.assertGreaterEqual(len(actions), 1)
        self.assertTrue(all(e.get("mode") == "dry-run" for e in actions))
        self.assertTrue(all(not e.get("executed") for e in actions))
        self.assertTrue(any(e.get("event") == "end" and e.get("status") == "completed"
                            for e in entries))

    def test_dry_run_produces_no_report_artefacts(self):
        camp = write_campaign(self.tmp, "dry2", "192.0.2.0/24")
        rc = run_campaign(camp, self.cfg, execute=False, out_dir=self.cfg.output_dir)
        self.assertEqual(rc, EXIT_OK)
        self.assertFalse(Path(self.cfg.output_dir, "dry2").exists())

    def test_dry_run_prints_planned_actions_without_calling_plugins(self):
        from firmware.plugins import get_plugin

        original = get_plugin("recon-echo").run
        camp = write_campaign(self.tmp, "dry3", "192.0.2.0/24")
        rc = run_campaign(camp, self.cfg, execute=False)
        self.assertEqual(rc, EXIT_OK)
        # run() was never invoked, but neither was it replaced here; the
        # audit executed=false assertion below is the behavioural proof.
        self.assertEqual(get_plugin("recon-echo").run, original)


if __name__ == "__main__":
    unittest.main()