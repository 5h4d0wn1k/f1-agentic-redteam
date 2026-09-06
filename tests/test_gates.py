"""Approval-gate behaviour tests (safety rail (d) + spec item 3d)."""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from firmware.audit import AuditLog
from firmware.errors import EXIT_ABORTED, EXIT_OK, EXIT_USAGE
from firmware.orchestrator import run_campaign
from firmware.plugins import get_plugin

from tests.helpers import GATED_PHASES, make_config, write_campaign


class GateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="f1-test-gates-")
        self.cfg = make_config(self.tmp)

    def _audit(self):
        return AuditLog(Path(self.cfg.audit_log)).read_entries()

    def test_gated_phase_aborts_campaign_non_interactive(self):
        camp = write_campaign(self.tmp, "gated", "192.0.2.0/24", GATED_PHASES)
        rc = run_campaign(camp, self.cfg, execute=True, interactive=False)
        self.assertEqual(rc, EXIT_ABORTED)
        entries = self._audit()
        self.assertTrue(any(e.get("event") == "abort"
                            and e.get("reason") == "approval_gate" for e in entries))
        aborts = [e for e in entries if e.get("reason") == "approval_gate"]
        self.assertEqual(aborts[0]["phase"], "post")
        executed_post = [e for e in entries
                         if e.get("event") == "action" and e.get("executed")
                         and e.get("plugin") == "post-echo"]
        self.assertEqual(executed_post, [])

    def test_gated_phase_continues_when_approved_interactively(self):
        camp = write_campaign(self.tmp, "gated", "192.0.2.0/24", GATED_PHASES)
        with mock.patch("builtins.input", return_value="y"):
            rc = run_campaign(camp, self.cfg, execute=True, interactive=True)
        self.assertEqual(rc, EXIT_OK)
        entries = self._audit()
        self.assertTrue(any(e.get("event") == "action" and e.get("executed")
                            and e.get("plugin") == "post-echo" for e in entries))
        self.assertTrue(any(e.get("event") == "end" and e.get("status") == "completed"
                            for e in entries))

    def test_gated_phase_denied_when_operator_says_no(self):
        camp = write_campaign(self.tmp, "gated", "192.0.2.0/24", GATED_PHASES)
        with mock.patch("builtins.input", return_value="n"):
            rc = run_campaign(camp, self.cfg, execute=True, interactive=True)
        self.assertEqual(rc, EXIT_ABORTED)
        entries = self._audit()
        self.assertTrue(any(e.get("reason") == "approval_denied" for e in entries))

    def test_execute_against_non_allowlisted_target_is_refused(self):
        camp = write_campaign(self.tmp, "outside", "10.99.0.5")
        rc = run_campaign(camp, self.cfg, execute=True)
        self.assertEqual(rc, EXIT_USAGE)
        self.assertEqual(self._audit(), [])

    def test_post_echo_plugin_needs_interaction(self):
        self.assertTrue(get_plugin("post-echo").requires_approval)
        self.assertTrue(get_plugin("recon-echo").requires_approval is False)

    def test_max_phases_cap_aborts(self):
        camp = write_campaign(self.tmp, "nocap", "192.0.2.0/24")
        rc = run_campaign(camp, self.cfg, execute=False, max_phases=0)
        self.assertEqual(rc, EXIT_ABORTED)
        entries = self._audit()
        self.assertTrue(any(e.get("reason") == "max_phases_reached" for e in entries))


if __name__ == "__main__":
    unittest.main()