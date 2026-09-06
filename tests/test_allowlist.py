"""Allowlist validation tests (safety rail (b))."""

import unittest
from pathlib import Path

from firmware.allowlist import Allowlist, is_documentation_target
from firmware.config import load_config
from firmware.errors import ConfigError

REPO_ROOT = Path(__file__).resolve().parent.parent


class AllowlistTests(unittest.TestCase):
    def setUp(self):
        self.al = Allowlist(["192.0.2.0/24", "198.51.100.0/24"])

    def test_allows_host_in_range(self):
        ok, _ = self.al.validate("192.0.2.7")
        self.assertTrue(ok)

    def test_rejects_host_outside_range(self):
        ok, msg = self.al.validate("10.0.0.7")
        self.assertFalse(ok)
        self.assertIn("allowlist", msg)

    def test_allows_contained_subnet(self):
        ok, _ = self.al.validate("192.0.2.128/25")
        self.assertTrue(ok)

    def test_rejects_non_contained_subnet(self):
        ok, _ = self.al.validate("192.0.3.0/24")
        self.assertFalse(ok)

    def test_rejects_hostname(self):
        ok, msg = self.al.validate("lab-ap.lan")
        self.assertFalse(ok)
        self.assertIn("hostnames", msg)

    def test_rejects_garbage(self):
        ok, _ = self.al.validate("not-an-address")
        self.assertFalse(ok)

    def test_empty_allowlist_refused_at_construction(self):
        with self.assertRaises(ConfigError):
            Allowlist([])

    def test_validate_all_collects_bad(self):
        bad = self.al.validate_all(["192.0.2.1", "1.1.1.1"])
        self.assertEqual(len(bad), 1)
        self.assertEqual(bad[0][0], "1.1.1.1")

    def test_documentation_range_detection(self):
        self.assertTrue(is_documentation_target("192.0.2.9"))
        self.assertTrue(is_documentation_target("203.0.113.0/24"))
        self.assertFalse(is_documentation_target("192.168.1.10"))

    def test_default_config_allowlist_loads(self):
        config = load_config(REPO_ROOT / "config" / "orchestrator.yaml")
        self.assertIn("192.0.2.0/24", config.allowlist)
        self.assertFalse(config.external_tools.get("live_execution"))


if __name__ == "__main__":
    unittest.main()