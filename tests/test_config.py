"""Config / campaign YAML loading and validation tests."""

import tempfile
import unittest
from pathlib import Path

from firmware.config import PHASE_NAMES, load_campaign, load_config, load_yaml, load_yaml_str
from firmware.errors import ConfigError

REPO_ROOT = Path(__file__).resolve().parent.parent


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="f1-test-config-")

    def test_orchestrator_config_loads(self):
        cfg = load_config(REPO_ROOT / "config" / "orchestrator.yaml")
        self.assertEqual(cfg.allowlist[0], "192.0.2.0/24")
        self.assertEqual(cfg.output_dir, "reports")
        self.assertEqual(cfg.log_level, "INFO")
        self.assertFalse(cfg.external_tools["live_execution"])

    def test_campaign_files_load_from_fixtures(self):
        for name in ("demo-three-phase", "demo-two-phase-execute",
                     "selftest-three-phase-dryrun",
                     "selftest-two-phase-execute", "selftest-gated-execute"):
            camp = load_campaign(REPO_ROOT / "campaigns" / (name + ".yaml"))
            self.assertEqual(camp.id, name)
            self.assertTrue(camp.targets)
            self.assertTrue(camp.phases)
            self.assertTrue(camp.checksum)
            for p in camp.phases:
                self.assertIn(p.phase, PHASE_NAMES)
                self.assertTrue(p.plugin)

    def test_subset_parser_matches_full_yaml(self):
        yaml_text = (
            "allowlist:\n"
            "  cidrs:\n"
            "    - 192.0.2.0/24\n"
            "    - [a, b, 'x,y']\n"
            "count: 3\n"
            "flag: true\n"
            "note: \"hello # world\"\n"
            "phases:\n"
            "  - phase: recon\n"
            "    plugin: recon-echo\n"
            "    timebox_secs: 5\n"
        )
        parsed = load_yaml_str(yaml_text)
        self.assertEqual(parsed["allowlist"]["cidrs"][0], "192.0.2.0/24")
        self.assertEqual(parsed["allowlist"]["cidrs"][1], ["a", "b", "x,y"])
        self.assertEqual(parsed["count"], 3)
        self.assertIs(parsed["flag"], True)
        self.assertEqual(parsed["note"], "hello # world")
        self.assertEqual(parsed["phases"][0]["phase"], "recon")
        self.assertEqual(parsed["phases"][0]["timebox_secs"], 5)

    def test_bad_phase_name_rejected(self):
        path = Path(self.tmp) / "bad.yaml"
        path.write_text(
            "id: bad\nname: b\ntargets:\n  - 192.0.2.0/24\nphases:\n"
            "  - phase: havoc\n    plugin: recon-echo\n", encoding="utf-8")
        with self.assertRaises(ConfigError):
            load_campaign(path)

    def test_missing_required_key_rejected(self):
        path = Path(self.tmp) / "bad2.yaml"
        path.write_text("id: bad\nname: b\nphases: []\n", encoding="utf-8")
        with self.assertRaises(ConfigError):
            load_campaign(path)

    def test_missing_campaign_file_rejected(self):
        with self.assertRaises(ConfigError):
            load_campaign(Path(self.tmp) / "missing.yaml")

    def test_tabs_rejected_by_subset_parser(self):
        from firmware.config import _SubsetParser

        with self.assertRaises(ConfigError):
            _SubsetParser("a:\n\t- 1\n")


if __name__ == "__main__":
    unittest.main()