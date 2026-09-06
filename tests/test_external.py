"""External-tool adapter safety tests (spec item 6)."""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from firmware.config import Campaign, Opts
from firmware.errors import PluginError, PluginUnavailable
from firmware.orchestrator import RunContext
from firmware.plugins.external import (
    HashcatCrackPlugin,
    MetasploitExploitPlugin,
    NmapScanPlugin,
)
from firmware.plugins import get_plugin


def _ctx(tmp, live=False, targets=("192.0.2.0/24",)):
    import logging

    opts = Opts(allowlist=list(targets), external_tools={"live_execution": live})
    camp = Campaign(id="ext", name="ext", description="",
                    targets=list(targets), phases=[], checksum="x")
    return RunContext(camp, opts, mode="execute",
                      logger=logging.getLogger("f1-test-ext"),
                      audit=None, out_dir=Path(tmp) / "reports")


class ExternalAdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="f1-test-ext-")

    def test_registered(self):
        self.assertIs(get_plugin("nmap-scan"), NmapScanPlugin)
        self.assertIs(get_plugin("metasploit-exploit"), MetasploitExploitPlugin)
        self.assertIs(get_plugin("hashcat-crack"), HashcatCrackPlugin)

    def test_exploit_and_crack_require_approval(self):
        self.assertTrue(MetasploitExploitPlugin.requires_approval)
        self.assertTrue(HashcatCrackPlugin.requires_approval)
        self.assertFalse(NmapScanPlugin.requires_approval)

    def test_dry_run_returns_command_without_tool(self):
        p = NmapScanPlugin(_ctx(self.tmp))
        actions = p.dry_run()
        self.assertEqual(len(actions), 1)
        self.assertIn("nmap", actions[0]["detail"])
        self.assertIn("target", actions[0])

    def test_run_refuses_when_live_execution_disabled(self):
        p = NmapScanPlugin(_ctx(self.tmp, live=False))
        with self.assertRaises(PluginError):
            p.run()

    def test_run_refuses_when_tool_absent(self):
        ctx = _ctx(self.tmp, live=True, targets=("192.168.50.0/24",))
        with mock.patch("firmware.plugins.external.shutil.which", return_value=None):
            p = NmapScanPlugin(ctx)
            with self.assertRaises(PluginUnavailable):
                p.run()

    def test_run_refuses_documentation_range_even_with_tool(self):
        ctx = _ctx(self.tmp, live=True)
        with mock.patch("firmware.plugins.external.shutil.which",
                        return_value="/usr/bin/nmap"):
            p = NmapScanPlugin(ctx)
            with self.assertRaises(PluginError):
                p.run()
        try:
            with mock.patch("firmware.plugins.external.shutil.which",
                            return_value="/usr/bin/nmap"):
                p = NmapScanPlugin(ctx)
                p.run()
        except PluginError as exc:
            self.assertIn("documentation", str(exc))
        else:
            self.fail("expected documentation-range refusal")

    def test_hashcat_adapters_validate_full(self):
        ctx = _ctx(self.tmp, live=True)
        with mock.patch("firmware.plugins.external.shutil.which",
                        return_value="/usr/bin/msfconsole"):
            p = MetasploitExploitPlugin(ctx)
            with self.assertRaises(PluginError):
                p.run()
        with mock.patch("firmware.plugins.external.shutil.which",
                        return_value="/usr/bin/hashcat"):
            p = HashcatCrackPlugin(ctx)
            with self.assertRaises(PluginError):
                p.run()


if __name__ == "__main__":
    unittest.main()