"""Report rendering tests (spec item 4)."""

import csv
import json
import tempfile
import unittest
from pathlib import Path

from firmware.config import Campaign, Opts
from firmware.reporting import normalize_severity, write_reports


def _campaign():
    return Campaign(id="test-camp", name="Test campaign", description="desc",
                    targets=["192.0.2.0/24"], phases=[], checksum="abc123")


def _findings():
    return [
        {"id": "F-0001", "phase": "recon", "plugin": "recon-echo",
         "target": "192.0.2.1", "severity": "info",
         "title": "Open service", "evidence": "banner x", "remediation": "close it"},
        {"id": "F-0002", "phase": "post", "plugin": "post-echo",
         "target": "192.0.2.2", "severity": "High",
         "title": "Credential", "evidence": "simulated", "remediation": "rotate"},
    ]


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="f1-test-reports-")
        self.out = Path(self.tmp) / "reports"
        self.phase_times = [
            {"phase": "recon", "plugin": "recon-echo",
             "elapsed_sec": 0.05, "approved": None, "mode": "execute"},
        ]

    def test_normalize_severity(self):
        self.assertEqual(normalize_severity("High"), "high")
        self.assertEqual(normalize_severity("MODERATE"), "medium")
        self.assertEqual(normalize_severity(None), "unknown")
        self.assertEqual(normalize_severity("bogus"), "unknown")

    def test_render_all_formats(self):
        paths = write_reports(self.out, campaign=_campaign(),
                              config=Opts(), mode="execute",
                              findings=_findings(), phase_times=self.phase_times)
        self.assertTrue(paths["findings"].exists())
        self.assertTrue(paths["report"].exists())
        self.assertTrue(paths["summary"].exists())

        doc = json.loads(paths["findings"].read_text(encoding="utf-8"))
        self.assertEqual(doc["campaign"]["id"], "test-camp")
        self.assertEqual(doc["summary"]["total_findings"], 2)
        self.assertEqual(doc["summary"]["by_severity"]["high"], 1)
        self.assertEqual(doc["summary"]["by_severity"]["info"], 1)
        for f in doc["findings"]:
            self.assertTrue(f["severity"] in ("high", "info"))
            self.assertTrue(f["evidence"])
            self.assertTrue(f["remediation"])

        md = paths["report"].read_text(encoding="utf-8")
        self.assertIn("## Findings", md)
        self.assertIn("Open service", md)
        self.assertIn("rotate", md)

        with paths["summary"].open("r", encoding="utf-8", newline="") as fh:
            rows = list(csv.reader(fh))
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0][0], "campaign_id")
        self.assertEqual(rows[1][4], "info")
        self.assertEqual(rows[2][4], "high")

    def test_empty_findings_still_renders(self):
        paths = write_reports(self.out, campaign=_campaign(),
                              config=Opts(), mode="execute",
                              findings=[], phase_times=[])
        doc = json.loads(paths["findings"].read_text(encoding="utf-8"))
        self.assertEqual(doc["summary"]["total_findings"], 0)
        self.assertIn("No findings", paths["report"].read_text(encoding="utf-8"))
        with paths["summary"].open("r", encoding="utf-8", newline="") as fh:
            rows = list(csv.reader(fh))
        self.assertEqual(len(rows), 1)


if __name__ == "__main__":
    unittest.main()