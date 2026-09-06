"""Offline self-test: verifies dry-run, execute, reports and gate abort.

Runs three campaigns on the RFC 5737 placeholder allowlist using only offline
echo plugins, then asserts on the JSONL audit log, structured reports and the
approval-gate abort behaviour. Exits 0 only when every check passes.
"""

import json
import sys
import tempfile
from pathlib import Path

from .audit import AuditLog
from .config import load_config
from .errors import EXIT_ABORTED, EXIT_OK
from .orchestrator import run_campaign
from .util import setup_logging, sha256_file

REPO_ROOT = Path(__file__).resolve().parent.parent

SELFTEST_CAMPAIGNS = (
    ("selftest-three-phase-dryrun.yaml", "A"),
    ("selftest-two-phase-execute.yaml", "B"),
    ("selftest-gated-execute.yaml", "C"),
)


class _Check(object):
    def __init__(self):
        self.total = 0
        self.passed = 0
        self.failed = []

    def check(self, label, condition, detail=""):
        self.total += 1
        if condition:
            self.passed += 1
            print("  [ ok ] %s" % label)
        else:
            self.failed.append(label)
            print("  [FAIL] %s%s" % (label, ("  -- " + detail) if detail else ""))


def _campaign_path(name):
    return REPO_ROOT / "campaigns" / name


def run_selftest(work_root=None):
    print("\n=== F1 offline self-test ===")
    if work_root is None:
        work_root = Path(tempfile.mkdtemp(prefix="f1-selftest-"))
    work_root = Path(work_root)
    wr = work_root / "reports"
    wl = work_root / "logs"
    audit_path = wl / "campaign.jsonl"
    config = load_config(REPO_ROOT / "config" / "orchestrator.yaml")
    checks = _Check()

    def run_cfg(path, execute, interactive=False, max_phases=None):
        return run_campaign(
            path, config, execute=execute, interactive=interactive,
            max_phases=max_phases, out_dir=wr, audit_path=audit_path,
            log_dir=wl, log_level="INFO")

    # ---- Stage A: three-phase dry-run -----------------------------------
    print("\nStage A: 3-phase dry-run campaign (offline echo plugins)")
    ca = _campaign_path("selftest-three-phase-dryrun.yaml")
    ra = run_cfg(ca, execute=False)
    checks.check("dry-run campaign exits 0", ra == EXIT_OK, "rc=%d" % ra)
    entries = AuditLog(audit_path).read_entries()
    actions_a = [e for e in entries if e.get("event") == "action"
                 and e.get("mode") == "dry-run"]
    checks.check("audit log has >=3 dry-run action entries", len(actions_a) >= 3,
                 "got %d" % len(actions_a))
    checks.check("dry-run actions all executed=false",
                 all(not e.get("executed") for e in actions_a))
    checks.check("every action entry has ts/phase/plugin/target/sha256",
                 all(e.get("ts") and e.get("phase") and e.get("plugin")
                     and e.get("target") and e.get("campaign_sha256")
                     for e in actions_a))
    checks.check("campaign checksum in audit matches campaign file",
                 bool(actions_a) and all(
                     e["campaign_sha256"] == sha256_file(ca) for e in actions_a))
    checks.check("dry-run produces no reports",
                 not (wr / "selftest-three-phase-dryrun").exists())

    # ---- Stage B: two-phase execute campaign ---------------------------
    print("\nStage B: 2-phase execute campaign (offline echo plugins)")
    cb = _campaign_path("selftest-two-phase-execute.yaml")
    rb = run_cfg(cb, execute=True)
    checks.check("execute campaign exits 0", rb == EXIT_OK, "rc=%d" % rb)
    entries = AuditLog(audit_path).read_entries()
    actions_b = [e for e in entries if e.get("event") == "action"
                 and e.get("mode") == "execute"
                 and e.get("campaign_id") == "selftest-two-phase-execute"]
    checks.check("audit log has executed action entries", len(actions_b) >= 1,
                 "got %d" % len(actions_b))
    checks.check("execute actions all executed=true",
                 all(e.get("executed") for e in actions_b))

    fdir = wr / "selftest-two-phase-execute"
    checks.check("findings.json written", (fdir / "findings.json").exists())
    checks.check("report.md written", (fdir / "report.md").exists())
    checks.check("summary.csv written", (fdir / "summary.csv").exists())
    try:
        with (fdir / "findings.json").open("r", encoding="utf-8") as fh:
            doc = json.load(fh)
        findings = doc["findings"]
        checks.check("findings list is non-empty", len(findings) > 0,
                     "got %d" % len(findings))
        checks.check("every finding has severity/evidence/remediation",
                     all(f.get("severity") and f.get("evidence")
                         and f.get("remediation") for f in findings))
        checks.check("summary.total matches findings length",
                     doc["summary"]["total_findings"] == len(findings))
        md = (fdir / "report.md").read_text(encoding="utf-8")
        checks.check("report.md contains a finding title",
                     any(f["title"] in md for f in findings))
    except Exception as exc:
        checks.check("report artefacts parse correctly", False, str(exc))

    print("\nStage C: approval gate aborts in non-interactive mode")
    cc = _campaign_path("selftest-gated-execute.yaml")
    rc_ = run_cfg(cc, execute=True)
    checks.check("gated campaign aborts with EXIT_ABORTED", rc_ == EXIT_ABORTED,
                 "rc=%d" % rc_)
    entries = AuditLog(audit_path).read_entries()
    aborts = [e for e in entries if e.get("event") == "abort"
              and e.get("reason") == "approval_gate"
              and e.get("campaign_id") == "selftest-gated-execute"]
    checks.check("audit contains approval_gate abort entry", len(aborts) >= 1)
    checks.check("no executed post-echo actions (no auto-continue)",
                 not any(e.get("event") == "action" and e.get("executed")
                         and e.get("plugin") == "post-echo" for e in entries))
    checks.check("no 'completed' end entry for aborted campaign",
                 not any(e.get("event") == "end" and e.get("status") == "completed"
                         and e.get("campaign_id") == "selftest-gated-execute"
                         for e in entries))

    print("\n=== SELFTEST RESULT ===")
    print("  checks run : %d" % checks.total)
    print("  checks pass: %d" % checks.passed)
    if checks.failed:
        print("  FAILED     : %d -> %s" % (len(checks.failed),
                                           ", ".join(checks.failed)))
        return 1
    print("  PASS (exit 0)")
    return EXIT_OK


def main(argv=None):
    return run_selftest()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))