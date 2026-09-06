"""Structured reporting: findings JSON, markdown report, CSV summary."""

import csv
import json
from pathlib import Path

from .util import now_iso

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info", "unknown")

_SEVERITY_ALIASES = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    "unknown": "unknown",
}


def normalize_severity(value):
    if value is None:
        return "unknown"
    return _SEVERITY_ALIASES.get(str(value).strip().lower(), "unknown")


def _one_line(text):
    return " ".join(str(text).replace("\r", " ").replace("\n", " ").split())


def _normalized_findings(findings):
    out = []
    for f in findings:
        f = dict(f)
        f["severity"] = normalize_severity(f.get("severity"))
        out.append(f)
    return out


def write_reports(out_dir, *, campaign, config, mode, findings, phase_times,
                  status="completed", reason=None):
    out_dir = Path(out_dir)
    cdir = out_dir / campaign.id
    cdir.mkdir(parents=True, exist_ok=True)
    generated_at = now_iso()
    findings = _normalized_findings(findings)
    by_severity = {}
    for f in findings:
        sev = f.get("severity", "unknown")
        by_severity[sev] = by_severity.get(sev, 0) + 1

    doc = {
        "campaign": {
            "id": campaign.id,
            "name": campaign.name,
            "description": campaign.description,
            "targets": campaign.targets,
            "campaign_sha256": campaign.checksum,
        },
        "mode": mode,
        "status": status,
        "reason": reason,
        "generated_at": generated_at,
        "phase_timings": phase_times,
        "findings": findings,
        "summary": {
            "total_findings": len(findings),
            "by_severity": by_severity,
            "gates_honored": True,
        },
    }

    findings_path = cdir / "findings.json"
    with findings_path.open("w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, sort_keys=True)
        fh.write("\n")

    report_path = cdir / "report.md"
    with report_path.open("w", encoding="utf-8") as fh:
        fh.write(render_markdown(doc))

    summary_path = cdir / "summary.csv"
    with summary_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["campaign_id", "phase", "plugin", "target", "severity",
                         "title", "evidence", "remediation"])
        for f in findings:
            writer.writerow([
                campaign.id,
                f.get("phase", ""),
                f.get("plugin", ""),
                f.get("target", ""),
                f.get("severity", ""),
                _one_line(f.get("title", "")),
                _one_line(f.get("evidence", "")),
                _one_line(f.get("remediation", "")),
            ])

    return {"dir": cdir, "findings": findings_path,
            "report": report_path, "summary": summary_path}


def render_markdown(doc):
    lines = []
    c = doc["campaign"]
    lines.append("# %s" % c["name"])
    lines.append("")
    lines.append("Campaign report produced by f1-agentic-redteam "
                 "(authorized lab testing only).")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("|---|---|")
    lines.append("| Campaign ID | `%s` |" % c["id"])
    lines.append("| Description | %s |" % c.get("description", ""))
    lines.append("| Targets | %s |" % ", ".join(c["targets"]))
    lines.append("| Mode | %s |" % doc["mode"])
    lines.append("| Status | %s |" % doc["status"])
    lines.append("| Campaign file sha256 | `%s` |" % c["campaign_sha256"])
    lines.append("| Generated at | %s |" % doc["generated_at"])
    lines.append("")
    lines.append("## Phase timings")
    lines.append("")
    lines.append("| # | Phase | Plugin | Elapsed (s) | Approved | Mode |")
    lines.append("|---|---|---|---|---|---|")
    if doc["phase_timings"]:
        for i, pt in enumerate(doc["phase_timings"], start=1):
            lines.append("| %d | %s | %s | %.2f | %s | %s |" % (
                i,
                pt.get("phase", ""),
                pt.get("plugin", ""),
                float(pt.get("elapsed_sec", 0.0)),
                pt.get("approved", "n/a"),
                pt.get("mode", "")))
    else:
        lines.append("| - | (none) | | | | |")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    lines.append("Total: **%d** %s" % (
        doc["summary"]["total_findings"], _severity_badge_counts(doc["summary"])))
    lines.append("")
    findings = doc["findings"]
    if not findings:
        lines.append("No findings were collected for this campaign.")
        lines.append("")
    for sev in SEVERITY_ORDER:
        group = [f for f in findings if f.get("severity") == sev]
        if not group:
            continue
        for f in group:
            lines.append("### [%s] %s" % (f["severity"].upper(), f["title"]))
            lines.append("")
            lines.append("- **ID**: `%s`" % f["id"])
            lines.append("- **Phase / plugin**: %s / %s" % (f["phase"], f["plugin"]))
            lines.append("- **Target**: %s" % f["target"])
            lines.append("- **Severity**: %s" % f["severity"])
            lines.append("")
            lines.append("**Evidence:**")
            lines.append("")
            lines.append("```")
            lines.append(str(f.get("evidence", "") or "(none)"))
            lines.append("```")
            lines.append("")
            lines.append("**Remediation:**")
            lines.append("")
            lines.append(str(f.get("remediation", "") or "(none)"))
            lines.append("")
    lines.append("---")
    lines.append("Report generated by f1-agentic-redteam. All actions and this "
                 "campaign file are recorded in logs/campaign.jsonl.")
    lines.append("")
    return "\n".join(lines)


def _severity_badge_counts(summary):
    by = summary.get("by_severity", {})
    bits = ["%s=%d" % (k, v) for k, v in sorted(by.items())]
    return " | ".join(bits) if bits else ""