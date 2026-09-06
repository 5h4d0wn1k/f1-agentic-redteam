"""Offline, safe echo plugins bundled as demos.

These plugins PRETEND to perform recon / exploit / post actions against the
campaign targets. They never touch the network: banners and matches are
simulated from a fixed pool, and every finding is labelled as a simulation.
A full campaign can therefore be exercised end-to-end in both dry-run and
--execute modes against the RFC 5737 research placeholder range with zero risk.
"""

import ipaddress

from .. import reporting
from .base import PhasePlugin
from .registry import register

MAX_SAMPLE_HOSTS = 3

_BANNERS = (
    "SSH-2.0-OpenSSH_8.9p1_lab-sim",
    "HTTP/1.1 200 OK (lab-console)",
    "220 lab-ftp SimulatedFTPd ready",
)
_EXPLOIT_NOTES = (
    "signature match CVE-2099-0001 (lab-simulated)",
    "signature match CVE-2099-0002 (lab-simulated)",
)
_POST_NOTES = (
    "simulated credential material staged",
    "simulated privilege-escalation primitive",
)


def expand_sample_hosts(targets, max_hosts=MAX_SAMPLE_HOSTS):
    out = []
    for t in targets:
        try:
            out.append(str(ipaddress.ip_address(str(t))))
            continue
        except ValueError:
            pass
        try:
            net = ipaddress.ip_network(str(t), strict=False)
        except ValueError:
            continue
        n = 0
        for host in net.hosts():
            out.append(str(host))
            n += 1
            if n >= max_hosts:
                break
    return out


@register
class ReconEchoPlugin(PhasePlugin):
    name = "recon-echo"
    title = "Recon echo (offline simulation)"
    phase = "recon"
    description = "Simulates banner/service discovery against the campaign targets without touching the network."

    def dry_run(self):
        actions = []
        for host in expand_sample_hosts(self.ctx.targets):
            actions.append({
                "action": "recon-echo simulate service banner grab",
                "target": host,
                "detail": "would pretend to connect and read a service banner (offline, no network)",
            })
        return actions

    def run(self):
        actions = []
        for i, host in enumerate(expand_sample_hosts(self.ctx.targets)):
            banner = _BANNERS[i % len(_BANNERS)]
            actions.append({
                "action": "recon-echo service banner observed (simulated)",
                "target": host,
                "detail": banner,
            })
            self.ctx.emit_finding(
                severity="info",
                title="Simulated open service on %s" % host,
                evidence=("offline banner grab returned %r; no network contact "
                          "was made" % banner),
                remediation=("Confirm only intended lab services are exposed on "
                             "this host; switch it off if not required."),
                target=host,
                plugin=self.name,
                phase=self.phase,
            )
        return actions


@register
class ExploitEchoPlugin(PhasePlugin):
    name = "exploit-echo"
    title = "Exploit echo (offline simulation)"
    phase = "exploit"
    description = "Simulates a vulnerability-match against the campaign targets; never interacts with the network."

    def dry_run(self):
        actions = []
        for host in expand_sample_hosts(self.ctx.targets):
            actions.append({
                "action": "exploit-echo simulate vulnerability match",
                "target": host,
                "detail": "would compare simulated service fingerprint against a "
                          "signature set (offline, no interaction)",
            })
        return actions

    def run(self):
        actions = []
        for i, host in enumerate(expand_sample_hosts(self.ctx.targets)):
            note = _EXPLOIT_NOTES[i % len(_EXPLOIT_NOTES)]
            actions.append({
                "action": "exploit-echo vulnerability match (simulated)",
                "target": host,
                "detail": note,
            })
            self.ctx.emit_finding(
                severity="medium",
                title="Simulated exploitable service on %s" % host,
                evidence="%s (offline simulation only)" % note,
                remediation=("Apply the vendor patch for the simulated defect and "
                             "restrict the service to lab-only networks."),
                target=host,
                plugin=self.name,
                phase=self.phase,
            )
        return actions


@register
class PostEchoPlugin(PhasePlugin):
    name = "post-echo"
    title = "Post-exploitation echo (offline simulation, approval gate)"
    phase = "post"
    description = "Simulates post-exploitation effects and requires approval before executing."
    requires_approval = True

    def dry_run(self):
        actions = []
        for host in expand_sample_hosts(self.ctx.targets):
            actions.append({
                "action": "post-echo simulate post-exploitation artifact",
                "target": host,
                "detail": "would simulate credential/acl capture (offline, no interaction)",
            })
        return actions

    def run(self):
        actions = []
        for i, host in enumerate(expand_sample_hosts(self.ctx.targets)):
            note = _POST_NOTES[i % len(_POST_NOTES)]
            actions.append({
                "action": "post-echo post-exploitation artifact (simulated)",
                "target": host,
                "detail": note,
            })
            self.ctx.emit_finding(
                severity="high",
                title="Simulated post-exploitation artifact on %s" % host,
                evidence="%s (offline simulation only)" % note,
                remediation=("Treat this as a drill: rotate lab credentials, review "
                             "ACLs and audit local persistence on the lab host."),
                target=host,
                plugin=self.name,
                phase=self.phase,
            )
        return actions


@register
class EchoFindingsPlugin(PhasePlugin):
    name = "echo-findings"
    title = "Findings + report renderer"
    phase = "report"
    description = "Renders structured findings.json, markdown report and CSV summary for the campaign."

    def dry_run(self):
        return [{
            "action": "write campaign reports (findings.json, report.md, summary.csv)",
            "target": self.ctx.campaign.id,
            "detail": "report artefacts would be written under %s" % self.ctx.out_dir,
        }]

    def run(self):
        if not self.ctx.findings:
            self._append_gentle_sample_findings()
        paths = reporting.write_reports(
            self.ctx.out_dir,
            campaign=self.ctx.campaign,
            config=self.ctx.config,
            mode=self.ctx.mode,
            findings=self.ctx.findings,
            phase_times=self.ctx.phase_times,
            status="completed",
        )
        self.ctx.report_written = True
        return [{
            "action": "wrote campaign reports",
            "target": self.ctx.campaign.id,
            "detail": "%s, %s, %s" % (paths["findings"], paths["report"], paths["summary"]),
        }]

    def _append_gentle_sample_findings(self):
        target = self.ctx.targets[0] if self.ctx.targets else "n/a"
        self.ctx.emit_finding(
            severity="info",
            title="Sample finding: campaign produced no earlier findings",
            evidence=("No recon/exploit/post plugin emitted findings; this gentle "
                      "sample was generated offline so a demo report has content."),
            remediation=("Add recon/exploit/post phases before the report phase to "
                         "collect real (or simulated) findings."),
            target=target,
            plugin=self.name,
            phase=self.phase,
        )