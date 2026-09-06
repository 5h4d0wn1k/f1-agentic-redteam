"""External-tool adapters: nmap, metasploit, hashcat.

These plugins NEVER shell out blindly:
  * they validate the tool is present on PATH and refuse when absent;
  * they refuse to execute against RFC 5737 documentation ranges (they cannot
    be a real lab);
  * they refuse to execute unless config external_tools.live_execution is
    explicitly set to true;
  * all subprocesses are launched with an explicit argv list and no shell.

dry_run() only prints the exact command that would run.
"""

import shlex
import shutil
import subprocess

from ..allowlist import is_documentation_target
from ..errors import PluginError, PluginUnavailable
from .base import PhasePlugin
from .registry import register


def _require_tool(name):
    tool = shutil.which(name)
    if not tool:
        raise PluginUnavailable(
            "external tool %r not found on PATH; install it or use an "
            "offline echo plugin instead" % name)
    return tool


def _require_live_execution(config):
    if not config.external_tools.get("live_execution"):
        raise PluginError(
            "live execution is disabled (config external_tools.live_execution "
            "is false). Set it to true ONLY when running against your own lab.")


def _reject_documentation_targets(targets, tool):
    for t in targets:
        if is_documentation_target(t):
            raise PluginError(
                "refusing to run %s against documentation range %s "
                "(RFC 5737); these ranges are placeholders, not a real lab. "
                "Point the campaign at YOUR OWN lab CIDR and allowlist it." % (tool, t))


def _run_command(cmd, timeout=300):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


@register
class NmapScanPlugin(PhasePlugin):
    name = "nmap-scan"
    title = "Nmap service scan adapter"
    phase = "recon"
    description = "External nmap adapter: service discovery against allowlisted lab targets."

    def _command(self, targets):
        return ["nmap", "-sV", "-p", "22,80,443,8080", "--open", "-oG", "-"] + list(targets)

    def dry_run(self):
        cmd = self._command(self.ctx.targets)
        return [{
            "action": "run external tool nmap (service scan)",
            "target": ", ".join(self.ctx.targets),
            "detail": shlex.join(cmd),
        }]

    def run(self):
        self.ctx.logger.warning("nmap-scan: live execution requested")
        _require_live_execution(self.ctx.config)
        _reject_documentation_targets(self.ctx.targets, "nmap")
        tool = _require_tool("nmap")
        cmd = self._command(self.ctx.targets)
        try:
            proc = _run_command(cmd, timeout=int(self.params.get("timeout_sec", 300)))
        except subprocess.TimeoutExpired:
            raise PluginError("nmap-scan timed out")
        actions = []
        for line in proc.stdout.splitlines():
            if not line.startswith("Host:"):
                continue
            host = line.split()[1]
            ports = line.split("Ports:")[1].split(",") if "Ports:" in line else []
            for port in ports:
                parts = [p.strip() for p in port.split("/")]
                if len(parts) < 5:
                    continue
                action = "nmap found open %s/tcp (%s)" % (parts[0], parts[4] or "?")
                actions.append({"action": action, "target": host, "detail": line.strip()})
                self.ctx.emit_finding(
                    severity="info",
                    title="Open service on %s" % host,
                    evidence=line.strip(),
                    remediation=("Close unused services on the lab host or move "
                                 "them behind the lab firewall."),
                    target=host,
                    plugin=self.name,
                    phase=self.phase,
                )
        return actions or [{
            "action": "nmap scan completed (no open services parsed by this adapter)",
            "target": ", ".join(self.ctx.targets),
            "detail": "rc=%d" % proc.returncode,
        }]


@register
class MetasploitExploitPlugin(PhasePlugin):
    name = "metasploit-exploit"
    title = "Metasploit exploit adapter"
    phase = "exploit"
    description = "External msfconsole adapter; requires approval and explicit live execution."
    requires_approval = True

    def _command(self):
        module = self.params.get("module", "auxiliary/scanner/ssh/ssh_login")
        resource = "use %s\nset RHOSTS %s\nrun\n" % (module, " ".join(self.ctx.targets))
        return ["msfconsole", "-q", "-x", resource]

    def dry_run(self):
        cmd = self._command()
        return [{
            "action": "run external tool msfconsole (module %s)" % self.params.get("module"),
            "target": " ".join(self.ctx.targets),
            "detail": shlex.join(cmd),
        }]

    def run(self):
        self.ctx.logger.warning("metasploit-exploit: live execution requested")
        _require_live_execution(self.ctx.config)
        _reject_documentation_targets(self.ctx.targets, "msfconsole")
        tool = _require_tool("msfconsole")
        cmd = self._command()
        try:
            proc = _run_command(cmd, timeout=int(self.params.get("timeout_sec", 600)))
        except subprocess.TimeoutExpired:
            raise PluginError("metasploit-exploit timed out")
        hits = [ln for ln in proc.stdout.splitlines() if ln.strip().startswith("[*]")]
        evidence = "\n".join(hits[:8]) or ("msfconsole finished rc=%d" % proc.returncode)
        self.ctx.emit_finding(
            severity="high",
            title="Simulated exploit session against metasploit module",
            evidence=evidence,
            remediation=("Run this only as an authorized test on your own lab; "
                         "remediate any confirmed access immediately."),
            target=", ".join(self.ctx.targets),
            plugin=self.name,
            phase=self.phase,
        )
        return [{
            "action": "msfconsole module executed",
            "target": ", ".join(self.ctx.targets),
            "detail": "rc=%d (see finding evidence)" % proc.returncode,
        }]


@register
class HashcatCrackPlugin(PhasePlugin):
    name = "hashcat-crack"
    title = "Hashcat hash-recovery adapter"
    phase = "post"
    description = "External hashcat adapter for recovering lab hash files; requires approval."
    requires_approval = True

    def _command(self):
        hash_file = self.params.get("hash_file", "")
        wordlist = self.params.get("wordlist", "")
        mode = self.params.get("mode", 0)
        return ["hashcat", "-m", str(mode), "-a", "0", hash_file, wordlist]

    def dry_run(self):
        cmd = self._command()
        return [{
            "action": "run external tool hashcat (mode %s)" % self.params.get("mode"),
            "target": self.params.get("hash_file", "?") or self.ctx.targets[0],
            "detail": shlex.join(cmd),
        }]

    def run(self):
        self.ctx.logger.warning("hashcat-crack: live execution requested")
        _require_live_execution(self.ctx.config)
        _reject_documentation_targets(self.ctx.targets, "hashcat")
        tool = _require_tool("hashcat")
        hash_file = self.params.get("hash_file", "")
        wordlist = self.params.get("wordlist", "")
        if not hash_file or not wordlist:
            raise PluginError("hashcat-crack needs params: hash_file and wordlist")
        cmd = self._command()
        try:
            proc = _run_command(cmd, timeout=int(self.params.get("timeout_sec", 900)))
        except subprocess.TimeoutExpired:
            raise PluginError("hashcat-crack timed out")
        cracked = [ln for ln in proc.stdout.splitlines()
                   if ":" in ln and ln.strip() and "(?" not in ln]
        evidence = "\n".join(cracked[:5]) or ("hashcat finished rc=%d" % proc.returncode)
        self.ctx.emit_finding(
            severity="high",
            title="Recovered lab hash material",
            evidence=evidence,
            remediation=("Rotate the recovered lab credentials and re-check "
                         "password policy; this is an authorized lab exercise only."),
            target=hash_file,
            plugin=self.name,
            phase=self.phase,
        )
        return [{
            "action": "hashcat executed against lab hash file",
            "target": hash_file,
            "detail": "rc=%d (see finding evidence)" % proc.returncode,
        }]