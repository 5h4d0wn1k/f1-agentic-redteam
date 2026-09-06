"""Campaign runner: dry-run/execute orchestration with hard safety rails.

Non-negotiable behaviour:
  * default mode is dry-run - nothing executes, every planned action prints;
  * --execute requires every target inside the configured allowlist;
  * every action is appended to the JSONL audit log with ts/phase/plugin/target
    and the sha256 checksum of the campaign file;
  * a phase that requires approval ABORTS the campaign in non-interactive mode;
  * SIGINT and --max-phases cap the campaign hard.
"""

import sys
import time
from pathlib import Path

from . import reporting
from .allowlist import Allowlist
from .audit import AuditLog
from .config import load_campaign
from .errors import (
    EXIT_ABORTED,
    EXIT_SIGINT,
    EXIT_USAGE,
    ApprovalGateAbort,
    ConfigError,
    MaxPhasesAbort,
    RTError,
    TimeboxAbort,
    UnknownPlugin,
)
from .plugins import get_plugin
from .util import now_iso, setup_logging

DRY_RUN_BANNER = ("\n### DRY-RUN MODE ###\n"
                  "Nothing will be executed. Planned actions are printed and "
                  "audited only. Re-run with --execute to execute them against "
                  "allowlisted lab targets.\n")


class RunContext(object):
    def __init__(self, campaign, config, *, mode, logger, audit, out_dir):
        self.campaign = campaign
        self.config = config
        self.mode = mode
        self.logger = logger
        self.audit = audit
        self.out_dir = Path(out_dir)
        self.targets = list(campaign.targets)
        self.findings = []
        self.phase_times = []
        self.report_written = False
        self._fid = 0

    def emit_finding(self, *, severity="info", title, evidence="",
                     remediation="", target="", plugin="", phase=""):
        sev = reporting.normalize_severity(severity)
        self._fid += 1
        finding = {
            "id": "F-%04d" % self._fid,
            "campaign_id": self.campaign.id,
            "phase": phase or "unknown",
            "plugin": plugin or "unknown",
            "target": target,
            "severity": sev,
            "title": title,
            "evidence": evidence,
            "remediation": remediation,
            "timestamp": now_iso(),
        }
        self.findings.append(finding)
        self.logger.info("finding [%s] %s target=%r", sev, title, target)
        return finding


def _prompt_approval(campaign, phase, plugin):
    print("\n=== APPROVAL GATE ===")
    print("Campaign: %s (%s)" % (campaign.id, campaign.name))
    print("Phase   : %s (plugin: %s)" % (phase.phase, phase.plugin))
    print("Targets : %s" % ", ".join(campaign.targets))
    try:
        answer = input("Approve executing this phase against these lab targets? [y/N]: ")
    except EOFError:
        return False
    return answer.strip().lower() in ("y", "yes")


def run_campaign(campaign_path, config, *, execute=False, interactive=False,
                 max_phases=None, out_dir=None, audit_path=None,
                 log_dir="logs", log_level="INFO"):
    """Run a single campaign and return a process exit code."""
    try:
        campaign = load_campaign(campaign_path)
    except (ConfigError, OSError) as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return EXIT_USAGE

    logger = setup_logging(log_dir, log_level, log_file=(config.log_file or "orchestrator.log"))

    if execute:
        logger.info("campaign %s starting in EXECUTE mode", campaign.id)
    else:
        logger.info("campaign %s starting in DRY-RUN mode", campaign.id)

    allow = Allowlist(config.allowlist)
    bad = allow.validate_all(campaign.targets)
    if bad:
        for target, msg in bad:
            logger.error("target blocked: %s", msg)
        print("ERROR: campaign %s has targets outside the configured allowlist:"
              % campaign.id, file=sys.stderr)
        for target, msg in bad:
            print("  - %s (%s)" % (target, msg), file=sys.stderr)
        print("  Add the lab CIDR to config/orchestrator.yaml 'allowlist.cidrs'.",
              file=sys.stderr)
        return EXIT_USAGE

    out_root = Path(out_dir or config.output_dir)
    audit = AuditLog(audit_path or config.audit_log)
    audit.start(mode="execute" if execute else "dry-run",
                campaign_id=campaign.id,
                campaign_sha256=campaign.checksum,
                targets=campaign.targets)

    ctx = RunContext(campaign, config, mode="execute" if execute else "dry-run",
                     logger=logger, audit=audit, out_dir=out_root)
    cap = max_phases if max_phases is not None else campaign.max_phases

    try:
        for index, phase in enumerate(campaign.phases):
            if index >= cap:
                audit.abort(reason="max_phases_reached", campaign_id=campaign.id,
                            campaign_sha256=campaign.checksum, phase=phase.phase,
                            plugin=phase.plugin,
                            detail="phase index %d exceeds --max-phases cap %d"
                                   % (index, cap))
                logger.error("ABORT: max-phases cap (%d) reached at phase index %d",
                             cap, index)
                return EXIT_ABORTED

            plugin_cls = get_plugin(phase.plugin)
            if plugin_cls is None:
                audit.abort(reason="unknown_plugin", campaign_id=campaign.id,
                            campaign_sha256=campaign.checksum, phase=phase.phase,
                            plugin=phase.plugin,
                            detail="no plugin registered for %r" % phase.plugin)
                logger.error("ABORT: unknown plugin %r", phase.plugin)
                return EXIT_USAGE

            plugin = plugin_cls(ctx, params=phase.params)
            gate = bool(phase.requires_approval or plugin.needs_interaction())
            t0 = time.monotonic()
            summary = {"phase": phase.phase, "plugin": phase.plugin}

            if not execute:
                logger.info("phase %s/%s: planning (dry-run, gate=%s)",
                            phase.phase, phase.plugin, gate)
                if gate:
                    print("[GATE] phase %s requires approval - noted in dry-run "
                          "(would prompt before executing)" % phase.phase)
                actions = plugin.dry_run() or []
                for a in actions:
                    target = a.get("target", campaign.targets[0])
                    detail = a.get("detail", "")
                    print("[DRY-RUN] phase=%-8s plugin=%-12s target=%-15s action=%s"
                          % (phase.phase, phase.plugin, target,
                             a.get("action", "noop")))
                    if detail:
                        print("           %s" % detail)
                    audit.action(mode="dry-run",
                                 campaign_id=campaign.id,
                                 campaign_sha256=campaign.checksum,
                                 phase=phase.phase, plugin=phase.plugin,
                                 target=target,
                                 action=a.get("action", "noop"),
                                 detail=detail,
                                 executed=False)
                summary.update(mode="dry-run", approved=None,
                               elapsed_sec=round(time.monotonic() - t0, 3))
                ctx.phase_times.append(summary)
                continue

            if gate:
                if not interactive:
                    audit.abort(reason="approval_gate", campaign_id=campaign.id,
                                campaign_sha256=campaign.checksum, phase=phase.phase,
                                plugin=phase.plugin,
                                detail=("phase requires approval and the run is "
                                        "non-interactive; aborting instead of "
                                        "auto-continuing"))
                    logger.error("ABORT: phase %s/%s requires approval and this "
                                 "run is non-interactive. No auto-continue.",
                                 phase.phase, phase.plugin)
                    print("ABORT: approval gate encountered for phase %s in "
                          "non-interactive mode. campaign NOT continued."
                          % phase.phase, file=sys.stderr)
                    return EXIT_ABORTED
                if not _prompt_approval(campaign, phase, plugin):
                    audit.abort(reason="approval_denied", campaign_id=campaign.id,
                                campaign_sha256=campaign.checksum, phase=phase.phase,
                                plugin=phase.plugin)
                    logger.error("ABORT: approval denied for phase %s", phase.phase)
                    return EXIT_ABORTED
                print(">> Approval granted for phase %s (plugin %s)."
                      % (phase.phase, phase.plugin))

            logger.info("phase %s/%s: executing", phase.phase, phase.plugin)
            actions = plugin.run() or []
            for a in actions:
                target = a.get("target", campaign.targets[0])
                detail = a.get("detail", "")
                print("[EXEC] phase=%-8s plugin=%-12s target=%-15s action=%s"
                      % (phase.phase, phase.plugin, target, a.get("action", "noop")))
                if detail:
                    print("         %s" % detail)
                audit.action(mode="execute",
                             campaign_id=campaign.id,
                             campaign_sha256=campaign.checksum,
                             phase=phase.phase, plugin=phase.plugin,
                             target=target,
                             action=a.get("action", "noop"),
                             detail=detail,
                             executed=True)

            elapsed = time.monotonic() - t0
            summary.update(mode="execute", approved=gate, elapsed_sec=round(elapsed, 3))
            ctx.phase_times.append(summary)

            if phase.timebox_secs is not None and elapsed > phase.timebox_secs:
                audit.abort(reason="timebox_exceeded", campaign_id=campaign.id,
                            campaign_sha256=campaign.checksum, phase=phase.phase,
                            plugin=phase.plugin,
                            detail="phase took %.2fs, timebox %.2fs"
                                   % (elapsed, phase.timebox_secs))
                logger.error("ABORT: phase %s/%s exceeded its %.0fs timebox",
                             phase.phase, phase.plugin, phase.timebox_secs)
                return EXIT_ABORTED
    except KeyboardInterrupt:
        audit.abort(reason="sigint", campaign_id=campaign.id,
                    campaign_sha256=campaign.checksum,
                    detail="operator SIGINT (hard kill)")
        logger.warning("campaign %s aborted by SIGINT", campaign.id)
        print("ABORT: SIGINT received - campaign halted. See audit log.",
              file=sys.stderr)
        return EXIT_SIGINT

    if ctx.mode == "execute" and not ctx.report_written:
        reporting.write_reports(
            out_root, campaign=campaign, config=config, mode=ctx.mode,
            findings=ctx.findings, phase_times=ctx.phase_times, status="completed")
        audit.end(status="completed", campaign_id=campaign.id,
                  campaign_sha256=campaign.checksum)
    else:
        audit.end(status="completed", campaign_id=campaign.id,
                  campaign_sha256=campaign.checksum,
                  detail="dry-run: no report artefacts written")

    print("\n### CAMPAIGN SUMMARY: %s" % campaign.id)
    print("Mode           : %s" % ctx.mode)
    print("Targets        : %s" % ", ".join(campaign.targets))
    print("Phases ran     : %d" % len(ctx.phase_times))
    print("Findings       : %d total" % len(ctx.findings))
    if ctx.findings:
        counts = {}
        for f in ctx.findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        print("  by severity  : %s" % ", ".join("%s=%d" % kv for kv in sorted(counts.items())))
    print("Reports        : %s" % ((out_root / campaign.id)
                                    if ctx.mode == "execute"
                                    else "(dry-run - no artefacts written)"))
    print("Audit log      : %s" % audit.path)
    logger.info("campaign %s completed ok", campaign.id)
    return 0