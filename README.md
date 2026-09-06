# F1 — Agentic Red-Team Campaign Orchestrator

Production-grade campaign orchestrator for **authorized security testing against
your own lab range**. Phases are plugins (`recon` → `exploit` → `post` →
`report`), campaigns are YAML, every action is audited, and hard safety rails
make accidental execution against non-lab targets impossible.

- **Stdlib-first Python 3** — runs with zero dependencies (PyYAML optional for
  full-featured YAML).
- **Dry-run by default** — executes nothing unless you pass `--execute`.
- **Allowlist-gated targets** — every target must fall inside the lab CIDRs in
  `config/orchestrator.yaml`.
- **JSONL audit log** — every action is recorded with timestamp, phase, plugin,
  target, and the sha256 checksum of the campaign file.
- **Approval gates** — phases marked `requires_approval` stop for confirmation;
  in non-interactive mode they **abort the campaign**, never auto-continue.
- **Structured reports** — `findings.json`, human `report.md`, and a CSV summary.
- **Offline self-test** — proves dry-run, execute, reports, and gate-abort
  behaviour with zero network access.

> Activates only campaigns you author. The bundled echo plugins are fully
> offline; nmap / msfconsole / hashcat adapters validate tool presence, refuse
> documentation ranges, and require `external_tools.live_execution: true`.

## Installation

```bash
python3 -m pip install -e .          # optional; installs the f1-redteam script
python3 -m firmware --help           # works without any install
```

Both entry points behave identically: `f1-redteam run ...` and
`python3 -m firmware run ...`.

## Quick start

```bash
python3 -m firmware selftest                                   # offline self-test, exit 0
python3 -m firmware list-plugins                               # registered plugins
python3 -m firmware run --campaign campaigns/demo-two-phase-execute.yaml
python3 -m firmware run --campaign campaigns/demo-two-phase-execute.yaml --execute
```

`run` without `--execute` is a dry run: it prints every planned action, appends
them to the audit log with `"executed": false`, and writes no report artefacts.

## Architecture

```
campaigns/*.yaml  ─┐
config/orchestrator.yaml ─┼─▶ firmware/orchestrator.run_campaign()
                    │          │  validation (allowlist, checksum, phases)
                    │          ▼
                    │      plugins/<name>   ▶ Severity-filled findings
                    │          │
                    ▼          ▼
per-action JSONL audit ──▶ logs/campaign.jsonl   (+ logs/orchestrator.log)
                    ▼
report phase ──▶ reports/<campaign-id>/{findings.json, report.md, summary.csv}
```

### Plugin registry

Each phase is a plugin class implementing:

| Method | Purpose |
|---|---|
| `run()` | Performs the phase in execute mode; may emit findings via the run context |
| `dry_run()` | Returns the exact planned actions without doing anything |
| `needs_interaction()` | True for plugins that require an approval gate |

Bundled plugins:

| Plugin | Phase | Approval | Description |
|---|---|---|---|
| `recon-echo` | recon | no | Offline simulation of service discovery |
| `exploit-echo` | exploit | no | Offline simulation of a vulnerability match |
| `post-echo` | post | **required** | Offline simulation of post-exploitation |
| `echo-findings` | report | no | Renders findings JSON / markdown / CSV |
| `nmap-scan` | recon | no | External nmap service-scan adapter |
| `metasploit-exploit` | exploit | **required** | External msfconsole adapter |
| `hashcat-crack` | post | **required** | External hashcat hash-recovery adapter |

External adapters refuse to run when the tool is absent, refuse RFC 5737
documentation ranges, and are inert until `external_tools.live_execution` is
explicitly set to `true`. They never use a shell: child processes are launched
with an explicit argument list.

## Usage

### Campaign authoring

Campaigns are YAML files in `campaigns/`:

```yaml
id: my-campaign
name: My lab campaign
description: "Authorized test against the lab range"
targets:
  - 192.0.2.0/24        # must be inside config allowlist
max_phases: 8
phases:
  - phase: recon
    plugin: recon-echo
    timebox_secs: 60
  - phase: exploit
    plugin: nmap-scan
    timebox_secs: 300
    requires_approval: true
  - phase: report
    plugin: echo-findings
```

Fields:

- `targets` — one or more IPs or CIDRs. Hostnames are rejected. Every target is
  validated against the allowlist before anything runs.
- `max_phases` — hard cap on phases (also enforced by `--max-phases`).
- `phases[]` — ordered list. `phase` must be `recon`, `exploit`, `post`, or
  `report`; `plugin` must name a registered plugin; `timebox_secs` bounds phase
  wall time; `params` passes options to the plugin (used by tool adapters, e.g.
  hashcat's `hash_file`/`wordlist`).

### Dry-run vs execute

- **Default (dry-run):** prints `[DRY-RUN] ...` for every planned action, audits
  them with `"executed": false`, writes no reports. Gates are noted but nothing
  prompts because nothing executes.
- **`--execute`:** requires all targets inside the allowlist; phases run and
  findings are collected; a `report` phase (or the orchestrator fallback) writes
  the artefacts; gates are enforced.

### Approval gates

A phase is gated when the campaign sets `requires_approval: true` or the plugin
itself requires approval (as `post-echo`, `metasploit-exploit`, and
`hashcat-crack` do).

- Interactive runs (`--interactive`, or a TTY) prompt `[y/N]` before executing
  such a phase; declining aborts the campaign.
- Non-interactive runs (scripts, CI) **abort immediately** with exit code 3 and
  an `approval_gate` audit entry. The orchestrator never auto-continues.

### Reports

`reports/<campaign-id>/`:

- `findings.json` — full structured document: campaign metadata, checksum, phase
  timings, every finding with `severity`/`evidence`/`remediation`, and a summary
  broken down by severity.
- `report.md` — human-readable markdown of the same data.
- `summary.csv` — one row per finding (`campaign_id,phase,plugin,target,severity,
  title,evidence,remediation`).

### Logging & audit

- `logs/orchestrator.log` — structured application log (file + stdout).
- `logs/campaign.jsonl` — append-only JSONL of `start`, `action`, `abort`, and
  `end` events. Every `action` carries `ts`, `phase`, `plugin`, `target`, and
  `campaign_sha256` (the sha256 of the campaign file at load time), so a
  campaign can never drift silently from its approved definition.

### Config

`config/orchestrator.yaml` sets the allowlist CIDRs, plugin defaults, output and
log paths, log level, and `external_tools.live_execution`. All defaults are
RFC 5737 documentation placeholders and are not routable.

## Safety Rails

Non-negotiable, enforced in code:

1. **Dry-run default** — `run` executes nothing unless `--execute` is passed.
2. **Allowlist only** — execution requires every target to be an IP/CIDR
   contained in `config/orchestrator.yaml` `allowlist.cidrs`. Non-allowlisted
   targets hard-refuse before any phase runs, in both dry-run and execute mode.
3. **Audit everything** — every action is appended to `logs/campaign.jsonl` with
   timestamp, phase, plugin, target, and the campaign-file checksum.
4. **Approval gates abort** — a phase marked `requires_approval` aborts the
   campaign (exit code 3) in non-interactive mode. Never auto-continues.
5. **Hard caps** — `--max-phases` and the campaign `max_phases` bound the number
   of phases; SIGINT halts the campaign immediately and is recorded as an abort
   event (exit code 130).
6. **External tooling** — tool adapters require the tool on PATH, refuse RFC 5737
   documentation ranges, and stay inert until
   `external_tools.live_execution: true` is set for your own lab only.
7. **Placeholders everywhere** — shipped campaigns and configs use only
   documentation-lab values (`192.0.2.0/24`, `lab-ap`, etc.). No real addresses.

## Metrics

Recorded for the video metric and `METRICS.md` after each live-lab run:

- **Findings per campaign** — count and severity breakdown from `findings.json`.
- **Phase timings** — wall-clock seconds per phase from `phase_timings`.
- **Gates honored** — number of approval gates encountered, how many approved/
  denied/aborted; the audit log is the source of truth.

## Live Lab Test Plan

1. Configure your own lab: replace the placeholder allowlist in
   `config/orchestrator.yaml` with the lab CIDR(s) and set
   `external_tools.live_execution: true`.
2. Copy `campaigns/lab-three-tool.yaml.example` to
   `campaigns/lab-three-tool.yaml`, point `targets` at your own lab CIDR, and
   review the nmap / metasploit / hashcat phases.
3. Dry-run first: `f1-redteam run --campaign campaigns/lab-three-tool.yaml`.
4. Execute interactively:
   `f1-redteam run --campaign campaigns/lab-three-tool.yaml --execute --interactive`
   and approve the exploit/post gates.
5. Verify: structured findings in `reports/lab-three-tool/findings.json`, every
   action prefixed-logged in `logs/campaign.jsonl`, and update `METRICS.md`.
6. Re-run `python3 -m firmware selftest` — must still exit 0 after the live test.

Live execution must be directed exclusively at your own hardware/lab range.

## Tests

```bash
python3 -m py_compile firmware/*.py firmware/plugins/*.py tests/*.py
python3 -m unittest discover           # stdlib unittest, 42 tests
python3 -m firmware.selftest           # offline e2e self-test, exit 0
```

The self-test runs a 3-phase dry-run campaign plus a 2-phase execute campaign on
the placeholder allowlist with only offline echo plugins, and verifies JSONL
audit entries, `findings.json`, `report.md`, and that a gated phase aborts
cleanly in non-interactive mode.

## IMPORTANT: Read before use.

This tool is provided **exclusively** for authorized security research, academic study, and defensive hardening. Use without explicit written authorization is illegal and unethical.

### Authorization Requirements

You must obtain explicit written permission from the system owner before deploying any agent or red-team framework against systems you do not own. Simulating "agents" and "red-teaming" against real third-party infrastructure without authorization is a crime in most jurisdictions.

### Legal Framework

Unauthorized access to or manipulation of computer systems is governed by the **Computer Fraud and Abuse Act (CFAA)** (18 U.S.C. § 1030), the **EU Directive on Attacks Against Information Systems** (2013/40/EU), and equivalent legislation in other jurisdictions. Penalties include imprisonment and significant fines.

### Acceptable Use

- Authorized red-team and penetration-testing engagements with written scope
- Academic research on AI-agent security and agentic-defense design
- Defensive hardening of your own agent pipelines and orchestration
- CTF competitions and controlled lab environments

### Domain-Specific Notice: Credential Harvesting & Cracking

The `post-echo`, `metasploit-exploit`, and `hashcat-crack` plugins emulate or
perform credential harvesting and hash recovery. Use them **only** against
credentials you own or have written authorization to test. Recovered material
must be treated as sensitive, stored locally, and rotated after the exercise.

### Prohibited Use

- Deploying agents against systems without written authorization
- Red-teaming live LLM pipelines that serve third parties
- Using poisoned memorize/decoy techniques against production agents you do not own
- Weaponizing agent memory-poisoning against another organization's systems
- Running campaigns, scans, or cracks against any third-party asset, address, or
  network segment — including documentation ranges used as placeholders

### No Warranty

This software is provided "as is" without warranty of any kind. The authors assume no liability for damages arising from use or misuse of this tool.

### Responsible Disclosure

If you discover vulnerabilities in third-party agent systems using this tool, follow coordinated disclosure practices. Report to the vendor directly and allow reasonable time for remediation before public disclosure.

## License

MIT License

-----------------------------------------------------------------------

### Legacy simulator

`firmware/agentic_redteam.py` retains the original fully-offline simulation of
an LLM-driven pentest agent being red-teamed (decoy / payload-trojan / memory
poisoning scenarios). It is unchanged and can still be run directly:

```bash
python3 firmware/agentic_redteam.py
```