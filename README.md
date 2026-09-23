> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# F1 — Agentic Red-Team Campaign Orchestrator

YAML-driven campaign orchestrator for authorized security testing against your own lab range: phase plugins (`recon` → `exploit` → `post` → `report`), dry-run by default, allowlist-gated targets, JSONL audit logs, and hard approval rails.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/5h4d0wn1k/f1-agentic-redteam.svg)](https://github.com/5h4d0wn1k/f1-agentic-redteam)
[![Last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/f1-agentic-redteam.svg)](https://github.com/5h4d0wn1k/f1-agentic-redteam)
[![Issues](https://img.shields.io/github/issues/5h4d0wn1k/f1-agentic-redteam.svg)](https://github.com/5h4d0wn1k/f1-agentic-redteam)

## Why

Agentic red-teaming gets dangerous the moment an "autonomous" run forgets your scope. F1 makes execution impossible outside your lab: every campaign is YAML, every target must sit inside the `config/orchestrator.yaml` allowlist, nothing executes unless you pass `--execute`, gated phases abort (never auto-continue) in non-interactive mode, and every action is append-logged with the campaign file's checksum. It is a disciplinarian orchestrator for shadow-lab attack-playbook research — stdlib-first, offline by default, audited by design.

## Features

- **Phase plugin registry** — `recon` / `exploit` / `post` / `report` plugins with `run()`, `dry_run()` and `needs_interaction()` contracts
- **Dry-run by default** — `run` executes nothing until `--execute`
- **Allowlist-gated targets** — IP/CIDR only, validated against lab CIDRs in `config/orchestrator.yaml`
- **Approval gates** — `requires_approval` phases prompt on a TTY or abort (exit 3) in non-interactive runs
- **JSONL audit log** — timestamped actions with campaign sha256, plus structured `logs/orchestrator.log`
- **Structured reports** — `findings.json`, human `report.md`, and `summary.csv`
- **External tool adapters** — nmap / msfconsole / hashcat adapters, inert without `external_tools.live_execution: true`, refuse RFC 5737 ranges

## Quickstart

```bash
git clone https://github.com/5h4d0wn1k/f1-agentic-redteam.git && cd f1-agentic-redteam

python3 -m firmware --help            # works with zero install
# or: python3 -m pip install -e .     # installs the f1-redteam script

python3 -m firmware selftest                                   # offline self-test, exit 0
python3 -m firmware list-plugins                               # registered plugins
python3 -m firmware run --campaign campaigns/demo-two-phase-execute.yaml
python3 -m firmware run --campaign campaigns/demo-two-phase-execute.yaml --execute
```

Author campaigns as YAML in `campaigns/` (see `campaigns/demo-*.yaml` and `campaigns/lab-three-tool.yaml.example`); targets must be IPs/CIDRs inside the allowlist.

## Project structure

- `firmware/` — orchestrator, allowlist, audit, reporting, self-test and plugin registry
- `campaigns/` — demo, self-test and example YAML campaigns
- `config/orchestrator.yaml` — allowlist CIDRs, plugin defaults, log/output paths (RFC 5737 placeholders only)
- `firmware/agentic_redteam.py` — legacy fully-offline LLM-red-team simulation (`python3 firmware/agentic_redteam.py`)

## Documentation

- [NOTICE.md](NOTICE.md) — usage notice
- [METRICS.md](METRICS.md) — findings/gates/phase-timing discipline
- [ETHICS.md](ETHICS.md) — educational purpose and authorized use only
- [SCOPE.md](SCOPE.md) — authorized-testing scope checklist
- [SECURITY.md](SECURITY.md) — vulnerability reporting
- [CONTRIBUTING.md](CONTRIBUTING.md) — safe contribution guidelines

## Contributing

New plugins, stricter guardrails and report formats are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md); every contribution must preserve the allowlist, dry-run and approval-gate invariants.

## License

MIT — see [LICENSE](LICENSE). Provided **AS IS**, for authorized security research and education only.