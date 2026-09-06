# METRICS — f1-agentic-redteam

Metric source of truth per live-lab run. Populated from `reports/<id>/findings.json`
and `logs/campaign.jsonl` after each live run against the lab range.

| Campaign | Date | Targets | Findings (total) | Findings by severity | Phase timings (s) | Gates (encounter/approved/denied/aborted) | Video |
|---|---|---|---|---|---|---|---|
| PENDING live-lab | | | | | | | |

Offline baseline (selftest, no network):

| Date | checks | result |
|---|---|---|
| 2026-09-06 | 20 | PASS (exit 0) |

Live Lab Test Plan (see README): run `campaigns/lab-three-tool.yaml` (nmap →
metasploit → hashcat) against the lab CIDR, then fill the first row above.