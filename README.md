# F1 — Agentic Red-Team Framework

Pure-Python offline simulation of an LLM-driven penetration-test agent being red-teamed, with attacker-vs-defender scoring.

## Overview

- Models the pentest agent as a deterministic state machine with tool-call capability (recon / exploit / collect) over a local event-driven "lab"
- Red-teams the agent itself with three adversarial scenarios: **decoy confusion**, **payload trojanization**, and **memory poisoning**
- Implements a **naive** agent that blindly trusts its context memory
- Implements a **hardened** agent with an auditor/worker split and runtime taint gates (HMAC-verified instruction tags)
- Measures attack-success-rate (SAR) and safety score for each scenario against both agents
- Emits a comparison report table quantifying the defender's improvement
- Fully offline: the "LLM" is a deterministic mock policy — no API keys, no network

## Features

- **Deterministic Mock LLM Policy**: reproducible tool-choice logic driven by agent memory and environment state
- **Event-Driven Lab**: reacts to tool calls, marks trojanized/decoy targets as tainted
- **Decoy Scenario**: attacker-planted instruction pivots the agent to a fake high-value asset
- **Payload Trojanization**: attacker injects a tainted instruction that exfiltrates to an attacker sink
- **Memory Poisoning**: attacker feeds the agent a callback to a C2 sink
- **HMAC Instruction Tagging**: auditor verifies payload integrity to detect tampering
- **Runtime Taint Gates**: block agent action on tainted tool responses
- **Scoring**: attack-success-rate (SAR) and safety score per scenario, plus averages
- **Zero Dependencies**: Python standard library only

## Installation

No external dependencies required — uses Python standard library only.

```bash
python3 firmware/agentic_redteam.py
```

## Usage

```python
from firmware.agentic_redteam import render_report

print(render_report(seed=42))      # full comparison report
```

```python
from firmware.agentic_redteam import run_agent, MockLMPolicy, RedTeamAgent
from firmware.agentic_redteam import Lab, build_memory

lab = Lab(7)
mem = build_memory("memory_poison", b"lab-key")
agent = RedTeamAgent(MockLMPolicy(7, "worker"), mem,
                     auditor_worker_split=True,
                     runtime_taint_gates=True,
                     gate_key=b"lab-key")
result = agent.run(lab)
print(result["flags"], result["notices"])
```

## Example Output

```
======================================================================
  F1 - AGENTIC RED-TEAM FRAMEWORK / RED-TEAMING REPORT
======================================================================
  Mode : fully-offline deterministic simulation (mock LLM)
  Seed : 42

Scenario (metric)    | Naive Agent      | Hardened Agent
----------------------------------------------------------------------
decoy SAR            | 16.7%            | 0.0%
decoy safety         | 16.7%            | 100.0%
payload_trojan SAR   | 83.3%            | 0.0%
payload_trojan safety| 16.7%            | 100.0%
memory_poison SAR    | 83.3%            | 0.0%
memory_poison safety | 16.7%            | 100.0%
----------------------------------------------------------------------
AVG attack-success   | 61.1%            | 0.0%
AVG safety           | 16.7%            | 100.0%
======================================================================
```

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

### Prohibited Use

- Deploying agents against systems without written authorization
- Red-teaming live LLM pipelines that serve third parties
- Using poisoned memorize/decoy techniques against production agents you do not own
- Weaponizing agent memory-poisoning against another organization's systems

### No Warranty

This software is provided "as is" without warranty of any kind. The authors assume no liability for damages arising from use or misuse of this tool.

### Responsible Disclosure

If you discover vulnerabilities in third-party agent systems using this tool, follow coordinated disclosure practices. Report to the vendor directly and allow reasonable time for remediation before public disclosure.

## License

MIT License
