# NOTICE — Legal & Operational Obligations

This repository is a security-testing orchestrator. By cloning, installing, or
using it you agree to the following, matching the full disclaimer in README.md
("IMPORTANT: Read before use.").

1. **Own-lab only.** Campaigns may only target systems, addresses, and network
   segments you own or have written authorization to test. No third-party
   assets. Ever.
2. **Authorization.** Obtain explicit written authorization before any
   `--execute` run. Scope, ranges, and tools must be documented before the run.
3. **Law.** Unauthorized access or manipulation is a crime in most
   jurisdictions (e.g. CFAA 18 U.S.C. § 1030, EU Directive 2013/40/EU).
4. **Scope of shipped defaults.** Every shipped campaign and config uses only
   RFC 5737 documentation values (192.0.2.0/24, 198.51.100.0/24,
   203.0.113.0/24). External tooling refuses to execute against these ranges.
5. **Credential harvesting & cracking.** The post/exploit/crack plugins emulate
   credential harvesting and hash recovery. Use only on your own credentials.
   Recovered material is sensitive: store locally, never commit, rotate after
   the exercise.
6. **Record-keeping.** Every campaign is logged to `logs/campaign.jsonl` with
   the sha256 of the campaign file. Keep these logs; they are your proof of
   scope and behaviour.
7. **No identity leaks.** No real names, employers, institutions, emails, MAC/
   SSID/BSSID addresses, or personally identifying information in issues,
   commits, or reports. Author identity is
   `5h4d0wn1k <5h4d0wn1k@users.noreply.github.com>`.
8. **Responsible disclosure.** Report vulnerabilities in third-party systems to
   the vendor and allow reasonable remediation time before public disclosure.

See also SECURITY / responsible disclosure: report issues via GitHub only.

— 5h4d0wn1k