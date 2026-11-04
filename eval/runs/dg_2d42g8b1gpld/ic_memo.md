# IC Memo: Brightwater Fleet Systems, Inc. (brightwaterfleet.example)

Date: 2026-11-03 | Digest: dg_2d42g8b1gpld
Rating: C | Decision: Escalate: full cyber diligence required before signing

## Executive summary

Bottom line: Escalate: full cyber diligence required before signing. The 71.6, C rating reflects a critical, potentially exploitable exposure, a publicly disclosed incident within 24 months, and limited evidence: outside-in signals only [F-008] [F-009]. Key risks: The internet-facing appliance listed in CISA KEV has an unverified version and needs urgent compromise review; a disclosed incident raises root-cause and closure questions; DMARC is not enforced, enabling domain spoofing; public hostnames suggest exposed admin, legacy and staging systems; and no SOC 2 report was provided [F-008] [F-009] [F-001] [F-004]. Management credibility: Not assessed: no management interview provided. Next steps: Obtain the SOC 2 Type II report and a management security interview, verify the appliance version and review VPN logs, obtain incident closure evidence, and confirm remediation sequencing and insurability [F-008] [F-009] [F-001].

## Why the rating

Score 71.6 reflects a critical, potentially exploitable exposure; a publicly disclosed incident within 24 months; limited evidence: outside-in signals only.
Confidence low, based on outside-in scan.

## Function scores

| Function | Score | Findings |
|---|---|---|
| Govern | Not assessed | 0 |
| Identify | 66.4 | 3 |
| Protect | 70.8 | 5 |
| Detect | Not assessed | 0 |
| Respond | 82.0 | 1 |
| Recover | Not assessed | 0 |

## Key risks

- [Critical] Internet-facing appliance listed in CISA KEV (version not verified) (F-008, $25K–$150K)
- [High] DMARC not enforced (p=none): domain can be spoofed for BEC/wire fraud (F-001, $8K–$30K)
- [High] Publicly disclosed security incident in the last 24 months (F-009, $25K–$100K)
- [Medium] SPF uses soft/neutral fail (F-002, $2K–$8K)
- [Medium] Publicly logged hostnames suggest exposed admin/legacy/staging systems (F-004, $10K–$50K)

## Management claims vs. evidence

-

## SOC 2 summary

No SOC 2 report provided.

## 100-day plan

| Window | Action | Owner | Cost |
|---|---|---|---|
| Days 0–30 | Immediately verify appliance version/firmware against CVE-PLACEHOLDER-0001, patch or isolate, rotate credentials, and review VPN logs for compromise. | IT Ops | $25K–$150K |
| Days 31–60 | Progress DMARC from p=none through quarantine to reject after validating all legitimate senders and DKIM/SPF alignment. | Security Engineering | $8K–$30K |
| Days 31–60 | Obtain incident report, regulator correspondence, remediation evidence and insurance history; validate lessons learned and close any open actions. | Incident Response | $25K–$100K |
| Days 61–100 | Inventory mail senders, validate SPF/DKIM alignment, then change ~all to -all with monitoring. | Security Engineering | $2K–$8K |
| Days 61–100 | Validate ownership and exposure of each risky hostname; restrict, patch, MFA-protect or decommission legacy/staging systems. | IT Ops | $10K–$50K |
| Days 61–100 | Disable TLSv1.0 and TLSv1.1, retain TLSv1.2+ with modern ciphers, and retest all hosted names. | Security Engineering | $2K–$15K |
| After day 100 | Enable DNSSEC with registrar/DNS provider, publish DS records, and test resolution and rollover procedures. | Security Engineering | $2K–$10K |
| After day 100 | Reconcile all 47 CT hostnames to owned business services, remove stale certificates/hosts, and implement certificate issuance approval. | IT Ops | $5K–$20K |
| After day 100 | Set Strict-Transport-Security with appropriate max-age after confirming HTTPS across subdomains, then monitor. | Security Engineering | $1K–$5K |
| Total | | | $80K–$388K |

## Deal recommendations

### Closing condition
- Require, before signing and within Days 0–30, verification of the appliance version, patching or isolation as needed, credential rotation, and a VPN-log compromise assessment; also obtain the current SOC 2 Type II report and a management security interview before relying on this rating [F-008]. (basis: F-008)
### Full diligence scope
- Include a focused review of the KEV-listed appliance exposure, its current version and patch status, and associated VPN logs in the diligence scope for Days 0–30 [F-008]. (basis: F-008)
### Specific indemnity
- Seek protection for pre-closing incident losses, informed by the incident review to be completed in Days 31–60 [F-009]. (basis: F-009)
### R&W insurance note
- Assume the known incident is likely excluded from R&W coverage and address that gap in transaction planning alongside the incident review in Days 31–60 [F-009]. (basis: F-009)
### Cyber insurance
- Confirm cyber insurability before close, including any underwriting requirement arising from unenforced DMARC, with remediation scheduled for Days 31–60 [F-001]. (basis: F-001)
### Post-close covenant
- Bind the company to complete the agreed remediation after close, covering email authentication, exposed hostnames, deprecated TLS, and incident actions across Days 31–60 and Days 61–100 [F-001] [F-002] [F-004] [F-006] [F-009]. (basis: F-001, F-002, F-004, F-006, F-009)
### Price adjustment
- No price adjustment is warranted on remediation cost alone: the $80K–$388K total across Days 0–30 through After day 100 is immaterial relative to the stated revenue band [F-001] [F-002] [F-003] [F-004] [F-005] [F-006] [F-007] [F-008] [F-009]. (basis: F-001, F-002, F-003, F-004, F-005, F-006, F-007, F-008, F-009)

## Questions for management

1. Provide the appliance model, current version and firmware, patch status, and VPN-log review results for the KEV-listed exposure [F-008]?
2. Provide the incident report, regulator correspondence, remediation evidence, insurance history, and status of open actions for the disclosed incident [F-009]?
3. Provide the inventory of legitimate mail senders and the validation plan for SPF and DKIM alignment before DMARC enforcement and hard fail are implemented [F-001] [F-002]?
4. Confirm ownership, business need, access controls, and patch status for each publicly logged VPN, legacy, staging, and admin hostname [F-004]?
5. Reconcile all 47 certificate hostnames to owned business services and confirm which hosts and certificates will be retired [F-005]?
6. Confirm the configuration plan and testing approach for disabling deprecated TLS versions and setting HSTS across hosted names [F-006] [F-007]?

## Limitations

- Unassessed CSF functions (no evidence from provided inputs): GV, DE, RC
- Passive outside-in assessment only; no authenticated or internal testing
- KEV matches are product-level; versions not verified
- No SOC 2 report provided
- No management interview provided
- Demo mode: signals from fixtures
- Remediation costs are triage estimates

---

Inputs: outside-in scan of brightwaterfleet.example
Models: orchestrator: muse-wonder-1.0 (meta_model_api); narrative: muse-wonder-1.0 (meta_model_api)
Run cost: $0.1852
Generated by PE Risk Key
