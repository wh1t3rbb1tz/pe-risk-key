# IC Memo: Brightwater Fleet Systems, Inc. (brightwaterfleet.example)

Date: 2026-11-03 | Digest: dg_a56a5p607l5e
Rating: C | Decision: Escalate: full cyber diligence required before signing

## Executive summary

Bottom line: Escalate: full cyber diligence required before signing. The 71.6 rating of C reflects a critical, potentially exploitable exposure, a publicly disclosed incident within 24 months, and limited evidence: outside-in signals only [F-008] [F-009]. Key risks: Critical internet-facing appliance exposure with version not verified, non-enforced DMARC enabling spoofing, exposed admin, legacy and staging hostnames, and a disclosed incident with 3,100 individuals notified; no SOC 2 report was provided [F-008] [F-001] [F-004] [F-009]. Management credibility: Not assessed: no management interview provided. Next steps: Complete diligence before signing, verify the appliance version, patch status and compromise assessment, obtain incident closure evidence, and request the SOC 2 report that was not provided, plus a management security interview [F-008] [F-009].

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
| Days 0–30 | Immediately verify ExampleGate version and patch status against KEV entry; patch, upgrade or restrict appliance access and hunt for compromise. | IT Ops | $25K–$150K |
| Days 31–60 | Move DMARC from p=none to quarantine then reject, validating all legitimate senders and alignment first. | Security Engineering | $8K–$30K |
| Days 31–60 | Obtain incident report, regulator correspondence and closure evidence; confirm remediation, notification completion and any ongoing obligations. | Incident Response | $25K–$100K |
| Days 61–100 | Inventory authorized senders, then change SPF ~all to -all once all legitimate sources are included. | Security Engineering | $2K–$8K |
| Days 61–100 | Inventory and validate each risky hostname; decommission legacy/staging systems or restrict them behind authenticated access. | IT Ops | $10K–$50K |
| Days 61–100 | Disable TLSv1.0 and TLSv1.1, retaining TLSv1.2+ with modern cipher configuration. | Security Engineering | $2K–$15K |
| After day 100 | Enable DNSSEC at registrar/registry and validate DS/DNSKEY chain and resolver handling. | Security Engineering | $2K–$10K |
| After day 100 | Reconcile all 47 CT hostnames to owners and business need; remove or consolidate unowned/stale services. | IT Ops | $5K–$20K |
| After day 100 | Set Strict-Transport-Security with an appropriate max-age on apex and www after confirming all subdomains support HTTPS. | Security Engineering | $1K–$5K |
| Total | | | $80K–$388K |

## Deal recommendations

### Closing condition
- Make signing contingent on verification of the appliance version and patch status and a compromise assessment in Days 0–30, and obtain the current SOC 2 Type II report and a management security interview before relying on this rating [F-008]. (basis: F-008)
### Full diligence scope
- Include a scoped review of the known-exploited appliance exposure, covering version, patching, access restrictions and compromise hunting, in Days 0–30 [F-008]. (basis: F-008)
### Specific indemnity
- Secure protection for pre-closing incident losses, including notification, regulatory and litigation obligations arising from the disclosed incident, with remediation confirmed in Days 31–60 [F-009]. (basis: F-009)
### R&W insurance note
- Assume the known incident is likely to be excluded from representations and warranties coverage and confirm the position with the broker before close, using closure evidence obtained in Days 31–60 [F-009]. (basis: F-009)
### Cyber insurance
- Confirm insurability and any underwriting requirements arising from non-enforced DMARC before close, with enforcement moved to quarantine then reject in Days 31–60 [F-001]. (basis: F-001)
### Post-close covenant
- Commit to completing remediation after close, covering DMARC and SPF enforcement, hostname validation, removal of deprecated TLS and incident obligations across Days 31–60 and Days 61–100 [F-001] [F-002] [F-004] [F-006] [F-009]. (basis: F-001, F-002, F-004, F-006, F-009)
### Price adjustment
- No price adjustment is warranted on cyber remediation alone: the $80K–$388K total across Days 0–30 through After day 100 is immaterial relative to the 50M-250M revenue band [F-001] [F-002] [F-003] [F-004] [F-005] [F-006] [F-007] [F-008] [F-009]. (basis: F-001, F-002, F-003, F-004, F-005, F-006, F-007, F-008, F-009)

## Questions for management

1. Provide the current appliance version, patch status, access restrictions and compromise assessment results [F-008]?
2. Provide the incident report, regulator correspondence and closure evidence, including confirmation of notification completion and any ongoing obligations [F-009]?
3. Reconcile all 47 hostnames to owners and business need, and confirm which services can be removed or consolidated [F-005]?
4. Provide the inventory and validation of each risky hostname, including access controls, patching and business need [F-004]?
5. Provide the plan to move DMARC from reporting to quarantine then reject and to change SPF to hard fail after validating legitimate senders [F-001] [F-002]?
6. Confirm the plan to disable TLSv1.0 and TLSv1.1, retain TLSv1.2 and above, and set Strict-Transport-Security after confirming HTTPS support [F-006] [F-007]?
7. Confirm the plan to enable DNSSEC and validate the registrar, registry and resolver chain [F-003]?

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
Run cost: $0.1911
Generated by PE Risk Key
