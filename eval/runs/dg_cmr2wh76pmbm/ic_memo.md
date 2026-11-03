# IC Memo: Brightwater Fleet Systems, Inc. (brightwaterfleet.example)

Date: 2026-11-03 | Digest: dg_cmr2wh76pmbm
Rating: C | Decision: Escalate: full cyber diligence required before signing

## Executive summary

Bottom line: Full cyber diligence is required before signing [F-008] [F-009]. Brightwater scored 71.6 with a C rating, capped by a critical, potentially exploitable exposure [F-008] and a publicly disclosed incident within 24 months [F-009].

Key risks: An internet-facing appliance is product-matched to a known exploited vulnerability, with version not verified [F-008]. A disclosed incident raises regulatory, customer-trust and insurance questions [F-009]. The domain can be spoofed for payment fraud and phishing because email authentication is not enforced [F-001] [F-002]. Publicly suggested admin, legacy and staging hosts expand the attack surface [F-004].

Management credibility: The input records 0 contradictions, with 0 contradicted, 0 unsupported and 0 supported claims, and no management interview was provided to test explanations [F-009].

Next steps: Verify the appliance and review for exploitation in the earliest remediation window [F-008], obtain incident closure evidence in the following window [F-009], and confirm insurability before close [F-001] [F-009].

## Why the rating

Score 71.6 reflects a critical, potentially exploitable exposure; a publicly disclosed incident within 24 months.
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
| Days 0–30 | Immediately verify appliance version/patch against KEV CVE, patch or restrict access, and review VPN logs for exploitation. | IT Ops | $25K–$150K |
| Days 31–60 | Move DMARC from p=none to quarantine then reject, monitoring rua reports and aligning all senders. | Security Engineering | $8K–$30K |
| Days 31–60 | Obtain incident report, remediation evidence, regulator/customer notification status, and confirm closure/lessons learned. | Incident Response | $25K–$100K |
| Days 61–100 | Inventory authorized senders, then change SPF from ~all to -all once legitimate mail is confirmed. | Security Engineering | $2K–$8K |
| Days 61–100 | Validate ownership and exposure of risky hosts, decommission legacy/staging or place admin/VPN behind strong access controls. | IT Ops | $10K–$50K |
| Days 61–100 | Disable TLSv1.0 and TLSv1.1 on www, retaining TLSv1.2+ with modern ciphers. | Security Engineering | $2K–$15K |
| After day 100 | Enable DNSSEC at registrar/DNS provider and validate DS publication. | Security Engineering | $2K–$10K |
| After day 100 | Reconcile CT hostnames to an authoritative asset inventory and remove orphaned certificates/hosts. | IT Ops | $5K–$20K |
| After day 100 | Set strict-transport-security header on apex and www after confirming HTTPS readiness. | Security Engineering | $1K–$5K |
| Total | | | $80K–$388K |

## Deal recommendations

### Closing condition
- Make signing conditional on verification of the internet-facing appliance version and patch level and completion of a compromise assessment, scheduled in Days 0–30 and consistent with full cyber diligence before signing [F-008]. (basis: F-008)
### Full diligence scope
- Commission a scope review of the KEV-listed appliance exposure as part of the escalated diligence before signing, covering patch status, access restrictions and VPN log review in Days 0–30 [F-008]. (basis: F-008)
### Specific indemnity
- Seek protection for pre-closing incident losses arising from the disclosed incident, with the incident file and closure evidence to be obtained in Days 31–60 in line with diligence before signing [F-009]. (basis: F-009)
### R&W insurance note
- Assume the known disclosed incident is likely to be excluded from representations and warranties coverage and structure the transaction accordingly, completing the related review in Days 31–60 under the pre-signing diligence escalation [F-009]. (basis: F-009)
### Cyber insurance
- Confirm cyber insurability and any underwriting requirements before close, because unenforced DMARC may affect terms, with remediation planned for Days 31–60 and diligence escalated before signing [F-001]. (basis: F-001)
### Post-close covenant
- Require completion of the remaining remediation as a post-close covenant, spanning Days 31–60 for DMARC and incident closure, Days 61–100 for SPF, risky-host and TLS work, and the escalated pre-signing diligence position [F-001] [F-002] [F-004] [F-006] [F-009]. (basis: F-001, F-002, F-004, F-006, F-009)
### Price adjustment
- No price adjustment is warranted, as total remediation of $80K–$388K is immaterial relative to the 50M-250M revenue band, with work phased from Days 0–30 through After day 100 alongside full diligence before signing [F-001] [F-008] [F-009]. (basis: F-001, F-002, F-003, F-004, F-005, F-006, F-007, F-008, F-009)

## Questions for management

1. Provide current appliance version, patch evidence and the VPN exploitation log review [F-008].
2. Provide the incident report, remediation evidence and regulator and customer notification status [F-009].
3. Reconcile the publicly logged hostnames to the authoritative asset inventory and confirm ownership and exposure of each risky host [F-004] [F-005].
4. Confirm the plan and sender inventory for enforcing DMARC and strengthening SPF [F-001] [F-002].
5. Confirm the plan to disable deprecated TLS versions and set HSTS on the affected hosts [F-006] [F-007].
6. Provide the plan to enable DNSSEC and validate publication [F-003].

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
Run cost: $0.2612
Generated by PE Risk Key
