# IC Memo: Brightwater Fleet Systems, Inc. (brightwaterfleet.example)

Date: 2026-11-03 | Digest: dg_4dii7b8jx6fv
Rating: D | Decision: Escalate: full cyber diligence required before signing

## Executive summary

Bottom line: Escalate to full cyber diligence before signing [F-008]. Brightwater Fleet Systems, Inc. scores 56.8 (rating D), capped by a critical, potentially exploitable exposure [F-008], a publicly disclosed incident within 24 months [F-009], and multiple management statements contradicted by evidence [C-001] [C-005].

Key risks: A KEV-listed VPN appliance needs urgent version and compromise verification [F-008]. A breach disclosed 2025-08-14 affecting ~3,100 individuals raises regulatory, notification and insurance questions [F-009]. Identity-control exceptions affect MFA and terminated-user access [F-010] [F-011]. DMARC at p=none leaves the domain spoofable for BEC/wire fraud [F-001].

Management credibility: Of 9 statements assessed, 7 were contradicted and 2 supported, spanning access, monitoring, email, incident history and legacy systems [C-001] [C-002] [C-003] [C-004] [C-005] [C-006] [C-007].

Next steps: Complete escalated diligence before signing, verify the VPN exposure first, obtain the incident file and remediation evidence, and independently validate security representations [F-008] [F-009] [F-010].

## Why the rating

Score 56.8 reflects a critical, potentially exploitable exposure; a publicly disclosed incident within 24 months; multiple management statements contradicted by evidence.
Confidence high, based on outside-in scan, SOC 2 report, management interview.

## Function scores

| Function | Score | Findings |
|---|---|---|
| Govern | 29.0 | 2 |
| Identify | 66.4 | 3 |
| Protect | 35.2 | 8 |
| Detect | 82.0 | 1 |
| Respond | 82.0 | 1 |
| Recover | 100.0 | 0 |

## Key risks

- [Critical] Internet-facing appliance listed in CISA KEV (version not verified) (F-008, $25K–$150K)
- [High] DMARC not enforced (p=none): domain can be spoofed for BEC/wire fraud (F-001, $8K–$30K)
- [High] Publicly disclosed security incident in the last 24 months (F-009, $25K–$100K)
- [High] SOC 2 exception in logical access controls (CC6.1) (F-010, $20K–$80K)
- [High] SOC 2 exception in logical access controls (CC6.2) (F-011, $20K–$80K)

## Management claims vs. evidence

- [Contradicted/High] C-001: Every admin account is behind MFA. No exceptions. That's been true for years. It's enforced through our conditional access policy.
  Evidence: F-010: SOC 2 exception in logical access controls (CC6.1); E-015: Exception noted. 4 of 25 sampled admin accounts were not enforced for MFA. These were service-desk accounts created via a legacy provisioning script that
- [Contradicted/High] C-002: Offboarding is automated. HR flags the termination and access is revoked same day through our identity provider.
  Evidence: F-011: SOC 2 exception in logical access controls (CC6.2); E-016: Exception noted. 3 of 15 terminated users retained active access for 6, 11, and 19 business days respectively.
- [Contradicted/High] C-003: We have a 24 7 SOC through our MSSP, every alert gets looked at, nothing sits.
  Evidence: F-012: SOC 2 exception in security monitoring (CC7.2); E-017: Exception noted. For 2 consecutive weeks (Nov 10–23, 2025), alerts were forwarded to a decommissioned distribution list and were not reviewed.
- [Contradicted/High] C-004: We're fully locked down there. DMARC is enforced. Nobody can spoof our domain.
  Evidence: F-001: DMARC not enforced (p=none): domain can be spoofed for BEC/wire fraud; E-001: DMARC record: v=DMARC1; p=none; rua=mailto:dmarc@brightwaterfleet.example; policy=none, pct=100, rua=true
- [Contradicted/High] C-005: No, nothing material. We've never had a breach.
  Evidence: F-009: Publicly disclosed security incident in the last 24 months; E-014: State AG breach notice dated 2025-08-14: unauthorized access to a customer support system; approx. 3,100 individuals notified. Entity match exact; disclo
- [Contradicted/Medium] C-006: We decommissioned the legacy stuff a while back. Everything external goes through the main app and the VPN.
  Evidence: F-004: Publicly logged hostnames suggest exposed admin/legacy/staging systems; E-007: Risky hostname pattern legacy; first_seen 2019-11-05, last_seen 2026-07-22; E-005: Risky hostname pattern jenkins|old; first_seen 2021-06-03, last_seen 2026-08-14; E-006: Risky hostname pattern staging; first_seen 2024-01-20, last_seen 2026-10-01
- [Contradicted/Medium] C-007: Annual third party test. The last one came back clean. No highs.
  Evidence: E-022: CC4.1-01 (An independent penetration test is performed annually.): No exceptions noted. 2 high-severity findings were reported in the test; remediation s; E-030: No exceptions noted. 2 high-severity findings were reported in the test; remediation status was outside the scope of this control.
- [Supported/Info] C-008: Daily backups to immutable storage in a second region and we do a restore test every quarter.
  Evidence: E-021: A1.2-01 (Production data is backed up daily to immutable storage and restore tests are performed quarterly.): No exceptions noted.
- [Supported/Info] C-009: We can get one. one we haven't needed it so far.
  Evidence: F-014: SOC 2 report period ended more than 90 days ago; no bridge letter provided; E-031: Management plans to obtain a bridge letter covering April 1, 2026 forward upon request.; E-034: Report period ended 2026-03-31; 216 days before 2026-11-02.

## SOC 2 summary

Opinion Unqualified; period 2025-04-01 to 2026-03-31; auditor Halvorsen & Pike LLP.
Exceptions:
- CC6.1: 4/25 deviations
- CC6.2: 3/15 deviations
- CC7.2: counts not stated
- CC8.1: 2/40 deviations
Carve-outs: Nimbus Cloud Services, LedgerPay Payroll.
Bridge gap: 216 days.

## 100-day plan

| Window | Action | Owner | Cost |
|---|---|---|---|
| Days 0–30 | Verify ExampleGate SSL-VPN version/patch against KEV, patch or isolate immediately if affected, and review appliance logs. | IT Ops | $25K–$150K |
| Days 31–60 | Move DMARC from p=none to quarantine then reject, validating all senders and DKIM/SPF alignment. | Security Engineering | $8K–$30K |
| Days 31–60 | Obtain incident report, regulator correspondence and remediation evidence; confirm notification completion and lessons learned. | Incident Response | $25K–$100K |
| Days 31–60 | Remediate CC6.1 exception: MFA is enforced for all administrative access to production systems. | Security Engineering | $20K–$80K |
| Days 31–60 | Remediate CC6.2 exception: Access for terminated employees is revoked within 1 business day of termination. | Security Engineering | $20K–$80K |
| Days 31–60 | Remediate CC7.2 exception: Security alerts generated by the SIEM are reviewed and triaged daily. | SecOps | $15K–$60K |
| Days 61–100 | Inventory authorized senders, then change SPF qualifier from ~all to -all. | Security Engineering | $2K–$8K |
| Days 61–100 | Validate ownership and exposure of each risky hostname, remove/decommission unused systems, and restrict admin access. | IT Ops | $10K–$50K |
| Days 61–100 | Disable TLSv1.0 and TLSv1.1, retaining TLSv1.2 and TLSv1.3 only. | Security Engineering | $2K–$15K |
| Days 61–100 | Remediate CC8.1 exception: Production changes are approved by a peer before deployment. | Security Engineering | $5K–$20K |
| Days 61–100 | Obtain a bridge letter covering through 2026-11-02. | CISO/Board | $2K–$10K |
| After day 100 | Enable DNSSEC at the registrar/DNS provider and verify the DS record chain. | Security Engineering | $2K–$10K |
| After day 100 | Reconcile all 47 CT hostnames to an asset inventory and remove orphaned certificates/hosts. | IT Ops | $5K–$20K |
| After day 100 | Set Strict-Transport-Security header on apex and www after confirming HTTPS coverage. | Security Engineering | $1K–$5K |
| After day 100 | Obtain the Nimbus Cloud Services SOC report and assess carve-out risk. | CISO/Board | $0–$5K |
| Total | | | $142K–$643K |

## Deal recommendations

### Closing condition
- Do not sign until the ExampleGate SSL-VPN is verified, in Days 0–30, as patched or isolated and a compromise assessment has reviewed the appliance logs [F-008]. Consistent with the escalate-before-signing decision, include a bring-down of the relevant security representations at signing so the position is confirmed again before the deal becomes binding [F-008]. (basis: F-008)
### Full diligence scope
- Commission an independent scope review of the KEV-listed VPN exposure and the surrounding external footprint, prioritised in the Days 0–30 window [F-008]. As part of the escalated full diligence, pair that technical review with independent validation of management representations rather than relying on interviews alone [C-001] [C-004] [C-005]. (basis: F-008, C-001, C-004, C-005)
### Specific indemnity
- Seek a specific indemnity, or equivalent escrow-backed protection, for losses arising from the pre-closing incident, with the underlying incident evidence package completed in Days 31–60 [F-009]. In line with the decision to escalate before signing, confirm the indemnity covers regulatory, notification and third-party claim costs linked to the disclosed event [F-009]. (basis: F-009)
### R&W insurance note
- Assume the known incident is likely excluded from representations and warranties coverage and structure the risk allocation accordingly [F-009]. While diligence remains escalated before signing, obtain the insurer and broker position during the Days 31–60 incident-review window so any exclusion is addressed in the documents rather than discovered after signing [F-009]. (basis: F-009)
### Cyber insurance
- Treat standalone cyber insurance as a likely underwriting requirement and confirm insurability, limits and exclusions before close, using the Days 31–60 remediation window for the email-authentication and access-control fixes [F-001] [F-010] [F-011]. Consistent with the escalated pre-signing posture, make binding cover or a firm underwriting indication a pre-close deliverable [F-001] [F-010] [F-011]. (basis: F-001, F-010, F-011)
### Post-close covenant
- Include a post-close covenant to complete the remaining remediation, with the access-control, monitoring, offboarding and email-authentication items scheduled for Days 31–60 and the hostname and legacy-exposure items carried through Days 61–100 [F-001] [F-010] [F-011] [F-012]. Given the escalate-before-signing decision, tie covenant reporting to evidence of closure for the incident-review and reporting-currency items as well [F-004] [F-009] [F-014]. (basis: F-001, F-004, F-009, F-010, F-011, F-012, F-014, F-013, F-002, F-006)
### Price adjustment
- No purchase-price adjustment is warranted on cyber-remediation cost alone, because the plan totals $142K–$643K, which is immaterial relative to the 50M-250M revenue band [F-008]. Keep the economics unchanged while using the escalated pre-signing diligence and the phased windows from Days 0–30 through After day 100 to manage execution risk instead [F-008]. (basis: F-008)

## Questions for management

1. Provide evidence of the current ExampleGate SSL-VPN version and patch status, and the results of the appliance log review [F-008].
2. Provide the full incident report, regulator correspondence and notification-completion evidence for the breach disclosed 2025-08-14 [F-009] [C-005].
3. Reconcile the statement that every admin account is behind MFA with the exception affecting 4 of 25 sampled admin accounts [C-001] [F-010].
4. Reconcile the statement that offboarding revokes access same day with the 3 of 15 terminated users who retained access for 6, 11 and 19 business days [C-002] [F-011].
5. Provide evidence that security alerts are now reviewed and triaged daily following the two-week gap in Nov 10–23, 2025 [F-012] [C-003].
6. Confirm the timetable and sender inventory for moving DMARC from p=none to enforcement and for tightening SPF from ~all to -all [F-001] [F-002] [C-004].
7. Provide a current inventory reconciling the 47 certificate hostnames, including the vpn, legacy, staging and old Jenkins systems, with decommissioning or access-restriction status for each [F-004] [F-005] [C-006].
8. Provide a bridge letter covering the period through 2026-11-02 and the SOC report for Nimbus Cloud Services as the carved-out infrastructure host [F-014] [F-015].

## Limitations

- Passive outside-in assessment only; no authenticated or internal testing
- KEV matches are product-level; versions not verified
- Demo mode: signals from fixtures
- Remediation costs are triage estimates

---

Inputs: outside-in scan of brightwaterfleet.example; brightwater_soc2_type2.md (sha256 d48efc43cbc8); brightwater_cto_interview.wav (sha256 dfec0d51325f)
Models: orchestrator: muse-wonder-1.0 (meta_model_api); document_analysis: muse-wonder-1.0 (meta_model_api); claim_extraction: muse-wonder-1.0 (meta_model_api); crosscheck: muse-wonder-1.0 (meta_model_api); narrative: muse-wonder-1.0 (meta_model_api)
Run cost: $0.5073
Generated by PE Risk Key
