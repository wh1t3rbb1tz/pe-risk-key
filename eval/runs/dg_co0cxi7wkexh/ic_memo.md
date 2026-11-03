# IC Memo: Brightwater Fleet Systems, Inc. (brightwaterfleet.example)

Date: 2026-11-03 | Digest: dg_co0cxi7wkexh
Rating: D | Decision: Escalate: full cyber diligence required before signing

## Executive summary

Bottom line: Escalate: full cyber diligence required before signing. Rated D at 56.8 because of a critical, potentially exploitable exposure, a publicly disclosed incident within 24 months, and multiple management statements contradicted by evidence [F-008] [F-009] [C-005]. Key risks: A critical internet-facing SSL-VPN exposure remains version-unverified; a disclosed breach 14 months ago notified approx. 3,100 individuals; administrative MFA and terminated-user access exceptions weaken access control; and DMARC at p=none leaves the domain spoofable [F-008] [F-009] [F-010] [F-011] [F-001]. Management credibility: Of 9 claims assessed, 7 were contradicted, 1 unsupported, 1 supported. Management credibility is materially weakened because claims on administrative MFA, offboarding, alert review, DMARC enforcement and incident history were contradicted by evidence [C-001] [C-002] [C-003] [C-004] [C-005] [C-006] [C-007]. Next steps: Verify the VPN patch level and compromise status, obtain the incident post-mortem and regulator status, secure a SOC 2 bridge letter, and independently validate access and monitoring controls [F-008] [F-009] [F-014] [F-010] [F-012].

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
  Evidence: F-010: SOC 2 exception in logical access controls (CC6.1); E-014: 4 of 25 sampled admin accounts were not enforced for MFA.
- [Contradicted/High] C-002: Offboarding is automated. HR flags the termination and access is revoked same day through our identity provider.
  Evidence: F-011: SOC 2 exception in logical access controls (CC6.2); E-015: 3 of 15 terminated users retained active access for 6, 11, and 19 business days respectively.
- [Contradicted/High] C-003: We have a 24 7 SOC through our MSSP, every alert gets looked at, nothing sits.
  Evidence: F-012: SOC 2 exception in security monitoring (CC7.2); E-016: For 2 consecutive weeks (Nov 10–23, 2025), alerts were forwarded to a decommissioned distribution list and were not reviewed.
- [Contradicted/High] C-004: We're fully locked down there. DMARC is enforced. Nobody can spoof our domain.
  Evidence: F-001: DMARC not enforced (p=none): domain can be spoofed for BEC/wire fraud; E-001: v=DMARC1; p=none; rua=mailto:dmarc@brightwaterfleet.example; policy=none, pct=100
- [Contradicted/High] C-005: No, nothing material. We've never had a breach.
  Evidence: F-009: Publicly disclosed security incident in the last 24 months; E-013: 2025-08-14 state AG breach notice: unauthorized access to a customer support system; approx. 3,100 individuals notified. disclosed_within_months: 14; ent
- [Contradicted/Medium] C-006: We decommissioned the legacy stuff a while back. Everything external goes through the main app and the VPN.
  Evidence: F-004: Publicly logged hostnames suggest exposed admin/legacy/staging systems; E-005: pattern=jenkins|old; first_seen=2021-06-03; last_seen=2026-08-14; E-007: pattern=legacy; first_seen=2019-11-05; last_seen=2026-07-22
- [Contradicted/Medium] C-007: Annual third party test. The last one came back clean. No highs.
  Evidence: E-021: CC4.1-01 (An independent penetration test is performed annually.): No exceptions noted. 2 high-severity findings were reported in the test; remediation s; E-029: No exceptions noted. 2 high-severity findings were reported in the test; remediation status was outside the scope of this control.
- [Unsupported/Low] C-009: We can get one. one we haven't needed it so far.
  Evidence: F-014: SOC 2 report period ended more than 90 days ago; no bridge letter provided; E-030: Management plans to obtain a bridge letter covering April 1, 2026 forward upon request.
- [Supported/Info] C-008: Daily backups to immutable storage in a second region and we do a restore test every quarter.
  Evidence: E-020: A1.2-01 (Production data is backed up daily to immutable storage and restore tests are performed quarterly.): No exceptions noted.

## SOC 2 summary

Opinion Unqualified; period 2025-04-01 to 2026-03-31; auditor Halvorsen & Pike LLP.
Exceptions:
- CC6.1: 4/25 deviations
- CC6.2: 3/15 deviations
- CC7.2: counts not stated
- CC8.1: 2/40 deviations
Carve-outs: Nimbus Cloud Services, LedgerPay Payroll.
Bridge gap: 213 days.

## 100-day plan

| Window | Action | Owner | Cost |
|---|---|---|---|
| Days 0–30 | Urgently verify ExampleGate version/patch against KEV entry, patch or isolate appliance, and review VPN logs for compromise. | IT Ops | $25K–$150K |
| Days 31–60 | Move DMARC from p=none to quarantine then reject, validating all senders and rua monitoring first. | Security Engineering | $8K–$30K |
| Days 31–60 | Obtain incident post-mortem, regulator closure status, and evidence of corrective actions; confirm no outstanding notification or litigation obligations. | Incident Response | $25K–$100K |
| Days 31–60 | Remediate CC6.1 exception: MFA is enforced for all administrative access to production systems. | Security Engineering | $20K–$80K |
| Days 31–60 | Remediate CC6.2 exception: Access for terminated employees is revoked within 1 business day of termination. | Security Engineering | $20K–$80K |
| Days 31–60 | Remediate CC7.2 exception: Security alerts generated by the SIEM are reviewed and triaged daily. | SecOps | $15K–$60K |
| Days 61–100 | Audit authorized senders, then change SPF ~all to -all in coordination with DMARC enforcement. | Security Engineering | $2K–$8K |
| Days 61–100 | Inventory each risky hostname, restrict or retire legacy/staging systems, and enforce MFA/VPN access for retained services. | IT Ops | $10K–$50K |
| Days 61–100 | Disable TLSv1.0 and TLSv1.1 on www host, standardize TLS 1.2+ configuration across web properties. | Security Engineering | $2K–$15K |
| Days 61–100 | Remediate CC8.1 exception: Production changes are approved by a peer before deployment. | Security Engineering | $5K–$20K |
| Days 61–100 | Obtain a bridge letter covering through 2026-10-30. | CISO/Board | $2K–$10K |
| After day 100 | Enable DNSSEC at registrar/DNS provider and verify DS publication and chain of trust. | Security Engineering | $2K–$10K |
| After day 100 | Reconcile CT hostnames to a CMDB/asset inventory, assign owners, and remove or monitor orphaned hostnames. | IT Ops | $5K–$20K |
| After day 100 | Add Strict-Transport-Security header with suitable max-age after confirming HTTPS-only operation on both hosts. | Security Engineering | $1K–$5K |
| After day 100 | Obtain the Nimbus Cloud Services SOC report and assess carve-out risk. | CISO/Board | $0–$5K |
| Total | | | $142K–$643K |

## Deal recommendations

### Closing condition
- Require verification of the internet-facing VPN appliance patch level and a compromise assessment, with a bring-down of security representations, before signing in Days 0–30 [F-008]. (basis: F-008)
### Full diligence scope
- Commission an independent review of the listed VPN exposure and validation of management representations within Days 0–30 [F-008]. (basis: F-008)
### Specific indemnity
- Negotiate protection for pre-closing incident losses arising from the disclosed incident, with diligence completed in Days 31–60 [F-009]. (basis: F-009)
### R&W insurance note
- Plan on the known disclosed incident being excluded from representations and warranties coverage, and address that gap during Days 31–60 [F-009]. (basis: F-009)
### Cyber insurance
- Confirm cyber insurability and expected underwriting requirements for email authentication and administrative access controls before close, aligned to remediation in Days 31–60 [F-001] [F-010] [F-011]. (basis: F-001, F-010, F-011)
### Post-close covenant
- Bind the company to complete the remaining access, monitoring, change, email, asset and assurance remediation as a post-close covenant across Days 31–60 and Days 61–100 [F-010] [F-011] [F-012] [F-013] [F-001] [F-002] [F-004] [F-006] [F-009] [F-014]. (basis: F-010, F-011, F-012, F-013, F-001, F-002, F-004, F-006, F-009, F-014)
### Price adjustment
- Make no price adjustment on cyber remediation alone, as the $142K–$643K total is immaterial relative to the 50M-250M revenue band, with work spanning Days 0–30 through After day 100 [F-001] [F-002] [F-003] [F-004] [F-005] [F-006] [F-007] [F-008] [F-009] [F-010] [F-011] [F-012] [F-013] [F-014] [F-015]. (basis: F-001, F-002, F-003, F-004, F-005, F-006, F-007, F-008, F-009, F-010, F-011, F-012, F-013, F-014, F-015)

## Questions for management

1. Provide the verified VPN appliance version, patch evidence and VPN log review for compromise [F-008]?
2. Provide the incident post-mortem, regulator closure status and evidence of corrective actions for the disclosed incident [F-009]?
3. Reconcile the claim of universal administrative MFA with the sampled accounts not enforced for MFA, and confirm current enforcement [F-010] [C-001]?
4. Reconcile same-day automated offboarding with terminated users retaining access, and confirm the current revocation process [F-011] [C-002]?
5. Confirm current security alert routing, daily triage ownership and evidence of review [F-012] [C-003]?
6. Confirm the plan and sender inventory to move email authentication from monitoring-only to enforcement [F-001] [C-004]?
7. Provide a bridge letter covering through 2026-10-30 and the infrastructure hosting provider assurance report [F-014] [F-015]?
8. Provide an inventory of VPN, legacy, staging and legacy portal hosts, confirming which are retained, restricted or retired [F-004] [C-006]?

## Limitations

- Passive outside-in assessment only; no authenticated or internal testing
- KEV matches are product-level; versions not verified
- Demo mode: signals from fixtures
- Remediation costs are triage estimates

---

Inputs: outside-in scan of brightwaterfleet.example; brightwater_soc2_type2.md (sha256 d48efc43cbc8); brightwater_cto_interview.wav (sha256 dfec0d51325f)
Models: orchestrator: muse-wonder-1.0 (meta_model_api); document_analysis: muse-wonder-1.0 (meta_model_api); claim_extraction: muse-wonder-1.0 (meta_model_api); crosscheck: muse-wonder-1.0 (meta_model_api); narrative: muse-wonder-1.0 (meta_model_api)
Run cost: $0.3794
Generated by PE Risk Key
