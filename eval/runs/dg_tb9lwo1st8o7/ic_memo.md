# IC Memo: Brightwater Fleet Systems, Inc. (brightwaterfleet.example)

Date: 2026-11-03 | Digest: dg_tb9lwo1st8o7
Rating: D | Decision: Escalate: full cyber diligence required before signing

## Executive summary

Bottom line: Escalate: full cyber diligence required before signing. Brightwater Fleet Systems is rated D at 56.8, capped by a critical, potentially exploitable exposure [F-008], a publicly disclosed incident within 24 months [F-009], and multiple management statements contradicted by evidence [C-001] [C-005]. Key risks: The internet-facing appliance exposure requires verification because its version is not verified [F-008]. The disclosed incident involved unauthorized access to a customer support system with approx. 3,100 individuals notified [F-009]. Access controls showed administrative accounts not enforced for MFA and terminated users retaining access beyond requirement [F-010] [F-011]. The domain can be spoofed because email authentication is not enforced [F-001]. Management credibility: Of 9 statements assessed, 7 were contradicted, 1 was unsupported, and 1 was supported [C-001] [C-007] [C-008] [C-009]. Absolute statements on MFA, offboarding, alert review, domain enforcement and breach history were each contradicted [C-001] [C-002] [C-003] [C-004] [C-005]. Next steps: Verify the appliance and complete the compromise assessment in Days 0–30 [F-008].

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
  Evidence: F-009: Publicly disclosed security incident in the last 24 months; E-014: State AG breach notice 2025-08-14: Notice filed for unauthorized access to a customer support system; approx. 3,100 individuals notified. Entity match ex
- [Contradicted/Medium] C-006: We decommissioned the legacy stuff a while back. Everything external goes through the main app and the VPN.
  Evidence: F-004: Publicly logged hostnames suggest exposed admin/legacy/staging systems; E-007: Risky hostname pattern=legacy, first_seen=2019-11-05, last_seen=2026-07-22; E-005: Risky hostname pattern=jenkins|old, first_seen=2021-06-03, last_seen=2026-08-14
- [Contradicted/Medium] C-007: Annual third party test. The last one came back clean. No highs.
  Evidence: E-022: CC4.1-01 (An independent penetration test is performed annually.): No exceptions noted. 2 high-severity findings were reported in the test; remediation s; E-030: No exceptions noted. 2 high-severity findings were reported in the test; remediation status was outside the scope of this control.
- [Unsupported/Low] C-009: We can get one. one we haven't needed it so far.
  Evidence: F-014: SOC 2 report period ended more than 90 days ago; no bridge letter provided; E-031: Management plans to obtain a bridge letter covering April 1, 2026 forward upon request.
- [Supported/Info] C-008: Daily backups to immutable storage in a second region and we do a restore test every quarter.
  Evidence: E-021: A1.2-01 (Production data is backed up daily to immutable storage and restore tests are performed quarterly.): No exceptions noted.

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
| Days 0–30 | Immediately verify ExampleGate SSL-VPN patch level against KEV, patch/isolate if affected, and check for compromise indicators. | IT Ops | $25K–$150K |
| Days 31–60 | Move DMARC to quarantine then reject, monitoring rua reports and aligning SPF/DKIM first. | Security Engineering | $8K–$30K |
| Days 31–60 | Obtain incident report, regulator closure status and remediation evidence; confirm support-system controls and notification obligations are closed. | Incident Response | $25K–$100K |
| Days 31–60 | Remediate CC6.1 exception: Exception noted. 4 of 25 sampled admin accounts were not enforced for MFA. These were service-desk accounts created via a legacy provisioning script that bypassed the conditional access policy. | Security Engineering | $20K–$80K |
| Days 31–60 | Remediate CC6.2 exception: Exception noted. 3 of 15 terminated users retained active access for 6, 11, and 19 business days respectively. | Security Engineering | $20K–$80K |
| Days 31–60 | Remediate CC7.2 exception: Exception noted. For 2 consecutive weeks (Nov 10–23, 2025), alerts were forwarded to a decommissioned distribution list and were not reviewed. | SecOps | $15K–$60K |
| Days 61–100 | Inventory legitimate senders and change SPF qualifier to -all after DMARC alignment checks. | Security Engineering | $2K–$8K |
| Days 61–100 | Inventory, access-test and retire or restrict risky hosts; confirm VPN/Jenkins/staging/legacy are authenticated and patched. | IT Ops | $10K–$50K |
| Days 61–100 | Disable TLSv1.0/1.1 on www, enforce TLSv1.2+ with modern ciphers and retest all hosts. | Security Engineering | $2K–$15K |
| Days 61–100 | Remediate CC8.1 exception: Exception noted. 2 of 40 changes lacked documented approval (emergency hotfixes). | Security Engineering | $5K–$20K |
| Days 61–100 | Obtain a bridge letter covering through 2026-10-30. | CISO/Board | $2K–$10K |
| After day 100 | Enable DNSSEC at registrar/DNS provider and verify DS publication and validation. | Security Engineering | $2K–$10K |
| After day 100 | Reconcile CT hostnames to asset inventory, remove orphaned certificates/hosts and implement continuous external monitoring. | IT Ops | $5K–$20K |
| After day 100 | Add Strict-Transport-Security header with appropriate max-age after confirming HTTPS coverage, then consider preload. | Security Engineering | $1K–$5K |
| After day 100 | Obtain the Nimbus Cloud Services SOC report and assess carve-out risk. | CISO/Board | $0–$5K |
| Total | | | $142K–$643K |

## Deal recommendations

### Closing condition
- Before signing, require verification of the internet-facing appliance patch level and a compromise assessment, completed in Days 0–30, plus a bring-down of security representations at signing. The appliance is listed as a critical, potentially exploitable exposure with version not verified, so patch status and compromise indicators must be verified rather than assumed [F-008]. (basis: F-008)
### Full diligence scope
- Commission a diligence workstream covering scope review of the listed appliance exposure in Days 0–30 and independent validation of management representations in Days 0–30 [F-008]. Independent validation is required because management representations on access, monitoring, email authentication and incident history were contradicted by evidence [C-001] [C-002] [C-003] [C-004] [C-005]. (basis: F-008, C-001, C-002, C-003, C-004, C-005)
### Specific indemnity
- Seek a specific indemnity for pre-closing incident losses arising from the publicly disclosed incident, with the related report and closure review tracked in Days 31–60. The incident involved unauthorized access to a customer support system with approx. 3,100 individuals notified [F-009]. (basis: F-009)
### R&W insurance note
- Advise the committee that the known, publicly disclosed incident is likely to be excluded from representations and warranties coverage, and confirm the position during Days 31–60 alongside the incident closure review [F-009]. The incident was disclosed 14 months ago and involved customer support data [F-009]. (basis: F-009)
### Cyber insurance
- Confirm insurability before close and treat cyber insurance placement as a likely underwriting requirement, aligned to the Days 31–60 remediation window for email authentication and access controls [F-001] [F-010] [F-011]. Underwriting is likely to focus on the unenforced domain authentication [F-001], administrative accounts not enforced for MFA [F-010], and terminated users retaining access beyond requirement [F-011]. (basis: F-001, F-010, F-011)
### Post-close covenant
- Bind management to a post-close covenant to complete remediation after close, with Days 31–60 items first, Days 61–100 items next, and reporting through completion [F-010] [F-011] [F-012]. The covenant should cover access and monitoring remediation [F-010] [F-011] [F-012], change approval remediation [F-013], email authentication [F-001] [F-002], risky host disposition [F-004], transport security [F-006], incident closure evidence [F-009], and the bridge letter [F-014]. (basis: F-010, F-011, F-012, F-013, F-001, F-002, F-004, F-006, F-009, F-014)
### Price adjustment
- On valuation, no price adjustment is warranted on cyber grounds, with remediation scheduled across Days 0–30, Days 31–60, Days 61–100, and After day 100 [F-008] [F-009] [F-001]. Total remediation is $142K–$643K, which is immaterial relative to the 50M-250M revenue band [F-008] [F-009]. (basis: F-008, F-009, F-001)

## Questions for management

1. Provide verified patch-level evidence and compromise-assessment results for the internet-facing appliance exposure [F-008].
2. Provide the incident report, regulator closure status, and remediation evidence for the incident disclosed on 2025-08-14 involving approx. 3,100 notified individuals [F-009] [C-005].
3. Reconcile the statement that every admin account is behind MFA with the evidence that 4 of 25 sampled administrative accounts were not enforced for MFA [F-010] [C-001].
4. Reconcile the statement that offboarding revokes access same day with the evidence that 3 of 15 terminated users retained access for 6, 11, and 19 business days [F-011] [C-002].
5. Reconcile the statement that every alert gets looked at with the evidence that alerts were not reviewed for 2 consecutive weeks, Nov 10–23, 2025 [F-012] [C-003].
6. Reconcile the statement that the domain cannot be spoofed with the record showing monitoring only and not enforced [F-001] [C-004].
7. Provide a bridge letter covering through 2026-10-30 and the carved-out infrastructure hosting provider report for review [F-014] [F-015].
8. Confirm the inventory, access testing, and disposition for the publicly logged vpn, legacy, staging, and Jenkins hostnames [F-004] [C-006].

## Limitations

- Passive outside-in assessment only; no authenticated or internal testing
- KEV matches are product-level; versions not verified
- Demo mode: signals from fixtures
- Remediation costs are triage estimates

---

Inputs: outside-in scan of brightwaterfleet.example; brightwater_soc2_type2.md (sha256 d48efc43cbc8); brightwater_cto_interview.wav (sha256 dfec0d51325f)
Models: orchestrator: muse-wonder-1.0 (meta_model_api); document_analysis: muse-wonder-1.0 (meta_model_api); claim_extraction: muse-wonder-1.0 (meta_model_api); crosscheck: muse-wonder-1.0 (meta_model_api); narrative: muse-wonder-1.0 (meta_model_api)
Run cost: $0.4855
Generated by PE Risk Key
