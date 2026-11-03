# IC Memo: Brightwater Fleet Systems (brightwaterfleet.example)

Date: 2026-11-03 | Digest: dg_mrlm1xvkjctc
Rating: D | Decision: Escalate: full cyber diligence required before signing

## Executive summary

Bottom line: Escalate to full cyber diligence before signing for Brightwater Fleet Systems. It is rated D at 56.8, capped by a critical, potentially exploitable exposure [F-008], a publicly disclosed incident within 24 months [F-009], and multiple management statements contradicted by evidence [C-001].
Key risks: The internet-facing ExampleGate SSL-VPN matches a CISA KEV-listed product with version not verified [F-008]. The disclosed incident affected approx. 3,100 individuals [F-009], 4 of 25 sampled admin accounts lacked enforced MFA [F-010], and 3 of 15 terminated users retained access [F-011]. DMARC is not enforced and alerts went unreviewed for 2 consecutive weeks [F-001] [F-012].
Management credibility: Of 9 contradictions, 7 were contradicted and 2 were supported [C-001] [C-005]. Contradictions cover MFA, offboarding, alert review, DMARC enforcement and incident history [C-001] [C-002] [C-003] [C-004] [C-005].
Next steps: Verify the SSL-VPN version and complete a compromise assessment in Days 0–30 before signing [F-008]. Complete incident and access-control diligence in Days 31–60 [F-009] [F-010].

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
  Evidence: F-001: DMARC not enforced (p=none): domain can be spoofed for BEC/wire fraud; E-001: DMARC record: v=DMARC1; p=none; rua=mailto:dmarc@brightwaterfleet.example; policy: none, pct: 100
- [Contradicted/High] C-005: No, nothing material. We've never had a breach.
  Evidence: F-009: Publicly disclosed security incident in the last 24 months; E-014: State AG breach notice dated 2025-08-14: unauthorized access to a customer support system; approx. 3,100 individuals notified. Entity match exact; disclo
- [Contradicted/Medium] C-006: We decommissioned the legacy stuff a while back. Everything external goes through the main app and the VPN.
  Evidence: F-004: Publicly logged hostnames suggest exposed admin/legacy/staging systems; E-005: Risky hostname jenkins-old.brightwaterfleet.example, pattern jenkins|old, first_seen 2021-06-03, last_seen 2026-08-14; E-007: Risky hostname legacy-portal.brightwaterfleet.example, pattern legacy, first_seen 2019-11-05, last_seen 2026-07-22; risky_hostnames_count 4
- [Contradicted/Medium] C-007: Annual third party test. The last one came back clean. No highs.
  Evidence: E-022: CC4.1-01 (An independent penetration test is performed annually.): No exceptions noted. 2 high-severity findings were reported in the test; remediation s; E-030: No exceptions noted. 2 high-severity findings were reported in the test; remediation status was outside the scope of this control.
- [Supported/Info] C-008: Daily backups to immutable storage in a second region and we do a restore test every quarter.
  Evidence: E-021: A1.2-01 (Production data is backed up daily to immutable storage and restore tests are performed quarterly.): No exceptions noted.
- [Supported/Info] C-009: We can get one. one we haven't needed it so far.
  Evidence: E-031: Management plans to obtain a bridge letter covering April 1, 2026 forward upon request.; F-014: SOC 2 report period ended more than 90 days ago; no bridge letter provided

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
| Days 0–30 | Immediately verify ExampleGate SSL-VPN version/patch against KEV CVE, patch or isolate the appliance, and review for compromise indicators. | IT Ops | $25K–$150K |
| Days 31–60 | Move DMARC from p=none to quarantine then reject after monitoring rua reports and validating all senders. | Security Engineering | $8K–$30K |
| Days 31–60 | Obtain breach investigation, regulator correspondence and remediation evidence; confirm notification obligations closed and lessons implemented. | Incident Response | $25K–$100K |
| Days 31–60 | Remediate CC6.1 exception: 4 of 25 sampled admin accounts were not enforced for MFA. | Security Engineering | $20K–$80K |
| Days 31–60 | Remediate CC6.2 exception: 3 of 15 terminated users retained active access for 6, 11, and 19 business days respectively. | Security Engineering | $20K–$80K |
| Days 31–60 | Remediate CC7.2 exception: For 2 consecutive weeks (Nov 10–23, 2025), alerts were forwarded to a decommissioned distribution list and were not reviewed. | SecOps | $15K–$60K |
| Days 61–100 | Inventory authorized senders, then change SPF from ~all to -all in coordination with DMARC enforcement. | Security Engineering | $2K–$8K |
| Days 61–100 | Validate reachability and ownership of risky hostnames, decommission or restrict legacy/staging/admin systems, and enforce MFA/patching on VPN. | IT Ops | $10K–$50K |
| Days 61–100 | Disable TLSv1.0 and TLSv1.1 on www and other web endpoints, retaining TLS 1.2+. | Security Engineering | $2K–$15K |
| Days 61–100 | Remediate CC8.1 exception: 2 of 40 changes lacked documented approval (emergency hotfixes). | Security Engineering | $5K–$20K |
| Days 61–100 | Obtain a bridge letter covering through 2026-10-30. | CISO/Board | $2K–$10K |
| After day 100 | Enable DNSSEC at the registrar/DNS provider and publish DS records, with monitoring for resolution failures. | Security Engineering | $2K–$10K |
| After day 100 | Reconcile all 47 CT hostnames to an authoritative asset inventory and remove or consolidate unowned/stale services. | IT Ops | $5K–$20K |
| After day 100 | Add Strict-Transport-Security header on apex and www after confirming HTTPS-only operation. | Security Engineering | $1K–$5K |
| After day 100 | Obtain the Nimbus Cloud Services SOC report and assess carve-out risk. | CISO/Board | $0–$5K |
| Total | | | $142K–$643K |

## Deal recommendations

### Closing condition
- Require verification of the ExampleGate SSL-VPN version and patch status, a compromise assessment, and a bring-down of security representations before signing in Days 0–30 as a closing condition under the full cyber diligence required before signing [F-008]. (basis: F-008)
### Full diligence scope
- Commission a scope that technically reviews the KEV-listed SSL-VPN exposure in Days 0–30 and independently validates management representations through Days 31–60 and Days 61–100, reflecting full cyber diligence before signing [F-008] [C-001] [C-005]. (basis: F-008, C-001, C-002, C-003, C-004, C-005, C-007)
### Specific indemnity
- Negotiate protection for pre-closing incident losses through a specific indemnity, informed by the incident review in Days 31–60 and by full cyber diligence before signing [F-009]. (basis: F-009)
### R&W insurance note
- Assume the known disclosed incident will be excluded from representations and warranties coverage, seek broker confirmation in Days 31–60, and complete full cyber diligence before signing without relying on that coverage for this exposure [F-009]. (basis: F-009)
### Cyber insurance
- Confirm cyber insurability and likely underwriting requirements before close, addressing domain-spoofing exposure and the access-control exceptions scheduled for Days 31–60 as part of full cyber diligence before signing [F-001] [F-010] [F-011]. (basis: F-001, F-010, F-011)
### Post-close covenant
- Impose a covenant to complete remaining remediation across Days 31–60, Days 61–100 and After day 100 for access controls, monitoring, change approvals, email authentication, exposed hostnames, transport security, incident closure and the bridge letter, following full cyber diligence before signing [F-010] [F-011] [F-012] [F-001] [F-009] [F-014]. (basis: F-010, F-011, F-012, F-013, F-001, F-002, F-004, F-006, F-009, F-014)
### Price adjustment
- Make no price adjustment on cyber grounds because total remediation of $142K–$643K across Days 0–30 through After day 100 is immaterial relative to the 50M-250M revenue band, while still completing full cyber diligence before signing [F-008] [F-009]. (basis: F-008, F-009, F-010)

## Questions for management

1. Provide the ExampleGate SSL-VPN version, patch evidence and compromise-assessment results for the KEV-listed appliance [F-008].
2. Provide the breach investigation, regulator correspondence and remediation-closure evidence for the disclosed incident affecting approx. 3,100 individuals [F-009] [C-005].
3. Reconcile the claim that every admin account is behind MFA with the 4 of 25 sampled admin accounts not enforced for MFA [F-010] [C-001].
4. Reconcile the claim of automated same-day offboarding with the 3 of 15 terminated users who retained access for 6, 11, and 19 business days [F-011] [C-002].
5. Provide evidence that security alerts are now routed, reviewed and escalated following the 2 consecutive weeks when alerts were not reviewed [F-012] [C-003].
6. Confirm the plan and timetable to move DMARC from monitoring-only to enforcement and to strengthen SPF [F-001] [F-002] [C-004].
7. Provide the SOC 2 bridge letter covering through 2026-10-30 and the Nimbus Cloud Services SOC report for the carved-out hosting service [F-014] [F-015].
8. Reconcile the 47 certificate-transparency hostnames to the authoritative asset inventory, including the VPN, old Jenkins, staging API and legacy portal hostnames [F-004] [F-005] [C-006].

## Limitations

- Passive outside-in assessment only; no authenticated or internal testing
- KEV matches are product-level; versions not verified
- Demo mode: signals from fixtures
- narrative validation incomplete
- Remediation costs are triage estimates

---

Inputs: outside-in scan of brightwaterfleet.example; brightwater_soc2_type2.md (sha256 d48efc43cbc8); brightwater_cto_interview.wav (sha256 dfec0d51325f)
Models: orchestrator: muse-wonder-1.0 (meta_model_api); document_analysis: muse-wonder-1.0 (meta_model_api); claim_extraction: muse-wonder-1.0 (meta_model_api); crosscheck: muse-wonder-1.0 (meta_model_api); narrative: muse-wonder-1.0 (meta_model_api)
Run cost: $0.4706
Generated by PE Risk Key
