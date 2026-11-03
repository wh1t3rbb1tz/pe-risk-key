# IC Memo: Brightwater Fleet Systems, Inc. (brightwaterfleet.example)

Date: 2026-11-03 | Digest: dg_ea8uqhzdk6f5
Rating: D | Decision: Escalate: full cyber diligence required before signing

## Executive summary

Bottom line: Escalate: full cyber diligence required before signing. Brightwater scored 55.5 with a D rating, capped by a critical, potentially exploitable exposure [F-008], a publicly disclosed incident within 24 months [F-009], and multiple management statements contradicted by evidence [C-001] [C-005]. Key risks: The known-exploited internet-facing appliance, with version not verified, could permit edge compromise [F-008]. The disclosed incident affecting approx. 3,100 individuals raises customer trust, regulatory follow-up and insurability concerns [F-009]. Admin accounts not enforced for multifactor authentication and terminated users retaining active access weaken access controls [F-010] [F-011]. Unenforced domain authentication leaves the domain spoofable for payment fraud and phishing [F-001]. Management credibility: Of 9 statements assessed, 7 were contradicted and 2 were supported. Claims on multifactor coverage, same-day offboarding, alert review, domain enforcement and no prior breach were each contradicted by evidence [C-001] [C-002] [C-003] [C-004] [C-005].

## Why the rating

Score 55.5 reflects a critical, potentially exploitable exposure; a publicly disclosed incident within 24 months; multiple management statements contradicted by evidence.
Confidence high, based on outside-in scan, SOC 2 report, management interview.

## Function scores

| Function | Score | Findings |
|---|---|---|
| Govern | 22.2 | 3 |
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
  Evidence: F-010: SOC 2 exception in logical access controls (CC6.1); E-014: **Exception noted.** 4 of 25 sampled admin accounts were not enforced for MFA. These were service-desk accounts created via a legacy provisioning script 
- [Contradicted/High] C-002: Offboarding is automated. HR flags the termination and access is revoked same day through our identity provider.
  Evidence: F-011: SOC 2 exception in logical access controls (CC6.2); E-015: **Exception noted.** 3 of 15 terminated users retained active access for 6, 11, and 19 business days respectively.
- [Contradicted/High] C-003: We have a 24 7 SOC through our MSSP, every alert gets looked at, nothing sits.
  Evidence: F-012: SOC 2 exception in security monitoring (CC7.2); E-017: **Exception noted.** For 2 consecutive weeks (Nov 10–23, 2025), alerts were forwarded to a decommissioned distribution list and were not reviewed.
- [Contradicted/High] C-004: We're fully locked down there. DMARC is enforced. Nobody can spoof our domain.
  Evidence: F-001: DMARC not enforced (p=none): domain can be spoofed for BEC/wire fraud; E-001: v=DMARC1; p=none; rua=mailto:dmarc@brightwaterfleet.example; policy: none; pct: 100
- [Contradicted/High] C-005: No, nothing material. We've never had a breach.
  Evidence: F-009: Publicly disclosed security incident in the last 24 months; E-013: type: state_ag_breach_notice; date: 2025-08-14; Notice filed for unauthorized access to a customer support system; approx. 3,100 individuals notified.; d
- [Contradicted/Medium] C-006: We decommissioned the legacy stuff a while back. Everything external goes through the main app and the VPN.
  Evidence: F-004: Publicly logged hostnames suggest exposed admin/legacy/staging systems; E-007: pattern: legacy; first_seen: 2019-11-05; last_seen: 2026-07-22; E-005: pattern: jenkins|old; first_seen: 2021-06-03; last_seen: 2026-08-14
- [Contradicted/Medium] C-007: Annual third party test. The last one came back clean. No highs.
  Evidence: E-025: CC4.1-01 (An independent penetration test is performed annually.): No exceptions noted. 2 high-severity findings were reported in the test; remediation s; E-021: No exceptions noted. 2 high-severity findings were reported in the test; remediation status was outside the scope of this control.
- [Supported/Info] C-008: Daily backups to immutable storage in a second region and we do a restore test every quarter.
  Evidence: E-024: A1.2-01 (Production data is backed up daily to immutable storage and restore tests are performed quarterly.): No exceptions noted.; E-020: No exceptions noted.
- [Supported/Info] C-009: We can get one. one we haven't needed it so far.
  Evidence: E-034: Management plans to obtain a bridge letter covering April 1, 2026 forward upon request.; F-015: SOC 2 report period ended more than 90 days ago; no bridge letter provided

## SOC 2 summary

Opinion Unqualified; period 2025-04-01 to 2026-03-31; auditor Halvorsen & Pike LLP.
Exceptions:
- CC6.1: 4/25 deviations
- CC6.2: 3/15 deviations
- CC6.6: counts not stated
- CC7.2: counts not stated
- CC8.1: 2/40 deviations
- CC9.2: counts not stated
- A1.2: counts not stated
- CC4.1: counts not stated
Carve-outs: Nimbus Cloud Services, LedgerPay Payroll.
Bridge gap: 213 days.

## 100-day plan

| Window | Action | Owner | Cost |
|---|---|---|---|
| Days 0–30 | Immediately verify ExampleGate SSL-VPN patch level for the KEV CVE, patch/upgrade or isolate, and review appliance logs. | IT Ops | $25K–$150K |
| Days 31–60 | Validate all mail sources, then move DMARC through quarantine to p=reject with monitoring. | Security Engineering | $8K–$30K |
| Days 31–60 | Obtain incident report, regulatory correspondence, remediation evidence, and confirm notification obligations are closed. | Incident Response | $25K–$100K |
| Days 31–60 | Remediate CC6.1 exception: **Exception noted.** 4 of 25 sampled admin accounts were not enforced for MFA. These were service-desk accounts created via a legacy provisioning script that bypassed the conditional access policy. | Security Engineering | $20K–$80K |
| Days 31–60 | Remediate CC6.2 exception: **Exception noted.** 3 of 15 terminated users retained active access for 6, 11, and 19 business days respectively. | Security Engineering | $20K–$80K |
| Days 31–60 | Remediate CC7.2 exception: **Exception noted.** For 2 consecutive weeks (Nov 10–23, 2025), alerts were forwarded to a decommissioned distribution list and were not reviewed. | SecOps | $15K–$60K |
| Days 61–100 | Inventory authorized senders, then change SPF from ~all to -all. | Security Engineering | $2K–$8K |
| Days 61–100 | Verify ownership/liveness of risky hosts, remove or restrict legacy/staging exposure, and enforce MFA on VPN. | IT Ops | $10K–$50K |
| Days 61–100 | Disable TLSv1.0 and TLSv1.1, retain TLSv1.2+ only, and verify all hosts. | Security Engineering | $2K–$15K |
| Days 61–100 | Remediate CC8.1 exception: **Exception noted.** 2 of 40 changes lacked documented approval (emergency hotfixes). | Security Engineering | $5K–$20K |
| Days 61–100 | Remediate CC9.2 exception: No exceptions noted. | CISO/Board | $5K–$25K |
| Days 61–100 | Obtain a bridge letter covering through 2026-10-30. | CISO/Board | $2K–$10K |
| After day 100 | Enable DNSSEC at registrar/DNS provider and verify DS records. | Security Engineering | $2K–$10K |
| After day 100 | Reconcile CT hostnames to CMDB/asset inventory and retire unmanaged hosts. | IT Ops | $5K–$20K |
| After day 100 | Set Strict-Transport-Security on apex and www after confirming HTTPS-only operation. | Security Engineering | $1K–$5K |
| After day 100 | Obtain the Nimbus Cloud Services SOC report and assess carve-out risk. | CISO/Board | $0–$5K |
| Total | | | $147K–$668K |

## Deal recommendations

### Closing condition
- Make signing contingent on verification of the internet-facing appliance patch level and a compromise assessment, together with a bring-down of the security representations, to be completed in Days 0–30. [F-008] The appliance is listed as known-exploited and its version is not verified, so patch status and appliance logs require confirmation in Days 0–30. [F-008] (basis: F-008)
### Full diligence scope
- Commission a scoped review of the known-exploited appliance exposure and independent validation of management representations during Days 0–30. [F-008] The version is not verified for the internet-facing appliance, so independent evidence is required rather than reliance on management statements. [F-008] [C-001] (basis: F-008)
### Specific indemnity
- Seek protection for pre-closing incident losses arising from the publicly disclosed incident, with the incident file and remediation evidence to be delivered in Days 31–60. [F-009] The disclosed incident raises customer trust, notification and regulatory follow-up exposure. [F-009] (basis: F-009)
### R&W insurance note
- Expect the known incident to be likely excluded from representations and warranties coverage, and address that gap in Days 31–60 alongside the incident diligence. [F-009] The publicly disclosed incident creates pre-closing loss exposure that may not transfer through that coverage. [F-009] (basis: F-009)
### Cyber insurance
- Confirm insurability before close and treat cyber insurance as a likely underwriting requirement, with remediation of the cited access and email authentication items scheduled in Days 31–60. [F-001] [F-010] [F-011] Unenforced domain authentication leaves the domain spoofable for payment fraud and phishing. [F-001] Admin accounts not enforced for multifactor authentication and terminated users retaining active access weaken access controls. [F-010] [F-011] (basis: F-001, F-010, F-011)
### Post-close covenant
- Commit the company to complete the remaining remediation after close, with priority items in Days 31–60, further items in Days 61–100, and longer-dated items After day 100. [F-010] [F-011] [F-012] Unreviewed security alerts for 2 consecutive weeks weaken detection and response. [F-012] Publicly logged admin, legacy and staging hostnames expand the attack surface and raise asset inventory questions. [F-004] (basis: F-010, F-011, F-012, F-013, F-014, F-001, F-002, F-004, F-006, F-009, F-015)

## Questions for management

1. Provide the appliance patch level, upgrade evidence and appliance log review for the known-exploited exposure. [F-008]
2. Provide the incident report, regulatory correspondence and evidence that notification obligations are closed for the 2025-08-14 incident. [F-009]
3. Reconcile the claim of multifactor coverage for every admin account with the sampled accounts not enforced for multifactor authentication. [F-010] [C-001]
4. Reconcile the claim of same-day automated offboarding with terminated users retaining active access for 6, 11, and 19 business days. [F-011] [C-002]
5. Provide evidence of alert review and routing after alerts were forwarded to a decommissioned distribution list and not reviewed for 2 consecutive weeks. [F-012] [C-003]
6. Confirm the plan and timeline to enforce domain authentication and strengthen sender authentication. [F-001] [F-002] [C-004]
7. Provide an inventory reconciliation for the 47 hostnames and confirmation of the live status of admin, legacy and staging hosts. [F-004] [F-005] [C-006]

## Limitations

- Passive outside-in assessment only; no authenticated or internal testing
- KEV matches are product-level; versions not verified
- Demo mode: signals from fixtures
- narrative validation incomplete
- Remediation costs are triage estimates

---

Inputs: outside-in scan of brightwaterfleet.example; brightwater_soc2_type2.md (sha256 d48efc43cbc8); brightwater_cto_interview.wav (sha256 dfec0d51325f)
Models: orchestrator: muse-wonder-1.0 (meta_model_api); document_analysis: muse-wonder-1.0 (meta_model_api); claim_extraction: muse-wonder-1.0 (meta_model_api); crosscheck: muse-wonder-1.0 (meta_model_api); narrative: muse-wonder-1.0 (meta_model_api)
Run cost: $0.4665
Generated by PE Risk Key
