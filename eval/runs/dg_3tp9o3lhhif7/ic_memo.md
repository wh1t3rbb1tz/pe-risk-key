# IC Memo: Brightwater Fleet Systems, Inc. (brightwaterfleet.example)

Date: 2026-11-03 | Digest: dg_3tp9o3lhhif7
Rating: D | Decision: Escalate: full cyber diligence required before signing

## Executive summary

Bottom line: Escalate: full cyber diligence required before signing. Brightwater Fleet Systems, Inc. scores 57.3 with a D rating, capped by a critical, potentially exploitable exposure [F-008], a publicly disclosed incident within 24 months [F-009], and multiple management statements contradicted by evidence [C-001] [C-005]. Key risks: The internet-facing appliance requires urgent verification because its version is not verified [F-008]. The 2025-08-14 incident affected a customer support system, with approx. 3,100 individuals notified [F-009]. Access testing found 4 of 25 admin accounts not enforced for multifactor authentication and 3 of 15 terminated users retained access for 6, 11, and 19 business days [F-010] [F-011]. Alerts were not reviewed for 2 consecutive weeks [F-012]. Management credibility: Of 9 statements, 7 were contradicted and 2 supported, including on multifactor authentication, offboarding, alert review, domain enforcement, and incident history [C-001] [C-002] [C-003] [C-004] [C-005].

## Why the rating

Score 57.3 reflects a critical, potentially exploitable exposure; a publicly disclosed incident within 24 months; multiple management statements contradicted by evidence.
Confidence high, based on outside-in scan, SOC 2 report, management interview.

## Function scores

| Function | Score | Findings |
|---|---|---|
| Govern | 29.0 | 2 |
| Identify | 66.4 | 3 |
| Protect | 35.2 | 8 |
| Detect | 82.0 | 1 |
| Respond | 86.5 | 1 |
| Recover | 100.0 | 0 |

## Key risks

- [Critical] Internet-facing appliance listed in CISA KEV (version not verified) (F-008, $25K–$150K)
- [High] DMARC not enforced (p=none): domain can be spoofed for BEC/wire fraud (F-001, $8K–$30K)
- [High] Publicly disclosed security incident in the last 24 months (F-009, $25K–$100K)
- [High] SOC 2 exception in logical access controls (CC6.1) (F-010, $20K–$80K)
- [High] SOC 2 exception in logical access controls (CC6.2) (F-011, $20K–$80K)

## Management claims vs. evidence

- [Contradicted/High] C-001: Every admin account is behind MFA. No exceptions. That's been true for years. It's enforced through our conditional access policy.
  Evidence: F-010: SOC 2 exception in logical access controls (CC6.1); E-014: 4 of 25 sampled admin accounts were not enforced for MFA. These were service-desk accounts created via a legacy provisioning script that bypassed the con
- [Contradicted/High] C-002: Offboarding is automated. HR flags the termination and access is revoked same day through our identity provider.
  Evidence: F-011: SOC 2 exception in logical access controls (CC6.2); E-015: 3 of 15 terminated users retained active access for 6, 11, and 19 business days respectively.
- [Contradicted/High] C-003: We have a 24 7 SOC through our MSSP, every alert gets looked at, nothing sits. Email
  Evidence: F-012: SOC 2 exception in security monitoring (CC7.2); E-016: For 2 consecutive weeks (Nov 10–23, 2025), alerts were forwarded to a decommissioned distribution list and were not reviewed.
- [Contradicted/High] C-004: We're fully locked down there. DMARC is enforced. Nobody can spoof our domain.
  Evidence: F-001: DMARC not enforced (p=none): domain can be spoofed for BEC/wire fraud; E-001: v=DMARC1; p=none; rua=mailto:dmarc@brightwaterfleet.example; policy=none, pct=100, rua=true
- [Contradicted/High] C-005: No, nothing material. We've never had a breach.
  Evidence: F-009: Publicly disclosed security incident in the last 24 months; E-013: type=state_ag_breach_notice, date=2025-08-14: Notice filed for unauthorized access to a customer support system; approx. 3,100 individuals notified. Enti
- [Contradicted/Medium] C-006: We decommissioned the legacy stuff a while back. Everything external goes through the main app and the VPN.
  Evidence: F-004: Publicly logged hostnames suggest exposed admin/legacy/staging systems; E-007: risky hostname pattern=legacy, first_seen=2019-11-05, last_seen=2026-07-22; E-005: risky hostname pattern=jenkins|old, first_seen=2021-06-03, last_seen=2026-08-14
- [Contradicted/Medium] C-007: Annual third party test. The last one came back clean. No highs.
  Evidence: E-021: CC4.1-01 (An independent penetration test is performed annually.): An independent penetration test is performed annually.; E-029: No exceptions noted. 2 high-severity findings were reported in the test; remediation status was outside the scope of this control.
- [Supported/Info] C-008: Daily backups to immutable storage in a second region and we do a restore test every quarter.
  Evidence: E-020: A1.2-01 (Production data is backed up daily to immutable storage and restore tests are performed quarterly.): Production data is backed up daily to immut
- [Supported/Info] C-009: We can get one. one we haven't needed it so far.
  Evidence: E-030: Management plans to obtain a bridge letter covering April 1, 2026 forward upon request.

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
| Days 0–30 | Immediately verify ExampleGate SSL-VPN version and KEV CVE applicability, patch or isolate the appliance, enforce MFA, and review logs for exploitation. | IT Ops | $25K–$150K |
| Days 31–60 | Move DMARC from p=none to quarantine then reject, validating all legitimate senders and rua reporting first. | Security Engineering | $8K–$30K |
| Days 31–60 | Request incident postmortem, regulator closure status, affected-system remediation, and evidence of post-incident monitoring and control improvements. | Incident Response | $25K–$100K |
| Days 31–60 | Remediate CC6.1 exception: 4 of 25 sampled admin accounts were not enforced for MFA. | Security Engineering | $20K–$80K |
| Days 31–60 | Remediate CC6.2 exception: 3 of 15 terminated users retained active access for 6, 11, and 19 business days respectively. | Security Engineering | $20K–$80K |
| Days 31–60 | Remediate CC7.2 exception: For 2 consecutive weeks (Nov 10–23, 2025), alerts were forwarded to a decommissioned distribution list and were not reviewed. | SecOps | $15K–$60K |
| Days 61–100 | Inventory authorized senders, then change SPF qualifier from ~all to -all in coordination with DMARC enforcement. | Security Engineering | $2K–$8K |
| Days 61–100 | Validate each risky hostname, restrict admin/staging access behind MFA/VPN, patch or decommission legacy systems, and inventory certificates. | IT Ops | $10K–$50K |
| Days 61–100 | Disable TLSv1.0 and TLSv1.1 on www and all edge endpoints, retaining TLSv1.2+ with modern ciphers. | Security Engineering | $2K–$15K |
| Days 61–100 | Remediate CC8.1 exception: 2 of 40 changes lacked documented approval (emergency hotfixes). | Security Engineering | $5K–$20K |
| Days 61–100 | Obtain a bridge letter covering through 2026-10-30. | CISO/Board | $2K–$10K |
| After day 100 | Enable DNSSEC at registrar/registry and monitor DS/DNSKEY validation. | Security Engineering | $2K–$10K |
| After day 100 | Reconcile the 47 CT hostnames against CMDB/cloud inventories, assign owners, and remove stale certificates/hosts. | IT Ops | $5K–$20K |
| After day 100 | Set Strict-Transport-Security with an appropriate max-age on apex and www after confirming all subdomains are HTTPS-ready. | Security Engineering | $1K–$5K |
| After day 100 | Obtain the Nimbus Cloud Services SOC report and assess carve-out risk. | CISO/Board | $0–$5K |
| Total | | | $142K–$643K |

## Deal recommendations

### Closing condition
- Make signing conditional on verification of the internet-facing appliance version and applicability of the listed exposure, completion of a compromise assessment, and bring-down of security representations, with this work completed in Days 0–30 [F-008]. (basis: F-008)
### Full diligence scope
- Commission an independent review, scoped in Days 0–30, that examines the listed appliance exposure and independently validates management representations before reliance is placed on them [F-008] [C-001] [C-002] [C-003] [C-004] [C-005]. (basis: F-008)
### Specific indemnity
- Allocate losses arising from the pre-closing incident disclosed on 2025-08-14 through a specific indemnity, while the related postmortem and closure work proceeds in Days 31–60 [F-009]. (basis: F-009)
### R&W insurance note
- Expect the disclosed incident to be treated as a known matter likely excluded from representations and warranties coverage, and plan on that basis during the Days 31–60 incident-review window [F-009]. (basis: F-009)
### Cyber insurance
- Confirm insurability and likely cyber insurance underwriting requirements before close, addressing the email authentication and access-control matters scheduled for Days 31–60 [F-001] [F-010] [F-011]. (basis: F-001, F-010, F-011)
### Post-close covenant
- Require completion after close of the outstanding access-control, monitoring, change-management, email-authentication, hostname, transport-security, incident, and reporting remediation, tracked across Days 31–60 and Days 61–100 [F-010] [F-011] [F-012] [F-013] [F-001] [F-002] [F-004] [F-006] [F-009] [F-014]. (basis: F-010, F-011, F-012, F-013, F-001, F-002, F-004, F-006, F-009, F-014)
### Price adjustment
- On price, no adjustment is warranted, because total remediation of $142K–$643K across Days 0–30 through After day 100 is immaterial relative to the 50M-250M revenue band [F-008] [F-009]. (basis: F-008, F-009)

## Questions for management

1. Provide evidence of the appliance version, patch level, exposure, multifactor authentication status, and log review for exploitation [F-008].
2. Provide the incident postmortem, regulator closure status, and remediation evidence for the customer support system incident disclosed on 2025-08-14 [F-009] [C-005].
3. Reconcile the statement that every admin account is behind multifactor authentication with the finding that 4 of 25 sampled admin accounts were not enforced [F-010] [C-001].
4. Reconcile the statement that offboarding revokes access the same day with the finding that 3 of 15 terminated users retained active access for 6, 11, and 19 business days [F-011] [C-002].
5. Provide evidence that security alerts are now routed, reviewed, and escalated following the 2 consecutive weeks when alerts were not reviewed [F-012] [C-003].
6. Confirm the roadmap and timeline to enforce domain authentication, including validation of legitimate senders and reporting [F-001] [C-004].
7. Provide an inventory reconciling the 47 hostnames and the 4 risky hostnames, with ownership, authentication, patching, and decommissioning status for each [F-004] [F-005] [C-006].
8. Provide the bridge letter covering through 2026-10-30 and the report for the carved-out infrastructure hosting provider [F-014] [F-015].

## Limitations

- Passive outside-in assessment only; no authenticated or internal testing
- KEV matches are product-level; versions not verified
- Demo mode: signals from fixtures
- narrative validation incomplete
- Remediation costs are triage estimates

---

Inputs: outside-in scan of brightwaterfleet.example; brightwater_soc2_type2.md (sha256 d48efc43cbc8); brightwater_cto_interview.wav (sha256 dfec0d51325f)
Models: orchestrator: muse-wonder-1.0 (meta_model_api); document_analysis: muse-wonder-1.0 (meta_model_api); claim_extraction: muse-wonder-1.0 (meta_model_api); crosscheck: muse-wonder-1.0 (meta_model_api); narrative: muse-wonder-1.0 (meta_model_api)
Run cost: $0.4467
Generated by PE Risk Key
