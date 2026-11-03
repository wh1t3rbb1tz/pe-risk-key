# IC Memo: Brightwater Fleet Systems, Inc. (brightwaterfleet.example)

Date: 2026-11-03 | Digest: dg_6f0pdq5c5kbz
Rating: D | Decision: Escalate: full cyber diligence required before signing

## Executive summary

Bottom line: Escalate: full cyber diligence required before signing. Rated D at 56.8, capped by a critical, potentially exploitable exposure, a publicly disclosed incident within 24 months, and multiple management statements contradicted by evidence [F-008] [F-009] [C-001] [C-005]. Key risks: A KEV-listed SSL-VPN appliance is internet-facing with version and patch status unverified. A disclosed breach 14 months ago affected ~3,100 individuals. MFA and timely de-provisioning exceptions leave admin and post-termination access exposed, and monitor-only DMARC allows domain spoofing [F-008] [F-009] [F-010] [F-011] [F-001]. Management credibility: Of 9 claims assessed, 7 were contradicted, 1 unsupported, 1 supported. Management credibility is materially weakened because core statements on MFA, offboarding, monitoring, DMARC, and incident history are contradicted by evidence [C-001] [C-002] [C-003] [C-004] [C-005] [C-006] [C-007]. Next steps: Immediately verify the SSL-VPN version and compromise status in Days 0–30, obtain breach and SOC 2 bridge evidence, independently validate management representations, and confirm insurability before signing [F-008] [F-009] [F-014] [F-001].

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
  Evidence: F-010: SOC 2 exception in logical access controls (CC6.1); E-014: Exception noted. 4 of 25 sampled admin accounts were not enforced for MFA. These were service-desk accounts created via a legacy provisioning script that
- [Contradicted/High] C-002: Offboarding is automated. HR flags the termination and access is revoked same day through our identity provider.
  Evidence: F-011: SOC 2 exception in logical access controls (CC6.2); E-015: Exception noted. 3 of 15 terminated users retained active access for 6, 11, and 19 business days respectively.
- [Contradicted/High] C-003: We have a 24 7 SOC through our MSSP, every alert gets looked at, nothing sits.
  Evidence: F-012: SOC 2 exception in security monitoring (CC7.2); E-016: Exception noted. For 2 consecutive weeks (Nov 10–23, 2025), alerts were forwarded to a decommissioned distribution list and were not reviewed.
- [Contradicted/High] C-004: We're fully locked down there. DMARC is enforced. Nobody can spoof our domain.
  Evidence: F-001: DMARC not enforced (p=none): domain can be spoofed for BEC/wire fraud; E-001: record: v=DMARC1; p=none; rua=mailto:dmarc@brightwaterfleet.example; policy: none; pct: 100; rua: true
- [Contradicted/High] C-005: No, nothing material. We've never had a breach.
  Evidence: F-009: Publicly disclosed security incident in the last 24 months; E-013: type: state_ag_breach_notice; date: 2025-08-14; Notice filed for unauthorized access to a customer support system; approx. 3,100 individuals notified. di
- [Contradicted/Medium] C-006: We decommissioned the legacy stuff a while back. Everything external goes through the main app and the VPN.
  Evidence: F-004: Publicly logged hostnames suggest exposed admin/legacy/staging systems; E-007: pattern: legacy; first_seen: 2019-11-05; last_seen: 2026-07-22; E-005: pattern: jenkins|old; first_seen: 2021-06-03; last_seen: 2026-08-14
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
| Days 0–30 | Immediately verify ExampleGate SSL-VPN version/patch against CVE-PLACEHOLDER-0001, patch or isolate, and review appliance logs for compromise. | IT Ops | $25K–$150K |
| Days 31–60 | Move DMARC from p=none to quarantine then reject, validating all legitimate senders and alignment first. | Security Engineering | $8K–$30K |
| Days 31–60 | Obtain breach investigation, regulator correspondence and remediation evidence; confirm notification completion and lessons-learned controls. | Incident Response | $25K–$100K |
| Days 31–60 | Remediate CC6.1 exception: MFA is enforced for all administrative access to production systems. | Security Engineering | $20K–$80K |
| Days 31–60 | Remediate CC6.2 exception: Access for terminated employees is revoked within 1 business day of termination. | Security Engineering | $20K–$80K |
| Days 31–60 | Remediate CC7.2 exception: Security alerts generated by the SIEM are reviewed and triaged daily. | SecOps | $15K–$60K |
| Days 61–100 | Audit authorized senders, then change SPF ~all to -all once legitimate sources are confirmed. | Security Engineering | $2K–$8K |
| Days 61–100 | Inventory the four risky hostnames, decommission or restrict legacy/staging/admin services, and enforce MFA and patching on any retained. | IT Ops | $10K–$50K |
| Days 61–100 | Disable TLS 1.0 and 1.1 on www, retaining TLS 1.2+ with current cipher configuration. | Security Engineering | $2K–$15K |
| Days 61–100 | Remediate CC8.1 exception: Production changes are approved by a peer before deployment. | Security Engineering | $5K–$20K |
| Days 61–100 | Obtain a bridge letter covering through 2026-10-30. | CISO/Board | $2K–$10K |
| After day 100 | Enable DNSSEC at the registrar/DNS provider and verify the DS record and chain of trust. | Security Engineering | $2K–$10K |
| After day 100 | Reconcile all 47 CT hostnames against the CMDB/asset inventory, retire unknown assets, and add CT monitoring. | IT Ops | $5K–$20K |
| After day 100 | Set Strict-Transport-Security on apex and www after confirming HTTPS-only operation, then consider preload. | Security Engineering | $1K–$5K |
| After day 100 | Obtain the Nimbus Cloud Services SOC report and assess carve-out risk. | CISO/Board | $0–$5K |
| Total | | | $142K–$643K |

## Deal recommendations

### Closing condition
- Require verification of the ExampleGate SSL-VPN version and patch status, a compromise assessment of appliance logs, and a bring-down of security representations before signing, aligned to Days 0–30 [F-008]. (basis: F-008)
### Full diligence scope
- Expand the review to independently assess the KEV-listed exposure and validate management representations against primary evidence, completing the initial scope in Days 0–30 [F-008]. (basis: F-008)
### Specific indemnity
- Seek a specific indemnity for losses arising from the pre-closing disclosed incident, with breach investigation and remediation evidence to be delivered in Days 31–60 [F-009]. (basis: F-009)
### R&W insurance note
- Expect the known disclosed incident to be excluded from representations and warranties coverage, and confirm that position during the Days 31–60 review of incident evidence [F-009]. (basis: F-009)
### Cyber insurance
- Confirm cyber insurability before close, including underwriter requirements on DMARC enforcement and the MFA and de-provisioning remediation scheduled for Days 31–60 [F-001] [F-010] [F-011]. (basis: F-001, F-010, F-011)
### Post-close covenant
- Covenant completion after close of the remaining access, monitoring, change-management, email-authentication, hostname, transport-security, breach and bridge-letter remediation across Days 31–60 and Days 61–100 [F-010] [F-011] [F-012] [F-013] [F-001] [F-002] [F-004] [F-006] [F-009] [F-014]. (basis: F-010, F-011, F-012, F-013, F-001, F-002, F-004, F-006, F-009, F-014)
### Price adjustment
- No price adjustment is warranted, as total remediation of $142K–$643K, phased from Days 0–30 through After day 100, is immaterial relative to the 50M-250M revenue band [F-001] [F-002] [F-003] [F-004] [F-005] [F-006] [F-007] [F-008] [F-009] [F-010] [F-011] [F-012] [F-013] [F-014] [F-015]. (basis: F-001, F-002, F-003, F-004, F-005, F-006, F-007, F-008, F-009, F-010, F-011, F-012, F-013, F-014, F-015)

## Questions for management

1. Provide the ExampleGate SSL-VPN version, patch status and appliance-log compromise review for the KEV-listed exposure [F-008]?
2. Provide the breach investigation, regulator correspondence, notification completion and remediation evidence for the disclosed incident [F-009]?
3. Reconcile the sampled admin accounts without MFA enforcement against the current administrative access population and conditional access coverage [F-010] [C-001]?
4. Confirm the current process and evidence for revoking terminated-user access within 1 business day of termination [F-011] [C-002]?
5. Provide evidence that security alerts have been reviewed and triaged daily since Nov 10–23, 2025 [F-012] [C-003]?
6. Provide a bridge letter covering through 2026-10-30 and the Nimbus Cloud Services SOC report for the carved-out hosting service [F-014] [F-015]?
7. Reconcile all 47 CT hostnames against the asset inventory and confirm the status, ownership and hardening of the four risky hostnames [F-004] [F-005]?

## Limitations

- Passive outside-in assessment only; no authenticated or internal testing
- KEV matches are product-level; versions not verified
- Demo mode: signals from fixtures
- Remediation costs are triage estimates

---

Inputs: outside-in scan of brightwaterfleet.example; brightwater_soc2_type2.md (sha256 d48efc43cbc8); brightwater_cto_interview.wav (sha256 dfec0d51325f)
Models: orchestrator: muse-wonder-1.0 (meta_model_api); document_analysis: muse-wonder-1.0 (meta_model_api); claim_extraction: muse-wonder-1.0 (meta_model_api); crosscheck: muse-wonder-1.0 (meta_model_api); narrative: muse-wonder-1.0 (meta_model_api)
Run cost: $0.3872
Generated by PE Risk Key
