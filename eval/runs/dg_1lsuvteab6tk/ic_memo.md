# IC Memo: Brightwater Fleet Systems, Inc. (brightwaterfleet.example)

Date: 2026-11-03 | Digest: dg_1lsuvteab6tk
Rating: D | Decision: Escalate: full cyber diligence required before signing

## Executive summary

Bottom line: Escalate: full cyber diligence required before signing. The rating is D at 56.8 because caps apply for a critical, potentially exploitable exposure, a publicly disclosed incident within 24 months, and multiple management statements contradicted by evidence [F-008] [F-009] [C-005]. Key risks: A critical perimeter exposure remains unverified at version level. Identity, offboarding and monitoring exceptions weaken access and detection controls. Domain spoofing protection is not enforced. A disclosed incident creates regulatory, customer and insurance exposure [F-008] [F-010] [F-011] [F-012] [F-001] [F-009]. Management credibility: Of 9 claims assessed, 7 were contradicted, 0 unsupported, 2 supported. Management credibility is materially weakened because core claims on access, monitoring, domain protection and incident history were contradicted by independent evidence [C-001] [C-002] [C-003] [C-004] [C-005] [C-006] [C-007]. Next steps: Complete full diligence before signing, verify the critical exposure and any compromise, review the disclosed incident in depth, and validate identity, monitoring and assurance evidence [F-008] [F-009] [F-010] [F-012] [F-014].

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
  Evidence: F-001: DMARC not enforced (p=none): domain can be spoofed for BEC/wire fraud; E-001: v=DMARC1; p=none; rua=mailto:dmarc@brightwaterfleet.example; policy: none; pct: 100
- [Contradicted/High] C-005: No, nothing material. We've never had a breach.
  Evidence: F-009: Publicly disclosed security incident in the last 24 months; E-013: type: state_ag_breach_notice; date: 2025-08-14; Notice filed for unauthorized access to a customer support system; approx. 3,100 individuals notified; di
- [Contradicted/Medium] C-006: We decommissioned the legacy stuff a while back. Everything external goes through the main app and the VPN.
  Evidence: F-004: Publicly logged hostnames suggest exposed admin/legacy/staging systems; E-007: pattern: legacy; first_seen: 2019-11-05; last_seen: 2026-07-22; E-005: pattern: jenkins|old; first_seen: 2021-06-03; last_seen: 2026-08-14
- [Contradicted/Medium] C-007: Annual third party test. The last one came back clean. No highs.
  Evidence: E-021: CC4.1-01 (An independent penetration test is performed annually.): No exceptions noted. 2 high-severity findings were reported in the test; remediation s; E-029: No exceptions noted. 2 high-severity findings were reported in the test; remediation status was outside the scope of this control.
- [Supported/Info] C-008: Daily backups to immutable storage in a second region and we do a restore test every quarter.
  Evidence: E-020: A1.2-01 (Production data is backed up daily to immutable storage and restore tests are performed quarterly.): No exceptions noted.
- [Supported/Info] C-009: We can get one. one we haven't needed it so far.
  Evidence: E-030: Management plans to obtain a bridge letter covering April 1, 2026 forward upon request.; F-014: SOC 2 report period ended more than 90 days ago; no bridge letter provided

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
| Days 0–30 | Immediately verify appliance version and patch status against the KEV entry, patch or restrict access, and review logs for exploitation. | IT Ops | $25K–$150K |
| Days 31–60 | Move DMARC from p=none through quarantine to reject, monitoring rua reports and aligning SPF/DKIM senders. | Security Engineering | $8K–$30K |
| Days 31–60 | Diligence incident root cause, remediation evidence, notifications, litigation/regulatory status, and corrective controls; obtain incident reports. | Incident Response | $25K–$100K |
| Days 31–60 | Remediate CC6.1 exception: Exception noted. 4 of 25 sampled admin accounts were not enforced for MFA. These were service-desk accounts created via a legacy provisioning script that bypassed the conditional access policy. | Security Engineering | $20K–$80K |
| Days 31–60 | Remediate CC6.2 exception: Exception noted. 3 of 15 terminated users retained active access for 6, 11, and 19 business days respectively. | Security Engineering | $20K–$80K |
| Days 31–60 | Remediate CC7.2 exception: Exception noted. For 2 consecutive weeks (Nov 10–23, 2025), alerts were forwarded to a decommissioned distribution list and were not reviewed. | SecOps | $15K–$60K |
| Days 61–100 | Audit authorized senders then change SPF ~all to -all in coordination with DMARC enforcement. | Security Engineering | $2K–$8K |
| Days 61–100 | Verify ownership and exposure of each risky hostname, restrict access, patch or decommission legacy/staging systems. | IT Ops | $10K–$50K |
| Days 61–100 | Disable TLSv1.0 and TLSv1.1 at the web tier/load balancer and retain only modern TLS versions. | Security Engineering | $2K–$15K |
| Days 61–100 | Remediate CC8.1 exception: Exception noted. 2 of 40 changes lacked documented approval (emergency hotfixes). | Security Engineering | $5K–$20K |
| Days 61–100 | Obtain a bridge letter covering through 2026-10-30. | CISO/Board | $2K–$10K |
| After day 100 | Enable DNSSEC at registrar/DNS provider and validate DS publication and resolver handling. | Security Engineering | $2K–$10K |
| After day 100 | Build authoritative external asset inventory, remove stale certificates/hosts, and enforce issuance approval. | IT Ops | $5K–$20K |
| After day 100 | Set Strict-Transport-Security on apex and www after confirming HTTPS coverage, then consider preload. | Security Engineering | $1K–$5K |
| After day 100 | Obtain the Nimbus Cloud Services SOC report and assess carve-out risk. | CISO/Board | $0–$5K |
| Total | | | $142K–$643K |

## Deal recommendations

### Closing condition
- Require, before signing, verification of the appliance version and patch status, a compromise assessment including review of exploitation logs, and a bring-down of security representations, completing the Days 0–30 actions [F-008]. (basis: F-008)
### Full diligence scope
- Authorize an expanded review that independently validates the perimeter exposure and tests management representations against underlying evidence, beginning with the Days 0–30 verification work [F-008]. (basis: F-008)
### Specific indemnity
- Negotiate protection for losses arising from the pre-closing disclosed incident, informed by diligence of root cause, notifications and corrective controls in Days 31–60 [F-009]. (basis: F-009)
### R&W insurance note
- Confirm with brokers that the known disclosed incident is likely excluded from representation and warranty coverage and reflect any gap in transaction protections, alongside the Days 31–60 incident diligence [F-009]. (basis: F-009)
### Cyber insurance
- Engage underwriters early to confirm insurability before close, evidencing planned remediation of domain authentication and administrative access controls in Days 31–60 [F-001] [F-010] [F-011]. (basis: F-001, F-010, F-011)
### Post-close covenant
- Bind the company to a post-close remediation programme covering access enforcement, offboarding, monitoring, change control, email authentication, external exposures and incident corrective actions, sequenced through Days 31–60, Days 61–100 and After day 100 where applicable [F-010] [F-011] [F-012] [F-013] [F-001] [F-002] [F-004] [F-006] [F-009] [F-014]. (basis: F-010, F-011, F-012, F-013, F-001, F-002, F-004, F-006, F-009, F-014)
### Price adjustment
- Record that no price adjustment is warranted on cyber remediation alone, as the $142K–$643K plan, sequenced across Days 0–30 through After day 100, is immaterial relative to the 50M-250M revenue band [F-001] [F-002] [F-003] [F-004] [F-005] [F-006] [F-007] [F-008] [F-009] [F-010] [F-011] [F-012] [F-013] [F-014] [F-015]. (basis: F-001, F-002, F-003, F-004, F-005, F-006, F-007, F-008, F-009, F-010, F-011, F-012, F-013, F-014, F-015)

## Questions for management

1. Provide evidence of the appliance version, current patch status and completed log review for signs of exploitation [F-008]?
2. Provide incident reports, root-cause analysis, notification records and the current regulatory and litigation status for the disclosed incident [F-009]?
3. Reconcile the sampled administrative accounts without enforced multifactor authentication with current access-control records and remediation evidence [F-010] [C-001]?
4. Reconcile terminated-user records with access revocation timestamps and provide evidence of current offboarding controls [F-011] [C-002]?
5. Provide evidence that security alerts are now routed, reviewed and escalated without interruption [F-012] [C-003]?
6. Confirm the plan and timetable for moving domain authentication from monitoring to enforcement and tightening sender policy [F-001] [F-002] [C-004]?
7. Provide a bridge letter covering through 2026-10-30 and the infrastructure hosting provider assurance report for review [F-014] [F-015]?

## Limitations

- Passive outside-in assessment only; no authenticated or internal testing
- KEV matches are product-level; versions not verified
- Demo mode: signals from fixtures
- Remediation costs are triage estimates

---

Inputs: outside-in scan of brightwaterfleet.example; brightwater_soc2_type2.md (sha256 d48efc43cbc8); brightwater_cto_interview.wav (sha256 dfec0d51325f)
Models: orchestrator: muse-wonder-1.0 (meta_model_api); document_analysis: muse-wonder-1.0 (meta_model_api); claim_extraction: muse-wonder-1.0 (meta_model_api); crosscheck: muse-wonder-1.0 (meta_model_api); narrative: muse-wonder-1.0 (meta_model_api)
Run cost: $0.3850
Generated by PE Risk Key
