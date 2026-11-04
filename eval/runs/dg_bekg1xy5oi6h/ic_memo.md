# IC Memo: Brightwater Fleet Systems, Inc. (brightwaterfleet.example)

Date: 2026-11-04 | Digest: dg_bekg1xy5oi6h
Rating: D | Decision: Escalate: full cyber diligence required before signing

## Executive summary

Bottom line: Escalate: full cyber diligence required before signing. The 56.8 score and D rating reflect a critical, potentially exploitable exposure, a publicly disclosed incident within 24 months, and multiple management statements contradicted by evidence [F-008] [F-009] [C-001]. Key risks: A critical internet-facing VPN exposure requires version verification; a disclosed incident affected 3,100 individuals; admin MFA and terminated-user access exceptions weaken identity controls; and DMARC is not enforced, leaving the domain spoofable for fraud [F-008] [F-009] [F-010] [F-011] [F-001]. Management credibility: Of 9 claims assessed, 7 were contradicted, 0 unsupported, 2 supported. Management credibility is materially weakened because core statements on access, monitoring, email authentication, and incident history were contradicted by documentary evidence [C-001] [C-002] [C-003] [C-004] [C-005] [C-006] [C-007]. Next steps: Commission full cyber diligence before signing, verify the VPN patch level and compromise history, obtain incident and updated assurance evidence, and confirm insurance placement [F-008] [F-009] [F-014].

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
- [Contradicted/High] C-002: Ofboarding is automated. HR flags the termination and access is revoked same day through our identity provider.
  Evidence: F-011: SOC 2 exception in logical access controls (CC6.2); E-015: Exception noted. 3 of 15 terminated users retained active access for 6, 11, and 19 business days respectively.
- [Contradicted/High] C-003: We have a 24-7 SOC through our MSSP. Every alert gets looked at, nothing nothing sits.
  Evidence: F-012: SOC 2 exception in security monitoring (CC7.2); E-016: Exception noted. For 2 consecutive weeks (Nov 10–23, 2025), alerts were forwarded to a decommissioned distribution list and were not reviewed.
- [Contradicted/High] C-004: We're fully locked down there. DMARC is enforced. Nobody can spoof our domain.
  Evidence: F-001: DMARC not enforced (p=none): domain can be spoofed for BEC/wire fraud; E-001: DMARC record: v=DMARC1; p=none; rua=mailto:dmarc@brightwaterfleet.example; policy=none, pct=100, rua=true.
- [Contradicted/High] C-005: No, nothing material. We've never had a breach.
  Evidence: F-009: Publicly disclosed security incident in the last 24 months; E-013: State AG breach notice dated 2025-08-14: unauthorized access to a customer support system; approx. 3,100 individuals notified; entity_match=exact; disclo
- [Contradicted/Medium] C-006: We decommissioned the legacy stuff a while back. back. Everything external goes through the through the main app and the VPN.
  Evidence: F-004: Publicly logged hostnames suggest exposed admin/legacy/staging systems; E-005: Risky hostname jenkins-old.brightwaterfleet.example, pattern=jenkins|old, first_seen=2021-06-03, last_seen=2026-08-14.; E-007: Risky hostname legacy-portal.brightwaterfleet.example, pattern=legacy, first_seen=2019-11-05, last_seen=2026-07-22; risky_hostnames_count=4.
- [Contradicted/Medium] C-007: Annual third party test. The last one came back clean. no highs.
  Evidence: E-021: CC4.1-01 (An independent penetration test is performed annually.): No exceptions noted. 2 high-severity findings were reported in the test; remediation s; E-029: No exceptions noted. 2 high-severity findings were reported in the test; remediation status was outside the scope of this control.
- [Supported/Info] C-008: Daily backups to immutable storage in a second region and we do a restore test every quarter.
  Evidence: E-020: A1.2-01 (Production data is backed up daily to immutable storage and restore tests are performed quarterly.): No exceptions noted.
- [Supported/Info] C-009: We can get one. one. We haven't needed it so far.
  Evidence: E-030: Management plans to obtain a bridge letter covering April 1, 2026 forward upon request.; F-014: SOC 2 report period ended more than 90 days ago; no bridge letter provided

## SOC 2 summary

Opinion Unqualified; period 2025-04-01 to 2026-03-31; auditor Halvorsen & Pike LLP.
Exceptions:
- CC6.1: 4/25 deviations
- CC6.2: 3/15 deviations
- CC7.2: counts not stated
- CC8.1: 2/40 deviations
Carve-outs: Nimbus Cloud Services, LedgerPay Payroll.
Bridge gap: 217 days.

## 100-day plan

| Window | Action | Owner | Cost |
|---|---|---|---|
| Days 0–30 | Immediately verify ExampleGate SSL-VPN version/patch against the KEV entry, patch or isolate the appliance, and review VPN logs for compromise. | IT Ops | $25K–$150K |
| Days 31–60 | Move DMARC from p=none to quarantine then reject, monitor rua reports, and align SPF/DKIM for all senders. | Security Engineering | $8K–$30K |
| Days 31–60 | Obtain incident report, regulator correspondence, remediation evidence, and lessons-learned actions; verify closure and monitoring improvements. | Incident Response | $25K–$100K |
| Days 31–60 | Remediate CC6.1 exception: MFA is enforced for all administrative access to production systems. | Security Engineering | $20K–$80K |
| Days 31–60 | Remediate CC6.2 exception: Access for terminated employees is revoked within 1 business day of termination. | Security Engineering | $20K–$80K |
| Days 31–60 | Remediate CC7.2 exception: Security alerts generated by the SIEM are reviewed and triaged daily. | SecOps | $15K–$60K |
| Days 61–100 | Inventory authorized senders, then change SPF ~all to -all once legitimate sources are confirmed. | Security Engineering | $2K–$8K |
| Days 61–100 | Validate ownership and exposure of each risky hostname, decommission or restrict legacy/staging/admin systems, and enforce MFA/patching on VPN. | IT Ops | $10K–$50K |
| Days 61–100 | Disable TLSv1.0 and TLSv1.1 on www/web front ends, retain TLSv1.2+, and rescan all hosts for consistency. | Security Engineering | $2K–$15K |
| Days 61–100 | Remediate CC8.1 exception: Production changes are approved by a peer before deployment. | Security Engineering | $5K–$20K |
| Days 61–100 | Obtain a bridge letter covering through 2026-11-03. | CISO/Board | $2K–$10K |
| After day 100 | Enable DNSSEC at the DNS provider/registrar, publish DS records, and monitor validation. | Security Engineering | $2K–$10K |
| After day 100 | Reconcile CT hostnames against CMDB/asset inventory, assign owners, and remove or retire unowned certificates/hosts. | IT Ops | $5K–$20K |
| After day 100 | Add Strict-Transport-Security header with an appropriate max-age on apex and www after confirming full HTTPS support. | Security Engineering | $1K–$5K |
| After day 100 | Obtain the Nimbus Cloud Services SOC report and assess carve-out risk. | CISO/Board | $0–$5K |
| Total | | | $142K–$643K |

## Deal recommendations

### Closing condition
- Require, during Days 0–30, verified VPN version and patch evidence, a compromise assessment of VPN logs, and a bring-down of security representations at signing [F-008]. (basis: F-008)
### Full diligence scope
- Commission, for Days 0–30, an independent review of the known-exploited VPN exposure and validation of management representations against documentary evidence [F-008]. (basis: F-008)
### Specific indemnity
- Secure specific protection for pre-closing losses from the disclosed incident, structured alongside the Days 31–60 incident-evidence review [F-009]. (basis: F-009)
### R&W insurance note
- Expect the known incident to be excluded from representations and warranties coverage, and address any gap during Days 31–60 [F-009]. (basis: F-009)
### Cyber insurance
- Confirm cyber insurability and likely underwriting requirements before close, addressing email authentication and identity controls within Days 31–60 [F-001] [F-010] [F-011]. (basis: F-001, F-010, F-011)
### Post-close covenant
- Bind a post-close covenant to complete identity, monitoring, email-authentication, and external-exposure remediation across Days 31–60 and Days 61–100 [F-010] [F-011] [F-012] [F-013] [F-001] [F-002] [F-004] [F-006] [F-009] [F-014]. (basis: F-010, F-011, F-012, F-013, F-001, F-002, F-004, F-006, F-009, F-014)
### Price adjustment
- Leave the purchase price unchanged because total remediation of $142K–$643K is immaterial relative to the 50M-250M revenue band, with work scheduled from Days 0–30 through After day 100 [F-001] [F-002] [F-003] [F-004] [F-005] [F-006] [F-007] [F-008] [F-009] [F-010] [F-011] [F-012] [F-013] [F-014] [F-015]. (basis: F-001, F-002, F-003, F-004, F-005, F-006, F-007, F-008, F-009, F-010, F-011, F-012, F-013, F-014, F-015)

## Questions for management

1. Provide verified VPN appliance version, patch status, and evidence from a review of VPN logs for compromise [F-008]?
2. Provide the incident report, regulator correspondence, remediation evidence, and lessons-learned actions for the disclosed incident [F-009]?
3. Reconcile the statement that every admin account is behind MFA with the sampled accounts that were not enforced for MFA [F-010] [C-001]?
4. Confirm the current terminated-user revocation process and provide evidence of access removal within the required timeframe [F-011] [C-002]?
5. Provide evidence that security alerts are now reviewed and triaged daily, including routing and escalation controls [F-012] [C-003]?
6. Reconcile the domain-authentication records with the planned move to enforced DMARC and hard-fail SPF [F-001] [F-002]?
7. Confirm ownership, exposure, and disposition for each publicly visible legacy, staging, and administrative hostname [F-004] [F-005]?
8. Provide the bridge letter and the carved-out infrastructure provider report for review [F-014] [F-015]?

## Limitations

- Passive outside-in assessment only; no authenticated or internal testing
- KEV matches are product-level; versions not verified
- Demo mode: signals from fixtures
- Remediation costs are triage estimates

---

Inputs: outside-in scan of brightwaterfleet.example; brightwater_soc2_type2.md (sha256 d48efc43cbc8); brightwater_cto_interview.wav (sha256 dfec0d51325f)
Models: orchestrator: muse-wonder-1.0 (meta_model_api); document_analysis: muse-wonder-1.0 (meta_model_api); transcription: muse-voice-transcribe-1.0 (meta_model_api); claim_extraction: muse-wonder-1.0 (meta_model_api); crosscheck: muse-wonder-1.0 (meta_model_api); narrative: muse-wonder-1.0 (meta_model_api)
Run cost: $0.4011
Generated by PE Risk Key
