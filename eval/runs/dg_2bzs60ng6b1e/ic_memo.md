# IC Memo: Brightwater Fleet Systems (brightwaterfleet.example)

Date: 2026-11-03 | Digest: dg_2bzs60ng6b1e
Rating: D | Decision: Escalate: full cyber diligence required before signing

## Executive summary

Bottom line: Escalate: full cyber diligence required before signing. It is rated D at 56.82 due to a critical, potentially exploitable exposure [F-008], a publicly disclosed incident within 24 months [F-009], and multiple management statements contradicted by evidence [C-001] [C-005].

Key risks: The VPN appliance needs urgent version, patch and compromise validation [F-008]. The domain can be spoofed because email authentication is not enforced [F-001]. Administrators lacked multifactor authentication and terminated users retained access [F-010] [F-011]. Security alerts went unreviewed and the prior incident affected approximately 3,100 individuals [F-012] [F-009].

Management credibility: Of 9 items, 7 were contradicted and 2 supported, spanning access, offboarding, monitoring, email authentication, incident history, legacy systems and third-party testing [C-001] [C-002] [C-003] [C-004] [C-005] [C-006] [C-007].

Next steps: Complete full diligence before signing, starting with Days 0–30 VPN verification, then Days 31–60 incident, email, access and monitoring remediation planning [F-008] [F-009] [F-001] [F-010] [F-012].

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
  Evidence: F-001: DMARC not enforced (p=none): domain can be spoofed for BEC/wire fraud; E-001: DMARC record: v=DMARC1; p=none; rua=mailto:dmarc@brightwaterfleet.example (policy: none, pct: 100, rua: true)
- [Contradicted/High] C-005: No, nothing material. We've never had a breach.
  Evidence: F-009: Publicly disclosed security incident in the last 24 months; E-014: State AG breach notice dated 2025-08-14 (disclosed_within_months: 14): unauthorized access to a customer support system; approx. 3,100 individuals notifi
- [Contradicted/Medium] C-006: We decommissioned the legacy stuff a while back. Everything external goes through the main app and the VPN.
  Evidence: F-004: Publicly logged hostnames suggest exposed admin/legacy/staging systems; E-005: Risky hostname pattern: jenkins|old; first_seen 2021-06-03, last_seen 2026-08-14; E-007: Risky hostname pattern: legacy; first_seen 2019-11-05, last_seen 2026-07-22
- [Contradicted/Medium] C-007: Annual third party test. The last one came back clean. No highs.
  Evidence: E-022: No exceptions noted. 2 high-severity findings were reported in the test; remediation status was outside the scope of this control.; E-030: No exceptions noted. 2 high-severity findings were reported in the test; remediation status was outside the scope of this control.
- [Supported/Info] C-008: Daily backups to immutable storage in a second region and we do a restore test every quarter.
  Evidence: E-021: No exceptions noted.
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
| Days 0–30 | Urgently verify ExampleGate SSL-VPN version and patch level against KEV, patch or isolate the appliance, and review VPN logs for compromise. | IT Ops | $25K–$150K |
| Days 31–60 | Move DMARC from p=none to p=quarantine then p=reject, validating SPF/DKIM alignment for all senders. | Security Engineering | $8K–$30K |
| Days 31–60 | Obtain incident report, regulator correspondence, and remediation evidence; confirm notification completion, root-cause closure, and any outstanding obligations. | Incident Response | $25K–$100K |
| Days 31–60 | Remediate CC6.1 exception: MFA is enforced for all administrative access to production systems. | Security Engineering | $20K–$80K |
| Days 31–60 | Remediate CC6.2 exception: Access for terminated employees is revoked within 1 business day of termination. | Security Engineering | $20K–$80K |
| Days 31–60 | Remediate CC7.2 exception: Security alerts generated by the SIEM are reviewed and triaged daily. | SecOps | $15K–$60K |
| Days 61–100 | Confirm all authorized senders, then change SPF qualifier from ~all to -all. | Security Engineering | $2K–$8K |
| Days 61–100 | Inventory listed hosts, confirm business need, remove or restrict legacy/staging/admin systems behind VPN/IP allowlists and MFA. | IT Ops | $10K–$50K |
| Days 61–100 | Disable TLSv1.0/TLSv1.1 on www, retain TLSv1.2+ with modern ciphers, and standardize TLS config across hosts. | Security Engineering | $2K–$15K |
| Days 61–100 | Remediate CC8.1 exception: Production changes are approved by a peer before deployment. | Security Engineering | $5K–$20K |
| Days 61–100 | Obtain a bridge letter covering through 2026-10-30. | CISO/Board | $2K–$10K |
| After day 100 | Enable DNSSEC at registrar/DNS provider and publish DS records, monitoring resolution after signing. | Security Engineering | $2K–$10K |
| After day 100 | Reconcile CT hostnames to an authoritative asset inventory, retire stale hosts, and assign owners for the remainder. | IT Ops | $5K–$20K |
| After day 100 | Add Strict-Transport-Security with appropriate max-age after confirming HTTPS-only operation on all subdomains. | Security Engineering | $1K–$5K |
| After day 100 | Obtain the Nimbus Cloud Services SOC report and assess carve-out risk. | CISO/Board | $0–$5K |
| Total | | | $142K–$643K |

## Deal recommendations

### Closing condition
- Closing condition: Given the deal signal to escalate and complete full cyber diligence before signing, make signing conditional on Days 0–30 verification and compromise assessment of the internet-facing VPN appliance and a bring-down of security representations at signing [F-008]. (basis: F-008, C-008, C-001, C-002, C-003, C-004, C-005, C-006, C-007)
### Full diligence scope
- Full diligence scope: Given the deal signal to escalate and complete full cyber diligence before signing, commission Days 0–30 and Days 31–60 diligence covering the scope and exploitability of the known-exploited-vulnerability-listed VPN exposure and independent validation of management representations [F-008] [C-001] [C-005]. (basis: F-008, C-001, C-005, F-004)
### Specific indemnity
- Specific indemnity: Given the deal signal to escalate and complete full cyber diligence before signing, seek a specific indemnity for pre-closing incident losses, with diligence and any related remediation tracked through Days 31–60 [F-009]. (basis: F-009, C-005)
### R&W insurance note
- Representations and warranties insurance: Given the deal signal to escalate and complete full cyber diligence before signing, assume the known incident is likely excluded from representations and warranties coverage and confirm the position during Days 0–30 diligence [F-009]. (basis: F-009, C-005)
### Cyber insurance
- Cyber insurance: Given the deal signal to escalate and complete full cyber diligence before signing, treat cyber insurance as a likely underwriting requirement and confirm insurability before close during Days 0–30 [F-009] [F-008]. (basis: F-009, F-008, C-005)
### Post-close covenant
- Post-close covenant: Given the deal signal to escalate and complete full cyber diligence before signing, impose a post-close covenant to complete remediation across Days 31–60, Days 61–100 and After day 100, including email authentication, access, monitoring and exposed-system remediation [F-001] [F-010] [F-011] [F-012]. (basis: F-001, F-010, F-011, F-012, F-002, F-004, F-006)
### Price adjustment
- Price adjustment: Given the deal signal to escalate and complete full cyber diligence before signing, no price adjustment is warranted because the $142K–$643K remediation total is immaterial relative to the 50M-250M revenue band, with spend sequenced across Days 0–30 through After day 100 [F-008] [F-009]. (basis: F-001, F-008, F-009)

## Questions for management

1. Provide evidence of the VPN appliance version, patch level, isolation status and compromise review, including relevant VPN logs [F-008].
2. Reconcile the statement that every administrator uses multifactor authentication with the sampled accounts that were not enforced [C-001] [F-010].
3. Reconcile the same-day offboarding statement with terminated users retaining access for 6, 11, and 19 business days [C-002] [F-011].
4. Provide the incident report, regulator correspondence and remediation closure evidence for the incident affecting approximately 3,100 individuals [F-009] [C-005].
5. Confirm the plan and timetable to move email authentication from monitoring to enforcement and strengthen sender validation [F-001] [F-002].
6. Provide evidence that security alerts are now reviewed daily and reconcile the two-week period when alerts were not reviewed [C-003] [F-012].
7. Reconcile the claimed decommissioning of legacy systems with the current inventory, ownership and access controls for publicly logged legacy, staging and administrative hosts [C-006] [F-004] [F-005].

## Limitations

- Passive outside-in assessment only; no authenticated or internal testing
- KEV matches are product-level; versions not verified
- Demo mode: signals from fixtures
- Remediation costs are triage estimates

---

Inputs: outside-in scan of brightwaterfleet.example; brightwater_soc2_type2.md (sha256 d48efc43cbc8); brightwater_cto_interview.wav (sha256 dfec0d51325f)
Models: orchestrator: muse-wonder-1.0 (meta_model_api); public_records: muse-spark-1.3 (meta_model_api); document_analysis: muse-wonder-1.0 (meta_model_api); transcription: muse-voice-transcribe-1.0 (meta_model_api); claim_extraction: muse-wonder-1.0 (meta_model_api); crosscheck: muse-wonder-1.0 (meta_model_api); narrative: muse-wonder-1.0 (meta_model_api)
Run cost: $0.4274
Generated by PE Risk Key
