# IC Memo: Brightwater Fleet Systems (brightwaterfleet.example)

Rating: D (score 56.82) | Confidence: high | Deal signal: escalate_full_diligence
Caps applied: CAP-CRIT, CAP-INCIDENT, CAP-CONTRADICTION

## Executive summary

Brightwater Fleet Systems is rated D at 56.82 with high confidence, deal signal escalate_full_diligence, and caps CAP-CRIT, CAP-INCIDENT, and CAP-CONTRADICTION applied [F-008] [F-009] [C-001]. GV scores 29.0 and PR 35.2, versus ID 66.4, DE 82.0, RS 82.0, and RC 100.0 [F-014] [F-001]. The top exposure is a potential known-exploited internet-facing ExampleGate appliance, version not verified [F-008]. A disclosed incident dated 2025-08-14 involved unauthorized access to a customer support system, with approx. 3,100 individuals notified [F-009]. Admin-access risk is elevated because sampled admin accounts bypassed MFA via a legacy provisioning script [F-010]. Terminated-user risk is elevated because sampled terminated users retained access beyond the revocation requirement [F-011]. Detection risk is elevated because SIEM alerts went to a decommissioned list and were not reviewed [F-012]. BEC/wire-fraud risk is elevated because DMARC is p=none and not enforced [F-001]. Management credibility is materially impaired: claims of universal MFA, same-day offboarding, continuous alert review, enforced DMARC, and no breach are contradicted [C-001] [C-002] [C-003] [C-004] [C-005]. Claims that legacy systems were decommissioned and third-party testing had no highs are also contradicted [C-006] [C-007]. Next, under escalate_full_diligence, require the days_0_30 ExampleGate action before signing [F-008], complete days_31_60 incident, DMARC, access, and monitoring diligence before closing [F-009] [F-001] [F-010] [F-011] [F-012], and reflect the plan total of 142000 USD to 643000 USD in protections and covenants for days_61_100 and post_100 items [F-002] [F-013] [F-003].

## Findings

| ID | Severity | Title | Cost |
|---|---|---|---|
| F-001 | high | DMARC not enforced (p=none): domain can be spoofed for BEC/wire fraud | $8,000 - $30,000 |
| F-002 | medium | SPF uses soft/neutral fail | $2,000 - $8,000 |
| F-003 | low | DNSSEC not enabled | $2,000 - $10,000 |
| F-004 | medium | Publicly logged hostnames suggest exposed admin/legacy/staging systems | $10,000 - $50,000 |
| F-005 | low | Large certificate footprint relative to company size | $5,000 - $20,000 |
| F-006 | medium | Deprecated TLS versions offered | $2,000 - $15,000 |
| F-007 | low | HSTS not set | $1,000 - $5,000 |
| F-008 | critical | Internet-facing appliance listed in CISA KEV (version not verified) | $25,000 - $150,000 |
| F-009 | high | Publicly disclosed security incident in the last 24 months | $25,000 - $100,000 |
| F-010 | high | SOC 2 exception in logical access controls (CC6.1) | $20,000 - $80,000 |
| F-011 | high | SOC 2 exception in logical access controls (CC6.2) | $20,000 - $80,000 |
| F-012 | high | SOC 2 exception in security monitoring (CC7.2) | $15,000 - $60,000 |
| F-013 | medium | SOC 2 exception in change management (CC8.1) | $5,000 - $20,000 |
| F-014 | medium | SOC 2 report period ended more than 90 days ago; no bridge letter provided | $2,000 - $10,000 |
| F-015 | low | Critical subservice organization carved out of SOC 2 scope | $0 - $5,000 |

## Contradictions

- C-001 [contradicted/high] refs=F-010, E-014: Every admin account is behind MFA. No exceptions. That's been true for years. It's enforced through our conditional access policy.
  SOC 2 CC6.1 exception: 4 of 25 sampled admin accounts were not enforced for MFA, bypassing conditional access via a legacy provisioning script.
- C-002 [contradicted/high] refs=F-011, E-015: Offboarding is automated. HR flags the termination and access is revoked same day through our identity provider.
  SOC 2 CC6.2 exception: 3 of 15 terminated users retained active access for 6, 11, and 19 business days, not same-day revocation.
- C-003 [contradicted/high] refs=F-012, E-016: We have a 24 7 SOC through our MSSP, every alert gets looked at, nothing sits.
  SOC 2 CC7.2 exception: for 2 weeks (Nov 10-23, 2025) alerts went to a decommissioned distribution list and were not reviewed.
- C-004 [contradicted/high] refs=F-001, E-001: We're fully locked down there. DMARC is enforced. Nobody can spoof our domain.
  DMARC record is v=DMARC1; p=none, policy none, so DMARC is not enforced and the domain can be spoofed.
- C-005 [contradicted/high] refs=F-009, E-013: No, nothing material. We've never had a breach.
  State AG breach notice dated 2025-08-14 reports unauthorized access to a customer support system with approx. 3,100 individuals notified.
- C-006 [contradicted/medium] refs=F-004, E-007, E-005: We decommissioned the legacy stuff a while back. Everything external goes through the main app and the VPN.
  CT presence alone doesn't prove a host is live, but legacy-portal (last_seen 2026-07-22) and jenkins-old (2026-08-14) certificates within the last 12 months show active maintenance, contradicting decommissioning a while back.
- C-007 [contradicted/medium] refs=E-021, E-029: Annual third party test. The last one came back clean. No highs.
  CC4.1-01 states 2 high-severity findings were reported in the test, contradicting a clean result with no highs, despite no control exceptions noted.
- C-008 [supported/info] refs=E-020: Daily backups to immutable storage in a second region and we do a restore test every quarter.
  SOC 2 A1.2-01 control was tested with no exceptions noted, positive evidence supporting the backup and restore-test claim for that control.
- C-009 [supported/info] refs=E-030: We can get one. one we haven't needed it so far.
  SOC 2 Section 5 states management plans to obtain a bridge letter covering April 1, 2026 forward upon request, corroborating that one can be obtained.

## 100-day plan

| Window | Action | Owner | Cost |
|---|---|---|---|
| Days 31-60 | Stage DMARC to quarantine then reject, align SPF/DKIM senders, and monitor rua reports. | Security Engineering | $8,000 - $30,000 |
| Days 61-100 | Inventory authorized senders then change SPF to -all once aligned. | Security Engineering | $2,000 - $8,000 |
| Days 61-100 | Validate ownership, exposure and patching of risky hosts; remove or restrict admin/legacy/staging systems. | IT Ops | $10,000 - $50,000 |
| Days 61-100 | Disable TLSv1.0/1.1, retain TLSv1.2+ with modern ciphers, and retest all hosts. | Security Engineering | $2,000 - $15,000 |
| Days 0-30 | Immediately verify ExampleGate version/patch against KEV CVE, patch or isolate VPN, and hunt for compromise. | IT Ops | $25,000 - $150,000 |
| Days 31-60 | Obtain incident report, regulator correspondence, remediation validation, and assess notification/credit-monitoring obligations. | Incident Response | $25,000 - $100,000 |
| Days 31-60 | Remediate CC6.1 exception: MFA is enforced for all administrative access to production systems. | Security Engineering | $20,000 - $80,000 |
| Days 31-60 | Remediate CC6.2 exception: Access for terminated employees is revoked within 1 business day of termination. | Security Engineering | $20,000 - $80,000 |
| Days 31-60 | Remediate CC7.2 exception: Security alerts generated by the SIEM are reviewed and triaged daily. | SecOps | $15,000 - $60,000 |
| Days 61-100 | Remediate CC8.1 exception: Production changes are approved by a peer before deployment. | Security Engineering | $5,000 - $20,000 |
| Days 61-100 | Obtain a bridge letter covering through 2026-10-30. | CISO/Board | $2,000 - $10,000 |

## Deal recommendations

- [escrow_or_holdback] Do not proceed to signing until the ExampleGate verification, patching or isolation, and compromise hunt in the days_0_30 remediation window are evidenced, consistent with escalate_full_diligence. [F-008] (basis: F-008)
- [escrow_or_holdback] Gate signing and closing on diligence evidence and remediation commitments for the incident review, DMARC enforcement, MFA, terminated-user revocation, and SIEM triage items scheduled in days_31_60, consistent with escalate_full_diligence. [F-009] [F-001] [F-010] [F-011] [F-012] (basis: F-009, F-010, F-011, F-012, F-001)
- [escrow_or_holdback] Make the days_61_100 items post-closing covenants with owners and completion evidence for SPF hardening, risky-host validation, legacy TLS removal, change-approval remediation, and the bridge letter, consistent with escalate_full_diligence. [F-002] [F-004] [F-006] [F-013] [F-014] (basis: F-002, F-004, F-006, F-013, F-014)
- [escrow_or_holdback] Track the post_100 items as post-closing hygiene and assurance actions for DNSSEC, certificate-footprint reconciliation, HSTS, and review of the carved-out Nimbus Cloud Services SOC report, consistent with escalate_full_diligence. [F-003] [F-005] [F-007] [F-015] (basis: F-003, F-005, F-007, F-015)

## Limitations

- Passive outside-in assessment only; no authenticated or internal testing
- KEV matches are product-level; versions not verified
- Demo mode: signals from fixtures
