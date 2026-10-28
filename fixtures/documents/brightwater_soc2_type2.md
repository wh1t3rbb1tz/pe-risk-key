# SYNTHETIC FIXTURE — NOT A REAL REPORT

> Fictional company, fictional auditor. Created for PE Risk Key testing during the
> Meta Global AI Developer Hackathon (Oct 27 – Nov 4, 2026). Any resemblance to a
> real organization is unintended. Render to PDF for upload tests.

---

# Brightwater Fleet Systems, Inc.

## SOC 2® Type II Report

**Description of the Fleet Telematics Platform System and the Suitability of the Design and Operating Effectiveness of Controls Relevant to Security and Availability**

**For the Period April 1, 2025 to March 31, 2026**

Prepared by: **Halvorsen & Pike LLP** (fictional)

---

## Section 1 — Independent Service Auditor's Report

To the Management of Brightwater Fleet Systems, Inc.:

**Scope.** We have examined Brightwater Fleet Systems, Inc.'s ("Brightwater") accompanying description of its Fleet Telematics Platform system for the period April 1, 2025 to March 31, 2026 (the "description") and the suitability of the design and operating effectiveness of controls stated in the description to provide reasonable assurance that Brightwater's service commitments and system requirements were achieved based on the trust services criteria relevant to Security and Availability.

**Subservice organizations.** Brightwater uses Nimbus Cloud Services (infrastructure hosting) and LedgerPay Payroll (HR and payroll processing, including employee termination records). The description includes only the controls of Brightwater and excludes controls of the subservice organizations (the **carve-out method**). Our examination did not extend to controls of the subservice organizations.

**Complementary user entity controls.** The description indicates that certain complementary user entity controls are necessary, along with Brightwater's controls, to achieve the service commitments. Our examination did not extend to such complementary user entity controls.

**Opinion.** In our opinion, in all material respects, the description presents the system as designed and implemented, and the controls stated in the description were suitably designed and operated effectively throughout the period, **except for the deviations described in Section 4**, which did not, in our judgment, rise to a level that would modify our opinion.

*Halvorsen & Pike LLP — May 22, 2026*

---

## Section 2 — Management's Assertion

Management of Brightwater asserts that the description fairly presents the Fleet Telematics Platform system throughout the period April 1, 2025 to March 31, 2026, and that controls were suitably designed and operated effectively, except for the matters noted in Section 4.

---

## Section 3 — Description of the System

### 3.1 Services provided
Brightwater provides a SaaS platform that ingests vehicle telematics, driver behavior events, and route data from approximately 410 commercial fleet customers.

### 3.2 Infrastructure
Production workloads run in Nimbus Cloud Services (carved out). Corporate identity is managed through a cloud identity provider with SSO for business applications. Administrative access to production uses a bastion host with VPN connectivity.

### 3.3 Monitoring
A managed security service provider (MSSP) operates 24x7 monitoring of Brightwater's SIEM. Alerts are routed to the internal security team for triage.

### 3.4 Data backup and recovery
Production databases are backed up daily to immutable storage in a separate region. Restore tests are performed quarterly.

### 3.5 Complementary User Entity Controls (CUECs)
User entities are responsible for:
1. Provisioning and de-provisioning their own users' access to the Brightwater platform.
2. Enabling SSO/MFA for their users through the customer administration console.
3. Reviewing user access to the platform at least quarterly.
4. Notifying Brightwater promptly of suspected security incidents involving their accounts.
5. Securing API credentials issued to them.

---

## Section 4 — Trust Services Criteria, Controls, Tests, and Results

| Ref | Criterion | Brightwater control | Auditor test | Result |
|---|---|---|---|---|
| CC6.1-01 | CC6.1 | MFA is enforced for all administrative access to production systems. | Selected 25 of 112 administrative accounts and inspected MFA enrollment and enforcement configuration. | **Exception noted.** 4 of 25 sampled admin accounts were not enforced for MFA. These were service-desk accounts created via a legacy provisioning script that bypassed the conditional access policy. |
| CC6.2-01 | CC6.2 | Access for terminated employees is revoked within 1 business day of termination. | Selected 15 of 64 terminations; compared termination date from HR system to access removal date. | **Exception noted.** 3 of 15 terminated users retained active access for 6, 11, and 19 business days respectively. |
| CC6.6-01 | CC6.6 | External network access to production requires VPN plus MFA. | Inspected VPN configuration and authentication settings. | No exceptions noted. |
| CC7.2-01 | CC7.2 | Security alerts generated by the SIEM are reviewed and triaged daily. | Selected 30 days and inspected alert review evidence. | **Exception noted.** For 2 consecutive weeks (Nov 10–23, 2025), alerts were forwarded to a decommissioned distribution list and were not reviewed. |
| CC8.1-01 | CC8.1 | Production changes are approved by a peer before deployment. | Selected 40 of 1,288 production changes; inspected approval records. | **Exception noted.** 2 of 40 changes lacked documented approval (emergency hotfixes). |
| CC9.2-01 | CC9.2 | Critical vendors undergo annual security review. | Inspected vendor inventory and review evidence for 8 critical vendors. | No exceptions noted. |
| A1.2-01 | A1.2 | Production data is backed up daily to immutable storage and restore tests are performed quarterly. | Inspected backup configuration and evidence of 4 quarterly restore tests. | No exceptions noted. |
| CC4.1-01 | CC4.1 | An independent penetration test is performed annually. | Inspected the penetration test report dated September 2025. | No exceptions noted. 2 high-severity findings were reported in the test; remediation status was outside the scope of this control. |

### 4.1 Management responses to exceptions

- **CC6.1-01:** Management disabled the legacy provisioning script in April 2026 and has begun migrating service-desk accounts to the standard conditional access policy. Migration expected to complete Q3 2026.
- **CC6.2-01:** Management is evaluating an automated HR-to-IdP de-provisioning integration. Until then, terminations are processed manually by IT upon email notification from HR.
- **CC7.2-01:** The distribution list was corrected on November 24, 2025. Management has added a weekly check that alert routing is functioning.
- **CC8.1-01:** Management has updated the emergency change procedure to require post-deployment approval within 48 hours.

---

## Section 5 — Other Information Provided by Management (unaudited)

Management plans to obtain a bridge letter covering April 1, 2026 forward upon request.
