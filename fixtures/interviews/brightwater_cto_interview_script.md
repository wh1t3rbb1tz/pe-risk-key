# SYNTHETIC FIXTURE — Management Interview Script

> Fictional diligence call for PE Risk Key testing. Record it yourself with two
> voices (you as the diligence lead, a second person as the CTO). Read naturally;
> small ad-libs are fine and make the transcript more realistic. Target length is
> about 4 minutes. Save as `fixtures/interviews/brightwater_cto_interview.m4a`.
>
> Bracketed notes are for you, not for reading aloud. They map each claim to the
> evidence it should be checked against and the expected verdict.

**Speakers:** Diligence Lead (you) · Dana Reyes, CTO, Brightwater Fleet Systems (fictional)

---

**Diligence Lead:** Thanks for making time, Dana. We'll keep this to the security basics so the deal team has a clean picture. Let's start with identity. How is admin access protected?

**Dana:** Every admin account is behind MFA. No exceptions. That's been true for years; it's enforced through our conditional access policy.

> [Claim 1: control_coverage. Check SOC 2 CC6.1-01: 4 of 25 admin accounts not enforced. Expected: CONTRADICTED, high.]

**Diligence Lead:** And when someone leaves the company?

**Dana:** Offboarding is automated. HR flags the termination, and access is revoked same day through our identity provider.

> [Claim 2: process_maturity. Check SOC 2 CC6.2-01 (3 of 15 retained access 6–19 business days) and management response (manual process, automation still being evaluated). Expected: CONTRADICTED, high.]

**Diligence Lead:** Talk to me about monitoring.

**Dana:** We have a 24/7 SOC through our MSSP. Every alert gets looked at. Nothing sits.

> [Claim 3: control_coverage. Check SOC 2 CC7.2-01: two weeks of unreviewed alerts. Expected: CONTRADICTED, high.]

**Diligence Lead:** Email is a big one for us. Our portfolio companies get hit with wire fraud attempts constantly. Where are you on spoofing protection?

**Dana:** We're fully locked down there. DMARC is enforced. Nobody can spoof our domain.

> [Claim 4: control_exists. Check outside-in: DMARC p=none, SPF ~all. Expected: CONTRADICTED, high.]

**Diligence Lead:** Any security incidents in the last few years?

**Dana:** No. Nothing material. We've never had a breach.

> [Claim 5: incident_history. Check public record: state AG breach notice Aug 2025, ~3,100 individuals. Expected: CONTRADICTED, high. This one should land hardest in the demo.]

**Diligence Lead:** What about your external attack surface? Legacy systems, old infrastructure?

**Dana:** We decommissioned the legacy stuff a while back. Everything external goes through the main app and the VPN.

> [Claim 6: control_coverage. Check outside-in: legacy-portal and jenkins-old hostnames in CT logs (last seen Jul and Aug 2026), legacy TLS on www. Expected: CONTRADICTED, medium. Note: CT presence alone does not prove a host is live; the verdict explanation should say so.]

**Diligence Lead:** Pen testing?

**Dana:** Annual third-party test. The last one came back clean. No highs.

> [Claim 7: third_party_assurance. Check SOC 2 CC4.1-01: Sept 2025 test reported 2 high-severity findings. Expected: CONTRADICTED, medium.]

**Diligence Lead:** Backups and recovery?

**Dana:** Daily backups to immutable storage in a second region, and we do a restore test every quarter.

> [Claim 8: control_exists. Check SOC 2 A1.2-01: no exceptions. Expected: SUPPORTED. Keep this one in the demo to show the engine is fair, not just negative.]

**Diligence Lead:** Last one. Do you have a bridge letter for the period since your SOC 2 ended?

**Dana:** We can get one. We haven't needed it so far.

> [Claim 9: third_party_assurance. Check SOC 2 period end Mar 31, 2026 and Section 5. Expected: SUPPORTED as a statement (it's accurate), but it reinforces the SOC2-BRIDGE-GAP finding.]

**Diligence Lead:** Great, that's what I needed. Thanks, Dana.

---

## Recording tips

- Record in a quiet room on your phone or laptop; 16 kHz or higher mono is plenty.
- Leave a short pause between speakers so diarization has clean turn boundaries.
- Do two takes. Use the cleaner one; keep the other as an eval variant.
- Don't use any real company names or real people's voices without consent.
