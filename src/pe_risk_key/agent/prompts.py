"""Orchestrator prompts.

``FINDING_MAPPING`` holds the finding-mapping rules shared by the agent
and the Wonder smoke test: given collector signals plus scoring.yaml,
how to write findings. The agent adds tool-loop instructions on top.
"""

from __future__ import annotations

import json

FINDING_MAPPING = """1. Map collector signals to findings using the rules in scoring.yaml. For each finding, set rule_id, baseline severity, csf_category, and title from the matching rule.
2. You may adjust severity by at most one level from the baseline, and only with a justification in deal_impact.
3. Cite evidence using only data in the collector output. Every evidence item must have a specific locator (DNS record, hostname, header name, URL, or version string) and the collection_method recorded in the collector output for that collector. Never invent evidence. Copy evidence locators exactly from the collector output fields (queried_name + record_type, URL, hostname); never construct or shorten them.
4. Cap KEV-based findings (KEV-POTENTIAL) at confidence medium and phrase them as "potential exposure".
5. Number findings F-001, F-002, ... and evidence items E-001, E-002, ... uniquely across the response.

Also: set finding source to "outside_in" (evidence source_type "outside_in", except "public_record" for the breach notice) and csf_function to the prefix of csf_category. Fill remediation with a brief summary and effort estimate, but set cost_low_usd, cost_high_usd, and effort_weeks to 0; the engine assigns costs and effort."""

AGENT_LOOP = """You work in a tool loop. Follow these rules:
1. Start with a one-paragraph plan: which collectors you will call and what each finding needs.
2. Call independent collectors in the same turn (one message, several tool calls) so they run in parallel.
3. Call match_known_exploited only after check_web_posture has returned, so it matches the fresh fingerprints.
4. Always pass the target company_name (and aliases when given) to search_public_incidents.
5. Set remediation cost_low_usd, cost_high_usd, and effort_weeks to 0; the engine assigns costs and effort.
6. When every collector has returned, call submit_findings exactly once with the complete findings list."""

SYSTEM_INTRO = (
    "You are a cybersecurity analyst producing triage-grade findings "
    "from passive collector signals for a PE deal team. Use the "
    "collector tools to gather signals, then submit findings with the "
    "submit_findings tool."
)


def system_prompt() -> str:
    """Full orchestrator system prompt."""
    return f"{SYSTEM_INTRO}\n\n{FINDING_MAPPING}\n\n{AGENT_LOOP}"


def target_brief(
    domain: str,
    company_name: str,
    aliases: list[str],
    employee_band: str,
    revenue_band: str,
    industry: str | None,
    scoring_rules_yaml: str,
) -> str:
    """Opening user message: target profile plus scoring rules."""
    lines = [
        f"Target domain: {domain}",
        f"Company: {company_name}",
        f"Aliases: {', '.join(aliases) if aliases else '(none)'}",
        f"Employee band: {employee_band}",
        f"Revenue band: {revenue_band}",
        f"Industry: {industry or '(unknown)'}",
        "",
        "Scoring rules:",
        f"```yaml\n{scoring_rules_yaml}```",
        "",
        "Gather signals with the collector tools, then submit findings.",
    ]
    return "\n".join(lines)


def coverage_followup(missing: list[str], outputs: dict) -> str:
    """Follow-up message asking for one resubmission after a coverage gap."""
    return (
        "Coverage check: you never called these collectors, so they were "
        f"run for you: {', '.join(missing)}.\n"
        f"```json\n{json.dumps(outputs, indent=2)}\n```\n"
        "Review these results and call submit_findings once more with "
        "the updated, complete findings list."
    )
