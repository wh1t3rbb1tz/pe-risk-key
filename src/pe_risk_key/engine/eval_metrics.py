# SPDX-License-Identifier: AGPL-3.0-or-later
"""Deterministic eval metrics: digests scored against expected fixtures.

Shared by ``scripts/run_digest.py`` (single-run report) and
``scripts/eval.py`` (multi-run harness). Pure functions over fixed
inputs; no model calls.
"""

from __future__ import annotations

import re
from typing import Any


def _finding_matches(
    finding: dict[str, Any], entry: dict[str, Any]
) -> bool:
    """True when a finding satisfies one expected-findings entry.

    Rule ids must match; entries that name a control or subservice org
    additionally require that string in the title or evidence excerpts.
    """
    if finding.get("rule_id") != entry.get("rule_id"):
        return False
    control_id = entry.get("control_id")
    if control_id and control_id not in str(finding.get("title", "")):
        return False
    org = entry.get("subservice_org")
    if org:
        haystack = str(finding.get("title", ""))
        for item in finding.get("evidence", []) or []:
            haystack += "\n" + str(item.get("excerpt", ""))
        if org not in haystack:
            return False
    return True


def score_findings(
    findings: list[dict[str, Any]],
    expected_findings: list[dict[str, Any]],
    must_not_find: list[str] | None = None,
) -> dict[str, Any]:
    """Greedy one-to-one match of findings to expected rules.

    Returns recall, precision (None when no findings), the matched and
    missing expected rules, unexpected rules, exact-severity matches
    among matched pairs, and must_not_find hits.
    """
    unmatched = list(findings)
    matched: list[tuple[dict[str, Any], dict[str, Any]]] = []
    missing: list[str] = []
    for entry in expected_findings:
        hit = next(
            (
                finding
                for finding in unmatched
                if _finding_matches(finding, entry)
            ),
            None,
        )
        if hit is None:
            missing.append(str(entry.get("rule_id")))
        else:
            unmatched.remove(hit)
            matched.append((entry, hit))
    total = len(expected_findings)
    recall = len(matched) / total if total else None
    precision = len(matched) / len(findings) if findings else None
    must = set(must_not_find or [])
    got_rules = {finding.get("rule_id") for finding in findings}
    return {
        "recall": recall,
        "precision": precision,
        "matched": len(matched),
        "total_expected": total,
        "total_findings": len(findings),
        "missing": missing,
        "unexpected": sorted(
            {str(rule) for rule in got_rules if rule} - {
                str(entry.get("rule_id")) for entry in expected_findings
            }
        ),
        "severity_exact": sum(
            1
            for entry, finding in matched
            if finding.get("severity") == entry.get("severity")
        ),
        "must_not_find_hits": sorted(got_rules & must),
    }


def _wanted_verdicts(entry: dict[str, Any]) -> list[str]:
    """Acceptable verdicts: ``verdict_any_of`` wins over ``verdict``."""
    options = entry.get("verdict_any_of")
    if options:
        return [str(option) for option in options]
    if entry.get("verdict"):
        return [str(entry["verdict"])]
    return []


def match_contradictions(
    contradictions: list[dict[str, Any]],
    expected_contradictions: list[dict[str, Any]],
    context_questions: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Match expected claims by keyword regex over claim + question text.

    Returns recall, verdict accuracy over matched claims (None when no
    claim matched), and the missing-claim and wrong-verdict labels.
    """
    questions = context_questions or {}
    matched = 0
    correct = 0
    misses: list[str] = []
    wrong: list[str] = []
    for entry in expected_contradictions:
        pattern = entry.get("match_keywords", "")
        label = f"claim {entry.get('claim_ref')}: {entry.get('topic')}"

        def _matches(contradiction: dict[str, Any]) -> bool:
            if not pattern:
                return False
            text = contradiction["claim"]["text"]
            haystack = text + "\n" + questions.get(text, "")
            return bool(re.search(pattern, haystack, re.IGNORECASE))

        hit = next((c for c in contradictions if _matches(c)), None)
        if hit is None:
            misses.append(label)
            continue
        matched += 1
        wanted = _wanted_verdicts(entry)
        if hit["verdict"] in wanted:
            correct += 1
        else:
            wrong.append(
                f"{label} (want {'/'.join(wanted)}, "
                f"got {hit['verdict']})"
            )
    total = len(expected_contradictions)
    return {
        "recall": matched / total if total else None,
        "accuracy": correct / matched if matched else None,
        "matched": matched,
        "correct": correct,
        "total_expected": total,
        "misses": misses,
        "wrong": wrong,
    }


def score_profile(
    overall: dict[str, Any], expected: dict[str, Any]
) -> dict[str, Any]:
    """Rating/caps/confidence/deal-signal match vs an expected block.

    Accepts both ``expected_overall`` (``caps_applied``, ``max_rating``)
    and ``expected_outside_in_only`` (``caps``, ``rating``) shapes; a
    rating matches when it equals ``rating`` (or ``max_rating``).
    """
    want_caps = expected.get("caps", expected.get("caps_applied", []))
    got_caps = overall.get("rating_caps_applied", [])
    want_rating = expected.get("rating", expected.get("max_rating"))
    got_rating = overall.get("rating")
    want_confidence = expected.get("confidence")
    got_confidence = overall.get("confidence")
    want_signal = expected.get("deal_signal")
    got_signal = overall.get("deal_signal")
    result = {
        "rating_match": got_rating == want_rating,
        "rating_want": want_rating,
        "rating_got": got_rating,
        "caps_match": sorted(want_caps) == sorted(got_caps),
        "caps_want": sorted(want_caps),
        "caps_got": sorted(got_caps),
        "confidence_match": got_confidence == want_confidence,
        "confidence_want": want_confidence,
        "confidence_got": got_confidence,
        "deal_signal_match": got_signal == want_signal,
        "deal_signal_want": want_signal,
        "deal_signal_got": got_signal,
    }
    result["profile_match"] = all(
        result[key]
        for key in (
            "rating_match",
            "caps_match",
            "confidence_match",
            "deal_signal_match",
        )
    )
    return result
