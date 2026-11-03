# SPDX-License-Identifier: AGPL-3.0-or-later
"""Deterministic engine package: scoring rules live here, never in prompts."""

from pe_risk_key.engine.rules import apply_rule_constraints

__all__ = ["apply_rule_constraints"]
