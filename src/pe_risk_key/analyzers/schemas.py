"""Internal extraction schemas for document analyzers (SPEC §4.2)."""

from __future__ import annotations

from typing import Any


def soc2_extraction_schema() -> dict[str, Any]:
    """Strict-ready schema for one-shot SOC 2 extraction.

    Authored directly in the strict subset (every object closed with
    ``additionalProperties: false``, every property required, nullable
    widening where a field may be absent) so it can be sent as strict
    ``json_schema`` without a transform step.
    """
    return {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "report_type",
            "period_start",
            "period_end",
            "auditor",
            "trust_services_categories",
            "opinion",
            "opinion_quote",
            "exceptions",
            "subservice_orgs",
            "cuecs",
            "notable_observations",
            "bridge_letter_provided",
        ],
        "properties": {
            "report_type": {
                "type": "string",
                "enum": ["type1", "type2"],
                "description": "type1 for SOC 2 Type I, type2 for Type II.",
            },
            "period_start": {
                "type": "string",
                "description": "Report period start as YYYY-MM-DD.",
            },
            "period_end": {
                "type": "string",
                "description": "Report period end as YYYY-MM-DD.",
            },
            "auditor": {
                "type": "string",
                "description": "Auditing firm name as stated in the report.",
            },
            "trust_services_categories": {
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": [
                        "security",
                        "availability",
                        "confidentiality",
                        "processing_integrity",
                        "privacy",
                    ],
                },
                "description": "Categories in scope, normalized to enum values.",
            },
            "opinion": {
                "type": "string",
                "enum": ["unqualified", "qualified", "adverse", "disclaimer"],
            },
            "opinion_quote": {
                "type": "string",
                "description": "Exact opinion sentence from the report.",
            },
            "exceptions": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "control_id",
                        "control_ref",
                        "description",
                        "auditor_test",
                        "deviations",
                        "sample_size",
                        "management_response",
                        "locator",
                        "quote",
                        "deal_impact",
                    ],
                    "properties": {
                        "control_id": {
                            "type": "string",
                            "description": "Criterion, e.g. CC6.1.",
                        },
                        "control_ref": {
                            "type": ["string", "null"],
                            "description": "Control reference, e.g. CC6.1-01.",
                        },
                        "description": {
                            "type": "string",
                            "description": "What the control does / what failed.",
                        },
                        "auditor_test": {
                            "type": "string",
                            "description": "Test the auditor performed.",
                        },
                        "deviations": {
                            "type": ["integer", "null"],
                            "minimum": 0,
                            "description": "Deviations noted, null if unstated.",
                        },
                        "sample_size": {
                            "type": ["integer", "null"],
                            "minimum": 0,
                            "description": "Sample size tested, null if unstated.",
                        },
                        "management_response": {
                            "type": ["string", "null"],
                        },
                        "locator": {
                            "type": "string",
                            "description": "Section/page/control ref of the exception.",
                        },
                        "quote": {
                            "type": "string",
                            "description": "Verbatim result text, max 400 chars.",
                        },
                        "deal_impact": {
                            "type": "string",
                            "description": "One-sentence diligence impact.",
                        },
                    },
                },
            },
            "subservice_orgs": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "name",
                        "method",
                        "services",
                        "critical",
                        "locator",
                    ],
                    "properties": {
                        "name": {"type": "string"},
                        "method": {
                            "type": "string",
                            "enum": ["carve_out", "inclusive"],
                        },
                        "services": {
                            "type": "string",
                            "description": "Services the org provides.",
                        },
                        "critical": {
                            "type": "boolean",
                            "description": "True if it hosts production systems or processes the data in scope.",
                        },
                        "locator": {
                            "type": "string",
                            "description": "Section/page where disclosed.",
                        },
                    },
                },
            },
            "cuecs": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["text", "locator"],
                    "properties": {
                        "text": {"type": "string"},
                        "locator": {"type": "string"},
                    },
                },
            },
            "notable_observations": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["text", "locator", "quote"],
                    "properties": {
                        "text": {
                            "type": "string",
                            "description": "Why this matters for diligence.",
                        },
                        "locator": {"type": "string"},
                        "quote": {
                            "type": "string",
                            "description": "Verbatim supporting text, max 400 chars.",
                        },
                    },
                },
            },
            "bridge_letter_provided": {
                "type": "boolean",
                "description": "True if a bridge letter covers the gap through the assessment date.",
            },
        },
    }
