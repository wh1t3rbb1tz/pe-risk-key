"""Tests for pe_risk_key.analyzers.soc2 (mocked model). No network."""

import copy
import hashlib
import json
from datetime import date
from pathlib import Path

import jsonschema
import pytest
from pypdf import PdfReader
from pypdf.generic import DecodedStreamObject, DictionaryObject, NameObject
from pypdf import PdfWriter

import pe_risk_key.analyzers.soc2 as soc2_module
from pe_risk_key.analyzers.soc2 import analyze_soc2
from pe_risk_key.schemas import subschema

SOC_TEXT = """# Synthetic SOC 2 Type II Report

Firm: Example Audit Partners LLP.
Period: April 1, 2025 to March 31, 2026.
Categories: Security and Availability.

## Opinion
In our opinion, the controls were suitably designed and operated effectively throughout the period, except for the deviations described in Section 4, which did not modify our opinion.

## Section 4 - Test Results
CC6.1-01 Logical access reviews. Test: inspected a sample of 25 quarterly access reviews. Result: 2 of 25 reviews were not evidenced. Management will automate reminders.
CC6.2-01 Admin access reviews. Result: 1 of 20 reviews was late.
CC7.2-01 Alert monitoring. Result: 3 of 30 alerts were unreviewed.
CC8.1-01 Change tickets. Result: 1 of 15 changes lacked approval.
CC1.1-01 Control environment. Result: no deviations noted.

## Subservice organizations
Nimbus Cloud Services provides production hosting. Carve-out method applies.
LedgerPay Payroll provides payroll processing. Carve-out method applies.

## Complementary user entity controls
Customers must review user access quarterly.

## Notes
Penetration testing is performed annually by an external firm.
A bridge letter covers the period through October 30, 2026.
"""

OPINION_QUOTE = "In our opinion, the controls were suitably designed and operated effectively throughout the period, except for the deviations described in Section 4, which did not modify our opinion."

AS_OF = date(2026, 10, 30)


def _exception(
    control_id,
    quote,
    control_ref=None,
    deviations=1,
    sample_size=10,
    management_response="Management acknowledged.",
    locator="Section 4",
    deal_impact="Deal impact sentence.",
):
    return {
        "control_id": control_id,
        "control_ref": control_ref,
        "description": f"Description of {control_id}.",
        "auditor_test": f"Test of {control_id}.",
        "deviations": deviations,
        "sample_size": sample_size,
        "management_response": management_response,
        "locator": locator,
        "quote": quote,
        "deal_impact": deal_impact,
    }


def _extraction(**overrides):
    base = {
        "report_type": "type2",
        "period_start": "2025-04-01",
        "period_end": "2026-03-31",
        "auditor": "Example Audit Partners LLP",
        "trust_services_categories": ["security", "availability"],
        "opinion": "unqualified",
        "opinion_quote": OPINION_QUOTE,
        "exceptions": [
            _exception(
                "CC6.1",
                "Result: 2 of 25 reviews were not evidenced.",
                control_ref="CC6.1-01",
                deviations=2,
                sample_size=25,
                management_response="Management will automate reminders.",
                locator="Section 4, CC6.1-01",
            )
        ],
        "subservice_orgs": [
            {
                "name": "Nimbus Cloud Services",
                "method": "carve_out",
                "services": "production hosting",
                "critical": True,
                "locator": "Subservice organizations",
            },
            {
                "name": "LedgerPay Payroll",
                "method": "carve_out",
                "services": "payroll processing",
                "critical": False,
                "locator": "Subservice organizations",
            },
        ],
        "cuecs": [
            {
                "text": "Customers must review user access quarterly.",
                "locator": "Complementary user entity controls",
            }
        ],
        "notable_observations": [
            {
                "text": "Annual pen test noted.",
                "locator": "Notes",
                "quote": "Penetration testing is performed annually by an external firm.",
            }
        ],
        "bridge_letter_provided": False,
    }
    base.update(overrides)
    return base


class _ScriptedSoc2Client:
    extraction = {}
    calls: list = []

    def __init__(self, role, mode="standard", **kwargs):
        assert role == "document_analysis", role
        self.total_usage = {
            "prompt_tokens": 1000,
            "completion_tokens": 200,
            "cached_tokens": 0,
        }

    def chat_json(
        self, messages, *, schema, schema_name, reasoning_effort=None, **kwargs
    ):
        type(self).calls.append(
            {
                "messages": messages,
                "schema": schema,
                "schema_name": schema_name,
                "reasoning_effort": reasoning_effort,
            }
        )
        return copy.deepcopy(type(self).extraction)


@pytest.fixture
def soc2_env(monkeypatch, tmp_path):
    _ScriptedSoc2Client.extraction = {}
    _ScriptedSoc2Client.calls = []
    monkeypatch.setattr(soc2_module, "ModelClient", _ScriptedSoc2Client)
    report = tmp_path / "report.md"
    report.write_text(SOC_TEXT, encoding="utf-8")
    return _ScriptedSoc2Client, report


def _write_pdf(path, pages):
    writer = PdfWriter()
    for text in pages:
        page = writer.add_blank_page(width=612, height=792)
        safe = (
            text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        )
        content = DecodedStreamObject()
        content.set_data(
            f"BT /F1 12 Tf 72 720 Td ({safe}) Tj ET".encode("latin-1")
        )
        font = DictionaryObject(
            {
                NameObject("/Type"): NameObject("/Font"),
                NameObject("/Subtype"): NameObject("/Type1"),
                NameObject("/BaseFont"): NameObject("/Helvetica"),
            }
        )
        page[NameObject("/Contents")] = writer._add_object(content)
        page[NameObject("/Resources")] = DictionaryObject(
            {
                NameObject("/Font"): DictionaryObject(
                    {NameObject("/F1"): writer._add_object(font)}
                )
            }
        )
    with open(path, "wb") as fh:
        writer.write(fh)


def test_text_extraction_end_to_end(soc2_env):
    client, report = soc2_env
    client.extraction = _extraction()
    result = analyze_soc2(report, "doc_abc123", AS_OF)
    assert result.doc_id == "doc_abc123"
    assert result.filename == "report.md"
    assert result.sha256 == hashlib.sha256(SOC_TEXT.encode()).hexdigest()
    assert result.opinion_quote == OPINION_QUOTE
    assert result.opinion_verified is True
    analysis = result.soc2_analysis
    assert analysis["report_type"] == "type2"
    assert analysis["opinion"] == "unqualified"
    assert analysis["bridge_gap_days"] == 213
    (exception,) = analysis["exceptions"]
    assert exception["control_id"] == "CC6.1"
    assert exception["deviations"] == 2
    assert exception["sample_size"] == 25
    assert (
        exception["management_response"]
        == "Management will automate reminders."
    )
    assert exception["finding_id"] == "F-001"
    assert result.signals["bridge_gap_days"] == 213
    assert result.signals["exceptions"] == [{"control_id": "CC6.1"}]
    assert [f["rule_id"] for f in result.findings] == [
        "SOC2-EXCEPTION-ACCESS",
        "SOC2-BRIDGE-GAP",
        "SOC2-CARVE-OUT-CRITICAL",
    ]
    access = result.findings[0]
    assert access["finding_id"] == "F-001"
    assert access["source"] == "document"
    assert access["confidence"] == "high"
    assert access["remediation"]["cost_low_usd"] == 20000
    assert access["remediation"]["cost_high_usd"] == 80000
    assert access["remediation"]["effort_weeks"] == 10
    assert [e["evidence_id"] for e in result.evidence_pool] == [
        "E-001",
        "E-002",
        "E-003",
        "E-004",
        "E-005",
        "E-006",
    ]
    assert result.evidence_pool[0]["collector"] == "soc2_analyzer"
    assert result.evidence_pool[0]["collection_method"] == "document_upload"
    assert result.dropped_unquoted == []
    assert result.dropped_no_locator == []
    assert result.usage == {
        "prompt_tokens": 1000,
        "completion_tokens": 200,
        "cached_tokens": 0,
    }
    assert result.estimated_cost_usd == pytest.approx(0.008)
    validator = jsonschema.Draft202012Validator(subschema("finding"))
    for finding in result.findings:
        assert list(validator.iter_errors(finding)) == []


def test_pdf_extraction_multipage(soc2_env, tmp_path):
    client, _ = soc2_env
    pdf_path = tmp_path / "report.pdf"
    _write_pdf(
        pdf_path,
        [OPINION_QUOTE, "Result: 2 of 25 reviews were not evidenced."],
    )
    assert len(PdfReader(str(pdf_path)).pages) == 2
    client.extraction = _extraction(
        exceptions=[
            _exception(
                "CC6.1", "Result: 2 of 25 reviews were not evidenced."
            )
        ],
        subservice_orgs=[],
        cuecs=[],
        notable_observations=[],
        bridge_letter_provided=True,
    )
    result = analyze_soc2(pdf_path, "doc_pdf1", AS_OF)
    assert result.filename == "report.pdf"
    assert result.opinion_quote == OPINION_QUOTE
    assert len(result.soc2_analysis["exceptions"]) == 1
    assert result.soc2_analysis["bridge_gap_days"] == 0
    assert [f["rule_id"] for f in result.findings] == [
        "SOC2-EXCEPTION-ACCESS"
    ]


def test_read_text_marks_pdf_pages(tmp_path):
    from pe_risk_key.analyzers.soc2 import _read_text

    pdf_path = tmp_path / "marked.pdf"
    _write_pdf(pdf_path, ["First page.", "Second page."])
    text, raw = _read_text(pdf_path)
    assert text.startswith("[page 1]\nFirst page.")
    assert "[page 2]\nSecond page." in text
    assert raw[:5] == b"%PDF-"


def test_fabricated_quote_dropped(soc2_env):
    client, report = soc2_env
    client.extraction = _extraction(
        exceptions=[_exception("CC6.1", "Totally invented result text.")],
        subservice_orgs=[],
        cuecs=[],
        notable_observations=[],
        bridge_letter_provided=True,
    )
    result = analyze_soc2(report, "doc_x", AS_OF)
    (drop,) = result.dropped_unquoted
    assert drop["type"] == "exception"
    assert drop["ref"] == "CC6.1"
    assert isinstance(drop["similarity_ratio"], float)
    assert drop["closest_window"]
    assert result.soc2_analysis["exceptions"] == []
    assert result.signals["exceptions"] == []
    assert result.findings == []
    assert result.evidence_pool == []


def test_missing_locator_dropped(soc2_env):
    client, report = soc2_env
    client.extraction = _extraction(
        exceptions=[
            _exception(
                "CC6.1",
                "Result: 2 of 25 reviews were not evidenced.",
                locator="  ",
            )
        ],
        subservice_orgs=[],
        cuecs=[],
        notable_observations=[],
        bridge_letter_provided=True,
    )
    result = analyze_soc2(report, "doc_x", AS_OF)
    assert result.dropped_no_locator == [{"type": "exception", "ref": "CC6.1"}]
    assert result.dropped_unquoted == []
    assert result.soc2_analysis["exceptions"] == []
    assert result.findings == []


def test_bridge_gap_math_and_bridge_letter(soc2_env):
    client, report = soc2_env
    client.extraction = _extraction(
        exceptions=[],
        subservice_orgs=[],
        cuecs=[],
        notable_observations=[],
        bridge_letter_provided=False,
    )
    result = analyze_soc2(report, "doc_x", "2026-10-30")
    assert result.soc2_analysis["bridge_gap_days"] == 213
    assert [f["rule_id"] for f in result.findings] == ["SOC2-BRIDGE-GAP"]
    client.extraction = _extraction(
        exceptions=[],
        subservice_orgs=[],
        cuecs=[],
        notable_observations=[],
        bridge_letter_provided=True,
    )
    result = analyze_soc2(report, "doc_x", AS_OF)
    assert result.soc2_analysis["bridge_gap_days"] == 0
    assert result.findings == []


def test_exception_rule_mapping(soc2_env):
    client, report = soc2_env
    client.extraction = _extraction(
        exceptions=[
            _exception("CC6.1", "Result: 2 of 25 reviews were not evidenced."),
            _exception("CC6.2", "Result: 1 of 20 reviews was late."),
            _exception("CC7.2", "Result: 3 of 30 alerts were unreviewed."),
            _exception("CC8.1", "Result: 1 of 15 changes lacked approval."),
            _exception(
                "CC1.1",
                "Result: no deviations noted.",
                deviations=None,
                sample_size=None,
                management_response=None,
            ),
        ],
        subservice_orgs=[],
        cuecs=[],
        notable_observations=[],
        bridge_letter_provided=True,
    )
    result = analyze_soc2(report, "doc_x", AS_OF)
    assert [f["rule_id"] for f in result.findings] == [
        "SOC2-EXCEPTION-ACCESS",
        "SOC2-EXCEPTION-ACCESS",
        "SOC2-EXCEPTION-MONITORING",
        "SOC2-EXCEPTION-CHANGE",
    ]
    assert len(result.soc2_analysis["exceptions"]) == 5
    unmapped = result.soc2_analysis["exceptions"][-1]
    assert unmapped["control_id"] == "CC1.1"
    assert "finding_id" not in unmapped
    assert unmapped["deviations"] == 0
    assert unmapped["sample_size"] == 0
    assert "management_response" not in unmapped
    assert result.soc2_analysis["exceptions"][0]["finding_id"] == "F-001"


def test_critical_carve_out_finding(soc2_env):
    client, report = soc2_env
    client.extraction = _extraction(
        exceptions=[],
        subservice_orgs=[
            {
                "name": "Nimbus Cloud Services",
                "method": "carve_out",
                "services": "production hosting",
                "critical": True,
                "locator": "Subservice organizations",
            },
            {
                "name": "LedgerPay Payroll",
                "method": "carve_out",
                "services": "payroll processing",
                "critical": False,
                "locator": "Subservice organizations",
            },
            {
                "name": "CloudCorp",
                "method": "inclusive",
                "services": "metrics",
                "critical": True,
                "locator": "Subservice organizations",
            },
        ],
        cuecs=[],
        notable_observations=[],
        bridge_letter_provided=True,
    )
    result = analyze_soc2(report, "doc_x", AS_OF)
    assert [f["rule_id"] for f in result.findings] == [
        "SOC2-CARVE-OUT-CRITICAL"
    ]
    (finding,) = result.findings
    assert "Nimbus Cloud Services" in finding["deal_impact"]
    assert len(result.soc2_analysis["subservice_orgs"]) == 3


@pytest.mark.parametrize(
    "opinion", ["unqualified", "qualified", "adverse", "disclaimer"]
)
def test_opinion_values(soc2_env, opinion):
    client, report = soc2_env
    client.extraction = _extraction(
        opinion=opinion,
        exceptions=[],
        subservice_orgs=[],
        cuecs=[],
        notable_observations=[],
        bridge_letter_provided=True,
    )
    result = analyze_soc2(report, "doc_x", AS_OF)
    assert result.soc2_analysis["opinion"] == opinion
    assert result.opinion_quote == OPINION_QUOTE


def test_unverified_opinion_quote_flagged(soc2_env):
    client, report = soc2_env
    client.extraction = _extraction(
        opinion_quote="The auditor loved everything.",
        exceptions=[],
        subservice_orgs=[],
        cuecs=[],
        notable_observations=[],
        bridge_letter_provided=True,
    )
    result = analyze_soc2(report, "doc_x", AS_OF)
    (drop,) = result.dropped_unquoted
    assert drop["type"] == "opinion"
    assert drop["ref"] == "opinion"
    assert isinstance(drop["similarity_ratio"], float)
    assert result.opinion_quote == "The auditor loved everything."
    assert result.opinion_verified is False
    assert result.soc2_analysis["opinion"] == "unqualified"


def test_id_offsets(soc2_env):
    client, report = soc2_env
    client.extraction = _extraction()
    result = analyze_soc2(report, "doc_x", AS_OF, offset=10)
    assert [f["finding_id"] for f in result.findings] == [
        "F-011",
        "F-012",
        "F-013",
    ]
    assert [e["evidence_id"] for e in result.evidence_pool] == [
        "E-011",
        "E-012",
        "E-013",
        "E-014",
        "E-015",
        "E-016",
    ]
    assert result.soc2_analysis["exceptions"][0]["finding_id"] == "F-011"


def test_soc2_analysis_matches_digest_subschema(soc2_env):
    client, report = soc2_env
    client.extraction = _extraction()
    result = analyze_soc2(report, "doc_x", AS_OF)
    validator = jsonschema.Draft202012Validator(subschema("soc2_analysis"))
    assert list(validator.iter_errors(result.soc2_analysis)) == []


def test_model_call_shape(soc2_env):
    client, report = soc2_env
    client.extraction = _extraction(
        exceptions=[],
        subservice_orgs=[],
        cuecs=[],
        notable_observations=[],
        bridge_letter_provided=True,
    )
    analyze_soc2(report, "doc_x", AS_OF)
    (call,) = client.calls
    assert call["schema_name"] == "soc2_extraction"
    assert call["reasoning_effort"] == "medium"
    assert call["schema"]["additionalProperties"] is False
    assert "opinion" in call["schema"]["required"]
    user_text = call["messages"][1]["content"]
    assert "2026-10-30" in user_text
    assert "CC6.1-01" in user_text


def test_unsupported_extension_rejected(soc2_env, tmp_path):
    client, _ = soc2_env
    client.extraction = _extraction()
    bad = tmp_path / "report.exe"
    bad.write_bytes(b"nope")
    with pytest.raises(ValueError, match="Unsupported SOC 2 file type"):
        analyze_soc2(bad, "doc_x", AS_OF)
    assert client.calls == []


FIXTURE = (
    Path(__file__).resolve().parents[1]
    / "fixtures/documents/brightwater_soc2_type2.md"
)

FIXTURE_OPINION = (
    "In our opinion, in all material respects, the description presents "
    "the system as designed and implemented, and the controls stated in "
    "the description were suitably designed and operated effectively "
    "throughout the period, except for the deviations described in "
    "Section 4, which did not, in our judgment, rise to a level that "
    "would modify our opinion."
)

FIXTURE_CC61 = (
    "Exception noted. 4 of 25 sampled admin accounts were not enforced "
    "for MFA."
)

FIXTURE_SPANNING = (
    "enforcement configuration. Exception noted. 4 of 25 sampled admin "
    "accounts were not enforced for MFA."
)


def _fixture_extraction():
    return _extraction(
        auditor="Halvorsen & Pike LLP",
        opinion_quote=FIXTURE_OPINION,
        exceptions=[
            _exception("CC6.1", FIXTURE_CC61, locator="Section 4, CC6.1-01")
        ],
        subservice_orgs=[],
        cuecs=[],
        notable_observations=[
            {
                "text": "Spanning observation.",
                "locator": "Section 4",
                "quote": FIXTURE_SPANNING,
            }
        ],
        bridge_letter_provided=False,
    )


def test_fixture_cc61_result_verifies(soc2_env):
    client, _ = soc2_env
    client.extraction = _fixture_extraction()
    result = analyze_soc2(FIXTURE, "doc_bw", AS_OF)
    assert [
        item["control_id"] for item in result.soc2_analysis["exceptions"]
    ] == ["CC6.1"]
    assert result.dropped_unquoted == []


def test_fixture_opinion_verifies(soc2_env):
    client, _ = soc2_env
    client.extraction = _fixture_extraction()
    result = analyze_soc2(FIXTURE, "doc_bw", AS_OF)
    assert result.opinion_verified is True
    assert result.opinion_quote == FIXTURE_OPINION


def test_fixture_bold_spanning_quote_verifies(soc2_env):
    client, _ = soc2_env
    client.extraction = _fixture_extraction()
    result = analyze_soc2(FIXTURE, "doc_bw", AS_OF)
    assert len(result.notable_observations) == 1
    assert result.notable_observations[0]["quote"] == FIXTURE_SPANNING


def test_ellipsis_quote_requires_ordered_segments():
    from pe_risk_key.analyzers.soc2 import _normalize, _verify_quote

    source = _normalize(
        "4 of 25 sampled admin accounts were not enforced for MFA. These "
        "were service-desk accounts created via a legacy provisioning "
        "script that bypassed the conditional access policy."
    )
    ok, _ = _verify_quote(
        "4 of 25 sampled admin accounts were not enforced for MFA. ... "
        "bypassed the conditional access policy.",
        source,
    )
    assert ok is not None
    bad, diagnostics = _verify_quote(
        "bypassed the conditional access policy. ... "
        "4 of 25 sampled admin accounts",
        source,
    )
    assert bad is None
    assert diagnostics["similarity_ratio"] >= 0.0


def test_hyphenated_line_break_verifies(soc2_env, tmp_path):
    client, _ = soc2_env
    path = tmp_path / "hyphen.md"
    sentence = "The controls were suitably designed and operated effectively."
    path.write_text(
        "The controls were suitably desig-\nned and operated effectively.\n",
        encoding="utf-8",
    )
    client.extraction = _extraction(
        opinion_quote=sentence,
        exceptions=[_exception("CC6.1", sentence)],
        subservice_orgs=[],
        cuecs=[],
        notable_observations=[],
        bridge_letter_provided=True,
    )
    result = analyze_soc2(path, "doc_h", AS_OF)
    assert [
        item["control_id"] for item in result.soc2_analysis["exceptions"]
    ] == ["CC6.1"]
    assert result.opinion_verified is True
    assert result.dropped_unquoted == []


def test_normalize_typography_and_markup():
    from pe_risk_key.analyzers.soc2 import _normalize

    assert _normalize("**Bold** and `code` and _em_") == "bold and code and em"
    assert _normalize("| a | b |") == "a b"
    assert _normalize("“Hi” — it’s …") == '"hi" - it\'s ...'
    assert _normalize("Nov 10–23, 2025") == "nov 10-23, 2025"
    assert _normalize("exam-\nple") == "example"
    assert _normalize("  Mixed\tCASE\n") == "mixed case"
