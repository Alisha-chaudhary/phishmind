"""
tests/test_pipeline.py

Phase 4: automated regression tests. Every .eml in data/test_emails/ that
has a matching .expected.json gets run through the full pipeline
(build_case + orchestrator.investigate) and asserted against that spec.

This is what turns "we manually eyeballed 4 cases and they looked right"
into something that keeps being true after risk_agent's scoring logic
changes. Adding threat pattern #11 or a fifth test email should mean:
drop the .eml + .expected.json pair in data/test_emails/, nothing else.

Run with:
    pytest tests/ -v
"""

import json
import glob
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from phishmind import build_case
from agents.orchestrator import investigate

TEST_EMAIL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "test_emails")


def _discover_cases():
    cases = []
    for eml_path in sorted(glob.glob(os.path.join(TEST_EMAIL_DIR, "*.eml"))):
        expected_path = eml_path.replace(".eml", ".expected.json")
        if os.path.exists(expected_path):
            cases.append((eml_path, expected_path))
    return cases


CASES = _discover_cases()


@pytest.mark.parametrize("eml_path,expected_path", CASES, ids=[os.path.basename(c[0]) for c in CASES])
def test_case_matches_expected_outcome(eml_path, expected_path):
    with open(expected_path) as f:
        expected = json.load(f)

    case = build_case(eml_path)
    case = investigate(case)
    ta = case.threat_assessment

    assert ta is not None, f"{eml_path}: no threat_assessment produced"
    assert ta.verdict == expected["expected_verdict"], (
        f"{eml_path}: verdict was '{ta.verdict}', expected '{expected['expected_verdict']}'. "
        f"Reasons: {ta.reasons}"
    )
    assert ta.severity == expected["expected_severity"], (
        f"{eml_path}: severity was '{ta.severity}', expected '{expected['expected_severity']}'"
    )

    expected_mitre_ids = set(expected.get("expected_mitre", []))
    actual_mitre_ids = {t.technique_id for t in ta.mitre_techniques}
    assert expected_mitre_ids <= actual_mitre_ids, (
        f"{eml_path}: missing expected MITRE technique(s) {expected_mitre_ids - actual_mitre_ids}"
    )

    if "analyst_review_recommended" in expected:
        assert ta.analyst_review_recommended == expected["analyst_review_recommended"], (
            f"{eml_path}: analyst_review_recommended was {ta.analyst_review_recommended}, "
            f"expected {expected['analyst_review_recommended']}"
        )


def test_default_mode_leaves_phase1_fields_untouched():
    """Guards the Phase 1 contract: without investigate(), agent_findings
    stays empty and verdict/confidence/verdict_reasons stay at their
    Phase 1 defaults (None/None/[])."""
    eml_path = os.path.join(TEST_EMAIL_DIR, "02_benign_github.eml")
    case = build_case(eml_path)
    assert case.agent_findings == []
    assert case.threat_assessment is None
    assert case.recommended_action is None
    assert case.verdict is None


def test_orchestrator_produces_all_three_findings():
    eml_path = os.path.join(TEST_EMAIL_DIR, "01_credential_phishing.eml")
    case = build_case(eml_path)
    case = investigate(case)
    agent_names = {f.agent_name for f in case.agent_findings}
    assert agent_names == {"ioc_agent", "email_agent", "url_agent"}


def test_mitre_techniques_always_have_justification():
    """Guardrail against MITRE over-mapping: every technique cited must
    have at least one evidence ref backing it."""
    for eml_path, _ in CASES:
        case = build_case(eml_path)
        case = investigate(case)
        for t in case.threat_assessment.mitre_techniques:
            assert len(t.justified_by) > 0, (
                f"{eml_path}: MITRE technique {t.technique_id} cited with no justified_by evidence"
            )

