"""
agents/risk_agent.py

The only place in PhishMind allowed to assign a verdict. Every other agent
produces findings; this one reads all of them plus the raw authentication
result and turns them into a ThreatAssessment and a RecommendedAction.

Core design principle (the reason this whole Phase 2 redesign happened):
authentication passing or failing is ONE INPUT, not a verdict by itself.
Concretely:
  - Clean SPF/DKIM/DMARC does NOT clear a case if email_agent flagged
    payment-change language -- a compromised legitimate account with a
    clean sending reputation is exactly the T1534 scenario.
  - A failed SPF does NOT automatically mean malicious -- legitimate
    senders fail SPF after infrastructure migrations before DNS propagates.
    That's the false-positive test case's whole point: reasons +
    missing_evidence + analyst_review_recommended exist so "we don't have
    enough to be sure" is a first-class, expressible outcome, distinct from
    both "benign" and "malicious".

This module is rule-based on purpose for now (see README Phase 2.5 note) --
deterministic scoring is easier to test against the expected-outcome specs
in data/test_emails/*.expected.json than an LLM-backed version would be.
"""

from core.models import (
    InvestigationCase,
    AgentFinding,
    AttackTechnique,
    ThreatAssessment,
    RecommendedAction,
)
from detection.modern_threats import MITRE_CATALOG

_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}


def _max(values: list[str], order: dict) -> str:
    if not values:
        return "low"
    return max(values, key=lambda v: order.get(v, 0))


def _mitre(technique_id: str, justified_by: list[str]) -> AttackTechnique:
    return AttackTechnique(
        technique_id=technique_id,
        technique_name=MITRE_CATALOG.get(technique_id, "Unknown technique"),
        justified_by=justified_by,
    )


def assess(case: InvestigationCase, findings: list[AgentFinding]) -> ThreatAssessment:
    by_agent = {f.agent_name: f for f in findings}
    email_f = by_agent.get("email_agent")
    url_f = by_agent.get("url_agent")

    reasons: list[str] = []
    missing_evidence: list[str] = []
    mitre: list[AttackTechnique] = []
    severities: list[str] = []
    auth = case.authentication

    # --- Signal 1: authentication -------------------------------------
    auth_failed = auth.header_present and any(
        v == "fail" for v in (auth.spf, auth.dkim, auth.dmarc) if v
    )
    auth_clean = auth.header_present and all(
        v in ("pass", None) for v in (auth.spf, auth.dkim, auth.dmarc)
    ) and any(v == "pass" for v in (auth.spf, auth.dkim, auth.dmarc))

    if not auth.header_present:
        missing_evidence.append(
            "No Authentication-Results header present -- SPF/DKIM/DMARC outcome unknown."
        )

    # --- Signal 2: payment-change / BEC language (email_agent) --------
    payment_flag = bool(email_f) and "payment_change_language" in " ".join(email_f.evidence_refs)
    if payment_flag:
        reasons.append(
            "Body contains payment- or bank-detail-change language. "
            + (
                "This is flagged even though authentication passed cleanly -- "
                "clean auth proves the sending path, not that the account or "
                "instruction is legitimate."
                if auth_clean else
                "Combined with authentication not passing cleanly, this is a strong phishing/BEC signal."
            )
        )
        severities.append("high")
        mitre.append(_mitre("T1534", email_f.evidence_refs))

    # --- Signal 3: sender identity (email_agent) ------------------------
    if email_f:
        if "display-name" in " ".join(r for r in email_f.evidence_refs if r.startswith("display-name")):
            reasons.append("Display name references a commonly-spoofed brand not matched by the sending domain.")
            severities.append("high")
            mitre.append(_mitre("T1036.005", [r for r in email_f.evidence_refs if r.startswith("display-name")]))
        reply_to_refs = [r for r in email_f.evidence_refs if r.startswith("reply-to")]
        if reply_to_refs:
            reasons.append("Reply-To domain diverges from the visible From domain.")
            severities.append("medium")

    # --- Signal 4: URL structure (url_agent) ---------------------------
    if url_f and url_f.evidence_refs:
        reasons.append("One or more URLs matched credential-harvest structure, abused legitimate hosting, or a high-abuse TLD.")
        severities.append(url_f.severity)
        mitre.append(_mitre("T1566.002", url_f.evidence_refs))

    # --- Signal 5: attachments -----------------------------------------
    if case.evidence.attachments:
        reasons.append(f"{len(case.evidence.attachments)} attachment(s) present -- hashed but not sandboxed (no detonation capability yet).")
        missing_evidence.append("Attachments were hashed only; no sandbox/detonation or reputation lookup performed.")
        mitre.append(_mitre("T1566.001", [a.sha256 for a in case.evidence.attachments]))

    # --- Signal 6: raw auth failure with nothing else corroborating ----
    if auth_failed and not (payment_flag or (url_f and url_f.evidence_refs) or (email_f and email_f.severity in ("high", "critical"))):
        reasons.append(
            "Authentication failed, but no other agent found corroborating evidence "
            "(no payment-change language, no suspicious URL structure, no display-name spoof). "
            "SPF/DKIM failures happen for legitimate reasons too (e.g. recent mail-infrastructure "
            "migration before DNS propagation) -- this alone is not sufficient to call the message malicious."
        )
        missing_evidence.append(
            "Sender's mail-infrastructure history is unknown; cannot distinguish spoofing from a "
            "legitimate but recently-changed sending source from headers alone."
        )
        severities.append("medium")

    # --- Verdict logic ---------------------------------------------------
    top_severity = _max(severities, _SEVERITY_ORDER)
    strong_corroboration = payment_flag or (email_f and email_f.severity == "high" and "display-name" in " ".join(email_f.evidence_refs)) or (url_f and url_f.severity in ("high", "critical"))

    if not reasons:
        verdict = "benign"
        confidence = "medium"
        review = False
        if not reasons:
            reasons.append("No phishing/BEC/spoofing/malicious-URL signals were found by any agent.")
    elif strong_corroboration and (auth_failed or payment_flag):
        verdict = "malicious" if (auth_failed and strong_corroboration) or (payment_flag and strong_corroboration) else "suspicious"
        confidence = "high" if len(reasons) >= 2 else "medium"
        review = True
    elif auth_failed and not strong_corroboration:
        # The false-positive guardrail case: failed auth alone, nothing else.
        verdict = "inconclusive"
        confidence = "low"
        review = True
    else:
        verdict = "suspicious"
        confidence = "medium"
        review = True

    return ThreatAssessment(
        verdict=verdict,
        severity=top_severity if reasons else "low",
        confidence=confidence,
        reasons=reasons,
        possible_attack_objective=(
            "Payment/wire fraud via compromised or spoofed trusted sender" if payment_flag else
            "Credential harvesting via malicious link" if (url_f and url_f.evidence_refs) else
            None
        ),
        mitre_techniques=mitre,
        missing_evidence=missing_evidence,
        analyst_review_recommended=review,
    )


def recommend(assessment: ThreatAssessment) -> RecommendedAction:
    if assessment.verdict == "malicious":
        action = "quarantine"
        rationale = "Verdict is malicious with corroborating evidence from multiple agents; quarantine pending analyst confirmation."
    elif assessment.verdict == "suspicious":
        action = "escalate_l2"
        rationale = "Verdict is suspicious; escalate for analyst review rather than auto-remediate on partial evidence."
    elif assessment.verdict == "inconclusive":
        action = "escalate_l2"
        rationale = "Evidence is insufficient to reach benign or malicious with confidence; route to an analyst rather than guess."
    else:
        action = "no_action"
        rationale = "No corroborated phishing/BEC/spoofing signals found."

    return RecommendedAction(
        action=action,
        rationale=rationale,
        requires_human_approval=True,
    )


def run(case: InvestigationCase, findings: list[AgentFinding]) -> tuple[ThreatAssessment, RecommendedAction]:
    assessment = assess(case, findings)
    action = recommend(assessment)
    return assessment, action
