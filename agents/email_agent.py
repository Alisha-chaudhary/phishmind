"""
agents/email_agent.py

Analyzes sender identity signals and body language -- the things Phase 1's
auth_analyzer surfaced as raw data (mismatches, spoof heuristic) plus new
Phase 2 body-content pattern matching (payment-change phrases, urgency
language). This is the agent responsible for catching the false-positive
guardrail case: authentication passing cleanly must not, by itself, cause
this agent to stay quiet about a payment-instruction-change request. That
is a deliberate design requirement, not an oversight -- see the module
docstring in risk_agent.py for how that finding is used downstream.
"""

from core.models import InvestigationCase, AgentFinding
from detection.modern_threats import PAYMENT_CHANGE_PHRASES, URGENCY_PHRASES


def run(case: InvestigationCase) -> AgentFinding:
    body = case.body_text_preview or ""
    subject = case.subject or ""
    combined_text = f"{subject}\n{body}"

    observations: list[str] = []
    evidence_refs: list[str] = []
    max_severity = "low"

    def _bump(sev: str) -> None:
        nonlocal max_severity
        order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        if order[sev] > order[max_severity]:
            max_severity = sev

    s = case.sender
    if s.reply_to_mismatch:
        observations.append(
            f"Reply-To domain ({s.reply_to_domain}) does not match From domain "
            f"({s.from_domain}) -- replies would route somewhere the visible sender doesn't control."
        )
        evidence_refs.append(f"reply-to:{s.reply_to_domain}")
        _bump("medium")

    if s.return_path_mismatch:
        observations.append(
            f"Return-Path domain ({s.return_path_domain}) does not match From domain "
            f"({s.from_domain})."
        )
        evidence_refs.append(f"return-path:{s.return_path_domain}")
        _bump("low")   # weaker signal alone than Reply-To mismatch; many legitimate bulk senders do this

    if s.display_name_spoof_suspected:
        observations.append(
            f"Display name '{s.from_display_name}' references a commonly-spoofed brand, "
            f"but the sending domain ({s.from_domain}) has no evident relationship to it."
        )
        evidence_refs.append(f"display-name:{s.from_display_name}")
        _bump("high")

    payment_hit = False
    for pattern in PAYMENT_CHANGE_PHRASES:
        if pattern.search(combined_text):
            observations.append(
                f"Body/subject contains payment- or bank-detail-change language ('{pattern.pattern}'). "
                "This is flagged regardless of authentication result -- SPF/DKIM/DMARC passing only "
                "proves the message came through an authorized sending path, not that the account "
                "wasn't compromised or that the instruction is legitimate."
            )
            evidence_refs.append("body:payment_change_language")
            _bump("high")
            payment_hit = True
            break

    urgency_hits = 0
    for pattern in URGENCY_PHRASES:
        if pattern.search(combined_text):
            urgency_hits += 1
    if urgency_hits:
        observations.append(
            f"Body/subject contains {urgency_hits} urgency/pressure phrase pattern(s), "
            "a tactic used to short-circuit normal verification steps."
        )
        evidence_refs.append("body:urgency_language")
        _bump("medium" if not payment_hit else "high")

    if not observations:
        finding_text = (
            "No sender-mismatch, spoof, payment-change, or urgency-language signals detected "
            "in headers or body preview."
        )
        confidence = "medium"   # body_text_preview is only the first 300 chars -- absence isn't conclusive
    else:
        finding_text = " | ".join(observations)
        confidence = "medium"

    return AgentFinding(
        agent_name="email_agent",
        finding=finding_text,
        evidence_refs=evidence_refs,
        confidence=confidence,
        severity=max_severity,
        reasoning=(
            "Sender-identity and body-language analysis. Deliberately does not "
            "consult case.authentication when deciding whether to flag payment-change "
            "or urgency language -- clean SPF/DKIM/DMARC describes the delivery path, "
            "not the trustworthiness of the request inside the message. Only the "
            "body_text_preview (first ~300 chars) is available at this stage, so a "
            "clean result here is a bounded claim, not a full-body guarantee."
        ),
    )
