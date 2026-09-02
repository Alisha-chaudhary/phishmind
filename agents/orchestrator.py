"""
agents/orchestrator.py

Coordinates the four Phase 2 agents against an already-built InvestigationCase.
Deliberately contains NO analysis logic of its own -- its only jobs are:
  1. call each agent in the right order,
  2. pass context between them (IOC agent's domains -> URL agent),
  3. collect findings onto the case,
  4. hand everything to risk_agent for the verdict.

If you find yourself writing an `if` statement in here that decides
something about whether a URL or sender looks bad, that logic belongs in
one of the agent modules instead -- see the "orchestrator scope creep" risk
noted in the Phase 2 plan.
"""

from core.models import InvestigationCase

from agents import ioc_agent, url_agent, email_agent, risk_agent, llm_agent


def investigate(
        case: InvestigationCase,
        enrich: bool = False,
        use_ai: bool = False,
    ) -> InvestigationCase:
    """Mutates and returns the given case with agent_findings, verdict,
        confidence, verdict_reasons, threat_assessment, and recommended_action
        populated. Does not touch anything Phase 1 already set."""

    indicators, ioc_finding = ioc_agent.run(case)
    known_domains = [i.normalized for i in indicators if i.indicator_type == "domain"]

    url_finding = url_agent.run(case, known_domains)
    email_finding = email_agent.run(case)

    findings = [ioc_finding, email_finding, url_finding]
    case.agent_findings = findings

    assessment, action = risk_agent.run(case, findings)
    case.threat_assessment = assessment
    case.recommended_action = action

    # Keep the Phase 1 placeholder fields in sync so anything that only
    # knows about the old shape (e.g. a report template built against
    # Phase 1) still gets a sensible value.
    case.verdict = assessment.verdict
    case.confidence = {"low": 30, "medium": 60, "high": 90}.get(
        assessment.confidence, 0
    )
    case.verdict_reasons = assessment.reasons

    
    # Phase 4.5: AI analyst assistance.
    # The deterministic risk_agent remains authoritative.
    if use_ai:
        try:
            case.llm_analysis = llm_agent.analyze(case)
        except Exception as exc:
            # AI failure must never break the deterministic investigation.
            case.llm_analysis = (
                f"AI analyst assistance unavailable: {exc}"
            )

    return case
