"""
agents/ioc_agent.py

Simplest agent in the pipeline on purpose (built first per the Phase 2
sequence). Its only job is to take the raw Evidence Phase 1 already
extracted and turn each item into a typed, normalized ThreatIndicator --
no judgment calls about whether any of it is malicious. That judgment
belongs to url_agent (structure) and risk_agent (verdict), not here.

The orchestrator passes this agent's normalized domain list forward to
url_agent as context, so url_agent doesn't re-derive domains it already
has and can spend its reasoning on URL structure instead.
"""

from core.models import InvestigationCase, ThreatIndicator, AgentFinding


def build_indicators(case: InvestigationCase) -> list[ThreatIndicator]:
    indicators: list[ThreatIndicator] = []

    for url in case.evidence.urls:
        indicators.append(ThreatIndicator(
            indicator_type="url",
            value=url,
            source_field="body_url",
            normalized=url.strip().lower(),
        ))

    for domain in case.evidence.domains:
        indicators.append(ThreatIndicator(
            indicator_type="domain",
            value=domain,
            source_field="body_or_header",
            normalized=domain.strip().lower(),
        ))

    for ip in case.evidence.ip_addresses:
        indicators.append(ThreatIndicator(
            indicator_type="ip",
            value=ip,
            source_field="body_or_received_header",
            normalized=ip.strip(),
        ))

    for att in case.evidence.attachments:
        indicators.append(ThreatIndicator(
            indicator_type="hash",
            value=att.sha256,
            source_field=f"attachment:{att.filename}",
            normalized=att.sha256.lower(),
        ))

    if case.sender.from_address:
        indicators.append(ThreatIndicator(
            indicator_type="email_address",
            value=case.sender.from_address,
            source_field="from_header",
            normalized=case.sender.from_address.strip().lower(),
        ))

    return indicators


def run(case: InvestigationCase) -> tuple[list[ThreatIndicator], AgentFinding]:
    """Returns (indicators, finding). The finding is a plain inventory
    statement -- IOC agent doesn't score anything, it just reports what
    it normalized so the risk agent has a clean count to reason about."""
    indicators = build_indicators(case)

    by_type: dict[str, int] = {}
    for ind in indicators:
        by_type[ind.indicator_type] = by_type.get(ind.indicator_type, 0) + 1

    summary = ", ".join(f"{count} {itype}" for itype, count in sorted(by_type.items())) or "no indicators found"

    finding = AgentFinding(
        agent_name="ioc_agent",
        finding=f"Normalized {len(indicators)} indicator(s): {summary}.",
        evidence_refs=[ind.normalized for ind in indicators],
        confidence="high",   # this is a count, not a judgment -- high confidence is appropriate
        severity="low",
        reasoning=(
            "IOC agent performs normalization and inventory only. It does not "
            "assess whether any indicator is malicious; that is url_agent's "
            "and risk_agent's job. A high indicator count is not itself a "
            "risk signal -- legitimate emails routinely contain multiple links."
        ),
    )
    return indicators, finding
