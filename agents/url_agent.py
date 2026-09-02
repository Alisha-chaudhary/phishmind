"""
agents/url_agent.py

Looks at URL STRUCTURE -- path, query string, TLD, lookalike substitutions,
abuse of legitimate hosting services. Takes the IOC agent's already-
normalized domain list as context so it doesn't re-derive domains; it
spends its reasoning on what those URLs actually look like, not on
re-parsing them from scratch.
"""

from urllib.parse import urlparse

from core.models import InvestigationCase, AgentFinding
from detection.modern_threats import (
    ABUSABLE_LEGITIMATE_SERVICES,
    CREDENTIAL_HARVEST_PATH_PATTERNS,
    SUSPICIOUS_TLDS,
    QUISHING_LANGUAGE,
)


def _tld_of(domain: str) -> str:
    parts = domain.split(".")
    return parts[-1].lower() if len(parts) > 1 else ""


def run(case: InvestigationCase, known_domains: list[str]) -> AgentFinding:
    urls = case.evidence.urls
    body = (case.body_text_preview or "")

    observations: list[str] = []
    evidence_refs: list[str] = []
    max_severity = "low"

    def _bump(sev: str) -> None:
        nonlocal max_severity
        order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        if order[sev] > order[max_severity]:
            max_severity = sev

    for url in urls:
        parsed = urlparse(url)
        host = parsed.netloc.split("@")[-1].split(":")[0].lower()
        path_and_query = f"{parsed.path}?{parsed.query}"

        if host in ABUSABLE_LEGITIMATE_SERVICES:
            observations.append(
                f"URL uses legitimate hosting service '{host}', commonly abused to host "
                f"phishing content behind a trusted domain: {url}"
            )
            evidence_refs.append(url)
            _bump("medium")

        for pattern in CREDENTIAL_HARVEST_PATH_PATTERNS:
            if pattern.search(path_and_query):
                observations.append(
                    f"URL path/query matches a credential-harvest pattern ({pattern.pattern}): {url}"
                )
                evidence_refs.append(url)
                _bump("medium")
                break

        tld = _tld_of(host)
        if tld in SUSPICIOUS_TLDS:
            observations.append(f"URL uses TLD '.{tld}', disproportionately used for abuse: {url}")
            evidence_refs.append(url)
            _bump("low")

    for pattern in QUISHING_LANGUAGE:
        if pattern.search(body):
            observations.append(
                "Body language references scanning a QR code/image to access a link -- "
                "a pattern used to move users off text-scannable URLs entirely (quishing). "
                "PhishMind cannot inspect embedded images, so this should be flagged for "
                "manual review rather than scored on URL evidence alone."
            )
            _bump("medium")
            break

    if not urls:
        finding_text = "No URLs present in this message; URL-based analysis has nothing to evaluate."
        confidence = "high"
    elif not observations:
        finding_text = f"{len(urls)} URL(s) present; none matched known abuse patterns in structure, host, or TLD."
        confidence = "medium"   # absence of a stdlib-detectable pattern is not proof of safety
    else:
        finding_text = " | ".join(observations)
        confidence = "medium"

    return AgentFinding(
        agent_name="url_agent",
        finding=finding_text,
        evidence_refs=evidence_refs,
        confidence=confidence,
        severity=max_severity,
        reasoning=(
            "Structural URL analysis only (path, host, TLD, known-abused hosting "
            "services). No reputation lookup was performed -- that requires the "
            "Phase 3 threat-intel integration and network access this stage "
            "deliberately doesn't have. A clean result here means 'no stdlib-"
            "detectable structural red flag', not 'confirmed safe'."
        ),
    )
