"""
core/models.py

Structured data model for a PhishMind investigation.

Every stage of the pipeline (parser -> evidence extractor -> auth analyzer)
writes into one of these dataclasses instead of passing around raw dicts.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional


@dataclass
class Attachment:
    filename: str
    content_type: str
    size_bytes: int
    md5: str
    sha1: str
    sha256: str


@dataclass
class AuthenticationResult:
    """
    What the RECEIVING mail server reported about this message, taken from
    the Authentication-Results header. We do not re-run SPF/DKIM/DMARC
    ourselves, because a captured .eml does not carry the originating SMTP
    connection (the IP that actually spoke to the mail server) -- so a
    from-scratch SPF check on a static file cannot be authoritative. We are
    a downstream analyst reading the receiving server's verdict, and it is
    more accurate to say that plainly than to claim a validation we can't
    actually perform.
    """
    spf: Optional[str] = None          # pass / fail / softfail / neutral / none
    dkim: Optional[str] = None         # pass / fail / none
    dmarc: Optional[str] = None        # pass / fail / none
    raw_header: Optional[str] = None
    header_present: bool = False


@dataclass
class SenderAnalysis:
    from_display_name: Optional[str] = None
    from_address: Optional[str] = None
    from_domain: Optional[str] = None
    reply_to_address: Optional[str] = None
    reply_to_domain: Optional[str] = None
    return_path_address: Optional[str] = None
    reply_to_mismatch: bool = False        # Reply-To domain != From domain
    return_path_mismatch: bool = False     # Return-Path domain != From domain
    display_name_spoof_suspected: bool = False  # e.g. "PayPal Support" from a random domain


@dataclass
class Evidence:
    urls: list = field(default_factory=list)          # list[str], defanged in report
    domains: list = field(default_factory=list)        # list[str], unique domains referenced
    ip_addresses: list = field(default_factory=list)   # list[str]
    attachments: list = field(default_factory=list)    # list[Attachment]



# ---------------------------------------------------------------------------
# Phase 2
# ---------------------------------------------------------------------------


@dataclass
class ThreatIndicator:
    """One normalized IOC pulled out of the case, tagged with where it came
    from. This is the unit the agents pass around and reference by value
    when they justify a finding."""
    indicator_type: str        # "domain" | "url" | "ip" | "hash" | "email_address"
    value: str
    source_field: str          # e.g. "body_url", "from_header", "attachment"
    normalized: str            # lowercased / consistently-formed value


@dataclass
class AgentFinding:
    """One observation from one analysis agent. Findings are additive and
    non-authoritative on their own -- the risk agent is the only thing that
    turns a pile of findings into a verdict."""
    agent_name: str            # "email_agent" | "ioc_agent" | "url_agent"
    finding: str                # short human-readable statement
    evidence_refs: list = field(default_factory=list)   # indicator/header values that support this
    confidence: str = "low"     # "low" | "medium" | "high" -- never a bare percentage
    severity: str = "low"       # "low" | "medium" | "high" | "critical"
    reasoning: str = ""          # why this finding was made


@dataclass
class AttackTechnique:
    technique_id: str          # e.g. "T1566.002"
    technique_name: str
    justified_by: list = field(default_factory=list)   # evidence_refs backing the mapping


@dataclass
class ThreatAssessment:
    """The risk agent's output. This is the only place a verdict is allowed
    to be assigned in the whole pipeline."""
    verdict: str = "inconclusive"      # "benign" | "suspicious" | "malicious" | "inconclusive"
    severity: str = "low"              # "low" | "medium" | "high" | "critical"
    confidence: str = "low"            # "low" | "medium" | "high"
    reasons: list = field(default_factory=list)
    possible_attack_objective: Optional[str] = None
    mitre_techniques: list = field(default_factory=list)      # list[AttackTechnique]
    missing_evidence: list = field(default_factory=list)
    analyst_review_recommended: bool = True


@dataclass
class RecommendedAction:
    action: str                 # "quarantine" | "block_domain" | "escalate_l2" | "no_action" | ...
    rationale: str = ""
    requires_human_approval: bool = True   # always True for now -- PhishMind never auto-remediates


@dataclass
class InvestigationCase:
    case_id: str
    source_file: str
    analyzed_at: str

    subject: Optional[str] = None
    date_header: Optional[str] = None
    message_id: Optional[str] = None

    sender: SenderAnalysis = field(default_factory=SenderAnalysis)
    authentication: AuthenticationResult = field(default_factory=AuthenticationResult)
    evidence: Evidence = field(default_factory=Evidence)

    body_text_preview: Optional[str] = None
    has_html_body: bool = False

    # Phase 1 placeholders, now populated by the Phase 2 risk agent when
    # --investigate is used. Left as None/[] when the CLI runs in Phase 1's
    # default (no-flag) mode, exactly as before.
    verdict: Optional[str] = None
    confidence: Optional[int] = None
    verdict_reasons: list = field(default_factory=list)

    # New in Phase 2. Empty list on any case that hasn't gone through the
    # orchestrator, so Phase 1 default output is completely unaffected.
    agent_findings: list = field(default_factory=list)         # list[AgentFinding]
    threat_assessment: Optional[ThreatAssessment] = None
    recommended_action: Optional[RecommendedAction] = None

    # Phase 3 threat-intelligence enrichment.
    # Empty unless --enrich is used.
    enrichment_results: list = field(default_factory=list)

    # Phase 4.5 AI analyst assistance.
    # Populated only when --ai is used.
    llm_analysis: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def new_case_id() -> str:
        return f"PHISH-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
