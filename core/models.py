"""
core/models.py

Structured data model for a PhishMind investigation.

Every stage of the pipeline (parser -> evidence extractor -> auth analyzer)
writes into one of these dataclasses instead of passing around raw dicts.
This is the same discipline ThreatLens uses: each module produces a typed
object, and the final report is just a serialization of that object tree.
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

    # Populated later by the risk/verdict layer (Phase 4). Kept here now so
    # the schema doesn't change shape when that layer is added.
    verdict: Optional[str] = None
    confidence: Optional[int] = None
    verdict_reasons: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def new_case_id() -> str:
        return f"PHISH-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"

