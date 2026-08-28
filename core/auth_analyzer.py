"""
core/auth_analyzer.py

Two things live here, both about "is the sender who they claim to be":

1. Authentication-Results parsing (SPF/DKIM/DMARC as reported by the
   RECEIVING mail server -- see the note in models.AuthenticationResult
   for why we read this instead of re-validating from scratch).

2. Sender analysis: From vs Reply-To vs Return-Path domain mismatches,
   and a light heuristic for display-name spoofing (e.g. display name says
   "Microsoft Account Team" but the address is on a domain with no
   relationship to microsoft.com).
"""

import re
from email.message import EmailMessage
from email.utils import parseaddr

from core.models import AuthenticationResult, SenderAnalysis

# Common brand names abused in display-name spoofing. Not exhaustive --
# meant as a first-pass heuristic flag for analyst review, not a verdict.
COMMONLY_SPOOFED_BRANDS = [
    "microsoft", "office365", "paypal", "apple", "amazon", "google",
    "netflix", "bank", "docusign", "irs", "fedex", "ups", "dhl",
    "linkedin", "facebook", "instagram", "chase", "wellsfargo", "hr",
    "it support", "helpdesk", "payroll",
]


def parse_authentication_results(msg: EmailMessage) -> AuthenticationResult:
    raw = msg.get("Authentication-Results")
    if not raw:
        return AuthenticationResult(header_present=False)

    raw = str(raw)

    def _extract(mechanism: str) -> str | None:
        match = re.search(rf"{mechanism}=(\w+)", raw, re.IGNORECASE)
        return match.group(1).lower() if match else None

    return AuthenticationResult(
        spf=_extract("spf"),
        dkim=_extract("dkim"),
        dmarc=_extract("dmarc"),
        raw_header=raw,
        header_present=True,
    )


def _domain_of(address: str) -> str | None:
    if not address or "@" not in address:
        return None
    return address.split("@")[-1].lower().strip()


def analyze_sender(msg: EmailMessage) -> SenderAnalysis:
    from_display, from_addr = parseaddr(str(msg.get("From", "")))
    _, reply_to_addr = parseaddr(str(msg.get("Reply-To", "")))
    _, return_path_addr = parseaddr(str(msg.get("Return-Path", "")))

    from_domain = _domain_of(from_addr)
    reply_to_domain = _domain_of(reply_to_addr)
    return_path_domain = _domain_of(return_path_addr)

    reply_to_mismatch = bool(
        reply_to_domain and from_domain and reply_to_domain != from_domain
    )
    return_path_mismatch = bool(
        return_path_domain and from_domain and return_path_domain != from_domain
    )

    display_name_spoof_suspected = False
    if from_display and from_domain:
        display_lower = from_display.lower()
        for brand in COMMONLY_SPOOFED_BRANDS:
            if brand in display_lower and brand.replace(" ", "") not in from_domain:
                display_name_spoof_suspected = True
                break

    return SenderAnalysis(
        from_display_name=from_display or None,
        from_address=from_addr or None,
        from_domain=from_domain,
        reply_to_address=reply_to_addr or None,
        reply_to_domain=reply_to_domain,
        return_path_address=return_path_addr or None,
        reply_to_mismatch=reply_to_mismatch,
        return_path_mismatch=return_path_mismatch,
        display_name_spoof_suspected=display_name_spoof_suspected,
    )

