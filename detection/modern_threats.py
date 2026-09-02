"""
detection/modern_threats.py

Pattern DATA, not logic. Every list/dict in this file is something an agent
can check membership or regex-match against. This module is deliberately
inert -- it makes no decisions and has no side effects -- because several
agents need the same threat-pattern definitions, and if each agent kept its
own copy they would drift out of sync as PhishMind grows. Adding threat
pattern #14 later should be a one-file, no-logic-touched change.

Nothing in here is a verdict. A phrase matching PAYMENT_CHANGE_PHRASES is a
signal an agent can cite in an AgentFinding -- turning signals into a
verdict is the risk agent's job alone, in agents/risk_agent.py.
"""

import re

# ---------------------------------------------------------------------------
# 1. Legitimate infrastructure abused for phishing hosting/redirects.
#    A hit here does NOT mean malicious -- these services are legitimate and
#    used constantly for real business. It means "worth a second look",
#    which is exactly the kind of signal that belongs in reasoning text
#    rather than being auto-escalated to a verdict.
# ---------------------------------------------------------------------------
ABUSABLE_LEGITIMATE_SERVICES = [
    "docs.google.com", "drive.google.com", "forms.gle", "forms.office.com",
    "onedrive.live.com", "sharepoint.com", "sites.google.com",
    "firebasestorage.googleapis.com", "storage.googleapis.com",
    "notion.site", "typeform.com", "canva.com", "bit.ly", "tinyurl.com",
    "t.co", "rebrand.ly", "linktr.ee", "herokuapp.com", "netlify.app",
    "vercel.app", "web.app", "glitch.me", "repl.co", "pages.dev",
]

# ---------------------------------------------------------------------------
# 2. URL path/query fragments common in credential-harvesting pages.
#    Matched against the URL's path + query, not the domain.
# ---------------------------------------------------------------------------
CREDENTIAL_HARVEST_PATH_PATTERNS = [
    re.compile(r"/login", re.I),
    re.compile(r"/signin", re.I),
    re.compile(r"/verify", re.I),
    re.compile(r"/account[-_]?(update|confirm|verify|suspend)", re.I),
    re.compile(r"/secure", re.I),
    re.compile(r"/wp-(admin|login)", re.I),         # compromised WordPress sites reused as phishing hosts
    re.compile(r"[?&]redirect", re.I),
    re.compile(r"[?&]session", re.I),
]

# ---------------------------------------------------------------------------
# 3. URL-structure heuristics that are cheap, stdlib-only, and don't need a
#    reputation API. These are individually weak signals -- the risk agent
#    should never treat any single one as sufficient on its own.
# ---------------------------------------------------------------------------
SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "click", "gq", "tk", "ml", "cf", "work",
    "loan", "men", "date", "review", "country", "kim", "science",
}

# Homoglyph / lookalike substitution pairs worth flagging in a domain name.
# Not exhaustive -- a starting set for the display-name/domain heuristic.
LOOKALIKE_SUBSTITUTIONS = {
    "0": "o", "1": "l", "5": "s", "3": "e", "rn": "m", "vv": "w",
}

# ---------------------------------------------------------------------------
# 4. BEC / payment-fraud language (T1534-style: abusing a trusted,
#    legitimately-authenticated channel rather than spoofing it).
#    This is the category the false-positive test case exists to guard --
#    clean SPF/DKIM/DMARC must NOT clear a message that contains these.
# ---------------------------------------------------------------------------
PAYMENT_CHANGE_PHRASES = [
    re.compile(r"updat(e|ed|ing) (my |our |the )?(bank|banking|account|payment) (detail|info|routing)", re.I),
    re.compile(r"new (bank|banking|account|payment|wire) (detail|info|instruction)", re.I),
    re.compile(r"chang(e|ed|ing) (my |our |the )?(bank|payment|remittance|routing)", re.I),
    re.compile(r"wire (the )?(funds|payment|money) to", re.I),
    re.compile(r"remit(tance)? (to|address)", re.I),
    re.compile(r"invoice.{0,20}attached.{0,40}(pay|remit|settle)", re.I),
]

URGENCY_PHRASES = [
    re.compile(r"(act|respond|reply|verify) (now|immediately|within)", re.I),
    re.compile(r"your account (will be|has been) (suspend|lock|clos|disabl)", re.I),
    re.compile(r"final (notice|warning|reminder)", re.I),
    re.compile(r"unusual (sign[- ]?in|activity|login) (detect|attempt)", re.I),
    re.compile(r"(within|before) (24|48) hours", re.I),
    re.compile(r"do not (share|forward) this (email|message)", re.I),  # isolation tactic, BEC/gift-card scams
]

# QR-code / "scan to view" phishing (quishing) -- can't detect the image
# itself with stdlib tools, but the surrounding language is a reliable tell.
QUISHING_LANGUAGE = [
    re.compile(r"scan (the |this )?(qr|code)", re.I),
    re.compile(r"scan to (view|access|verify|open)", re.I),
]

# ---------------------------------------------------------------------------
# 5. MITRE ATT&CK technique catalog PhishMind is allowed to cite. Kept as a
#    closed list on purpose -- the risk agent must only ever reference an
#    ID from here, each with an explicit justified_by evidence ref. This is
#    the guardrail against MITRE over-mapping (citing an ID because the
#    verdict is malicious and IDs look thorough, not because the evidence
#    actually supports that specific technique).
# ---------------------------------------------------------------------------
MITRE_CATALOG = {
    "T1566.001": "Phishing: Spearphishing Attachment",
    "T1566.002": "Phishing: Spearphishing Link",
    "T1598.002": "Phishing for Information: Spearphishing Attachment",
    "T1598.003": "Phishing for Information: Spearphishing Link",
    "T1534": "Internal Spearphishing",          # used here for compromised-account payment fraud, per project spec
    "T1036.005": "Masquerading: Match Legitimate Name or Location",
    "T1585.002": "Establish Accounts: Email Accounts",
}
