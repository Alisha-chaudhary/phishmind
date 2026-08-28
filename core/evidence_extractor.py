"""
core/evidence_extractor.py

Pulls indicators of compromise (IOCs) out of email content: URLs, domains,
and IP addresses. Works on raw text (plain body + a stripped version of the
HTML body) so it catches links regardless of whether the email is
plain-text or HTML.

Kept dependency-free (stdlib only, `re` + `ipaddress`) on purpose -- this
runs on every case, so it should not require network access or an API key.
Threat intel enrichment (reputation lookups) is a separate, later stage.
"""

import re
import ipaddress
from urllib.parse import urlparse

URL_RE = re.compile(
    r"""(?i)\b((?:https?://|hxxps?://)[^\s"'<>\)\]]+)"""
)

# Matches IPv4 addresses that appear as standalone tokens (e.g. in Received
# headers or a raw IP used instead of a domain in a URL).
IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)

HTML_TAG_RE = re.compile(r"<[^>]+>")


def _strip_html(html: str) -> str:
    """Minimal tag stripper so URLs embedded in href/src attributes and
    visible text both surface as plain text for the URL regex."""
    return HTML_TAG_RE.sub(" ", html)


def _normalize_url(raw_url: str) -> str:
    """Un-defang a URL if it was already defanged (hxxp -> http) so we can
    parse it consistently. The defanging for *display* happens later, in
    the report layer -- internally we work with live-looking strings."""
    return raw_url.replace("hxxp", "http")


def extract_urls(text: str, html: str) -> list[str]:
    combined = f"{text}\n{_strip_html(html)}"
    found = URL_RE.findall(combined)
    normalized = {_normalize_url(u).rstrip(".,;\"'") for u in found}
    return sorted(normalized)


def extract_domains(urls: list[str], headers: dict[str, str]) -> list[str]:
    domains = set()
    for url in urls:
        try:
            netloc = urlparse(url).netloc
            host = netloc.split("@")[-1].split(":")[0].lower()
            if host:
                domains.add(host)
        except Exception:
            continue

    # Also pull the domain half of the From/Reply-To/Return-Path addresses
    for header_name in ("from", "reply-to", "return-path"):
        value = headers.get(header_name, "")
        match = re.search(r"@([\w.-]+\.[A-Za-z]{2,})", value)
        if match:
            domains.add(match.group(1).lower())

    return sorted(domains)


def extract_ip_addresses(text: str, headers_raw: str) -> list[str]:
    combined = f"{text}\n{headers_raw}"
    candidates = set(IPV4_RE.findall(combined))
    valid_public_ips = set()
    for ip in candidates:
        try:
            addr = ipaddress.ip_address(ip)
            # Skip loopback/private/reserved -- these are almost always
            # internal hop artifacts in Received headers, not real IOCs.
            if not (addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local):
                valid_public_ips.add(ip)
        except ValueError:
            continue
    return sorted(valid_public_ips)

