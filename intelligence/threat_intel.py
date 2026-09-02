"""
intelligence/threat_intel.py

Phase 3: reputation lookups against external threat-intel APIs. Every
function here is a thin, defensive wrapper: on missing key, network error,
timeout, or rate limit, it returns a result with `available=False` and a
`reason` string instead of raising -- a threat-intel outage should degrade
PhishMind's confidence, not crash the CLI.

This module makes real network calls and is therefore the one part of
PhishMind that needs `requests` (see requirements.txt) and needs
config/.env populated to do anything beyond report "not configured".
Everything upstream of this file (Phase 1 core, Phase 2 agents) has zero
network dependency by design -- this is the only place that changes.
"""

from dataclasses import dataclass, field
from typing import Optional

import requests

from config.settings import (
    VIRUSTOTAL_API_KEY,
    ABUSEIPDB_API_KEY,
    URLSCAN_API_KEY,
    REQUEST_TIMEOUT_SECONDS,
)


@dataclass
class EnrichmentResult:
    source: str                     # "virustotal" | "abuseipdb" | "urlscan"
    indicator: str
    available: bool = False
    malicious_votes: Optional[int] = None
    total_votes: Optional[int] = None
    reputation_score: Optional[int] = None
    categories: list = field(default_factory=list)
    reason: Optional[str] = None    # why unavailable, if it is


def check_domain_virustotal(domain: str) -> EnrichmentResult:
    if not VIRUSTOTAL_API_KEY:
        return EnrichmentResult(source="virustotal", indicator=domain, reason="VIRUSTOTAL_API_KEY not configured")

    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        if resp.status_code == 429:
            return EnrichmentResult(source="virustotal", indicator=domain, reason="rate limited")
        if resp.status_code != 200:
            return EnrichmentResult(source="virustotal", indicator=domain, reason=f"HTTP {resp.status_code}")

        data = resp.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values()) if stats else None

        return EnrichmentResult(
            source="virustotal",
            indicator=domain,
            available=True,
            malicious_votes=malicious,
            total_votes=total,
        )
    except requests.RequestException as exc:
        return EnrichmentResult(source="virustotal", indicator=domain, reason=f"request failed: {exc}")


def check_ip_abuseipdb(ip: str) -> EnrichmentResult:
    if not ABUSEIPDB_API_KEY:
        return EnrichmentResult(source="abuseipdb", indicator=ip, reason="ABUSEIPDB_API_KEY not configured")

    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        if resp.status_code == 429:
            return EnrichmentResult(source="abuseipdb", indicator=ip, reason="rate limited")
        if resp.status_code != 200:
            return EnrichmentResult(source="abuseipdb", indicator=ip, reason=f"HTTP {resp.status_code}")

        data = resp.json().get("data", {})
        return EnrichmentResult(
            source="abuseipdb",
            indicator=ip,
            available=True,
            reputation_score=data.get("abuseConfidenceScore"),
            categories=[data.get("usageType")] if data.get("usageType") else [],
        )
    except requests.RequestException as exc:
        return EnrichmentResult(source="abuseipdb", indicator=ip, reason=f"request failed: {exc}")


def check_url_urlscan(url: str) -> EnrichmentResult:
    if not URLSCAN_API_KEY:
        return EnrichmentResult(source="urlscan", indicator=url, reason="URLSCAN_API_KEY not configured")

    try:
        resp = requests.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f"page.url:\"{url}\""},
            headers={"API-Key": URLSCAN_API_KEY},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        if resp.status_code == 429:
            return EnrichmentResult(source="urlscan", indicator=url, reason="rate limited")
        if resp.status_code != 200:
            return EnrichmentResult(source="urlscan", indicator=url, reason=f"HTTP {resp.status_code}")

        results = resp.json().get("results", [])
        malicious = sum(1 for r in results if r.get("verdicts", {}).get("overall", {}).get("malicious"))
        return EnrichmentResult(
            source="urlscan",
            indicator=url,
            available=True,
            malicious_votes=malicious,
            total_votes=len(results),
        )
    except requests.RequestException as exc:
        return EnrichmentResult(source="urlscan", indicator=url, reason=f"request failed: {exc}")


def enrich_case(domains: list, ips: list, urls: list, limit_per_type: int = 5) -> list:
    """Enriches up to `limit_per_type` of each indicator type (keeps a
    default run cheap against free-tier rate limits). Returns a flat list
    of EnrichmentResult, mixing 'available' and 'unavailable' entries --
    the caller (risk_agent, in a future revision) decides what to do with
    each. This function never raises."""
    results = []
    for domain in domains[:limit_per_type]:
        results.append(check_domain_virustotal(domain))
    for ip in ips[:limit_per_type]:
        results.append(check_ip_abuseipdb(ip))
    for url in urls[:limit_per_type]:
        results.append(check_url_urlscan(url))
    return results

