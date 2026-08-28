#!/usr/bin/env python3
"""
phishmind.py

Day 1 CLI entry point.

    python phishmind.py suspicious.eml
    python phishmind.py suspicious.eml --json
    python phishmind.py suspicious.eml --json -o case.json

Runs the Phase 1 core engine pipeline:

    .eml file
        -> email_parser        (headers, body, attachments)
        -> evidence_extractor  (URLs, domains, IPs)
        -> auth_analyzer       (SPF/DKIM/DMARC, sender mismatch analysis)
        -> InvestigationCase   (structured output)

No agents, no threat intel API calls, no verdict logic yet -- those are
Phase 2-4. This stage's only job is to turn a raw email into clean,
structured evidence an analyst (or, later, an agent) can reason over.
"""

import argparse
import json
import sys
from datetime import datetime, timezone

from core.email_parser import (
    load_eml,
    get_header,
    extract_body,
    extract_attachments,
)
from core.evidence_extractor import (
    extract_urls,
    extract_domains,
    extract_ip_addresses,
)
from core.auth_analyzer import parse_authentication_results, analyze_sender
from core.models import InvestigationCase, Evidence


def build_case(eml_path: str) -> InvestigationCase:
    msg = load_eml(eml_path)

    text_body, html_body, has_html = extract_body(msg)
    urls = extract_urls(text_body, html_body)

    headers = {
        "from": get_header(msg, "From") or "",
        "reply-to": get_header(msg, "Reply-To") or "",
        "return-path": get_header(msg, "Return-Path") or "",
    }
    domains = extract_domains(urls, headers)
    ips = extract_ip_addresses(text_body, str(msg.get("Received", "")))
    attachments = extract_attachments(msg)

    case = InvestigationCase(
        case_id=InvestigationCase.new_case_id(),
        source_file=eml_path,
        analyzed_at=datetime.now(timezone.utc).isoformat(),
        subject=get_header(msg, "Subject"),
        date_header=get_header(msg, "Date"),
        message_id=get_header(msg, "Message-ID"),
        sender=analyze_sender(msg),
        authentication=parse_authentication_results(msg),
        evidence=Evidence(
            urls=urls,
            domains=domains,
            ip_addresses=ips,
            attachments=attachments,
        ),
        body_text_preview=(text_body or "")[:300].strip(),
        has_html_body=has_html,
    )
    return case


def print_human(case: InvestigationCase) -> None:
    print(f"\n{'=' * 60}")
    print(f"  PHISHMIND -- INVESTIGATION CASE")
    print(f"{'=' * 60}")
    print(f"Case ID     : {case.case_id}")
    print(f"Source file : {case.source_file}")
    print(f"Analyzed at : {case.analyzed_at}")
    print(f"\n-- Message --")
    print(f"Subject     : {case.subject}")
    print(f"Date        : {case.date_header}")
    print(f"Message-ID  : {case.message_id}")

    s = case.sender
    print(f"\n-- Sender analysis --")
    print(f"From        : {s.from_display_name} <{s.from_address}>")
    print(f"From domain : {s.from_domain}")
    print(f"Reply-To    : {s.reply_to_address}  (mismatch: {s.reply_to_mismatch})")
    print(f"Return-Path : {s.return_path_address}  (mismatch: {s.return_path_mismatch})")
    print(f"Display-name spoof suspected: {s.display_name_spoof_suspected}")

    a = case.authentication
    print(f"\n-- Authentication (as reported by receiving server) --")
    if a.header_present:
        print(f"SPF   : {a.spf}")
        print(f"DKIM  : {a.dkim}")
        print(f"DMARC : {a.dmarc}")
    else:
        print("No Authentication-Results header present in this message.")

    e = case.evidence
    print(f"\n-- Evidence --")
    print(f"URLs found       : {len(e.urls)}")
    for u in e.urls:
        print(f"  - {u}")
    print(f"Domains referenced: {len(e.domains)}")
    for d in e.domains:
        print(f"  - {d}")
    print(f"Public IPs found : {len(e.ip_addresses)}")
    for ip in e.ip_addresses:
        print(f"  - {ip}")
    print(f"Attachments      : {len(e.attachments)}")
    for att in e.attachments:
        print(f"  - {att.filename} ({att.content_type}, {att.size_bytes}B, sha256={att.sha256[:16]}...)")

    print(f"\n-- Body preview --")
    print(case.body_text_preview or "(no plain-text body extracted)")
    print(f"\n{'=' * 60}\n")


def main():
    parser = argparse.ArgumentParser(description="PhishMind - phishing email investigation engine (Day 1 core)")
    parser.add_argument("eml_file", help="Path to a .eml file to investigate")
    parser.add_argument("--json", action="store_true", help="Output structured JSON instead of human-readable text")
    parser.add_argument("-o", "--output", help="Write output to this file instead of stdout")
    args = parser.parse_args()

    try:
        case = build_case(args.eml_file)
    except FileNotFoundError:
        print(f"Error: file not found: {args.eml_file}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"Error parsing {args.eml_file}: {exc}", file=sys.stderr)
        sys.exit(1)

    if args.json:
        output = json.dumps(case.to_dict(), indent=2, default=str)
        if args.output:
            with open(args.output, "w") as f:
                f.write(output)
            print(f"Wrote {args.output}")
        else:
            print(output)
    else:
        if args.output:
            import contextlib
            with open(args.output, "w") as f, contextlib.redirect_stdout(f):
                print_human(case)
            print(f"Wrote {args.output}")
        else:
            print_human(case)


if __name__ == "__main__":
    main()

