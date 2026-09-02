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
from agents.orchestrator import investigate


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
    try:
        _print_human_rich(case)
    except ImportError:
        _print_human_plain(case)


def _print_human_rich(case: InvestigationCase) -> None:
    """Phase 6: colorized terminal output via `rich`, falls back to the
    plain formatter (unchanged since Phase 1) if rich isn't installed."""
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel

    console = Console()
    console.rule("[bold]PHISHMIND -- INVESTIGATION CASE[/bold]")
    console.print(f"Case ID     : {case.case_id}")
    console.print(f"Source file : {case.source_file}")
    console.print(f"Analyzed at : {case.analyzed_at}")

    console.print("\n[bold]-- Message --[/bold]")
    console.print(f"Subject     : {case.subject}")
    console.print(f"Date        : {case.date_header}")
    console.print(f"Message-ID  : {case.message_id}")

    s = case.sender
    console.print("\n[bold]-- Sender analysis --[/bold]")
    console.print(f"From        : {s.from_display_name} <{s.from_address}>")
    console.print(f"From domain : {s.from_domain}")
    mismatch_style = "red" if s.reply_to_mismatch else "green"
    console.print(f"Reply-To    : {s.reply_to_address}  (mismatch: [{mismatch_style}]{s.reply_to_mismatch}[/{mismatch_style}])")
    rp_style = "red" if s.return_path_mismatch else "green"
    console.print(f"Return-Path : {s.return_path_address}  (mismatch: [{rp_style}]{s.return_path_mismatch}[/{rp_style}])")
    spoof_style = "red" if s.display_name_spoof_suspected else "green"
    console.print(f"Display-name spoof suspected: [{spoof_style}]{s.display_name_spoof_suspected}[/{spoof_style}]")

    a = case.authentication
    console.print("\n[bold]-- Authentication (as reported by receiving server) --[/bold]")
    if a.header_present:
        for label, val in (("SPF", a.spf), ("DKIM", a.dkim), ("DMARC", a.dmarc)):
            style = "green" if val == "pass" else ("red" if val == "fail" else "yellow")
            console.print(f"{label:5}: [{style}]{val}[/{style}]")
    else:
        console.print("No Authentication-Results header present in this message.")

    e = case.evidence
    console.print("\n[bold]-- Evidence --[/bold]")
    console.print(f"URLs ({len(e.urls)}): " + (", ".join(e.urls) or "none"))
    console.print(f"Domains ({len(e.domains)}): " + (", ".join(e.domains) or "none"))
    console.print(f"Public IPs ({len(e.ip_addresses)}): " + (", ".join(e.ip_addresses) or "none"))
    console.print(f"Attachments ({len(e.attachments)}): " + (", ".join(f"{att.filename} ({att.sha256[:12]}...)" for att in e.attachments) or "none"))

    console.print("\n[bold]-- Body preview --[/bold]")
    console.print(case.body_text_preview or "(no plain-text body extracted)")

    if case.threat_assessment is not None:
        ta = case.threat_assessment
        ra = case.recommended_action
        console.rule("[bold]PHASE 2 -- AGENT INVESTIGATION[/bold]")

        table = Table(title="Agent findings")
        table.add_column("Agent")
        table.add_column("Confidence")
        table.add_column("Severity")
        table.add_column("Finding")
        for f in case.agent_findings:
            sev_style = {"low": "green", "medium": "yellow", "high": "red", "critical": "bold red"}.get(f.severity, "white")
            table.add_row(f.agent_name, f.confidence, f"[{sev_style}]{f.severity}[/{sev_style}]", f.finding)
        console.print(table)

        verdict_style = {"benign": "green", "suspicious": "yellow", "malicious": "bold red", "inconclusive": "cyan"}.get(ta.verdict, "white")
        panel_body = (
            f"[{verdict_style}]{ta.verdict.upper()}[/{verdict_style}]  "
            f"(severity={ta.severity}, confidence={ta.confidence}, analyst_review={ta.analyst_review_recommended})\n\n"
            + "\n".join(f"- {r}" for r in ta.reasons)
        )
        if ta.possible_attack_objective:
            panel_body += f"\n\nPossible objective: {ta.possible_attack_objective}"
        if ta.mitre_techniques:
            panel_body += "\n\nMITRE: " + ", ".join(f"{t.technique_id} ({t.technique_name})" for t in ta.mitre_techniques)
        if ta.missing_evidence:
            panel_body += "\n\nMissing evidence:\n" + "\n".join(f"- {m}" for m in ta.missing_evidence)
        console.print(Panel(panel_body, title="Threat Assessment"))

        if ra:
            console.print(f"\n[bold]Recommended action:[/bold] {ra.action} (requires human approval: {ra.requires_human_approval})")
            console.print(f"Rationale: {ra.rationale}")
        
        if case.llm_analysis:
            console.rule("[bold]PHASE 4.5 -- AI ANALYST ASSISTANCE[/bold]")
            console.print(Panel(
                case.llm_analysis,
                title="Gemini SOC Analyst Explanation",
            ))
    console.print()


def _print_human_plain(case: InvestigationCase) -> None:
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

    if case.threat_assessment is not None:
        ta = case.threat_assessment
        ra = case.recommended_action
        print(f"\n{'=' * 60}")
        print(f"  PHASE 2 -- AGENT INVESTIGATION")
        print(f"{'=' * 60}")
        for f in case.agent_findings:
            print(f"\n[{f.agent_name}] (confidence={f.confidence}, severity={f.severity})")
            print(f"  {f.finding}")
        print(f"\n-- Threat assessment (risk_agent) --")
        print(f"Verdict     : {ta.verdict.upper()}")
        print(f"Severity    : {ta.severity}")
        print(f"Confidence  : {ta.confidence}")
        print(f"Analyst review recommended: {ta.analyst_review_recommended}")
        if ta.possible_attack_objective:
            print(f"Possible objective: {ta.possible_attack_objective}")
        print(f"Reasons:")
        for r in ta.reasons:
            print(f"  - {r}")
        if ta.mitre_techniques:
            print(f"MITRE ATT&CK techniques:")
            for t in ta.mitre_techniques:
                print(f"  - {t.technique_id}: {t.technique_name}")
        if ta.missing_evidence:
            print(f"Missing evidence:")
            for m in ta.missing_evidence:
                print(f"  - {m}")
        if ra:
            print(f"\nRecommended action: {ra.action} (requires human approval: {ra.requires_human_approval})")
            print(f"Rationale: {ra.rationale}")

    print(f"\n{'=' * 60}\n")


def main():
    parser = argparse.ArgumentParser(description="PhishMind - phishing email investigation engine (Day 1 core)")
    parser.add_argument("eml_file", help="Path to a .eml file to investigate")
    parser.add_argument("--json", action="store_true", help="Output structured JSON instead of human-readable text")
    parser.add_argument("-o", "--output", help="Write output to this file instead of stdout")
    parser.add_argument(
        "--investigate", action="store_true",
        help="Phase 2: run the multi-agent investigation pipeline (email/IOC/URL agents + risk verdict) "
             "on top of the Phase 1 evidence extraction. Without this flag, output is identical to Phase 1.",
    )
    parser.add_argument(
        "--enrich", action="store_true",
        help="Phase 3: additionally call threat-intel APIs (VirusTotal/AbuseIPDB/urlscan.io) for domains/"
             "IPs/URLs found. Requires config/.env with at least one API key set, and network access. "
             "Implies --investigate.",
    )
    parser.add_argument(
        "--report", metavar="FORMAT", choices=["html", "md"],
        help="Phase 5: also write a standalone incident report (html or md) alongside normal output. "
             "Implies --investigate.",
    )


    parser.add_argument(
        "--ai",
        action="store_true",
        help="Phase 4.5: generate an AI-assisted SOC analyst explanation using Gemini. "
             "Implies --investigate.",
    )

    args = parser.parse_args()

    try:
        case = build_case(args.eml_file)
        if args.investigate or args.enrich or args.report or args.ai:
            case = investigate(
                case,
                enrich=args.enrich,
                use_ai=args.ai,
            )
      
     
    except FileNotFoundError:
        print(f"Error: file not found: {args.eml_file}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"Error parsing {args.eml_file}: {exc}", file=sys.stderr)
        sys.exit(1)

    if args.report:
        from reports.report_generator import write_report
        try:
            report_path = write_report(case, args.report)
            print(f"Report written: {report_path}", file=sys.stderr)
        except RuntimeError as exc:
            print(f"Warning: {exc}", file=sys.stderr)

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



