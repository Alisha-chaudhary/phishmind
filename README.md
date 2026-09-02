# PhishMind

An agentic phishing/BEC email investigation engine. Feed it a `.eml` file;
it parses it, extracts evidence, runs three analysis agents in parallel,
and a risk agent produces a verdict with MITRE ATT&CK mapping and a
recommended action -- every action requires human approval, PhishMind
never auto-remediates.

Built in the same modular style as [ThreatLens](https://github.com/Alisha-chaudhary): each
module has exactly one job, every stage produces a typed object instead of
a raw dict, and the final report is a serialization of that object tree.

## Quick start

```bash
pip install -r Requirements.txt --break-system-packages

# Phase 1: parse + extract evidence only
python phishmind.py data/test_emails/01_credential_phishing.eml

# Phase 2: full agentic investigation with verdict
python phishmind.py data/test_emails/01_credential_phishing.eml --investigate

# Phase 3: also enrich indicators against threat-intel APIs
cp config/.env.example config/.env   # fill in whichever keys you have
python phishmind.py data/test_emails/01_credential_phishing.eml --enrich

# Phase 5: also write a standalone incident report
python phishmind.py data/test_emails/01_credential_phishing.eml --investigate --report html

# JSON output for any of the above
python phishmind.py data/test_emails/01_credential_phishing.eml --investigate --json

# Phase 4: run the automated test suite
pytest tests/ -v
```

## Why this project exists

Most portfolio SOC-automation projects stop at "check SPF/DKIM/DMARC, flag
if it fails." That's a real gap: a BEC attacker using a **compromised but
legitimately-authenticated** mailbox sails through clean SPF/DKIM/DMARC
every time. PhishMind's entire Phase 2 redesign exists to fix that one
design flaw: **authentication is one input into the verdict, never the
verdict itself.**

Two test cases in `data/test_emails/` exist specifically to prove this:

| File | Auth | What it tests |
|---|---|---|
| `03_compromised_legitimate_sender.eml` | clean SPF/DKIM/DMARC | Payment-change language must still get flagged (`suspicious`), not cleared, just because auth passed. |
| `04_false_positive_auth_failure.eml` | SPF fail, DKIM/DMARC pass | A lone SPF failure (e.g. from a recent mail-infra migration) must **not** be called `malicious` with nothing else corroborating it -- correct outcome is `inconclusive`, with `analyst_review_recommended: true`. |

`tests/test_pipeline.py` asserts against both automatically, alongside two
more baseline cases, so this guardrail can't silently regress as the
scoring logic evolves.

## Architecture

```
.eml file
    │
    ▼
┌─────────────────────────── Phase 1 (core/) ───────────────────────────┐
│ email_parser  → headers, body, attachments (+hashes)                  │
│ evidence_extractor → URLs, domains, public IPs                        │
│ auth_analyzer → SPF/DKIM/DMARC (as reported by receiving server),     │
│                 Reply-To/Return-Path mismatch, display-name spoof     │
└─────────────────────────────────┬──────────────────────────────────────┘
                                   ▼
                         InvestigationCase (core/models.py)
                                   │
                    ── only reached with --investigate ──
                                   ▼
┌────────────────────── Phase 2 (agents/, detection/) ───────────────────┐
│                    agents/orchestrator.py                              │
│         ┌───────────┬──────────────┬──────────────┐                   │
│         ▼           ▼              ▼                                  │
│    ioc_agent    email_agent    url_agent                              │
│  (normalize &  (sender ID,   (URL structure,                          │
│   inventory     BEC/urgency   credential-harvest                      │
│   indicators)   language)     paths, abused hosts)                    │
│         └───────────┴──────────────┘                                  │
│                      ▼                                                 │
│              agents/risk_agent.py                                     │
│      (only place a verdict is assigned; folds in                      │
│       Phase 3 enrichment when --enrich is used)                       │
└──────────────────────────────────┬──────────────────────────────────────┘
                                    ▼
                    ── only reached with --enrich ──
┌──────────────── Phase 3 (intelligence/, config/) ──────────────────────┐
│  VirusTotal (domains) · AbuseIPDB (IPs) · urlscan.io (URLs)            │
│  Degrades to `available=False` + reason on missing key / network      │
│  error / rate limit -- never crashes the CLI, never silently no-ops.  │
└──────────────────────────────────┬──────────────────────────────────────┘
                                    ▼
                    ── only reached with --report ──
┌────────────────────────── Phase 5 (reports/) ──────────────────────────┐
│  Standalone incident report: Markdown (stdlib) or HTML (Jinja2)        │
└──────────────────────────────────────────────────────────────────────┘

Phase 4 (tests/): pytest suite asserting pipeline output against
data/test_emails/*.expected.json specs. Runs independently of the CLI.

Phase 6 (this file, phishmind.py): rich-colorized terminal output,
falling back to plain text automatically if `rich` isn't installed.
```

## Project layout

```
phishmind/
├── phishmind.py                 # CLI entry point -- wires everything together
│
├── core/                        # Phase 1 -- parsing & evidence extraction
│   ├── models.py                #   typed dataclasses for the whole pipeline
│   ├── email_parser.py          #   .eml -> headers/body/attachments
│   ├── evidence_extractor.py    #   URL/domain/IP extraction
│   └── auth_analyzer.py         #   SPF/DKIM/DMARC + sender mismatch/spoof heuristics
│
├── agents/                      # Phase 2 -- agentic investigation
│   ├── orchestrator.py          #   coordinates agents; no analysis logic of its own
│   ├── ioc_agent.py             #   normalizes/inventories indicators
│   ├── url_agent.py             #   URL structure analysis
│   ├── email_agent.py           #   sender identity + BEC/urgency language
│   └── risk_agent.py            #   the only place a verdict is assigned
│
├── detection/
│   └── modern_threats.py        # Pattern DATA only (no logic) -- shared by all agents
│
├── intelligence/                # Phase 3 -- threat-intel enrichment
│   └── threat_intel.py          #   VirusTotal / AbuseIPDB / urlscan.io clients
│
├── config/                      # Phase 3 -- API key loading
│   ├── settings.py
│   └── .env.example             #   copy to .env, fill in keys you have (none required)
│
├── reports/                     # Phase 5 -- incident report generation
│   └── report_generator.py      #   Markdown + HTML (Jinja2) report rendering
│
├── tests/                       # Phase 4 -- automated regression suite
│   └── test_pipeline.py
│
├── data/test_emails/            # Synthetic .eml fixtures + .expected.json specs
│
├── README.md
└── Requirements.txt
```

## Design decisions worth knowing (interview/SOP talking points)

- **Authentication-Results parsing, not from-scratch SPF/DKIM validation.**
  A saved `.eml` doesn't carry the original SMTP connection info (the IP
  that actually delivered it), so a from-scratch SPF check on a static
  file can't be authoritative. Reading the receiving server's own verdict
  is what a real analyst does.
- **Confidence is `low`/`medium`/`high`, never a bare percentage** --
  avoids the false-precision trap of a made-up "87% malicious" score.
  Every finding also carries `reasoning` so a confidence level is always
  justified in text, not just a label.
- **MITRE technique IDs are drawn from a closed catalog** (`detection/modern_threats.py:MITRE_CATALOG`)
  and every citation carries `justified_by` evidence refs --
  `tests/test_pipeline.py::test_mitre_techniques_always_have_justification`
  enforces this. Guards against the common portfolio-project mistake of
  tacking on MITRE IDs because the verdict is malicious and IDs look thorough.
- **Every `RecommendedAction.requires_human_approval` defaults to `True`,
  no exceptions.** PhishMind investigates and recommends; it never
  auto-quarantines or auto-blocks anything.
- **Rule-based agents, not LLM-backed**, by deliberate choice: deterministic
  scoring is testable against the `.expected.json` specs in a way an
  LLM-backed agent wouldn't be, and it's free to run at any volume. An
  LLM-backed reasoning layer on top of these findings (Phase "2.5") is a
  natural next step once the rule-based baseline is solid and well-tested.
- **One real bug found and fixed during Phase 2 build-out:** the original
  `COMMONLY_SPOOFED_BRANDS` list in `core/auth_analyzer.py` included
  generic department words (`"hr"`, `"payroll"`, `"it support"`) matched
  by raw substring, which flagged an ordinary "HR Team" internal email as
  a brand-spoof attempt. Fixed by removing generic terms and switching to
  word-boundary matching -- documented here rather than silently patched,
  since it's exactly the kind of false positive this project is meant to
  demonstrate awareness of.

## Roadmap / what's left

- **Phase 2.5 (optional):** swap `risk_agent`'s rule-based scoring for an
  LLM-backed reasoning layer (e.g. via LangChain, matching the stack in
  [SentinelAI SOC Copilot](https://github.com/Alisha-chaudhary)), using the
  current rule-based agent as a fallback / sanity check.
- **Attachment sandboxing:** attachments are currently hashed only
  (`AttackTechnique T1566.001` is cited but never corroborated by
  detonation). A future phase could integrate a sandbox API or static
  macro/script analysis for Office documents.
- **Batch mode:** `phishmind.py` currently investigates one `.eml` at a
  time; a `--batch <dir>` flag processing a whole mailbox export is a
  natural CLI extension using the same `orchestrator.investigate()` call
  per file.
- **CI:** a GitHub Actions workflow running `pytest tests/ -v` on every
  push would turn the Phase 4 suite from "runs locally" into "enforced
  on every commit" -- a good next addition for the portfolio narrative.


